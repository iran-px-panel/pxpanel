# ============================================================
# PXpanel 12.1.0 Beta
# Railway Ready
# ============================================================

import asyncio
import base64
import hashlib
import json
import logging
import os
import secrets
import time

from collections import defaultdict, deque
from datetime import datetime, timedelta
from pathlib import Path
from urllib.parse import quote, parse_qs

import aiofiles
import httpx
import uvicorn

from fastapi import (
    FastAPI,
    Request,
    HTTPException,
    Depends,
)
from fastapi.responses import (
    Response,
    HTMLResponse,
    JSONResponse,
    RedirectResponse,
)
from fastapi.middleware.cors import CORSMiddleware


# ============================================================
# APP
# ============================================================

APP_NAME = "PXpanel"
APP_VERSION = "12.1.0 Beta"

SUPPORT_USERNAME = "@logic_sec"
SUPPORT_URL = "https://t.me/logic_sec"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

logger = logging.getLogger(APP_NAME)


# ============================================================
# TIMEZONE
# ============================================================

try:
    from zoneinfo import ZoneInfo

    IRAN_TZ = ZoneInfo("Asia/Tehran")

except Exception:
    IRAN_TZ = None


# ============================================================
# RAILWAY
# ============================================================

PORT = int(
    os.environ.get(
        "PORT",
        "8000",
    )
)

DATA_DIR = Path(
    os.environ.get(
        "RAILWAY_VOLUME_MOUNT_PATH",
        os.environ.get(
            "DATA_DIR",
            "./data",
        ),
    )
)

DATA_DIR.mkdir(
    parents=True,
    exist_ok=True,
)

DATA_FILE = DATA_DIR / "pxpanel_state.json"
SECRET_FILE = DATA_DIR / "pxpanel_secret.key"


# ============================================================
# FASTAPI
# ============================================================

app = FastAPI(
    title=APP_NAME,
    version=APP_VERSION,
    docs_url=None,
    redoc_url=None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
# LOCKS
# ============================================================

SAVE_LOCK = asyncio.Lock()
LINKS_LOCK = asyncio.Lock()
SUBS_LOCK = asyncio.Lock()
SESSIONS_LOCK = asyncio.Lock()


# ============================================================
# SECRET
# ============================================================

def load_or_create_secret() -> str:
    env_secret = os.environ.get("SECRET_KEY")

    if env_secret:
        return env_secret

    try:
        if SECRET_FILE.exists():
            existing = (
                SECRET_FILE
                .read_text(
                    encoding="utf-8"
                )
                .strip()
            )

            if existing:
                return existing

        generated = secrets.token_urlsafe(48)

        SECRET_FILE.write_text(
            generated,
            encoding="utf-8",
        )

        return generated

    except Exception as exc:
        logger.warning(
            "Could not persist SECRET_KEY: %s",
            exc,
        )

        return secrets.token_urlsafe(48)


SECRET_KEY = load_or_create_secret()


# ============================================================
# CONFIG
# ============================================================

CONFIG = {
    "port": PORT,
    "secret": SECRET_KEY,
    "host": os.environ.get(
        "RAILWAY_PUBLIC_DOMAIN",
        "localhost",
    ),
}


# ============================================================
# STATE
# ============================================================

LINKS: dict = {}
SUBS: dict = {}
SESSIONS: dict = {}
connections: dict = {}

stats = {
    "total_bytes": 0,
    "total_requests": 0,
    "total_errors": 0,
    "start_time": time.time(),
}

error_logs = deque(maxlen=100)
activity_logs = deque(maxlen=250)

hourly_traffic = defaultdict(int)

http_client: httpx.AsyncClient | None = None


# ============================================================
# PROTOCOL
# ============================================================

PROTOCOLS = (
    "vless-ws",
    "xhttp-packet-up",
    "xhttp-stream-up",
    "xhttp-stream-one",
)

DEFAULT_PROTOCOL = "vless-ws"

FINGERPRINTS = (
    "chrome",
    "firefox",
    "safari",
    "ios",
    "android",
    "edge",
    "360",
    "qq",
    "random",
    "randomized",
)

DEFAULT_FINGERPRINT = "chrome"

DEFAULT_ALPN_BY_PROTOCOL = {
    "vless-ws": "http/1.1",
    "xhttp-packet-up": "h2,http/1.1",
    "xhttp-stream-up": "h2,http/1.1",
    "xhttp-stream-one": "h2,http/1.1",
}

DEFAULT_PORT = 443
MIN_PORT = 1
MAX_PORT = 65535

DEFAULT_SPEED_LIMIT = 0


# ============================================================
# LOGGING
# ============================================================

def log_activity(
    kind: str,
    message: str,
    level: str = "info",
):
    activity_logs.append(
        {
            "kind": kind,
            "level": level,
            "message": message,
            "time": datetime.now().isoformat(),
        }
    )


# ============================================================
# HELPERS
# ============================================================

def escape_html(value) -> str:
    return (
        str(
            value
            if value is not None
            else ""
        )
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#039;")
    )


def safe_int(
    value,
    default=0,
    minimum=0,
    maximum=None,
):
    try:
        number = int(value)
    except Exception:
        number = default

    if number < minimum:
        number = minimum

    if maximum is not None and number > maximum:
        number = maximum

    return number


def safe_float(
    value,
    default=0.0,
    minimum=0.0,
):
    try:
        number = float(value)
    except Exception:
        number = default

    return max(
        minimum,
        number,
    )


def generate_uuid():
    value = secrets.token_hex(16)

    return (
        f"{value[:8]}-"
        f"{value[8:12]}-"
        f"{value[12:16]}-"
        f"{value[16:20]}-"
        f"{value[20:32]}"
    )


def auto_config_name() -> str:
    alphabet = (
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789"
    )

    suffix = "".join(
        secrets.choice(alphabet)
        for _ in range(8)
    )

    return f"pxpanel_{suffix}"


def now_ir():
    if IRAN_TZ:
        return datetime.now(IRAN_TZ)

    return datetime.now()


def uptime():
    seconds = int(
        time.time()
        - stats["start_time"]
    )

    h = seconds // 3600

    m = (
        seconds
        % 3600
    ) // 60

    s = (
        seconds
        % 60
    )

    return (
        f"{h:02d}:"
        f"{m:02d}:"
        f"{s:02d}"
    )


def fmt_bytes(value: int):
    value = int(
        value or 0
    )

    if value < 1024:
        return f"{value} B"

    if value < 1024 ** 2:
        return (
            f"{value / 1024:.1f} KB"
        )

    if value < 1024 ** 3:
        return (
            f"{value / 1024 ** 2:.2f} MB"
        )

    return (
        f"{value / 1024 ** 3:.2f} GB"
    )


def parse_size_to_bytes(
    value: float,
    unit: str,
):
    if value <= 0:
        return 0

    unit = (
        unit
        or "GB"
    ).upper()

    if unit == "TB":
        return int(
            value
            * 1024 ** 4
        )

    if unit == "GB":
        return int(
            value
            * 1024 ** 3
        )

    if unit == "MB":
        return int(
            value
            * 1024 ** 2
        )

    if unit == "KB":
        return int(
            value
            * 1024
        )

    return int(value)


def parse_speed_to_bytes(
    value: float,
    unit: str,
):
    if value <= 0:
        return 0

    unit = (
        unit
        or "MBIT"
    ).upper()

    if unit == "MBIT":
        return int(
            value
            * 1024
            * 1024
            / 8
        )

    if unit == "KB":
        return int(
            value * 1024
        )

    if unit == "MB":
        return int(
            value
            * 1024
            * 1024
        )

    return int(value)


def is_link_expired(
    link: dict,
):
    expiry = link.get(
        "expires_at"
    )

    if not expiry:
        return False

    try:
        return (
            datetime.now()
            > datetime.fromisoformat(
                expiry
            )
        )

    except Exception:
        return False


def is_link_allowed(
    link: dict | None,
):
    if link is None:
        return False

    if not link.get(
        "active",
        True,
    ):
        return False

    if is_link_expired(link):
        return False

    limit = int(
        link.get(
            "limit_bytes",
            0,
        )
        or 0
    )

    used = int(
        link.get(
            "used_bytes",
            0,
        )
        or 0
    )

    if (
        limit > 0
        and used >= limit
    ):
        return False

    return True


def unique_ips_for_uuid(
    uuid: str,
):
    return {
        connection.get("ip")
        for connection in connections.values()
        if connection.get("uuid") == uuid
        and connection.get("ip")
    }


def client_ip(
    request: Request,
):
    forwarded = request.headers.get(
        "x-forwarded-for"
    )

    if forwarded:
        return (
            forwarded
            .split(",")[0]
            .strip()
        )

    real = request.headers.get(
        "x-real-ip"
    )

    if real:
        return real.strip()

    if request.client:
        return request.client.host

    return "unknown"


def is_ip_allowed(
    link: dict | None,
    uuid: str,
    ip: str,
):
    if link is None:
        return False

    limit = int(
        link.get(
            "ip_limit",
            0,
        )
        or 0
    )

    if limit <= 0:
        return True

    ips = unique_ips_for_uuid(uuid)

    if ip in ips:
        return True

    return len(ips) < limit


def get_host(
    request: Request | None = None,
) -> str:

    if request is not None:
        forwarded = request.headers.get(
            "x-forwarded-host"
        )

        normal = request.headers.get(
            "host"
        )

        host = (
            forwarded
            or normal
        )

        if host:
            host = host.split(":")[0].strip()

            CONFIG["host"] = host

            return host

    railway_domain = os.environ.get(
        "RAILWAY_PUBLIC_DOMAIN"
    )

    if railway_domain:
        return railway_domain

    return CONFIG["host"]


# ============================================================
# PASSWORD
# ============================================================

def hash_password(
    password: str,
) -> str:

    payload = (
        password
        + SECRET_KEY
    ).encode("utf-8")

    return hashlib.sha256(
        payload
    ).hexdigest()


DEFAULT_ADMIN_PASSWORD = os.environ.get(
    "ADMIN_PASSWORD",
    "pxpanel2026",
)

AUTH = {
    "password_hash":
        hash_password(
            DEFAULT_ADMIN_PASSWORD
        )
}


# ============================================================
# LOGIN BRUTE-FORCE PROTECTION
# ============================================================
# Maximum failed login attempts per IP inside the rolling window.
LOGIN_MAX_ATTEMPTS = 5
LOGIN_WINDOW_SECONDS = 15 * 60
LOGIN_LOCKOUT_SECONDS = 15 * 60
LOGIN_MIN_PASSWORD_LENGTH = 6

LOGIN_FAILURES = defaultdict(deque)
LOGIN_LOCKED_UNTIL = {}


def _cleanup_login_state(ip: str, now: float | None = None):
    now = now if now is not None else time.time()

    locked_until = LOGIN_LOCKED_UNTIL.get(ip, 0)
    if locked_until and locked_until <= now:
        LOGIN_LOCKED_UNTIL.pop(ip, None)

    failures = LOGIN_FAILURES.get(ip)
    if not failures:
        return

    cutoff = now - LOGIN_WINDOW_SECONDS
    while failures and failures[0] <= cutoff:
        failures.popleft()

    if not failures:
        LOGIN_FAILURES.pop(ip, None)


def login_is_blocked(ip: str):
    now = time.time()
    _cleanup_login_state(ip, now)

    locked_until = LOGIN_LOCKED_UNTIL.get(ip, 0)
    if locked_until > now:
        return True, max(1, int(locked_until - now))

    return False, 0


def register_login_failure(ip: str):
    now = time.time()
    _cleanup_login_state(ip, now)

    failures = LOGIN_FAILURES.setdefault(ip, deque())
    failures.append(now)

    if len(failures) >= LOGIN_MAX_ATTEMPTS:
        LOGIN_LOCKED_UNTIL[ip] = now + LOGIN_LOCKOUT_SECONDS
        failures.clear()
        log_activity(
            "auth",
            f"IP به دلیل تلاش‌های متعدد ورود ناموفق به مدت {LOGIN_LOCKOUT_SECONDS // 60} دقیقه مسدود شد: {ip}",
            "err",
        )
        return True, LOGIN_LOCKOUT_SECONDS

    return False, max(0, LOGIN_MAX_ATTEMPTS - len(failures))


def clear_login_failures(ip: str):
    LOGIN_FAILURES.pop(ip, None)
    LOGIN_LOCKED_UNTIL.pop(ip, None)


# ============================================================
# SESSION
# ============================================================

SESSION_COOKIE = "pxpanel_session"

SESSION_TTL = (
    60
    * 60
    * 24
    * 365
)


async def create_session() -> str:

    token = secrets.token_urlsafe(48)

    async with SESSIONS_LOCK:
        SESSIONS[token] = (
            time.time()
            + SESSION_TTL
        )

    return token


async def is_valid_session(
    token: str | None,
) -> bool:

    if not token:
        return False

    async with SESSIONS_LOCK:

        expiry = SESSIONS.get(token)

        if expiry is None:
            return False

        if expiry < time.time():

            SESSIONS.pop(
                token,
                None,
            )

            return False

        return True


async def destroy_session(
    token: str | None,
):
    if not token:
        return

    async with SESSIONS_LOCK:
        SESSIONS.pop(
            token,
            None,
        )


async def require_auth(
    request: Request,
):
    token = request.cookies.get(
        SESSION_COOKIE
    )

    if not await is_valid_session(
        token
    ):
        raise HTTPException(
            status_code=401,
            detail="unauthorized",
        )

    return token


def set_auth_cookie(
    response,
    request: Request,
    token: str,
):
    forwarded_proto = (
        request.headers
        .get(
            "x-forwarded-proto",
            "",
        )
        .lower()
    )

    is_https = (
        forwarded_proto == "https"
        or request.url.scheme == "https"
    )

    response.set_cookie(
        key=SESSION_COOKIE,
        value=token,
        max_age=SESSION_TTL,
        httponly=True,
        samesite="lax",
        path="/",
        secure=is_https,
    )


# ============================================================
# VLESS LINK GENERATION
# ============================================================

def generate_vless_link(
    uuid: str,
    host: str,
    remark: str = "PXpanel",
    protocol: str = DEFAULT_PROTOCOL,
    fingerprint: str | None = None,
    alpn: str | None = None,
    port: int | None = None,
):

    fp = (
        fingerprint
        or DEFAULT_FINGERPRINT
    ).strip().lower()

    if fp not in FINGERPRINTS:
        fp = DEFAULT_FINGERPRINT

    alpn_value = (
        (
            alpn
            or ""
        ).strip()
        or DEFAULT_ALPN_BY_PROTOCOL.get(
            protocol,
            "http/1.1",
        )
    )

    port_value = (
        port
        or DEFAULT_PORT
    )

    if not (
        MIN_PORT
        <= port_value
        <= MAX_PORT
    ):
        port_value = DEFAULT_PORT

    # ========================================================
    # IMPORTANT:
    # The working VLESS WebSocket core stays unchanged.
    # ========================================================

    if protocol == "vless-ws":

        path = (
            f"/ws/{uuid}"
        )

        params = {
            "encryption": "none",
            "security": "tls",
            "type": "ws",
            "host": host,
            "path": path,
            "sni": host,
            "fp": fp,
            "alpn": alpn_value,
        }

    else:

        mode = protocol.replace(
            "xhttp-",
            "",
        )

        path = (
            f"/xhttp-siz10/"
            f"{mode}/"
            f"{uuid}"
        )

        params = {
            "encryption": "none",
            "security": "tls",
            "type": "xhttp",
            "mode": mode,
            "host": host,
            "path": path,
            "sni": host,
            "fp": fp,
            "alpn": alpn_value,
        }

    query = "&".join(
        f"{key}="
        f"{quote(str(value))}"
        for key, value in params.items()
    )

    return (
        f"vless://"
        f"{uuid}@"
        f"{host}:"
        f"{port_value}?"
        f"{query}#"
        f"{quote(remark)}"
    )


def vless_link_for_link(
    link: dict,
    uid: str,
    host: str,
):
    return generate_vless_link(
        uid,
        host,
        remark=(
            f"pxpanel-"
            f"{link.get('label', '')}"
        ),
        protocol=link.get(
            "protocol",
            DEFAULT_PROTOCOL,
        ),
        fingerprint=link.get(
            "fingerprint",
            DEFAULT_FINGERPRINT,
        ),
        alpn=link.get(
            "alpn"
        ),
        port=link.get(
            "port",
            DEFAULT_PORT,
        ),
    )


def get_link_info(
    link: dict,
    uid: str,
    host: str,
):
    return {
        "uuid": uid,
        "name": link.get(
            "label",
            "",
        ),
        "label": link.get(
            "label",
            "",
        ),
        "protocol": link.get(
            "protocol",
            DEFAULT_PROTOCOL,
        ),
        "active": is_link_allowed(link),
        "used_bytes": int(
            link.get(
                "used_bytes",
                0,
            )
            or 0
        ),
        "limit_bytes": int(
            link.get(
                "limit_bytes",
                0,
            )
            or 0
        ),
        "expires_at": link.get(
            "expires_at"
        ),
        "ip_limit": int(
            link.get(
                "ip_limit",
                0,
            )
            or 0
        ),
        "speed_limit_bytes": int(
            link.get(
                "speed_limit_bytes",
                0,
            )
            or 0
        ),
        "connection_limit": int(
            link.get(
                "connection_limit",
                0,
            )
            or 0
        ),
        "fragment": link.get(
            "fragment",
            "off",
        ),
        "fingerprint": link.get(
            "fingerprint",
            DEFAULT_FINGERPRINT,
        ),
        "alpn": link.get(
            "alpn",
            "",
        ),
        "port": link.get(
            "port",
            DEFAULT_PORT,
        ),
        "note": link.get(
            "note",
            "",
        ),
        "vless": vless_link_for_link(
            link,
            uid,
            host,
        ),
        "sub": (
            f"https://{host}"
            f"/sub/{uid}"
        ),
        "info": (
            f"https://{host}"
            f"/info/{uid}"
        ),
        "support": SUPPORT_USERNAME,
    }


# ============================================================
# PERSISTENCE
# ============================================================

async def load_state():

    global AUTH

    try:

        DATA_DIR.mkdir(
            parents=True,
            exist_ok=True,
        )

        if not DATA_FILE.exists():
            return

        async with aiofiles.open(
            DATA_FILE,
            "r",
            encoding="utf-8",
        ) as file:
            raw = await file.read()

        data = json.loads(raw)

        LINKS.update(
            data.get(
                "links",
                {},
            )
        )

        SUBS.update(
            data.get(
                "subs",
                {},
            )
        )

        stored_password = data.get(
            "password_hash"
        )

        if stored_password:
            AUTH[
                "password_hash"
            ] = stored_password

        # Compatibility for older records
        for uid, link in LINKS.items():

            link.setdefault(
                "protocol",
                DEFAULT_PROTOCOL,
            )

            link.setdefault(
                "fingerprint",
                DEFAULT_FINGERPRINT,
            )

            link.setdefault(
                "alpn",
                "",
            )

            link.setdefault(
                "port",
                DEFAULT_PORT,
            )

            link.setdefault(
                "ip_limit",
                0,
            )

            link.setdefault(
                "speed_limit_bytes",
                0,
            )

            link.setdefault(
                "connection_limit",
                0,
            )

            link.setdefault(
                "fragment",
                "off",
            )

            link.setdefault(
                "used_bytes",
                0,
            )

        logger.info(
            "State loaded: %d links / %d subscriptions",
            len(LINKS),
            len(SUBS),
        )

    except Exception as exc:

        logger.exception(
            "Could not load state: %s",
            exc,
        )


async def save_state():

    async with SAVE_LOCK:

        try:

            DATA_DIR.mkdir(
                parents=True,
                exist_ok=True,
            )

            payload = {
                "links":
                    dict(LINKS),

                "subs":
                    dict(SUBS),

                "password_hash":
                    AUTH[
                        "password_hash"
                    ],

                "saved_at":
                    datetime.now().isoformat(),
            }

            temp_file = (
                DATA_FILE.with_suffix(
                    ".tmp"
                )
            )

            async with aiofiles.open(
                temp_file,
                "w",
                encoding="utf-8",
            ) as file:

                await file.write(
                    json.dumps(
                        payload,
                        ensure_ascii=False,
                        indent=2,
                    )
                )

            temp_file.replace(
                DATA_FILE
            )

        except Exception as exc:

            logger.exception(
                "Could not save state: %s",
                exc,
            )


# ============================================================
# DEFAULT LINK
# ============================================================

_default_link_created = False


async def ensure_default_link():

    global _default_link_created

    if _default_link_created:
        return

    async with LINKS_LOCK:

        if not any(
            item.get("is_default")
            for item in LINKS.values()
        ):

            digest = hashlib.sha256(
                (
                    "default"
                    + SECRET_KEY
                ).encode("utf-8")
            ).hexdigest()

            uid = (
                f"{digest[:8]}-"
                f"{digest[8:12]}-"
                f"{digest[12:16]}-"
                f"{digest[16:20]}-"
                f"{digest[20:32]}"
            )

            LINKS[uid] = {
                "label":
                    "لینک پیش‌فرض",

                "limit_bytes":
                    0,

                "used_bytes":
                    0,

                "created_at":
                    datetime.now().isoformat(),

                "active":
                    True,

                "expires_at":
                    None,

                "note":
                    "",

                "is_default":
                    True,

                "sub_id":
                    None,

                "protocol":
                    DEFAULT_PROTOCOL,

                "fingerprint":
                    DEFAULT_FINGERPRINT,

                "alpn":
                    "http/1.1",

                "port":
                    DEFAULT_PORT,

                "ip_limit":
                    0,

                "speed_limit_bytes":
                    DEFAULT_SPEED_LIMIT,

                "connection_limit":
                    0,

                "fragment":
                    "off",
            }

            asyncio.create_task(
                save_state()
            )

    _default_link_created = True


# ============================================================
# LINK MANAGEMENT
# ============================================================

async def make_link(
    label: str = "لینک جدید",
    limit_bytes: int = 0,
    expires_at: str | None = None,
    note: str = "",
    sub_id: str | None = None,
    protocol: str = DEFAULT_PROTOCOL,
    fingerprint: str = DEFAULT_FINGERPRINT,
    alpn: str = "",
    port: int = DEFAULT_PORT,
    ip_limit: int = 0,
    speed_limit_bytes: int = 0,
    connection_limit: int = 0,
    fragment: str = "off",
):

    if protocol not in PROTOCOLS:
        protocol = DEFAULT_PROTOCOL

    fingerprint = (
        fingerprint
        or DEFAULT_FINGERPRINT
    ).strip().lower()

    if fingerprint not in FINGERPRINTS:
        fingerprint = DEFAULT_FINGERPRINT

    if not (
        MIN_PORT
        <= port
        <= MAX_PORT
    ):
        port = DEFAULT_PORT

    uid = generate_uuid()

    record = {
        "label":
            (
                label
                or "لینک جدید"
            ).strip()[:60],

        "limit_bytes":
            max(
                0,
                int(limit_bytes),
            ),

        "used_bytes":
            0,

        "created_at":
            datetime.now().isoformat(),

        "active":
            True,

        "expires_at":
            expires_at,

        "note":
            (
                note
                or ""
            ).strip()[:500],

        "is_default":
            False,

        "sub_id":
            sub_id,

        "protocol":
            protocol,

        "fingerprint":
            fingerprint,

        "alpn":
            (
                alpn
                or ""
            ).strip()[:100],

        "port":
            port,

        "ip_limit":
            max(
                0,
                int(ip_limit),
            ),

        "speed_limit_bytes":
            max(
                0,
                int(speed_limit_bytes),
            ),

        "connection_limit":
            max(
                0,
                int(connection_limit),
            ),

        "fragment":
            (
                fragment
                or "off"
            ).strip().lower(),
    }

    async with LINKS_LOCK:
        LINKS[uid] = record

    if sub_id:

        async with SUBS_LOCK:

            if sub_id in SUBS:

                ids = SUBS[
                    sub_id
                ].setdefault(
                    "link_ids",
                    [],
                )

                if uid not in ids:
                    ids.append(uid)

    await save_state()

    log_activity(
        "link",
        (
            f"کانفیگ "
            f"«{record['label']}» "
            f"ساخته شد"
        ),
        "ok",
    )

    return uid, record


async def remove_link(
    uid: str,
):

    async with LINKS_LOCK:

        if uid not in LINKS:
            return None

        label = LINKS[
            uid
        ].get(
            "label",
            uid,
        )

        sub_id = LINKS[
            uid
        ].get(
            "sub_id"
        )

        del LINKS[uid]

    if sub_id:

        async with SUBS_LOCK:

            if sub_id in SUBS:

                ids = SUBS[
                    sub_id
                ].get(
                    "link_ids",
                    [],
                )

                if uid in ids:
                    ids.remove(uid)

    await save_state()

    log_activity(
        "link",
        (
            f"کانفیگ "
            f"«{label}» "
            f"حذف شد"
        ),
        "warn",
    )

    return label


async def set_link_active(
    uid: str,
    active: bool,
):

    async with LINKS_LOCK:

        if uid not in LINKS:
            return None

        LINKS[
            uid
        ][
            "active"
        ] = bool(active)

        record = LINKS[uid]

    await save_state()

    log_activity(
        "link",
        (
            f"کانفیگ "
            f"«{record['label']}» "
            f"{'فعال' if active else 'غیرفعال'} شد"
        ),
        "ok"
        if active
        else "warn",
    )

    return record


# ============================================================
# SUB GROUPS
# ============================================================

async def create_sub_group(
    name: str = "گروه جدید",
    desc: str = "",
    password: str = "",
):

    name = (
        name
        or "گروه جدید"
    ).strip()[:60]

    desc = (
        desc
        or ""
    ).strip()[:200]

    password = (
        password
        or ""
    ).strip()

    sub_id = generate_uuid()

    uuid_key = secrets.token_urlsafe(16)

    record = {
        "name":
            name,

        "desc":
            desc,

        "password_hash":
            (
                hash_password(password)
                if password
                else None
            ),

        "uuid_key":
            uuid_key,

        "created_at":
            datetime.now().isoformat(),

        "link_ids":
            [],
    }

    async with SUBS_LOCK:
        SUBS[sub_id] = record

    await save_state()

    log_activity(
        "sub",
        (
            f"گروه "
            f"«{name}» "
            f"ساخته شد"
        ),
        "ok",
    )

    return (
        sub_id,
        record,
    )


async def set_link_sub(
    uid: str,
    sub_id: str | None,
):

    async with LINKS_LOCK:

        if uid not in LINKS:
            return False

        old_sub = LINKS[
            uid
        ].get(
            "sub_id"
        )

        label = LINKS[
            uid
        ].get(
            "label",
            uid,
        )

    if sub_id is not None:

        async with SUBS_LOCK:

            if sub_id not in SUBS:
                return False

    async with SUBS_LOCK:

        if (
            old_sub
            and old_sub in SUBS
        ):

            ids = SUBS[
                old_sub
            ].get(
                "link_ids",
                [],
            )

            if uid in ids:
                ids.remove(uid)

        if (
            sub_id
            and sub_id in SUBS
        ):

            ids = SUBS[
                sub_id
            ].setdefault(
                "link_ids",
                [],
            )

            if uid not in ids:
                ids.append(uid)

    async with LINKS_LOCK:

        if uid in LINKS:

            LINKS[
                uid
            ][
                "sub_id"
            ] = sub_id

    await save_state()

    log_activity(
        "link",
        (
            f"کانفیگ "
            f"«{label}» "
            f"{'به گروه اضافه شد' if sub_id else 'از گروه خارج شد'}"
        ),
        "info",
    )

    return True


async def remove_sub_group(
    sub_id: str,
):

    async with SUBS_LOCK:

        if sub_id not in SUBS:
            return None

        name = SUBS[
            sub_id
        ].get(
            "name",
            sub_id,
        )

        del SUBS[sub_id]

    async with LINKS_LOCK:

        for link in LINKS.values():

            if (
                link.get("sub_id")
                == sub_id
            ):
                link["sub_id"] = None

    await save_state()

    log_activity(
        "sub",
        (
            f"گروه "
            f"«{name}» "
            f"حذف شد"
        ),
        "warn",
    )

    return name


# ============================================================
# STARTUP
# ============================================================

@app.on_event("startup")
async def startup():

    global http_client

    limits = httpx.Limits(
        max_connections=500,
        max_keepalive_connections=100,
    )

    timeout = httpx.Timeout(
        30.0,
        connect=10.0,
    )

    http_client = httpx.AsyncClient(
        limits=limits,
        timeout=timeout,
        follow_redirects=True,
    )

    await load_state()

    await ensure_default_link()

    log_activity(
        "system",
        (
            f"{APP_NAME} "
            f"v{APP_VERSION} "
            f"راه‌اندازی شد"
        ),
        "ok",
    )

    logger.info(
        "%s v%s started on 0.0.0.0:%s",
        APP_NAME,
        APP_VERSION,
        PORT,
    )

    logger.info(
        "Data directory: %s",
        DATA_DIR,
    )


@app.on_event("shutdown")
async def shutdown():

    await save_state()

    if http_client:
        await http_client.aclose()


# ============================================================
# LANDING
# ============================================================

LANDING_HTML = r"""
<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">

<title>PXpanel</title>

<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>

<link
href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700;800;900&display=swap"
rel="stylesheet">

<style>
*{
    box-sizing:border-box;
}

html,body{
    margin:0;
    min-height:100%;
}

body{
    min-height:100vh;
    display:flex;
    justify-content:center;
    align-items:center;
    padding:20px;
    color:#fff;
    font-family:"Vazirmatn",sans-serif;

    background:
        radial-gradient(
            circle at 15% 15%,
            rgba(99,102,241,.22),
            transparent 30%
        ),
        radial-gradient(
            circle at 85% 85%,
            rgba(139,92,246,.18),
            transparent 30%
        ),
        #07070a;
}

.card{
    width:100%;
    max-width:580px;
    padding:32px;
    border-radius:28px;

    border:1px solid rgba(255,255,255,.09);

    background:
        linear-gradient(
            145deg,
            rgba(255,255,255,.07),
            rgba(255,255,255,.025)
        );

    backdrop-filter:blur(28px) saturate(150%);

    box-shadow:
        0 30px 90px rgba(0,0,0,.45);
}

.brand{
    display:flex;
    align-items:center;
    gap:12px;
}

.logo{
    width:48px;
    height:48px;
    border-radius:15px;

    display:flex;
    justify-content:center;
    align-items:center;

    font-size:18px;
    font-weight:900;

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );
}

.brand-name{
    font-size:17px;
    font-weight:900;
}

.version{
    margin-top:4px;
    font-size:11px;
    color:#a78bfa;
}

.status{
    display:inline-block;
    margin-top:23px;
    padding:7px 11px;
    border-radius:999px;

    color:#86efac;
    background:rgba(34,197,94,.07);
    border:1px solid rgba(34,197,94,.15);

    font-size:11px;
}

h1{
    margin:18px 0 0;
    font-size:28px;
    line-height:1.55;
}

.desc{
    margin-top:12px;
    color:rgba(255,255,255,.52);
    line-height:2;
    font-size:13px;
}

.path{
    margin-top:22px;
    padding:15px;
    border-radius:15px;

    background:rgba(0,0,0,.18);
    border:1px solid rgba(255,255,255,.07);

    direction:ltr;
    text-align:left;
    font-family:Consolas,monospace;
    color:#c4b5fd;
}

.actions{
    display:flex;
    gap:10px;
    margin-top:20px;
}

.btn{
    flex:1;
    padding:13px;
    border-radius:14px;
    text-align:center;
    text-decoration:none;

    font-size:12px;
    font-weight:800;
}

.primary{
    color:#fff;
    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );
}

.secondary{
    color:#fff;
    background:rgba(255,255,255,.035);
    border:1px solid rgba(255,255,255,.08);
}

.footer{
    margin-top:22px;
    padding-top:16px;
    border-top:1px solid rgba(255,255,255,.07);

    display:flex;
    justify-content:space-between;

    font-size:10px;
    color:rgba(255,255,255,.35);
}

.support{
    color:#a78bfa;
    text-decoration:none;
}

@media(max-width:600px){
    .card{
        padding:24px;
        border-radius:22px;
    }

    h1{
        font-size:23px;
    }

    .actions{
        flex-direction:column;
    }
}
</style>
</head>

<body>

<div class="card">

<div class="brand">

<div class="logo">P</div>

<div>
<div class="brand-name">
PXpanel
</div>

<div class="version">
12.1.0 Beta
</div>
</div>

</div>

<div class="status">
● سیستم آنلاین و فعال است
</div>

<h1>
برای ورود به پنل
<br>
ابتدا وارد شوید
</h1>

<div class="desc">
این صفحه، درگاه عمومی PXpanel است.
برای دسترسی به داشبورد مدیریت از مسیر ورود استفاده کنید.
</div>

<div class="path">
/login
</div>

<div class="actions">

<a
href="/login"
class="btn primary"
>
ورود به پنل
</a>

<a
href="https://t.me/Pixonal"
target="_blank"
rel="noopener"
class="btn secondary"
>
پشتیبانی
</a>

</div>

<div class="footer">

<span>
PXpanel · 12.1.0 Beta
</span>

<a
href="https://t.me/Pixonal"
target="_blank"
class="support"
>
@Pixonal
</a>

</div>

</div>

</body>
</html>
"""


@app.get(
    "/",
    response_class=HTMLResponse,
)
async def root(
    request: Request,
):

    if await is_valid_session(
        request.cookies.get(
            SESSION_COOKIE
        )
    ):
        return RedirectResponse(
            "/dashboard"
        )

    return HTMLResponse(
        LANDING_HTML
    )


# ============================================================
# HEALTH
# ============================================================

@app.get("/health")
async def health():

    return {
        "status": "ok",
        "service": APP_NAME,
        "version": APP_VERSION,
        "connections": len(connections),
        "uptime": uptime(),
    }


# ============================================================
# LOGIN
# ============================================================

LOGIN_HTML = r"""
<!DOCTYPE html>
<html lang="fa" dir="rtl">

<head>

<meta charset="UTF-8">

<meta
name="viewport"
content="width=device-width,initial-scale=1"
>

<title>ورود | PXpanel</title>

<link
rel="preconnect"
href="https://fonts.googleapis.com"
>

<link
rel="preconnect"
href="https://fonts.gstatic.com"
crossorigin
>

<link
href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800;900&display=swap"
rel="stylesheet"
>

<style>

*{
    box-sizing:border-box;
}

body{
    margin:0;
    min-height:100vh;

    display:flex;
    align-items:center;
    justify-content:center;

    padding:20px;

    font-family:"Vazirmatn",sans-serif;
    color:#fff;

    background:
        radial-gradient(
            circle at 15% 15%,
            rgba(99,102,241,.20),
            transparent 32%
        ),
        #07070a;
}

.card{
    width:100%;
    max-width:420px;
    padding:30px;
    border-radius:26px;

    background:rgba(255,255,255,.045);
    border:1px solid rgba(255,255,255,.09);

    backdrop-filter:blur(28px);

    box-shadow:
        0 30px 90px rgba(0,0,0,.45);
}

.logo{
    width:49px;
    height:49px;

    display:flex;
    align-items:center;
    justify-content:center;

    border-radius:16px;
    margin-bottom:20px;

    font-weight:900;

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );
}

h1{
    margin:0;
    font-size:25px;
}

.version{
    margin-top:5px;
    color:#a78bfa;
    font-size:11px;
}

.desc{
    margin-top:9px;
    color:rgba(255,255,255,.48);
    line-height:1.9;
    font-size:12px;
}

form{
    margin-top:21px;
}

label{
    display:block;
    margin-bottom:8px;
    font-size:12px;
    color:rgba(255,255,255,.55);
}

input{
    width:100%;
    padding:14px;

    border:1px solid rgba(255,255,255,.08);
    outline:none;
    border-radius:14px;

    color:#fff;
    background:rgba(0,0,0,.18);

    direction:ltr;
    text-align:left;

    font-family:"Vazirmatn",sans-serif;
}

input:focus{
    border-color:rgba(129,140,248,.6);
}

button{
    width:100%;
    margin-top:13px;
    padding:14px;

    border:0;
    border-radius:14px;

    color:#fff;
    cursor:pointer;

    font-family:"Vazirmatn",sans-serif;
    font-weight:800;

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );
}

.error{
    margin-top:12px;
    padding:11px;

    border-radius:12px;

    color:#fca5a5;
    background:rgba(239,68,68,.08);
    border:1px solid rgba(239,68,68,.15);

    font-size:11px;
}

.support{
    display:block;
    margin-top:18px;
    text-align:center;

    color:#a78bfa;
    text-decoration:none;

    font-size:11px;
}

</style>

</head>

<body>

<div class="card">

<div class="logo">
P
</div>

<h1>
ورود به PXpanel
</h1>

<div class="version">
12.1.0 Beta
</div>

<div class="desc">
برای ادامه رمز عبور پنل مدیریت را وارد کنید.
</div>

<form
method="post"
action="/login"
>

<label>
رمز عبور
</label>

<input
type="password"
name="password"
autocomplete="current-password"
autofocus
placeholder="رمز عبور"
>

<button type="submit">
ورود به پنل
</button>

</form>

<a
href="https://t.me/Pixonal"
target="_blank"
class="support"
>
پشتیبانی @Pixonal
</a>

</div>

</body>
</html>
"""


def login_error_html(
    message: str,
):
    safe_message = escape_html(
        message
    )

    return LOGIN_HTML.replace(
        "</form>",
        (
            f"""
            <div class="error">
                {safe_message}
            </div>
            </form>
            """
        ),
    )


@app.get(
    "/login",
    response_class=HTMLResponse,
)
async def login_page(
    request: Request,
):

    if await is_valid_session(
        request.cookies.get(
            SESSION_COOKIE
        )
    ):
        return RedirectResponse(
            "/dashboard"
        )

    return HTMLResponse(
        LOGIN_HTML
    )


@app.post("/login")
async def login_form(
    request: Request,
):

    try:

        content_type = (
            request.headers
            .get(
                "content-type",
                "",
            )
            .lower()
        )

        if "application/json" in content_type:

            body = await request.json()

            password = str(
                body.get(
                    "password",
                    "",
                )
            ).strip()

        else:

            raw = await request.body()

            parsed = parse_qs(
                raw.decode(
                    "utf-8",
                    errors="ignore",
                )
            )

            password = (
                parsed.get(
                    "password",
                    [""],
                )[0]
                .strip()
            )

    except Exception as exc:

        logger.exception(
            "Login parser error: %s",
            exc,
        )

        return HTMLResponse(
            login_error_html(
                "خطا در پردازش اطلاعات ورود."
            ),
            status_code=400,
        )

    ip = client_ip(request)

    blocked, retry_after = login_is_blocked(ip)
    if blocked:
        minutes = max(1, (retry_after + 59) // 60)
        return HTMLResponse(
            login_error_html(
                f"به دلیل تلاش‌های ناموفق متعدد، ورود موقتاً مسدود شده است. حدود {minutes} دقیقه دیگر دوباره تلاش کنید."
            ),
            status_code=429,
            headers={"Retry-After": str(retry_after)},
        )

    if not password:
        register_login_failure(ip)
        return HTMLResponse(
            login_error_html(
                "رمز عبور را وارد کنید."
            ),
            status_code=400,
        )

    if (
        hash_password(password)
        != AUTH["password_hash"]
    ):

        locked, value = register_login_failure(ip)
        if locked:
            return HTMLResponse(
                login_error_html(
                    "تعداد تلاش‌های ناموفق بیش از حد مجاز بود. این IP برای ۱۵ دقیقه مسدود شد."
                ),
                status_code=429,
                headers={"Retry-After": str(LOGIN_LOCKOUT_SECONDS)},
            )

        remaining = value
        log_activity(
            "auth",
            (
                f"تلاش ورود ناموفق از {ip}؛ "
                f"{remaining} تلاش باقی مانده"
            ),
            "err",
        )

        return HTMLResponse(
            login_error_html(
                f"رمز عبور اشتباه است. {remaining} تلاش دیگر باقی مانده است."
            ),
            status_code=401,
        )

    clear_login_failures(ip)

    token = await create_session()

    response = RedirectResponse(
        "/dashboard?login=1",
        status_code=303,
    )

    set_auth_cookie(
        response,
        request,
        token,
    )

    log_activity(
        "auth",
        (
            f"ورود موفق به پنل "
            f"از {client_ip(request)}"
        ),
        "ok",
    )

    return response


@app.post("/api/login")
async def api_login(
    request: Request,
):

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="JSON نامعتبر است",
        )

    password = str(
        body.get(
            "password",
            "",
        )
    ).strip()

    ip = client_ip(request)

    blocked, retry_after = login_is_blocked(ip)
    if blocked:
        raise HTTPException(
            status_code=429,
            detail=f"ورود موقتاً مسدود است. حدود {max(1, (retry_after + 59) // 60)} دقیقه دیگر تلاش کنید.",
            headers={"Retry-After": str(retry_after)},
        )

    if not password:
        register_login_failure(ip)
        raise HTTPException(
            status_code=400,
            detail="رمز عبور را وارد کنید",
        )

    if (
        hash_password(password)
        != AUTH["password_hash"]
    ):

        locked, value = register_login_failure(ip)
        if locked:
            raise HTTPException(
                status_code=429,
                detail="تعداد تلاش‌های ناموفق بیش از حد مجاز بود. این IP برای ۱۵ دقیقه مسدود شد.",
                headers={"Retry-After": str(LOGIN_LOCKOUT_SECONDS)},
            )

        log_activity(
            "auth",
            (
                f"تلاش ورود ناموفق از {ip}؛ "
                f"{value} تلاش باقی مانده"
            ),
            "err",
        )

        raise HTTPException(
            status_code=401,
            detail=f"رمز عبور اشتباه است؛ {value} تلاش دیگر باقی مانده است",
        )

    clear_login_failures(ip)

    token = await create_session()

    response = JSONResponse(
        {
            "ok": True,
            "authenticated": True,
        }
    )

    set_auth_cookie(
        response,
        request,
        token,
    )

    return response


# ============================================================
# LOGOUT
# ============================================================

@app.get("/logout")
async def logout_page(
    request: Request,
):

    await destroy_session(
        request.cookies.get(
            SESSION_COOKIE
        )
    )

    response = RedirectResponse(
        "/login"
    )

    response.delete_cookie(
        SESSION_COOKIE,
        path="/",
    )

    return response


@app.post("/api/logout")
async def api_logout(
    request: Request,
):

    await destroy_session(
        request.cookies.get(
            SESSION_COOKIE
        )
    )

    response = JSONResponse(
        {
            "ok": True
        }
    )

    response.delete_cookie(
        SESSION_COOKIE,
        path="/",
    )

    return response


@app.get("/api/me")
async def api_me(
    request: Request,
):

    return {
        "authenticated":
            await is_valid_session(
                request.cookies.get(
                    SESSION_COOKIE
                )
            )
    }


# ============================================================
# CHANGE PASSWORD
# ============================================================

@app.post("/api/change-password")
async def api_change_password(
    request: Request,
    token=Depends(require_auth),
):

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="اطلاعات نامعتبر است",
        )

    current_password = str(
        body.get(
            "current_password",
            "",
        )
    )

    if (
        hash_password(current_password)
        != AUTH["password_hash"]
    ):
        raise HTTPException(
            status_code=400,
            detail="رمز فعلی اشتباه است",
        )

    new_password = str(
        body.get(
            "new_password",
            "",
        )
    )

    repeat_password = str(
        body.get(
            "repeat_password",
            "",
        )
    )

    if len(new_password) < 6:
        raise HTTPException(
            status_code=400,
            detail="رمز جدید باید حداقل ۶ کاراکتر باشد",
        )

    if new_password != repeat_password:
        raise HTTPException(
            status_code=400,
            detail="تکرار رمز عبور یکسان نیست",
        )

    AUTH[
        "password_hash"
    ] = hash_password(
        new_password
    )

    async with SESSIONS_LOCK:

        SESSIONS.clear()

        SESSIONS[token] = (
            time.time()
            + SESSION_TTL
        )

    await save_state()

    log_activity(
        "auth",
        "رمز عبور پنل تغییر کرد",
        "ok",
    )

    return {
        "ok": True
    }


# ============================================================
# CREATE LINK
# ============================================================

@app.post("/api/links")
async def create_link_api(
    request: Request,
    _=Depends(require_auth),
):

    try:
        body = await request.json()

        if not isinstance(body, dict):
            raise ValueError(
                "body is not object"
            )

    except Exception as exc:

        logger.exception(
            "Create link JSON error: %s",
            exc,
        )

        raise HTTPException(
            status_code=400,
            detail="اطلاعات ارسال‌شده معتبر نیست.",
        )

    limit_value = safe_float(
        body.get(
            "limit_value",
            0,
        )
    )

    limit_unit = str(
        body.get(
            "limit_unit",
            "GB",
        )
        or "GB"
    ).upper()

    limit_bytes = (
        0
        if limit_value <= 0
        else parse_size_to_bytes(
            limit_value,
            limit_unit,
        )
    )

    expires_days = safe_int(
        body.get(
            "expires_days",
            0,
        ),
        minimum=0,
    )

    expires_at = (
        (
            datetime.now()
            + timedelta(
                days=expires_days
            )
        ).isoformat()
        if expires_days > 0
        else None
    )

    port = safe_int(
        body.get(
            "port",
            DEFAULT_PORT,
        ),
        default=DEFAULT_PORT,
        minimum=MIN_PORT,
        maximum=MAX_PORT,
    )

    ip_limit = safe_int(
        body.get(
            "ip_limit",
            0,
        ),
        minimum=0,
    )

    speed_value = safe_float(
        body.get(
            "speed_limit_value",
            0,
        )
    )

    speed_unit = str(
        body.get(
            "speed_limit_unit",
            "MBIT",
        )
        or "MBIT"
    ).upper()

    speed_bytes = (
        0
        if speed_value <= 0
        else parse_speed_to_bytes(
            speed_value,
            speed_unit,
        )
    )

    connection_limit = safe_int(
        body.get(
            "connection_limit",
            0,
        ),
        minimum=0,
    )

    protocol = str(
        body.get(
            "protocol",
            DEFAULT_PROTOCOL,
        )
        or DEFAULT_PROTOCOL
    ).strip()

    if protocol not in PROTOCOLS:
        protocol = DEFAULT_PROTOCOL

    fingerprint = str(
        body.get(
            "fingerprint",
            DEFAULT_FINGERPRINT,
        )
        or DEFAULT_FINGERPRINT
    ).strip().lower()

    if fingerprint not in FINGERPRINTS:
        fingerprint = DEFAULT_FINGERPRINT

    fragment = str(
        body.get(
            "fragment",
            "off",
        )
        or "off"
    ).strip().lower()

    allowed_fragments = {
        "off",
        "safe",
        "balanced",
        "aggressive",
    }

    if fragment not in allowed_fragments:
        fragment = "off"

    uid, link = await make_link(
        label=body.get(
            "label",
            auto_config_name(),
        ),
        limit_bytes=limit_bytes,
        expires_at=expires_at,
        note=body.get(
            "note",
            "",
        ),
        sub_id=body.get(
            "sub_id"
        ),
        protocol=protocol,
        fingerprint=fingerprint,
        alpn=body.get(
            "alpn",
            DEFAULT_ALPN_BY_PROTOCOL.get(
                protocol,
                "http/1.1",
            ),
        ),
        port=port,
        ip_limit=ip_limit,
        speed_limit_bytes=speed_bytes,
        connection_limit=connection_limit,
        fragment=fragment,
    )

    host = get_host(request)

    result = {
        **get_link_info(
            link,
            uid,
            host,
        ),
        "ok": True,
    }

    return result


# ============================================================
# AUTO CREATE
# ============================================================

@app.post("/api/links/auto")
async def create_auto_link(
    request: Request,
    _=Depends(require_auth),
):

    try:

        host = get_host(request)

        uid, link = await make_link(
            label=auto_config_name(),

            # Unlimited
            limit_bytes=0,
            expires_at=None,
            ip_limit=0,
            speed_limit_bytes=0,
            connection_limit=0,

            note=(
                "Auto generated by "
                "PXpanel"
            ),

            # IMPORTANT:
            # Keep working protocol.
            protocol="vless-ws",

            fingerprint="chrome",

            alpn="http/1.1",

            port=443,

            fragment="off",
        )

        result = {
            **get_link_info(
                link,
                uid,
                host,
            ),
            "ok": True,
        }

        log_activity(
            "link",
            (
                f"کانفیگ خودکار "
                f"«{link['label']}» ساخته شد"
            ),
            "ok",
        )

        return result

    except Exception as exc:

        logger.exception(
            "Auto config creation failed"
        )

        stats["total_errors"] += 1

        error_logs.append(
            {
                "error":
                    str(exc),

                "path":
                    "/api/links/auto",

                "time":
                    datetime.now().isoformat(),
            }
        )

        raise HTTPException(
            status_code=500,
            detail=(
                "خطا در ساخت کانفیگ: "
                f"{exc}"
            ),
        )


# ============================================================
# LIST LINKS
# ============================================================

@app.get("/api/links")
async def list_links(
    request: Request,
    _=Depends(require_auth),
):

    host = get_host(request)

    async with LINKS_LOCK:
        snapshot = dict(LINKS)

    result = []

    for uid, link in snapshot.items():

        info = get_link_info(
            link,
            uid,
            host,
        )

        result.append(
            {
                **info,

                "created_at":
                    link.get(
                        "created_at"
                    ),

                "expired":
                    is_link_expired(
                        link
                    ),

                "sub_url":
                    f"https://{host}/sub/{uid}",

                "info_url":
                    f"https://{host}/info/{uid}",

                "connected_ips":
                    len(
                        unique_ips_for_uuid(
                            uid
                        )
                    ),
            }
        )

    result.sort(
        key=lambda item:
            item.get(
                "created_at",
                "",
            ),
        reverse=True,
    )

    return {
        "links": result
    }


# ============================================================
# LINK INFO API
# ============================================================

@app.get("/api/links/{uid}/info")
async def link_info_api(
    uid: str,
    request: Request,
    _=Depends(require_auth),
):

    async with LINKS_LOCK:

        link = LINKS.get(uid)

        if not link:
            raise HTTPException(
                status_code=404,
                detail="link not found",
            )

        snapshot = dict(link)

    host = get_host(request)

    return {
        "ok": True,
        **get_link_info(
            snapshot,
            uid,
            host,
        ),
    }


# ============================================================
# UPDATE LINK
# ============================================================

@app.patch("/api/links/{uid}")
async def update_link(
    uid: str,
    request: Request,
    _=Depends(require_auth),
):

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="اطلاعات نامعتبر است",
        )

    if not isinstance(body, dict):
        raise HTTPException(
            status_code=400,
            detail="اطلاعات نامعتبر است",
        )

    async with LINKS_LOCK:

        if uid not in LINKS:
            raise HTTPException(
                status_code=404,
                detail="link not found",
            )

        link = LINKS[uid]

        old_sub = link.get(
            "sub_id"
        )

        label = link.get(
            "label",
            uid,
        )

        if "active" in body:
            link["active"] = bool(
                body["active"]
            )

        if "label" in body:

            value = str(
                body["label"]
            ).strip()

            if value:
                link["label"] = value[:60]

        if "note" in body:

            link["note"] = str(
                body.get(
                    "note",
                    "",
                )
            )[:500]

        if "reset_usage" in body:

            if body.get(
                "reset_usage"
            ):
                link[
                    "used_bytes"
                ] = 0

        if "limit_value" in body:

            value = safe_float(
                body.get(
                    "limit_value",
                    0,
                )
            )

            unit = str(
                body.get(
                    "limit_unit",
                    "GB",
                )
                or "GB"
            )

            link[
                "limit_bytes"
            ] = (
                0
                if value <= 0
                else parse_size_to_bytes(
                    value,
                    unit,
                )
            )

        if "expires_days" in body:

            days = safe_int(
                body.get(
                    "expires_days",
                    0,
                ),
                minimum=0,
            )

            link[
                "expires_at"
            ] = (
                (
                    datetime.now()
                    + timedelta(
                        days=days
                    )
                ).isoformat()
                if days > 0
                else None
            )

        if "fingerprint" in body:

            fingerprint = str(
                body.get(
                    "fingerprint",
                    DEFAULT_FINGERPRINT,
                )
            ).strip().lower()

            link[
                "fingerprint"
            ] = (
                fingerprint
                if fingerprint in FINGERPRINTS
                else DEFAULT_FINGERPRINT
            )

        if "alpn" in body:

            link["alpn"] = str(
                body.get(
                    "alpn",
                    "",
                )
            )[:100]

        if "port" in body:

            p = safe_int(
                body.get(
                    "port",
                    DEFAULT_PORT,
                ),
                default=DEFAULT_PORT,
                minimum=MIN_PORT,
                maximum=MAX_PORT,
            )

            link["port"] = p

        if "ip_limit" in body:

            link["ip_limit"] = safe_int(
                body.get(
                    "ip_limit",
                    0,
                ),
                minimum=0,
            )

        if "connection_limit" in body:

            link[
                "connection_limit"
            ] = safe_int(
                body.get(
                    "connection_limit",
                    0,
                ),
                minimum=0,
            )

        if "speed_limit_value" in body:

            speed_value = safe_float(
                body.get(
                    "speed_limit_value",
                    0,
                )
            )

            speed_unit = str(
                body.get(
                    "speed_limit_unit",
                    "MBIT",
                )
                or "MBIT"
            )

            link[
                "speed_limit_bytes"
            ] = (
                0
                if speed_value <= 0
                else parse_speed_to_bytes(
                    speed_value,
                    speed_unit,
                )
            )

        if "protocol" in body:

            protocol = str(
                body.get(
                    "protocol",
                    DEFAULT_PROTOCOL,
                )
            ).strip()

            link["protocol"] = (
                protocol
                if protocol in PROTOCOLS
                else DEFAULT_PROTOCOL
            )

        if "fragment" in body:

            fragment = str(
                body.get(
                    "fragment",
                    "off",
                )
                or "off"
            ).strip().lower()

            if fragment not in {
                "off",
                "safe",
                "balanced",
                "aggressive",
            }:
                fragment = "off"

            link["fragment"] = fragment

        if "sub_id" in body:

            link[
                "sub_id"
            ] = (
                body.get(
                    "sub_id"
                )
                or None
            )

        new_sub = body.get(
            "sub_id",
            "UNCHANGED",
        )

    if new_sub != "UNCHANGED":

        async with SUBS_LOCK:

            if (
                old_sub
                and old_sub in SUBS
            ):

                ids = SUBS[
                    old_sub
                ].get(
                    "link_ids",
                    [],
                )

                if uid in ids:
                    ids.remove(uid)

            if (
                new_sub
                and new_sub in SUBS
            ):

                ids = SUBS[
                    new_sub
                ].setdefault(
                    "link_ids",
                    [],
                )

                if uid not in ids:
                    ids.append(uid)

    await save_state()

    log_activity(
        "link",
        (
            f"کانفیگ "
            f"«{label}» "
            f"ویرایش شد"
        ),
        "info",
    )

    return {
        "ok": True
    }


# ============================================================
# RESET USAGE
# ============================================================

@app.post(
    "/api/links/{uid}/reset-usage"
)
async def reset_link_usage(
    uid: str,
    _=Depends(require_auth),
):

    async with LINKS_LOCK:

        link = LINKS.get(uid)

        if not link:
            raise HTTPException(
                status_code=404,
                detail="link not found",
            )

        link["used_bytes"] = 0

        label = link.get(
            "label",
            uid,
        )

    await save_state()

    log_activity(
        "link",
        (
            f"مصرف کانفیگ "
            f"«{label}» ریست شد"
        ),
        "info",
    )

    return {
        "ok": True,
        "uuid": uid,
        "used_bytes": 0,
    }


# ============================================================
# LINK ACTION
# ============================================================

@app.post(
    "/api/links/{uid}/action"
)
async def link_action(
    uid: str,
    request: Request,
    _=Depends(require_auth),
):

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="JSON نامعتبر است",
        )

    action = str(
        body.get(
            "action",
            "",
        )
    ).strip().lower()

    if action == "reset":

        await reset_link_usage(
            uid,
            _
        )

        return {
            "ok": True,
            "action": "reset",
        }

    if action == "enable":

        result = await set_link_active(
            uid,
            True,
        )

        if result is None:
            raise HTTPException(
                status_code=404,
                detail="link not found",
            )

        return {
            "ok": True,
            "action": "enable",
        }

    if action == "disable":

        result = await set_link_active(
            uid,
            False,
        )

        if result is None:
            raise HTTPException(
                status_code=404,
                detail="link not found",
            )

        return {
            "ok": True,
            "action": "disable",
        }

    raise HTTPException(
        status_code=400,
        detail="unknown action",
    )


# ============================================================
# DELETE LINK
# ============================================================

@app.delete("/api/links/{uid}")
async def delete_link(
    uid: str,
    _=Depends(require_auth),
):

    label = await remove_link(uid)

    if label is None:
        raise HTTPException(
            status_code=404,
            detail="link not found",
        )

    return {
        "ok": True,
        "deleted": uid,
    }




def subscription_metadata_headers(used_bytes: int, limit_bytes: int, expires_at, host: str, info_url: str, title: str):
    """Standard subscription headers understood by v2rayNG/v2rayN/Hiddify and similar clients."""
    used_bytes = max(0, int(used_bytes or 0))
    limit_bytes = max(0, int(limit_bytes or 0))

    expire_unix = 0
    if expires_at:
        try:
            dt = datetime.fromisoformat(str(expires_at))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=IRAN_TZ) if IRAN_TZ else dt
            expire_unix = max(0, int(dt.timestamp()))
        except Exception:
            expire_unix = 0

    userinfo = f"upload=0; download={used_bytes}; total={limit_bytes}; expire={expire_unix}"

    return {
        "profile-title": quote(title, safe=""),
        "profile-web-page-url": info_url,
        "support-url": SUPPORT_URL,
        "profile-update-interval": "12",
        "subscription-userinfo": userinfo,
        "content-disposition": 'inline; filename="subscription.txt"',
    }

# ============================================================
# SINGLE SUB
# ============================================================

@app.get("/sub/{uuid}")
async def subscription_single(
    uuid: str,
    request: Request,
):

    async with LINKS_LOCK:
        link = LINKS.get(uuid)

    if not is_link_allowed(link):
        raise HTTPException(
            status_code=404,
            detail="not found or inactive",
        )

    host = get_host(request)

    vless = vless_link_for_link(
        link,
        uuid,
        host,
    )

    content = (
        base64
        .b64encode(
            vless.encode()
        )
        .decode()
    )

    used = int(link.get("used_bytes", 0) or 0)
    limit = int(link.get("limit_bytes", 0) or 0)
    volume_text = f"{fmt_bytes(used)}/{fmt_bytes(limit)}" if limit > 0 else f"{fmt_bytes(used)}/∞"
    expiry_text = str(link.get("expires_at") or "∞")
    profile_title = f"0.0.0.0 | {volume_text} | {expiry_text} | {link.get('label','PXpanel')} | کانال تلگرام: logic_sec"
    headers = subscription_metadata_headers(
        used,
        limit,
        link.get("expires_at"),
        host,
        f"https://{host}/info/{uuid}",
        profile_title,
    )

    return Response(
        content=content,
        media_type="text/plain; charset=utf-8",
        headers=headers,
    )

# ============================================================
# SUB ALL
# ============================================================

@app.get("/sub-all")
async def subscription_all(
    request: Request,
    _=Depends(require_auth),
):

    host = get_host(request)

    async with LINKS_LOCK:

        lines = [
            vless_link_for_link(
                link,
                uid,
                host,
            )

            for uid, link
            in LINKS.items()

            if is_link_allowed(link)
        ]

    content = (
        base64
        .b64encode(
            "\n".join(
                lines
            ).encode()
        )
        .decode()
    )

    return Response(
        content=content,
        media_type="text/plain",
    )


# ============================================================
# INFO PAGE
# ============================================================

@app.get(
    "/info/{uid}",
    response_class=HTMLResponse,
)
async def info_page(
    uid: str,
    request: Request,
):
    async with LINKS_LOCK:
        link = LINKS.get(uid)
        if not link:
            return HTMLResponse("<html lang=\"fa\" dir=\"rtl\"><body style=\"margin:0;background:#07070a;color:#fff;font-family:sans-serif;padding:40px\"><h2>کانفیگ پیدا نشد</h2></body></html>", status_code=404)
        snapshot = dict(link)

    host = get_host(request)
    vless_url = vless_link_for_link(snapshot, uid, host)
    sub_url = f"https://{host}/sub/{uid}"
    used = int(snapshot.get("used_bytes", 0) or 0)
    limit = int(snapshot.get("limit_bytes", 0) or 0)
    if limit > 0:
        usage_percent = max(0, min(100, round((used / limit) * 100, 1)))
        usage_value = f"{fmt_bytes(used)} / {fmt_bytes(limit)}"
        remaining_value = fmt_bytes(max(0, limit - used))
    else:
        usage_percent = 0
        usage_value = f"{fmt_bytes(used)} / نامحدود"
        remaining_value = "نامحدود"

    expires_at = snapshot.get("expires_at")
    if expires_at:
        try:
            expiry_dt = datetime.fromisoformat(str(expires_at))
            now_dt = datetime.now(expiry_dt.tzinfo) if expiry_dt.tzinfo else datetime.now()
            seconds = int((expiry_dt - now_dt).total_seconds())
            if seconds <= 0:
                expiry_remaining = "منقضی شده"
            else:
                days, rem = divmod(seconds, 86400)
                hours, rem = divmod(rem, 3600)
                minutes, _ = divmod(rem, 60)
                expiry_remaining = f"{days} روز و {hours} ساعت" if days else (f"{hours} ساعت و {minutes} دقیقه" if hours else f"{minutes} دقیقه")
        except Exception:
            expiry_remaining = "نامشخص"
        expiry_display = str(expires_at)
    else:
        expiry_remaining = "نامحدود"
        expiry_display = "نامحدود"

    status_text = "فعال" if is_link_allowed(snapshot) else "غیرفعال"
    status_class = "good" if status_text == "فعال" else "bad"
    ip_limit = "نامحدود" if not snapshot.get("ip_limit",0) else str(snapshot.get("ip_limit"))
    connection_limit = "نامحدود" if not snapshot.get("connection_limit",0) else str(snapshot.get("connection_limit"))
    speed_limit = "نامحدود" if not snapshot.get("speed_limit_bytes",0) else fmt_bytes(snapshot.get("speed_limit_bytes",0)) + "/s"

    info_html = f"""<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>{escape_html(snapshot.get("label","PXpanel"))} | INFO</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
<style>
:root{{--bg:#07080d;--panel:rgba(17,19,28,.72);--line:rgba(255,255,255,.08);--muted:rgba(255,255,255,.42);--text:#f6f7fb;--green:#34d399;--blue:#60a5fa;--orange:#f59e0b;--red:#fb7185;--purple:#a78bfa}}
*{{box-sizing:border-box}}
html,body{{margin:0;min-height:100%;background:var(--bg)}}
body{{font-family:"Vazirmatn",sans-serif;color:var(--text);padding:24px;background:radial-gradient(circle at 15% 0%,rgba(96,165,250,.16),transparent 30%),radial-gradient(circle at 95% 30%,rgba(167,139,250,.13),transparent 28%),radial-gradient(circle at 80% 100%,rgba(52,211,153,.08),transparent 30%),#07080d}}
.page{{width:min(920px,100%);margin:auto}}
.shell{{position:relative;overflow:hidden;border:1px solid var(--line);background:linear-gradient(145deg,rgba(255,255,255,.05),rgba(255,255,255,.02));backdrop-filter:blur(28px);border-radius:30px;box-shadow:0 35px 100px rgba(0,0,0,.38)}}
.shell:before{{content:"";position:absolute;inset:0;pointer-events:none;background:linear-gradient(120deg,rgba(255,255,255,.04),transparent 35%,rgba(255,255,255,.02))}}
.hero{{position:relative;padding:25px 25px 20px;border-bottom:1px solid rgba(255,255,255,.06)}}
.hero-row{{display:flex;align-items:center;justify-content:space-between;gap:16px}}
.brand{{display:flex;align-items:center;gap:13px}}
.brand-icon{{width:46px;height:46px;display:grid;place-items:center;border:1px solid rgba(96,165,250,.2);background:linear-gradient(145deg,rgba(96,165,250,.14),rgba(167,139,250,.08));border-radius:15px;color:#93c5fd;font-weight:900;font-size:16px}}
.hero h1{{margin:0;font-size:21px;font-weight:900;letter-spacing:-.35px}}
.hero-meta{{margin-top:4px;color:var(--muted);font-size:9px;word-break:break-all}}
.status{{display:inline-flex;align-items:center;gap:7px;padding:8px 11px;border-radius:12px;font-size:9px;font-weight:800;white-space:nowrap}}
.status i{{width:7px;height:7px;border-radius:50%;background:currentColor;box-shadow:0 0 14px currentColor}}
.status.good{{color:#6ee7b7;border:1px solid rgba(52,211,153,.18);background:rgba(52,211,153,.08)}}
.status.bad{{color:#fda4af;border:1px solid rgba(251,113,133,.18);background:rgba(251,113,133,.08)}}
.notice{{margin-top:18px;display:flex;gap:11px;align-items:flex-start;padding:13px 14px;border:1px solid rgba(167,139,250,.17);background:linear-gradient(120deg,rgba(167,139,250,.10),rgba(96,165,250,.04));border-radius:16px;color:rgba(255,255,255,.62);font-size:9px;line-height:2}}
.notice-icon{{width:25px;height:25px;flex:0 0 25px;display:grid;place-items:center;border-radius:9px;background:rgba(167,139,250,.13);border:1px solid rgba(167,139,250,.18);color:#c4b5fd;font-size:12px}}
.notice strong{{color:#ddd6fe}}
.dashboard{{display:grid;grid-template-columns:1.35fr .65fr;gap:12px;padding:16px}}
.usage-card,.side-card{{border:1px solid var(--line);background:rgba(255,255,255,.025);border-radius:20px}}
.usage-card{{padding:18px}}
.section-kicker{{font-size:8px;color:rgba(255,255,255,.30);font-weight:800;letter-spacing:.7px;text-transform:uppercase}}
.section-title{{margin-top:4px;font-size:13px;font-weight:900}}
.usage-line{{display:flex;align-items:end;justify-content:space-between;gap:12px;margin-top:16px}}
.usage-number{{font-size:22px;font-weight:900;letter-spacing:-.5px}}
.usage-number span{{font-size:10px;color:var(--muted);font-weight:600}}
.usage-percent{{font-size:12px;font-weight:900;color:#86efac}}
.track{{height:12px;margin-top:12px;border-radius:999px;background:rgba(255,255,255,.055);overflow:hidden;border:1px solid rgba(255,255,255,.035)}}
.track span{{display:block;height:100%;width:{usage_percent}%;border-radius:inherit;background:linear-gradient(90deg,#34d399,#f59e0b);box-shadow:0 0 20px rgba(52,211,153,.18)}}
.usage-bottom{{display:flex;justify-content:space-between;gap:10px;margin-top:9px;color:var(--muted);font-size:8px}}
.side-card{{padding:14px}}
.side-row{{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:10px 0;border-bottom:1px solid rgba(255,255,255,.05)}}
.side-row:last-child{{border-bottom:0;padding-bottom:0}}
.side-label{{font-size:8px;color:var(--muted)}}
.side-value{{font-size:9px;font-weight:800}}
.stats{{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;padding:0 16px 16px}}
.metric{{position:relative;overflow:hidden;padding:14px 14px 13px;border-radius:18px;border:1px solid rgba(255,255,255,.07);background:rgba(255,255,255,.025)}}
.metric:before{{content:"";position:absolute;inset:0;background:linear-gradient(145deg,rgba(255,255,255,.025),transparent 55%)}}
.metric .dot{{width:8px;height:8px;border-radius:50%;margin-bottom:9px;background:var(--c);box-shadow:0 0 18px color-mix(in srgb,var(--c) 45%,transparent)}}
.metric-label{{color:var(--muted);font-size:8px}}
.metric-value{{margin-top:5px;font-size:12px;font-weight:900;color:var(--c);word-break:break-word}}
.metric.green{{--c:#34d399}} .metric.orange{{--c:#f59e0b}} .metric.blue{{--c:#60a5fa}} .metric.purple{{--c:#a78bfa}}
.content{{padding:0 16px 18px}}
.section{{margin-top:10px;padding:16px;border:1px solid rgba(255,255,255,.07);background:rgba(255,255,255,.022);border-radius:20px}}
.section-head{{display:flex;align-items:end;justify-content:space-between;gap:10px}}
.section-head .section-title{{margin:0}}
.section-sub{{color:var(--muted);font-size:8px}}
.info-grid{{display:grid;grid-template-columns:repeat(2,1fr);gap:9px;margin-top:12px}}
.info-item{{padding:12px;border-radius:15px;border:1px solid rgba(255,255,255,.06);background:rgba(0,0,0,.13)}}
.info-label{{font-size:8px;color:var(--muted)}}
.info-value{{margin-top:5px;font-size:9px;font-weight:700;color:rgba(255,255,255,.86);word-break:break-word}}
.code{{direction:ltr;text-align:left;font-family:Consolas,monospace;font-size:8.5px;color:#c4b5fd;font-weight:500}}
.link-card{{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px;border-radius:15px;border:1px solid rgba(255,255,255,.06);background:rgba(0,0,0,.13);margin-top:9px}}
.link-card:first-child{{margin-top:12px}}
.link-main{{min-width:0}}
.link-name{{font-size:8px;color:var(--muted);font-weight:800}}
.link-url{{margin-top:4px;direction:ltr;text-align:left;font-family:Consolas,monospace;font-size:8px;color:#c4b5fd;word-break:break-all}}
.copy-hint{{flex:0 0 auto;font-size:8px;color:rgba(255,255,255,.28)}}
.downloads{{display:grid;grid-template-columns:repeat(3,1fr);gap:9px;margin-top:12px}}
.download{{display:flex;align-items:center;gap:10px;min-height:68px;padding:12px;text-decoration:none;color:#fff;border:1px solid rgba(255,255,255,.07);background:linear-gradient(145deg,rgba(255,255,255,.035),rgba(255,255,255,.015));border-radius:16px;transition:transform .2s ease,border-color .2s ease,background .2s ease}}
.download:hover{{transform:translateY(-2px);border-color:rgba(96,165,250,.28);background:linear-gradient(145deg,rgba(96,165,250,.07),rgba(255,255,255,.02))}}
.app-icon{{width:31px;height:31px;flex:0 0 31px;display:grid;place-items:center;border-radius:10px;background:rgba(96,165,250,.11);border:1px solid rgba(96,165,250,.14);color:#93c5fd;font-size:11px;font-weight:900}}
.download strong{{display:block;font-size:9px}}
.download span{{display:block;margin-top:2px;color:var(--muted);font-size:7.5px}}
.channel{{margin-top:15px;padding:12px 14px;text-align:center;border:1px solid rgba(52,211,153,.12);background:rgba(52,211,153,.045);border-radius:14px;color:var(--muted);font-size:8px}}
.channel b{{color:#6ee7b7}}
@media(max-width:760px){{body{{padding:12px}}.dashboard{{grid-template-columns:1fr}}.stats{{grid-template-columns:repeat(2,1fr)}}.downloads{{grid-template-columns:1fr}}.hero-row{{align-items:flex-start;flex-direction:column}}}}
</style>
</head>
<body>
<div class="page"><div class="shell">
<section class="hero">
<div class="hero-row"><div class="brand"><div class="brand-icon">PX</div><div><h1>{escape_html(snapshot.get("label","PXpanel"))}</h1><div class="hero-meta">0.0.0.0 · UUID: {escape_html(uid)} · PXpanel {APP_VERSION}</div></div></div><div class="status {status_class}"><i></i>{status_text}</div></div>
<div class="notice"><div class="notice-icon">!</div><div><strong>اطلاعیه اتصال</strong><br>لینک SUB را در برنامه‌ای که استفاده می‌کنید به‌عنوان Subscription وارد کنید. برای اتصال مستقیم نیز می‌توانید VLESS را Import کنید. <strong>کانال تلگرام: logic_sec</strong></div></div>
</section>

<section class="dashboard">
<div class="usage-card"><div class="section-kicker">Traffic Overview</div><div class="section-title">مصرف سرویس</div><div class="usage-line"><div class="usage-number">{escape_html(fmt_bytes(used))} <span>/ {escape_html(fmt_bytes(limit)) if limit > 0 else '∞'}</span></div><div class="usage-percent">{usage_percent}%</div></div><div class="track"><span></span></div><div class="usage-bottom"><span>باقی‌مانده: {escape_html(remaining_value)}</span><span>زمان: {escape_html(expiry_remaining)}</span></div></div>
<div class="side-card"><div class="section-kicker">Service</div><div class="side-row"><span class="side-label">انقضا</span><span class="side-value">{escape_html(expiry_display)}</span></div><div class="side-row"><span class="side-label">IP Limit</span><span class="side-value">{escape_html(ip_limit)}</span></div><div class="side-row"><span class="side-label">Connection</span><span class="side-value">{escape_html(connection_limit)}</span></div><div class="side-row"><span class="side-label">Speed</span><span class="side-value">{escape_html(speed_limit)}</span></div></div>
</section>

<section class="stats">
<div class="metric green"><div class="dot"></div><div class="metric-label">مصرف فعلی</div><div class="metric-value">{escape_html(fmt_bytes(used))}</div></div>
<div class="metric orange"><div class="dot"></div><div class="metric-label">باقی‌مانده</div><div class="metric-value">{escape_html(remaining_value)}</div></div>
<div class="metric blue"><div class="dot"></div><div class="metric-label">اتصالات فعال</div><div class="metric-value">{len(unique_ips_for_uuid(uid))}</div></div>
<div class="metric purple"><div class="dot"></div><div class="metric-label">زمان باقی‌مانده</div><div class="metric-value">{escape_html(expiry_remaining)}</div></div>
</section>

<div class="content">
<section class="section"><div class="section-head"><div class="section-title">جزئیات فنی</div><div class="section-sub">Configuration Details</div></div><div class="info-grid"><div class="info-item"><div class="info-label">Protocol</div><div class="info-value code">{escape_html(snapshot.get("protocol","vless-ws"))}</div></div><div class="info-item"><div class="info-label">Fingerprint</div><div class="info-value code">{escape_html(snapshot.get("fingerprint","chrome"))}</div></div><div class="info-item"><div class="info-label">IP Limit</div><div class="info-value">{escape_html(ip_limit)}</div></div><div class="info-item"><div class="info-label">Connection Limit</div><div class="info-value">{escape_html(connection_limit)}</div></div><div class="info-item"><div class="info-label">Speed Limit</div><div class="info-value">{escape_html(speed_limit)}</div></div><div class="info-item"><div class="info-label">تاریخ انقضا</div><div class="info-value">{escape_html(expiry_display)}</div></div></div></section>

<section class="section"><div class="section-head"><div class="section-title">لینک‌های سرویس</div><div class="section-sub">Copy / Import</div></div><div class="link-card"><div class="link-main"><div class="link-name">VLESS</div><div class="link-url">{escape_html(vless_url)}</div></div><div class="copy-hint">VLESS</div></div><div class="link-card"><div class="link-main"><div class="link-name">SUBSCRIPTION</div><div class="link-url">{escape_html(sub_url)}</div></div><div class="copy-hint">SUB</div></div></section>

<section class="section"><div class="section-head"><div class="section-title">دانلود برنامه‌ها</div><div class="section-sub">Official Releases</div></div><div class="downloads"><a class="download" href="https://github.com/2dust/v2rayNG/releases/latest" target="_blank" rel="noopener noreferrer"><div class="app-icon">NG</div><div><strong>v2rayNG</strong><span>Android</span></div></a><a class="download" href="https://github.com/2dust/v2rayN/releases/latest" target="_blank" rel="noopener noreferrer"><div class="app-icon">N</div><div><strong>v2rayN</strong><span>Windows / macOS / Linux</span></div></a><a class="download" href="https://github.com/hiddify/hiddify-app/releases/latest" target="_blank" rel="noopener noreferrer"><div class="app-icon">H</div><div><strong>Hiddify</strong><span>Android / Windows / macOS / Linux</span></div></a></div></section>

<div class="channel">پشتیبانی و اطلاعیه‌ها · <b>کانال تلگرام: logic_sec</b></div>
</div></div></div>
</body></html>"""
    return HTMLResponse(info_html)


# ============================================================
# SUB GROUP API
# ============================================================

@app.post("/api/subs")
async def create_sub_api(
    request: Request,
    _=Depends(require_auth),
):

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="JSON نامعتبر است",
        )

    sub_id, sub = await create_sub_group(
        name=body.get(
            "name",
            "گروه جدید",
        ),
        desc=body.get(
            "desc",
            "",
        ),
        password=body.get(
            "password",
            "",
        ),
    )

    host = get_host(request)

    return {
        "sub_id":
            sub_id,

        **sub,

        "password_hash":
            None,

        "public_url":
            (
                f"https://{host}"
                f"/p/{sub['uuid_key']}"
            ),

        "sub_url":
            (
                f"https://{host}"
                f"/sub-group/{sub['uuid_key']}"
            ),
    }


@app.get("/api/subs")
async def list_subs_api(
    request: Request,
    _=Depends(require_auth),
):

    host = get_host(request)

    async with SUBS_LOCK:
        snapshot_subs = dict(SUBS)

    async with LINKS_LOCK:
        snapshot_links = dict(LINKS)

    result = []

    for sid, sub in snapshot_subs.items():

        link_ids = sub.get(
            "link_ids",
            [],
        )

        active_count = sum(
            1
            for lid in link_ids
            if is_link_allowed(
                snapshot_links.get(
                    lid
                )
            )
        )

        total_used = sum(
            snapshot_links[
                lid
            ].get(
                "used_bytes",
                0,
            )

            for lid in link_ids

            if lid in snapshot_links
        )

        result.append(
            {
                "sub_id":
                    sid,

                **sub,

                "password_hash":
                    None,

                "has_password":
                    sub.get(
                        "password_hash"
                    ) is not None,

                "links_count":
                    len(link_ids),

                "active_count":
                    active_count,

                "total_used_bytes":
                    total_used,

                "total_used_fmt":
                    fmt_bytes(
                        total_used
                    ),

                "public_url":
                    (
                        f"https://{host}"
                        f"/p/{sub['uuid_key']}"
                    ),

                "sub_url":
                    (
                        f"https://{host}"
                        f"/sub-group/{sub['uuid_key']}"
                    ),
            }
        )

    result.sort(
        key=lambda item:
            item.get(
                "created_at",
                "",
            ),
        reverse=True,
    )

    return {
        "subs": result
    }


@app.patch("/api/subs/{sub_id}")
async def update_sub_api(
    sub_id: str,
    request: Request,
    _=Depends(require_auth),
):

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="JSON نامعتبر است",
        )

    async with SUBS_LOCK:

        if sub_id not in SUBS:
            raise HTTPException(
                status_code=404,
                detail="sub not found",
            )

        sub = SUBS[sub_id]

        if "name" in body:
            sub["name"] = str(
                body["name"]
            )[:60]

        if "desc" in body:
            sub["desc"] = str(
                body["desc"]
            )[:200]

        if "password" in body:

            password = str(
                body.get(
                    "password",
                    "",
                )
            ).strip()

            sub["password_hash"] = (
                hash_password(password)
                if password
                else None
            )

        if "link_ids" in body:

            sub["link_ids"] = list(
                body["link_ids"]
            )

    await save_state()

    return {
        "ok": True
    }


@app.delete("/api/subs/{sub_id}")
async def delete_sub_api(
    sub_id: str,
    _=Depends(require_auth),
):

    name = await remove_sub_group(
        sub_id
    )

    if name is None:
        raise HTTPException(
            status_code=404,
            detail="sub not found",
        )

    return {
        "ok": True,
        "deleted": sub_id,
    }


@app.post("/api/subs/{sub_id}/links")
async def assign_link_to_sub(
    sub_id: str,
    request: Request,
    _=Depends(require_auth),
):

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(
            status_code=400,
            detail="JSON نامعتبر است",
        )

    link_id = str(
        body.get(
            "link_id",
            "",
        )
    )

    action = str(
        body.get(
            "action",
            "add",
        )
    )

    if action == "add":

        success = await set_link_sub(
            link_id,
            sub_id,
        )

    else:

        success = await set_link_sub(
            link_id,
            None,
        )

    if not success:
        raise HTTPException(
            status_code=404,
            detail="link or sub not found",
        )

    return {
        "ok": True
    }


# ============================================================
# GROUP SUB
# ============================================================

@app.get("/sub-group/{uuid_key}")
async def sub_group_subscription(
    uuid_key: str,
    request: Request,
):

    async with SUBS_LOCK:

        sub = next(
            (
                item
                for item
                in SUBS.values()
                if item.get(
                    "uuid_key"
                ) == uuid_key
            ),
            None,
        )

    if not sub:
        raise HTTPException(
            status_code=404,
            detail="not found",
        )

    if sub.get(
        "password_hash"
    ):

        password = (
            request.query_params.get(
                "pw",
                "",
            )
        )

        if (
            hash_password(password)
            != sub["password_hash"]
        ):

            raise HTTPException(
                status_code=403,
                detail="wrong password",
            )

    host = get_host(request)

    async with LINKS_LOCK:

        lines = []

        for link_id in sub.get(
            "link_ids",
            [],
        ):

            link = LINKS.get(
                link_id
            )

            if (
                link
                and is_link_allowed(
                    link
                )
            ):

                lines.append(
                    vless_link_for_link(
                        link,
                        link_id,
                        host,
                    )
                )

    content = (
        base64
        .b64encode(
            "\n".join(
                lines
            ).encode()
        )
        .decode()
    )

    total_used = 0
    total_limit = 0
    expiries = []
    valid_ids = list(sub.get("link_ids", []))

    async with LINKS_LOCK:
        for link_id in valid_ids:
            link = LINKS.get(link_id)
            if not link or not is_link_allowed(link):
                continue
            total_used += int(link.get("used_bytes", 0) or 0)
            total_limit += int(link.get("limit_bytes", 0) or 0)
            if link.get("expires_at"):
                expiries.append(str(link.get("expires_at")))

    # For a group subscription, expose aggregate usage/expiry in standard headers.
    group_limit = total_limit if total_limit > 0 else 0
    group_expiry = None
    if expiries:
        try:
            group_expiry = min(
                expiries,
                key=lambda x: datetime.fromisoformat(x)
            )
        except Exception:
            group_expiry = expiries[0]

    group_volume_text = (
        f"{fmt_bytes(total_used)}/{fmt_bytes(group_limit)}"
        if group_limit > 0
        else f"{fmt_bytes(total_used)}/∞"
    )
    group_expiry_text = group_expiry or "∞"
    group_title = (
        f"0.0.0.0 | {group_volume_text} | {group_expiry_text} | "
        f"{sub['name']} | کانال تلگرام: logic_sec"
    )
    headers = subscription_metadata_headers(
        total_used,
        group_limit,
        group_expiry,
        host,
        f"https://{host}/public-sub/{uuid_key}",
        group_title,
    )

    return Response(
        content=content,
        media_type="text/plain; charset=utf-8",
        headers=headers,
    )


# ============================================================
# PUBLIC GROUP
# ============================================================

PUBLIC_SUB_HTML = r"""
<!DOCTYPE html>
<html lang="fa" dir="rtl">

<head>
<meta charset="UTF-8">

<meta
name="viewport"
content="width=device-width,initial-scale=1"
>

<title>
PXpanel
</title>

<style>

*{
    box-sizing:border-box;
}

body{
    margin:0;
    min-height:100vh;

    display:flex;
    justify-content:center;
    align-items:center;

    padding:20px;

    font-family:Arial,sans-serif;

    color:#fff;

    background:
        radial-gradient(
            circle at top right,
            rgba(99,102,241,.17),
            transparent 30%
        ),
        #07070a;
}

.card{
    width:100%;
    max-width:560px;

    padding:28px;
    border-radius:25px;

    background:rgba(255,255,255,.045);

    border:
        1px solid
        rgba(255,255,255,.08);

    backdrop-filter:blur(25px);
}

h1{
    margin-top:0;
}

.text{
    color:rgba(255,255,255,.55);
    line-height:2;
    font-size:13px;
}

.url{
    margin-top:20px;
    padding:14px;

    border-radius:13px;

    background:rgba(0,0,0,.22);

    color:#c4b5fd;

    direction:ltr;
    word-break:break-all;

    font-family:Consolas,monospace;
}

.support{
    display:inline-block;
    margin-top:18px;

    color:#a78bfa;
    text-decoration:none;
}

.version{
    color:#a78bfa;
    font-size:11px;
}

</style>
</head>

<body>

<div class="card">

<h1>
PXpanel
</h1>

<div class="version">
12.1.0 Beta
</div>

<div class="text">
اشتراک شما آماده است.
</div>

<div
class="url"
id="subUrl"
></div>

<a
class="support"
href="https://t.me/Pixonal"
target="_blank"
rel="noopener"
>
پشتیبانی @Pixonal
</a>

</div>

<script>

const url =
    location.origin +
    location.pathname.replace(
        "/p/",
        "/sub-group/"
    );

document.getElementById(
    "subUrl"
).textContent = url;

</script>

</body>
</html>
"""


@app.get(
    "/p/{uuid_key}",
    response_class=HTMLResponse,
)
async def public_sub_page(
    uuid_key: str,
):

    async with SUBS_LOCK:

        exists = any(
            item.get(
                "uuid_key"
            ) == uuid_key
            for item in SUBS.values()
        )

    if not exists:

        return HTMLResponse(
            """
            <h2
            style="
            font-family:sans-serif;
            padding:40px;
            "
            >
            گروه پیدا نشد
            </h2>
            """,
            status_code=404,
        )

    return HTMLResponse(
        PUBLIC_SUB_HTML
    )


@app.get("/api/public/sub/{uuid_key}")
async def public_sub_data(
    uuid_key: str,
    request: Request,
):

    async with SUBS_LOCK:

        entry = next(
            (
                (
                    sid,
                    item,
                )

                for sid, item
                in SUBS.items()

                if item.get(
                    "uuid_key"
                ) == uuid_key
            ),
            None,
        )

    if not entry:
        raise HTTPException(
            status_code=404,
            detail="not found",
        )

    _, sub = entry

    has_password = (
        sub.get(
            "password_hash"
        ) is not None
    )

    if has_password:

        password = (
            request
            .query_params
            .get(
                "pw",
                "",
            )
        )

        if (
            hash_password(password)
            != sub[
                "password_hash"
            ]
        ):

            return JSONResponse(
                {
                    "locked": True,
                    "name":
                        sub["name"],
                }
            )

    host = get_host(request)

    async with LINKS_LOCK:
        snapshot = dict(LINKS)

    links_out = []

    active_connections = 0

    for link_id in sub.get(
        "link_ids",
        [],
    ):

        link = snapshot.get(
            link_id
        )

        if not link:
            continue

        allowed = is_link_allowed(
            link
        )

        connection_count = sum(
            1
            for item in connections.values()
            if item.get("uuid") == link_id
        )

        active_connections += (
            connection_count
        )

        links_out.append(
            {
                "uuid":
                    link_id,

                "label":
                    link.get(
                        "label"
                    ),

                "active":
                    allowed,

                "protocol":
                    link.get(
                        "protocol",
                        DEFAULT_PROTOCOL,
                    ),

                "used_bytes":
                    link.get(
                        "used_bytes",
                        0,
                    ),

                "used_fmt":
                    fmt_bytes(
                        link.get(
                            "used_bytes",
                            0,
                        )
                    ),

                "limit_bytes":
                    link.get(
                        "limit_bytes",
                        0,
                    ),

                "limit_fmt":
                    (
                        "∞"
                        if not link.get(
                            "limit_bytes",
                            0,
                        )
                        else fmt_bytes(
                            link[
                                "limit_bytes"
                            ]
                        )
                    ),

                "expires_at":
                    link.get(
                        "expires_at"
                    ),

                "vless_link":
                    vless_link_for_link(
                        link,
                        link_id,
                        host,
                    ),

                "sub_url":
                    (
                        f"https://{host}"
                        f"/sub/{link_id}"
                    ),

                "info_url":
                    (
                        f"https://{host}"
                        f"/info/{link_id}"
                    ),

                "connections":
                    connection_count,

                "ip_limit":
                    link.get(
                        "ip_limit",
                        0,
                    ),

                "speed_limit_bytes":
                    link.get(
                        "speed_limit_bytes",
                        0,
                    ),

                "connection_limit":
                    link.get(
                        "connection_limit",
                        0,
                    ),
            }
        )

    total_used = sum(
        item["used_bytes"]
        for item in links_out
    )

    return {
        "locked": False,

        "name":
            sub["name"],

        "desc":
            sub.get(
                "desc",
                "",
            ),

        "sub_url":
            (
                f"https://{host}"
                f"/sub-group/{uuid_key}"
            ),

        "active_connections":
            active_connections,

        "total_used_fmt":
            fmt_bytes(
                total_used
            ),

        "support":
            SUPPORT_USERNAME,

        "links":
            links_out,
    }


# ============================================================
# STATS
# ============================================================

@app.get("/stats")
async def get_stats(
    _=Depends(require_auth),
):

    async with LINKS_LOCK:
        snapshot = dict(LINKS)

    return {
        "service":
            APP_NAME,

        "version":
            APP_VERSION,

        "active_connections":
            len(connections),

        "total_traffic_mb":
            round(
                stats[
                    "total_bytes"
                ]
                / (
                    1024 ** 2
                ),
                2,
            ),

        "total_traffic_bytes":
            stats[
                "total_bytes"
            ],

        "total_requests":
            stats[
                "total_requests"
            ],

        "total_errors":
            stats[
                "total_errors"
            ],

        "uptime":
            uptime(),

        "timestamp":
            datetime.now().isoformat(),

        "hourly":
            dict(
                hourly_traffic
            ),

        "recent_errors":
            list(
                error_logs
            )[-10:],

        "links_count":
            len(snapshot),

        "active_links":
            sum(
                1
                for link
                in snapshot.values()
                if is_link_allowed(
                    link
                )
            ),

        "expired_links":
            sum(
                1
                for link
                in snapshot.values()
                if is_link_expired(
                    link
                )
            ),

        "subs_count":
            len(SUBS),
    }


@app.get("/api/activity")
async def get_activity(
    _=Depends(require_auth),
):

    return {
        "logs":
            list(
                activity_logs
            )[-150:]
    }


# ============================================================
# CONNECTIONS
# ============================================================

@app.get("/api/connections")
async def get_connections(
    _=Depends(require_auth),
):

    async with LINKS_LOCK:
        snapshot = dict(LINKS)

    grouped = {}

    for connection in connections.values():

        ip = connection.get(
            "ip",
            "نامشخص",
        )

        link = snapshot.get(
            connection.get(
                "uuid"
            )
        )

        label = (
            link.get(
                "label"
            )
            if link
            else "نامشخص"
        )

        group = grouped.get(ip)

        if group is None:

            group = {
                "ip":
                    ip,

                "sessions":
                    0,

                "bytes":
                    0,

                "labels":
                    set(),

                "transports":
                    set(),

                "first_connected_at":
                    connection.get(
                        "connected_at"
                    ),

                "last_connected_at":
                    connection.get(
                        "connected_at"
                    ),
            }

            grouped[ip] = group

        group["sessions"] += 1

        group["bytes"] += int(
            connection.get(
                "bytes",
                0,
            )
            or 0
        )

        group["labels"].add(
            label
        )

        group["transports"].add(
            connection.get(
                "transport",
                DEFAULT_PROTOCOL,
            )
        )

    result = []

    for group in grouped.values():

        result.append(
            {
                "ip":
                    group["ip"],

                "sessions":
                    group["sessions"],

                "labels":
                    sorted(
                        group["labels"]
                    ),

                "label":
                    (
                        " · ".join(
                            sorted(
                                group["labels"]
                            )
                        )
                        if group["labels"]
                        else "نامشخص"
                    ),

                "transports":
                    sorted(
                        group["transports"]
                    ),

                "bytes":
                    group["bytes"],

                "bytes_fmt":
                    fmt_bytes(
                        group["bytes"]
                    ),

                "connected_at":
                    group[
                        "first_connected_at"
                    ],

                "last_connected_at":
                    group[
                        "last_connected_at"
                    ],
            }
        )

    result.sort(
        key=lambda item:
            item.get(
                "last_connected_at"
            )
            or "",
        reverse=True,
    )

    return {
        "connections":
            result,

        "count":
            len(result),

        "raw_count":
            len(connections),
    }


# ============================================================
# OPTIONAL EXISTING PROJECT MODULES
# ============================================================

# ============================================================
# IMPORTANT:
# DO NOT REPLACE THIS VLESS CORE.
# ============================================================

try:

    from relay_vless import (
        RELAY_BUF,
        parse_vless_header,
        check_and_use,
        relay_ws_to_tcp,
        relay_tcp_to_ws,
        websocket_tunnel,
    )

    app.add_api_websocket_route(
        "/ws/{uuid}",
        websocket_tunnel,
    )

    logger.info(
        "VLESS relay loaded."
    )

except Exception as exc:

    logger.warning(
        "VLESS relay module unavailable: %s",
        exc,
    )


# ============================================================
# XHTTP
# ============================================================

try:

    from xhttp_siz10 import (
        router as xhttp_router
    )

    app.include_router(
        xhttp_router
    )

    logger.info(
        "XHTTP module loaded."
    )

except Exception as exc:

    logger.warning(
        "XHTTP module unavailable: %s",
        exc,
    )


# ============================================================
# TELEGRAM
# ============================================================

try:

    from telegram_bot import (
        start_bot as _tg_start_bot,
        stop_bot as _tg_stop_bot,
    )

except Exception:

    async def _tg_start_bot():
        return None

    async def _tg_stop_bot():
        return None


@app.on_event("startup")
async def start_optional_telegram():

    try:

        await _tg_start_bot()

        logger.info(
            "Telegram module initialized."
        )

    except Exception as exc:

        logger.warning(
            "Telegram bot disabled/error: %s",
            exc,
        )


# ============================================================
# HTTP PROXY
# ============================================================

_HOP = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-encoding",
    "content-length",
}


@app.api_route(
    "/proxy/{target_url:path}",
    methods=[
        "GET",
        "POST",
        "PUT",
        "DELETE",
        "PATCH",
        "HEAD",
        "OPTIONS",
    ],
)
async def http_proxy(
    target_url: str,
    request: Request,
):

    if not target_url.startswith("http"):
        target_url = (
            "https://"
            + target_url
        )

    if http_client is None:
        raise HTTPException(
            status_code=503,
            detail="HTTP client not ready",
        )

    try:

        body = await request.body()

        headers = {
            key: value
            for key, value
            in request.headers.items()
            if (
                key.lower()
                not in _HOP
            )
            and (
                key.lower()
                != "host"
            )
        }

        response = await http_client.request(
            method=request.method,
            url=target_url,
            headers=headers,
            content=body,
        )

        stats["total_bytes"] += len(
            response.content
        )

        stats["total_requests"] += 1

        hourly_traffic[
            now_ir().strftime(
                "%H:00"
            )
        ] += len(
            response.content
        )

        output_headers = {
            key: value
            for key, value
            in response.headers.items()
            if key.lower() not in _HOP
        }

        return Response(
            content=response.content,
            status_code=response.status_code,
            headers=output_headers,
        )

    except Exception as exc:

        stats["total_errors"] += 1

        error_logs.append(
            {
                "error":
                    str(exc),

                "url":
                    target_url,

                "time":
                    datetime.now().isoformat(),
            }
        )

        logger.exception(
            "Proxy error: %s",
            target_url,
        )

        raise HTTPException(
            status_code=502,
            detail=(
                "Proxy error: "
                f"{exc}"
            ),
        )


# ============================================================
# DASHBOARD
# ============================================================

DASHBOARD_HTML = r"""
<!DOCTYPE html>

<html lang="fa" dir="rtl">

<head>

<meta charset="UTF-8">

<meta
name="viewport"
content="width=device-width,initial-scale=1"
/>

<title>
PXpanel 12.1.0 Beta
</title>

<link
rel="preconnect"
href="https://fonts.googleapis.com"
>

<link
rel="preconnect"
href="https://fonts.gstatic.com"
crossorigin
>

<link
href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@300;400;500;600;700;800;900&display=swap"
rel="stylesheet"
>

<style>

*{
    box-sizing:border-box;
}

html,
body{
    margin:0;
    min-height:100%;
}

body{
    min-height:100vh;

    color:#fff;

    font-family:"Vazirmatn",sans-serif;

    background:
        radial-gradient(
            circle at 10% 0%,
            rgba(99,102,241,.13),
            transparent 25%
        ),
        radial-gradient(
            circle at 100% 100%,
            rgba(139,92,246,.10),
            transparent 25%
        ),
        #07070a;
}

.wrapper{
    width:min(
        1280px,
        calc(100% - 24px)
    );

    margin:auto;
    padding:18px 0 50px;
}

.topbar{
    display:flex;
    align-items:center;
    justify-content:space-between;
    gap:12px;

    margin-bottom:15px;
}

.brand{
    display:flex;
    align-items:center;
    gap:11px;
}

.logo{
    width:44px;
    height:44px;

    display:flex;
    align-items:center;
    justify-content:center;

    border-radius:14px;

    font-weight:900;

    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );
}

.brand-name{
    font-size:16px;
    font-weight:900;
}

.brand-desc{
    margin-top:2px;
    color:rgba(255,255,255,.37);
    font-size:10px;
}

.brand-version{
    color:#a78bfa;
    font-size:9px;
    margin-top:2px;
}

.top-actions{
    display:flex;
    gap:7px;
    flex-wrap:wrap;
}

.top-btn{
    border:1px solid rgba(255,255,255,.08);

    padding:9px 12px;

    border-radius:11px;

    color:#fff;
    background:rgba(255,255,255,.035);

    font-family:"Vazirmatn",sans-serif;

    font-size:10px;
    cursor:pointer;
    text-decoration:none;
}

.top-btn.primary{
    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );
}

.top-btn.danger{
    color:#fca5a5;
}

.stats-grid{
    display:grid;
    grid-template-columns:
        repeat(6,1fr);

    gap:9px;
}

.stat{
    position:relative;
    overflow:hidden;
    padding:14px;
    border-radius:16px;

    border:
        1px solid
        rgba(255,255,255,.07);

    background:
        rgba(255,255,255,.03);
}

.stat-label{
    color:rgba(255,255,255,.35);
    font-size:9px;
}

.stat-value{
    margin-top:6px;

    font-size:19px;
    font-weight:900;
}
.stat::after{content:"";position:absolute;right:0;bottom:0;left:0;height:2px;background:var(--stat-color,#818cf8);opacity:.8}
.stat:nth-child(1){--stat-color:#60a5fa}.stat:nth-child(2){--stat-color:#4ade80}.stat:nth-child(3){--stat-color:#f59e0b}.stat:nth-child(4){--stat-color:#a78bfa}.stat:nth-child(5){--stat-color:#fb7185}.stat:nth-child(6){--stat-color:#22d3ee}.stat-value{color:var(--stat-color,#fff)}


.panel{
    margin-top:11px;

    overflow:hidden;

    border-radius:19px;

    border:
        1px solid
        rgba(255,255,255,.07);

    background:
        rgba(255,255,255,.03);
}

.panel-head{
    padding:14px 16px;

    display:flex;

    justify-content:space-between;
    align-items:center;

    gap:10px;

    border-bottom:
        1px solid
        rgba(255,255,255,.06);
}

.panel-title{
    font-size:12px;
    font-weight:800;
}

.panel-sub{
    color:rgba(255,255,255,.32);
    font-size:9px;
    margin-top:3px;
}

.table-wrap{
    overflow:auto;
}

table{
    width:100%;

    min-width:1120px;

    border-collapse:collapse;
}

th,
td{
    text-align:right;

    padding:12px 13px;

    border-bottom:
        1px solid
        rgba(255,255,255,.045);

    font-size:10px;
}

th{
    color:rgba(255,255,255,.32);
    font-weight:500;
}

.badge{
    display:inline-flex;

    padding:4px 8px;

    border-radius:999px;

    font-size:8px;
}

.badge.active{
    color:#86efac;
    background:rgba(34,197,94,.08);
}

.badge.off{
    color:#fca5a5;
    background:rgba(239,68,68,.08);
}

.actions{
    display:flex;
    flex-wrap:wrap;
    gap:4px;
}

.action{
    border:0;

    padding:6px 8px;

    border-radius:8px;

    color:rgba(255,255,255,.82);

    background:rgba(255,255,255,.05);

    font-family:"Vazirmatn",sans-serif;

    font-size:8px;

    cursor:pointer;
}

.action.primary{
    background:
        rgba(99,102,241,.18);
}

.action.danger{
    color:#fca5a5;
}

.url-box{
    max-width:280px;

    direction:ltr;
    text-align:left;

    white-space:nowrap;
    overflow:hidden;
    text-overflow:ellipsis;

    color:#c4b5fd;

    font-family:Consolas,monospace;

    font-size:8px;
}

.pre{
    margin:0;

    padding:15px;

    max-height:280px;

    overflow:auto;

    color:rgba(255,255,255,.45);

    font-family:Consolas,monospace;

    font-size:9px;

    white-space:pre-wrap;
}

.download-grid{
    display:grid;

    grid-template-columns:
        repeat(3,1fr);

    gap:8px;

    padding:14px;
}

.download{
    display:block;

    padding:11px;

    border-radius:12px;

    color:#fff;
    text-decoration:none;

    border:
        1px solid
        rgba(255,255,255,.06);

    background:
        rgba(255,255,255,.025);

    font-size:10px;
}

.download span{
    display:block;

    margin-top:3px;

    color:rgba(255,255,255,.34);

    font-size:8px;
}

.notice{
    margin:0 14px 14px;

    padding:14px;

    border-radius:13px;

    background:
        rgba(99,102,241,.06);

    border:
        1px solid
        rgba(99,102,241,.13);

    color:rgba(255,255,255,.62);

    line-height:1.9;

    font-size:10px;
}

.notice strong{
    color:#c4b5fd;
}

.empty{
    padding:25px;

    text-align:center;

    color:rgba(255,255,255,.30);

    font-size:11px;
}

.modal-backdrop{
    position:fixed;

    inset:0;

    z-index:100;

    display:none;

    align-items:center;
    justify-content:center;

    padding:15px;

    background:
        rgba(0,0,0,.62);

    backdrop-filter:blur(12px);
}

.modal-backdrop.open{
    display:flex;
}

.modal{
    width:100%;
    max-width:720px;

    max-height:
        calc(100vh - 30px);

    overflow:auto;

    padding:20px;

    border-radius:22px;

    background:#0d0d12;

    border:
        1px solid
        rgba(255,255,255,.08);

    box-shadow:
        0 30px 100px
        rgba(0,0,0,.55);
}

.modal-head{
    display:flex;
    justify-content:space-between;
    align-items:center;

    margin-bottom:15px;
}

.modal-title{
    font-size:14px;
    font-weight:800;
}

.close{
    width:34px;
    height:34px;

    border:0;
    border-radius:10px;

    color:#fff;
    background:rgba(255,255,255,.05);

    cursor:pointer;
}

.form-grid{
    display:grid;

    grid-template-columns:
        repeat(2,1fr);

    gap:9px;
}

.field{
    display:flex;
    flex-direction:column;
    gap:6px;
}

.field.full{
    grid-column:
        1 / -1;
}

.field label{
    color:rgba(255,255,255,.4);
    font-size:9px;
}

.field input,
.field select,
.field textarea{
    width:100%;

    padding:11px;

    border-radius:11px;

    border:
        1px solid
        rgba(255,255,255,.07);

    background:
        rgba(255,255,255,.035);

    color:#fff;

    outline:none;

    font-family:
        "Vazirmatn",
        sans-serif;

    font-size:10px;
}

.field textarea{
    min-height:90px;
    resize:vertical;
}

.field input:focus,
.field select:focus,
.field textarea:focus{
    border-color:
        rgba(99,102,241,.55);
}

.modal-actions{
    margin-top:15px;

    display:flex;

    gap:8px;
}

.modal-btn{
    flex:1;

    padding:11px;

    border:0;
    border-radius:11px;

    cursor:pointer;

    font-family:
        "Vazirmatn",sans-serif;

    color:#fff;
}

.modal-btn.primary{
    background:
        linear-gradient(
            135deg,
            #6366f1,
            #8b5cf6
        );
}

.modal-btn.secondary{
    background:
        rgba(255,255,255,.05);
}

.toast{
    position:fixed;

    left:50%;
    top:18px;
    bottom:auto;

    z-index:200;

    padding:11px 14px;

    border-radius:12px;

    background:rgba(20,20,27,.97);

    border:
        1px solid
        rgba(255,255,255,.08);

    color:#fff;

    font-size:11px;
    font-weight:700;

    opacity:0;

    transform:
        translate(-50%,-140%);

    pointer-events:none;

    transition:
        .2s ease;
}

.toast.show{
    opacity:1;

    transform:
        translate(-50%,0);
}

/* LOGIN NOTICE START — DELETE THIS WHOLE BLOCK TO DISABLE THE LOGIN NOTICE */
.login-notice-backdrop{position:fixed;inset:0;z-index:500;display:flex;align-items:center;justify-content:center;padding:16px;background:rgba(0,0,0,.72);backdrop-filter:blur(14px)}
.login-notice{width:min(620px,100%);max-height:calc(100vh - 32px);overflow:auto;padding:22px;border:1px solid rgba(255,255,255,.10);border-radius:24px;background:linear-gradient(180deg,rgba(24,24,34,.98),rgba(12,12,17,.98));box-shadow:0 30px 100px rgba(0,0,0,.60);animation:noticeIn .28s ease both}
.login-notice-head{display:flex;align-items:center;gap:12px;margin-bottom:16px}.login-notice-icon{width:42px;height:42px;display:flex;align-items:center;justify-content:center;border-radius:13px;background:rgba(99,102,241,.14);border:1px solid rgba(129,140,248,.22);color:#a5b4fc;font-size:18px}.login-notice h3{margin:0;font-size:15px}.login-notice p{margin:5px 0 0;color:rgba(255,255,255,.42);font-size:9px;line-height:1.9}.notice-downloads{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-top:14px}.notice-download{display:block;padding:12px;border-radius:14px;text-decoration:none;color:#fff;background:rgba(255,255,255,.035);border:1px solid rgba(255,255,255,.07);transition:.2s ease}.notice-download:hover{transform:translateY(-2px);border-color:rgba(129,140,248,.30);background:rgba(129,140,248,.07)}.notice-download strong{display:block;font-size:10px}.notice-download span{display:block;margin-top:3px;color:rgba(255,255,255,.36);font-size:8px}.login-notice-body{margin-top:14px;padding:14px;border-radius:14px;background:rgba(255,255,255,.025);border:1px solid rgba(255,255,255,.06);color:rgba(255,255,255,.62);font-size:10px;line-height:2}.login-notice-body b{color:#fff}.login-notice-actions{margin-top:14px;display:flex;gap:8px}.login-notice-actions button{flex:1;padding:11px;border:0;border-radius:12px;color:#fff;background:linear-gradient(135deg,#6366f1,#8b5cf6);font-family:inherit;cursor:pointer}@keyframes noticeIn{from{opacity:0;transform:translateY(16px) scale(.985)}to{opacity:1;transform:translateY(0) scale(1)}}
/* LOGIN NOTICE END */

/* REGION NOTICE + RESPONSIVE UI OVERRIDES */
.login-notice-backdrop{
    padding:clamp(10px,3vw,24px);
    background:rgba(3,4,9,.76);
    backdrop-filter:blur(18px) saturate(135%);
}
.login-notice{
    width:min(680px,100%);
    max-height:min(760px,calc(100vh - 24px));
    padding:clamp(16px,3vw,24px);
    border-radius:24px;
    border:1px solid rgba(167,139,250,.18);
    background:
        radial-gradient(circle at 90% 0%,rgba(99,102,241,.13),transparent 32%),
        linear-gradient(180deg,rgba(25,25,37,.98),rgba(11,11,16,.99));
    box-shadow:0 35px 110px rgba(0,0,0,.62),inset 0 1px rgba(255,255,255,.04);
}
.login-notice-head{align-items:flex-start}
.login-notice-icon{
    width:46px;height:46px;min-width:46px;border-radius:15px;
    display:flex;align-items:center;justify-content:center;
    background:rgba(99,102,241,.12);
    border:1px solid rgba(167,139,250,.22);
    color:#c4b5fd;
}
.login-notice-icon svg{width:24px;height:24px;display:block}
.login-notice h3{font-size:15px;letter-spacing:-.2px}
.login-notice p{font-size:10px;line-height:2;color:rgba(255,255,255,.46)}
.login-notice-body{
    margin-top:12px;
    padding:15px;
    border-radius:16px;
    background:rgba(99,102,241,.065);
    border:1px solid rgba(129,140,248,.14);
    color:rgba(255,255,255,.66);
    font-size:10px;
    line-height:2.15;
}
.login-notice-body b{color:#fff}
.region-warning{
    margin-top:10px;
    padding:13px 14px;
    border-radius:15px;
    border:1px solid rgba(251,191,36,.17);
    background:rgba(251,191,36,.055);
    color:rgba(255,255,255,.72);
    line-height:2.1;
}
.region-warning .warning-title{
    display:flex;align-items:center;gap:8px;
    color:#fcd34d;font-weight:800;margin-bottom:3px;
}
.region-warning svg{width:17px;height:17px;flex:none}
.notice-downloads{grid-template-columns:repeat(3,minmax(0,1fr));gap:9px}
.notice-download{min-width:0}
.notice-download strong{font-size:10px}
.login-notice-actions button{min-height:42px;display:flex;align-items:center;justify-content:center;gap:7px}.login-notice-actions button svg{width:16px;height:16px}

.top-actions{display:flex;align-items:center;justify-content:flex-start;gap:8px;flex-wrap:wrap}
.top-btn{display:inline-flex;align-items:center;justify-content:center;gap:7px;white-space:nowrap}
.top-btn svg{width:15px;height:15px;flex:none}
.wrapper{width:min(1180px,calc(100% - 28px));margin-inline:auto}
.footer{margin-top:22px;padding:12px 2px 4px;opacity:.72}

@media(max-width:760px){
    .wrapper{width:calc(100% - 20px)}
    .topbar{gap:12px}
    .top-actions{width:100%;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:7px}
    .top-btn{width:100%;min-height:40px;padding:9px 10px}
    .top-btn.danger{grid-column:1 / -1}
    .notice-downloads{grid-template-columns:1fr}
    .login-notice{border-radius:20px}
}
@media(max-width:430px){
    .top-actions{grid-template-columns:1fr 1fr}
    .brand-name{font-size:15px}
    .brand-desc{font-size:9px}
    .stats-grid{grid-template-columns:1fr 1fr!important}
    .login-notice-head{gap:9px}
    .login-notice-icon{width:40px;height:40px;min-width:40px}
    .login-notice h3{font-size:14px}
}

@media(prefers-reduced-motion:reduce){
    .login-notice{animation:none}
    .notice-download{transition:none}
}

@media(max-width:1100px){

    .stats-grid{
        grid-template-columns:
            repeat(3,1fr);
    }

    .download-grid{
        grid-template-columns:
            repeat(2,1fr);
    }
}

@media(max-width:700px){

    .wrapper{
        width:
            calc(100% - 14px);
    }

    .topbar{
        align-items:
            flex-start;

        flex-direction:
            column;
    }

    .stats-grid{
        grid-template-columns:
            repeat(2,1fr);
    }

    .form-grid{
        grid-template-columns:1fr;
    }

    .field.full{
        grid-column:auto;
    }

    .download-grid{
        grid-template-columns:1fr;
    }
}

</style>

</head>

<body>

<div class="wrapper">

<div class="topbar">

<div class="brand">

<div class="logo">
P
</div>

<div>

<div class="brand-name">
PXpanel
</div>

<div class="brand-desc">
داشبورد مدیریت سرویس
</div>

<div class="brand-version">
12.1.0 Beta
</div>

</div>

</div>

<div class="top-actions">

<button
class="top-btn primary"
onclick="openAutoModal()"
><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9"><path d="M12 5v14M5 12h14"/></svg>
ساخت خودکار
</button>

<button
class="top-btn"
onclick="openManualModal()"
><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M4 20h4L19 9l-4-4L4 16v4Z"/><path d="m13.5 6.5 4 4"/></svg>
ساخت دستی
</button>

<button
class="top-btn"
onclick="openPasswordModal()"
><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><rect x="4" y="10" width="16" height="10" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/></svg>
تغییر رمز
</button>

<a
href="/logout"
class="top-btn danger"
><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8"><path d="M10 5H5v14h5"/><path d="m14 8 4 4-4 4"/><path d="M18 12H9"/></svg>
خروج
</a>

</div>

</div>


<div class="stats-grid">

<div class="stat">
<div class="stat-label">
کل کانفیگ‌ها
</div>
<div
id="totalLinks"
class="stat-value"
>
-
</div>
</div>

<div class="stat">
<div class="stat-label">
فعال
</div>
<div
id="activeLinks"
class="stat-value"
>
-
</div>
</div>

<div class="stat">
<div class="stat-label">
اتصالات
</div>
<div
id="connections"
class="stat-value"
>
-
</div>
</div>

<div class="stat">
<div class="stat-label">
Traffic
</div>
<div
id="traffic"
class="stat-value"
>
-
</div>
</div>

<div class="stat">
<div class="stat-label">
Requests
</div>
<div
id="requests"
class="stat-value"
>
-
</div>
</div>

<div class="stat">
<div class="stat-label">
Uptime
</div>
<div
id="uptime"
class="stat-value"
>
-
</div>
</div>

</div>


<div class="panel">

<div class="panel-head">

<div>

<div class="panel-title">
مدیریت کانفیگ‌ها
</div>

<div class="panel-sub">
VLESS / SUB / INFO
</div>

</div>

<button
class="top-btn primary"
onclick="refresh()"
>
↻ بروزرسانی
</button>

</div>

<div class="table-wrap">

<table>

<thead>

<tr>

<th>
نام
</th>

<th>
پروتکل
</th>

<th>
وضعیت
</th>

<th>
مصرف
</th>

<th>
زمان
</th>

<th>
اتصال
</th>

<th>
VLESS
</th>

<th>
عملیات
</th>

</tr>

</thead>

<tbody id="linksTable">

</tbody>

</table>

</div>

</div>


<div class="panel">

<div class="panel-head">

<div>
<div class="panel-title">
آخرین فعالیت‌ها
</div>
</div>

</div>

<pre
id="logs"
class="pre"
>
در حال بارگذاری...
</pre>

</div>


<div class="panel">

<div class="panel-head">

<div>
<div class="panel-title">
دانلود برنامه اتصال
</div>

<div class="panel-sub">
Android / iPhone / iPad / Windows
</div>

</div>

</div>

<div class="download-grid">

<a
class="download"
href="https://play.google.com/store/apps/details?id=com.happproxy"
target="_blank"
rel="noopener"
>
Happ Android
<span>
Google Play
</span>
</a>

<a
class="download"
href="https://dl.v2rayng.org/releases/latest/v2rayNG_2.2.6_arm64-v8a.apk"
target="_blank"
rel="noopener"
>
v2rayNG
<span>
Android APK
</span>
</a>

<a
class="download"
href="https://play.google.com/store/apps/details?id=dev.hexasoftware.v2box"
target="_blank"
rel="noopener"
>
V2Box Android
<span>
Google Play
</span>
</a>

<a
class="download"
href="https://apps.apple.com/app/happ-proxy-utility/id6504287215"
target="_blank"
rel="noopener"
>
Happ
<span>
iPhone / iPad
</span>
</a>

<a
class="download"
href="https://apps.apple.com/app/v2box-v2ray-client/id6446814690"
target="_blank"
rel="noopener"
>
V2Box
<span>
iPhone / iPad
</span>
</a>

<a
class="download"
href="https://apps.apple.com/app/streisand/id6450534064"
target="_blank"
rel="noopener"
>
Streisand
<span>
iPhone / iPad
</span>
</a>

<a
class="download"
href="https://apps.apple.com/app/foxray/id6448898396"
target="_blank"
rel="noopener"
>
FoXray
<span>
iPhone / iPad
</span>
</a>

<a
class="download"
href="https://github.com/2dust/v2rayN/releases/latest"
target="_blank"
rel="noopener"
>
v2rayN
<span>
Windows
</span>
</a>

<a
class="download"
href="https://happ-proxy.com/"
target="_blank"
rel="noopener"
>
Happ
<span>
Windows
</span>
</a>

</div>

<div class="notice">

<strong>
اطلاعیه مهم | آپدیت برنامه اتصال
</strong>

<br>

دوستان عزیز ❤️
برای اینکه کانفیگ‌های جدید بهترین
سازگاری، پایداری و عملکرد رو داشته باشن،
لطفاً برنامه‌ای که برای اتصال استفاده می‌کنید
رو به آخرین نسخه آپدیت کنید. 🔄⚡️

</div>

</div>

</div>


<!-- ===================================================== -->
<!-- MANUAL MODAL -->
<!-- ===================================================== -->

<div
id="manualModal"
class="modal-backdrop"
>

<div class="modal">

<div class="modal-head">

<div class="modal-title">
ساخت کانفیگ دستی
</div>

<button
class="close"
onclick="closeManualModal()"
>
×
</button>

</div>

<div class="form-grid">

<div class="field">

<label>
نام کانفیگ
</label>

<input
id="manualName"
placeholder="نام کانفیگ"
/>

</div>


<div class="field">

<label>
پروتکل
</label>

<select id="manualProtocol">

<option value="vless-ws">
VLESS WebSocket
</option>

<option value="xhttp-packet-up">
XHTTP Packet Up
</option>

<option value="xhttp-stream-up">
XHTTP Stream Up
</option>

<option value="xhttp-stream-one">
XHTTP Stream One
</option>

</select>

</div>


<div class="field">

<label>
حجم
</label>

<input
id="manualVolume"
type="number"
min="0"
placeholder="0 = نامحدود"
/>

</div>


<div class="field">

<label>
واحد حجم
</label>

<select id="manualVolumeUnit">

<option value="GB">
GB
</option>

<option value="MB">
MB
</option>

<option value="TB">
TB
</option>

</select>

</div>


<div class="field">

<label>
تعداد روز
</label>

<input
id="manualDays"
type="number"
min="0"
placeholder="0 = نامحدود"
/>

</div>


<div class="field">

<label>
محدودیت IP
</label>

<input
id="manualIpLimit"
type="number"
min="0"
placeholder="0 = نامحدود"
/>

</div>


<div class="field">

<label>
محدودیت اتصال
</label>

<input
id="manualConnections"
type="number"
min="0"
placeholder="0 = نامحدود"
/>

</div>


<div class="field">

<label>
سرعت
</label>

<input
id="manualSpeed"
type="number"
min="0"
placeholder="0 = نامحدود"
/>

</div>


<div class="field">

<label>
Fingerprint
</label>

<select id="manualFingerprint">

<option value="chrome">
Chrome
</option>

<option value="firefox">
Firefox
</option>

<option value="safari">
Safari
</option>

<option value="ios">
iOS
</option>

<option value="android">
Android
</option>

<option value="edge">
Edge
</option>

<option value="360">
360
</option>

<option value="qq">
QQ
</option>

<option value="random">
Random
</option>

<option value="randomized">
Randomized
</option>

</select>

</div>


<div class="field">

<label>
Fragment
</label>

<select id="manualFragment">

<option value="off">
خاموش
</option>

<option value="safe">
Safe
</option>

<option value="balanced">
Balanced
</option>

<option value="aggressive">
Aggressive
</option>

</select>

</div>


<div class="field">

<label>
Port
</label>

<input
id="manualPort"
type="number"
min="1"
max="65535"
value="443"
/>

</div>


<div class="field">

<label>
ALPN
</label>

<input
id="manualAlpn"
value="http/1.1"
/>

</div>


<div class="field full">

<label>
یادداشت
</label>

<textarea
id="manualNote"
placeholder="یادداشت اختیاری"
></textarea>

</div>

</div>

<div class="modal-actions">

<button
class="modal-btn secondary"
onclick="closeManualModal()"
>
انصراف
</button>

<button
class="modal-btn primary"
onclick="createManual()"
>
ساخت کانفیگ
</button>

</div>

</div>

</div>


<!-- ===================================================== -->
<!-- AUTO MODAL -->
<!-- ===================================================== -->

<div
id="autoModal"
class="modal-backdrop"
>

<div class="modal">

<div class="modal-head">

<div class="modal-title">
ساخت خودکار
</div>

<button
class="close"
onclick="closeAutoModal()"
>
×
</button>

</div>

<div
style="
color:rgba(255,255,255,.55);
font-size:11px;
line-height:2;
"
>

کانفیگ خودکار با نام تصادفی
<code>pxpanel_********</code>
ساخته می‌شود.

<br>

حجم: <b>نامحدود</b>

<br>

زمان: <b>نامحدود</b>

<br>

IP: <b>نامحدود</b>

<br>

سرعت: <b>نامحدود</b>

<br>

اتصال: <b>نامحدود</b>

<br>

پروتکل:
<b>VLESS WebSocket</b>

<br>

Port:
<b>443</b>

</div>

<div class="modal-actions">

<button
class="modal-btn secondary"
onclick="closeAutoModal()"
>
انصراف
</button>

<button
class="modal-btn primary"
onclick="createAuto()"
>
ساخت خودکار
</button>

</div>

</div>

</div>


<!-- ===================================================== -->
<!-- PASSWORD MODAL -->
<!-- ===================================================== -->

<div
id="passwordModal"
class="modal-backdrop"
>

<div class="modal">

<div class="modal-head">

<div class="modal-title">
تغییر رمز پنل
</div>

<button
class="close"
onclick="closePasswordModal()"
>
×
</button>

</div>

<div class="form-grid">

<div class="field full">

<label>
رمز فعلی
</label>

<input
id="currentPassword"
type="password"
/>

</div>

<div class="field">

<label>
رمز جدید
</label>

<input
id="newPassword"
type="password"
/>

</div>

<div class="field">

<label>
تکرار رمز جدید
</label>

<input
id="repeatPassword"
type="password"
/>

</div>

</div>

<div class="modal-actions">

<button
class="modal-btn secondary"
onclick="closePasswordModal()"
>
انصراف
</button>

<button
class="modal-btn primary"
onclick="changePassword()"
>
ذخیره رمز
</button>

</div>

</div>

</div>


    <!-- LOGIN NOTICE START -->
<div id="loginNoticeModal" class="login-notice-backdrop" role="dialog" aria-modal="true" aria-labelledby="regionNoticeTitle">
<div class="login-notice">
<div class="login-notice-head">
<div class="login-notice-icon">
<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true"><path d="M12 3a9 9 0 1 0 9 9"/><path d="M12 7v5l3 2"/><path d="M16.5 3.5h4v4"/><path d="m20.5 3.5-5 5"/></svg>
</div>
<div>
<h3 id="regionNoticeTitle">راهنمای اتصال سرویس</h3>
<p>اطلاعیه مهم منطقه‌ای قبل از اتصال کانفیگ‌ها</p>
</div>
</div>
<div class="login-notice-body">
<b>نکته:</b> لینک SUB را داخل برنامه Import / Subscription اضافه کنید. برای اتصال مستقیم نیز می‌توانید لینک VLESS را وارد کنید.
<div class="region-warning">
<div class="warning-title"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9"><path d="m12 3 9 17H3L12 3Z"/><path d="M12 9v5"/><path d="M12 17h.01"/></svg>هشدار منطقه‌ای اتصال</div>
⚠️⚠️ اگه براتون پنل نصب شد ولی کانفیگ ها پینگ ندادن — دامنه فیلتر شده — دوباره بسازید ⚠️⚠️
</div>
</div>
<div class="notice-downloads">
<a class="notice-download" href="https://github.com/2dust/v2rayNG/releases/latest" target="_blank" rel="noopener noreferrer"><strong>v2rayNG</strong><span>Android</span></a>
<a class="notice-download" href="https://github.com/2dust/v2rayN/releases/latest" target="_blank" rel="noopener noreferrer"><strong>v2rayN</strong><span>Windows / macOS / Linux</span></a>
<a class="notice-download" href="https://github.com/hiddify/hiddify-app/releases/latest" target="_blank" rel="noopener noreferrer"><strong>Hiddify</strong><span>Android / Windows / macOS / Linux</span></a>
</div>
<div class="login-notice-actions"><button type="button" onclick="closeLoginNotice()"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="m5 12 4 4L19 6"/></svg>متوجه شدم</button></div>
</div></div>
    <!-- LOGIN NOTICE END -->

<div
id="toast"
class="toast"
></div>


<script>

let editingLink = null;


/* LOGIN NOTICE START — DELETE THIS WHOLE BLOCK TO DISABLE THE LOGIN NOTICE */
function closeLoginNotice(){const modal=document.getElementById("loginNoticeModal");if(modal)modal.remove();try{history.replaceState({},document.title,location.pathname)}catch(e){}}
(function(){
    const modal=document.getElementById("loginNoticeModal");
    if(modal && new URLSearchParams(location.search).get("login") !== "1") modal.remove();
})();
window.addEventListener("keydown",event=>{if(event.key==="Escape")closeLoginNotice()});
/* LOGIN NOTICE END */

function escapeHtml(value){

    return String(
        value ?? ""
    )

    .replaceAll(
        "&",
        "&amp;"
    )

    .replaceAll(
        "<",
        "&lt;"
    )

    .replaceAll(
        ">",
        "&gt;"
    )

    .replaceAll(
        '"',
        "&quot;"
    )

    .replaceAll(
        "'",
        "&#039;"
    );

}


function formatBytes(value){

    value =
        Number(
            value || 0
        );

    if(
        value < 1024
    ){
        return (
            value +
            " B"
        );
    }

    if(
        value < 1024 ** 2
    ){
        return (
            (
                value /
                1024
            ).toFixed(1)
            +
            " KB"
        );
    }

    if(
        value < 1024 ** 3
    ){
        return (
            (
                value /
                1024 ** 2
            ).toFixed(2)
            +
            " MB"
        );
    }

    return (
        (
            value /
            1024 ** 3
        ).toFixed(2)
        +
        " GB"
    );

}


function showToast(message){

    const toast =
        document.getElementById(
            "toast"
        );

    toast.textContent =
        message;

    toast.classList.add(
        "show"
    );

    clearTimeout(
        window.__toastTimer
    );

    window.__toastTimer =
        setTimeout(
            () => {
                toast.classList.remove(
                    "show"
                );
            },
            2200
        );

}


async function api(
    url,
    options = {}
){

    try{

        const response =
            await fetch(
                url,
                {
                    cache:"no-store",
                    credentials:"same-origin",
                    ...options
                }
            );

        if(
            response.status === 401
        ){

            location.href =
                "/login";

            return null;

        }

        let data = null;

        try{

            data =
                await response.json();

        }catch{

            data = {
                ok:false,
                error:
                    "پاسخ سرور قابل خواندن نیست"
            };

        }

        if(
            !response.ok
        ){

            const message =
                data.detail ||
                data.error ||
                "خطای سرور";

            showToast(
                message
            );

            console.error(
                "API error:",
                url,
                data
            );

            return null;
        }

        return data;

    }catch(error){

        console.error(
            "Request failed:",
            url,
            error
        );

        showToast(
            "ارتباط با سرور برقرار نشد"
        );

        return null;

    }

}


async function refresh(){

    const results =
        await Promise.all([
            api("/stats"),
            api("/api/links"),
            api("/api/activity")
        ]);

    const statsData =
        results[0];

    const linksData =
        results[1];

    const activity =
        results[2];

    if(statsData){

        document.getElementById(
            "totalLinks"
        ).textContent =
            statsData.links_count;

        document.getElementById(
            "activeLinks"
        ).textContent =
            statsData.active_links;

        document.getElementById(
            "connections"
        ).textContent =
            statsData.active_connections;

        document.getElementById(
            "traffic"
        ).textContent =
            formatBytes(
                statsData.total_traffic_bytes
            );

        document.getElementById(
            "requests"
        ).textContent =
            statsData.total_requests;

        document.getElementById(
            "uptime"
        ).textContent =
            statsData.uptime;
    }


    if(linksData){

        const table =
            document.getElementById(
                "linksTable"
            );

        table.innerHTML = "";


        if(
            !linksData.links ||
            !linksData.links.length
        ){

            table.innerHTML = `
                <tr>
                    <td
                    colspan="8"
                    class="empty"
                    >
                    هنوز کانفیگی ساخته نشده است.
                    </td>
                </tr>
            `;

        }else{

            for(
                const link
                of linksData.links
            ){

                const row =
                    document.createElement(
                        "tr"
                    );

                const limit =
                    Number(
                        link.limit_bytes ||
                        0
                    );

                const used =
                    Number(
                        link.used_bytes ||
                        0
                    );

                let usageText =
                    formatBytes(
                        used
                    );

                if(limit > 0){

                    usageText +=
                        " / " +
                        formatBytes(
                            limit
                        );

                }else{

                    usageText +=
                        " / ∞";
                }


                row.innerHTML = `

<td>

<div style="font-weight:700">
${escapeHtml(
    link.label
)}
</div>

<div
style="
margin-top:3px;
color:rgba(255,255,255,.25);
font-size:8px;
"
>
${escapeHtml(
    link.uuid
)}
</div>

</td>


<td>
${escapeHtml(
    link.protocol
)}
</td>


<td>

<span class="
    badge
    ${
        link.active
        ? "active"
        : "off"
    }
">

${
    link.active
    ? "فعال"
    : "غیرفعال"
}

</span>

</td>


<td>
${usageText}
</td>


<td>
${
    link.expires_at
    ? escapeHtml(
        link.expires_at
      )
    : "∞"
}
</td>


<td>
${link.connected_ips || 0}
</td>


<td>

<div
class="url-box"
title="${escapeHtml(link.vless)}"
>
${escapeHtml(link.vless)}
</div>

</td>


<td>

<div class="actions">

<button
class="action primary"
type="button"
data-action="copy-vless"
>
VLESS
</button>

<button
class="action"
type="button"
data-action="copy-sub"
>
SUB
</button>

<button
class="action"
type="button"
data-action="open-info"
>
INFO
</button>

<button
class="action"
type="button"
data-action="toggle"
>
${
    link.active
    ? "خاموش"
    : "فعال"
}
</button>

<button
class="action"
type="button"
data-action="reset"
>
ریست
</button>

<button
class="action danger"
type="button"
data-action="delete"
>
حذف
</button>

</div>

</td>

`;

                const actionButtons =
                    row.querySelectorAll(
                        "button[data-action]"
                    );

                actionButtons.forEach(
                    (button) => {
                        button.addEventListener(
                            "click",
                            async () => {
                                const action =
                                    button.dataset.action;

                                if (action === "copy-vless") {
                                    await copyText(link.vless);
                                    return;
                                }

                                if (action === "copy-sub") {
                                    await copyText(link.sub);
                                    return;
                                }

                                if (action === "open-info") {
                                    if (!link.info) {
                                        showToast("لینک INFO موجود نیست");
                                        return;
                                    }
                                    window.open(
                                        String(link.info),
                                        "_blank",
                                        "noopener,noreferrer"
                                    );
                                    return;
                                }

                                button.disabled = true;
                                try {
                                    if (action === "toggle") {
                                        await toggleLink(
                                            link.uuid,
                                            !Boolean(link.active)
                                        );
                                    } else if (action === "reset") {
                                        await resetUsage(link.uuid);
                                    } else if (action === "delete") {
                                        await deleteLink(link.uuid);
                                    }
                                } finally {
                                    button.disabled = false;
                                }
                            }
                        );
                    }
                );

                table.appendChild(
                    row
                );

            }

        }
    }


    if(
        activity
        &&
        activity.logs
    ){

        document.getElementById(
            "logs"
        ).textContent =
            activity.logs
                .slice()
                .reverse()
                .map(
                    item =>
                        `[${item.level}] ${item.message}`
                )
                .join(
                    "\n"
                )
                ||
                "فعالیتی ثبت نشده است";

    }

}


async function copyText(text){

    const value =
        String(text ?? "").trim();

    if (!value) {
        showToast("متنی برای کپی وجود ندارد");
        return false;
    }

    try {
        if (navigator.clipboard && typeof navigator.clipboard.writeText === "function") {
            await navigator.clipboard.writeText(value);
            showToast("کپی شد");
            return true;
        }
    } catch (error) {
        console.warn("Clipboard API failed:", error);
    }

    try {
        const textarea = document.createElement("textarea");
        textarea.value = value;
        textarea.setAttribute("readonly", "");
        textarea.style.position = "fixed";
        textarea.style.left = "-9999px";
        textarea.style.top = "0";
        textarea.style.opacity = "0";
        document.body.appendChild(textarea);
        textarea.focus();
        textarea.select();
        textarea.setSelectionRange(0, textarea.value.length);
        const copied = document.execCommand("copy");
        textarea.remove();

        if (copied) {
            showToast("کپی شد");
            return true;
        }
    } catch (error) {
        console.warn("Legacy clipboard fallback failed:", error);
    }

    try {
        window.prompt("لینک را کپی کنید:", value);
    } catch (error) {
        console.warn("Prompt fallback failed:", error);
    }

    return false;

}

function openManualModal(){

    document
        .getElementById(
            "manualModal"
        )
        .classList.add(
            "open"
        );

}


function closeManualModal(){

    document
        .getElementById(
            "manualModal"
        )
        .classList.remove(
            "open"
        );

}


function openAutoModal(){

    document
        .getElementById(
            "autoModal"
        )
        .classList.add(
            "open"
        );

}


function closeAutoModal(){

    document
        .getElementById(
            "autoModal"
        )
        .classList.remove(
            "open"
        );

}


function openPasswordModal(){

    document
        .getElementById(
            "passwordModal"
        )
        .classList.add(
            "open"
        );

}


function closePasswordModal(){

    document
        .getElementById(
            "passwordModal"
        )
        .classList.remove(
            "open"
        );

}


async function createAuto(){

    closeAutoModal();

    showToast(
        "در حال ساخت کانفیگ..."
    );

    const result =
        await api(
            "/api/links/auto",
            {
                method:"POST"
            }
        );

    if(
        !result
        ||
        !result.ok
    ){
        return;
    }

    await copyText(
        result.vless
    );

    showToast(
        "کانفیگ ساخته شد و VLESS کپی شد"
    );

    await refresh();

}


async function createManual(){

    const body = {

        label:
            document
                .getElementById(
                    "manualName"
                )
                .value
                .trim()
            ||
            "کانفیگ جدید",

        limit_value:
            Number(
                document
                    .getElementById(
                        "manualVolume"
                    )
                    .value
                || 0
            ),

        limit_unit:
            document
                .getElementById(
                    "manualVolumeUnit"
                )
                .value,

        expires_days:
            Number(
                document
                    .getElementById(
                        "manualDays"
                    )
                    .value
                || 0
            ),

        ip_limit:
            Number(
                document
                    .getElementById(
                        "manualIpLimit"
                    )
                    .value
                || 0
            ),

        connection_limit:
            Number(
                document
                    .getElementById(
                        "manualConnections"
                    )
                    .value
                || 0
            ),

        speed_limit_value:
            Number(
                document
                    .getElementById(
                        "manualSpeed"
                    )
                    .value
                || 0
            ),

        speed_limit_unit:
            "MBIT",

        protocol:
            document
                .getElementById(
                    "manualProtocol"
                )
                .value,

        fingerprint:
            document
                .getElementById(
                    "manualFingerprint"
                )
                .value,

        fragment:
            document
                .getElementById(
                    "manualFragment"
                )
                .value,

        port:
            Number(
                document
                    .getElementById(
                        "manualPort"
                    )
                    .value
                || 443
            ),

        alpn:
            document
                .getElementById(
                    "manualAlpn"
                )
                .value,

        note:
            document
                .getElementById(
                    "manualNote"
                )
                .value

    };


    const result =
        await api(
            "/api/links",
            {
                method:"POST",

                headers:{
                    "Content-Type":
                        "application/json"
                },

                body:
                    JSON.stringify(
                        body
                    )
            }
        );


    if(
        !result
    ){
        return;
    }


    closeManualModal();

    if(result.vless){

        await copyText(
            result.vless
        );

        showToast(
            "کانفیگ ساخته شد"
        );

    }

    await refresh();

}


async function toggleLink(
    uuid,
    active
){

    const result =
        await api(
            "/api/links/" +
            encodeURIComponent(uuid),
            {
                method:"PATCH",
                headers:{
                    "Content-Type":"application/json"
                },
                body:JSON.stringify({
                    active:Boolean(active)
                })
            }
        );

    if (!result || result.ok !== true) {
        return false;
    }

    showToast(
        active
        ? "کانفیگ فعال شد"
        : "کانفیگ غیرفعال شد"
    );

    await refresh();
    return true;

}


async function resetUsage(
    uuid
){

    const result =
        await api(
            "/api/links/" +
            encodeURIComponent(uuid) +
            "/reset-usage",
            {
                method:"POST"
            }
        );

    if (!result || result.ok !== true) {
        return false;
    }

    showToast("مصرف ریست شد");
    await refresh();
    return true;

}


async function deleteLink(
    uuid
){

    if (!confirm("این کانفیگ حذف شود؟")) {
        return false;
    }

    const result =
        await api(
            "/api/links/" +
            encodeURIComponent(uuid),
            {
                method:"DELETE"
            }
        );

    if (!result || result.ok !== true) {
        return false;
    }

    showToast("کانفیگ حذف شد");
    await refresh();
    return true;

}


async function changePassword(){

    const current =
        document
            .getElementById(
                "currentPassword"
            )
            .value;

    const newPassword =
        document
            .getElementById(
                "newPassword"
            )
            .value;

    const repeat =
        document
            .getElementById(
                "repeatPassword"
            )
            .value;


    const result =
        await api(
            "/api/change-password",
            {
                method:"POST",

                headers:{
                    "Content-Type":
                        "application/json"
                },

                body:
                    JSON.stringify({

                        current_password:
                            current,

                        new_password:
                            newPassword,

                        repeat_password:
                            repeat

                    })
            }
        );


    if(
        result
        &&
        result.ok
    ){

        closePasswordModal();

        document
            .getElementById(
                "currentPassword"
            )
            .value = "";

        document
            .getElementById(
                "newPassword"
            )
            .value = "";

        document
            .getElementById(
                "repeatPassword"
            )
            .value = "";

        showToast(
            "رمز عبور تغییر کرد"
        );

    }

}


refresh();

setInterval(
    refresh,
    1000
);

</script>

<!-- ===================================================== -->
<!-- POST LOGIN REGION / DOMAIN NOTICE -->
<!-- ===================================================== -->

<div
    id="regionNotice"
    style="
        display:none;
        position:fixed;
        inset:0;
        z-index:99999;
        align-items:center;
        justify-content:center;
        padding:20px;
        background:rgba(2,6,23,.78);
        backdrop-filter:blur(18px);
        -webkit-backdrop-filter:blur(18px);
    "
>
    <div
        style="
            width:min(560px,100%);
            position:relative;
            overflow:hidden;
            border:1px solid rgba(245,158,11,.28);
            border-radius:26px;
            padding:26px;
            background:linear-gradient(145deg,rgba(30,25,8,.98),rgba(10,12,20,.98));
            box-shadow:0 30px 100px rgba(0,0,0,.55),0 0 60px rgba(245,158,11,.10);
            font-family:"Vazirmatn",sans-serif;
        "
    >
        <div
            style="
                position:absolute;
                width:180px;
                height:180px;
                left:-70px;
                top:-90px;
                border-radius:999px;
                background:rgba(245,158,11,.12);
                filter:blur(35px);
                pointer-events:none;
            "
        ></div>

        <div style="display:flex;align-items:flex-start;gap:14px;position:relative;">
            <div
                style="
                    flex:0 0 auto;
                    width:54px;
                    height:54px;
                    display:flex;
                    align-items:center;
                    justify-content:center;
                    border-radius:17px;
                    color:#fbbf24;
                    border:1px solid rgba(251,191,36,.25);
                    background:rgba(245,158,11,.10);
                "
            >
                <svg width="28" height="28" viewBox="0 0 24 24" fill="none" aria-hidden="true">
                    <path d="M12 3 2.8 19a1.4 1.4 0 0 0 1.22 2h15.96a1.4 1.4 0 0 0 1.22-2L12 3Z" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/>
                    <path d="M12 9v4" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
                    <circle cx="12" cy="16.8" r="1" fill="currentColor"/>
                </svg>
            </div>

            <div style="min-width:0;flex:1;">
                <div style="font-size:18px;font-weight:900;color:#fff;line-height:1.5;">هشدار مهم قبل ساخت کانفیگ</div>
                <div style="margin-top:5px;font-size:11px;color:rgba(255,255,255,.45);">بررسی دامنه و محدودیت‌های منطقه‌ای</div>
            </div>

            <button
                type="button"
                onclick="closeRegionNotice()"
                aria-label="بستن"
                style="
                    width:38px;
                    height:38px;
                    flex:0 0 auto;
                    border:1px solid rgba(255,255,255,.08);
                    border-radius:12px;
                    color:rgba(255,255,255,.65);
                    background:rgba(255,255,255,.04);
                    cursor:pointer;
                    display:flex;
                    align-items:center;
                    justify-content:center;
                "
            >
                <svg width="18" height="18" viewBox="0 0 24 24" fill="none">
                    <path d="m7 7 10 10M17 7 7 17" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>
                </svg>
            </button>
        </div>

        <div
            style="
                position:relative;
                margin-top:20px;
                padding:17px;
                border:1px solid rgba(251,191,36,.16);
                border-radius:18px;
                background:rgba(245,158,11,.055);
                color:rgba(255,255,255,.82);
                font-size:13px;
                line-height:2.05;
                text-align:right;
            "
        >
            <strong style="color:#fbbf24;">⚠️⚠️</strong> اگه براتون پنل نصب شد ولی کانفیگ ها پینگ ندادن — دامنه فیلتر شده — دوباره بسازید <strong style="color:#fbbf24;">⚠️⚠️</strong>
            <div style="margin-top:10px;color:rgba(255,255,255,.48);font-size:11px;line-height:1.9;">
                ممکنه دسترسی دامنه به‌دلیل محدودیت‌های منطقه‌ای، اپراتور یا ISP متفاوت باشه. در این شرایط یک دامنه جدید امتحان کنید.
            </div>
        </div>

        <button
            type="button"
            onclick="closeRegionNotice()"
            style="
                position:relative;
                width:100%;
                margin-top:15px;
                min-height:46px;
                border:1px solid rgba(251,191,36,.20);
                border-radius:15px;
                color:#17120a;
                background:linear-gradient(135deg,#fbbf24,#f59e0b);
                font-family:inherit;
                font-weight:900;
                cursor:pointer;
            "
        >
            متوجه شدم
        </button>
    </div>
</div>

<script>
(function(){
    const params = new URLSearchParams(window.location.search);
    if (params.get("login") === "1") {
        const modal = document.getElementById("regionNotice");
        if (modal) {
            modal.style.display = "flex";
            document.body.style.overflow = "hidden";
        }
        const cleanUrl = window.location.pathname;
        window.history.replaceState({}, document.title, cleanUrl);
    }
})();

function closeRegionNotice(){
    const modal = document.getElementById("regionNotice");
    if (modal) modal.style.display = "none";
    document.body.style.overflow = "";
}

document.addEventListener("keydown", function(event){
    if (event.key === "Escape") closeRegionNotice();
});
</script>

</body>
</html>
"""


@app.get(
    "/dashboard",
    response_class=HTMLResponse,
)
async def dashboard(
    request: Request,
):

    if not await is_valid_session(
        request.cookies.get(
            SESSION_COOKIE
        )
    ):
        return RedirectResponse(
            "/login"
        )

    await ensure_default_link()

    return HTMLResponse(
        DASHBOARD_HTML
    )


# ============================================================
# TEST
# ============================================================

@app.get(
    "/test-ws",
    response_class=HTMLResponse,
)
async def test_ws():

    return HTMLResponse(
        """
        <script>
        location.href='/dashboard'
        </script>
        """
    )


# ============================================================
# GLOBAL ERROR HANDLER
# ============================================================

@app.exception_handler(Exception)
async def global_exception_handler(
    request: Request,
    exc: Exception,
):

    stats[
        "total_errors"
    ] += 1

    error_logs.append(
        {
            "error":
                str(exc),

            "path":
                str(request.url),

            "method":
                request.method,

            "time":
                datetime.now().isoformat(),
        }
    )

    logger.exception(
        "Unhandled exception: %s %s",
        request.method,
        request.url,
    )

    # API requests
    if (
        request.url.path.startswith(
            "/api/"
        )
        or request.url.path == "/stats"
    ):

        return JSONResponse(
            {
                "ok": False,
                "error":
                    str(exc)
                or "internal server error",
            },
            status_code=500,
        )

    return HTMLResponse(
        """
        <html lang="fa" dir="rtl">
        <body style="
            background:#07070a;
            color:#fff;
            font-family:sans-serif;
            padding:40px;
        ">
            <h2>
            خطای داخلی PXpanel
            </h2>

            <p>
            لطفاً لاگ Railway را بررسی کنید.
            </p>
        </body>
        </html>
        """,
        status_code=500,
    )


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":

    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=PORT,
        log_level="info",
        workers=1,
    )
