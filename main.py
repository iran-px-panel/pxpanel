# ============================================================
# PXPanel 13.6.1
# Railway Ready
# ============================================================

import asyncio
import base64
import hashlib
import json
import logging
import os
import secrets
import string
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

APP_NAME = "PXPanel"
APP_VERSION = "13.6.1"

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

DATA_FILE = DATA_DIR / "pixonpanel_state.json"
SECRET_FILE = DATA_DIR / "pixonpanel_secret.key"


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
CATEGORIES: dict = {}

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
    "vmess-ws",
    "trojan-ws",
    "shadowsocks",
    "socks5",
    "http",
    "hysteria2",
    "tuic",
    "wireguard",
    "highspeed-demo",
    "gaming-lite-demo",
)

PROTOCOL_LABELS = {
    "vless-ws": "VLESS WebSocket",
    "xhttp-packet-up": "XHTTP Packet Up",
    "xhttp-stream-up": "XHTTP Stream Up",
    "xhttp-stream-one": "XHTTP Stream One",
    "vmess-ws": "VMess WebSocket",
    "trojan-ws": "Trojan WebSocket",
    "shadowsocks": "Shadowsocks",
    "socks5": "SOCKS5",
    "http": "HTTP Proxy",
    "hysteria2": "Hysteria 2",
    "tuic": "TUIC",
    "wireguard": "WireGuard",
    "highspeed-demo": "HighSpeed Upload/Download (دمو)",
    "gaming-lite-demo": "Gaming Lite (دمو)",
}

PROTOCOL_ALIASES = {
    "vmess": "vmess-ws", "trojan": "trojan-ws", "ss": "shadowsocks",
    "socks": "socks5", "hy2": "hysteria2", "hysteria": "hysteria2",
}

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


def normalize_protocol(protocol: str | None) -> str:
    value = str(protocol or DEFAULT_PROTOCOL).strip().lower()
    value = PROTOCOL_ALIASES.get(value, value)
    return value if value in PROTOCOLS else DEFAULT_PROTOCOL


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


def random_config_name(existing=None):
    existing = existing or set()
    alphabet = string.ascii_lowercase + string.digits
    for _ in range(80):
        length = secrets.randbelow(6) + 8
        name = "".join(secrets.choice(alphabet) for _ in range(length))
        if name not in existing and name and not name[0].isdigit():
            return name
    return secrets.token_hex(6)

def sanitize_config_name(name: str) -> str:
    if not name:
        return random_config_name()
    cleaned = "".join(ch for ch in str(name) if ch.isascii() and ch.isalnum())
    if not cleaned or cleaned[0].isdigit():
        cleaned = ("a" + cleaned) if cleaned else random_config_name()
    return cleaned[:40]

def auto_config_name() -> str:
    return random_config_name()


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

SESSION_COOKIE = "pixonpanel_session"

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
    uuid: str, host: str, remark: str = "PXPanel",
    protocol: str = DEFAULT_PROTOCOL, fingerprint: str | None = None,
    alpn: str | None = None, port: int | None = None,
):
    protocol = normalize_protocol(protocol)
    fp = (fingerprint or DEFAULT_FINGERPRINT).strip().lower()
    if fp not in FINGERPRINTS: fp = DEFAULT_FINGERPRINT
    port_value = safe_int(port, DEFAULT_PORT, MIN_PORT, MAX_PORT)
    alpn_value = (alpn or DEFAULT_ALPN_BY_PROTOCOL.get(protocol, "http/1.1")).strip()
    label = quote(str(remark or "PXPanel"), safe="")
    if protocol == "vless-ws":
        q = {"encryption":"none","security":"tls","type":"ws","host":host,"path":f"/ws/{uuid}","sni":host,"fp":fp,"alpn":alpn_value}
        return "vless://" + uuid + "@" + host + ":" + str(port_value) + "?" + "&".join(f"{k}={quote(str(v), safe=',/') }" for k,v in q.items()) + "#" + label
    if protocol.startswith("xhttp-"):
        mode = protocol.replace("xhttp-", "")
        q = {"encryption":"none","security":"tls","type":"xhttp","mode":mode,"host":host,"path":f"/xhttp-siz10/{mode}/{uuid}","sni":host,"fp":fp,"alpn":alpn_value}
        return "vless://" + uuid + "@" + host + ":" + str(port_value) + "?" + "&".join(f"{k}={quote(str(v), safe=',/') }" for k,v in q.items()) + "#" + label
    if protocol == "vmess-ws":
        raw = {"v":"2","ps":remark,"add":host,"port":port_value,"id":uuid,"aid":0,"scy":"auto","net":"ws","type":"none","host":host,"path":f"/ws/{uuid}","tls":"tls","sni":host,"fp":fp}
        return "vmess://" + base64.b64encode(json.dumps(raw,separators=(",",":"),ensure_ascii=False).encode()).decode()
    if protocol == "trojan-ws":
        return f"trojan://{uuid}@{host}:{port_value}?security=tls&type=ws&host={quote(host)}&path={quote('/ws/'+uuid)}&sni={quote(host)}#{label}"
    if protocol == "shadowsocks":
        method = os.getenv("SS_METHOD", "aes-256-gcm")
        userinfo = base64.urlsafe_b64encode(f"{method}:{uuid}".encode()).decode().rstrip("=")
        return f"ss://{userinfo}@{host}:{port_value}#{label}"
    if protocol == "socks5": return f"socks5://{uuid}:{uuid}@{host}:{port_value}#{label}"
    if protocol == "http": return f"http://{uuid}:{uuid}@{host}:{port_value}#{label}"
    if protocol == "hysteria2": return f"hysteria2://{uuid}@{host}:{port_value}/?sni={quote(host)}&insecure=0#{label}"
    if protocol == "tuic": return f"tuic://{uuid}:{uuid}@{host}:{port_value}?sni={quote(host)}&alpn=h3#{label}"
    if protocol == "wireguard": return f"wireguard://{uuid}@{host}:{port_value}?publicKey={uuid}#{label}"
    if protocol == "highspeed-demo":
        q = {"encryption":"none","security":"tls","type":"xhttp","mode":"stream-up","host":host,"path":f"/xhttp-siz10/stream-up/{uuid}","sni":host,"fp":fp,"alpn":"h2,http/1.1"}
        return "vless://" + uuid + "@" + host + ":" + str(port_value) + "?" + "&".join(f"{k}={quote(str(v), safe=',/')}" for k,v in q.items()) + "#" + label
    if protocol == "gaming-lite-demo":
        return f"hysteria2://{uuid}@{host}:{port_value}/?sni={quote(host)}&insecure=0&obfs=salamander#{label}"
    return f"vless://{uuid}@{host}:{port_value}"

def vless_link_for_link(
    link: dict,
    uid: str,
    host: str,
):
    return generate_vless_link(
        uid,
        host,
        remark=str(link.get("label") or "Config"),
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
    connected_count = len(unique_ips_for_uuid(uid))
    is_active = is_link_allowed(link)
    limit_b = int(link.get("limit_bytes", 0) or 0)
    used_b = int(link.get("used_bytes", 0) or 0)
    is_expired = is_link_expired(link) or (limit_b > 0 and used_b >= limit_b)
    if not is_active or is_expired:
        status_color = "red"
    elif connected_count > 0:
        status_color = "green"
    else:
        status_color = "gray"
    clean_ips = link.get("clean_ips") or []
    cfg_count = int(link.get("config_count") or 1)
    show_vless = len(clean_ips) <= 1 and cfg_count <= 1
    cat = CATEGORIES.get(str(link.get("category_id") or "0")) or {}
    return {
        "uuid": uid,
        "name": link.get("label", ""),
        "label": link.get("label", ""),
        "protocol": link.get("protocol", DEFAULT_PROTOCOL),
        "active": is_active,
        "used_bytes": used_b,
        "limit_bytes": limit_b,
        "expires_at": link.get("expires_at"),
        "ip_limit": int(link.get("ip_limit", 0) or 0),
        "speed_limit_bytes": int(link.get("speed_limit_bytes", 0) or 0),
        "connection_limit": int(link.get("connection_limit", 0) or 0),
        "fragment": link.get("fragment", "off"),
        "fingerprint": link.get("fingerprint", DEFAULT_FINGERPRINT),
        "alpn": link.get("alpn", ""),
        "port": link.get("port", DEFAULT_PORT),
        "note": link.get("note", ""),
        "clean_ips": clean_ips,
        "alarm_enabled": bool(link.get("alarm_enabled", False)),
        "category_id": str(link.get("category_id") or "0"),
        "category_number": int(cat.get("number", 0)),
        "category_name": str(cat.get("name", "عمومی")),
        "config_count": cfg_count,
        "status_color": status_color,
        "connected_ips": connected_count,
        "show_vless": show_vless,
        "vless": vless_link_for_link(link, uid, host) if show_vless else "",
        "vless_full": vless_link_for_link(link, uid, host),
        "sub": f"https://{host}/sub/{uid}",
        "info": f"https://{host}/info/{uid}",
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

        CATEGORIES.update(
            data.get(
                "categories",
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
            link.setdefault("clean_ips", [])
            link.setdefault("alarm_enabled", False)
            link.setdefault("category_id", "0")
            link.setdefault("config_count", 1)
            link.setdefault("usage_history", [])

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

                "categories":
                    dict(CATEGORIES),

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



async def ensure_default_categories():
    if CATEGORIES:
        return
    CATEGORIES["0"] = {
        "id": "0", "name": "عمومی", "number": 0,
        "limit_bytes": 0, "expires_days": 0, "connection_limit": 0,
        "speed_limit_bytes": 0, "ip_limit": 0, "clean_ips": [],
        "random_name": False, "single_user": False,
        "created_at": datetime.now().isoformat(),
    }
    CATEGORIES["1"] = {
        "id": "1", "name": "VIP", "number": 1,
        "limit_bytes": 0, "expires_days": 0, "connection_limit": 1,
        "speed_limit_bytes": 0, "ip_limit": 1, "clean_ips": [],
        "random_name": False, "single_user": True,
        "created_at": datetime.now().isoformat(),
    }
    asyncio.create_task(save_state())

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
    clean_ips=None,
    alarm_enabled: bool = False,
    category_id: str = "0",
    config_count: int = 1,
):

    protocol = normalize_protocol(protocol)

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
            sanitize_config_name((label or "").strip() or random_config_name()),

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

        "security_profile": "balanced",
        "multi_login": False,
        "protocol_label": PROTOCOL_LABELS.get(protocol, protocol),
        "clean_ips": list(clean_ips or []),
        "alarm_enabled": bool(alarm_enabled),
        "category_id": str(category_id or "0"),
        "config_count": max(1, min(40, int(config_count or 1))),
        "usage_history": [],
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

    await ensure_default_categories()
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

<title>PX Panel</title>

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
            rgba(37,99,235,.22),
            transparent 30%
        ),
        radial-gradient(
            circle at 85% 85%,
            rgba(59,130,246,.18),
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
            #2563eb,
            #3b82f6
        );
}

.brand-name{
    font-size:17px;
    font-weight:900;
}

.version{
    margin-top:4px;
    font-size:11px;
    color:#60a5fa;
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
    color:#93c5fd;
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
            #2563eb,
            #3b82f6
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
    color:#60a5fa;
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

/* PXPanel 13.0.1 responsive system */
html{scroll-behavior:smooth} body{overflow-x:hidden} button,input,select,textarea{touch-action:manipulation} .modal{overscroll-behavior:contain}
@media(max-width:900px){.container,.shell,.dashboard,.main,.content{max-width:100%!important;width:100%!important}.grid,.stats-grid,.cards-grid,.form-grid{grid-template-columns:repeat(2,minmax(0,1fr))!important}.sidebar{z-index:1000}}
@media(max-width:640px){body{padding:10px!important;font-size:14px}.grid,.stats-grid,.cards-grid,.form-grid{grid-template-columns:1fr!important}.card,.panel,.section,.modal{border-radius:18px!important}.modal{max-height:92vh;overflow:auto;padding:14px!important}.header,.topbar,.toolbar,.actions{flex-wrap:wrap!important}.header>* ,.topbar>*{max-width:100%}.btn,button{min-height:44px}.field input,.field select,.field textarea,input,select,textarea{min-height:44px;font-size:16px;max-width:100%}table{display:block;overflow-x:auto;white-space:nowrap}.link-row,.config-row{flex-direction:column!important;align-items:stretch!important}.brand-name{font-size:15px}}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{animation-duration:.01ms!important;transition-duration:.01ms!important;scroll-behavior:auto!important}}
</style>
</head>

<body>

<div class="card">

<div class="brand">

<div class="logo">P</div>

<div>
<div class="brand-name">
PX Panel
</div>

<div class="version">
13.6.1
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
این صفحه، درگاه عمومی PX Panel است.
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
PX Panel · 13.6.1
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

<title>ورود | PX Panel</title>

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
            rgba(37,99,235,.20),
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
            #2563eb,
            #3b82f6
        );
}

h1{
    margin:0;
    font-size:25px;
}

.version{
    margin-top:5px;
    color:#60a5fa;
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
            #2563eb,
            #3b82f6
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

    color:#60a5fa;
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
ورود به PX Panel
</h1>

<div class="version">
13.6.1
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

    raw_clean = body.get("clean_ips") or body.get("clean_ip") or ""
    if isinstance(raw_clean, list):
        clean_ips = [str(x).strip() for x in raw_clean if str(x).strip()]
    else:
        clean_ips = [x.strip() for x in str(raw_clean).replace(",", "\n").splitlines() if x.strip()]
    alarm_enabled = bool(body.get("alarm_enabled", False))
    category_id = str(body.get("category_id") or "0")
    if category_id not in CATEGORIES:
        category_id = "0"
    config_count = safe_int(body.get("config_count", 1), minimum=1, maximum=40)
    cat = CATEGORIES.get(category_id) or {}
    if cat.get("limit_bytes") and limit_bytes <= 0:
        limit_bytes = int(cat["limit_bytes"])
    if cat.get("expires_days") and expires_days <= 0:
        expires_days = int(cat["expires_days"])
        expires_at = (datetime.now() + timedelta(days=expires_days)).isoformat() if expires_days > 0 else None
    if cat.get("connection_limit") and connection_limit <= 0:
        connection_limit = int(cat["connection_limit"])
    if cat.get("speed_limit_bytes") and speed_bytes <= 0:
        speed_bytes = int(cat["speed_limit_bytes"])
    if cat.get("ip_limit") and ip_limit <= 0:
        ip_limit = int(cat["ip_limit"])
    if cat.get("clean_ips") and not clean_ips:
        clean_ips = list(cat["clean_ips"])
    if cat.get("single_user"):
        if ip_limit == 0: ip_limit = 1
        if connection_limit == 0: connection_limit = 1
    label_val = body.get("label", "")
    if cat.get("random_name") or not str(label_val).strip():
        label_val = random_config_name()
    else:
        label_val = sanitize_config_name(str(label_val))

    uid, link = await make_link(
        label=label_val,
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
        clean_ips=clean_ips,
        alarm_enabled=alarm_enabled,
        category_id=category_id,
        config_count=config_count,
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
        body = await request.json()
    except Exception:
        body = {}
    if not isinstance(body, dict): body = {}
    host = get_host(request)
    protocol = normalize_protocol(body.get("protocol", DEFAULT_PROTOCOL))
    profile = str(body.get("profile", "balanced")).strip().lower()
    profiles = {
        "normal": {"ip":0,"conn":0,"speed":0,"fp":"chrome","fragment":"off"},
        "balanced": {"ip":2,"conn":4,"speed":0,"fp":"chrome","fragment":"safe"},
        "gaming": {"ip":1,"conn":2,"speed":0,"fp":"chrome","fragment":"safe"},
        "maximum": {"ip":0,"conn":0,"speed":0,"fp":"randomized","fragment":"safe"},
    }
    cfg = profiles.get(profile, profiles["balanced"])
    uid, link = await make_link(
        label=auto_config_name(), limit_bytes=0, expires_at=None,
        ip_limit=cfg["ip"], speed_limit_bytes=cfg["speed"], connection_limit=cfg["conn"],
        note=f"Auto generated by PXPanel | profile={profile}",
        protocol=protocol, fingerprint=cfg["fp"],
        alpn=DEFAULT_ALPN_BY_PROTOCOL.get(protocol, ""), port=443, fragment=cfg["fragment"],
    )
    link["security_profile"] = profile
    result = {**get_link_info(link, uid, host), "ok": True, "profile": profile}
    log_activity("link", f"کانفیگ خودکار «{link['label']}» با {PROTOCOL_LABELS.get(protocol, protocol)} ساخته شد", "ok")
    return result


# ============================================================
# LIST LINKS
# ============================================================

@app.get("/api/protocols")
async def api_protocols(request: Request):
    require_auth(request)
    return {"protocols": [{"id": p, "label": PROTOCOL_LABELS.get(p, p)} for p in PROTOCOLS], "default": DEFAULT_PROTOCOL}


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
    clean_ips = link.get("clean_ips") or []
    used = int(link.get("used_bytes", 0) or 0)
    limit = int(link.get("limit_bytes", 0) or 0)
    remaining = max(0, limit - used) if limit > 0 else 0
    volume_text = f"{fmt_bytes(used)}/{fmt_bytes(limit)} (باقی {fmt_bytes(remaining)})" if limit > 0 else f"{fmt_bytes(used)}/∞"
    expires_at = link.get("expires_at")
    if expires_at:
        try:
            exp_dt = datetime.fromisoformat(str(expires_at))
            now_dt = datetime.now(exp_dt.tzinfo) if getattr(exp_dt, "tzinfo", None) else datetime.now()
            secs = int((exp_dt - now_dt).total_seconds())
            if secs <= 0:
                time_text = "منقضی"
            else:
                days, rem = divmod(secs, 86400)
                hours, rem = divmod(rem, 3600)
                mins = rem // 60
                time_text = f"{days}د {hours}س" if days else (f"{hours}س {mins}د" if hours else f"{mins}د")
        except Exception:
            time_text = str(expires_at)[:16]
    else:
        time_text = "∞"
    label = str(link.get("label") or "Config")
    stats_remark = f"{label} | {volume_text} | {time_text}"
    stats_line = generate_vless_link(uuid, "0.0.0.0", remark=stats_remark, protocol=link.get("protocol", DEFAULT_PROTOCOL), fingerprint=link.get("fingerprint", DEFAULT_FINGERPRINT), alpn=link.get("alpn"), port=link.get("port", DEFAULT_PORT))
    lines = [stats_line]
    used_names = set()
    cfg_count = max(1, min(40, int(link.get("config_count") or 1)))
    if clean_ips:
        hosts = list(clean_ips)
        while len(hosts) < cfg_count:
            hosts.extend(clean_ips)
        hosts = hosts[:cfg_count]
        for cip in hosts:
            name = random_config_name(used_names)
            used_names.add(name)
            lines.append(generate_vless_link(uuid, cip, remark=name, protocol=link.get("protocol", DEFAULT_PROTOCOL), fingerprint=link.get("fingerprint", DEFAULT_FINGERPRINT), alpn=link.get("alpn"), port=link.get("port", DEFAULT_PORT)))
    else:
        for i in range(cfg_count):
            name = random_config_name(used_names)
            used_names.add(name)
            lines.append(generate_vless_link(uuid, host, remark=name, protocol=link.get("protocol", DEFAULT_PROTOCOL), fingerprint=link.get("fingerprint", DEFAULT_FINGERPRINT), alpn=link.get("alpn"), port=link.get("port", DEFAULT_PORT)))
    content = base64.b64encode("\n".join(lines).encode()).decode()
    profile_title = f"0.0.0.0 | {stats_remark}"
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
    ip_limit = "نامحدود" if not snapshot.get("ip_limit", 0) else str(snapshot.get("ip_limit"))
    connection_limit = "نامحدود" if not snapshot.get("connection_limit", 0) else str(snapshot.get("connection_limit"))
    speed_limit = "نامحدود" if not snapshot.get("speed_limit_bytes", 0) else fmt_bytes(snapshot.get("speed_limit_bytes", 0)) + "/s"

    usage_history = snapshot.get("usage_history", [])
    svg_points = "0,50 300,50"
    if usage_history and len(usage_history) > 1:
        max_hist = max(usage_history) if max(usage_history) > 0 else 1
        pts = []
        step = 300 / (len(usage_history) - 1)
        for i, val in enumerate(usage_history):
            x = i * step
            y = 60 - min(60, max(4, (val / max_hist) * 52))
            pts.append(f"{x:.1f},{y:.1f}")
        svg_points = " ".join(pts)
    elif usage_history and len(usage_history) == 1:
        svg_points = f"0,50 300,{60 - min(60, max(4, (usage_history[0] / (limit if limit > 0 else max(used, 1))) * 52)):.1f}"

    status_badge_html = 'text-emerald-300 border border-emerald-400/25 bg-emerald-400/10' if status_class == 'good' else 'text-rose-300 border border-rose-400/25 bg-rose-400/10'
    label_escaped = escape_html(snapshot.get("label", "PXpanel"))
    uid_escaped = escape_html(uid)
    app_version_str = escape_html(str(APP_VERSION))
    used_bytes_str = escape_html(fmt_bytes(used))
    limit_bytes_str = escape_html(fmt_bytes(limit)) if limit > 0 else '∞'
    remaining_value_escaped = escape_html(remaining_value)
    expiry_remaining_escaped = escape_html(expiry_remaining)
    expiry_display_escaped = escape_html(expiry_display)
    ip_limit_escaped = escape_html(ip_limit)
    connection_limit_escaped = escape_html(connection_limit)
    speed_limit_escaped = escape_html(speed_limit)
    protocol_escaped = escape_html(snapshot.get("protocol", "vless-ws"))
    fingerprint_escaped = escape_html(snapshot.get("fingerprint", "chrome"))
    vless_url_escaped = escape_html(vless_url)
    sub_url_escaped = escape_html(sub_url)
    dash_calc_offset = f"{339.29 - (339.29 * min(usage_percent, 100) / 100):.1f}"

    info_html = f"""<!DOCTYPE html>
<html lang="fa" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover">
<title>{label_escaped} | INFO</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Vazirmatn:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
<script src="https://cdn.tailwindcss.com"></script>
<script src="https://cdn.jsdelivr.net/npm/qrcode-generator@1.4.4/qrcode.min.js"></script>
<script>
  tailwind.config = {{
    theme: {{
      extend: {{
        fontFamily: {{ vazir: ['Vazirmatn','system-ui','sans-serif'] }}
      }}
    }}
  }}
</script>
<style>
  :root {{
    --bg-main: #05060a;
    --bg-card: rgba(255, 255, 255, 0.04);
    --bg-card-hover: rgba(255, 255, 255, 0.07);
    --border-color: rgba(255, 255, 255, 0.1);
    --text-main: #f1f5f9;
    --text-muted: rgba(255, 255, 255, 0.4);
    --bg-sub-card: rgba(0, 0, 0, 0.2);
    --grad-1: rgba(96,165,250,.16);
    --grad-2: rgba(96,165,250,.13);
    --grad-3: rgba(52,211,153,.08);
  }}

  body.theme-lighter {{
    --bg-main: #131722;
    --bg-card: rgba(255, 255, 255, 0.075);
    --bg-card-hover: rgba(255, 255, 255, 0.115);
    --border-color: rgba(255, 255, 255, 0.16);
    --text-main: #ffffff;
    --text-muted: rgba(255, 255, 255, 0.6);
    --bg-sub-card: rgba(0, 0, 0, 0.35);
    --grad-1: rgba(96,165,250,.24);
    --grad-2: rgba(96,165,250,.20);
    --grad-3: rgba(52,211,153,.13);
  }}

  html,body{{background:var(--bg-main); transition: background 0.3s ease, color 0.3s ease;}}
  body{{
    background:
      radial-gradient(ellipse 80% 50% at 10% -10%, var(--grad-1), transparent 50%),
      radial-gradient(ellipse 60% 40% at 95% 15%, var(--grad-2), transparent 45%),
      radial-gradient(ellipse 55% 35% at 60% 100%, var(--grad-3), transparent 40%),
      var(--bg-main);
  }}
  .status-dot{{box-shadow:0 0 10px currentColor}}
  ::-webkit-scrollbar{{width:8px;height:8px}}
  ::-webkit-scrollbar-thumb{{background:rgba(255,255,255,.12);border-radius:99px}}
  * {{ box-shadow: none !important; }}
  .copy-btn svg{{transition:none}}
  
  .dynamic-card {{
    background-color: var(--bg-card);
    border-color: var(--border-color);
    transition: background-color 0.3s ease, border-color 0.3s ease;
  }}
  .dynamic-card:hover {{
    background-color: var(--bg-card-hover);
  }}
  .sub-box {{
    background-color: var(--bg-sub-card);
  }}
</style>
</head>
<body class="font-vazir text-slate-100 antialiased min-h-screen py-8 px-3 sm:px-4 md:py-14">

<div class="w-full max-w-4xl mx-auto space-y-5 sm:space-y-6 md:space-y-8">

  <!-- Top Bar Theme Toggle Button -->
  <div class="flex justify-end">
    <button type="button" onclick="toggleTheme()" class="inline-flex items-center gap-1.5 px-4 py-2 rounded-full text-xs font-extrabold text-amber-300 border border-amber-400/30 bg-amber-400/10 hover:bg-amber-400/20 transition-colors shadow-lg">
      <svg id="themeIcon" xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M6.34 17.66l-1.41 1.41M19.07 4.93l-1.41 1.41"/></svg>
      تغییر تم
    </button>
  </div>

  <!-- Hero -->
  <section class="rounded-[26px] sm:rounded-[28px] border dynamic-card backdrop-blur-2xl p-5 sm:p-6 md:p-8">
    <div class="flex flex-col md:flex-row md:items-center md:justify-between gap-5">
      <div class="flex items-center gap-4">
        <div class="w-13 h-13 sm:w-14 sm:h-14 shrink-0 rounded-2xl grid place-items-center bg-gradient-to-br from-blue-400/20 to-purple-400/10 border border-blue-400/25 text-blue-300">
          <svg xmlns="http://www.w3.org/2000/svg" width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2l8 4v6c0 5.2-3.4 9-8 10-4.6-1-8-4.8-8-10V6l8-4z"/><path d="M9.5 12l1.8 1.8L15 10"/></svg>
        </div>
        <div class="min-w-0">
          <h1 class="text-lg sm:text-xl md:text-2xl font-black tracking-tight truncate">{label_escaped}</h1>
          <p class="mt-1.5 text-[10.5px] sm:text-[11px] text-white/40 break-all">UUID: {uid_escaped} &nbsp;·&nbsp; PXpanel {app_version_str}</p>
        </div>
      </div>
      <div class="flex items-center gap-2.5 self-start md:self-auto flex-wrap">
        <button type="button" onclick="openQrModal()" class="inline-flex items-center gap-1.5 px-3.5 py-2 rounded-full text-xs font-extrabold text-purple-300 border border-purple-400/30 bg-purple-400/10 hover:bg-purple-400/20 transition-colors">
          <svg xmlns="http://www.w3.org/2000/svg" width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7"/><rect x="14" y="3" width="7" height="7"/><rect x="14" y="14" width="7" height="7"/><rect x="3" y="14" width="7" height="7"/></svg>
          QR Code
        </button>
        <div class="inline-flex items-center gap-2 px-4 py-2 rounded-full text-xs font-extrabold {status_badge_html}">
          <span class="status-dot w-2 h-2 rounded-full bg-current"></span>
          {status_text}
        </div>
      </div>
    </div>
  </section>

  <!-- Usage overview -->
  <section class="grid grid-cols-1 lg:grid-cols-[1.6fr_1fr] gap-5 sm:gap-6">

    <div class="rounded-[22px] border dynamic-card backdrop-blur-2xl p-5 sm:p-6 md:p-7">
      <div class="flex items-center gap-2.5">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" class="text-white/35"><path d="M3 3v18h18"/><path d="M7 15l4-6 3 3 4-7"/></svg>
        <div>
          <p class="text-[10px] font-extrabold tracking-widest uppercase text-white/30">Traffic Overview</p>
          <p class="mt-0.5 text-sm font-black">مصرف سرویس</p>
        </div>
      </div>

      <div class="mt-6 flex flex-col sm:flex-row items-center sm:items-start gap-6">
        <div class="relative shrink-0 w-[128px] h-[128px]">
          <svg width="128" height="128" viewBox="0 0 132 132" class="-rotate-90">
            <circle cx="66" cy="66" r="54" fill="none" stroke="rgba(255,255,255,0.07)" stroke-width="10"/>
            <circle cx="66" cy="66" r="54" fill="none" stroke="url(#usageRingGradient)" stroke-width="10" stroke-linecap="round"
              stroke-dasharray="339.29" stroke-dashoffset="{dash_calc_offset}"/>
            <defs>
              <linearGradient id="usageRingGradient" x1="0%" y1="0%" x2="100%" y2="100%">
                <stop offset="0%" stop-color="#34d399"/>
                <stop offset="100%" stop-color="#f59e0b"/>
              </linearGradient>
            </defs>
          </svg>
          <div class="absolute inset-0 grid place-items-center">
            <div class="text-center">
              <p class="text-xl font-black leading-none">{usage_percent}%</p>
              <p class="mt-1.5 text-[10px] text-white/40">مصرف‌شده</p>
            </div>
          </div>
        </div>

        <div class="flex-1 w-full min-w-0">
          <div class="text-xl sm:text-2xl font-black tracking-tight">
            {used_bytes_str}
            <span class="text-sm font-semibold text-white/40"> / {limit_bytes_str}</span>
          </div>

          <div class="mt-4 rounded-xl border border-white/[0.05] sub-box px-3 pt-3 pb-1.5">
            <p class="flex items-center gap-1.5 text-[10px] text-white/35 mb-1">
              <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.4" stroke-linecap="round" stroke-linejoin="round"><path d="M3 17l6-6 4 4 8-8"/><path d="M17 7h4v4"/></svg>
              روند مصرف
            </p>
            <svg viewBox="0 0 300 64" class="w-full h-14" preserveAspectRatio="none">
              <defs>
                <linearGradient id="trendFill" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stop-color="#60a5fa" stop-opacity="0.35"/>
                  <stop offset="100%" stop-color="#60a5fa" stop-opacity="0"/>
                </linearGradient>
              </defs>
              <path d="M0,64 L{svg_points} L300,64 Z" fill="url(#trendFill)"/>
              <path d="M{svg_points}" fill="none" stroke="#60a5fa" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"/>
            </svg>
          </div>

          <div class="mt-4 flex items-center justify-between text-[11px] text-white/40 flex-wrap gap-2">
            <span class="inline-flex items-center gap-1.5">
              <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/></svg>
              باقی‌مانده: <b class="text-white/70 font-bold">{remaining_value_escaped}</b>
            </span>
            <span class="inline-flex items-center gap-1.5">
              <svg xmlns="http://www.w3.org/2000/svg" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="17" rx="2"/><path d="M3 9h18M8 3v3M16 3v3"/></svg>
              زمان: <b class="text-white/70 font-bold">{expiry_remaining_escaped}</b>
            </span>

          </div>
        </div>
      </div>
    </div>

    <div class="rounded-[22px] border dynamic-card backdrop-blur-2xl p-5 sm:p-6 md:p-7">
      <div class="flex items-center gap-2.5">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" class="text-white/35"><circle cx="12" cy="12" r="9"/><path d="M12 8v4l3 2"/></svg>
        <p class="text-[10px] font-extrabold tracking-widest uppercase text-white/30">Service</p>
      </div>
      <div class="mt-4 divide-y divide-white/[0.06]">
        <div class="flex items-center justify-between py-3 first:pt-0">
          <span class="inline-flex items-center gap-2 text-[11px] text-white/45">
            <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="18" height="17" rx="2"/><path d="M3 9h18M8 3v3M16 3v3"/></svg>
            انقضا
          </span>
          <span class="text-xs font-extrabold">{expiry_display_escaped}</span>
        </div>
        <div class="flex items-center justify-between py-3">
          <span class="inline-flex items-center gap-2 text-[11px] text-white/45">
            <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.55a11 11 0 0 1 14 0"/><path d="M8.5 16a6 6 0 0 1 7 0"/><path d="M12 20h.01"/></svg>
            IP Limit
          </span>
          <span class="text-xs font-extrabold">{ip_limit_escaped}</span>
        </div>
        <div class="flex items-center justify-between py-3">
          <span class="inline-flex items-center gap-2 text-[11px] text-white/45">
            <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M4 9V7a2 2 0 0 1 2-2h12a2 2 0 0 1 2 2v2"/><rect x="2" y="9" width="20" height="8" rx="2"/><path d="M6 17v2M18 17v2"/></svg>
            Connection
          </span>
          <span class="text-xs font-extrabold">{connection_limit_escaped}</span>
        </div>
        <div class="flex items-center justify-between py-3 last:pb-0">
          <span class="inline-flex items-center gap-2 text-[11px] text-white/45">
            <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M13 2L3 14h7l-1 8 10-12h-7l1-8z"/></svg>
            Speed
          </span>
          <span class="text-xs font-extrabold">{speed_limit_escaped}</span>
        </div>
      </div>
    </div>

  </section>

  <!-- Stats -->
  <section class="grid grid-cols-2 md:grid-cols-4 gap-3.5 sm:gap-4 md:gap-5">

    <div class="rounded-2xl border dynamic-card backdrop-blur-xl p-4 sm:p-5 hover:border-emerald-400/20 transition-colors duration-200">
      <div class="w-9 h-9 rounded-xl grid place-items-center bg-emerald-400/10 border border-emerald-400/20 text-emerald-300">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3v18h18"/><path d="M18 9l-5 5-3-3-4 4"/></svg>
      </div>
      <p class="mt-4 text-[11px] text-white/45">مصرف فعلی</p>
      <p class="mt-1 text-[14px] sm:text-[15px] font-black text-emerald-300 break-words">{used_bytes_str}</p>
    </div>

    <div class="rounded-2xl border dynamic-card backdrop-blur-xl p-4 sm:p-5 hover:border-amber-400/20 transition-colors duration-200">
      <div class="w-9 h-9 rounded-xl grid place-items-center bg-amber-400/10 border border-amber-400/20 text-amber-300">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 3"/></svg>
      </div>
      <p class="mt-4 text-[11px] text-white/45">باقی‌مانده</p>
      <p class="mt-1 text-[14px] sm:text-[15px] font-black text-amber-300 break-words">{remaining_value_escaped}</p>
    </div>

    <div class="rounded-2xl border dynamic-card backdrop-blur-xl p-4 sm:p-5 hover:border-blue-400/20 transition-colors duration-200">
      <div class="w-9 h-9 rounded-xl grid place-items-center bg-blue-400/10 border border-blue-400/20 text-blue-300">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><rect x="4" y="4" width="16" height="16" rx="3"/><path d="M9 4v16M4 9h16"/></svg>
      </div>
      <p class="mt-4 text-[11px] text-white/45">اتصالات فعال</p>
      <p class="mt-1 text-[14px] sm:text-[15px] font-black text-blue-300 break-words">{len(unique_ips_for_uuid(uid))}</p>
    </div>

    <div class="rounded-2xl border dynamic-card backdrop-blur-xl p-4 sm:p-5 hover:border-purple-400/20 transition-colors duration-200">
      <div class="w-9 h-9 rounded-xl grid place-items-center bg-purple-400/10 border border-purple-400/20 text-purple-300">
        <svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 2l9 4.5v6c0 5-3.6 8.7-9 9.5-5.4-.8-9-4.5-9-9.5v-6L12 2z"/></svg>
      </div>
      <p class="mt-4 text-[11px] text-white/45">زمان باقی‌مانده</p>
      <p class="mt-1 text-[14px] sm:text-[15px] font-black text-purple-300 break-words">{expiry_remaining_escaped}</p>
    </div>

  </section>

  <!-- Technical details -->
  <section class="rounded-[22px] border dynamic-card backdrop-blur-2xl p-5 sm:p-6 md:p-7">
    <div class="flex items-center justify-between gap-3 mb-5">
      <p class="flex items-center gap-2 text-sm font-black">
        <svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" class="text-white/40"><path d="M4 21v-7M4 10V3M12 21v-11M12 6V3M20 21v-5M20 12V3"/><path d="M1 14h6M9 8h6M17 16h6"/></svg>
        جزئیات فنی
      </p>
      <p class="text-[11px] text-white/40">Configuration Details</p>
    </div>
    <div class="grid grid-cols-1 sm:grid-cols-2 gap-3.5">
      <div class="rounded-2xl border border-white/[0.06] sub-box p-4">
        <p class="text-[11px] text-white/45">Protocol</p>
        <p class="mt-2 text-[11px] font-medium text-purple-300 tracking-wide" dir="ltr" style="font-family:ui-monospace,Consolas,monospace">{protocol_escaped}</p>
      </div>
      <div class="rounded-2xl border border-white/[0.06] sub-box p-4">
        <p class="text-[11px] text-white/45">Fingerprint</p>
        <p class="mt-2 text-[11px] font-medium text-purple-300 tracking-wide" dir="ltr" style="font-family:ui-monospace,Consolas,monospace">{fingerprint_escaped}</p>
      </div>
      <div class="rounded-2xl border border-white/[0.06] sub-box p-4">
        <p class="text-[11px] text-white/45">IP Limit</p>
        <p class="mt-2 text-xs font-bold text-white/85">{ip_limit_escaped}</p>
      </div>
      <div class="rounded-2xl border border-white/[0.06] sub-box p-4">
        <p class="text-[11px] text-white/45">Connection Limit</p>
        <p class="mt-2 text-xs font-bold text-white/85">{connection_limit_escaped}</p>
      </div>
      <div class="rounded-2xl border border-white/[0.06] sub-box p-4">
        <p class="text-[11px] text-white/45">Speed Limit</p>
        <p class="mt-2 text-xs font-bold text-white/85">{speed_limit_escaped}</p>
      </div>
      <div class="rounded-2xl border border-white/[0.06] sub-box p-4">
        <p class="text-[11px] text-white/45">تاریخ انقضا</p>
        <p class="mt-2 text-xs font-bold text-white/85">{expiry_display_escaped}</p>
      </div>
    </div>
  </section>

  <!-- Links -->
  <section class="rounded-[22px] border dynamic-card backdrop-blur-2xl p-5 sm:p-6 md:p-7">
    <div class="flex items-center justify-between gap-3 mb-5">
      <p class="flex items-center gap-2 text-sm font-black">
        <svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" class="text-white/40"><path d="M10 13a5 5 0 0 0 7.07 0l2.83-2.83a5 5 0 0 0-7.07-7.07L11.5 4.5"/><path d="M14 11a5 5 0 0 0-7.07 0l-2.83 2.83a5 5 0 0 0 7.07 7.07l1.41-1.41"/></svg>
        لینک‌های سرویس
      </p>
      <p class="text-[11px] text-white/40">Copy / Import</p>
    </div>

    <div class="space-y-3">
      <div class="flex flex-col sm:flex-row sm:items-center gap-3 sm:gap-4 rounded-2xl border border-white/[0.06] sub-box p-4 hover:border-purple-400/25 transition-colors duration-200">
        <div class="min-w-0 flex-1">
          <p class="text-[11px] font-extrabold text-white/45 tracking-wide">VLESS</p>
          <p id="vlessLinkText" class="mt-1.5 text-[11px] text-purple-300 break-all leading-6" dir="ltr" style="font-family:ui-monospace,Consolas,monospace">{vless_url_escaped}</p>
        </div>
        <button id="vlessCopyBtn" type="button" onclick="pxCopy('vlessLinkText','vlessCopyBtn')"
          class="copy-btn shrink-0 self-start sm:self-center inline-flex items-center gap-1.5 text-[11px] font-bold text-white/60 px-3.5 py-2 rounded-xl bg-white/[0.05] border border-white/10 hover:bg-white/[0.1] hover:text-white transition-colors duration-200">
          <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>
          <span>کپی</span>
        </button>
      </div>

      <div class="flex flex-col sm:flex-row sm:items-center gap-3 sm:gap-4 rounded-2xl border border-white/[0.06] sub-box p-4 hover:border-purple-400/25 transition-colors duration-200">
        <div class="min-w-0 flex-1">
          <p class="text-[11px] font-extrabold text-white/45 tracking-wide">SUBSCRIPTION</p>
          <p id="subLinkText" class="mt-1.5 text-[11px] text-purple-300 break-all leading-6" dir="ltr" style="font-family:ui-monospace,Consolas,monospace">{sub_url_escaped}</p>
        </div>
        <button id="subCopyBtn" type="button" onclick="pxCopy('subLinkText','subCopyBtn')"
          class="copy-btn shrink-0 self-start sm:self-center inline-flex items-center gap-1.5 text-[11px] font-bold text-white/60 px-3.5 py-2 rounded-xl bg-white/[0.05] border border-white/10 hover:bg-white/[0.1] hover:text-white transition-colors duration-200">
          <svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.3" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="12" height="12" rx="2"/><path d="M5 15V5a2 2 0 0 1 2-2h10"/></svg>
          <span>کپی</span>
        </button>
      </div>
    </div>
  </section>

  <!-- Downloads -->
  <section class="rounded-[22px] border dynamic-card backdrop-blur-2xl p-5 sm:p-6 md:p-7">
    <div class="flex items-center justify-between gap-3 mb-5">
      <p class="flex items-center gap-2 text-sm font-black">
        <svg xmlns="http://www.w3.org/2000/svg" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" class="text-white/40"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><path d="M7 10l5 5 5-5"/><path d="M12 15V3"/></svg>
        دانلود برنامه‌ها
      </p>
      <p class="text-[11px] text-white/40">Official Releases</p>
    </div>

    <div class="grid grid-cols-1 sm:grid-cols-3 gap-3.5">
      <a href="https://github.com/2dust/v2rayNG/releases/latest" target="_blank" rel="noopener noreferrer"
         class="flex items-center gap-3 rounded-2xl border border-white/10 sub-box p-4 hover:border-blue-400/25 transition-colors duration-200">
        <div class="w-10 h-10 shrink-0 rounded-xl grid place-items-center bg-blue-400/10 border border-blue-400/20 text-blue-300 font-black text-[11px]">NG</div>
        <div class="min-w-0">
          <p class="text-xs font-extrabold">v2rayNG</p>
          <p class="mt-0.5 text-[10px] text-white/40">Android</p>
        </div>
      </a>
      <a href="https://github.com/2dust/v2rayN/releases/latest" target="_blank" rel="noopener noreferrer"
         class="flex items-center gap-3 rounded-2xl border border-white/10 sub-box p-4 hover:border-blue-400/25 transition-colors duration-200">
        <div class="w-10 h-10 shrink-0 rounded-xl grid place-items-center bg-blue-400/10 border border-blue-400/20 text-blue-300 font-black text-[11px]">N</div>
        <div class="min-w-0">
          <p class="text-xs font-extrabold">v2rayN</p>
          <p class="mt-0.5 text-[10px] text-white/40">Windows / macOS / Linux</p>
        </div>
      </a>
      <a href="https://github.com/hiddify/hiddify-app/releases/latest" target="_blank" rel="noopener noreferrer"
         class="flex items-center gap-3 rounded-2xl border border-white/10 sub-box p-4 hover:border-blue-400/25 transition-colors duration-200">
        <div class="w-10 h-10 shrink-0 rounded-xl grid place-items-center bg-blue-400/10 border border-blue-400/20 text-blue-300 font-black text-[11px]">H</div>
        <div class="min-w-0">
          <p class="text-xs font-extrabold">Hiddify</p>
          <p class="mt-0.5 text-[10px] text-white/40">Android / Windows / macOS / Linux</p>
        </div>
      </a>
    </div>
  </section>

  <!-- Footer -->
  <div class="rounded-2xl border border-emerald-400/15 bg-emerald-400/[0.05] p-4 text-center text-xs text-white/45">
    پشتیبانی و اطلاعیه‌ها &nbsp;·&nbsp; <b class="text-emerald-300">کانال تلگرام: logic_sec</b>
  </div>

</div>

<!-- QR Code Modal Popup -->
<div id="qrModal" class="fixed inset-0 z-50 flex items-center justify-center p-4 bg-black/80 backdrop-blur-md hidden">
  <div class="w-full max-w-sm rounded-[24px] border border-white/15 bg-[#0b0c14] p-6 text-center shadow-2xl relative">
    <button type="button" onclick="closeQrModal()" class="absolute top-4 left-4 w-8 h-8 rounded-full bg-white/5 border border-white/10 grid place-items-center text-white/60 hover:text-white">✕</button>
    <p class="text-sm font-black text-white/90 mb-2">QR Code اسکن کانفیگ</p>
    <p class="text-[11px] text-white/40 mb-4">برای اتصال سریع با گوشی موبایل</p>
    <div id="qrcodeContainer" class="bg-white p-4 rounded-2xl inline-block mx-auto mb-4 border border-white/10"></div>
    <p id="qrModalText" class="text-[10px] text-purple-300 break-all max-h-16 overflow-y-auto px-2" dir="ltr"></p>
  </div>
</div>

<script>
const vlessUrlData = "{vless_url}";

// Theme toggle logic with localStorage support (2 themes total)
function toggleTheme() {{
  const body = document.body;
  body.classList.toggle('theme-lighter');
  const isLighter = body.classList.contains('theme-lighter');
  localStorage.setItem('px_theme', isLighter ? 'lighter' : 'dark');
}}

// Initialize saved theme on load
(function() {{
  if (localStorage.getItem('px_theme') === 'lighter') {{
    document.body.classList.add('theme-lighter');
  }}
}})();

function openQrModal() {{
  var modal = document.getElementById('qrModal');
  var container = document.getElementById('qrcodeContainer');
  var txtEl = document.getElementById('qrModalText');
  container.innerHTML = "";
  txtEl.textContent = vlessUrlData;
  modal.classList.remove('hidden');
  try {{
    var typeNumber = 0;
    var errorCorrectionLevel = 'L';
    var qr = qrcode(typeNumber, errorCorrectionLevel);
    qr.addData(vlessUrlData);
    qr.make();
    container.innerHTML = qr.createImgTag(5, 8);
  }} catch (e) {{
    container.innerHTML = "<p class='text-xs text-black'>خطا در تولید QR Code</p>";
  }}
}}

function closeQrModal() {{
  document.getElementById('qrModal').classList.add('hidden');
}}

document.getElementById('qrModal').addEventListener('click', function(e) {{
  if (e.target === this) closeQrModal();
}});

function pxCopy(textId, btnId) {{
  var el = document.getElementById(textId);
  var btn = document.getElementById(btnId);
  if (!el || !btn) return;
  var text = el.textContent.textContext || el.textContent.trim();
  var done = function() {{
    var original = btn.getAttribute('data-original');
    if (!original) {{
      original = btn.innerHTML;
      btn.setAttribute('data-original', original);
    }}
    btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.6" stroke-linecap="round" stroke-linejoin="round"><path d="M20 6L9 17l-5-5"/></svg><span>کپی شد</span>';
    btn.classList.add('text-emerald-300','border-emerald-400/30','bg-emerald-400/10');
    setTimeout(function() {{
      btn.innerHTML = original;
      btn.classList.remove('text-emerald-300','border-emerald-400/30','bg-emerald-400/10');
    }}, 1700);
  }};
  if (navigator.clipboard && navigator.clipboard.writeText) {{
    navigator.clipboard.writeText(text).then(done).catch(function() {{ fallbackCopy(text, done); }});
  }} else {{
    fallbackCopy(text, done);
  }}
}}
function fallbackCopy(text, cb) {{
  var ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.opacity = '0';
  document.body.appendChild(ta);
  ta.select();
  try {{ document.execCommand('copy'); }} catch (e) {{}}
  document.body.removeChild(ta);
  if (cb) cb();
}}
</script>
</body>
</html>"""
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
PX Panel
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
            rgba(37,99,235,.17),
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

    color:#93c5fd;

    direction:ltr;
    word-break:break-all;

    font-family:Consolas,monospace;
}

.support{
    display:inline-block;
    margin-top:18px;

    color:#60a5fa;
    text-decoration:none;
}

.version{
    color:#60a5fa;
    font-size:11px;
}

</style>
</head>

<body>

<div class="card">

<h1>
PX Panel
</h1>

<div class="version">
13.6.1
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




@app.post("/api/mix-sub")
async def mix_subscription(request: Request, _=Depends(require_auth)):
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="JSON نامعتبر")
    ids = body.get("link_ids") or []
    if not isinstance(ids, list) or len(ids) < 2:
        raise HTTPException(status_code=400, detail="حداقل ۲ کانفیگ انتخاب کنید")
    if len(ids) > 40:
        raise HTTPException(status_code=400, detail="حداکثر ۴۰ کانفیگ")
    host = get_host(request)
    lines = []
    used_names = set()
    total_used = 0
    total_limit = 0
    labels = []
    async with LINKS_LOCK:
        for lid in ids:
            link = LINKS.get(lid)
            if not link or not is_link_allowed(link):
                continue
            labels.append(str(link.get("label") or lid[:8]))
            total_used += int(link.get("used_bytes", 0) or 0)
            total_limit += int(link.get("limit_bytes", 0) or 0)
            name = random_config_name(used_names)
            used_names.add(name)
            lines.append(generate_vless_link(
                lid, host, remark=name,
                protocol=link.get("protocol", DEFAULT_PROTOCOL),
                fingerprint=link.get("fingerprint", DEFAULT_FINGERPRINT),
                alpn=link.get("alpn"),
                port=link.get("port", DEFAULT_PORT),
            ))
    if not lines:
        raise HTTPException(status_code=400, detail="هیچ کانفیگ معتبری انتخاب نشده")
    # stats first line
    vol = f"{fmt_bytes(total_used)}/{fmt_bytes(total_limit)}" if total_limit > 0 else f"{fmt_bytes(total_used)}/∞"
    mix_label = "Mix-" + random_config_name()[:6]
    stats = f"{mix_label} | {vol} | {len(lines)} configs"
    first = generate_vless_link(ids[0], "127.0.0.1", remark=stats, protocol="vless-ws")
    content = base64.b64encode(("\n".join([first] + lines)).encode()).decode()
    # store as a sub group for reuse
    sub_id, sub = await create_sub_group(name=mix_label, desc="مخلوط‌سازی کانفیگ‌ها")
    async with SUBS_LOCK:
        if sub_id in SUBS:
            SUBS[sub_id]["link_ids"] = list(ids)
    await save_state()
    return {
        "ok": True,
        "sub_url": f"https://{host}/sub-group/{sub['uuid_key']}",
        "name": mix_label,
        "count": len(lines),
        "content_preview": stats,
    }


@app.get("/api/categories")
async def list_categories(_=Depends(require_auth)):
    items = [{**cat, "id": cid} for cid, cat in CATEGORIES.items()]
    items.sort(key=lambda x: int(x.get("number", 0)))
    return {"categories": items}

@app.post("/api/categories")
async def create_category(request: Request, _=Depends(require_auth)):
    if len(CATEGORIES) >= 10:
        raise HTTPException(status_code=400, detail="حداکثر ۱۰ دسته‌بندی")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="JSON نامعتبر")
    name = str(body.get("name") or "دسته جدید").strip()[:40]
    used = {int(x.get("number", 0)) for x in CATEGORIES.values()}
    num = 0
    while num in used:
        num += 1
    cid = str(num)
    limit_value = safe_float(body.get("limit_value", 0))
    limit_unit = str(body.get("limit_unit") or "GB").upper()
    limit_bytes = 0 if limit_value <= 0 else parse_size_to_bytes(limit_value, limit_unit)
    speed_value = safe_float(body.get("speed_limit_value", 0))
    speed_bytes = 0 if speed_value <= 0 else parse_speed_to_bytes(speed_value, "MBIT")
    raw_clean = body.get("clean_ips") or ""
    if isinstance(raw_clean, list):
        clean_ips = [str(x).strip() for x in raw_clean if str(x).strip()]
    else:
        clean_ips = [x.strip() for x in str(raw_clean).replace(",", "\n").splitlines() if x.strip()]
    record = {
        "id": cid, "name": name, "number": num,
        "limit_bytes": limit_bytes,
        "expires_days": safe_int(body.get("expires_days", 0), minimum=0),
        "connection_limit": safe_int(body.get("connection_limit", 0), minimum=0),
        "speed_limit_bytes": speed_bytes,
        "ip_limit": safe_int(body.get("ip_limit", 0), minimum=0),
        "clean_ips": clean_ips,
        "random_name": bool(body.get("random_name", False)),
        "single_user": bool(body.get("single_user", False)),
        "created_at": datetime.now().isoformat(),
    }
    CATEGORIES[cid] = record
    await save_state()
    return {"ok": True, **record}


@app.patch("/api/categories/{cid}")
async def update_category(cid: str, request: Request, _=Depends(require_auth)):
    if cid not in CATEGORIES:
        raise HTTPException(status_code=404, detail="یافت نشد")
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="JSON نامعتبر")
    cat = CATEGORIES[cid]
    if "name" in body:
        cat["name"] = str(body.get("name") or cat["name"]).strip()[:40]
    if "limit_value" in body:
        lv = safe_float(body.get("limit_value", 0))
        unit = str(body.get("limit_unit") or "GB").upper()
        cat["limit_bytes"] = 0 if lv <= 0 else parse_size_to_bytes(lv, unit)
    if "expires_days" in body:
        cat["expires_days"] = safe_int(body.get("expires_days", 0), minimum=0)
    if "connection_limit" in body:
        cat["connection_limit"] = safe_int(body.get("connection_limit", 0), minimum=0)
    if "speed_limit_value" in body:
        sv = safe_float(body.get("speed_limit_value", 0))
        cat["speed_limit_bytes"] = 0 if sv <= 0 else parse_speed_to_bytes(sv, "MBIT")
    if "ip_limit" in body:
        cat["ip_limit"] = safe_int(body.get("ip_limit", 0), minimum=0)
    if "clean_ips" in body:
        raw = body.get("clean_ips") or ""
        if isinstance(raw, list):
            cat["clean_ips"] = [str(x).strip() for x in raw if str(x).strip()]
        else:
            cat["clean_ips"] = [x.strip() for x in str(raw).replace(",", "\n").splitlines() if x.strip()]
    if "random_name" in body:
        cat["random_name"] = bool(body.get("random_name"))
    if "single_user" in body:
        cat["single_user"] = bool(body.get("single_user"))
    await save_state()
    return {"ok": True, **cat}

@app.delete("/api/categories/{cid}")
async def delete_category(cid: str, _=Depends(require_auth)):
    if cid in ("0", "1"):
        raise HTTPException(status_code=400, detail="پیش‌فرض قابل حذف نیست")
    if cid not in CATEGORIES:
        raise HTTPException(status_code=404, detail="یافت نشد")
    del CATEGORIES[cid]
    for link in LINKS.values():
        if str(link.get("category_id")) == cid:
            link["category_id"] = "0"
    await save_state()
    return {"ok": True}

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
PX Panel 13.6.1
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
*::-webkit-scrollbar{width:6px;height:6px}
*::-webkit-scrollbar-track{background:transparent}
*::-webkit-scrollbar-thumb{background:rgba(255,255,255,.12);border-radius:99px}
*::-webkit-scrollbar-thumb:hover{background:rgba(255,255,255,.2)}
*{scrollbar-width:thin;scrollbar-color:rgba(255,255,255,.12) transparent}


body{
    min-height:100vh;

    color:#fff;

    font-family:"Vazirmatn",sans-serif;

    background:
        radial-gradient(
            circle at 10% 0%,
            rgba(37,99,235,.13),
            transparent 25%
        ),
        radial-gradient(
            circle at 100% 100%,
            rgba(59,130,246,.10),
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
            #2563eb,
            #3b82f6
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
    color:#60a5fa;
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
            #2563eb,
            #3b82f6
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
.stat::after{content:"";position:absolute;right:0;bottom:0;left:0;height:2px;background:var(--stat-color,#60a5fa);opacity:.8}
.stat:nth-child(1){--stat-color:#60a5fa}.stat:nth-child(2){--stat-color:#4ade80}.stat:nth-child(3){--stat-color:#f59e0b}.stat:nth-child(4){--stat-color:#60a5fa}.stat:nth-child(5){--stat-color:#fb7185}.stat:nth-child(6){--stat-color:#22d3ee}.stat-value{color:var(--stat-color,#fff)}


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
        rgba(37,99,235,.18);
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

    color:#93c5fd;

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
        rgba(37,99,235,.06);

    border:
        1px solid
        rgba(37,99,235,.13);

    color:rgba(255,255,255,.62);

    line-height:1.9;

    font-size:10px;
}

.notice strong{
    color:#93c5fd;
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
        rgba(37,99,235,.55);
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
            #2563eb,
            #3b82f6
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
.login-notice-head{display:flex;align-items:center;gap:12px;margin-bottom:16px}.login-notice-icon{width:42px;height:42px;display:flex;align-items:center;justify-content:center;border-radius:13px;background:rgba(37,99,235,.14);border:1px solid rgba(129,140,248,.22);color:#93c5fd;font-size:18px}.login-notice h3{margin:0;font-size:15px}.login-notice p{margin:5px 0 0;color:rgba(255,255,255,.42);font-size:9px;line-height:1.9}.notice-downloads{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;margin-top:14px}.notice-download{display:block;padding:12px;border-radius:14px;text-decoration:none;color:#fff;background:rgba(255,255,255,.035);border:1px solid rgba(255,255,255,.07);transition:.2s ease}.notice-download:hover{transform:translateY(-2px);border-color:rgba(129,140,248,.30);background:rgba(129,140,248,.07)}.notice-download strong{display:block;font-size:10px}.notice-download span{display:block;margin-top:3px;color:rgba(255,255,255,.36);font-size:8px}.login-notice-body{margin-top:14px;padding:14px;border-radius:14px;background:rgba(255,255,255,.025);border:1px solid rgba(255,255,255,.06);color:rgba(255,255,255,.62);font-size:10px;line-height:2}.login-notice-body b{color:#fff}.login-notice-actions{margin-top:14px;display:flex;gap:8px}.login-notice-actions button{flex:1;padding:11px;border:0;border-radius:12px;color:#fff;background:linear-gradient(135deg,#2563eb,#3b82f6);font-family:inherit;cursor:pointer}@keyframes noticeIn{from{opacity:0;transform:translateY(16px) scale(.985)}to{opacity:1;transform:translateY(0) scale(1)}}
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
    border:1px solid rgba(96,165,250,.18);
    background:
        radial-gradient(circle at 90% 0%,rgba(37,99,235,.13),transparent 32%),
        linear-gradient(180deg,rgba(25,25,37,.98),rgba(11,11,16,.99));
    box-shadow:0 35px 110px rgba(0,0,0,.62),inset 0 1px rgba(255,255,255,.04);
}
.login-notice-head{align-items:flex-start}
.login-notice-icon{
    width:46px;height:46px;min-width:46px;border-radius:15px;
    display:flex;align-items:center;justify-content:center;
    background:rgba(37,99,235,.12);
    border:1px solid rgba(96,165,250,.22);
    color:#93c5fd;
}
.login-notice-icon svg{width:24px;height:24px;display:block}
.login-notice h3{font-size:15px;letter-spacing:-.2px}
.login-notice p{font-size:10px;line-height:2;color:rgba(255,255,255,.46)}
.login-notice-body{
    margin-top:12px;
    padding:15px;
    border-radius:16px;
    background:rgba(37,99,235,.065);
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
PX Panel
</div>

<div class="brand-desc">
داشبورد مدیریت سرویس
</div>
<div class="brand-version">13.6.1</div>
<div style="margin-top:5px;font-size:10px;display:flex;align-items:center;gap:6px">
<svg width="14" height="14" viewBox="0 0 24 24" fill="#ff0000"><path d="M23.5 6.2a3 3 0 0 0-2.1-2.1C19.5 3.5 12 3.5 12 3.5s-7.5 0-9.4.6A3 3 0 0 0 .5 6.2 31.5 31.5 0 0 0 0 12a31.5 31.5 0 0 0 .5 5.8 3 3 0 0 0 2.1 2.1c1.9.6 9.4.6 9.4.6s7.5 0 9.4-.6a3 3 0 0 0 2.1-2.1A31.5 31.5 0 0 0 24 12a31.5 31.5 0 0 0-.5-5.8zM9.75 15.5v-7l6.5 3.5-6.5 3.5z"/></svg>
<a href="https://www.youtube.com/@LogicSec_YT" target="_blank" rel="noopener" style="color:#93c5fd;text-decoration:none">LogicSec_YT</a>
</div>

</div>

</div>

<div class="top-actions">

<button class="top-btn primary" onclick="openAutoModal()" title="ساخت خودکار" style="min-width:44px">
<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.7"><rect x="3" y="8" width="18" height="12" rx="2"/><circle cx="12" cy="14" r="2"/><path d="M8 8V6a4 4 0 0 1 8 0v2"/></svg>
</button>
<button class="top-btn" onclick="openManualModal()" title="ساخت دستی" style="min-width:44px">
<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M12 5v14M5 12h14"/></svg>
</button>
<button class="top-btn" onclick="openCategoryModal()" title="دسته‌بندی" style="min-width:44px">
<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M4 6h16M4 12h10M4 18h14"/></svg>
</button>
<button class="top-btn" onclick="openMixModal()" title="مخلوط‌سازی کانفیگ‌ها" style="min-width:44px;background:rgba(239,68,68,.18);border-color:rgba(239,68,68,.35);color:#fca5a5">
<svg viewBox="0 0 24 24" width="18" height="18" fill="none" stroke="currentColor" stroke-width="1.7"><path d="M16 3h5v5M4 20L21 3M21 16v5h-5M15 15l6 6M4 4l5 5"/></svg>
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
ترافیک مصرفی
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
ریکویست
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
تایم فعال بودن
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
مدیریت کانفیگ‌هـا
</div>

<div class="panel-sub" style="display: flex; align-items: center; justify-content: center; gap: 6px; font-size: 0.75rem; color: rgba(255, 255, 255, 0.6); padding: 12px; text-align: center; direction: rtl;">
  <span style="opacity: 0.8;">پشتیبانــی:</span>
  <a href="https://t.me/logictop12" target="_blank" rel="noopener noreferrer" style="font-weight: 500; color: #34d399; text-decoration: none; transition: color 0.2s ease;" onmouseover="this.style.color='#6ee7b7'; this.style.textDecoration='underline';" onmouseout="this.style.color='#34d399'; this.style.textDecoration='none';">
    @logictop12
  </a>
</div>

</div>

<button
class="top-btn primary"
onclick="refresh()"
>
↻ بروزرسانـی
</button>

</div>

<div class="table-wrap">

<table>

<thead>

<tr>

<th>دسته</th>
<th>
نـام
</th>

<th>
پروتـکل
</th>

<th>
وضعیـت
</th>

<th>
مصـرف
</th>

<th>
زمـان
</th>

<th>
اتصـال
</th>

<th>
VLESS
</th>

<th>
عملیـات
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
<div class="panel-title">آخرین فعالیت‌ها</div>
<div class="panel-sub">لاگ زنده سیستم · حداکثر ۱۵۰ رویداد</div>
</div>

<button class="top-btn" onclick="refresh()" style="font-size:10px">↻ بروزرسانی</button>

</div>

<div id="logs" style="padding:10px 12px;max-height:340px;overflow:auto">
<div style="text-align:center;color:rgba(255,255,255,.3);padding:24px;font-size:11px">در حال بارگذاری...</div>
</div>

</div>


<div class="panel">

<div class="panel-head">

<div>
<div class="panel-title">
دانلود برنامه اتصــال
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
 مهـم | آپدیـت برنامـه اتصـال
</strong>

<br>

دوستان عزیـز ❤️
برای اینکـه کانفیگ‌هـای جدیـد بهتریـن
سازگـــاری، پایداری و عملکرد رو داشته باشن،
لطفـاً برنامـه‌ای کــــــــه بـرای اتصـال استفـاده می‌کنیـد
رو بــه آخرین نسخـــه آپدیــت کنیــد. 🔄⚡️

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
ساخـت کانفیـگ دستــی
</div>

<button class="close" onclick="closeManualModal()" style="display: flex; align-items: center; justify-content: center; width: 32px; height: 32px; background: rgba(255, 255, 255, 0.05); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 50%; color: rgba(255, 255, 255, 0.7); font-size: 1.25rem; line-height: 1; cursor: pointer; transition: all 0.2s;" onmouseover="this.style.background='rgba(255, 255, 255, 0.1)'; this.style.color='#ffffff';" onmouseout="this.style.background='rgba(255, 255, 255, 0.05)'; this.style.color='rgba(255, 255, 255, 0.7)';">
  ×
</button>

</div>

<div class="form-grid">

<div class="field">

<label>
اسـم کانفیـگ
</label>

<input
id="manualName"
placeholder="اسم کانفیگ"
/>

</div>


<div class="field" style="margin-bottom: 16px;">
  <label style="display: flex; align-items: center; justify-content: space-between; font-size: 0.875rem; color: #ffffff; margin-bottom: 6px;">
    <span>پروتکــل (بتا)</span>
    <span style="font-size: 0.75rem; color: #34d399; background-color: rgba(52, 211, 153, 0.1); padding: 2px 8px; border-radius: 9999px;">پیشنهادی: XHTTP Packet Up</span>
  </label>
  <select id="manualProtocol" style="width: 100%; background-color: #1f2937; color: #ffffff; padding: 10px 12px; border: 1px solid rgba(255, 255, 255, 0.15); border-radius: 8px; font-size: 0.875rem; outline: none; cursor: pointer;">
    <option value="vless-ws" style="background-color: #1f2937; color: #ffffff;">VLESS WebSocket</option>
    <option value="xhttp-packet-up" style="background-color: #1f2937; color: #ffffff;">XHTTP Packet Up (پیشنهادی)</option>
    <option value="xhttp-stream-up" style="background-color: #1f2937; color: #ffffff;">XHTTP Stream Up</option>
    <option value="xhttp-stream-one" style="background-color: #1f2937; color: #ffffff;">XHTTP Stream One</option>
    <option value="vmess-ws" style="background-color: #1f2937; color: #ffffff;">VMess WebSocket</option>
    <option value="trojan-ws" style="background-color: #1f2937; color: #ffffff;">Trojan WebSocket</option>
    <option value="shadowsocks" style="background-color: #1f2937; color: #ffffff;">Shadowsocks</option>
    <option value="socks5" style="background-color: #1f2937; color: #ffffff;">SOCKS5</option>
    <option value="http" style="background-color: #1f2937; color: #ffffff;">HTTP Proxy</option>
    <option value="hysteria2" style="background-color: #1f2937; color: #ffffff;">Hysteria 2</option>
    <option value="tuic" style="background-color: #1f2937; color: #ffffff;">TUIC</option>
    <option value="highspeed-demo" style="background-color: #1f2937; color: #60a5fa;">HighSpeed Upload/Download (دمو)</option>
    <option value="gaming-lite-demo" style="background-color: #1f2937; color: #60a5fa;">Gaming Lite (دمو)</option>
  </select>
</div>

<div class="field">
<label>دسته‌بندی</label>
<select id="manualCategory" style="width:100%;background:#1f2937;color:#fff;padding:10px;border:1px solid rgba(255,255,255,.15);border-radius:8px">
<option value="0">0 — عمومی</option>
<option value="1">1 — VIP</option>
</select>
</div>
<div class="field">
<label>تعداد کانفیگ در ساب (۱-۴۰)</label>
<input id="manualConfigCount" type="number" min="1" max="40" value="1" />
</div>
<div class="field full">
<label>IP تمیز (اختیاری)</label>
<textarea id="manualCleanIps" style="min-height:60px;direction:ltr" placeholder="1.2.3.4"></textarea>
</div>
<div class="field">
<label style="display:flex;align-items:center;gap:8px;cursor:pointer" onclick="toggleAlarmCheck()">
<span id="alarmToggle" style="display:inline-flex;width:20px;height:20px;border-radius:5px;border:2px solid #6b7280;background:#374151;align-items:center;justify-content:center;color:transparent;font-size:12px">✓</span>
<input type="checkbox" id="manualAlarm" style="display:none">
آلارم انقضا/حجم
</label>
</div>

<div class="field">

<label>
حجـم
</label>

<input
id="manualVolume"
type="number"
min="0"
placeholder="0 = نامحدود"
/>

</div>


<div class="field" style="margin-bottom: 16px;">
  <label style="display: flex; align-items: center; justify-content: space-between; font-size: 0.875rem; color: #ffffff; margin-bottom: 6px;">
    <span>واحد حجـم</span>
    <span style="font-size: 0.75rem; color: #34d399; background-color: rgba(52, 211, 153, 0.1); padding: 2px 8px; border-radius: 9999px;">پیشنهادی: GB</span>
  </label>
  <select id="manualVolumeUnit" style="width: 100%; background-color: #1f2937; color: #ffffff; padding: 10px 12px; border: 1px solid rgba(255, 255, 255, 0.15); border-radius: 8px; font-size: 0.875rem; outline: none; cursor: pointer;">
    <option value="GB" style="background-color: #1f2937; color: #ffffff;">GB</option>
    <option value="MB" style="background-color: #1f2937; color: #ffffff;">MB</option>
    <option value="TB" style="background-color: #1f2937; color: #ffffff;">TB</option>
  </select>
</div>


<div class="field">

<label>
تعـداد روز
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
محدودیـت IP
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
محدودیـت اتصـال
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
محدودیـت سرعـت
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

<select id="manualFingerprint" style="width: 100%; background-color: #1f2937; color: #ffffff; padding: 10px 12px; border: 1px solid rgba(255, 255, 255, 0.15); border-radius: 8px; font-size: 0.875rem; outline: none; cursor: pointer;">
  <option value="chrome" style="background-color: #1f2937; color: #ffffff;">Chrome</option>
  <option value="firefox" style="background-color: #1f2937; color: #ffffff;">Firefox</option>
  <option value="safari" style="background-color: #1f2937; color: #ffffff;">Safari</option>
  <option value="ios" style="background-color: #1f2937; color: #ffffff;">iOS</option>
  <option value="android" style="background-color: #1f2937; color: #ffffff;">Android</option>
  <option value="edge" style="background-color: #1f2937; color: #ffffff;">Edge</option>
  <option value="360" style="background-color: #1f2937; color: #ffffff;">360</option>
  <option value="qq" style="background-color: #1f2937; color: #ffffff;">QQ</option>
  <option value="random" style="background-color: #1f2937; color: #ffffff;">Random</option>
  <option value="randomized" style="background-color: #1f2937; color: #ffffff;">Randomized</option>
</select>

</div>


<div class="field">

<label style="display: flex; align-items: center; justify-content: space-between; font-size: 0.875rem; color: #ffffff; margin-bottom: 6px;">
  <span>Fragment</span>
  <span style="font-size: 0.75rem; color: #34d399; background-color: rgba(52, 211, 153, 0.1); padding: 2px 8px; border-radius: 9999px;">پیشنهادی: خاموش</span>
</label>

<select id="manualFragment" style="background-color: #1f2937; color: #ffffff; padding: 8px 12px; border: 1px solid rgba(255, 255, 255, 0.15); border-radius: 8px; font-size: 0.875rem; outline: none; cursor: pointer;">
  <option value="off" style="background-color: #1f2937; color: #ffffff;">خاموش</option>
  <option value="safe" style="background-color: #1f2937; color: #ffffff;">Safe</option>
  <option value="balanced" style="background-color: #1f2937; color: #ffffff;">Balanced</option>
  <option value="aggressive" style="background-color: #1f2937; color: #ffffff;">Aggressive</option>
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
یادداشــت
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

ساخـت خودکــار

</div>



<button class="close" onclick="closeAutoModal()" style="display: flex; align-items: center; justify-content: center; width: 32px; height: 32px; background: rgba(255, 255, 255, 0.05); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 50%; color: rgba(255, 255, 255, 0.7); font-size: 1.25rem; line-height: 1; cursor: pointer; transition: all 0.2s;" onmouseover="this.style.background='rgba(255, 255, 255, 0.1)'; this.style.color='#ffffff';" onmouseout="this.style.background='rgba(255, 255, 255, 0.05)'; this.style.color='rgba(255, 255, 255, 0.7)';">
  ×
</button>



</div>



<div class="form-grid" style="margin-top:14px">
<div class="field"><label>دسته‌بندی</label>
<select id="autoCategory" style="width:100%;background:#1f2937;color:#fff;padding:10px;border:1px solid rgba(255,255,255,.15);border-radius:8px">
<option value="0">0 — عمومی</option><option value="1">1 — VIP</option>
</select></div>
<div class="field"><label>تعداد کانفیگ (۱-۴۰)</label>
<input id="autoConfigCount" type="number" min="1" max="40" value="1" /></div>
<div class="field">

<label>پروتکـل</label>

<select id="autoProtocol" style="width: 100%; background-color: #1f2937; color: #ffffff; padding: 10px 12px; border: 1px solid rgba(255, 255, 255, 0.15); border-radius: 8px; font-size: 0.875rem; outline: none; cursor: pointer;">
  <option value="vless-ws" style="background-color: #1f2937; color: #ffffff;">VLESS WebSocket</option>
  <option value="xhttp-packet-up" style="background-color: #1f2937; color: #ffffff;">XHTTP Packet Up</option>
  <option value="xhttp-stream-up" style="background-color: #1f2937; color: #ffffff;">XHTTP Stream Up</option>
  <option value="xhttp-stream-one" style="background-color: #1f2937; color: #ffffff;">XHTTP Stream One</option>
  <option value="vmess-ws" style="background-color: #1f2937; color: #ffffff;">VMess WebSocket</option>
  <option value="trojan-ws" style="background-color: #1f2937; color: #ffffff;">Trojan WebSocket</option>
  <option value="shadowsocks" style="background-color: #1f2937; color: #ffffff;">Shadowsocks</option>
  <option value="socks5" style="background-color: #1f2937; color: #ffffff;">SOCKS5</option>
  <option value="http" style="background-color: #1f2937; color: #ffffff;">HTTP Proxy</option>
  <option value="hysteria2" style="background-color: #1f2937; color: #ffffff;">Hysteria 2</option>
  <option value="tuic" style="background-color: #1f2937; color: #ffffff;">TUIC</option>
  <option value="highspeed-demo" style="background-color: #1f2937; color: #60a5fa;">HighSpeed Upload/Download (دمو)</option>
  <option value="gaming-lite-demo" style="background-color: #1f2937; color: #60a5fa;">Gaming Lite (دمو)</option>
  <option value="xhttp-packet-up" style="background-color: #1f2937; color: #60a5fa;">XHTTP Packet Up</option>
  <option value="xhttp-stream-up" style="background-color: #1f2937; color: #60a5fa;">XHTTP Stream Up</option>
</select>

</div>

<div class="field" style="margin-bottom: 16px;">

  <label style="display: flex; align-items: center; justify-content: space-between; font-size: 0.875rem; color: #ffffff; margin-bottom: 6px;">

    <span>پروفایـل امنیتـی</span>

    <span style="font-size: 0.75rem; color: #34d399; background-color: rgba(52, 211, 153, 0.1); padding: 2px 8px; border-radius: 9999px;">پیشنهادی: Maximum</span>

  </label>

  <select id="autoProfile" style="width: 100%; background-color: #1f2937; color: #ffffff; padding: 10px 12px; border: 1px solid rgba(255, 255, 255, 0.15); border-radius: 8px; font-size: 0.875rem; outline: none; cursor: pointer;">

    <option value="balanced" style="background-color: #1f2937; color: #ffffff;">Balanced</option>

    <option value="gaming" style="background-color: #1f2937; color: #ffffff;">Gaming</option>

    <option value="maximum" style="background-color: #1f2937; color: #ffffff;">Maximum</option>

    <option value="normal" style="background-color: #1f2937; color: #ffffff;">Normal</option>

  </select>

</div>

</div>



<div

style="

color:rgba(255,255,255,.55);

font-size:11px;

line-height:2;

">



اسم کانفیگ ها کاملا رندوم

<code>pxpanel_********</code>

ساخته می‌شود.



<br>



حجـم: <b>نامحدود</b>



<br>



زمـان: <b>نامحدود</b>



<br>



محدودیـت ایپـی: <b>نامحدود</b>



<br>



محدودیـت سرعـت: <b>نامحدود</b>



<br>



محدودیـت اتصال همزمـان: <b>نامحدود</b>



<br>



پروتکـل:

<b>VLESS WebSocket</b>



<br>



پورت:

<b>443</b>



</div>



<div class="modal-actions">



<button

class="modal-btn secondary"

onclick="closeAutoModal()"

>

لغو

</button>



<button

class="modal-btn primary"

onclick="createAuto()"

>

ساخت

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
تغییر رمز پنـل
</div>

<button class="close" onclick="closePasswordModal()" style="display: flex; align-items: center; justify-content: center; width: 32px; height: 32px; background: rgba(255, 255, 255, 0.05); border: 1px solid rgba(255, 255, 255, 0.1); border-radius: 50%; color: rgba(255, 255, 255, 0.7); font-size: 1.25rem; line-height: 1; cursor: pointer; transition: all 0.2s;" onmouseover="this.style.background='rgba(255, 255, 255, 0.1)'; this.style.color='#ffffff';" onmouseout="this.style.background='rgba(255, 255, 255, 0.05)'; this.style.color='rgba(255, 255, 255, 0.7)';">
  ×
</button>

</div>

<div class="form-grid">

<div class="field full">

<label>
رمز فعلـی
</label>

<input
id="currentPassword"
type="password"
/>

</div>

<div class="field">

<label>
رمز جدیـد
</label>

<input
id="newPassword"
type="password"
/>

</div>

<div class="field">

<label>
تکرار رمز جدیـد
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
لغو
</button>

<button
class="modal-btn primary"
onclick="changePassword()"
>
ذخیره رمـز عبور
</button>

</div>

</div>

</div>


    <!-- LOGIN NOTICE START -->
<div id="loginNoticeModal" class="login-notice-backdrop" role="dialog" aria-modal="true" aria-labelledby="regionNoticeTitle">
  <div class="login-notice">
    <div class="login-notice-head">
      <div class="login-notice-icon">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" aria-hidden="true">
          <path d="M12 3a9 9 0 1 0 9 9"/>
          <path d="M12 7v5l3 2"/>
          <path d="M16.5 3.5h4v4"/>
          <path d="m20.5 3.5-5 5"/>
        </svg>
      </div>
      <div>
        <h3 id="regionNoticeTitle">راهنمای اتصال سرویس</h3>
        <p>اطلاعیه مهم منطقه‌ای پیش از اتصال کانفیگ‌ها</p>
      </div>
    </div>
    <div class="login-notice-body">
      <p><b>نکته:</b> برای استفاده، لینک اشتراک (SUB) را در برنامه وارد (Import / Subscription) کرده یا از لینک مستقیم VLESS استفاده کنید.</p>
      <div class="region-warning" role="alert">
        <div class="warning-title">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" aria-hidden="true">
            <path d="m12 3 9 17H3L12 3Z"/>
            <path d="M12 9v5"/>
            <path d="M12 17h.01"/>
          </svg>
          هشدار منطقه‌ای اتصال
        </div>
        <p>در صورتی که پنل با موفقیت نصب شد اما کانفیگ‌ها پینگ نداشتند، دامنه مسدود شده است؛ لطفاً دامنه جدیدی بسازید.</p>
      </div>
    </div>
    <div class="notice-downloads">
      <a class="notice-download" href="https://github.com/2dust/v2rayNG/releases/latest" target="_blank" rel="noopener noreferrer">
        <strong>v2rayNG</strong>
        <span>اندروید</span>
      </a>
      <a class="notice-download" href="https://github.com/2dust/v2rayN/releases/latest" target="_blank" rel="noopener noreferrer">
        <strong>v2rayN</strong>
        <span>ویندوز / مک / لینوکس</span>
      </a>
      <a class="notice-download" href="https://github.com/hiddify/hiddify-app/releases/latest" target="_blank" rel="noopener noreferrer">
        <strong>Hiddify</strong>
        <span>چندپلتفرمی</span>
      </a>
    </div>
    <div class="login-notice-actions">
      <button type="button" onclick="closeLoginNotice()">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true">
          <path d="m5 12 4 4L19 6"/>
        </svg>
        متوجه شدم
      </button>
    </div>
  </div>
</div>
<!-- LOGIN NOTICE END -->

<div id="mixModal" class="modal-backdrop">
<div class="modal" style="max-width:640px">
<div class="modal-head"><div class="modal-title">مخلوط‌سازی کانفیگ‌ها</div>
<button class="close" onclick="closeMixModal()">×</button></div>
<p style="color:rgba(255,255,255,.55);font-size:11px;line-height:1.9;margin:0 0 12px">
چند کانفیگ از لیست «مدیریت کانفیگ‌ها» را انتخاب کنید تا داخل یک ساب واحد ترکیب شوند.
حداقل ۲ و حداکثر ۴۰ کانفیگ. بعد از ساخت، لینک ساب مخلوط در اختیار شماست.
</p>
<div id="mixList" style="max-height:280px;overflow:auto;margin-bottom:12px"></div>
<div class="modal-actions">
<button class="modal-btn secondary" onclick="closeMixModal()">بستن</button>
<button class="modal-btn primary" style="background:linear-gradient(135deg,#dc2626,#ef4444)" onclick="doMixConfigs()">ساخت ساب مخلوط</button>
</div></div></div>

<div id="categoryModal" class="modal-backdrop">
<div class="modal" style="max-width:620px">
<div class="modal-head"><div class="modal-title">دسته‌بندی‌ها</div>
<button class="close" onclick="closeCategoryModal()">×</button></div>
<div id="categoryList" style="font-size:11px;margin-bottom:12px"></div>
<div class="form-grid">
<div class="field full"><label>نام</label><input id="catName" placeholder="نام دسته‌بندی" /></div>
<div class="field"><label>حجم</label><input id="catVolume" type="number" min="0" placeholder="0 = نامحدود" /></div>
<div class="field"><label>واحد</label><select id="catVolumeUnit"><option value="GB">GB</option><option value="MB">MB</option><option value="TB">TB</option></select></div>
<div class="field"><label>روز</label><input id="catDays" type="number" min="0" placeholder="0 = نامحدود" /></div>
<div class="field"><label>IP Limit</label><input id="catIp" type="number" min="0" placeholder="0 = نامحدود" /></div>
<div class="field"><label>اتصال</label><input id="catConn" type="number" min="0" placeholder="0 = نامحدود" /></div>
<div class="field"><label>سرعت Mbit</label><input id="catSpeed" type="number" min="0" placeholder="0 = نامحدود" /></div>
<div class="field full"><label>IP تمیز</label><textarea id="catClean" style="min-height:48px;direction:ltr" placeholder="اختیاری"></textarea></div>
<div class="field"><label><input type="checkbox" id="catRandom"> اسم تصادفی</label></div>
<div class="field"><label><input type="checkbox" id="catSingle"> تک‌کاربره</label></div>
<input type="hidden" id="catEditId" value="" />
</div>
<div class="modal-actions">
<button class="modal-btn secondary" onclick="closeCategoryModal()">بستن</button>
<button class="modal-btn primary" onclick="createCategory()">ساخت</button>
</div></div></div>

<div id="toast" class="toast"></div>


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
            api("/api/activity"),
            api("/api/categories")
        ]);
    if(results[3]&&results[3].categories){
      var opts=results[3].categories.map(function(cat){return "<option value='"+cat.id+"'>"+cat.number+" — "+escapeHtml(cat.name)+"</option>";}).join("");
      ["manualCategory","autoCategory"].forEach(function(id){var s=document.getElementById(id);if(s){var v=s.value;s.innerHTML=opts;if(v)s.value=v;}});
    }

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
                    colspan="9"
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

<td style="text-align:center;font-weight:800;color:#60a5fa">${link.category_number != null ? link.category_number : 0}</td>
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
<span style="display:inline-block;width:10px;height:10px;border-radius:50%;margin-left:5px;background:${link.status_color==='green'?'#22c55e':(link.status_color==='red'?'#ef4444':'#6b7280')}"></span>
<span class="badge ${link.active ? 'active' : 'off'}">${link.active ? 'فعال' : 'غیرفعال'}</span>
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

${link.show_vless !== false && link.vless ? '<button class="action primary" type="button" data-action="copy-vless">VLESS</button>' : ''}

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


    if(activity && activity.logs){
        var box = document.getElementById("logs");
        if(box){
            var items = activity.logs.slice().reverse();
            if(!items.length){
                box.innerHTML = "<div style='text-align:center;color:rgba(255,255,255,.3);padding:24px;font-size:11px'>فعالیتی ثبت نشده است</div>";
            } else {
                var html = "";
                items.forEach(function(item){
                    var level = (item.level || "info").toLowerCase();
                    var color = "#60a5fa";
                    var bg = "rgba(37,99,235,.08)";
                    var border = "rgba(96,165,250,.18)";
                    var icon = "ℹ";
                    if(level === "ok" || level === "success"){
                        color = "#4ade80"; bg = "rgba(34,197,94,.08)"; border = "rgba(74,222,128,.2)"; icon = "✓";
                    } else if(level === "err" || level === "error"){
                        color = "#f87171"; bg = "rgba(239,68,68,.08)"; border = "rgba(248,113,113,.2)"; icon = "!";
                    } else if(level === "warn" || level === "warning"){
                        color = "#fbbf24"; bg = "rgba(245,158,11,.08)"; border = "rgba(251,191,36,.2)"; icon = "⚠";
                    }
                    var t = item.time || "";
                    try {
                        if(t){
                            var d = new Date(t);
                            if(!isNaN(d.getTime())){
                                t = d.toLocaleString("fa-IR", {hour:"2-digit", minute:"2-digit", second:"2-digit", day:"2-digit", month:"2-digit"});
                            }
                        }
                    } catch(e){}
                    var kind = item.kind ? ("<span style='opacity:.55;margin-left:6px'>· " + escapeHtml(item.kind) + "</span>") : "";
                    html += "<div style='display:flex;gap:10px;align-items:flex-start;padding:10px 12px;margin-bottom:6px;border-radius:12px;background:" + bg + ";border:1px solid " + border + "'>";
                    html += "<div style='flex:0 0 28px;width:28px;height:28px;border-radius:9px;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:900;color:" + color + ";background:rgba(0,0,0,.2);border:1px solid " + border + "'>" + icon + "</div>";
                    html += "<div style='flex:1;min-width:0'>";
                    html += "<div style='font-size:11px;font-weight:600;color:rgba(255,255,255,.88);line-height:1.7'>" + escapeHtml(item.message || "") + "</div>";
                    html += "<div style='margin-top:3px;font-size:9px;color:rgba(255,255,255,.35);display:flex;gap:8px;flex-wrap:wrap'>";
                    html += "<span style='color:" + color + ";font-weight:700'>" + escapeHtml(level.toUpperCase()) + "</span>" + kind;
                    if(t) html += "<span style='margin-right:auto;direction:ltr'>" + escapeHtml(t) + "</span>";
                    html += "</div></div></div>";
                });
                box.innerHTML = html;
            }
        }
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
    const protocol = document.getElementById("autoProtocol")?.value || "vless-ws";
    const profile = document.getElementById("autoProfile")?.value || "balanced";
    const category_id = (document.getElementById("autoCategory")||{}).value || "0";
    const config_count = Number((document.getElementById("autoConfigCount")||{}).value || 1);
    closeAutoModal();
    showToast("در حال ساخت کانفیگ حرفه‌ای...");
    const result = await api("/api/links", {
        method:"POST",
        headers:{"Content-Type":"application/json"},
        body:JSON.stringify({protocol, profile, category_id, config_count, label:"", limit_value:0, expires_days:0})
    });
    if(!result || !result.ok) return;
    const config = result.config || result.vless || result.link || "";
    await copyText(config);
    showToast("کانفیگ ساخته شد و در کلیپ‌بورد قرار گرفت");
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
                .value,
        clean_ips: (document.getElementById("manualCleanIps")||{}).value || "",
        alarm_enabled: !!(document.getElementById("manualAlarm")||{}).checked,
        category_id: (document.getElementById("manualCategory")||{}).value || "0",
        config_count: Number((document.getElementById("manualConfigCount")||{}).value || 1)

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


function openMixModal(){
  var list=document.getElementById("mixList");
  if(!list)return;
  api("/api/links").then(function(data){
    if(!data||!data.links){list.innerHTML="<div class='empty'>کانفیگی نیست</div>";return;}
    var html="";
    data.links.forEach(function(link){
      if(!link.active)return;
      html+="<label style='display:flex;align-items:center;gap:10px;padding:8px 10px;border-radius:10px;background:rgba(255,255,255,.03);margin-bottom:5px;cursor:pointer'>";
      html+="<input type='checkbox' class='mix-check' value='"+link.uuid+"' style='width:16px;height:16px'>";
      html+="<span style='flex:1'><b>"+escapeHtml(link.label)+"</b> <span style='color:rgba(255,255,255,.35);font-size:9px'>"+escapeHtml(link.protocol||"")+"</span></span>";
      html+="<span style='color:#60a5fa;font-size:10px'>دسته "+(link.category_number!=null?link.category_number:0)+"</span>";
      html+="</label>";
    });
    list.innerHTML=html||"<div class='empty'>کانفیگ فعالی نیست</div>";
  });
  document.getElementById("mixModal").classList.add("open");
}
function closeMixModal(){document.getElementById("mixModal").classList.remove("open");}
async function doMixConfigs(){
  var ids=[];
  document.querySelectorAll(".mix-check:checked").forEach(function(el){ids.push(el.value);});
  if(ids.length<2){showToast("حداقل ۲ کانفیگ انتخاب کنید");return;}
  var res=await api("/api/mix-sub",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({link_ids:ids})});
  if(res&&res.ok){
    showToast("ساب مخلوط ساخته شد ("+res.count+")");
    if(res.sub_url){await copyText(res.sub_url);showToast("لینک ساب کپی شد");}
    closeMixModal();
  }
}

function toggleAlarmCheck(){
  var cb=document.getElementById("manualAlarm");
  var box=document.getElementById("alarmToggle");
  if(!cb||!box)return;
  cb.checked=!cb.checked;
  if(cb.checked){box.style.background="#22c55e";box.style.borderColor="#22c55e";box.style.color="#fff";}
  else{box.style.background="#374151";box.style.borderColor="#6b7280";box.style.color="transparent";}
}
function openCategoryModal(){loadCategoriesUI();document.getElementById("categoryModal").classList.add("open");}
function closeCategoryModal(){document.getElementById("categoryModal").classList.remove("open");}
async function loadCategoriesUI(){
  var data=await api("/api/categories");
  if(!data||!data.categories)return;
  window.__cats = data.categories;
  var list=document.getElementById("categoryList");
  var html=""; var opts="";
  data.categories.forEach(function(cat){
    opts+="<option value='"+cat.id+"'>"+cat.number+" — "+escapeHtml(cat.name)+"</option>";
    html+="<div style='display:flex;justify-content:space-between;align-items:center;padding:8px;border-radius:10px;background:rgba(255,255,255,.03);margin-bottom:5px;gap:8px'><span><b style='color:#60a5fa'>"+cat.number+"</b> — "+escapeHtml(cat.name);
    if(cat.single_user) html+=" <span style='color:#fbbf24;font-size:9px'>تک‌کاربره</span>";
    html+="</span><span style='display:flex;gap:4px'>";
    html+="<button class='action' type='button' onclick=\"editCategory('"+cat.id+"')\">ویرایش</button>";
    if(cat.id!=="0"&&cat.id!=="1") html+="<button class='action danger' type='button' onclick=\"deleteCategory('"+cat.id+"')\">حذف</button>";
    html+="</span></div>";
  });
  if(list) list.innerHTML=html;
  ["manualCategory","autoCategory"].forEach(function(id){var s=document.getElementById(id);if(s){var v=s.value;s.innerHTML=opts;if(v)s.value=v;}});
}
function editCategory(id){
  var cat=(window.__cats||[]).find(function(x){return x.id===id});
  if(!cat)return;
  document.getElementById("catEditId").value=id;
  document.getElementById("catName").value=cat.name||"";
  document.getElementById("catVolume").value="";
  document.getElementById("catDays").value=cat.expires_days||0;
  document.getElementById("catIp").value=cat.ip_limit||0;
  document.getElementById("catConn").value=cat.connection_limit||0;
  document.getElementById("catSpeed").value="";
  document.getElementById("catClean").value=(cat.clean_ips||[]).join("\n");
  document.getElementById("catRandom").checked=!!cat.random_name;
  document.getElementById("catSingle").checked=!!cat.single_user;
  showToast("در حال ویرایش: "+cat.name);
}

async function createCategory(){
  var body={name:(document.getElementById("catName").value||"").trim()||"دسته جدید",
    limit_value:Number(document.getElementById("catVolume").value||0),
    limit_unit:document.getElementById("catVolumeUnit").value,
    expires_days:Number(document.getElementById("catDays").value||0),
    ip_limit:Number(document.getElementById("catIp").value||0),
    connection_limit:Number(document.getElementById("catConn").value||0),
    speed_limit_value:Number(document.getElementById("catSpeed").value||0),
    clean_ips:(document.getElementById("catClean").value||"").trim(),
    random_name:!!document.getElementById("catRandom").checked,
    single_user:!!document.getElementById("catSingle").checked};
  var editId=(document.getElementById("catEditId")||{}).value||"";
  var res;
  if(editId){
    res=await api("/api/categories/"+encodeURIComponent(editId),{method:"PATCH",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
  } else {
    res=await api("/api/categories",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify(body)});
  }
  if(res&&res.ok){
    showToast(editId?"ویرایش شد":"ساخته شد");
    document.getElementById("catName").value="";
    document.getElementById("catEditId").value="";
    await loadCategoriesUI();
  }
}
async function deleteCategory(id){
  if(!confirm("حذف؟"))return;
  var res=await api("/api/categories/"+encodeURIComponent(id),{method:"DELETE"});
  if(res&&res.ok){showToast("حذف شد");await loadCategoriesUI();}
}

refresh();
setInterval(refresh, 3000);


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
                <div style="font-size:18px;font-weight:900;color:#fff;line-height:1.5;">به بهترین نسخه PX Panel خوش اومدید عشقا 💙</div>
                <div style="margin-top:5px;font-size:11px;color:rgba(255,255,255,.45);">کانال تلگرام: LogicSec</div>
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
            <div style="color:rgba(255,255,255,.85);font-size:13px;line-height:2;margin-bottom:10px;">
              به <b style="color:#60a5fa;">PX Panel</b> خوش آمدید. پنل آماده مدیریت کانفیگ‌ها، دسته‌بندی و سابسکریپشن است.
            </div>
            <div style="margin-top:8px;padding:12px;border-radius:12px;background:rgba(37,99,235,.1);border:1px solid rgba(96,165,250,.2);color:#93c5fd;font-size:12px;">
              کانال تلگرام: <b>LogicSec</b>
            </div>
            <div style="margin-top:12px;color:rgba(255,255,255,.5);font-size:11px;line-height:1.9;">
              اگر کانفیگ‌ها پینگ ندادند، دامنه ممکن است فیلتر شده باشد — دامنه جدید بسازید.
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

    await ensure_default_categories()
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
            خطای داخلی PX Panel
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
