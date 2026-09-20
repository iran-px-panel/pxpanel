# telegram_bot.py

import asyncio
import json
import os
import re
from datetime import datetime, timedelta
from pathlib import Path
import httpx
from main import (
    LINKS,
    SUBS,
    CATEGORIES,
    ADMIN_ACCOUNTS,
    APP_VERSION,
    make_link,
    remove_link,
    set_link_active,
    vless_link_for_link,
    get_host,
    fmt_bytes,
    is_link_allowed,
    is_link_expired,
    logger,
    log_activity,
    PROTOCOLS,
    DEFAULT_PROTOCOL,
    FINGERPRINTS,
    DEFAULT_FINGERPRINT,
    DEFAULT_ALPN_BY_PROTOCOL,
    DEFAULT_PORT,
    parse_size_to_bytes,
    parse_speed_to_bytes,
    create_sub_group,
    set_link_sub,
    remove_sub_group,
    DATA_DIR,
    stats,
    connections,
    uptime,
    unique_ips_for_uuid,
    activity_logs,
    load_tg_settings,
)
import sales as sales

sales.load_sales()

_backup_task: asyncio.Task | None = None
_BACKUP_STATE = {"last_daily": None, "last_monthly": None}


async def _send_backup_to_telegram(kind: str = "daily") -> bool:
    """Build a full JSON backup (configs + subs + categories + admins + telegram + sales)
    and push it straight into the bot chat of every admin — no web dashboard needed."""
    try:
        sales.load_sales()
        sales_export = sales.export_state()
    except Exception:
        sales_export = {}
    payload = {
        "type": "pxpanel_full_backup",
        "kind": kind,
        "version": APP_VERSION,
        "created_at": datetime.now().isoformat(),
        "links": dict(LINKS),
        "subs": dict(SUBS),
        "categories": dict(CATEGORIES),
        "admin_accounts": dict(ADMIN_ACCOUNTS),
        "telegram": load_tg_settings(),
        "sales": sales_export,
    }
    body = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
    fname = f"pxpanel-backup-{kind}-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
    label = {
        "daily": "📦 بک‌آپ روزانه",
        "monthly-day28": "🗓 بک‌آپ کامل (روز ۲۸ ماه)",
        "manual": "📦 بک‌آپ دستی",
    }.get(kind, "📦 بک‌آپ")
    caption = (
        f"{label}\n"
        f"لینک‌ها: {len(LINKS)} · ساب‌ها: {len(SUBS)} · پلن‌های فروش: {len(sales_export.get('plans') or {})}\n"
        f"زمان: {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    )
    ok = await send_document_to_admins(fname, body, caption=caption)
    try:
        log_activity("backup", f"{label} به تلگرام ارسال شد" if ok else f"{label}: ادمینی تنظیم نشده", "ok" if ok else "warn")
    except Exception:
        pass
    return ok


async def _backup_scheduler_loop():
    """Runs for the lifetime of the bot: sends a daily backup at ~04:00, plus an extra
    full backup on day 28 of each month — both delivered directly into the Telegram chat."""
    await asyncio.sleep(60)
    while _running:
        try:
            now = datetime.now()
            today_key = now.strftime("%Y-%m-%d")
            if now.hour == 4 and _BACKUP_STATE["last_daily"] != today_key:
                await _send_backup_to_telegram("daily")
                _BACKUP_STATE["last_daily"] = today_key
            if now.day == 28 and now.hour == 4 and _BACKUP_STATE["last_monthly"] != today_key:
                await _send_backup_to_telegram("monthly-day28")
                _BACKUP_STATE["last_monthly"] = today_key
        except asyncio.CancelledError:
            break
        except Exception as exc:
            logger.warning(f"backup scheduler: {exc}")
        await asyncio.sleep(300)

BOT_NAME = "پی ایکس بات"
BOT_NAME_EN = "PX Bot"

BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
_admin_ids_raw = os.environ.get("TELEGRAM_ADMIN_IDS", "").strip()
ADMIN_IDS = {int(x) for x in _admin_ids_raw.replace(" ", "").split(",") if x.isdigit()} if _admin_ids_raw else set()
API_BASE = f"https://api.telegram.org/bot{BOT_TOKEN}" if BOT_TOKEN else ""
_mode = "polling"

FORCE_JOIN = {
    "enabled": False,
    "channel": "",  # @username or -100id
}

PAGE_SIZE = 6
_client: httpx.AsyncClient | None = None
_poll_task: asyncio.Task | None = None
_running = False
_pending: dict = {}

WIZARD_STEPS = ["label", "protocol", "fingerprint", "alpn", "port", "volume", "speed", "iplimit", "days"]

PROTOCOL_LABELS = {
    "vless-ws": "🟢 VLESS · WebSocket",
    "xhttp-packet-up": "⚡ XHTTP packet-up",
    "xhttp-stream-up": "⚡ XHTTP stream-up",
    "xhttp-stream-one": "⚡ XHTTP stream-one",
    "vmess-ws": "🔵 VMess · WS",
    "trojan-ws": "🟠 Trojan · WS",
    "shadowsocks": "🟣 Shadowsocks",
    "socks5": "🧦 SOCKS5",
    "http": "🌐 HTTP",
    "hysteria2": "🚀 Hysteria2",
    "tuic": "💎 TUIC",
    "wireguard": "🛡 WireGuard",
}


def _protocol_label(p: str) -> str:
    return PROTOCOL_LABELS.get(p, p)


def _fp_label(fp: str) -> str:
    return f"🖥 {fp}"


def _settings_path() -> Path:
    return Path(DATA_DIR) / "telegram_settings.json"


def _load_force_join():
    global FORCE_JOIN
    try:
        p = _settings_path()
        if p.exists():
            s = json.loads(p.read_text(encoding="utf-8"))
            fj = s.get("force_join") or {}
            FORCE_JOIN["enabled"] = bool(fj.get("enabled"))
            FORCE_JOIN["channel"] = str(fj.get("channel") or "").strip()
    except Exception as e:
        logger.warning(f"force_join load: {e}")


def _save_force_join():
    try:
        p = _settings_path()
        data = {}
        if p.exists():
            data = json.loads(p.read_text(encoding="utf-8"))
        data["force_join"] = {
            "enabled": bool(FORCE_JOIN.get("enabled")),
            "channel": str(FORCE_JOIN.get("channel") or "").strip(),
        }
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    except Exception as e:
        logger.warning(f"force_join save: {e}")


def configure_bot(token: str, admin_ids: str):
    global BOT_TOKEN, ADMIN_IDS, API_BASE
    BOT_TOKEN = (token or "").strip()
    raw = (admin_ids or "").strip()
    ADMIN_IDS = {int(x) for x in raw.replace(" ", "").split(",") if x.isdigit()} if raw else set()
    API_BASE = f"https://api.telegram.org/bot{BOT_TOKEN}" if BOT_TOKEN else ""
    _load_force_join()
    logger.info(f"{BOT_NAME} configured (admins={len(ADMIN_IDS)}, token={'yes' if BOT_TOKEN else 'no'})")


async def setup_webhook(url: str) -> bool:
    if not BOT_TOKEN:
        return False
    try:
        if url:
            res = await _call(
                "setWebhook",
                url=url,
                allowed_updates=["message", "callback_query"],
                drop_pending_updates=True,
            )
        else:
            res = await _call("deleteWebhook", drop_pending_updates=True)
        ok = bool(res and res.get("ok"))
        logger.info(f"{BOT_NAME} webhook: {ok} url={url or 'deleted'}")
        return ok
    except Exception as e:
        logger.warning(f"webhook error: {e}")
        return False


async def process_update(upd: dict):
    try:
        if "message" in upd:
            await _handle_message(upd["message"])
        elif "callback_query" in upd:
            await _handle_callback(upd["callback_query"])
    except Exception as e:
        logger.warning(f"process_update error: {e}")


# API helpers 
async def _call(method: str, **params):
    if not API_BASE:
        return None
    global _client
    if _client is None:
        _client = httpx.AsyncClient(timeout=httpx.Timeout(40.0, connect=10.0))
    try:
        r = await _client.post(f"{API_BASE}/{method}", json=params)
        return r.json()
    except Exception as e:
        logger.warning(f"tg api {method}: {e}")
        return None


async def _send(chat_id: int, text: str, kb: dict | None = None, parse_mode: str = "HTML"):
    payload = {"chat_id": chat_id, "text": text, "parse_mode": parse_mode, "disable_web_page_preview": True}
    if kb:
        payload["reply_markup"] = kb
    return await _call("sendMessage", **payload)


async def _send_photo_by_file_id(chat_id: int, file_id: str, caption: str = "", kb: dict | None = None):
    payload = {"chat_id": chat_id, "photo": file_id, "caption": caption[:1024], "parse_mode": "HTML"}
    if kb:
        payload["reply_markup"] = kb
    return await _call("sendPhoto", **payload)


async def send_document_to_admins(filename: str, content: bytes, caption: str = "") -> bool:
    """Push a file (e.g. a full backup) directly into the Telegram bot chat of every admin."""
    if not API_BASE or not ADMIN_IDS:
        return False
    global _client
    if _client is None:
        _client = httpx.AsyncClient(timeout=httpx.Timeout(60.0, connect=10.0))
    ok_any = False
    for admin_id in list(ADMIN_IDS):
        try:
            files = {"document": (filename, content, "application/json")}
            data = {"chat_id": admin_id, "caption": caption[:1024]}
            r = await _client.post(f"{API_BASE}/sendDocument", data=data, files=files)
            j = r.json()
            if j.get("ok"):
                ok_any = True
        except Exception as e:
            logger.warning(f"send_document_to_admins({admin_id}): {e}")
    return ok_any


async def _edit(chat_id: int, message_id: int, text: str, kb: dict | None = None, parse_mode: str = "HTML"):
    payload = {
        "chat_id": chat_id,
        "message_id": message_id,
        "text": text,
        "parse_mode": parse_mode,
        "disable_web_page_preview": True,
    }
    if kb:
        payload["reply_markup"] = kb
    return await _call("editMessageText", **payload)


async def _answer_cb(cb_id: str, text: str = "", alert: bool = False):
    return await _call("answerCallbackQuery", callback_query_id=cb_id, text=text[:200], show_alert=alert)


def _is_admin(chat_id: int) -> bool:
    return chat_id in ADMIN_IDS


async def _check_membership(user_id: int) -> bool:
    """True if force-join disabled or user is member of required channel."""
    if not FORCE_JOIN.get("enabled"):
        return True
    ch = (FORCE_JOIN.get("channel") or "").strip()
    if not ch:
        return True
    if not ch.startswith("@") and not ch.lstrip("-").isdigit():
        ch = "@" + ch
    res = await _call("getChatMember", chat_id=ch, user_id=user_id)
    if not res or not res.get("ok"):
        return False
    status = (res.get("result") or {}).get("status", "")
    return status in ("creator", "administrator", "member", "restricted")


def _force_join_kb():
    ch = (FORCE_JOIN.get("channel") or "").strip().lstrip("@")
    rows = []
    if ch:
        rows.append([{"text": "📢 عضویت در کانال", "url": f"https://t.me/{ch}"}])
    rows.append([{"text": "✅ عضو شدم — بررسی مجدد", "callback_data": "fj:check"}])
    return {"inline_keyboard": rows}


def _main_menu_kb():
    return {
        "inline_keyboard": [
            [{"text": "📊 داشبورد و آمار زنده", "callback_data": "stats"}],
            [
                {"text": "🟢 لیست کانفیگ‌ها", "callback_data": "list:0"},
                {
                    "text": "➕ ساخت کانفیگ", 
                    "callback_data": "newcfg",
                    "style": "success" 
                },
            ],
            [
                {"text": "🗂 گروه‌های ساب", "callback_data": "subs:0"},
                {"text": "🔌 اتصالات زنده", "callback_data": "conns"},
            ],
            [{"text": "💰 فروش و سفارش‌ها", "callback_data": "sales:menu"}],
            [{"text": "📜 لاگ فعالیت", "callback_data": "logs"}],
            [{"text": "⚙️ تنظیمات پنل ربات", "callback_data": "settings"}],
            [{"text": "🔄 بروزرسانی منو", "callback_data": "menu"}],
        ]
    }

def _settings_kb():
    fj_on = FORCE_JOIN.get("enabled")
    return {
        "inline_keyboard": [
            [{"text": f"{'🟢' if fj_on else '⚪'} عضویت اجباری: {'فعال' if fj_on else 'خاموش'}", "callback_data": "fj:toggle"}],
            [{"text": "📢 تنظیم کانال عضویت", "callback_data": "fj:set"}],
            [{"text": "📦 ارسال بک‌آپ همین الان", "callback_data": "backup:now"}],
            [{"text": "ℹ️ وضعیت ربات", "callback_data": "botinfo"}],
            [{"text": "🏠 منوی اصلی", "callback_data": "menu"}],
        ]
    }


def _links_list_kb(page: int):
    items = sorted(LINKS.items(), key=lambda kv: kv[1].get("created_at", ""), reverse=True)
    total = len(items)
    start = page * PAGE_SIZE
    chunk = items[start : start + PAGE_SIZE]
    rows = []
    for uid, l in chunk:
        online = len(unique_ips_for_uuid(uid))
        if not is_link_allowed(l):
            dot = "🔴"
        elif online > 0:
            dot = "🟢"
        else:
            dot = "⚪"
        label = (l.get("label") or "?")[:22]
        extra = f" · {online}👤" if online else ""
        rows.append([{"text": f"{dot} {label}{extra}", "callback_data": f"view:{uid}"}])
    
    nav = []
    if start > 0:
        nav.append({"text": "⬅️ قبلی", "callback_data": f"list:{page-1}"})
    if start + PAGE_SIZE < total:
        nav.append({"text": "بعدی ➡️", "callback_data": f"list:{page+1}"})
    if nav:
        rows.append(nav)
        
    rows.append([
        {
            "text": "🟢 ساخت کانفیگ جدید", 
            "callback_data": "newcfg",
            "style": "success"
        }
    ])
    
    rows.append([{"text": "🏠 منوی اصلی", "callback_data": "menu"}])
    return {"inline_keyboard": rows}

def _link_detail_kb(uid: str, active: bool):
    return {
        "inline_keyboard": [
            [{"text": "🔗 کپی لینک VLESS", "callback_data": f"link:{uid}"}],
            [{"text": "📡 لینک ساب", "callback_data": f"sublink:{uid}"}],
            [{"text": "📄 صفحه INFO", "callback_data": f"info:{uid}"}],
            [
                {
                    "text": "🔴 غیرفعال" if active else "🟢 فعال‌سازی",
                    "callback_data": f"toggle:{uid}",
                    "style": "danger" if active else "success" 
                }
            ],
            [
                {
                    "text": "🗑 حذف کانفیگ", 
                    "callback_data": f"del:{uid}",
                    "style": "danger" 
                }
            ],
            [{"text": "⬅️ بازگشت به لیست", "callback_data": "list:0"}],
        ]
    }


def _confirm_delete_kb(uid: str):
    return {
        "inline_keyboard": [
            [
                {"text": "🟢 بله، حذف کن", "callback_data": f"delok:{uid}"},
                {"text": "❌ انصراف", "callback_data": f"view:{uid}"},
            ]
        ]
    }


def _wizard_cancel_kb():
    return {"inline_keyboard": [[{"text": "❌ انصراف از ساخت", "callback_data": "w:cancel"}]]}


def _wizard_protocol_kb():
    rows = [[{"text": _protocol_label(p), "callback_data": f"w:proto:{p}"}] for p in list(PROTOCOLS)[:12]]
    rows.append([{"text": "❌ انصراف", "callback_data": "w:cancel"}])
    return {"inline_keyboard": rows}


def _wizard_fp_kb():
    rows, row = [], []
    for fp in FINGERPRINTS:
        row.append({"text": _fp_label(fp), "callback_data": f"w:fp:{fp}"})
        if len(row) == 2:
            rows.append(row)
            row = []
    if row:
        rows.append(row)
    rows.append([{"text": "❌ انصراف", "callback_data": "w:cancel"}])
    return {"inline_keyboard": rows}


def _wizard_skip_kb(step_key: str, label: str):
    return {
        "inline_keyboard": [
            [{"text": f"🟢 {label}", "callback_data": f"w:skip:{step_key}"}],
            [{"text": "❌ انصراف", "callback_data": "w:cancel"}],
        ]
    }


def _wizard_alpn_kb():
    return {
        "inline_keyboard": [
            [{"text": "🟢 http/1.1", "callback_data": "w:alpnpreset:p1"}],
            [{"text": "h2,http/1.1", "callback_data": "w:alpnpreset:p2"}],
            [{"text": "h2", "callback_data": "w:alpnpreset:p3"}],
            [{"text": "⏭ پیش‌فرض پروتکل", "callback_data": "w:skip:alpn"}],
            [{"text": "❌ انصراف", "callback_data": "w:cancel"}],
        ]
    }


def _subs_list_kb(page: int):
    items = sorted(SUBS.items(), key=lambda kv: kv[1].get("created_at", ""), reverse=True)
    total = len(items)
    start = page * PAGE_SIZE
    chunk = items[start : start + PAGE_SIZE]
    rows = []
    for sid, s in chunk:
        cnt = len(s.get("link_ids", []))
        rows.append([{"text": f"🗂 {(s.get('name') or '?')[:26]} ({cnt})", "callback_data": f"subview:{sid}"}])
    nav = []
    if start > 0:
        nav.append({"text": "⬅️ قبلی", "callback_data": f"subs:{page-1}"})
    if start + PAGE_SIZE < total:
        nav.append({"text": "بعدی ➡️", "callback_data": f"subs:{page+1}"})
    if nav:
        rows.append(nav)
    rows.append([{"text": "🟢 ساخت گروه جدید", "callback_data": "newsub"}])
    rows.append([{"text": "🏠 منوی اصلی", "callback_data": "menu"}])
    return {"inline_keyboard": rows}


def _sub_detail_kb(sid: str):
    return {
        "inline_keyboard": [
            [{"text": "➕ افزودن کانفیگ", "callback_data": f"subaddlink:{sid}:0"}],
            [{"text": "🗑 حذف گروه", "callback_data": f"subdel:{sid}"}],
            [{"text": "⬅️ لیست گروه‌ها", "callback_data": "subs:0"}],
        ]
    }


def _confirm_subdel_kb(sid: str):
    return {
        "inline_keyboard": [
            [
                {"text": "🟢 بله، حذف", "callback_data": f"subdelok:{sid}"},
                {"text": "❌ انصراف", "callback_data": f"subview:{sid}"},
            ]
        ]
    }


def _pick_link_for_group_kb(sid: str, page: int):
    items = sorted(LINKS.items(), key=lambda kv: kv[1].get("created_at", ""), reverse=True)
    total = len(items)
    start = page * PAGE_SIZE
    chunk = items[start : start + PAGE_SIZE]
    rows = []
    for uid, l in chunk:
        in_this = "✅ " if l.get("sub_id") == sid else ""
        rows.append([{"text": f"{in_this}{(l.get('label') or '?')[:28]}", "callback_data": f"subaddlinkdo:{sid}:{uid}"}])
    nav = []
    if start > 0:
        nav.append({"text": "⬅️", "callback_data": f"subaddlink:{sid}:{page-1}"})
    if start + PAGE_SIZE < total:
        nav.append({"text": "➡️", "callback_data": f"subaddlink:{sid}:{page+1}"})
    if nav:
        rows.append(nav)
    rows.append([{"text": "⬅️ بازگشت", "callback_data": f"subview:{sid}"}])
    return {"inline_keyboard": rows}


def _group_public_url(s: dict) -> str:
    host = get_host()
    return f"https://{host}/p/{s.get('uuid_key', '')}"


# ── Text formatters ──────────────────────────────────────────────────────────
def _welcome_text() -> str:
    return (
        f"🤖 <b>{BOT_NAME}</b> <i>({BOT_NAME_EN})</i>\n"
        f"{'─' * 18}\n"
        f"✨ پنل مدیریت کامل از تلگرام\n"
        f"🟢 ساخت و مدیریت کانفیگ\n"
        f"📊 آمار زنده · 🔌 اتصالات\n"
        f"📢 عضویت اجباری · 🗂 ساب\n\n"
        f"از منوی زیر یک بخش را انتخاب کنید:"
    )


def _stats_text() -> str:
    active_links = sum(1 for l in LINKS.values() if is_link_allowed(l))
    total_used = sum(int(l.get("used_bytes") or 0) for l in LINKS.values())
    online = len(connections)
    s = sales.get_sales_stats()
    return (
        f"📊 <b>داشبورد {BOT_NAME}</b>\n"
        f"{'─' * 18}\n"
        f"⏱ آپتایم سرور: <code>{uptime()}</code>\n"
        f"📦 کل کانفیگ‌ها: <b>{len(LINKS)}</b>\n"
        f"🟢 فعال: <b>{active_links}</b>\n"
        f"🔌 اتصالات زنده: <b>{online}</b>\n"
        f"📈 ترافیک مصرفی: <b>{fmt_bytes(total_used)}</b>\n"
        f"📡 درخواست‌ها: <b>{stats.get('total_requests', 0)}</b>\n"
        f"⚠️ خطاها: <b>{stats.get('total_errors', 0)}</b>\n"
        f"🗂 گروه‌های ساب: <b>{len(SUBS)}</b>\n"
        f"{'─' * 18}\n"
        f"💰 سفارش‌های در انتظار: <b>{s['orders_pending']}</b>\n"
        f"✅ فروش موفق: <b>{s['paid_orders']}</b>\n"
        f"💵 درآمد: <b>{s['revenue_toman']:,} تومان</b>"
        + (f" / {s['revenue_usdt']:.2f} USDT" if s['revenue_usdt'] else "")
    )


def _format_link_detail(uid: str, link: dict) -> str:
    online = len(unique_ips_for_uuid(uid))
    active = is_link_allowed(link)
    used = int(link.get("used_bytes") or 0)
    limit = int(link.get("limit_bytes") or 0)
    usage = f"{fmt_bytes(used)}" + (f" / {fmt_bytes(limit)}" if limit else " / ∞")
    exp = link.get("expires_at") or "∞"
    st = "🟢 فعال" if active else "🔴 غیرفعال"
    return (
        f"📄 <b>{link.get('label') or uid[:8]}</b>\n"
        f"{'─' * 18}\n"
        f"وضعیت: {st}\n"
        f"پروتکل: <code>{link.get('protocol', DEFAULT_PROTOCOL)}</code>\n"
        f"مصرف: <b>{usage}</b>\n"
        f"انقضا: <code>{exp}</code>\n"
        f"👤 متصل الان: <b>{online}</b>\n"
        f"UUID: <code>{uid}</code>"
    )


def _format_sub_detail(sid: str, s: dict) -> str:
    cnt = len(s.get("link_ids", []))
    pw = "🔒 دارد" if s.get("password_hash") else "🔓 بدون رمز"
    return (
        f"🗂 <b>{s.get('name', '?')}</b>\n"
        f"{'─' * 18}\n"
        f"توضیحات: {s.get('desc') or '—'}\n"
        f"تعداد کانفیگ: <b>{cnt}</b>\n"
        f"رمز: {pw}\n\n"
        f"🔗 لینک عمومی:\n<code>{_group_public_url(s)}</code>"
    )


# ── Wizard ───────────────────────────────────────────────────────────────────
_VOLUME_RE = re.compile(r"^([\d.]+)\s*(GB|MB|KB)?$", re.IGNORECASE)
_SPEED_RE = re.compile(r"^([\d.]+)\s*(MBIT|MBPS|MB|KB)?$", re.IGNORECASE)


def _parse_volume_text(text: str):
    m = _VOLUME_RE.match(text.strip())
    if not m:
        return None
    try:
        value = float(m.group(1))
    except ValueError:
        return None
    if value <= 0:
        return 0
    unit = (m.group(2) or "GB").upper()
    return parse_size_to_bytes(value, unit)


def _parse_speed_text(text: str):
    m = _SPEED_RE.match(text.strip())
    if not m:
        return None
    try:
        value = float(m.group(1))
    except ValueError:
        return None
    if value <= 0:
        return 0
    unit_raw = (m.group(2) or "MBIT").upper()
    unit = "MBIT" if unit_raw in ("MBIT", "MBPS") else unit_raw
    return parse_speed_to_bytes(value, unit)


def _parse_nonneg_int(text: str):
    try:
        return max(0, int(text.strip()))
    except ValueError:
        return None


def _wizard_prompt(step: str) -> tuple[str, dict | None]:
    n = WIZARD_STEPS.index(step) + 1 if step in WIZARD_STEPS else len(WIZARD_STEPS)
    head = f"🧩 <b>ساخت کانفیگ</b> — مرحله {n}/{len(WIZARD_STEPS)}\n{'─' * 18}\n"
    if step == "label":
        return head + "✏️ نام کانفیگ را بفرست (یا دکمه رندوم):", {
            "inline_keyboard": [
                [{"text": "🎲 نام تصادفی", "callback_data": "w:randlabel"}],
                [{"text": "❌ انصراف", "callback_data": "w:cancel"}],
            ]
        }
    if step == "protocol":
        return head + "📡 پروتکل را انتخاب کن:", _wizard_protocol_kb()
    if step == "fingerprint":
        return head + "🖥 Fingerprint:", _wizard_fp_kb()
    if step == "alpn":
        return head + "🔤 ALPN:", _wizard_alpn_kb()
    if step == "port":
        return head + "🔢 پورت (۱–۶۵۵۳۵) یا رد کن:", _wizard_skip_kb("port", "پورت ۴۴۳")
    if step == "volume":
        return head + "📦 حجم مثل <code>10GB</code> (۰ = نامحدود):", _wizard_skip_kb("volume", "نامحدود")
    if step == "speed":
        return head + "🚀 سرعت Mbps مثل <code>50</code> (۰ = نامحدود):", _wizard_skip_kb("speed", "نامحدود")
    if step == "iplimit":
        return head + "👤 محدودیت IP همزمان (۰ = نامحدود):", _wizard_skip_kb("iplimit", "نامحدود")
    if step == "days":
        return head + "📅 انقضا به روز (۰ = بدون انقضا):", _wizard_skip_kb("days", "بدون انقضا")
    return head, _wizard_cancel_kb()


async def _wizard_finish(chat_id: int, data: dict):
    label = data.get("label") or "px-" + os.urandom(3).hex()
    protocol = data.get("protocol") or DEFAULT_PROTOCOL
    fingerprint = data.get("fingerprint") or DEFAULT_FINGERPRINT
    alpn = data.get("alpn") or DEFAULT_ALPN_BY_PROTOCOL.get(protocol, "http/1.1")
    port = int(data.get("port") or DEFAULT_PORT)
    limit_bytes = int(data.get("volume") or 0)
    speed_bytes = int(data.get("speed") or 0)
    ip_limit = int(data.get("iplimit") or 0)
    days = int(data.get("days") or 0)
    expires_at = (datetime.now() + timedelta(days=days)).isoformat() if days > 0 else None
    try:
        uid, link = await make_link(
            label=label,
            limit_bytes=limit_bytes,
            expires_at=expires_at,
            protocol=protocol,
            fingerprint=fingerprint,
            alpn=alpn,
            port=port,
            ip_limit=ip_limit,
            speed_limit_bytes=speed_bytes,
        )
        host = get_host()
        vless = vless_link_for_link(link, uid, host)
        sub = f"https://{host}/sub/{uid}"
        text = (
            f"✅ <b>کانفیگ ساخته شد!</b>\n"
            f"{'─' * 18}\n"
            f"🏷 نام: <b>{label}</b>\n"
            f"📡 {protocol}\n\n"
            f"🔗 <b>VLESS</b>\n<code>{vless}</code>\n\n"
            f"📡 <b>ساب</b>\n<code>{sub}</code>"
        )
        await _send(chat_id, text, _link_detail_kb(uid, True))
    except Exception as e:
        logger.warning(f"wizard finish: {e}")
        await _send(chat_id, f"❌ خطا در ساخت: {e}", _main_menu_kb())
    _pending.pop(chat_id, None)


# ── Guards ───────────────────────────────────────────────────────────────────
async def _guard(chat_id: int, user_id: int | None = None) -> bool:
    """Admin + optional force-join. Returns False if blocked (message already sent)."""
    if not _is_admin(chat_id):
        await _send(
            chat_id,
            f"⛔️ دسترسی فقط برای ادمین {BOT_NAME}.\n"
            f"آیدی عددی خود را به پنل وب اضافه کنید.",
        )
        return False
    uid = user_id or chat_id
    if not await _check_membership(uid):
        ch = FORCE_JOIN.get("channel") or "—"
        await _send(
            chat_id,
            f"📢 <b>عضویت اجباری</b>\n"
            f"{'─' * 18}\n"
            f"برای استفاده از {BOT_NAME} باید در کانال عضو باشید:\n"
            f"<code>{ch}</code>",
            _force_join_kb(),
        )
        return False
    return True


# ── SALES: admin-side keyboards/text ────────────────────────────────────────
PLAN_WIZARD_STEPS = ["name", "days", "volume_gb", "speed_mbps", "price_toman", "price_usdt"]
PAY_WIZARD_STEPS = ["card_number", "card_holder", "crypto_wallet", "crypto_network"]


def _sales_menu_kb():
    return {
        "inline_keyboard": [
            [{"text": "📦 پلن‌های فروش", "callback_data": "sales:plans:0"}],
            [{"text": "🧾 سفارش‌های در انتظار", "callback_data": "sales:orders:pending:0"}],
            [{"text": "📜 همه سفارش‌ها", "callback_data": "sales:orders:all:0"}],
            [{"text": "💳 تنظیم درگاه پرداخت", "callback_data": "sales:payset"}],
            [{"text": "🏠 منوی اصلی", "callback_data": "menu"}],
        ]
    }


def _sales_menu_text() -> str:
    s = sales.get_sales_stats()
    pay = sales.get_payment_info()
    card_ok = "✅" if pay.get("card_number") else "❌"
    crypto_ok = "✅" if pay.get("crypto_wallet") else "❌"
    return (
        f"💰 <b>فروش و سفارش‌ها</b>\n"
        f"{'─' * 18}\n"
        f"📦 پلن‌ها: <b>{s['plans']}</b>\n"
        f"🧾 سفارش‌ها: <b>{s['orders_total']}</b> (در انتظار: <b>{s['orders_pending']}</b>)\n"
        f"✅ فروش موفق: <b>{s['paid_orders']}</b>\n"
        f"💵 درآمد: <b>{s['revenue_toman']:,} تومان</b>"
        + (f" / {s['revenue_usdt']:.2f} USDT" if s['revenue_usdt'] else "") + "\n"
        f"{'─' * 18}\n"
        f"کارت بانکی تنظیم شده: {card_ok}\n"
        f"کیف‌پول کریپتو تنظیم شده: {crypto_ok}"
    )


def _plans_admin_kb(page: int = 0):
    items = sales.list_plans()
    total = len(items)
    start = page * PAGE_SIZE
    chunk = items[start:start + PAGE_SIZE]
    rows = []
    for pid, p in chunk:
        dot = "🟢" if p.get("active", True) else "⚪"
        price = f"{int(p.get('price_toman') or 0):,}ت"
        rows.append([{"text": f"{dot} {p.get('name','?')} · {p.get('days')}روز/{p.get('volume_gb')}GB · {price}", "callback_data": f"sales:planview:{pid}"}])
    nav = []
    if start > 0:
        nav.append({"text": "⬅️", "callback_data": f"sales:plans:{page-1}"})
    if start + PAGE_SIZE < total:
        nav.append({"text": "➡️", "callback_data": f"sales:plans:{page+1}"})
    if nav:
        rows.append(nav)
    rows.append([{"text": "➕ پلن جدید", "callback_data": "sales:planadd", "style": "success"}])
    rows.append([{"text": "⬅️ بازگشت", "callback_data": "sales:menu"}])
    return {"inline_keyboard": rows}


def _plan_detail_text(pid: str, p: dict) -> str:
    return (
        f"📦 <b>{p.get('name')}</b>\n"
        f"{'─' * 18}\n"
        f"مدت: <b>{p.get('days')} روز</b>\n"
        f"حجم: <b>{p.get('volume_gb')} GB</b>\n"
        f"سرعت: <b>{p.get('speed_mbps') or '∞'} Mbps</b>\n"
        f"قیمت: <b>{int(p.get('price_toman') or 0):,} تومان</b>"
        + (f" / {p.get('price_usdt')} USDT" if p.get('price_usdt') else "") + "\n"
        f"وضعیت: {'🟢 فعال (قابل خرید)' if p.get('active', True) else '⚪ غیرفعال'}"
    )


def _plan_detail_kb(pid: str, active: bool):
    return {
        "inline_keyboard": [
            [{"text": "🔴 غیرفعال کردن" if active else "🟢 فعال کردن", "callback_data": f"sales:plantoggle:{pid}"}],
            [{"text": "🗑 حذف پلن", "callback_data": f"sales:plandel:{pid}", "style": "danger"}],
            [{"text": "⬅️ بازگشت به پلن‌ها", "callback_data": "sales:plans:0"}],
        ]
    }


def _plan_wizard_prompt(step: str) -> str:
    n = PLAN_WIZARD_STEPS.index(step) + 1
    head = f"🧩 <b>پلن جدید</b> — مرحله {n}/{len(PLAN_WIZARD_STEPS)}\n{'─' * 18}\n"
    labels = {
        "name": "✏️ نام پلن را بفرست (مثال: یک ماهه ۳۰ گیگ):",
        "days": "📅 مدت اعتبار به روز (مثال: 30):",
        "volume_gb": "📦 حجم به گیگابایت (مثال: 30):",
        "speed_mbps": "🚀 محدودیت سرعت Mbps (0 = نامحدود):",
        "price_toman": "💵 قیمت به تومان (مثال: 150000):",
        "price_usdt": "💲 قیمت به USDT (اختیاری، 0 اگر ندارد):",
    }
    return head + labels[step]


def _payment_info_text() -> str:
    p = sales.get_payment_info()
    return (
        f"💳 <b>اطلاعات درگاه پرداخت (کارت‌به‌کارت / کریپتو)</b>\n"
        f"{'─' * 18}\n"
        f"شماره کارت: <code>{p.get('card_number') or '—'}</code>\n"
        f"به نام: {p.get('card_holder') or '—'}\n"
        f"کیف‌پول کریپتو: <code>{p.get('crypto_wallet') or '—'}</code>\n"
        f"شبکه: {p.get('crypto_network') or '—'}\n\n"
        f"برای ویرایش، «شروع ویرایش» را بزن و مراحل را کامل کن."
    )


def _payment_info_kb():
    return {
        "inline_keyboard": [
            [{"text": "✏️ شروع ویرایش", "callback_data": "sales:payedit"}],
            [{"text": "⬅️ بازگشت", "callback_data": "sales:menu"}],
        ]
    }


def _pay_wizard_prompt(step: str) -> str:
    n = PAY_WIZARD_STEPS.index(step) + 1
    head = f"🧩 <b>تنظیم درگاه پرداخت</b> — مرحله {n}/{len(PAY_WIZARD_STEPS)}\n{'─' * 18}\n"
    labels = {
        "card_number": "💳 شماره کارت را بفرست (یا «-» برای رد کردن):",
        "card_holder": "👤 نام صاحب کارت را بفرست (یا «-»):",
        "crypto_wallet": "🪙 آدرس کیف‌پول کریپتو را بفرست (یا «-»):",
        "crypto_network": "🌐 شبکه کریپتو (مثال TRC20) را بفرست (یا «-»):",
    }
    return head + labels[step]


def _orders_kb(status: str, page: int = 0):
    items = sales.list_orders(None if status == "all" else status)
    total = len(items)
    start = page * PAGE_SIZE
    chunk = items[start:start + PAGE_SIZE]
    rows = []
    icons = {"pending": "🕓", "review": "🔎", "approved": "✅", "rejected": "❌"}
    for oid, o in chunk:
        icon = icons.get(o.get("status"), "•")
        rows.append([{"text": f"{icon} {oid} · {o.get('plan_name','?')} · {int(o.get('price_toman') or 0):,}ت", "callback_data": f"sales:orderview:{oid}"}])
    if not chunk:
        rows.append([{"text": "— سفارشی نیست —", "callback_data": "sales:menu"}])
    nav = []
    if start > 0:
        nav.append({"text": "⬅️", "callback_data": f"sales:orders:{status}:{page-1}"})
    if start + PAGE_SIZE < total:
        nav.append({"text": "➡️", "callback_data": f"sales:orders:{status}:{page+1}"})
    if nav:
        rows.append(nav)
    rows.append([{"text": "⬅️ بازگشت", "callback_data": "sales:menu"}])
    return {"inline_keyboard": rows}


def _order_detail_text(oid: str, o: dict) -> str:
    status_fa = {
        "pending": "🕓 در انتظار پرداخت",
        "review": "🔎 در حال بررسی رسید",
        "approved": "✅ تایید و تحویل شده",
        "rejected": "❌ رد شده",
    }.get(o.get("status"), o.get("status"))
    return (
        f"🧾 <b>سفارش {oid}</b>\n"
        f"{'─' * 18}\n"
        f"پلن: <b>{o.get('plan_name')}</b>\n"
        f"مبلغ: <b>{int(o.get('price_toman') or 0):,} تومان</b>"
        + (f" / {o.get('price_usdt')} USDT" if o.get('price_usdt') else "") + "\n"
        f"خریدار: <code>{o.get('buyer_chat_id')}</code> ({o.get('buyer_username') or '—'})\n"
        f"وضعیت: {status_fa}\n"
        f"زمان ثبت: <code>{str(o.get('created_at'))[:16]}</code>"
    )


def _order_admin_kb(oid: str, status: str):
    if status in ("pending", "review"):
        return {
            "inline_keyboard": [
                [
                    {"text": "✅ تایید و ارسال کانفیگ", "callback_data": f"sales:approve:{oid}", "style": "success"},
                    {"text": "❌ رد سفارش", "callback_data": f"sales:reject:{oid}", "style": "danger"},
                ],
                [{"text": "⬅️ بازگشت", "callback_data": "sales:orders:pending:0"}],
            ]
        }
    return {"inline_keyboard": [[{"text": "⬅️ بازگشت", "callback_data": "sales:orders:all:0"}]]}


# ── SALES: buyer-side (non-admin) keyboards/text ────────────────────────────
def _buyer_welcome_text() -> str:
    return (
        f"🛍 <b>فروشگاه کانفیگ {BOT_NAME}</b>\n"
        f"{'─' * 18}\n"
        f"خرید کاملاً خودکار نیست؛ بعد از انتخاب پلن، مبلغ را واریز/ترانسفر می‌کنی،\n"
        f"رسید را همینجا می‌فرستی و بعد از تایید ادمین کانفیگت تحویل داده می‌شود.\n\n"
        f"برای شروع، «🛒 خرید کانفیگ» را بزن."
    )


def _buyer_menu_kb():
    return {"inline_keyboard": [[{"text": "🛒 خرید کانفیگ", "callback_data": "buy:plans:0"}]]}


def _buyer_plans_kb(page: int = 0):
    items = sales.list_plans(active_only=True)
    total = len(items)
    start = page * PAGE_SIZE
    chunk = items[start:start + PAGE_SIZE]
    rows = []
    for pid, p in chunk:
        price = f"{int(p.get('price_toman') or 0):,} تومان"
        rows.append([{"text": f"📦 {p.get('name')} · {p.get('days')} روز · {price}", "callback_data": f"buy:plan:{pid}"}])
    if not chunk:
        rows.append([{"text": "فعلاً پلنی موجود نیست", "callback_data": "buy:noop"}])
    nav = []
    if start > 0:
        nav.append({"text": "⬅️", "callback_data": f"buy:plans:{page-1}"})
    if start + PAGE_SIZE < total:
        nav.append({"text": "➡️", "callback_data": f"buy:plans:{page+1}"})
    if nav:
        rows.append(nav)
    return {"inline_keyboard": rows}


def _buyer_plan_text(p: dict) -> str:
    return (
        f"📦 <b>{p.get('name')}</b>\n"
        f"{'─' * 18}\n"
        f"مدت: <b>{p.get('days')} روز</b>\n"
        f"حجم: <b>{p.get('volume_gb')} GB</b>\n"
        f"سرعت: <b>{p.get('speed_mbps') or '∞'} Mbps</b>\n"
        f"قیمت: <b>{int(p.get('price_toman') or 0):,} تومان</b>"
        + (f" یا {p.get('price_usdt')} USDT" if p.get('price_usdt') else "")
    )


def _buyer_order_text(oid: str, o: dict) -> str:
    pay = sales.get_payment_info()
    lines = [
        f"🧾 <b>سفارش شما ثبت شد</b> — کد: <code>{oid}</code>",
        f"{'─' * 18}",
        f"پلن: <b>{o.get('plan_name')}</b>",
        f"مبلغ: <b>{int(o.get('price_toman') or 0):,} تومان</b>"
        + (f" یا {o.get('price_usdt')} USDT" if o.get('price_usdt') else ""),
        "",
        "💳 پرداخت کارت‌به‌کارت:",
    ]
    if pay.get("card_number"):
        lines.append(f"شماره کارت: <code>{pay['card_number']}</code>")
        lines.append(f"به نام: {pay.get('card_holder') or '—'}")
    else:
        lines.append("— هنوز تنظیم نشده، با ادمین هماهنگ کن —")
    if pay.get("crypto_wallet"):
        lines.append("")
        lines.append("🪙 پرداخت کریپتو:")
        lines.append(f"آدرس: <code>{pay['crypto_wallet']}</code>")
        lines.append(f"شبکه: {pay.get('crypto_network') or '—'}")
    lines.append("")
    lines.append("بعد از واریز، دکمه زیر را بزن و عکس رسید را بفرست 👇")
    return "\n".join(lines)


def _buyer_order_kb(oid: str):
    return {
        "inline_keyboard": [
            [{"text": "📸 ارسال رسید پرداخت", "callback_data": f"buy:receipt:{oid}"}],
            [{"text": "⬅️ بازگشت به پلن‌ها", "callback_data": "buy:plans:0"}],
        ]
    }


# ── Handlers ─────────────────────────────────────────────────────────────────
async def _handle_message(msg: dict):
    chat = msg.get("chat") or {}
    chat_id = chat.get("id")
    if chat_id is None:
        return
    user = msg.get("from") or {}
    user_id = user.get("id") or chat_id
    text = (msg.get("text") or "").strip()

    st = _pending.get(chat_id) or {}

    # ── buyer: waiting for a payment-receipt photo ──
    if st.get("action") == "buy_receipt":
        oid = st.get("order_id")
        photos = msg.get("photo") or []
        if not photos:
            await _send(chat_id, "📸 لطفاً فقط یک عکس از رسید پرداخت بفرست.")
            return
        file_id = photos[-1].get("file_id")
        o = sales.set_order_receipt(oid, file_id)
        _pending.pop(chat_id, None)
        if not o:
            await _send(chat_id, "❌ سفارش پیدا نشد.")
            return
        await _send(chat_id, "✅ رسید دریافت شد. منتظر تایید ادمین باش، به‌محض تایید کانفیگت اینجا ارسال می‌شود.")
        uname = f"@{user.get('username')}" if user.get("username") else (user.get("first_name") or "")
        caption = (
            f"🧾 <b>رسید جدید برای سفارش {oid}</b>\n"
            f"پلن: {o.get('plan_name')}\n"
            f"مبلغ: {int(o.get('price_toman') or 0):,} تومان\n"
            f"خریدار: {uname} (<code>{chat_id}</code>)"
        )
        for admin_id in list(ADMIN_IDS):
            await _send_photo_by_file_id(admin_id, file_id, caption, _order_admin_kb(oid, "review"))
        return

    # pending force-join channel set
    if st.get("action") == "set_fj_channel":
        if not _is_admin(chat_id):
            return
        ch = text.strip()
        if ch:
            FORCE_JOIN["channel"] = ch
            _save_force_join()
            _pending.pop(chat_id, None)
            await _send(chat_id, f"✅ کانال عضویت اجباری: <code>{ch}</code>", _settings_kb())
        return

    if st.get("action") == "newsub_name":
        if not await _guard(chat_id, user_id):
            return
        name = text[:40] or "group"
        try:
            sid, sub = await create_sub_group(name=name, desc="از پی ایکس بات")
            _pending.pop(chat_id, None)
            await _send(chat_id, _format_sub_detail(sid, sub), _sub_detail_kb(sid))
        except Exception as e:
            await _send(chat_id, f"❌ {e}", _main_menu_kb())
        return

    # ── admin: new sales plan wizard (text steps) ──
    if st.get("action") == "plan_wizard":
        if not _is_admin(chat_id):
            return
        step = st.get("step")
        data = st.setdefault("data", {})
        if step == "name":
            data["name"] = text[:40] or "پلن"
            st["step"] = "days"
        elif step == "days":
            n = _parse_nonneg_int(text)
            if n is None:
                await _send(chat_id, "⚠️ عدد روز بفرست.")
                return
            data["days"] = n
            st["step"] = "volume_gb"
        elif step == "volume_gb":
            try:
                data["volume_gb"] = float(text.strip())
            except ValueError:
                await _send(chat_id, "⚠️ عدد گیگابایت بفرست (مثال 30).")
                return
            st["step"] = "speed_mbps"
        elif step == "speed_mbps":
            n = _parse_nonneg_int(text)
            if n is None:
                await _send(chat_id, "⚠️ عدد بفرست (0 = نامحدود).")
                return
            data["speed_mbps"] = n
            st["step"] = "price_toman"
        elif step == "price_toman":
            n = _parse_nonneg_int(text)
            if n is None:
                await _send(chat_id, "⚠️ عدد تومان بفرست.")
                return
            data["price_toman"] = n
            st["step"] = "price_usdt"
        elif step == "price_usdt":
            try:
                data["price_usdt"] = float(text.strip())
            except ValueError:
                data["price_usdt"] = 0
            pid = sales.create_plan(
                name=data["name"], days=data["days"], volume_gb=data["volume_gb"],
                speed_mbps=data.get("speed_mbps", 0), price_toman=data.get("price_toman", 0),
                price_usdt=data.get("price_usdt", 0),
            )
            _pending.pop(chat_id, None)
            await _send(chat_id, f"✅ پلن «{data['name']}» ساخته شد.", _plans_admin_kb(0))
            return
        prompt = _plan_wizard_prompt(st["step"])
        await _send(chat_id, prompt, {"inline_keyboard": [[{"text": "❌ انصراف", "callback_data": "sales:plans:0"}]]})
        return

    # ── admin: payment info wizard (text steps) ──
    if st.get("action") == "pay_wizard":
        if not _is_admin(chat_id):
            return
        step = st.get("step")
        data = st.setdefault("data", {})
        val = "" if text.strip() == "-" else text.strip()
        data[step] = val
        try:
            idx = PAY_WIZARD_STEPS.index(step)
            nxt = PAY_WIZARD_STEPS[idx + 1] if idx + 1 < len(PAY_WIZARD_STEPS) else None
        except ValueError:
            nxt = None
        if nxt:
            st["step"] = nxt
            await _send(chat_id, _pay_wizard_prompt(nxt), {"inline_keyboard": [[{"text": "❌ انصراف", "callback_data": "sales:menu"}]]})
            return
        sales.set_payment_info(**data)
        _pending.pop(chat_id, None)
        await _send(chat_id, "✅ اطلاعات پرداخت ذخیره شد.", _payment_info_kb())
        return

    # wizard text steps (config builder)
    if st.get("action") == "wizard":
        if not await _guard(chat_id, user_id):
            return
        step = st.get("step")
        data = st.setdefault("data", {})
        if step == "label":
            data["label"] = text[:40]
            st["step"] = "protocol"
            prompt, kb = _wizard_prompt("protocol")
            await _send(chat_id, prompt, kb)
            return
        if step == "port":
            n = _parse_nonneg_int(text)
            if n is None or n < 1 or n > 65535:
                await _send(chat_id, "⚠️ پورت نامعتبر. دوباره بفرست یا رد کن.", _wizard_skip_kb("port", "پورت ۴۴۳"))
                return
            data["port"] = n
            st["step"] = "volume"
            prompt, kb = _wizard_prompt("volume")
            await _send(chat_id, prompt, kb)
            return
        if step == "volume":
            v = _parse_volume_text(text)
            if v is None:
                await _send(chat_id, "⚠️ مثل 10GB بنویس.", _wizard_skip_kb("volume", "نامحدود"))
                return
            data["volume"] = v
            st["step"] = "speed"
            prompt, kb = _wizard_prompt("speed")
            await _send(chat_id, prompt, kb)
            return
        if step == "speed":
            v = _parse_speed_text(text)
            if v is None:
                await _send(chat_id, "⚠️ مثل 50 بنویس (Mbps).", _wizard_skip_kb("speed", "نامحدود"))
                return
            data["speed"] = v
            st["step"] = "iplimit"
            prompt, kb = _wizard_prompt("iplimit")
            await _send(chat_id, prompt, kb)
            return
        if step == "iplimit":
            n = _parse_nonneg_int(text)
            if n is None:
                await _send(chat_id, "⚠️ عدد معتبر بفرست.", _wizard_skip_kb("iplimit", "نامحدود"))
                return
            data["iplimit"] = n
            st["step"] = "days"
            prompt, kb = _wizard_prompt("days")
            await _send(chat_id, prompt, kb)
            return
        if step == "days":
            n = _parse_nonneg_int(text)
            if n is None:
                await _send(chat_id, "⚠️ عدد روز بفرست.", _wizard_skip_kb("days", "بدون انقضا"))
                return
            data["days"] = n
            await _wizard_finish(chat_id, data)
            return

    if text.startswith("/start") or text in ("/menu", "منو"):
        if _is_admin(chat_id):
            if not await _guard(chat_id, user_id):
                return
            await _send(chat_id, _welcome_text(), _main_menu_kb())
        else:
            await _send(chat_id, _buyer_welcome_text(), _buyer_menu_kb())
        return

    if text.startswith("/stats"):
        if not await _guard(chat_id, user_id):
            return
        await _send(chat_id, _stats_text(), _main_menu_kb())
        return

    if text.startswith("/buy"):
        await _send(chat_id, _buyer_welcome_text(), _buyer_menu_kb())
        return

    if not _is_admin(chat_id):
        await _send(chat_id, _buyer_welcome_text(), _buyer_menu_kb())
        return

    if not await _guard(chat_id, user_id):
        return
    await _send(chat_id, "از منوی زیر استفاده کن 👇", _main_menu_kb())


async def _handle_buy_callback(data: str, chat_id: int, mid: int, user_id: int, user: dict):
    if data.startswith("buy:plans:"):
        page = int(data.split(":")[2])
        await _edit(chat_id, mid, "🛒 <b>پلن‌های موجود</b>\nیکی را انتخاب کن:", _buyer_plans_kb(page))
        return
    if data == "buy:noop":
        return
    if data.startswith("buy:plan:"):
        pid = data.split(":", 2)[2]
        p = sales.get_plan(pid)
        if not p:
            await _edit(chat_id, mid, "❌ این پلن دیگر موجود نیست.", _buyer_menu_kb())
            return
        uname = user.get("username") or ""
        oid, o = sales.create_order(pid, chat_id, uname)
        await _edit(chat_id, mid, _buyer_order_text(oid, o), _buyer_order_kb(oid))
        return
    if data.startswith("buy:receipt:"):
        oid = data.split(":", 2)[2]
        o = sales.get_order(oid)
        if not o:
            await _edit(chat_id, mid, "❌ سفارش پیدا نشد.", _buyer_menu_kb())
            return
        _pending[chat_id] = {"action": "buy_receipt", "order_id": oid}
        await _edit(chat_id, mid, "📸 حالا عکس رسید پرداخت را بفرست:", {
            "inline_keyboard": [[{"text": "❌ انصراف", "callback_data": f"buy:plan:{o.get('plan_id')}"}]]
        })
        return


async def _handle_callback(cb: dict):
    cb_id = cb.get("id")
    data = cb.get("data") or ""
    msg = cb.get("message") or {}
    chat = msg.get("chat") or {}
    chat_id = chat.get("id")
    mid = msg.get("message_id")
    user = cb.get("from") or {}
    user_id = user.get("id") or chat_id
    if chat_id is None:
        return

    # force-join check button — available even when blocked
    if data == "fj:check":
        ok = await _check_membership(user_id)
        if ok:
            await _answer_cb(cb_id, "✅ عضویت تأیید شد")
            await _edit(chat_id, mid, _welcome_text(), _main_menu_kb())
        else:
            await _answer_cb(cb_id, "هنوز عضو نیستید", alert=True)
        return

    # buyer flow is open to everyone, admin or not
    if data.startswith("buy:"):
        await _answer_cb(cb_id)
        await _handle_buy_callback(data, chat_id, mid, user_id, user)
        return

    if not _is_admin(chat_id):
        await _answer_cb(cb_id, "⛔️ فقط ادمین", alert=True)
        return

    # membership for other actions
    if data not in ("fj:toggle", "fj:set", "settings", "botinfo") and FORCE_JOIN.get("enabled"):
        if not await _check_membership(user_id):
            await _answer_cb(cb_id, "عضویت اجباری", alert=True)
            await _edit(
                chat_id,
                mid,
                f"📢 عضویت اجباری فعال است.\nکانال: <code>{FORCE_JOIN.get('channel')}</code>",
                _force_join_kb(),
            )
            return

    await _answer_cb(cb_id)

    if data == "menu":
        await _edit(chat_id, mid, _welcome_text(), _main_menu_kb())
        return

    if data == "stats":
        await _edit(chat_id, mid, _stats_text(), {
            "inline_keyboard": [
                [{"text": "🔄 بروزرسانی آمار", "callback_data": "stats"}],
                [{"text": "🏠 منوی اصلی", "callback_data": "menu"}],
            ]
        })
        return

    if data == "conns":
        lines = [f"🔌 <b>اتصالات زنده</b> · {len(connections)}\n{'─' * 18}"]
        for i, (cid, c) in enumerate(list(connections.items())[:20]):
            lines.append(
                f"• <code>{(c.get('ip') or '?')}</code> · "
                f"{(c.get('uuid') or '')[:8]}… · "
                f"{fmt_bytes(c.get('bytes') or 0)}"
            )
        if not connections:
            lines.append("هیچ اتصال فعالی نیست.")
        await _edit(
            chat_id,
            mid,
            "\n".join(lines),
            {"inline_keyboard": [[{"text": "🔄", "callback_data": "conns"}], [{"text": "🏠 منو", "callback_data": "menu"}]]},
        )
        return

    if data == "logs":
        logs = list(activity_logs)[-15:]
        lines = [f"📜 <b>آخرین فعالیت‌ها</b>\n{'─' * 18}"]
        if not logs:
            lines.append("لاگی نیست.")
        for item in reversed(logs):
            tm = str(item.get("time") or "")[11:19]
            lines.append(f"<code>{tm}</code> {(item.get('message') or '')[:80]}")
        await _edit(
            chat_id,
            mid,
            "\n".join(lines),
            {"inline_keyboard": [[{"text": "🔄", "callback_data": "logs"}], [{"text": "🏠 منو", "callback_data": "menu"}]]},
        )
        return

    if data == "settings":
        _load_force_join()
        fj = FORCE_JOIN
        text = (
            f"⚙️ <b>تنظیمات {BOT_NAME}</b>\n"
            f"{'─' * 18}\n"
            f"عضویت اجباری: {'🟢 فعال' if fj.get('enabled') else '⚪ خاموش'}\n"
            f"کانال: <code>{fj.get('channel') or '—'}</code>\n"
            f"ادمین‌ها: <b>{len(ADMIN_IDS)}</b>"
        )
        await _edit(chat_id, mid, text, _settings_kb())
        return

    if data == "fj:toggle":
        FORCE_JOIN["enabled"] = not bool(FORCE_JOIN.get("enabled"))
        _save_force_join()
        await _edit(
            chat_id,
            mid,
            f"{'🟢 عضویت اجباری فعال شد' if FORCE_JOIN['enabled'] else '⚪ عضویت اجباری خاموش شد'}\n"
            f"کانال: <code>{FORCE_JOIN.get('channel') or '—'}</code>",
            _settings_kb(),
        )
        return

    if data == "fj:set":
        _pending[chat_id] = {"action": "set_fj_channel"}
        await _edit(
            chat_id,
            mid,
            "📢 آیدی کانال را بفرست:\nمثال: <code>@mychannel</code> یا <code>-100123...</code>",
            {"inline_keyboard": [[{"text": "❌ انصراف", "callback_data": "settings"}]]},
        )
        return

    if data == "backup:now":
        await _edit(chat_id, mid, "⏳ در حال تهیه و ارسال بک‌آپ…")
        ok = await _send_backup_to_telegram("manual")
        await _edit(
            chat_id,
            mid,
            "✅ بک‌آپ ارسال شد." if ok else "⚠️ ارسال نشد — ادمینی تنظیم نشده یا خطا رخ داد.",
            _settings_kb(),
        )
        return

    if data == "botinfo":
        await _edit(
            chat_id,
            mid,
            f"ℹ️ <b>{BOT_NAME}</b> ({BOT_NAME_EN})\n"
            f"{'─' * 18}\n"
            f"حالت: <code>{_mode}</code>\n"
            f"توکن: {'✅' if BOT_TOKEN else '❌'}\n"
            f"ادمین‌ها: {len(ADMIN_IDS)}\n"
            f"آپتایم پنل: <code>{uptime()}</code>",
            _settings_kb(),
        )
        return

    if data.startswith("list:"):
        page = int(data.split(":")[1])
        await _edit(
            chat_id,
            mid,
            f"🟢 <b>لیست کانفیگ‌ها</b> ({len(LINKS)})\nانتخاب کنید:",
            _links_list_kb(page),
        )
        return

    if data == "newcfg":
        _pending[chat_id] = {"action": "wizard", "step": "label", "data": {}}
        prompt, kb = _wizard_prompt("label")
        await _edit(chat_id, mid, prompt, kb)
        return

    if data.startswith("view:"):
        uid = data.split(":", 1)[1]
        link = LINKS.get(uid)
        if not link:
            await _edit(chat_id, mid, "❌ پیدا نشد", _links_list_kb(0))
            return
        await _edit(chat_id, mid, _format_link_detail(uid, link), _link_detail_kb(uid, is_link_allowed(link)))
        return

    if data.startswith("link:"):
        uid = data.split(":", 1)[1]
        link = LINKS.get(uid)
        if not link:
            return
        host = get_host()
        vless = vless_link_for_link(link, uid, host)
        await _edit(
            chat_id,
            mid,
            f"🔗 <b>VLESS</b>\n<code>{vless}</code>",
            _link_detail_kb(uid, is_link_allowed(link)),
        )
        return

    if data.startswith("sublink:"):
        uid = data.split(":", 1)[1]
        host = get_host()
        sub = f"https://{host}/sub/{uid}"
        link = LINKS.get(uid) or {}
        await _edit(
            chat_id,
            mid,
            f"📡 <b>سابسکریپشن</b>\n<code>{sub}</code>",
            _link_detail_kb(uid, is_link_allowed(link)),
        )
        return

    if data.startswith("info:"):
        uid = data.split(":", 1)[1]
        host = get_host()
        url = f"https://{host}/info/{uid}"
        link = LINKS.get(uid) or {}
        await _edit(
            chat_id,
            mid,
            f"📄 <b>صفحه INFO</b>\n{url}",
            _link_detail_kb(uid, is_link_allowed(link)),
        )
        return

    if data.startswith("toggle:"):
        uid = data.split(":", 1)[1]
        link = LINKS.get(uid)
        if not link:
            return
        new_state = not is_link_allowed(link)
        await set_link_active(uid, new_state)
        link = LINKS.get(uid) or link
        await _edit(
            chat_id,
            mid,
            _format_link_detail(uid, link) + f"\n\n{'🟢 فعال شد' if new_state else '🔴 غیرفعال شد'}",
            _link_detail_kb(uid, new_state),
        )
        return

    if data.startswith("del:") and not data.startswith("delok:"):
        uid = data.split(":", 1)[1]
        await _edit(chat_id, mid, "⚠️ مطمئن هستید این کانفیگ حذف شود؟", _confirm_delete_kb(uid))
        return

    if data.startswith("delok:"):
        uid = data.split(":", 1)[1]
        await remove_link(uid)
        await _edit(chat_id, mid, "🗑 کانفیگ حذف شد.", _links_list_kb(0))
        return

    # wizard callbacks
    if data == "w:cancel":
        _pending.pop(chat_id, None)
        await _edit(chat_id, mid, "❌ ساخت لغو شد.", _main_menu_kb())
        return

    if data == "w:randlabel":
        st = _pending.setdefault(chat_id, {"action": "wizard", "step": "label", "data": {}})
        st["data"]["label"] = "px" + os.urandom(4).hex()
        st["step"] = "protocol"
        prompt, kb = _wizard_prompt("protocol")
        await _edit(chat_id, mid, prompt, kb)
        return

    if data.startswith("w:proto:"):
        proto = data.split(":", 2)[2]
        st = _pending.setdefault(chat_id, {"action": "wizard", "step": "protocol", "data": {}})
        st["data"]["protocol"] = proto
        st["step"] = "fingerprint"
        prompt, kb = _wizard_prompt("fingerprint")
        await _edit(chat_id, mid, prompt, kb)
        return

    if data.startswith("w:fp:"):
        fp = data.split(":", 2)[2]
        st = _pending.setdefault(chat_id, {"action": "wizard", "data": {}})
        st["data"]["fingerprint"] = fp
        st["step"] = "alpn"
        prompt, kb = _wizard_prompt("alpn")
        await _edit(chat_id, mid, prompt, kb)
        return

    if data.startswith("w:alpnpreset:"):
        key = data.split(":")[-1]
        mapping = {"p1": "http/1.1", "p2": "h2,http/1.1", "p3": "h2"}
        st = _pending.setdefault(chat_id, {"action": "wizard", "data": {}})
        st["data"]["alpn"] = mapping.get(key, "http/1.1")
        st["step"] = "port"
        prompt, kb = _wizard_prompt("port")
        await _edit(chat_id, mid, prompt, kb)
        return

    if data.startswith("w:skip:"):
        step = data.split(":")[-1]
        st = _pending.setdefault(chat_id, {"action": "wizard", "data": {}})
        data_map = st.setdefault("data", {})
        order = ["label", "protocol", "fingerprint", "alpn", "port", "volume", "speed", "iplimit", "days"]
        defaults = {"port": 443, "volume": 0, "speed": 0, "iplimit": 0, "days": 0, "alpn": ""}
        if step in defaults:
            data_map[step] = defaults[step]
        try:
            idx = order.index(step)
            nxt = order[idx + 1] if idx + 1 < len(order) else None
        except ValueError:
            nxt = None
        if nxt:
            st["step"] = nxt
            prompt, kb = _wizard_prompt(nxt)
            await _edit(chat_id, mid, prompt, kb)
        else:
            await _wizard_finish(chat_id, data_map)
            await _edit(chat_id, mid, "✅ در حال نهایی‌سازی…", _main_menu_kb())
        return

    # subs
    if data.startswith("subs:"):
        page = int(data.split(":")[1])
        await _edit(chat_id, mid, f"🗂 <b>گروه‌های ساب</b> ({len(SUBS)})", _subs_list_kb(page))
        return

    if data == "newsub":
        _pending[chat_id] = {"action": "newsub_name"}
        await _edit(
            chat_id,
            mid,
            "✏️ نام گروه ساب را بفرست:",
            {"inline_keyboard": [[{"text": "❌ انصراف", "callback_data": "subs:0"}]]},
        )
        return

    if data.startswith("subview:"):
        sid = data.split(":", 1)[1]
        s = SUBS.get(sid)
        if not s:
            await _edit(chat_id, mid, "❌ گروه نیست", _subs_list_kb(0))
            return
        await _edit(chat_id, mid, _format_sub_detail(sid, s), _sub_detail_kb(sid))
        return

    if data.startswith("subdel:") and not data.startswith("subdelok:"):
        sid = data.split(":", 1)[1]
        await _edit(chat_id, mid, "⚠️ حذف این گروه؟", _confirm_subdel_kb(sid))
        return

    if data.startswith("subdelok:"):
        sid = data.split(":", 1)[1]
        try:
            await remove_sub_group(sid)
        except Exception:
            pass
        await _edit(chat_id, mid, "🗑 گروه حذف شد.", _subs_list_kb(0))
        return

    if data.startswith("subaddlink:") and not data.startswith("subaddlinkdo:"):
        parts = data.split(":")
        sid, page = parts[1], int(parts[2]) if len(parts) > 2 else 0
        await _edit(chat_id, mid, "➕ کانفیگ را برای افزودن انتخاب کن:", _pick_link_for_group_kb(sid, page))
        return

    if data.startswith("subaddlinkdo:"):
        parts = data.split(":")
        sid, uid = parts[1], parts[2]
        try:
            await set_link_sub(uid, sid)
            await _edit(chat_id, mid, f"✅ کانفیگ به گروه اضافه شد.", _sub_detail_kb(sid))
        except Exception as e:
            await _edit(chat_id, mid, f"❌ {e}", _sub_detail_kb(sid))
        return

    # ── SALES: admin management callbacks ──
    if data == "sales:menu":
        await _edit(chat_id, mid, _sales_menu_text(), _sales_menu_kb())
        return

    if data.startswith("sales:plans:"):
        page = int(data.split(":")[2])
        await _edit(chat_id, mid, "📦 <b>پلن‌های فروش</b>\nروی یک پلن بزن برای مدیریت:", _plans_admin_kb(page))
        return

    if data == "sales:planadd":
        _pending[chat_id] = {"action": "plan_wizard", "step": "name", "data": {}}
        await _edit(chat_id, mid, _plan_wizard_prompt("name"), {"inline_keyboard": [[{"text": "❌ انصراف", "callback_data": "sales:plans:0"}]]})
        return

    if data.startswith("sales:planview:"):
        pid = data.split(":", 2)[2]
        p = sales.get_plan(pid)
        if not p:
            await _edit(chat_id, mid, "❌ پلن پیدا نشد.", _plans_admin_kb(0))
            return
        await _edit(chat_id, mid, _plan_detail_text(pid, p), _plan_detail_kb(pid, p.get("active", True)))
        return

    if data.startswith("sales:plantoggle:"):
        pid = data.split(":", 2)[2]
        p = sales.toggle_plan(pid)
        if not p:
            await _edit(chat_id, mid, "❌ پلن پیدا نشد.", _plans_admin_kb(0))
            return
        await _edit(chat_id, mid, _plan_detail_text(pid, p), _plan_detail_kb(pid, p.get("active", True)))
        return

    if data.startswith("sales:plandel:"):
        pid = data.split(":", 2)[2]
        sales.delete_plan(pid)
        await _edit(chat_id, mid, "🗑 پلن حذف شد.", _plans_admin_kb(0))
        return

    if data == "sales:payset":
        await _edit(chat_id, mid, _payment_info_text(), _payment_info_kb())
        return

    if data == "sales:payedit":
        _pending[chat_id] = {"action": "pay_wizard", "step": "card_number", "data": {}}
        await _edit(chat_id, mid, _pay_wizard_prompt("card_number"), {"inline_keyboard": [[{"text": "❌ انصراف", "callback_data": "sales:menu"}]]})
        return

    if data.startswith("sales:orders:"):
        parts = data.split(":")
        status, page = parts[2], int(parts[3])
        title = {"pending": "🧾 سفارش‌های در انتظار", "all": "📜 همه سفارش‌ها"}.get(status, "سفارش‌ها")
        await _edit(chat_id, mid, f"{title}", _orders_kb(status, page))
        return

    if data.startswith("sales:orderview:"):
        oid = data.split(":", 2)[2]
        o = sales.get_order(oid)
        if not o:
            await _edit(chat_id, mid, "❌ سفارش پیدا نشد.", _sales_menu_kb())
            return
        await _edit(chat_id, mid, _order_detail_text(oid, o), _order_admin_kb(oid, o.get("status")))
        return

    if data.startswith("sales:approve:"):
        oid = data.split(":", 2)[2]
        o = sales.get_order(oid)
        if not o:
            await _edit(chat_id, mid, "❌ سفارش پیدا نشد.", _sales_menu_kb())
            return
        try:
            days = int(o.get("days") or 0)
            volume_gb = float(o.get("volume_gb") or 0)
            speed_mbps = float(o.get("speed_mbps") or 0)
            expires_at = (datetime.now() + timedelta(days=days)).isoformat() if days > 0 else None
            uid, link = await make_link(
                label=f"sale-{oid}",
                limit_bytes=parse_size_to_bytes(volume_gb, "GB") if volume_gb else 0,
                expires_at=expires_at,
                speed_limit_bytes=parse_speed_to_bytes(speed_mbps, "MBIT") if speed_mbps else 0,
            )
            host = get_host()
            vless = vless_link_for_link(link, uid, host)
            sub = f"https://{host}/sub/{uid}"
            sales.mark_order(oid, "approved", link_uid=uid)
            await _send(
                o.get("buyer_chat_id"),
                f"✅ <b>پرداخت شما تایید شد!</b>\n{'─' * 18}\n"
                f"🏷 پلن: {o.get('plan_name')}\n\n"
                f"🔗 <b>VLESS</b>\n<code>{vless}</code>\n\n"
                f"📡 <b>ساب</b>\n<code>{sub}</code>",
            )
            await _edit(chat_id, mid, f"✅ تایید شد و کانفیگ برای خریدار ارسال شد.\n\n{_order_detail_text(oid, sales.get_order(oid))}", _order_admin_kb(oid, "approved"))
        except Exception as e:
            logger.warning(f"sales approve: {e}")
            await _edit(chat_id, mid, f"❌ خطا در ساخت کانفیگ: {e}", _order_admin_kb(oid, o.get("status")))
        return

    if data.startswith("sales:reject:"):
        oid = data.split(":", 2)[2]
        o = sales.get_order(oid)
        if not o:
            await _edit(chat_id, mid, "❌ سفارش پیدا نشد.", _sales_menu_kb())
            return
        sales.mark_order(oid, "rejected")
        await _send(o.get("buyer_chat_id"), "❌ متاسفانه پرداخت شما تایید نشد. برای پیگیری با پشتیبانی تماس بگیرید.")
        await _edit(chat_id, mid, "❌ سفارش رد شد و به خریدار اطلاع داده شد.", _order_admin_kb(oid, "rejected"))
        return


# ── Polling ──────────────────────────────────────────────────────────────────
async def _poll_loop():
    offset = 0
    while _running:
        try:
            res = await _call(
                "getUpdates",
                offset=offset,
                timeout=25,
                allowed_updates=["message", "callback_query"],
            )
            if not res or not res.get("ok"):
                await asyncio.sleep(2)
                continue
            for upd in res.get("result") or []:
                offset = max(offset, int(upd.get("update_id", 0)) + 1)
                try:
                    if "message" in upd:
                        await _handle_message(upd["message"])
                    elif "callback_query" in upd:
                        await _handle_callback(upd["callback_query"])
                except Exception as e:
                    logger.warning(f"update handle: {e}")
        except asyncio.CancelledError:
            break
        except Exception as e:
            logger.warning(f"poll error: {e}")
            await asyncio.sleep(3)


async def start_bot(mode: str = "polling"):
    global _client, _poll_task, _running, _mode
    _mode = mode if mode in ("polling", "webhook") else "polling"
    if not BOT_TOKEN:
        try:
            p = Path(DATA_DIR) / "telegram_settings.json"
            if p.exists():
                s = json.loads(p.read_text(encoding="utf-8"))
                if s.get("token"):
                    configure_bot(s.get("token", ""), s.get("admin_ids", ""))
        except Exception:
            pass
    if not BOT_TOKEN:
        logger.info(f"{BOT_NAME}: توکن تنظیم نشده — غیرفعال.")
        return
    _load_force_join()
    if not ADMIN_IDS:
        logger.warning(f"{BOT_NAME}: هیچ ادمینی تنظیم نشده.")
    if _client is None:
        _client = httpx.AsyncClient(timeout=httpx.Timeout(40.0, connect=10.0))
    _running = True
    # set bot
    try:
        await _call("setMyName", name=BOT_NAME)
        await _call(
            "setMyDescription",
            description=f"{BOT_NAME} ({BOT_NAME_EN}) — مدیریت کامل پنل PXPanel از تلگرام",
        )
        await _call(
            "setMyCommands",
            commands=[
                {"command": "start", "description": "🏠 منوی اصلی"},
                {"command": "buy", "description": "🛒 خرید کانفیگ"},
                {"command": "stats", "description": "📊 آمار زنده"},
                {"command": "menu", "description": "📋 منو"},
            ],
        )
    except Exception:
        pass
    if _mode == "polling":
        if _poll_task is None or _poll_task.done():
            _poll_task = asyncio.create_task(_poll_loop())
        logger.info(f"{BOT_NAME}: polling mode")
    else:
        if _poll_task and not _poll_task.done():
            _poll_task.cancel()
        logger.info(f"{BOT_NAME}: webhook mode")

    global _backup_task
    if _backup_task is None or _backup_task.done():
        _backup_task = asyncio.create_task(_backup_scheduler_loop())


async def stop_bot():
    global _running, _client
    _running = False
    if _poll_task:
        _poll_task.cancel()
    if _client:
        await _client.aclose()
        _client = None
