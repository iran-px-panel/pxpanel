# sales.py — plans / orders / manual payment verification for PXPanel
# Used by main.py (web API) and telegram_bot.py (سفارش/فروش از تلگرام)

import json
import uuid as uuidlib
from datetime import datetime
from pathlib import Path

from main import DATA_DIR, logger

SALES_FILE = Path(DATA_DIR) / "sales_state.json"

_state = {
    "plans": {},
    "orders": {},
    "payment": {
        "card_number": "",
        "card_holder": "",
        "crypto_wallet": "",
        "crypto_network": "",
    },
    "stats": {"paid_orders": 0, "revenue_toman": 0, "revenue_usdt": 0},
}
_loaded = False


def load_sales():
    global _loaded
    if _loaded:
        return
    try:
        if SALES_FILE.exists():
            data = json.loads(SALES_FILE.read_text(encoding="utf-8"))
            _state["plans"].update(data.get("plans") or {})
            _state["orders"].update(data.get("orders") or {})
            _state["payment"].update(data.get("payment") or {})
            _state["stats"].update(data.get("stats") or {})
    except Exception as e:
        logger.warning(f"sales load: {e}")
    _loaded = True


def save_sales():
    try:
        SALES_FILE.parent.mkdir(parents=True, exist_ok=True)
        SALES_FILE.write_text(
            json.dumps(_state, ensure_ascii=False, indent=2), encoding="utf-8"
        )
    except Exception as e:
        logger.warning(f"sales save: {e}")


def export_state() -> dict:
    return json.loads(json.dumps(_state, ensure_ascii=False))


def import_state(data: dict, merge: bool = True):
    if not isinstance(data, dict):
        return
    if not merge:
        _state["plans"].clear()
        _state["orders"].clear()
    _state["plans"].update(data.get("plans") or {})
    _state["orders"].update(data.get("orders") or {})
    _state["payment"].update(data.get("payment") or {})
    _state["stats"].update(data.get("stats") or {})
    save_sales()


# ── Plans ─────────────────────────────────────────────────────────────────
def list_plans(active_only: bool = False):
    items = sorted(_state["plans"].items(), key=lambda kv: kv[1].get("order", 0))
    if active_only:
        items = [(k, v) for k, v in items if v.get("active", True)]
    return items


def get_plan(plan_id: str):
    return _state["plans"].get(plan_id)


def create_plan(name, days, volume_gb, speed_mbps=0, price_toman=0, price_usdt=0):
    pid = uuidlib.uuid4().hex[:8]
    _state["plans"][pid] = {
        "name": name,
        "days": int(days or 0),
        "volume_gb": float(volume_gb or 0),
        "speed_mbps": float(speed_mbps or 0),
        "price_toman": int(price_toman or 0),
        "price_usdt": float(price_usdt or 0),
        "active": True,
        "order": len(_state["plans"]),
        "created_at": datetime.now().isoformat(),
    }
    save_sales()
    return pid


def toggle_plan(plan_id: str, active: bool | None = None):
    p = _state["plans"].get(plan_id)
    if not p:
        return None
    p["active"] = (not p.get("active", True)) if active is None else bool(active)
    save_sales()
    return p


def delete_plan(plan_id: str):
    _state["plans"].pop(plan_id, None)
    save_sales()


# ── Payment info (manual card / crypto verification) ────────────────────────
def set_payment_info(card_number="", card_holder="", crypto_wallet="", crypto_network=""):
    p = _state["payment"]
    if card_number:
        p["card_number"] = card_number
    if card_holder:
        p["card_holder"] = card_holder
    if crypto_wallet:
        p["crypto_wallet"] = crypto_wallet
    if crypto_network:
        p["crypto_network"] = crypto_network
    save_sales()


def get_payment_info() -> dict:
    return dict(_state["payment"])


# ── Orders ───────────────────────────────────────────────────────────────
def create_order(plan_id: str, buyer_chat_id: int, buyer_username: str = ""):
    plan = get_plan(plan_id)
    if not plan:
        return None, None
    oid = uuidlib.uuid4().hex[:8].upper()
    order = {
        "plan_id": plan_id,
        "plan_name": plan.get("name"),
        "buyer_chat_id": buyer_chat_id,
        "buyer_username": buyer_username,
        "status": "pending",  # pending -> awaiting_receipt -> review -> approved | rejected
        "created_at": datetime.now().isoformat(),
        "price_toman": plan.get("price_toman"),
        "price_usdt": plan.get("price_usdt"),
        "days": plan.get("days"),
        "volume_gb": plan.get("volume_gb"),
        "speed_mbps": plan.get("speed_mbps"),
        "link_uid": None,
        "receipt_file_id": None,
    }
    _state["orders"][oid] = order
    save_sales()
    return oid, order


def get_order(oid: str):
    return _state["orders"].get(oid)


def list_orders(status: str | None = None):
    items = sorted(
        _state["orders"].items(), key=lambda kv: kv[1].get("created_at", ""), reverse=True
    )
    if status:
        items = [(k, v) for k, v in items if v.get("status") == status]
    return items


def set_order_receipt(oid: str, file_id: str):
    o = _state["orders"].get(oid)
    if not o:
        return None
    o["receipt_file_id"] = file_id
    o["status"] = "review"
    save_sales()
    return o


def mark_order(oid: str, status: str, link_uid: str | None = None):
    o = _state["orders"].get(oid)
    if not o:
        return None
    o["status"] = status
    if link_uid:
        o["link_uid"] = link_uid
    if status == "approved":
        _state["stats"]["paid_orders"] = _state["stats"].get("paid_orders", 0) + 1
        _state["stats"]["revenue_toman"] = _state["stats"].get(
            "revenue_toman", 0
        ) + int(o.get("price_toman") or 0)
        _state["stats"]["revenue_usdt"] = _state["stats"].get(
            "revenue_usdt", 0
        ) + float(o.get("price_usdt") or 0)
    save_sales()
    return o


def get_sales_stats() -> dict:
    pending = sum(
        1 for o in _state["orders"].values() if o.get("status") in ("pending", "review")
    )
    return {
        "plans": len(_state["plans"]),
        "orders_total": len(_state["orders"]),
        "orders_pending": pending,
        "paid_orders": _state["stats"].get("paid_orders", 0),
        "revenue_toman": _state["stats"].get("revenue_toman", 0),
        "revenue_usdt": _state["stats"].get("revenue_usdt", 0),
    }
