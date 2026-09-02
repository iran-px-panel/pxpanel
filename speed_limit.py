# speed_limit.py
# محدودیت سرعت (Bandwidth Throttling) به‌ازای هر کانفیگ — پیاده‌سازی با الگوی Token Bucket
# جدا شده از relay_vless.py و xhttp_siz10.py؛ هر دو این ماژول رو صدا می‌زنن (منطق اونا دست‌نخورده).

import asyncio
import time

from main import LINKS

# هر uuid یک Bucket جدا داره؛ Bucket با نرخ صفر (بدون محدودیت) اصلاً ساخته نمی‌شه.
_buckets: dict = {}

MIN_RATE = 1024          # حداقل نرخ برای جلوگیری از تقسیم بر صفر یا سرعت‌های غیرمنطقی (1 KB/s)
MIN_BURST = 16 * 1024    # حداقل ظرفیت بافر burst (برای اینکه چانک‌های کوچیک بی‌دلیل صف نکشن)


class _Bucket:
    __slots__ = ("rate", "capacity", "tokens", "last")

    def __init__(self, rate_bytes_per_sec: float):
        self.rate = max(rate_bytes_per_sec, MIN_RATE)
        # ظرفیت burst: معادل ۱ ثانیه از نرخ مجاز (حداقل ۱۶ کیلوبایت) تا چانک‌های نرمال گیر نکنن
        self.capacity = max(self.rate, MIN_BURST)
        self.tokens = self.capacity
        self.last = time.monotonic()

    def _refill(self):
        now = time.monotonic()
        elapsed = now - self.last
        if elapsed > 0:
            self.last = now
            self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)

    async def consume(self, n: int):
        """تا وقتی n بایت توکن آماده نشه، به‌صورت غیرمسدودکننده (async sleep) صبر می‌کنه."""
        while True:
            self._refill()
            if self.tokens >= n:
                self.tokens -= n
                return
            deficit = n - self.tokens
            wait = deficit / self.rate
            # سقف sleep کوتاهه تا اگه نرخ کانفیگ از پنل تغییر کرد، زود متوجه بشیم
            await asyncio.sleep(min(max(wait, 0.004), 0.5))


def _get_bucket(uuid: str, rate: int) -> _Bucket:
    b = _buckets.get(uuid)
    if b is None or b.rate != max(rate, MIN_RATE):
        b = _Bucket(rate)
        _buckets[uuid] = b
    return b


async def throttle(uuid: str, nbytes: int):
    """اگه کانفیگ محدودیت سرعت داشته باشه (speed_limit_bytes > 0)، تا نوبتِ ارسال
    این تعداد بایت صبر می‌کنه. اگه محدودیتی نباشه، فوری برمی‌گرده (بدون سربار محسوس)."""
    if nbytes <= 0:
        return
    link = LINKS.get(uuid)
    rate = int((link or {}).get("speed_limit_bytes", 0) or 0)
    if rate <= 0:
        return
    bucket = _get_bucket(uuid, rate)
    await bucket.consume(nbytes)


def reset_bucket(uuid: str):
    """وقتی محدودیت سرعت یک کانفیگ از پنل تغییر کرد یا کانفیگ حذف شد صدا زده می‌شه،
    تا بافر توکن قدیمی پاک بشه (نرخ جدید در فراخوانی بعدی throttle از نو ساخته می‌شه)."""
    _buckets.pop(uuid, None)
