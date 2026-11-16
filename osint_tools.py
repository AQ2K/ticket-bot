"""
🧰 أدوات OSINT — جمع المعلومات من المصادر العلنية وعرضها داخل تيليجرام
=====================================================================
كل الدوال هنا مستقلة تماماً عن تيليجرام: تستقبل نص المستخدم وتُرجع كائن
‎LookupResult‎ يحتوي على نص التقرير (بصيغة HTML) وقائمة «إجراءات» تتحول في
‎keyboards.py‎ إلى أزرار تعرض نتائجها داخل المحادثة نفسها.

المصادر المجانية المستخدمة (بدون مفاتيح):
  • DNS-over-HTTPS من Cloudflare و Google  ← سجلات DNS
  • RDAP (rdap.org)                         ← بيانات تسجيل الدومين و IP (بديل WHOIS)
  • ip-api.com و ipwho.is                   ← الموقع الجغرافي لعناوين IP
  • Shodan InternetDB                       ← المنافذ المفتوحة والثغرات المعروفة
  • GreyNoise Community و RIPEstat          ← سمعة IP وجهة الإبلاغ عن الإساءة
  • crt.sh و HackerTarget                   ← النطاقات الفرعية
  • urlscan.io                              ← فحوصات المواقع ولقطات الشاشة
  • Wayback Machine                         ← الأرشيف
  • XposedOrNot                             ← تسريبات البريد الإلكتروني
  • Gravatar                                ← الملف العلني المرتبط بالبريد
  • WhatsMyName + واجهات المنصات            ← فحص وجود اسم المستخدم
  • مكتبة phonenumbers (تعمل محلياً)        ← تحليل أرقام الهواتف

البحث داخل تيليجرام (Google Dorks): Serper أو Brave عند توفر مفتاح مجاني،
وإلا بحث مجاني محدود عبر مكتبة ddgs.
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import math
import re
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from html import escape, unescape
from pathlib import PurePosixPath
from typing import Any, TypeVar
from urllib.parse import quote, unquote, urljoin, urlsplit

import httpx
import phonenumbers
from phonenumbers import PhoneNumberFormat, PhoneNumberType, carrier, geocoder
from phonenumbers import timezone as pn_timezone

import config

logger = logging.getLogger(__name__)

T = TypeVar("T")


# ═══════════════════════════════════════════════════════════
# 📦 هياكل البيانات
# ═══════════════════════════════════════════════════════════


class InvalidInput(ValueError):
    """تُرفع عندما يكون إدخال المستخدم غير صالح — نص الخطأ يُعرض للمستخدم كما هو."""


@dataclass(frozen=True)
class Action:
    """زر تحت التقرير.

    kind:
      url        ← رابط يفتح تطبيقاً (واتساب / تيليجرام)
      search     ← بحث Google Dork تُعرض نتائجه داخل تيليجرام (value = الاستعلام)
      subdomains ← النطاقات الفرعية (value = الدومين)
      urlscan    ← فحوصات urlscan ولقطة شاشة (value = الدومين)
      map        ← إرسال الموقع على خريطة تيليجرام (extra = خط العرض، خط الطول، العنوان، الوصف)
      photo      ← إرسال صورة داخل المحادثة (value = رابط الصورة، extra = التعليق)
      lookup     ← تقرير جديد من قسم آخر (value = الهدف، extra = اسم القسم)
      wmn        ← فحص اليوزر في +600 موقع (value = اليوزر)
      download   ← إرسال الملف نفسه داخل المحادثة (value = رابط الملف)
    """

    label: str
    kind: str
    value: str = ""
    extra: tuple = ()
    wide: bool = False


@dataclass
class LookupResult:
    """نتيجة البحث: نص التقرير (HTML) + أزرار الإجراءات."""

    text: str
    actions: list[Action] = field(default_factory=list)
    autorun: Action | None = None  # إجراء يُنفَّذ تلقائياً بعد عرض التقرير (مثل Dork مخصص)
    autorun_needs_key: bool = False  # True ← لا يُنفَّذ تلقائياً إلا إذا كان مفتاح البحث مفعّلاً


def url_action(label: str, url: str, *, wide: bool = False) -> Action:
    return Action(label, "url", url, wide=wide)


def search_action(
    label: str, query: str, *, docs: bool = False, wide: bool = False, browser: bool = False
) -> Action:
    """زر بحث Google Dork. browser=True ← يفتح Google في المتصفح بدل عرض النتائج داخل تيليجرام."""
    extra = tuple(tag for tag, on in (("docs", docs), ("browser", browser)) if on)
    return Action(label, "search", query, extra, wide)


# ═══════════════════════════════════════════════════════════
# 🔧 دوال مساعدة عامة
# ═══════════════════════════════════════════════════════════

# تحويل الأرقام العربية/الفارسية إلى أرقام إنجليزية
_DIGITS_TABLE = str.maketrans("٠١٢٣٤٥٦٧٨٩۰۱۲۳۴۵۶۷۸۹", "01234567890123456789")

# محارف التحكم وعلامات الاتجاه الخفية (تظهر كثيراً عند النسخ من واتساب)
_INVISIBLE_RE = re.compile(r"[\x00-\x1f\x7f​-‏‪-‮⁦-⁩﻿]")
_TAG_RE = re.compile(r"<[^>]+>")


def esc(value: Any) -> str:
    """تهريب النص لاستخدامه داخل رسائل HTML في تيليجرام."""
    return escape(str(value), quote=False)


def esc_attr(value: Any) -> str:
    """تهريب النص لاستخدامه داخل خاصية HTML مثل href."""
    return escape(str(value), quote=True)


def strip_tags(text: str | None) -> str:
    """حذف وسوم HTML من النصوص القادمة من محركات البحث."""
    return unescape(_TAG_RE.sub("", text or "")).strip()


def clean_query(raw: str | None) -> str:
    """تنظيف نص المستخدم: حذف المحارف الخفية والمسافات الزائدة والتحقق من الطول."""
    text = _INVISIBLE_RE.sub(" ", raw or "")
    text = re.sub(r"\s+", " ", text).strip()
    if not text:
        raise InvalidInput("❌ لم يصلني أي نص، أرسل الهدف المطلوب من فضلك.")
    if len(text) > config.MAX_QUERY_LENGTH:
        raise InvalidInput(f"❌ النص طويل جداً — الحد الأقصى {config.MAX_QUERY_LENGTH} حرفاً.")
    return text


def google(dork: str) -> str:
    """رابط بحث Google (يُستخدم فقط كخيار احتياطي عند تعذّر البحث داخل تيليجرام)."""
    return f"https://www.google.com/search?q={quote(dork, safe='')}"


_OPERATOR_RE = re.compile(r"\b(site|filetype|ext|intitle|inurl|intext|before|after):", re.IGNORECASE)


def phrase(text: str) -> str:
    """إحاطة النص بعلامتي تنصيص للتطابق الحرفي، إلا إذا احتوى أصلاً على عوامل بحث."""
    text = text.strip()
    if '"' in text or _OPERATOR_RE.search(text):
        return text
    return f'"{text}"'


def flag(country_code: str | None) -> str:
    """تحويل رمز الدولة (مثل SA) إلى علم إيموجي 🇸🇦."""
    if not country_code or len(country_code) != 2 or not country_code.isalpha():
        return "🏳️"
    return "".join(chr(0x1F1E6 + ord(c) - ord("A")) for c in country_code.upper())


def _kv(label: str, value: Any, *, code: bool = True) -> str | None:
    """سطر «• العنوان: القيمة» — يُرجع None إذا كانت القيمة فارغة ليتم تجاهله."""
    if value is None or value == "" or value == []:
        return None
    shown = f"<code>{esc(value)}</code>" if code else esc(value)
    return f"• {label}: {shown}"


def _join(lines: list[str | None]) -> str:
    """دمج الأسطر مع تجاهل القيم الفارغة (None) والإبقاء على الأسطر الفارغة المقصودة."""
    return "\n".join(line for line in lines if line is not None)


def _short(text: str, limit: int = 120) -> str:
    """اختصار النصوص الطويلة."""
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _yes_no(value: bool | None) -> str:
    if value is None:
        return "❔"
    return "✅" if value else "❌"


def _age_text(date_str: str | None) -> str | None:
    """حساب العمر من تاريخ بصيغة YYYY-MM-DD."""
    if not date_str:
        return None
    try:
        created = datetime.strptime(date_str[:10], "%Y-%m-%d").replace(tzinfo=timezone.utc)
    except ValueError:
        return None
    days = (datetime.now(timezone.utc) - created).days
    if days < 0:
        return None
    years, rest = divmod(days, 365)
    months = rest // 30
    parts = []
    if years:
        parts.append(f"{years} سنة")
    if months:
        parts.append(f"{months} شهر")
    return " و ".join(parts) if parts else f"{days} يوم"


def split_message(text: str, limit: int = 3900) -> list[str]:
    """تقسيم النص الطويل إلى رسائل (حد تيليجرام 4096 حرفاً) عند فواصل الأسطر."""
    chunks: list[str] = []
    current = ""
    for line in text.split("\n"):
        if current and len(current) + len(line) + 1 > limit:
            chunks.append(current)
            current = line
        else:
            current = f"{current}\n{line}" if current else line
    if current:
        chunks.append(current)
    return chunks or [""]


async def _safe(awaitable: Awaitable[T], default: T, timeout: float | None = None) -> T:
    """تنفيذ استعلام فرعي بأمان: أي خطأ أو تأخير يُرجع القيمة الافتراضية بدل إيقاف البوت."""
    try:
        if timeout is not None:
            return await asyncio.wait_for(awaitable, timeout)
        return await awaitable
    except asyncio.TimeoutError:
        logger.warning("⏱️ انتهت مهلة استعلام فرعي")
    except Exception:  # noqa: BLE001 — نريد حماية البوت من أي خطأ غير متوقع
        logger.exception("⚠️ خطأ غير متوقع في استعلام فرعي")
    return default


# ═══════════════════════════════════════════════════════════
# 🌍 عميل HTTP المشترك
# ═══════════════════════════════════════════════════════════

_client: httpx.AsyncClient | None = None


def get_client() -> httpx.AsyncClient:
    """عميل HTTP واحد مشترك لكل الطلبات (أسرع ويعيد استخدام الاتصالات)."""
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(
            timeout=httpx.Timeout(config.HTTP_TIMEOUT),
            follow_redirects=True,
            headers={"User-Agent": config.USER_AGENT},
            limits=httpx.Limits(max_connections=50, max_keepalive_connections=20),
        )
    return _client


async def close_client() -> None:
    """إغلاق عميل HTTP عند إيقاف البوت."""
    global _client
    if _client is not None and not _client.is_closed:
        await _client.aclose()
    _client = None


async def _fetch(
    url: str,
    *,
    params: dict | None = None,
    headers: dict | None = None,
    timeout: float | None = None,
) -> httpx.Response | None:
    """طلب GET آمن — يُرجع None عند أي خطأ في الشبكة."""
    kwargs: dict[str, Any] = {"params": params, "headers": headers}
    if timeout is not None:
        kwargs["timeout"] = timeout
    try:
        return await get_client().get(url, **kwargs)
    except httpx.HTTPError as exc:
        logger.warning("🌐 فشل الطلب إلى %s: %s", urlsplit(url).netloc, exc.__class__.__name__)
        return None


async def _get_json(
    url: str,
    *,
    params: dict | None = None,
    headers: dict | None = None,
    timeout: float | None = None,
    ok_statuses: tuple[int, ...] = (200,),
) -> Any | None:
    """طلب GET يُرجع JSON، أو None عند الفشل أو عند رمز حالة غير متوقع."""
    resp = await _fetch(url, params=params, headers=headers, timeout=timeout)
    if resp is None or resp.status_code not in ok_statuses:
        return None
    try:
        return resp.json()
    except ValueError:
        return None


# ═══════════════════════════════════════════════════════════
# 🔎 البحث داخل تيليجرام (Google Dorks)
# ═══════════════════════════════════════════════════════════


@dataclass
class SearchOutcome:
    """نتيجة بحث: قائمة النتائج + اسم المصدر + سبب الفشل إن وُجد."""

    items: list[dict]
    provider: str = ""
    error: str | None = None  # no_key | failed


@dataclass
class SearchPage:
    """صفحة واحدة من نتائج البحث جاهزة للعرض."""

    text: str
    page: int
    pages: int
    items: list[tuple[int, dict]]  # (رقم النتيجة، النتيجة)


_SEARCH_CACHE: dict[str, tuple[float, SearchOutcome]] = {}
_SEARCH_CACHE_TTL = 600  # 10 دقائق — يوفّر رصيد مفتاح البحث عند تكرار نفس البحث


def _search_item(title: Any, url: Any, snippet: Any) -> dict:
    return {"title": strip_tags(str(title or "")), "url": str(url or ""), "snippet": strip_tags(str(snippet or ""))}


async def _search_serper(query: str) -> list[dict] | None:
    """نتائج Google عبر Serper.dev (يتطلب SERPER_API_KEY)."""
    try:
        resp = await get_client().post(
            "https://google.serper.dev/search",
            json={"q": query, "num": 10},
            headers={"X-API-KEY": config.SERPER_API_KEY},
            timeout=15,
        )
    except httpx.HTTPError as exc:
        logger.warning("🔎 فشل الاتصال بـ Serper: %s", exc.__class__.__name__)
        return None
    if resp.status_code != 200:
        logger.warning("🔎 Serper أعاد الرمز %s (تحقق من المفتاح أو الرصيد)", resp.status_code)
        return None
    try:
        data = resp.json()
    except ValueError:
        return None
    return [
        _search_item(r.get("title"), r.get("link"), r.get("snippet"))
        for r in data.get("organic") or []
        if r.get("link")
    ]


async def _search_brave(query: str) -> list[dict] | None:
    """نتائج Brave Search API (يتطلب BRAVE_API_KEY)."""
    resp = await _fetch(
        "https://api.search.brave.com/res/v1/web/search",
        params={"q": query, "count": 10},
        headers={"X-Subscription-Token": config.BRAVE_API_KEY, "Accept": "application/json"},
        timeout=15,
    )
    if resp is None or resp.status_code != 200:
        if resp is not None:
            logger.warning("🔎 Brave أعاد الرمز %s (تحقق من المفتاح أو الرصيد)", resp.status_code)
        return None
    try:
        data = resp.json()
    except ValueError:
        return None
    return [
        _search_item(r.get("title"), r.get("url"), r.get("description"))
        for r in (data.get("web") or {}).get("results") or []
        if r.get("url")
    ]


async def _search_keyless(query: str) -> list[dict] | None:
    """بحث مجاني بدون مفتاح عبر مكتبة ddgs — محدود لأن محركات البحث كثيراً ما تحجب الخوادم."""
    try:
        from ddgs import DDGS
    except ImportError:
        return None

    def run() -> list[dict]:
        return DDGS(timeout=8).text(query, max_results=10, backend="auto")

    try:
        results = await asyncio.wait_for(asyncio.to_thread(run), timeout=25)
    except Exception as exc:  # noqa: BLE001 — المكتبة ترفع أنواعاً مختلفة من الأخطاء
        logger.info("🔎 البحث المجاني لم يُرجع نتائج: %s", exc.__class__.__name__)
        return None
    items = [_search_item(r.get("title"), r.get("href"), r.get("body")) for r in results if r.get("href")]
    return items or None


async def web_search(query: str) -> SearchOutcome:
    """تنفيذ البحث: Serper ← Brave ← البحث المجاني، مع ذاكرة مؤقتة لمدة 10 دقائق."""
    key = query.strip().lower()
    cached = _SEARCH_CACHE.get(key)
    if cached and time.time() - cached[0] < _SEARCH_CACHE_TTL:
        return cached[1]

    outcome: SearchOutcome | None = None
    if config.SERPER_API_KEY:
        items = await _search_serper(query)
        if items is not None:
            outcome = SearchOutcome(items, "Google")
    if outcome is None and config.BRAVE_API_KEY:
        items = await _search_brave(query)
        if items is not None:
            outcome = SearchOutcome(items, "Brave")
    if outcome is None:
        items = await _search_keyless(query)
        if items is not None:
            outcome = SearchOutcome(items, "بحث مجاني")
    if outcome is None:
        has_key = bool(config.SERPER_API_KEY or config.BRAVE_API_KEY)
        return SearchOutcome([], error="failed" if has_key else "no_key")

    _SEARCH_CACHE[key] = (time.time(), outcome)
    if len(_SEARCH_CACHE) > 500:
        oldest = min(_SEARCH_CACHE, key=lambda k: _SEARCH_CACHE[k][0])
        _SEARCH_CACHE.pop(oldest, None)
    return outcome


_NUM_EMOJI = ("1️⃣", "2️⃣", "3️⃣", "4️⃣", "5️⃣", "6️⃣", "7️⃣", "8️⃣", "9️⃣", "🔟")

NO_SEARCH_KEY_TEXT = (
    "⚠️ <b>البحث داخل تيليجرام غير مفعّل بعد.</b>\n"
    "محركات البحث تمنع البحث المجاني القادم من الخوادم، لذلك يحتاج البوت مفتاحاً مجانياً (مرة واحدة فقط):\n"
    "1️⃣ سجّل في <b>serper.dev</b> وانسخ <b>API Key</b> (2,500 بحث مجاناً بدون بطاقة)\n"
    "2️⃣ أضفه في GitHub ← Settings ← Secrets and variables ← Actions باسم <code>SERPER_API_KEY</code>\n"
    "3️⃣ من تبويب Actions اضغط <b>Run workflow</b> — وبعدها كل النتائج تظهر هنا."
)

NO_SEARCH_USER_TEXT = "⚠️ البحث داخل تيليجرام غير متاح حالياً — حاول لاحقاً."


SEPARATOR = "━━━━━━━━━━━━━━━━"

# إيموجي لكل موقع ونوع ملف — تجعل النتائج أوضح بنظرة واحدة
_SITE_ICONS = (
    ("tiktok.com", "🎵"), ("instagram.com", "📸"), ("x.com", "𝕏"), ("twitter.com", "🐦"),
    ("facebook.com", "📘"), ("youtube.com", "▶️"), ("youtu.be", "▶️"), ("linkedin.com", "💼"),
    ("github.com", "💻"), ("pastebin.com", "📋"), ("reddit.com", "👽"), ("snapchat.com", "👻"),
    ("t.me", "✈️"), ("telegram.me", "✈️"), ("threads.net", "🧵"), ("scribd.com", "📚"),
    ("slideshare.net", "🖥️"), ("docs.google.com", "🗃️"), ("drive.google.com", "🗃️"),
    ("wikipedia.org", "📖"), ("researchgate.net", "🎓"), ("academia.edu", "🎓"), ("arxiv.org", "🎓"),
)
_EXT_ICONS = {
    ".pdf": "📕", ".doc": "📘", ".docx": "📘", ".xls": "📗", ".xlsx": "📗", ".csv": "📗",
    ".ppt": "📙", ".pptx": "📙", ".txt": "🗒️", ".zip": "🗜️",
}

# استخراج أرقام الحسابات من مقتطفات Google (إنجليزي وعربي)
_SNIPPET_STATS = (
    ("👥", "متابع", r"(\d[\d.,]*\s?[KMB]?)\s*(?:Followers|من المتابعين)"),
    ("➡️", "يتابع", r"(\d[\d.,]*\s?[KMB]?)\s*Following"),
    ("❤️", "إعجاب", r"(\d[\d.,]*\s?[KMB]?)\s*(?:Likes|من تسجيلات الإعجاب)"),
    ("🖼️", "منشور", r"(\d[\d.,]*\s?[KMB]?)\s*(?:Posts|من المنشورات)"),
    ("🎬", "فيديو", r"(\d[\d.,]*\s?[KMB]?)\s*Videos"),
)


def _result_icon(url: str) -> str:
    parts = urlsplit(url)
    path, host = parts.path.lower(), (parts.hostname or "").lower()
    for ext, icon in _EXT_ICONS.items():
        if path.endswith(ext):
            return icon
    for site, icon in _SITE_ICONS:
        if host == site or host.endswith("." + site):
            return icon
    if ".gov" in host:
        return "🏛️"
    if ".edu" in host or ".ac." in host:
        return "🎓"
    return "🌐"


def _display_url(url: str) -> str:
    """رابط مختصر للعرض: tiktok.com/@user/video/123…"""
    parts = urlsplit(url)
    host = (parts.hostname or "").removeprefix("www.")
    return _short(host + unquote(parts.path.rstrip("/")), 55)


def _clean_snippet(text: str) -> str:
    """تنظيف مقتطفات Google: فصل الجمل الملتصقة وتوحيد المسافات."""
    text = re.sub(r"\.(?=[؀-ۿA-Z])", ". ", text)
    text = re.sub(r"(?<=[؀-ۿ])\.(?=\S)", ". ", text)  # «الإعجاب.1766» ← «الإعجاب. 1766»
    text = re.sub(r"\s*\|\s*", " | ", text)
    text = re.sub(r"\s*·\s*", " · ", text)
    return re.sub(r"\s+", " ", text).strip(" .|·")


def _snippet_stats(text: str) -> str | None:
    found = []
    for icon, label, pattern in _SNIPPET_STATS:
        match = re.search(pattern, text, re.IGNORECASE)
        if match:
            found.append(f"{icon} {match.group(1).strip()} {label}")
    return " • ".join(found) if found else None


def _has_emoji_prefix(text: str) -> bool:
    return bool(text) and not text[0].isalnum() and text[0] not in "\"'(@#"


def format_search_page(
    title: str, query: str, outcome: SearchOutcome, page: int, *, show_setup_hint: bool = True
) -> SearchPage:
    """تنسيق صفحة من نتائج البحث كنص HTML مرتب داخل تيليجرام."""
    per_page = max(1, config.SEARCH_RESULTS_PER_PAGE)
    items = outcome.items
    pages = max(1, math.ceil(len(items) / per_page))
    page = min(max(page, 0), pages - 1)
    start = page * per_page
    chunk = list(enumerate(items[start : start + per_page], start=start + 1))

    heading = title if _has_emoji_prefix(title) else f"🔎 {title}"
    lines: list[str | None] = [
        f"<b>{esc(heading)}</b>",
        SEPARATOR,
        f"🧭 <code>{esc(_short(query, 200))}</code>",
    ]
    if items:
        lines.append(
            f"📊 النتائج: <b>{len(items)}</b> • 🌐 {esc(outcome.provider)} • 📄 صفحة <b>{page + 1}</b>/{pages}"
        )
    lines.append(SEPARATOR)

    if not items:
        if outcome.error == "no_key":
            lines.append(NO_SEARCH_KEY_TEXT if show_setup_hint else NO_SEARCH_USER_TEXT)
        elif outcome.error:
            lines.append("⚠️ تعذّر الاتصال بمحرك البحث حالياً (قد يكون رصيد المفتاح انتهى) — حاول لاحقاً.")
        else:
            lines += [
                "📭 <b>لا توجد نتائج لهذا البحث.</b>",
                "💡 جرّب خياراً آخر من الأزرار، أو اكتب الاسم بطريقة مختلفة (عربي / إنجليزي).",
            ]

    for number, item in chunk:
        badge = _NUM_EMOJI[number - 1] if number <= len(_NUM_EMOJI) else f"{number}."
        title_text = esc(_short(item["title"] or _display_url(item["url"]), 90))
        snippet = _clean_snippet(item["snippet"]) if item["snippet"] else ""
        stats = _snippet_stats(f"{item['title']} {item['snippet']}")
        lines += [
            "",
            f'{badge} {_result_icon(item["url"])} <b><a href="{esc_attr(item["url"])}">{title_text}</a></b>',
            f"🔗 <i>{esc(_display_url(item['url']))}</i>",
            f"📝 {esc(_short(snippet, 220))}" if snippet else None,
            stats,
        ]

    if items:
        lines += ["", SEPARATOR, "👆 اضغط على العنوان لفتح الصفحة"]
    return SearchPage(_join(lines).strip(), page, pages, chunk)


# ═══════════════════════════════════════════════════════════
# 🧭 استعلامات DNS / RDAP / الموقع الجغرافي (مجانية بدون مفاتيح)
# ═══════════════════════════════════════════════════════════

_DNS_TYPE_CODES = {"A": 1, "NS": 2, "CNAME": 5, "PTR": 12, "MX": 15, "TXT": 16, "AAAA": 28}
_DOH_ENDPOINTS = ("https://cloudflare-dns.com/dns-query", "https://dns.google/resolve")


async def dns_query(name: str, rtype: str) -> list[str]:
    """استعلام DNS عبر HTTPS (DoH) — يجرب Cloudflare ثم Google كاحتياطي."""
    code = _DNS_TYPE_CODES[rtype]
    for endpoint in _DOH_ENDPOINTS:
        data = await _get_json(
            endpoint,
            params={"name": name, "type": rtype},
            headers={"accept": "application/dns-json"},
        )
        if not isinstance(data, dict):
            continue  # جرّب الخادم التالي
        if data.get("Status") != 0:
            return []  # NXDOMAIN أو خطأ آخر من خادم DNS
        records: list[str] = []
        for answer in data.get("Answer") or []:
            if answer.get("type") != code:
                continue
            value = str(answer.get("data", "")).strip()
            if rtype == "TXT":
                value = re.sub(r'"\s+"', "", value).strip('"')
            else:
                value = value.rstrip(".")
            if value and value not in records:
                records.append(value)
        if rtype == "MX":
            records.sort(key=lambda r: int(r.split()[0]) if r.split()[0].isdigit() else 0)
        return records
    return []


async def rdap_lookup(kind: str, target: str) -> dict | None:
    """استعلام RDAP (البديل الحديث لـ WHOIS) — kind: domain أو ip."""
    data = await _get_json(
        f"https://rdap.org/{kind}/{quote(target, safe='')}",
        headers={"accept": "application/rdap+json, application/json"},
    )
    return data if isinstance(data, dict) else None


def _rdap_entity_name(data: dict, role: str) -> str | None:
    """استخراج اسم جهة بدور معين (مثل registrar) من بيانات RDAP."""
    for entity in data.get("entities") or []:
        if role not in (entity.get("roles") or []):
            continue
        vcard = entity.get("vcardArray")
        if isinstance(vcard, list) and len(vcard) > 1:
            for item in vcard[1]:
                if isinstance(item, list) and len(item) > 3 and item[0] == "fn" and item[3]:
                    return str(item[3])
        if entity.get("handle"):
            return str(entity["handle"])
    return None


def _rdap_events(data: dict) -> dict[str, str]:
    """استخراج التواريخ المهمة (التسجيل، الانتهاء، آخر تحديث) من RDAP."""
    events: dict[str, str] = {}
    for event in data.get("events") or []:
        action, date = event.get("eventAction"), event.get("eventDate")
        if action and date:
            events[action] = str(date)[:10]
    return events


async def _rdap_domain(domain: str) -> tuple[str, dict] | None:
    """RDAP للدومين مع تجربة النطاق الأب عند إدخال نطاق فرعي (mail.example.com ← example.com)."""
    labels = domain.split(".")
    candidates = [".".join(labels[i:]) for i in range(len(labels) - 1)][:3]
    for candidate in candidates:
        data = await rdap_lookup("domain", candidate)
        if data and (data.get("ldhName") or data.get("objectClassName") == "domain"):
            return candidate, data
    return None


async def ip_geolocation(ip: str) -> dict | None:
    """الموقع الجغرافي لعنوان IP عبر ip-api.com، ثم ipwho.is كاحتياطي.

    ملاحظة: النسخة المجانية من ip-api.com تعمل عبر HTTP فقط وبحد 45 طلباً في الدقيقة.
    """
    fields = (
        "status,message,country,countryCode,regionName,city,lat,lon,timezone,"
        "isp,org,as,reverse,mobile,proxy,hosting"
    )
    data = await _get_json(f"http://ip-api.com/json/{ip}", params={"fields": fields})
    if isinstance(data, dict) and data.get("status") == "success":
        return {
            "country": data.get("country"),
            "country_code": data.get("countryCode"),
            "region": data.get("regionName"),
            "city": data.get("city"),
            "lat": data.get("lat"),
            "lon": data.get("lon"),
            "timezone": data.get("timezone"),
            "isp": data.get("isp"),
            "org": data.get("org"),
            "asn": data.get("as"),
            "reverse": data.get("reverse"),
            "mobile": data.get("mobile"),
            "proxy": data.get("proxy"),
            "hosting": data.get("hosting"),
        }

    data = await _get_json(f"https://ipwho.is/{ip}")
    if isinstance(data, dict) and data.get("success"):
        conn = data.get("connection") or {}
        asn = conn.get("asn")
        return {
            "country": data.get("country"),
            "country_code": data.get("country_code"),
            "region": data.get("region"),
            "city": data.get("city"),
            "lat": data.get("latitude"),
            "lon": data.get("longitude"),
            "timezone": (data.get("timezone") or {}).get("id"),
            "isp": conn.get("isp"),
            "org": conn.get("org"),
            "asn": f"AS{asn} {conn.get('org') or ''}".strip() if asn else None,
            "reverse": None,
            "mobile": None,
            "proxy": None,
            "hosting": None,
        }
    return None


async def internetdb(ip: str) -> dict | None:
    """Shodan InternetDB (مجاني بدون مفتاح): المنافذ المفتوحة، أسماء المضيف، الثغرات المعروفة."""
    data = await _get_json(f"https://internetdb.shodan.io/{ip}")
    return data if isinstance(data, dict) else None


async def greynoise(ip: str) -> dict | None:
    """GreyNoise Community: هل يقوم هذا الـ IP بمسح الإنترنت؟ وهل هو خدمة معروفة؟"""
    data = await _get_json(f"https://api.greynoise.io/v3/community/{ip}", ok_statuses=(200, 404))
    return data if isinstance(data, dict) and "noise" in data else None


async def abuse_contacts(ip: str) -> list[str]:
    """جهة الإبلاغ عن الإساءة لهذا الـ IP عبر RIPEstat."""
    data = await _get_json(
        "https://stat.ripe.net/data/abuse-contact-finder/data.json", params={"resource": ip}
    )
    contacts = ((data or {}).get("data") or {}).get("abuse_contacts") if isinstance(data, dict) else None
    return [str(c) for c in contacts or []][:3]


async def wayback_snapshot(target: str, timestamp: str | None = None) -> dict | None:
    """لقطة من أرشيف Wayback Machine — الأحدث افتراضياً، أو الأقرب لتاريخ معيّن (مثل 19900101 = الأقدم)."""
    params = {"url": target}
    if timestamp:
        params["timestamp"] = timestamp
    data = await _get_json("https://archive.org/wayback/available", params=params)
    closest = ((data or {}).get("archived_snapshots") or {}).get("closest") or {}
    if not (closest.get("available") and closest.get("url")):
        return None
    ts = str(closest.get("timestamp", ""))
    date = f"{ts[0:4]}-{ts[4:6]}-{ts[6:8]}" if len(ts) >= 8 else ts
    return {"url": str(closest["url"]).replace("http://", "https://", 1), "date": date}


# ═══════════════════════════════════════════════════════════
# ✅ التحقق من صحة المدخلات
# ═══════════════════════════════════════════════════════════

_DOMAIN_RE = re.compile(
    r"^(?=.{1,253}$)(?:(?!-)[a-z0-9-]{1,63}(?<!-)\.)+(?:[a-z]{2,63}|xn--[a-z0-9-]{1,59})$"
)


def is_ip(text: str) -> bool:
    try:
        ipaddress.ip_address(text.strip("[]"))
        return True
    except ValueError:
        return False


def normalize_domain(raw: str) -> str:
    """تحويل الإدخال إلى اسم نطاق نظيف: حذف http/المسار/المنفذ/www وتحويل النطاقات العربية."""
    text = raw.strip().lower()
    if "://" in text:
        text = urlsplit(text).hostname or ""
    else:
        text = text.split("/")[0].split("?")[0].split("#")[0]
        text = text.rsplit("@", 1)[-1].split(":")[0]
    text = text.strip().rstrip(".")
    if text.startswith("www.") and text.count(".") >= 2:
        text = text[4:]
    try:
        text = text.encode("idna").decode("ascii")  # دعم النطاقات العربية (IDN)
    except UnicodeError:
        raise InvalidInput("❌ اسم النطاق غير صالح. أرسل نطاقاً مثل <code>example.com</code>") from None
    if not _DOMAIN_RE.match(text):
        raise InvalidInput("❌ اسم النطاق غير صالح. أرسل نطاقاً مثل <code>example.com</code>")
    return text


# ═══════════════════════════════════════════════════════════
# 1️⃣ 🕵️ بحث متقدم: X / Instagram / TikTok
# ═══════════════════════════════════════════════════════════

_SOCIAL_HANDLE_RE = re.compile(r"@?([A-Za-z0-9_.]{2,30})")

_INSIDE_HINT = "👇 اضغط على أي زر وستظهر النتائج هنا داخل تيليجرام."


async def social_lookup(query: str) -> LookupResult:
    """بحث Google Dorks عن اسم أو يوزر في X و Instagram و TikTok — النتائج داخل تيليجرام."""
    q = clean_query(query)
    match = _SOCIAL_HANDLE_RE.fullmatch(q)
    handle = match.group(1) if match else None
    term = phrase(handle or q)

    dorks = [
        ("𝕏 نتائج X", f"site:x.com {term}"),
        ("🐦 أرشيف Twitter", f"site:twitter.com {term}"),
        ("📸 نتائج Instagram", f"site:instagram.com {term}"),
        ("🎵 نتائج TikTok", f"site:tiktok.com {term}"),
    ]
    combined = f"{term} (site:x.com OR site:instagram.com OR site:tiktok.com)"

    # أزرار الدورك تفتح Google في المتصفح مباشرة
    actions = [search_action(label, dork, browser=True) for label, dork in dorks]
    actions.append(search_action("🌐 كل المنصات في بحث واحد", combined, wide=True, browser=True))
    if handle:
        actions += [
            search_action("🗣️ إشارات للحساب خارج X", f'"@{handle}" -site:x.com -site:twitter.com', browser=True),
            search_action("🔗 روابط الحساب (Linktree...)", f'"{handle}" (site:linktr.ee OR site:beacons.ai OR site:linkin.bio)', browser=True),
            Action("🧭 فحص اليوزر في +600 موقع", "wmn", handle, wide=True),
        ]

    lines = [
        "🕵️ <b>بحث متقدم — X / Instagram / TikTok</b>",
        "",
        f"🎯 الهدف: <code>{esc(q)}</code>",
        f"🧩 النوع: {'اسم مستخدم محتمل 👤' if handle else 'اسم / عبارة بحث 🔤'}",
        "",
        "<b>🔎 الاستعلامات المُولّدة (Google Dorks):</b>",
        *[f"• <code>{esc(dork)}</code>" for _, dork in dorks],
        "",
        "🌐 اضغط أي زر ليفتح نتائج Google في متصفحك.",
        "💡 <i>نصيحة: جرّب الاسم بالعربية والإنجليزية للحصول على نتائج أشمل.</i>",
    ]
    return LookupResult(_join(lines), actions)


# ═══════════════════════════════════════════════════════════
# 2️⃣ 🔗 رابط / ملف (وثائق وملفات)
# ═══════════════════════════════════════════════════════════

_URL_HINT_RE = re.compile(r"^(https?://|www\.)", re.IGNORECASE)


def _extract_site(text: str) -> str | None:
    """إذا كان الإدخال رابطاً يُرجع اسم النطاق، وإلا None (أي أنه كلمة بحث عادية)."""
    t = text.strip()
    looks_like_url = bool(_URL_HINT_RE.match(t)) or (
        " " not in t and "/" in t and "." in t.split("/", 1)[0]
    )
    if not looks_like_url:
        return None
    if not re.match(r"^https?://", t, re.IGNORECASE):
        t = "http://" + t
    host = urlsplit(t).hostname
    if not host:
        return None
    try:
        return normalize_domain(host)
    except InvalidInput:
        return None


async def docs_lookup(query: str) -> LookupResult:
    """البحث عن الوثائق والملفات المنشورة علناً — النتائج والملفات نفسها داخل تيليجرام."""
    q = clean_query(query)
    site = _extract_site(q)
    all_types = "(filetype:pdf OR filetype:docx OR filetype:xlsx OR filetype:pptx)"

    if site:
        # 🔗 وضع الرابط: حصر البحث داخل الموقع المحدد
        base = f"site:{site}"
        dorks = [
            ("📕 PDF", f"{base} filetype:pdf"),
            ("📘 Word", f"{base} (filetype:doc OR filetype:docx)"),
            ("📗 Excel", f"{base} (filetype:xls OR filetype:xlsx)"),
            ("📙 PowerPoint", f"{base} (filetype:ppt OR filetype:pptx)"),
            ("🗒️ TXT / CSV", f"{base} (filetype:txt OR filetype:csv)"),
        ]
        actions = [search_action(label, dork, docs=True) for label, dork in dorks]
        actions += [
            search_action("📂 كل أنواع الملفات", f"{base} {all_types}", docs=True, wide=True),
            search_action("📄 الصفحات المفهرسة", base),
            Action("🔬 فحوصات ولقطة شاشة", "urlscan", site),
        ]
        first, last = await asyncio.gather(
            _safe(wayback_snapshot(site, "19900101"), None, timeout=config.HTTP_TIMEOUT),
            _safe(wayback_snapshot(q), None, timeout=config.HTTP_TIMEOUT),
        )
        if last is None:
            last = await _safe(wayback_snapshot(site), None, timeout=config.HTTP_TIMEOUT)
        mode_lines = [
            f"🔗 تم التعرف على رابط — سيتم حصر البحث داخل: <code>{esc(site)}</code>",
            _wayback_line("🕰️ أول أرشفة", first),
            _wayback_line("🕰️ آخر أرشفة", last),
        ]
    else:
        # 🔤 وضع الكلمة المفتاحية
        base = phrase(q)
        dorks = [
            ("📕 PDF", f"{base} filetype:pdf"),
            ("📘 Word", f"{base} (filetype:doc OR filetype:docx)"),
            ("📗 Excel", f"{base} (filetype:xls OR filetype:xlsx)"),
            ("📙 PowerPoint", f"{base} (filetype:ppt OR filetype:pptx)"),
            ("🏛️ حكومي/أكاديمي", f"{base} (site:.gov OR site:.edu)"),
            ("🎓 أبحاث علمية", f"{base} (site:researchgate.net OR site:academia.edu OR site:arxiv.org)"),
            ("📚 Scribd", f"site:scribd.com {base}"),
            ("🖥️ SlideShare", f"site:slideshare.net {base}"),
            ("🗃️ Google Docs/Drive", f"{base} (site:docs.google.com OR site:drive.google.com)"),
        ]
        file_kinds = {"📕 PDF", "📘 Word", "📗 Excel", "📙 PowerPoint"}
        actions = [search_action(label, dork, docs=label in file_kinds) for label, dork in dorks]
        actions.append(search_action("📂 كل أنواع الملفات", f"{base} {all_types}", docs=True, wide=True))
        mode_lines = [f"🔤 كلمة البحث: <code>{esc(q)}</code>"]

    lines = [
        f"📄 <b>وثائق — {esc(site or q)}</b>",
        "━━━━━━━━━━━━━━━━━━━━",
        "",
        *mode_lines,
        "",
        "<b>🔎 أمثلة على الاستعلامات المُولّدة:</b>",
        *[f"• <code>{esc(dork)}</code>" for _, dork in dorks[:4]],
        "",
        _INSIDE_HINT,
        "📥 <i>في نتائج الملفات اضغط زر التحميل ليصلك الملف نفسه هنا.</i>",
    ]
    # نتائج «كل أنواع الملفات» تظهر مباشرة تحت التقرير (عند تفعيل مفتاح البحث)
    first = next(a for a in actions if a.label == "📂 كل أنواع الملفات")
    return LookupResult(_join(lines), actions, autorun=first, autorun_needs_key=True)


def _wayback_line(label: str, snapshot: dict | None) -> str:
    if snapshot:
        return f'{label}: <a href="{esc_attr(snapshot["url"])}">{esc(snapshot["date"])}</a>'
    return f"{label}: <i>لا توجد لقطات محفوظة</i>"


# ═══════════════════════════════════════════════════════════
# 3️⃣ 🌐 الدومين
# ═══════════════════════════════════════════════════════════


def _ports_line(db: dict | None) -> str | None:
    """سطر المنافذ المفتوحة من Shodan InternetDB."""
    if not db or not db.get("ports"):
        return None
    ports = ", ".join(str(p) for p in sorted(db["ports"])[:15])
    more = f" (+{len(db['ports']) - 15})" if len(db["ports"]) > 15 else ""
    return f"• 🛰️ المنافذ المفتوحة: <code>{ports}</code>{more}"


async def domain_lookup(query: str) -> LookupResult:
    """تقرير الدومين: DNS + RDAP + الاستضافة + المنافذ + الأرشيف، وأزرار تعرض المزيد داخل تيليجرام."""
    q = clean_query(query)
    if is_ip(q):
        raise InvalidInput("ℹ️ هذا عنوان IP وليس دومين — استخدم قسم «🌐 IP» من القائمة الرئيسية.")
    domain = normalize_domain(q)

    a, aaaa, mx, ns, txt, rdap, first, last = await asyncio.gather(
        _safe(dns_query(domain, "A"), []),
        _safe(dns_query(domain, "AAAA"), []),
        _safe(dns_query(domain, "MX"), []),
        _safe(dns_query(domain, "NS"), []),
        _safe(dns_query(domain, "TXT"), []),
        _safe(_rdap_domain(domain), None, timeout=15),
        _safe(wayback_snapshot(domain, "19900101"), None, timeout=config.HTTP_TIMEOUT),
        _safe(wayback_snapshot(domain), None, timeout=config.HTTP_TIMEOUT),
    )
    hosting, db = (None, None)
    if a:
        hosting, db = await asyncio.gather(_safe(ip_geolocation(a[0]), None), _safe(internetdb(a[0]), None))

    lines: list[str | None] = [f"🌐 <b>تقرير الدومين:</b> <code>{esc(domain)}</code>", ""]

    # 📇 بيانات التسجيل
    if rdap:
        registered, data = rdap
        events = _rdap_events(data)
        statuses = data.get("status") or []
        lines += [
            "<b>📇 بيانات التسجيل (RDAP / WHOIS):</b>",
            _kv("النطاق المسجَّل", registered) if registered != domain else None,
            _kv("المسجِّل (Registrar)", _rdap_entity_name(data, "registrar")),
            _kv("تاريخ الإنشاء", events.get("registration")),
            _kv("عمر النطاق", _age_text(events.get("registration")), code=False),
            _kv("تاريخ الانتهاء", events.get("expiration")),
            _kv("آخر تحديث", events.get("last changed")),
            _kv("الحالة", "، ".join(statuses[:3]), code=False) if statuses else None,
        ]
    else:
        lines.append("📇 بيانات التسجيل: <i>غير متاحة عبر RDAP لهذا الامتداد</i>")

    # 🧭 سجلات DNS
    lines += ["", "<b>🧭 سجلات DNS:</b>"]
    has_dns = False
    for label, records, limit in (("A", a, 5), ("AAAA", aaaa, 3), ("MX", mx, 5), ("NS", ns, 4)):
        if records:
            has_dns = True
            shown = ", ".join(f"<code>{esc(r)}</code>" for r in records[:limit])
            more = f" <i>(+{len(records) - limit})</i>" if len(records) > limit else ""
            lines.append(f"• <b>{label}:</b> {shown}{more}")
    if txt:
        has_dns = True
        lines.append("• <b>TXT:</b>")
        lines += [f"   ◦ <code>{esc(_short(r, 110))}</code>" for r in txt[:5]]
        if len(txt) > 5:
            lines.append(f"   ◦ <i>(+{len(txt) - 5} سجلات أخرى)</i>")
    if not has_dns:
        lines.append("• لا توجد سجلات DNS — قد يكون النطاق غير مسجَّل أو غير مفعَّل.")

    # 🖥️ الاستضافة
    if hosting or db:
        lines += ["", "<b>🖥️ الخادم:</b>"]
        if hosting:
            host_name = hosting.get("org") or hosting.get("isp") or "غير معروف"
            asn = f" ({esc(hosting['asn'])})" if hosting.get("asn") else ""
            lines.append(
                f"• الاستضافة: {flag(hosting.get('country_code'))} "
                f"{esc(hosting.get('country') or '')} — {esc(host_name)}{asn}"
            )
        lines.append(_ports_line(db))

    # 🕰️ الأرشيف
    if first or last:
        lines += ["", "<b>🕰️ الأرشيف (Wayback Machine):</b>", _wayback_line("• أول أرشفة", first), _wayback_line("• آخر أرشفة", last)]

    lines += ["", _INSIDE_HINT]

    actions = [
        Action("🌿 النطاقات الفرعية", "subdomains", domain),
        Action("🔬 فحوصات ولقطة شاشة", "urlscan", domain),
    ]
    if a:
        actions.append(Action("🌐 تقرير IP الخادم", "lookup", a[0], ("ip",)))
    actions += [
        search_action("📂 الملفات المنشورة", f"site:{domain} (filetype:pdf OR filetype:docx OR filetype:xlsx)", docs=True),
        search_action("📄 الصفحات المفهرسة", f"site:{domain}"),
        search_action("🔑 صفحات الدخول", f"site:{domain} (inurl:login OR inurl:signin OR intitle:login)"),
        search_action("🗣️ إشارات خارجية", f'"{domain}" -site:{domain}'),
        search_action("💻 إشارات في GitHub", f'"{domain}" site:github.com'),
        search_action("📋 إشارات في Pastebin", f'"{domain}" site:pastebin.com'),
    ]
    return LookupResult(_join(lines), actions)


def _subdomain_set(raw_names: Any, domain: str) -> set[str]:
    """تنظيف قائمة أسماء وإبقاء النطاقات الفرعية التابعة للدومين فقط."""
    names: set[str] = set()
    for raw in raw_names:
        for name in str(raw).lower().split("\n"):
            name = name.strip().removeprefix("*.").rstrip(".")
            if name and " " not in name and "@" not in name and (name == domain or name.endswith("." + domain)):
                names.add(name)
    return names


async def _crtsh(domain: str) -> set[str] | None:
    """النطاقات الفرعية من سجلات شهادات SSL العلنية (crt.sh)."""
    data = await _get_json(
        "https://crt.sh/", params={"q": domain, "output": "json", "exclude": "expired"}, timeout=25
    )
    if not isinstance(data, list):
        return None
    return _subdomain_set((row.get("name_value", "") for row in data if isinstance(row, dict)), domain)


async def _certspotter(domain: str) -> set[str] | None:
    """النطاقات الفرعية من سجلات الشهادات عبر Cert Spotter (سريع ومجاني)."""
    data = await _get_json(
        "https://api.certspotter.com/v1/issuances",
        params={"domain": domain, "include_subdomains": "true", "expand": "dns_names"},
        timeout=15,
    )
    if not isinstance(data, list):
        return None
    return _subdomain_set((n for row in data if isinstance(row, dict) for n in row.get("dns_names") or []), domain)


async def _subdomain_center(domain: str) -> set[str] | None:
    """النطاقات الفرعية من قاعدة subdomain.center المجانية."""
    data = await _get_json("https://api.subdomain.center/", params={"domain": domain}, timeout=25)
    return _subdomain_set(data, domain) if isinstance(data, list) else None


async def _hackertarget(domain: str) -> set[str] | None:
    """النطاقات الفرعية من HackerTarget (احتياطي مجاني محدود يومياً)."""
    resp = await _fetch("https://api.hackertarget.com/hostsearch/", params={"q": domain}, timeout=20)
    if resp is None or resp.status_code != 200:
        return None
    text = resp.text.strip()
    if not text or "error" in text[:80].lower() or "exceeded" in text.lower():
        return None
    return _subdomain_set((line.split(",")[0] for line in text.splitlines()), domain)


async def subdomains_report(domain: str) -> str:
    """تقرير النطاقات الفرعية: دمج عدة مصادر مجانية بالتوازي وعرضها داخل تيليجرام."""
    header = f"🌿 <b>النطاقات الفرعية لـ</b> <code>{esc(domain)}</code>"
    sources = {"Cert Spotter": _certspotter, "crt.sh": _crtsh, "subdomain.center": _subdomain_center}
    results = await asyncio.gather(*(_safe(fn(domain), None, timeout=30) for fn in sources.values()))
    found: set[str] = set()
    used = []
    for name, result in zip(sources, results, strict=True):
        if result:
            found |= result
            used.append(name)
    if not found:
        fallback = await _safe(_hackertarget(domain), None, timeout=25)
        if fallback:
            found, used = fallback, ["HackerTarget"]
    if not found and all(r is None for r in results):
        return header + "\n\n⚠️ تعذّر جلب البيانات حالياً من المصادر — حاول بعد قليل."
    if not found:
        return header + "\n\n📭 لم يتم العثور على نطاقات فرعية."
    names = sorted(found, key=lambda n: (n.count("."), n))
    source = "، ".join(used)
    shown: list[str] = []
    budget = 3300
    for name in names:
        if budget - len(name) - 1 < 0:
            break
        shown.append(name)
        budget -= len(name) + 1
    more = len(names) - len(shown)
    return (
        f"{header}\n📊 العدد: <b>{len(names)}</b> • المصدر: {source}\n\n"
        f"<pre>{esc(chr(10).join(shown))}</pre>"
        + (f"\n<i>(+{more} نطاقات أخرى)</i>" if more else "")
    )


async def urlscan_report(domain: str) -> tuple[str, str | None]:
    """آخر فحوصات urlscan.io للدومين + رابط لقطة الشاشة لأحدث فحص."""
    header = f"🔬 <b>فحوصات urlscan.io لـ</b> <code>{esc(domain)}</code>"
    data = await _get_json(
        "https://urlscan.io/api/v1/search/", params={"q": f"page.domain:{domain}", "size": 8}, timeout=20
    )
    results = data.get("results") if isinstance(data, dict) else None
    if results is None:
        return header + "\n\n⚠️ تعذّر الاتصال بـ urlscan.io حالياً — حاول بعد قليل.", None
    if not results:
        return header + "\n\n📭 لا توجد فحوصات علنية لهذا الدومين.", None
    lines = [header, ""]
    for result in results[:8]:
        task, page = result.get("task") or {}, result.get("page") or {}
        url = page.get("url") or task.get("url") or ""
        rid = result.get("_id")
        link = f'<a href="https://urlscan.io/result/{esc_attr(rid)}/">{esc(_short(url, 60))}</a>' if rid else esc(_short(url, 60))
        lines.append(f"• {esc(str(task.get('time', ''))[:10])} {flag(page.get('country'))} {link}")
        details = [
            f"IP: <code>{esc(page['ip'])}</code>" if page.get("ip") else None,
            f"الخادم: {esc(page['server'])}" if page.get("server") else None,
            f"الحالة: {esc(page['status'])}" if page.get("status") else None,
        ]
        details_text = " | ".join(d for d in details if d)
        if details_text:
            lines.append(f"   {details_text}")
    screenshot = next((r.get("screenshot") for r in results if r.get("screenshot")), None)
    return _join(lines), screenshot


# ═══════════════════════════════════════════════════════════
# 4️⃣ 🌐 عنوان IP
# ═══════════════════════════════════════════════════════════


async def ip_lookup(query: str) -> LookupResult:
    """تقرير IP: الموقع، المزود، ASN، المنافذ، السمعة، جهة الإبلاغ — وخريطة داخل تيليجرام."""
    q = clean_query(query).translate(_DIGITS_TABLE)
    note = None
    try:
        ip = ipaddress.ip_address(q.strip("[]"))
    except ValueError:
        # ليس IP — نحاول اعتباره دومين وتحويله إلى IP
        try:
            domain = normalize_domain(q)
        except InvalidInput:
            raise InvalidInput(
                "❌ عنوان IP غير صالح. أرسل عنواناً مثل <code>8.8.8.8</code> أو اسم نطاق مثل <code>example.com</code>"
            ) from None
        records = await _safe(dns_query(domain, "A"), []) or await _safe(dns_query(domain, "AAAA"), [])
        if not records:
            raise InvalidInput(
                f"❌ تعذّر تحويل <code>{esc(domain)}</code> إلى عنوان IP — تأكد من صحة النطاق."
            ) from None
        ip = ipaddress.ip_address(records[0])
        note = f"🔁 تم تحويل <code>{esc(domain)}</code> إلى <code>{ip}</code>"

    if not ip.is_global:
        raise InvalidInput(
            "⚠️ هذا عنوان IP خاص/محلي أو محجوز (مثل 192.168.x.x أو 10.x.x.x) "
            "ولا يمكن تحديد موقعه عبر الإنترنت."
        )

    ip_str = str(ip)
    geo, rdap, ptr, db, noise, abuse = await asyncio.gather(
        _safe(ip_geolocation(ip_str), None),
        _safe(rdap_lookup("ip", ip_str), None),
        _safe(dns_query(ip.reverse_pointer, "PTR"), []),
        _safe(internetdb(ip_str), None),
        _safe(greynoise(ip_str), None),
        _safe(abuse_contacts(ip_str), []),
    )

    lines: list[str | None] = [f"🌐 <b>تقرير IP:</b> <code>{ip_str}</code> (IPv{ip.version})"]
    if note:
        lines.append(note)
    lines.append("")

    place = None
    if geo:
        place = " — ".join(p for p in (geo.get("region"), geo.get("city")) if p)
        coords = f"{geo['lat']}, {geo['lon']}" if geo.get("lat") is not None else None
        lines += [
            f"{flag(geo.get('country_code'))} الدولة: <b>{esc(geo.get('country') or 'غير معروف')}</b>"
            + (f" ({esc(geo['country_code'])})" if geo.get("country_code") else ""),
            _kv("🏙️ المنطقة / المدينة", place, code=False),
            _kv("📍 الإحداثيات التقريبية", coords),
            _kv("🕒 المنطقة الزمنية", geo.get("timezone")),
            _kv("🏢 مزود الخدمة (ISP)", geo.get("isp"), code=False),
            _kv("🏛️ المنظمة", geo.get("org"), code=False),
            _kv("🔢 ASN", geo.get("asn")),
        ]
        if geo.get("hosting") is not None:
            lines.append(
                f"• 🛡️ مؤشرات: استضافة/سيرفر {_yes_no(geo.get('hosting'))} | "
                f"بروكسي/VPN {_yes_no(geo.get('proxy'))} | شبكة جوال {_yes_no(geo.get('mobile'))}"
            )
    else:
        lines.append("⚠️ <i>تعذّر جلب الموقع الجغرافي حالياً — جرّب لاحقاً.</i>")

    reverse = (ptr[0] if ptr else None) or (geo or {}).get("reverse")
    lines.append(_kv("🔁 Reverse DNS", reverse))

    # 🛰️ Shodan InternetDB
    if db:
        lines += ["", "<b>🛰️ المنافذ والخدمات (Shodan InternetDB):</b>", _ports_line(db)]
        if db.get("hostnames"):
            lines.append(_kv("أسماء المضيف", ", ".join(db["hostnames"][:5])))
        if db.get("tags"):
            lines.append(_kv("الوسوم", ", ".join(db["tags"][:6])))
        if db.get("cpes"):
            lines.append(_kv("البرمجيات المكتشفة", ", ".join(c.removeprefix("cpe:/") for c in db["cpes"][:4])))
        vulns = db.get("vulns") or []
        if vulns:
            shown = ", ".join(vulns[:6]) + (f" (+{len(vulns) - 6})" if len(vulns) > 6 else "")
            lines.append(f"• ⚠️ ثغرات معروفة: <b>{len(vulns)}</b> — <code>{esc(shown)}</code>")

    # 📡 السمعة
    if noise:
        if noise.get("riot"):
            reputation = f"✅ خدمة معروفة وموثوقة ({esc(noise.get('name') or '')})"
        elif noise.get("noise"):
            classification = {"malicious": "🔴 ضار", "benign": "🟢 غير ضار", "unknown": "🟡 غير معروف"}.get(
                str(noise.get("classification")), "🟡 غير معروف"
            )
            reputation = f"📡 يقوم بمسح الإنترنت — التصنيف: {classification}"
        else:
            reputation = "⚪ لم يُرصد وهو يمسح الإنترنت"
        lines += ["", f"<b>📡 السمعة (GreyNoise):</b> {reputation}"]
    if abuse:
        lines.append(_kv("🚨 الإبلاغ عن إساءة", ", ".join(abuse)))

    if rdap:
        start, end = rdap.get("startAddress"), rdap.get("endAddress")
        net_range = f"{start} - {end}" if start and end else None
        lines += [
            "",
            "<b>📶 بيانات الشبكة (RDAP):</b>",
            _kv("اسم الشبكة", rdap.get("name") or rdap.get("handle")),
            _kv("النطاق", net_range),
            _kv("الجهة المسجِّلة", _rdap_entity_name(rdap, "registrant"), code=False),
        ]

    lines += ["", "ℹ️ <i>الموقع الجغرافي تقريبي ويعكس موقع مزود الخدمة وليس موقع الشخص.</i>"]

    actions: list[Action] = []
    if geo and geo.get("lat") is not None:
        address = ", ".join(p for p in (geo.get("city"), geo.get("region"), geo.get("country")) if p)
        actions.append(
            Action("🗺️ عرض الموقع على الخريطة", "map", ip_str,
                   (float(geo["lat"]), float(geo["lon"]), f"📍 موقع تقريبي لـ {ip_str}", address or ip_str), wide=True)
        )
    actions.append(search_action("🔎 إشارات في الإنترنت", f'"{ip_str}"'))
    actions.append(search_action("🚨 بلاغات وتقارير", f'"{ip_str}" (abuse OR spam OR malware OR phishing)'))
    if reverse and not is_ip(reverse):
        try:
            actions.append(Action("🌐 فحص الدومين المرتبط", "lookup", normalize_domain(reverse), ("domain",), wide=True))
        except InvalidInput:
            pass
    return LookupResult(_join(lines), actions)


# ═══════════════════════════════════════════════════════════
# 5️⃣ 📞 رقم الهاتف
# ═══════════════════════════════════════════════════════════

_PHONE_TYPES_AR = {
    PhoneNumberType.MOBILE: "📱 جوال",
    PhoneNumberType.FIXED_LINE: "☎️ هاتف أرضي",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "📱 أرضي أو جوال",
    PhoneNumberType.TOLL_FREE: "🆓 رقم مجاني",
    PhoneNumberType.PREMIUM_RATE: "💰 رقم بتعرفة مميزة",
    PhoneNumberType.SHARED_COST: "🤝 تكلفة مشتركة",
    PhoneNumberType.VOIP: "🌐 VoIP (اتصال عبر الإنترنت)",
    PhoneNumberType.PERSONAL_NUMBER: "👤 رقم شخصي",
    PhoneNumberType.PAGER: "📟 بيجر",
    PhoneNumberType.UAN: "🏢 رقم موحّد (UAN)",
    PhoneNumberType.VOICEMAIL: "📨 بريد صوتي",
    PhoneNumberType.UNKNOWN: "❔ غير معروف",
}

_PHONE_FORMAT_HINT = (
    "أرسل الرقم بالصيغة الدولية مع رمز الدولة، مثل:\n"
    "<code>+966501234567</code> أو <code>00201001234567</code>"
)


def _parse_phone(raw: str) -> phonenumbers.PhoneNumber:
    """تحليل رقم الهاتف — يقبل +966… أو 00966… أو 966… (مع دعم الأرقام العربية)."""
    text = re.sub(r"[\s\-().]", "", raw.translate(_DIGITS_TABLE))
    if text.startswith("00"):
        text = "+" + text[2:]
    elif not text.startswith("+"):
        if not text.isdigit() or text.startswith("0"):
            raise InvalidInput(f"❌ لا يمكن تحديد الدولة.\n{_PHONE_FORMAT_HINT}")
        text = "+" + text
    try:
        number = phonenumbers.parse(text, None)
    except phonenumbers.NumberParseException:
        raise InvalidInput(f"❌ رقم الهاتف غير صالح.\n{_PHONE_FORMAT_HINT}") from None
    if not phonenumbers.is_possible_number(number):
        raise InvalidInput(f"❌ طول الرقم غير صحيح بالنسبة لرمز الدولة.\n{_PHONE_FORMAT_HINT}")
    return number


def _phone_report(raw: str) -> LookupResult:
    """تحليل الرقم محلياً (بدون إنترنت) وبناء التقرير والأزرار."""
    number = _parse_phone(clean_query(raw))
    e164 = phonenumbers.format_number(number, PhoneNumberFormat.E164)
    intl = phonenumbers.format_number(number, PhoneNumberFormat.INTERNATIONAL)
    national = phonenumbers.format_number(number, PhoneNumberFormat.NATIONAL)
    region = phonenumbers.region_code_for_number(number) or ""
    country_ar = geocoder.country_name_for_number(number, "ar") or geocoder.country_name_for_number(number, "en")
    area = geocoder.description_for_number(number, "ar") or geocoder.description_for_number(number, "en")
    operator = carrier.name_for_number(number, "en")
    zones = [z for z in pn_timezone.time_zones_for_number(number) if z != "Etc/Unknown"]
    num_type = _PHONE_TYPES_AR.get(phonenumbers.number_type(number), "❔ غير معروف")
    valid = phonenumbers.is_valid_number(number)
    digits = e164.lstrip("+")

    lines: list[str | None] = [
        "📞 <b>تقرير رقم الهاتف</b>",
        "",
        _kv("الصيغة الدولية", intl),
        _kv("صيغة E.164", e164),
        _kv("الصيغة المحلية", national),
        f"• الدولة: {flag(region)} <b>{esc(country_ar or 'غير معروف')}</b>"
        + (f" ({esc(region)})" if region else "")
        + f" — رمز <code>+{number.country_code}</code>",
        _kv("المنطقة", area, code=False) if area and area != country_ar else None,
        f"• نوع الرقم: {num_type}",
        _kv("المشغّل الأصلي", operator, code=False),
        _kv("المنطقة الزمنية", "، ".join(zones)),
        f"• صالح وفق خطة الترقيم: {_yes_no(valid)}",
        "",
        "ℹ️ <i>المشغّل المعروض هو المشغّل الأصلي للرقم وقد يكون نُقل لمشغّل آخر.</i>",
        "",
        _INSIDE_HINT,
    ]

    actions = [
        url_action("💬 فتح في واتساب", f"https://wa.me/{digits}"),
        url_action("✈️ فتح في تيليجرام", f"https://t.me/+{digits}"),
        search_action("🔎 بحث بكل الصيغ", f'"{e164}" OR "{intl}" OR "{national}"', wide=True),
        search_action(
            "👥 إشارات في الشبكات الاجتماعية",
            f'("{e164}" OR "{national}") '
            "(site:facebook.com OR site:x.com OR site:instagram.com OR site:linkedin.com)",
            wide=True,
        ),
    ]
    return LookupResult(_join(lines), actions)


async def phone_lookup(query: str) -> LookupResult:
    """تحليل رقم الهاتف في خيط منفصل حتى لا يتأثر البوت بتحميل قاعدة بيانات الأرقام."""
    return await asyncio.to_thread(_phone_report, query)


# ═══════════════════════════════════════════════════════════
# 6️⃣ 👤 اسم المستخدم (Username)
# ═══════════════════════════════════════════════════════════


@dataclass(frozen=True)
class _Platform:
    """منصة يمكن فحص وجود اسم المستخدم عليها عبر واجهة عامة بدون مفاتيح."""

    name: str
    profile: str  # رابط الملف الشخصي — {u} = اليوزر، {ul} = اليوزر بأحرف صغيرة
    check: str  # رابط الفحص
    kind: str  # status | json_list | json_object | contains | keybase
    pattern: str = r"[A-Za-z0-9_.-]{1,39}"  # صيغة اليوزر المقبولة على المنصة
    marker: str = ""  # نص يدل على وجود الحساب (لنوع contains)
    not_found: tuple[int, ...] = (404,)


_PLATFORMS: tuple[_Platform, ...] = (
    _Platform("GitHub", "https://github.com/{u}", "https://api.github.com/users/{u}", "status",
              r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})"),
    _Platform("GitLab", "https://gitlab.com/{u}", "https://gitlab.com/api/v4/users?username={u}", "json_list"),
    _Platform("Telegram", "https://t.me/{u}", "https://t.me/{u}", "contains",
              r"[A-Za-z][A-Za-z0-9_]{4,31}", marker="tgme_page_title"),
    _Platform("Bluesky", "https://bsky.app/profile/{ul}.bsky.social",
              "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={ul}.bsky.social", "status",
              r"[A-Za-z0-9-]{3,18}", not_found=(400, 404)),
    _Platform("Keybase", "https://keybase.io/{u}",
              "https://keybase.io/_/api/1.0/user/lookup.json?usernames={u}&fields=basics", "keybase",
              r"[A-Za-z0-9_]{2,16}"),
    _Platform("Docker Hub", "https://hub.docker.com/u/{ul}", "https://hub.docker.com/v2/users/{ul}/", "status",
              r"[A-Za-z0-9]{4,30}"),
    _Platform("Dev.to", "https://dev.to/{u}", "https://dev.to/api/users/by_username?url={u}", "status",
              r"[A-Za-z0-9_]{2,30}"),
    _Platform("Hacker News", "https://news.ycombinator.com/user?id={u}",
              "https://hacker-news.firebaseio.com/v0/user/{u}.json", "json_object", r"[A-Za-z0-9_-]{2,15}"),
    _Platform("Chess.com", "https://www.chess.com/member/{u}", "https://api.chess.com/pub/player/{ul}", "status",
              r"[A-Za-z0-9_-]{3,25}"),
    _Platform("Lichess", "https://lichess.org/@/{u}", "https://lichess.org/api/user/{u}", "status",
              r"[A-Za-z0-9_-]{2,20}"),
)

# منصات لا يمكن فحصها بدون تسجيل دخول — نبحث عنها داخل تيليجرام عبر Google Dorks
_SEARCH_PLATFORMS: tuple[tuple[str, str], ...] = (
    ("𝕏 X", "x.com"),
    ("📸 Instagram", "instagram.com"),
    ("🎵 TikTok", "tiktok.com"),
    ("📘 Facebook", "facebook.com"),
    ("▶️ YouTube", "youtube.com"),
    ("👻 Snapchat", "snapchat.com"),
    ("👽 Reddit", "reddit.com"),
    ("💼 LinkedIn", "linkedin.com"),
)

_USERNAME_RE = re.compile(r"[A-Za-z0-9._-]{2,40}")


async def _check_platform(platform: _Platform, username: str) -> tuple[str, Any]:
    """فحص وجود اليوزر على منصة واحدة.

    الحالة: found (موجود) | missing (غير موجود) | unknown (تعذّر التحقق) | skipped (صيغة غير مدعومة)
    """
    if not re.fullmatch(platform.pattern, username):
        return "skipped", None
    url = platform.check.format(u=quote(username, safe=""), ul=quote(username.lower(), safe=""))
    resp = await _fetch(url, headers={"accept": "application/json, text/html;q=0.9"})
    if resp is None:
        return "unknown", None
    if resp.status_code in platform.not_found:
        return "missing", None
    if resp.status_code != 200:
        return "unknown", None  # مثل 403/429 بسبب تحديد معدل الطلبات
    if platform.kind == "status":
        try:
            return "found", resp.json()
        except ValueError:
            return "found", None
    if platform.kind == "contains":
        return ("found" if platform.marker in resp.text else "missing"), None
    try:
        data = resp.json()
    except ValueError:
        return "unknown", None
    if platform.kind == "json_list":
        return ("found" if isinstance(data, list) and data else "missing"), None
    if platform.kind == "json_object":
        return ("found" if isinstance(data, dict) else "missing"), None
    if platform.kind == "keybase" and isinstance(data, dict):
        code = (data.get("status") or {}).get("code")
        them = data.get("them") or []
        if code == 0 and them and them[0]:
            return "found", None
        if code in (0, 100, 205):
            return "missing", None
    return "unknown", None


async def username_lookup(query: str) -> LookupResult:
    """فحص وجود اسم المستخدم على عدة منصات + ملف GitHub العلني + فحص شامل وبحث داخل تيليجرام."""
    q = clean_query(query).lstrip("@").strip()
    if not _USERNAME_RE.fullmatch(q):
        raise InvalidInput(
            "❌ اسم المستخدم يجب أن يكون بالأحرف الإنجليزية والأرقام فقط وبدون مسافات "
            "(مثل <code>john_doe</code>).\n"
            "💡 للبحث بالاسم الكامل استخدم قسم «🕵️ بحث متقدم»."
        )
    username = q
    u = quote(username, safe="")

    results = await asyncio.gather(
        *(_safe(_check_platform(p, username), ("unknown", None), timeout=config.HTTP_TIMEOUT + 2) for p in _PLATFORMS)
    )

    order = {"found": 0, "missing": 1, "unknown": 2, "skipped": 3}
    rows = sorted(zip(_PLATFORMS, results, strict=True), key=lambda row: order[row[1][0]])
    found = sum(1 for _, (state, _) in rows if state == "found")
    checked = sum(1 for _, (state, _) in rows if state in ("found", "missing"))

    lines: list[str | None] = [
        f"👤 <b>تقرير اسم المستخدم:</b> <code>{esc(username)}</code>",
        "",
        "<b>🔎 فحص الوجود السريع:</b>",
    ]
    for platform, (state, _) in rows:
        profile = platform.profile.format(u=u, ul=quote(username.lower(), safe=""))
        if state == "found":
            lines.append(f'✅ <a href="{esc_attr(profile)}">{esc(platform.name)}</a>')
        elif state == "missing":
            lines.append(f"❌ {esc(platform.name)}")
        elif state == "unknown":
            lines.append(f"⚠️ {esc(platform.name)} — <i>تعذّر التحقق</i>")
        else:
            lines.append(f"➖ {esc(platform.name)} — <i>صيغة اليوزر غير مدعومة</i>")
    lines += ["", f"📊 موجود في <b>{found}</b> من أصل <b>{checked}</b> منصة تم فحصها."]

    # 🐙 ملف GitHub العلني
    github_state, github = results[0]
    if github_state == "found" and isinstance(github, dict):
        created = str(github.get("created_at") or "")[:10] or None
        lines += [
            "",
            "<b>🐙 ملف GitHub العلني:</b>",
            _kv("الاسم", github.get("name"), code=False),
            _kv("النبذة", _short(str(github["bio"]), 150) if github.get("bio") else None, code=False),
            _kv("الشركة", github.get("company"), code=False),
            _kv("الموقع", github.get("location"), code=False),
            _kv("المدونة / الموقع", github.get("blog")),
            _kv("حساب X", github.get("twitter_username")),
            f"• المستودعات العامة: <b>{github.get('public_repos', 0)}</b> | "
            f"المتابِعون: <b>{github.get('followers', 0)}</b>",
            _kv("تاريخ الإنشاء", created),
        ]

    lines += [
        "",
        "🧭 اضغط «فحص شامل» لفحص اليوزر في أكثر من 600 موقع، أو ابحث عنه في المنصات الكبرى — "
        "كل النتائج تظهر هنا داخل تيليجرام.",
    ]

    actions = [Action("🧭 فحص شامل في +600 موقع (WhatsMyName)", "wmn", username, wide=True)]
    actions += [search_action(f"{label}", f'site:{site} "{username}"') for label, site in _SEARCH_PLATFORMS]
    actions.append(search_action("🔎 كل الإشارات في الإنترنت", f'"{username}"', wide=True))
    return LookupResult(_join(lines), actions)


# ═══════════════════════════════════════════════════════════
# 🧭 الفحص الشامل لليوزر (WhatsMyName — أكثر من 600 موقع)
# ═══════════════════════════════════════════════════════════

_WMN_DATA_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
_WMN_SKIP_CATEGORIES = {"xx NSFW xx", "archived", "dating"}
_WMN_OK_PROTECTION = {"user-agent"}  # المواقع المحمية بـ Cloudflare وغيرها تفشل غالباً من الخوادم
_WMN_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0 Safari/537.36"
)
_wmn_cache: dict[str, Any] = {"sites": [], "time": 0.0}

WMN_CATEGORIES_AR = {
    "social": "👥 تواصل اجتماعي", "gaming": "🎮 ألعاب", "tech": "💻 تقنية", "coding": "👨‍💻 برمجة",
    "hobby": "🎨 هوايات", "music": "🎵 موسيقى", "shopping": "🛍️ تسوق", "finance": "💰 مالية",
    "business": "💼 أعمال", "images": "🖼️ صور", "blog": "✍️ مدونات", "art": "🖌️ فن",
    "video": "🎬 فيديو", "political": "🏛️ سياسة", "news": "📰 أخبار", "health": "🩺 صحة",
    "misc": "📦 متنوع",
}


@dataclass(frozen=True)
class WmnHit:
    name: str
    url: str
    category: str


async def _wmn_sites() -> list[dict]:
    """تحميل قائمة المواقع من مشروع WhatsMyName (مع تخزين مؤقت لمدة 24 ساعة)."""
    if _wmn_cache["sites"] and time.time() - _wmn_cache["time"] < 86400:
        return _wmn_cache["sites"]
    data = await _get_json(_WMN_DATA_URL, timeout=30)
    if not isinstance(data, dict):
        return _wmn_cache["sites"]
    sites = [
        s for s in data.get("sites") or []
        if isinstance(s, dict)
        and "{account}" in str(s.get("uri_check", ""))
        and s.get("cat") not in _WMN_SKIP_CATEGORIES
        and s.get("valid", True)
        and set(s.get("protection") or []) <= _WMN_OK_PROTECTION
    ]
    _wmn_cache.update(sites=sites, time=time.time())
    return sites


async def wmn_scan(
    username: str, progress: Callable[[int, int], Awaitable[None]] | None = None
) -> tuple[list[WmnHit], int, int]:
    """فحص وجود اليوزر في كل مواقع WhatsMyName بالتوازي. يُرجع (النتائج، عدد ما تم فحصه، الإجمالي)."""
    sites = await _wmn_sites()
    if not sites:
        raise InvalidInput("⚠️ تعذّر تحميل قائمة مواقع WhatsMyName حالياً — حاول لاحقاً.")

    hits: list[WmnHit] = []
    done = 0
    semaphore = asyncio.Semaphore(config.WMN_CONCURRENCY)
    headers = {
        "User-Agent": _WMN_BROWSER_UA,
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
    }

    async with httpx.AsyncClient(
        timeout=httpx.Timeout(config.WMN_SITE_TIMEOUT),
        follow_redirects=False,  # قواعد WhatsMyName تعتمد على رموز التحويل (301/302)
        headers=headers,
        limits=httpx.Limits(max_connections=config.WMN_CONCURRENCY),
    ) as client:

        async def check(site: dict) -> None:
            nonlocal done
            account = username
            for char in str(site.get("strip_bad_char") or ""):
                account = account.replace(char, "")
            safe_account = quote(account, safe="")
            url = str(site["uri_check"]).replace("{account}", safe_account)
            try:
                async with semaphore:
                    extra_headers = site.get("headers") if isinstance(site.get("headers"), dict) else None
                    if site.get("post_body"):
                        body = str(site["post_body"]).replace("{account}", account)
                        resp = await client.post(url, content=body, headers=extra_headers)
                    else:
                        resp = await client.get(url, headers=extra_headers)
                if resp.status_code == site.get("e_code") and str(site.get("e_string", "")) in resp.text:
                    pretty = str(site.get("uri_pretty") or site["uri_check"]).replace("{account}", safe_account)
                    hits.append(WmnHit(str(site.get("name", "?")), pretty, str(site.get("cat") or "misc")))
            except (httpx.HTTPError, UnicodeError, ValueError):
                pass
            finally:
                done += 1

        tasks = [asyncio.create_task(check(site)) for site in sites]
        deadline = asyncio.get_running_loop().time() + config.WMN_MAX_SECONDS
        pending: set[asyncio.Task] = set(tasks)
        while pending:
            remaining = deadline - asyncio.get_running_loop().time()
            if remaining <= 0:
                break
            _, pending = await asyncio.wait(pending, timeout=min(4.0, remaining))
            if progress is not None and pending:
                try:
                    await progress(done, len(sites))
                except Exception:  # noqa: BLE001 — فشل تحديث رسالة التقدم لا يوقف الفحص
                    pass
        for task in pending:
            task.cancel()
        if pending:
            await asyncio.gather(*pending, return_exceptions=True)

    hits.sort(key=lambda h: (h.category, h.name.lower()))
    return hits, done, len(sites)


def format_wmn(username: str, hits: list[WmnHit], checked: int, total: int) -> str:
    """تنسيق نتائج الفحص الشامل مجمّعة حسب التصنيف."""
    lines = [
        f"🧭 <b>نتائج الفحص الشامل لليوزر:</b> <code>{esc(username)}</code>",
        f"✅ تم العثور عليه في <b>{len(hits)}</b> موقع من أصل <b>{checked}</b> تم فحصها"
        + (f" (من {total})" if checked < total else ""),
    ]
    if not hits:
        lines += ["", "📭 لم يتم العثور على حسابات بهذا الاسم."]
    current = None
    for hit in hits:
        if hit.category != current:
            current = hit.category
            lines += ["", f"<b>{esc(WMN_CATEGORIES_AR.get(current, '📦 ' + current))}</b>"]
        lines.append(f'• <a href="{esc_attr(hit.url)}">{esc(hit.name)}</a>')
    lines += ["", "ℹ️ <i>المصدر: مشروع WhatsMyName — قد توجد نتائج خاطئة، تحقّق يدوياً من الحسابات المهمة.</i>"]
    return "\n".join(lines)


# ═══════════════════════════════════════════════════════════
# 7️⃣ ✉️ البريد الإلكتروني
# ═══════════════════════════════════════════════════════════

_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]{1,64}@[A-Za-z0-9.\-]{1,253}\.[A-Za-z]{2,63}$")

_FREE_PROVIDERS = {
    "gmail.com": "Gmail", "googlemail.com": "Gmail", "outlook.com": "Outlook", "outlook.sa": "Outlook",
    "hotmail.com": "Hotmail", "live.com": "Microsoft Live", "msn.com": "MSN", "yahoo.com": "Yahoo",
    "ymail.com": "Yahoo", "icloud.com": "iCloud", "me.com": "iCloud", "mac.com": "iCloud",
    "aol.com": "AOL", "proton.me": "Proton Mail", "protonmail.com": "Proton Mail", "pm.me": "Proton Mail",
    "gmx.com": "GMX", "gmx.net": "GMX", "mail.ru": "Mail.ru", "yandex.com": "Yandex", "yandex.ru": "Yandex",
    "zoho.com": "Zoho", "tutanota.com": "Tuta", "tuta.io": "Tuta", "qq.com": "QQ", "163.com": "NetEase",
}

_DISPOSABLE_DOMAINS = {
    "mailinator.com", "10minutemail.com", "guerrillamail.com", "guerrillamail.net", "sharklasers.com",
    "grr.la", "yopmail.com", "temp-mail.org", "tempmail.com", "tempmail.net", "throwawaymail.com",
    "trashmail.com", "getnada.com", "nada.email", "dispostable.com", "maildrop.cc", "mohmal.com",
    "fakeinbox.com", "mintemail.com", "emailondeck.com", "mailnesia.com", "tempr.email", "discard.email",
    "mail.tm", "1secmail.com", "moakt.com", "tmpmail.org", "minuteinbox.com", "inboxkitten.com",
    "mailcatch.com", "spambox.us", "tempail.com", "emailfake.com", "mail7.io",
}


async def _gravatar_exists(email_md5: str) -> bool | None:
    """هل توجد صورة Gravatar علنية مرتبطة بالبريد؟"""
    resp = await _fetch(f"https://www.gravatar.com/avatar/{email_md5}", params={"d": "404", "s": "80"})
    if resp is None:
        return None
    if resp.status_code == 200:
        return True
    if resp.status_code == 404:
        return False
    return None


async def gravatar_profile(email_md5: str) -> dict | None:
    """الملف العلني في Gravatar (الاسم، الموقع، الحسابات المرتبطة)."""
    data = await _get_json(f"https://en.gravatar.com/{email_md5}.json")
    entries = data.get("entry") if isinstance(data, dict) else None
    return entries[0] if isinstance(entries, list) and entries and isinstance(entries[0], dict) else None


async def email_breaches(email: str) -> list[str] | None:
    """أسماء التسريبات المعروفة التي ظهر فيها البريد (XposedOrNot — مجاني). None = تعذّر التحقق."""
    resp = await _fetch(f"https://api.xposedornot.com/v1/check-email/{quote(email, safe='@')}", timeout=15)
    if resp is None:
        return None
    if resp.status_code == 404:
        return []
    if resp.status_code != 200:
        return None
    try:
        data = resp.json()
    except ValueError:
        return None
    breaches = data.get("breaches") if isinstance(data, dict) else None
    if not breaches:
        return []
    flat = breaches[0] if isinstance(breaches[0], list) else breaches
    return [str(b) for b in flat if b]


async def email_lookup(query: str) -> LookupResult:
    """تقرير البريد: المزود، MX، SPF/DMARC، التسريبات، Gravatar — كله داخل تيليجرام."""
    email = clean_query(query).lower()
    if not _EMAIL_RE.match(email):
        raise InvalidInput("❌ البريد الإلكتروني غير صالح. أرسل بريداً مثل <code>name@example.com</code>")
    local, domain_part = email.rsplit("@", 1)
    domain = normalize_domain(domain_part)
    email = f"{local}@{domain}"
    email_md5 = hashlib.md5(email.encode(), usedforsecurity=False).hexdigest()

    mx, txt, dmarc, gravatar, profile, breaches = await asyncio.gather(
        _safe(dns_query(domain, "MX"), []),
        _safe(dns_query(domain, "TXT"), []),
        _safe(dns_query(f"_dmarc.{domain}", "TXT"), []),
        _safe(_gravatar_exists(email_md5), None),
        _safe(gravatar_profile(email_md5), None),
        _safe(email_breaches(email), None),
    )

    if domain in _DISPOSABLE_DOMAINS:
        provider = "🗑️ بريد مؤقت (Disposable) — يُستخدم عادةً للتسجيل المؤقت"
    elif domain in _FREE_PROVIDERS:
        provider = f"🆓 مزود بريد مجاني ({_FREE_PROVIDERS[domain]})"
    else:
        provider = "🏢 نطاق خاص (شركة / مؤسسة / شخصي)"

    spf = next((r for r in txt if r.lower().startswith("v=spf1")), None)
    dmarc_rec = next((r for r in dmarc if r.lower().startswith("v=dmarc1")), None)
    dmarc_policy = None
    if dmarc_rec:
        m = re.search(r"\bp=([a-z]+)", dmarc_rec, re.IGNORECASE)
        dmarc_policy = m.group(1).lower() if m else None

    mx_hosts = [r.split()[-1] for r in mx]
    if mx_hosts:
        shown = ", ".join(f"<code>{esc(h)}</code>" for h in mx_hosts[:3])
        more = f" <i>(+{len(mx_hosts) - 3})</i>" if len(mx_hosts) > 3 else ""
        mx_line = f"• سجلات MX: ✅ {shown}{more}"
    else:
        mx_line = "• سجلات MX: ❌ لا توجد — غالباً هذا النطاق لا يستقبل البريد"

    gravatar_text = {True: "✅ توجد صورة علنية مرتبطة بهذا البريد", False: "❌ لا توجد", None: "❔ تعذّر التحقق"}

    lines: list[str | None] = [
        f"✉️ <b>تقرير البريد الإلكتروني:</b> <code>{esc(email)}</code>",
        "",
        _kv("اسم المستخدم", local),
        _kv("النطاق", domain),
        f"• نوع المزود: {provider}",
        mx_line,
        f"• حماية SPF: {'✅ مفعّلة' if spf else '❌ غير موجودة'}",
        f"• حماية DMARC: {'✅ مفعّلة' if dmarc_rec else '❌ غير موجودة'}"
        + (f" (السياسة: <code>{esc(dmarc_policy)}</code>)" if dmarc_policy else ""),
        f"• Gravatar: {gravatar_text[gravatar]}",
    ]

    # 🔐 التسريبات
    lines += ["", "<b>🔐 التسريبات المعروفة (XposedOrNot):</b>"]
    if breaches is None:
        lines.append("❔ تعذّر التحقق حالياً — حاول لاحقاً.")
    elif not breaches:
        lines.append("✅ لم يظهر هذا البريد في أي تسريب معروف.")
    else:
        shown_breaches = "، ".join(esc(b) for b in breaches[:25])
        more = f" <i>(+{len(breaches) - 25})</i>" if len(breaches) > 25 else ""
        lines += [f"⚠️ ظهر في <b>{len(breaches)}</b> تسريباً:", f"{shown_breaches}{more}"]

    # 👤 ملف Gravatar العلني
    if profile:
        accounts = [
            f'<a href="{esc_attr(acc["url"])}">{esc(acc.get("shortname") or acc.get("domain") or "حساب")}</a>'
            for acc in profile.get("accounts") or []
            if isinstance(acc, dict) and acc.get("url")
        ][:8]
        lines += [
            "",
            "<b>👤 ملف Gravatar العلني:</b>",
            _kv("الاسم", profile.get("displayName") or profile.get("preferredUsername"), code=False),
            _kv("الموقع", profile.get("currentLocation"), code=False),
            _kv("النبذة", _short(str(profile["aboutMe"]), 150) if profile.get("aboutMe") else None, code=False),
            f"• الحسابات المرتبطة: {'، '.join(accounts)}" if accounts else None,
        ]

    lines += ["", _INSIDE_HINT]

    actions: list[Action] = []
    if gravatar:
        actions.append(
            Action("🖼️ عرض صورة Gravatar", "photo", f"https://www.gravatar.com/avatar/{email_md5}?s=600",
                   (f"🖼️ صورة Gravatar المرتبطة بـ {email}",), wide=True)
        )
    actions += [
        search_action("🔎 بحث عن البريد", f'"{email}"'),
        search_action("📋 Pastebin", f'"{email}" site:pastebin.com'),
        search_action("💻 GitHub", f'"{email}" site:github.com'),
    ]
    if domain not in _FREE_PROVIDERS and domain not in _DISPOSABLE_DOMAINS:
        actions += [
            search_action("🏢 عناوين أخرى على النطاق", f'"@{domain}"'),
            Action("🌐 فحص نطاق البريد", "lookup", domain, ("domain",)),
        ]
    return LookupResult(_join(lines), actions)


# ═══════════════════════════════════════════════════════════
# 🔓 فحص التسريبات (Data Breaches)
# ═══════════════════════════════════════════════════════════
# يعرض: في أي تسريبات ظهر الهدف، متى، وما نوع البيانات المسرّبة (بريد، هاتف، كلمة مرور...)
# ⚠️ لا يعرض كلمات المرور نفسها — فقط حقيقة تسريبها ونوعها، مع نصائح الحماية.
# المصادر المجانية: XposedOrNot (للبريد) و LeakCheck public (بريد/يوزر/هاتف/دومين).

# تصنيف حقول LeakCheck إلى مجموعات عربية بإيموجي
_LEAK_FIELD_GROUPS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("🔑 كلمات المرور", ("password", "hashed_password", "hash", "salt")),
    ("📧 البريد الإلكتروني", ("email", "emails")),
    ("👤 اسم المستخدم", ("username", "login", "nick")),
    ("📞 رقم الهاتف", ("phone", "mobile", "telephone")),
    ("🪪 الاسم", ("name", "first_name", "last_name", "middle_name", "fullname")),
    ("📍 العنوان", ("address", "city", "state", "zip", "country", "area", "region", "postal")),
    ("🎂 تاريخ الميلاد", ("dob", "birthday", "birthdate", "age")),
    ("🌐 عنوان IP", ("ip", "ip1", "ip2", "ip_address", "last_ip", "reg_ip")),
    ("⚧️ الجنس", ("gender", "sex")),
    ("🏢 الشركة / العمل", ("company", "job", "occupation")),
)


def _count(value: Any) -> str | None:
    """تنسيق عدد السجلات: 24922471 ← 24.9M."""
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    for divisor, suffix in ((1_000_000_000, "B"), (1_000_000, "M"), (1_000, "K")):
        if number >= divisor:
            return f"{number / divisor:.1f}".removesuffix(".0") + suffix
    return f"{number:,}"


def _leak_data_types(fields: list[str]) -> list[str]:
    """تحويل أسماء الحقول المسرّبة إلى مجموعات عربية مقروءة."""
    lowered = {str(f).lower() for f in fields}
    groups = []
    for label, keys in _LEAK_FIELD_GROUPS:
        if lowered & set(keys):
            groups.append(label)
    return groups


def _has_password_field(fields: list[str]) -> bool:
    return bool({str(f).lower() for f in fields} & {"password", "hashed_password", "hash"})


async def leakcheck_public(query: str) -> dict | None:
    """LeakCheck public API: عدد التسريبات، المصادر، وأنواع الحقول — بدون قيمة كلمة المرور نفسها."""
    data = await _get_json("https://leakcheck.io/api/public", params={"check": query}, timeout=20)
    if not isinstance(data, dict) or not data.get("success"):
        return None
    return {
        "found": int(data.get("found") or 0),
        "fields": [str(f) for f in data.get("fields") or []],
        "sources": [
            {"name": str(s.get("name") or "غير معروف"), "date": str(s.get("date") or "")}
            for s in data.get("sources") or []
            if isinstance(s, dict)
        ],
    }


async def xposed_email(email: str) -> dict | None:
    """XposedOrNot: تفاصيل تسريبات البريد (الاسم، التاريخ، نوع البيانات، خطورة كلمات المرور)."""
    data = await _get_json(
        f"https://api.xposedornot.com/v1/breach-analytics?email={quote(email, safe='@')}", timeout=20
    )
    if not isinstance(data, dict):
        return None
    details = (data.get("ExposedBreaches") or {}).get("breaches_details") or []
    metrics = data.get("BreachMetrics") or {}
    risk = (metrics.get("risk") or [{}])[0] if metrics.get("risk") else {}
    strength = (metrics.get("passwords_strength") or [{}])[0] if metrics.get("passwords_strength") else {}
    breaches = [
        {
            "name": b.get("breach"),
            "date": str(b.get("xposed_date") or ""),
            "records": b.get("xposed_records"),
            "data": [d.strip() for d in str(b.get("xposed_data") or "").split(";") if d.strip()],
            "domain": b.get("domain"),
            "pw_risk": b.get("password_risk"),
        }
        for b in details
        if isinstance(b, dict) and b.get("breach")
    ]
    return {
        "breaches": breaches,
        "risk_label": risk.get("risk_label"),
        "risk_score": risk.get("risk_score"),
        "plaintext": int(strength.get("PlainText") or 0),
        "easy": int(strength.get("EasyToCrack") or 0),
        "strong": int(strength.get("StrongHash") or 0),
    }


_RISK_ICON = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}


def _detect_leak_target(q: str) -> tuple[str, str]:
    """تحديد نوع الهدف: email / phone / domain / username — وتطبيعه."""
    q = q.strip()
    if _EMAIL_RE.match(q.lower()):
        return "email", q.lower()
    digits = re.sub(r"[\s\-()]", "", q.translate(_DIGITS_TABLE)).lstrip("+")
    if digits.isdigit() and 7 <= len(digits) <= 15 and not re.search(r"[A-Za-z]", q):
        return "phone", digits
    if "." in q and " " not in q and not q.lstrip("@").replace(".", "").replace("_", "").isalnum():
        try:
            return "domain", normalize_domain(q)
        except InvalidInput:
            pass
    if "." in q and " " not in q and re.search(r"\.[a-z]{2,}$", q.lower()):
        try:
            return "domain", normalize_domain(q)
        except InvalidInput:
            pass
    handle = q.lstrip("@").strip()
    if _USERNAME_RE.fullmatch(handle):
        return "username", handle
    raise InvalidInput(
        "❌ أرسل بريداً إلكترونياً، أو يوزر، أو رقم هاتف (بالصيغة الدولية)، أو دومين.\n"
        "مثال: <code>name@example.com</code> أو <code>john_doe</code> أو <code>+966501234567</code>"
    )


_LEAK_KINDS_AR = {"email": "📧 بريد إلكتروني", "phone": "📞 رقم هاتف", "domain": "🌐 دومين", "username": "👤 يوزر"}


async def leaks_lookup(query: str) -> LookupResult:
    """🔓 فحص التسريبات: في أي تسريبات ظهر الهدف وما نوع البيانات المكشوفة (دون عرض كلمات المرور)."""
    kind, target = _detect_leak_target(clean_query(query))

    xposed = await _safe(xposed_email(target), None, timeout=25) if kind == "email" else None
    leakcheck = await _safe(leakcheck_public(target), None, timeout=20)

    lines: list[str | None] = [
        "🔓 <b>فحص التسريبات</b>",
        "━━━━━━━━━━━━━━━━",
        f"🎯 الهدف: <code>{esc(target)}</code>",
        f"🧩 النوع: {_LEAK_KINDS_AR[kind]}",
    ]

    xp_breaches = xposed.get("breaches") if xposed else []
    lc_found = leakcheck.get("found", 0) if leakcheck else 0
    lc_sources = leakcheck.get("sources", []) if leakcheck else []
    lc_fields = leakcheck.get("fields", []) if leakcheck else []
    clean = not xp_breaches and not lc_found

    if xposed is None and leakcheck is None:
        lines += ["━━━━━━━━━━━━━━━━", "⚠️ تعذّر الوصول لقواعد التسريبات حالياً — حاول بعد قليل."]
        return LookupResult(_join(lines), _leak_actions(kind, target))

    if clean:
        lines += [
            "━━━━━━━━━━━━━━━━",
            "✅ <b>لم يظهر هذا الهدف في أي تسريب معروف.</b>",
            "💡 استمر في استخدام كلمة مرور قوية وفريدة والتحقق بخطوتين (2FA).",
        ]
        return LookupResult(_join(lines), _leak_actions(kind, target))

    # ملخص الخطورة
    if xposed and xposed.get("risk_label"):
        icon = _RISK_ICON.get(str(xposed["risk_label"]), "⚪")
        lines.append(f"⚠️ مستوى الخطورة: {icon} <b>{esc(xposed['risk_label'])}</b> ({xposed.get('risk_score', '?')}/100)")
    total_breaches = len(xp_breaches)
    summary = []
    if total_breaches:
        summary.append(f"🗂️ <b>{total_breaches}</b> تسريب معروف")
    if lc_found:
        summary.append(f"📊 <b>{lc_found}</b> سجل في قواعد الاختراقات")
    lines += ["━━━━━━━━━━━━━━━━", " • ".join(summary) if summary else "🔴 <b>ظهر الهدف في تسريبات.</b>"]

    # أنواع البيانات المكشوفة
    data_types = set(_leak_data_types(lc_fields))
    for breach in xp_breaches:
        data_types.update(_xp_data_to_groups(breach.get("data", [])))
    if data_types:
        ordered = [label for label, _ in _LEAK_FIELD_GROUPS if label in data_types]
        lines += ["", "<b>🧬 أنواع البيانات المكشوفة:</b>", "، ".join(ordered)]

    # كلمات المرور — حقيقة التسريب فقط، لا القيمة
    password_leaked = _has_password_field(lc_fields) or any(
        (b.get("pw_risk") or "unknown") != "unknown" for b in xp_breaches
    ) or (xposed and (xposed["plaintext"] or xposed["easy"] or xposed["strong"]))
    if password_leaked:
        pw_lines = ["", "<b>🔑 كلمات المرور:</b> ⚠️ ظهرت ضمن البيانات المسرّبة"]
        if xposed and (xposed["plaintext"] or xposed["easy"] or xposed["strong"]):
            pw_lines.append(
                f"   • نص صريح: {xposed['plaintext']} • سهلة الكسر: {xposed['easy']} • مشفّرة بقوة: {xposed['strong']}"
            )
        pw_lines.append("🔒 <i>البوت لا يعرض كلمة المرور نفسها — غيّرها فوراً في كل موقع استُخدمت فيه وفعّل التحقق بخطوتين.</i>")
        lines += pw_lines

    # تفاصيل التسريبات (XposedOrNot)
    if xp_breaches:
        lines += ["", "<b>🗂️ أبرز التسريبات:</b>"]
        for breach in xp_breaches[:12]:
            year = breach["date"][:4] if breach.get("date") else ""
            records = f" • {_count(breach['records'])} سجل" if breach.get("records") else ""
            lines.append(f"• <b>{esc(breach['name'])}</b>" + (f" ({year})" if year else "") + records)
        if len(xp_breaches) > 12:
            lines.append(f"• <i>(+{len(xp_breaches) - 12} تسريب آخر)</i>")

    # مصادر LeakCheck (أسماء فقط)
    if lc_sources:
        names = ", ".join(esc(s["name"]) for s in lc_sources[:10])
        more = f" <i>(+{len(lc_sources) - 10})</i>" if len(lc_sources) > 10 else ""
        lines += ["", f"<b>📂 مصادر إضافية:</b> {names}{more}"]

    lines += [
        "━━━━━━━━━━━━━━━━",
        "🛡️ <b>ماذا تفعل؟</b> غيّر كلمات المرور المتكررة، فعّل التحقق بخطوتين، واحذر رسائل التصيّد.",
        "ℹ️ <i>للاستخدام الدفاعي: افحص حساباتك أنت لحمايتها.</i>",
    ]
    return LookupResult(_join(lines), _leak_actions(kind, target))


_XP_DATA_MAP = (
    ("🔑 كلمات المرور", ("password",)),
    ("📧 البريد الإلكتروني", ("email",)),
    ("👤 اسم المستخدم", ("username",)),
    ("📞 رقم الهاتف", ("phone",)),
    ("🪪 الاسم", ("name",)),
    ("📍 العنوان", ("address", "geographic", "location")),
    ("🎂 تاريخ الميلاد", ("birth", "age")),
    ("🌐 عنوان IP", ("ip address",)),
    ("⚧️ الجنس", ("gender",)),
)


def _xp_data_to_groups(data: list[str]) -> set[str]:
    joined = " ".join(data).lower()
    return {label for label, keys in _XP_DATA_MAP if any(k in joined for k in keys)}


def _leak_actions(kind: str, target: str) -> list[Action]:
    """أزرار فحص يدوي إضافي تفتح في المتصفح."""
    actions: list[Action] = []
    if kind == "email":
        actions += [
            url_action("🔐 Have I Been Pwned", f"https://haveibeenpwned.com/account/{quote(target, safe='@')}"),
            url_action("🧬 XposedOrNot", f"https://xposedornot.com/email/{quote(target, safe='@')}"),
        ]
    elif kind == "domain":
        actions.append(url_action("🔐 HIBP — تسريبات النطاق", "https://haveibeenpwned.com/DomainSearch"))
    actions.append(url_action("🔎 LeakCheck", f"https://leakcheck.io/?check={quote(target, safe='@')}", wide=True))
    return actions


# ═══════════════════════════════════════════════════════════
# 📥 تحميل الملفات لإرسالها داخل تيليجرام
# ═══════════════════════════════════════════════════════════

_DOWNLOAD_EXTENSIONS = (
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".csv", ".txt", ".rtf", ".odt", ".ods", ".zip",
)


def downloadable_ext(url: str) -> str | None:
    """امتداد الملف إذا كان الرابط يشير لملف يمكن إرساله داخل تيليجرام."""
    path = urlsplit(url).path.lower()
    return next((ext for ext in _DOWNLOAD_EXTENSIONS if path.endswith(ext)), None)


def _safe_filename(url: str) -> str:
    name = unquote(PurePosixPath(urlsplit(url).path).name) or "document"
    name = re.sub(r"[^\w.\- ]", "_", name).strip(" .") or "document"
    return name[-120:]


async def _is_public_host(host: str) -> bool:
    """حماية من الوصول لعناوين داخلية: كل عناوين المضيف يجب أن تكون عامة."""
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, None)
    except OSError:
        return False
    return bool(infos) and all(ipaddress.ip_address(str(info[4][0]).split("%")[0]).is_global for info in infos)


async def download_file(url: str, max_mb: int | None = None) -> tuple[bytes, str]:
    """تحميل ملف من نتيجة بحث (بحد أقصى للحجم ومع منع العناوين الداخلية) لإرساله في المحادثة."""
    limit_mb = max_mb or config.MAX_DOWNLOAD_MB
    max_bytes = limit_mb * 1024 * 1024
    for _ in range(5):  # متابعة التحويلات يدوياً مع فحص كل عنوان
        parts = urlsplit(url)
        if parts.scheme not in ("http", "https") or not parts.hostname:
            raise InvalidInput("❌ رابط الملف غير مدعوم.")
        if not await _is_public_host(parts.hostname):
            raise InvalidInput("⛔ لا يمكن تحميل هذا الملف (عنوان غير عام).")
        async with get_client().stream("GET", url, follow_redirects=False, timeout=30) as resp:
            if resp.is_redirect and resp.headers.get("location"):
                url = urljoin(url, resp.headers["location"])
                continue
            if resp.status_code != 200:
                raise InvalidInput(f"❌ تعذّر تحميل الملف (رمز {resp.status_code}).")
            length = resp.headers.get("content-length", "")
            if length.isdigit() and int(length) > max_bytes:
                raise InvalidInput(f"❌ الملف أكبر من {limit_mb} ميغابايت.")
            chunks: list[bytes] = []
            size = 0
            async for chunk in resp.aiter_bytes():
                size += len(chunk)
                if size > max_bytes:
                    raise InvalidInput(f"❌ الملف أكبر من {limit_mb} ميغابايت.")
                chunks.append(chunk)
            return b"".join(chunks), _safe_filename(url)
    raise InvalidInput("❌ الرابط يحوّل لعناوين كثيرة جداً.")


# ═══════════════════════════════════════════════════════════
# 8️⃣ 🔎 Google Dorks — قائمة خيارات جاهزة والنتائج داخل تيليجرام
# ═══════════════════════════════════════════════════════════

_GOV_SITES = "(site:.gov OR site:gov.sa OR site:gov.ae OR site:gov.kw OR site:gov.qa OR site:gov.eg)"
_EDU_SITES = "(site:.edu OR site:edu.sa OR site:ac.ae OR site:ac.uk OR site:researchgate.net)"
_SOCIAL_SITES = "(site:x.com OR site:instagram.com OR site:tiktok.com OR site:facebook.com OR site:snapchat.com)"
_NEWS_SITES = "(site:aljazeera.net OR site:alarabiya.net OR site:skynewsarabia.com OR site:bbc.com OR site:cnn.com)"


def _one_year_ago() -> str:
    return (datetime.now(timezone.utc) - timedelta(days=365)).strftime("%Y-%m-%d")


async def _looks_like_live_domain(text: str) -> str | None:
    """هل الإدخال دومين حقيقي؟ (رابط، أو اسم نطاق له سجلات DNS) — لتمييزه عن كلمات مثل john.doe."""
    site = _extract_site(text)
    if site:
        return site
    if " " in text or "." not in text or is_ip(text):
        return None
    try:
        domain = normalize_domain(text)
    except InvalidInput:
        return None
    has_dns = await _safe(dns_query(domain, "NS"), []) or await _safe(dns_query(domain, "A"), [])
    return domain if has_dns else None


async def dorks_lookup(query: str) -> LookupResult:
    """قائمة Google Dorks جاهزة حسب نوع الهدف — أو تنفيذ Dork مخصص فوراً."""
    q = clean_query(query)

    # ✍️ Dork مخصص كتبه المستخدم بنفسه ← ننفّذه مباشرة
    if '"' in q or _OPERATOR_RE.search(q) or " OR " in q:
        run = search_action("🔎 نتائج الـ Dork", q, docs="filetype:" in q.lower() or "ext:" in q.lower())
        text = _join([
            "✍️ <b>Dork مخصص</b>",
            f"<code>{esc(q)}</code>",
            "",
            "⏳ النتائج في الرسالة التالية 👇",
        ])
        return LookupResult(text, [Action("🔁 إعادة البحث", run.kind, run.value, run.extra, wide=True)], autorun=run)

    year_ago = _one_year_ago()
    domain = await _looks_like_live_domain(q)
    if domain:
        kind_text = "🌐 دومين"
        options = [
            ("📄 كل الصفحات المفهرسة", f"site:{domain}", False),
            ("🌿 النطاقات الفرعية", f"site:*.{domain} -site:www.{domain}", False),
            ("📕 ملفات PDF", f"site:{domain} filetype:pdf", True),
            ("📗 Excel و CSV", f"site:{domain} (filetype:xls OR filetype:xlsx OR filetype:csv)", True),
            ("📘 Word و PowerPoint", f"site:{domain} (filetype:doc OR filetype:docx OR filetype:ppt OR filetype:pptx)", True),
            ("🔑 صفحات الدخول", f"site:{domain} (inurl:login OR inurl:signin OR intitle:login)", False),
            ("⚙️ لوحات التحكم", f"site:{domain} (inurl:admin OR inurl:dashboard OR intitle:dashboard)", False),
            ("📁 مجلدات مفتوحة", f'site:{domain} intitle:"index of"', False),
            ("📧 عناوين البريد", f'"@{domain}"', False),
            ("🗣️ إشارات خارجية", f'"{domain}" -site:{domain}', False),
            ("👥 في الشبكات الاجتماعية", f'"{domain}" (site:x.com OR site:linkedin.com OR site:facebook.com)', False),
            ("💻 في GitHub", f'"{domain}" site:github.com', False),
            ("📋 في Pastebin", f'"{domain}" site:pastebin.com', False),
            ("📅 الجديد خلال سنة", f"site:{domain} after:{year_ago}", False),
        ]
        target = domain
    else:
        kind_text = "🔤 اسم / كلمة بحث"
        term = phrase(q)
        options = [
            ("📕 PDF", f"{term} filetype:pdf", True),
            ("📘 Word", f"{term} (filetype:doc OR filetype:docx)", True),
            ("📗 Excel", f"{term} (filetype:xls OR filetype:xlsx)", True),
            ("📙 PowerPoint", f"{term} (filetype:ppt OR filetype:pptx)", True),
            ("🏛️ مواقع حكومية", f"{term} {_GOV_SITES}", False),
            ("🎓 مواقع أكاديمية", f"{term} {_EDU_SITES}", False),
            ("👥 الشبكات الاجتماعية", f"{term} {_SOCIAL_SITES}", False),
            ("💼 LinkedIn", f"site:linkedin.com/in {term}", False),
            ("▶️ YouTube", f"site:youtube.com {term}", False),
            ("📰 الأخبار", f"{term} {_NEWS_SITES}", False),
            ("🗣️ منتديات ونقاشات", f"{term} (site:reddit.com OR site:quora.com OR inurl:forum OR inurl:thread)", False),
            ("💻 GitHub", f"site:github.com {term}", False),
            ("📋 Pastebin", f"site:pastebin.com {term}", False),
            ("🗃️ Google Drive", f"{term} (site:docs.google.com OR site:drive.google.com)", False),
            ("📚 Scribd و SlideShare", f"{term} (site:scribd.com OR site:slideshare.net)", False),
            ("🔤 في عنوان الصفحة", f"intitle:{term}", False),
            ("🔗 في رابط الصفحة", f"inurl:{term}", False),
            ("📅 خلال آخر سنة", f"{term} after:{year_ago}", False),
        ]
        target = q

    actions = [search_action(label, dork, docs=docs) for label, dork, docs in options]
    actions.append(search_action("🔎 بحث عام", phrase(target), wide=True))

    text = _join([
        "🔎 <b>Google Dorks — بحث متقدم داخل تيليجرام</b>",
        "",
        f"🎯 الهدف: <code>{esc(target)}</code>",
        f"🧩 النوع: {kind_text}",
        "",
        f"👇 اختر من <b>{len(actions)}</b> خياراً جاهزاً — النتائج تظهر هنا مباشرة.",
        "💡 تقدر ترسل Dork جاهز بنفسك، مثل: <code>site:gov.sa \"ميزانية\" filetype:pdf</code>",
    ])
    return LookupResult(text, actions)


# ═══════════════════════════════════════════════════════════
# 🚦 الموزّع الرئيسي
# ═══════════════════════════════════════════════════════════

LOOKUPS: dict[str, Callable[[str], Awaitable[LookupResult]]] = {
    "dorks": dorks_lookup,
    "social": social_lookup,
    "domain": domain_lookup,
    "ip": ip_lookup,
    "phone": phone_lookup,
    "user": username_lookup,
    "docs": docs_lookup,
    "email": email_lookup,
    "leaks": leaks_lookup,
}


async def run_lookup(category: str, query: str) -> LookupResult:
    """تنفيذ البحث المناسب حسب القسم الذي اختاره المستخدم."""
    func = LOOKUPS.get(category)
    if func is None:
        raise InvalidInput("❌ قسم غير معروف — ارجع للقائمة الرئيسية واختر مجدداً.")
    return await func(query)
