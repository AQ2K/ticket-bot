"""
🧰 أدوات OSINT — مولّدات Google Dorks ودوال الاستعلام من المصادر العلنية
=======================================================================
كل الدوال هنا مستقلة تماماً عن تيليجرام: تستقبل نص المستخدم وتُرجع كائن
‎LookupResult‎ يحتوي على نص التقرير (بصيغة HTML) وقائمة روابط تتحول لاحقاً
إلى أزرار في ‎keyboards.py‎.

لا يتطلب أي مفتاح API مدفوع — المصادر المستخدمة مجانية وعلنية:
  • DNS-over-HTTPS من Cloudflare و Google  ← سجلات DNS
  • RDAP (rdap.org)                         ← بيانات تسجيل الدومين و IP (بديل WHOIS)
  • ip-api.com و ipwho.is                   ← الموقع الجغرافي لعناوين IP
  • Wayback Machine API                     ← لقطات الأرشيف
  • مكتبة phonenumbers (تعمل محلياً)        ← تحليل أرقام الهواتف
  • واجهات عامة لبعض المنصات                ← فحص وجود اسم المستخدم
"""

from __future__ import annotations

import asyncio
import hashlib
import ipaddress
import logging
import re
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html import escape
from typing import Any, TypeVar
from urllib.parse import quote, urlsplit

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
class Link:
    """زر رابط مباشر: النص الظاهر + الرابط + هل يأخذ عرض السطر كاملاً."""

    label: str
    url: str
    wide: bool = False


@dataclass
class LookupResult:
    """نتيجة البحث: نص التقرير (HTML) + أزرار الروابط."""

    text: str
    links: list[Link] = field(default_factory=list)


# ═══════════════════════════════════════════════════════════
# 🔧 دوال مساعدة عامة
# ═══════════════════════════════════════════════════════════

# تحويل الأرقام العربية/الفارسية إلى أرقام إنجليزية
_DIGITS_TABLE = str.maketrans("٠١٢٣٤٥٦٧٨٩۰۱۲۳۴۵۶۷۸۹", "01234567890123456789")

# محارف التحكم وعلامات الاتجاه الخفية (تظهر كثيراً عند النسخ من واتساب)
_INVISIBLE_RE = re.compile(r"[\x00-\x1f\x7f​-‏‪-‮⁦-⁩﻿]")


def esc(value: Any) -> str:
    """تهريب النص لاستخدامه داخل رسائل HTML في تيليجرام."""
    return escape(str(value), quote=False)


def esc_attr(value: Any) -> str:
    """تهريب النص لاستخدامه داخل خاصية HTML مثل href."""
    return escape(str(value), quote=True)


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
    """بناء رابط بحث Google مع ترميز الاستعلام بالكامل."""
    return f"https://www.google.com/search?q={quote(dork, safe='')}"


def scholar(query: str) -> str:
    """بناء رابط بحث Google Scholar."""
    return f"https://scholar.google.com/scholar?q={quote(query, safe='')}"


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
    """حساب عمر النطاق من تاريخ التسجيل."""
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


async def _fetch(url: str, *, params: dict | None = None, headers: dict | None = None) -> httpx.Response | None:
    """طلب GET آمن — يُرجع None عند أي خطأ في الشبكة."""
    try:
        return await get_client().get(url, params=params, headers=headers)
    except httpx.HTTPError as exc:
        logger.warning("🌐 فشل الطلب إلى %s: %s", urlsplit(url).netloc, exc.__class__.__name__)
        return None


async def _get_json(url: str, *, params: dict | None = None, headers: dict | None = None) -> Any | None:
    """طلب GET يُرجع JSON، أو None عند الفشل أو عند رمز حالة غير 200."""
    resp = await _fetch(url, params=params, headers=headers)
    if resp is None or resp.status_code != 200:
        return None
    try:
        return resp.json()
    except ValueError:
        return None


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


async def wayback_snapshot(target: str) -> dict | None:
    """أحدث لقطة محفوظة في أرشيف Wayback Machine لرابط أو دومين."""
    data = await _get_json("https://archive.org/wayback/available", params={"url": target})
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


async def social_lookup(query: str) -> LookupResult:
    """توليد Google Dorks وروابط مباشرة للبحث عن اسم أو يوزر في X و Instagram و TikTok."""
    q = clean_query(query)
    match = _SOCIAL_HANDLE_RE.fullmatch(q)
    handle = match.group(1) if match else None
    term = phrase(handle or q)

    dorks = [
        ("𝕏 بحث في X", f"site:x.com {term}"),
        ("🐦 أرشيف Twitter", f"site:twitter.com {term}"),
        ("📸 Instagram", f"site:instagram.com {term}"),
        ("🎵 TikTok", f"site:tiktok.com {term}"),
    ]
    combined = f"{term} (site:x.com OR site:instagram.com OR site:tiktok.com)"

    links = [Link(label, google(dork)) for label, dork in dorks]
    links.append(Link("🌐 كل المنصات في بحث واحد", google(combined), wide=True))
    links.append(Link("⚡ بحث X المباشر", f"https://x.com/search?q={quote(handle or q, safe='')}&f=live"))
    links.append(Link("⚡ بحث TikTok المباشر", f"https://www.tiktok.com/search?q={quote(handle or q, safe='')}"))

    if handle:
        u = quote(handle, safe="")
        links += [
            Link("👤 حساب X", f"https://x.com/{u}"),
            Link("👤 حساب Instagram", f"https://www.instagram.com/{u}/"),
            Link("👤 حساب TikTok", f"https://www.tiktok.com/@{u}"),
            Link("💬 منشورات الحساب على X", f"https://x.com/search?q={quote(f'from:{handle}', safe='')}&f=live"),
            Link("🗣️ إشارات للحساب خارج X", google(f'"@{handle}" -site:x.com -site:twitter.com')),
            Link("🕰️ أرشيف الحساب (Wayback)", f"https://web.archive.org/web/*/x.com/{u}*"),
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
        "👇 اضغط على أي زر لفتح النتائج مباشرة في المتصفح.",
        "💡 <i>نصيحة: جرّب الاسم بالعربية والإنجليزية للحصول على نتائج أشمل.</i>",
    ]
    return LookupResult(_join(lines), links)


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
    """البحث عن الوثائق والملفات المنشورة علناً (PDF / Word / Excel / ...)."""
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
        links = [Link(label, google(dork)) for label, dork in dorks]
        links += [
            Link("🎓 Scholar", scholar(base)),
            Link("📂 كل أنواع الملفات", google(f"{base} {all_types}"), wide=True),
            Link("🕰️ أرشيف Wayback", f"https://web.archive.org/web/*/{site}/*"),
            Link("🔬 urlscan.io", f"https://urlscan.io/search/#domain:{site}"),
            Link("🧪 VirusTotal", f"https://www.virustotal.com/gui/domain/{site}"),
            Link("🔍 صفحات مفهرسة", google(base)),
        ]
        # أحدث لقطة للرابط نفسه، وإن لم توجد فللموقع كاملاً
        snapshot = await _safe(wayback_snapshot(q), None, timeout=config.HTTP_TIMEOUT)
        if snapshot is None:
            snapshot = await _safe(wayback_snapshot(site), None, timeout=config.HTTP_TIMEOUT)
        mode_lines = [
            f"🔗 تم التعرف على رابط — سيتم حصر البحث داخل: <code>{esc(site)}</code>",
            (
                f'🕰️ آخر لقطة في الأرشيف: <a href="{esc_attr(snapshot["url"])}">{esc(snapshot["date"])}</a>'
                if snapshot
                else "🕰️ آخر لقطة في الأرشيف: <i>لا توجد لقطات محفوظة</i>"
            ),
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
            ("📚 Scribd", f"site:scribd.com {base}"),
            ("🖥️ SlideShare", f"site:slideshare.net {base}"),
            ("🗃️ Google Docs/Drive", f"{base} (site:docs.google.com OR site:drive.google.com)"),
        ]
        links = [Link(label, google(dork)) for label, dork in dorks]
        links.insert(5, Link("🎓 Scholar", scholar(q)))
        links.append(Link("📂 كل أنواع الملفات", google(f"{base} {all_types}"), wide=True))
        mode_lines = [f"🔤 كلمة البحث: <code>{esc(q)}</code>"]

    lines = [
        "🔗 <b>وثائق وملفات — بحث Google Dorks</b>",
        "",
        *mode_lines,
        "",
        "<b>🔎 أمثلة على الاستعلامات المُولّدة:</b>",
        *[f"• <code>{esc(dork)}</code>" for _, dork in dorks[:4]],
        "",
        "👇 اختر نوع الملف لفتح نتائج البحث مباشرة في المتصفح.",
    ]
    return LookupResult(_join(lines), links)


# ═══════════════════════════════════════════════════════════
# 3️⃣ 🌐 الدومين
# ═══════════════════════════════════════════════════════════


async def domain_lookup(query: str) -> LookupResult:
    """تقرير الدومين: سجلات DNS + بيانات التسجيل RDAP + الاستضافة + روابط أدوات الفحص."""
    q = clean_query(query)
    if is_ip(q):
        raise InvalidInput("ℹ️ هذا عنوان IP وليس دومين — استخدم قسم «🌐 IP» من القائمة الرئيسية.")
    domain = normalize_domain(q)

    a, aaaa, mx, ns, txt, rdap = await asyncio.gather(
        _safe(dns_query(domain, "A"), []),
        _safe(dns_query(domain, "AAAA"), []),
        _safe(dns_query(domain, "MX"), []),
        _safe(dns_query(domain, "NS"), []),
        _safe(dns_query(domain, "TXT"), []),
        _safe(_rdap_domain(domain), None, timeout=15),
    )
    hosting = await _safe(ip_geolocation(a[0]), None) if a else None

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
    if hosting:
        host_name = hosting.get("org") or hosting.get("isp") or "غير معروف"
        asn = f" ({esc(hosting['asn'])})" if hosting.get("asn") else ""
        lines += [
            "",
            f"<b>🖥️ الاستضافة:</b> {flag(hosting.get('country_code'))} "
            f"{esc(hosting.get('country') or '')} — {esc(host_name)}{asn}",
        ]

    links = [
        Link("📜 الشهادات crt.sh", f"https://crt.sh/?q={quote('%.' + domain, safe='')}"),
        Link("🕰️ Wayback Machine", f"https://web.archive.org/web/*/{domain}/*"),
        Link("🧪 VirusTotal", f"https://www.virustotal.com/gui/domain/{domain}"),
        Link("🗂️ SecurityTrails", f"https://securitytrails.com/domain/{domain}/dns"),
        Link("🔬 urlscan.io", f"https://urlscan.io/search/#domain:{domain}"),
        Link("🛰️ Shodan", f"https://www.shodan.io/search?query={quote('hostname:' + domain, safe='')}"),
        Link("📇 WHOIS", f"https://who.is/whois/{domain}"),
        Link("🧱 BuiltWith", f"https://builtwith.com/{domain}"),
        Link("🌿 النطاقات الفرعية", google(f"site:*.{domain} -site:www.{domain}")),
        Link("📂 الملفات المنشورة", google(f"site:{domain} (filetype:pdf OR filetype:docx OR filetype:xlsx)")),
        Link("🔑 صفحات الدخول", google(f"site:{domain} (inurl:login OR inurl:signin OR intitle:login)")),
        Link("🗣️ إشارات خارجية", google(f'"{domain}" -site:{domain}')),
        Link("💻 إشارات في GitHub", google(f'"{domain}" site:github.com')),
        Link("📋 إشارات في Pastebin", google(f'"{domain}" site:pastebin.com')),
    ]
    return LookupResult(_join(lines), links)


# ═══════════════════════════════════════════════════════════
# 4️⃣ 🌐 عنوان IP
# ═══════════════════════════════════════════════════════════


async def ip_lookup(query: str) -> LookupResult:
    """تقرير IP: الموقع الجغرافي، مزود الخدمة، ASN، Reverse DNS، النطاق الشبكي + روابط الفحص."""
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
    geo, rdap, ptr = await asyncio.gather(
        _safe(ip_geolocation(ip_str), None),
        _safe(rdap_lookup("ip", ip_str), None),
        _safe(dns_query(ip.reverse_pointer, "PTR"), []),
    )

    lines: list[str | None] = [f"🌐 <b>تقرير IP:</b> <code>{ip_str}</code> (IPv{ip.version})"]
    if note:
        lines.append(note)
    lines.append("")

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

    if rdap:
        start, end = rdap.get("startAddress"), rdap.get("endAddress")
        net_range = f"{start} - {end}" if start and end else None
        net_name = rdap.get("name") or rdap.get("handle")
        lines += [
            "",
            "<b>📶 بيانات الشبكة (RDAP):</b>",
            _kv("اسم الشبكة", net_name),
            _kv("النطاق", net_range),
            _kv("الجهة المسجِّلة", _rdap_entity_name(rdap, "registrant"), code=False),
        ]

    lines += ["", "ℹ️ <i>الموقع الجغرافي تقريبي ويعكس موقع مزود الخدمة وليس موقع الشخص.</i>"]

    links = []
    if geo and geo.get("lat") is not None:
        links.append(Link("🗺️ عرض على الخريطة", f"https://www.google.com/maps?q={geo['lat']},{geo['lon']}", wide=True))
    links += [
        Link("🛰️ Shodan", f"https://www.shodan.io/host/{ip_str}"),
        Link("🔭 Censys", f"https://search.censys.io/hosts/{ip_str}"),
        Link("🚨 AbuseIPDB", f"https://www.abuseipdb.com/check/{ip_str}"),
        Link("🧪 VirusTotal", f"https://www.virustotal.com/gui/ip-address/{ip_str}"),
        Link("📡 GreyNoise", f"https://viz.greynoise.io/ip/{ip_str}"),
        Link("ℹ️ ipinfo.io", f"https://ipinfo.io/{ip_str}"),
        Link("🌐 BGP (Hurricane Electric)", f"https://bgp.he.net/ip/{ip_str}"),
        Link("🛡️ Cisco Talos", f"https://talosintelligence.com/reputation_center/lookup?search={ip_str}"),
        Link("🔎 إشارات في Google", google(f'"{ip_str}"'), wide=True),
    ]
    return LookupResult(_join(lines), links)


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
    """تحليل الرقم محلياً (بدون إنترنت) وبناء التقرير والروابط."""
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
    ]

    links = [
        Link("💬 واتساب", f"https://wa.me/{digits}"),
        Link("✈️ تيليجرام", f"https://t.me/+{digits}"),
        Link("🔎 Google (كل الصيغ)", google(f'"{e164}" OR "{intl}" OR "{national}"'), wide=True),
    ]
    if region:
        links.append(
            Link("📇 Truecaller", f"https://www.truecaller.com/search/{region.lower()}/{number.national_number}")
        )
    links += [
        Link("📇 Sync.me", f"https://sync.me/search/?number={digits}"),
        Link(
            "👥 إشارات في الشبكات الاجتماعية",
            google(
                f'("{e164}" OR "{national}") '
                "(site:facebook.com OR site:x.com OR site:instagram.com OR site:linkedin.com)"
            ),
            wide=True,
        ),
    ]
    return LookupResult(_join(lines), links)


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

# روابط مباشرة لمنصات لا يمكن فحصها بدون تسجيل دخول (يفتحها المستخدم بنفسه)
_PROFILE_LINKS: tuple[tuple[str, str], ...] = (
    ("𝕏 X", "https://x.com/{u}"),
    ("📸 Instagram", "https://www.instagram.com/{u}/"),
    ("🎵 TikTok", "https://www.tiktok.com/@{u}"),
    ("📘 Facebook", "https://www.facebook.com/{u}"),
    ("▶️ YouTube", "https://www.youtube.com/@{u}"),
    ("👻 Snapchat", "https://www.snapchat.com/add/{u}"),
    ("🧵 Threads", "https://www.threads.net/@{u}"),
    ("👽 Reddit", "https://www.reddit.com/user/{u}"),
    ("🎮 Twitch", "https://www.twitch.tv/{u}"),
    ("📌 Pinterest", "https://www.pinterest.com/{u}/"),
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
    """فحص وجود اسم المستخدم على عدة منصات + ملف GitHub العلني + روابط مباشرة."""
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

    lines += ["", "👇 روابط مباشرة لمنصات تتطلب فتحها يدوياً للتحقق:"]

    links = [Link(label, url.format(u=u)) for label, url in _PROFILE_LINKS]
    links += [
        Link("🧭 WhatsMyName (فحص +600 موقع)", f"https://whatsmyname.app/?q={u}", wide=True),
        Link("🔎 بحث Google عن اليوزر", google(f'"{username}"'), wide=True),
    ]
    return LookupResult(_join(lines), links)


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


async def email_lookup(query: str) -> LookupResult:
    """تقرير البريد: نوع المزود، سجلات MX، حماية SPF/DMARC، Gravatar + روابط فحص التسريبات."""
    email = clean_query(query).lower()
    if not _EMAIL_RE.match(email):
        raise InvalidInput("❌ البريد الإلكتروني غير صالح. أرسل بريداً مثل <code>name@example.com</code>")
    local, domain_part = email.rsplit("@", 1)
    domain = normalize_domain(domain_part)
    email = f"{local}@{domain}"
    email_md5 = hashlib.md5(email.encode(), usedforsecurity=False).hexdigest()

    mx, txt, dmarc, gravatar = await asyncio.gather(
        _safe(dns_query(domain, "MX"), []),
        _safe(dns_query(domain, "TXT"), []),
        _safe(dns_query(f"_dmarc.{domain}", "TXT"), []),
        _safe(_gravatar_exists(email_md5), None),
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
        "",
        "💡 <i>استخدم الأزرار بالأسفل للتحقق من ظهور البريد في التسريبات العلنية أو على الإنترنت.</i>",
    ]

    e = quote(email, safe="@")
    links = [
        Link("🔐 Have I Been Pwned", f"https://haveibeenpwned.com/account/{e}"),
        Link("🧬 Epieos", f"https://epieos.com/?q={e}&t=email"),
        Link("🔎 Google", google(f'"{email}"')),
        Link("📋 Pastebin", google(f'"{email}" site:pastebin.com')),
        Link("💻 GitHub", google(f'"{email}" site:github.com')),
        Link("📮 MXToolbox", f"https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{domain}&run=toolpage"),
    ]
    if gravatar:
        links.append(Link("🖼️ صورة Gravatar", f"https://www.gravatar.com/avatar/{email_md5}?s=400"))
    if domain not in _FREE_PROVIDERS and domain not in _DISPOSABLE_DOMAINS:
        links.append(Link("🏢 عناوين أخرى على نفس النطاق", google(f'"@{domain}"'), wide=True))
    return LookupResult(_join(lines), links)


# ═══════════════════════════════════════════════════════════
# 🚦 الموزّع الرئيسي
# ═══════════════════════════════════════════════════════════

LOOKUPS: dict[str, Callable[[str], Awaitable[LookupResult]]] = {
    "social": social_lookup,
    "domain": domain_lookup,
    "ip": ip_lookup,
    "phone": phone_lookup,
    "user": username_lookup,
    "docs": docs_lookup,
    "email": email_lookup,
}


async def run_lookup(category: str, query: str) -> LookupResult:
    """تنفيذ البحث المناسب حسب القسم الذي اختاره المستخدم."""
    func = LOOKUPS.get(category)
    if func is None:
        raise InvalidInput("❌ قسم غير معروف — ارجع للقائمة الرئيسية واختر مجدداً.")
    return await func(query)
