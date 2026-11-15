"""
📥 تحميل المقاطع واستخراج معلومات الحسابات — TikTok / Instagram / X (تويتر)
==========================================================================
كل النتائج تُرسل داخل تيليجرام: المقطع نفسه، الصور، ومعلومات الحساب.

المصادر (مجانية بدون مفاتيح):
  • yt-dlp                     ← تحميل مقاطع TikTok و Instagram + قائمة آخر فيديوهات TikTok
  • FxTwitter / vxTwitter      ← مقاطع وصور X، ومعلومات حسابات X
  • صفحة الحساب في TikTok      ← معلومات حسابات TikTok
  • واجهة Instagram العامة     ← معلومات حسابات Instagram (وإن حُجبت: من نتائج Google عبر مفتاح Serper)
  • vxinstagram                ← صور منشورات Instagram
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import shutil
import tempfile
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from osint_tools import (
    LOOKUPS,
    Action,
    InvalidInput,
    LookupResult,
    _fetch,
    _get_json,
    _join,
    _kv,
    _safe,
    _short,
    clean_query,
    esc,
    esc_attr,
    get_client,
    web_search,
)

logger = logging.getLogger(__name__)

_BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0 Safari/537.36"
)
_BROWSER_HEADERS = {"User-Agent": _BROWSER_UA, "Accept-Language": "en-US,en;q=0.9"}

# حد رفع الملفات للبوتات في تيليجرام 50 ميغابايت — نترك هامشاً بسيطاً
MAX_UPLOAD_BYTES = 49 * 1024 * 1024


# ═══════════════════════════════════════════════════════════
# 🔧 أدوات مساعدة
# ═══════════════════════════════════════════════════════════


def fmt_num(value: Any) -> str | None:
    """تنسيق الأرقام الكبيرة: 162900000 ← 162,900,000 (162.9M)."""
    try:
        number = int(value)
    except (TypeError, ValueError):
        return None
    if number < 0:
        return None
    for divisor, suffix in ((1_000_000_000, "B"), (1_000_000, "M"), (1_000, "K")):
        if number >= divisor:
            compact = f"{number / divisor:.1f}".removesuffix(".0")
            return f"{number:,} ({compact}{suffix})"
    return f"{number:,}"


def _date_from_ts(value: Any) -> str | None:
    try:
        return datetime.fromtimestamp(int(value), tz=timezone.utc).strftime("%Y-%m-%d")
    except (TypeError, ValueError, OSError):
        return None


def _date_from_twitter(value: Any) -> str | None:
    try:
        return datetime.strptime(str(value), "%a %b %d %H:%M:%S %z %Y").strftime("%Y-%m-%d")
    except ValueError:
        return None


def _date_from_ymd(value: Any) -> str | None:
    text = str(value or "")
    return f"{text[:4]}-{text[4:6]}-{text[6:8]}" if len(text) == 8 and text.isdigit() else None


# ═══════════════════════════════════════════════════════════
# 🔗 التعرف على الروابط
# ═══════════════════════════════════════════════════════════

_MEDIA_URL_RES = {
    "tiktok": re.compile(r"https?://(?:www\.|m\.|vm\.|vt\.)?tiktok\.com/[^\s<>\"']+", re.IGNORECASE),
    "instagram": re.compile(r"https?://(?:www\.)?(?:instagram\.com|instagr\.am)/[^\s<>\"']+", re.IGNORECASE),
    "x": re.compile(
        r"https?://(?:www\.|mobile\.)?(?:x\.com|twitter\.com|fxtwitter\.com|vxtwitter\.com|fixupx\.com)/[^\s<>\"']+",
        re.IGNORECASE,
    ),
}

PLATFORM_NAMES = {"tiktok": "🎵 TikTok", "instagram": "📸 Instagram", "x": "𝕏 X (تويتر)"}


def find_media_url(text: str) -> tuple[str, str] | None:
    """البحث عن رابط مقطع مدعوم داخل النص ← (المنصة، الرابط)."""
    for platform, pattern in _MEDIA_URL_RES.items():
        match = pattern.search(text or "")
        if match:
            return platform, match.group(0).rstrip(").,،")
    return None


def is_media_post_url(text: str) -> bool:
    """هل النص يحتوي رابط منشور/مقطع (وليس رابط حساب فقط)؟"""
    found = find_media_url(text)
    if not found:
        return False
    platform, url = found
    if platform == "x":
        return "/status" in url
    if platform == "instagram":
        return bool(re.search(r"/(?:p|reel|reels|tv)/", url))
    return "/video/" in url or "/photo/" in url or bool(re.search(r"//(?:vm|vt)\.tiktok\.com/", url)) or "/t/" in url


# ═══════════════════════════════════════════════════════════
# 📥 تحميل المقاطع
# ═══════════════════════════════════════════════════════════


@dataclass
class MediaItem:
    kind: str  # video | photo
    url: str | None = None  # رابط مباشر (تيليجرام يحمّله بنفسه)
    path: str | None = None  # ملف محلي بعد التحميل
    duration: int | None = None
    width: int | None = None
    height: int | None = None


@dataclass
class MediaResult:
    caption: str
    items: list[MediaItem] = field(default_factory=list)
    tmpdir: str | None = None

    def cleanup(self) -> None:
        if self.tmpdir:
            shutil.rmtree(self.tmpdir, ignore_errors=True)


def media_lookup_text(platform: str, url: str) -> str:
    return _join([
        f"📥 <b>تحميل من {PLATFORM_NAMES[platform]}</b>",
        f"🔗 <code>{esc(_short(url, 150))}</code>",
        "",
        "⏳ جاري التحميل — سيصلك المقطع هنا في الرسالة التالية.",
        "⚠️ <i>حمّل المحتوى العام فقط واحترم حقوق أصحابه.</i>",
    ])


async def media_lookup(query: str) -> LookupResult:
    """قسم «تحميل مقاطع»: التحقق من الرابط ثم التحميل تلقائياً."""
    text = (query or "").strip()[:2000]  # روابط المقاطع قد تكون أطول من حد نص البحث العادي
    found = find_media_url(text)
    if not found:
        raise InvalidInput(
            "❌ أرسل رابط مقطع أو منشور من <b>TikTok</b> أو <b>Instagram</b> أو <b>X (تويتر)</b>، مثل:\n"
            "<code>https://www.tiktok.com/@user/video/123...</code>"
        )
    platform, url = found
    action = Action("🔁 إعادة التحميل", "media", url, wide=True)
    return LookupResult(media_lookup_text(platform, url), [action], autorun=action)


async def download_media(url: str) -> MediaResult:
    """تحميل مقطع/صور من الرابط حسب المنصة."""
    found = find_media_url(url)
    if not found:
        raise InvalidInput("❌ الرابط غير مدعوم — أرسل رابطاً من TikTok أو Instagram أو X.")
    platform, url = found
    if platform == "x":
        return await _x_media(url)
    if platform == "tiktok":
        return await _ytdlp_media(url, "tiktok")
    try:
        return await _ytdlp_media(url, "instagram")
    except InvalidInput as exc:
        photos = await _instagram_photos(url)
        if photos:
            return photos
        raise exc


# ── X (تويتر) ───────────────────────────────────────────────


async def _fx_json(path: str) -> dict | None:
    """FxTwitter مع إعادة المحاولة (الخدمة تُرجع أحياناً 404 مؤقتاً)."""
    for attempt in range(3):
        data = await _get_json(f"https://api.fxtwitter.com/{path}", ok_statuses=(200, 404), timeout=15)
        if isinstance(data, dict) and data.get("code") == 200:
            return data
        await asyncio.sleep(0.7 * (attempt + 1))
    return None


async def _vx_json(path: str) -> dict | None:
    data = await _get_json(f"https://api.vxtwitter.com/{path}", timeout=15)
    return data if isinstance(data, dict) and "error" not in data else None


def _best_mp4(variants: list[dict], duration: float | None) -> str | None:
    """أفضل جودة mp4 يمكن رفعها لتيليجرام (أقل من 49 ميغابايت تقريباً)."""
    mp4s = sorted(
        (v for v in variants if "mp4" in str(v.get("content_type") or v.get("url", "")) and v.get("url")),
        key=lambda v: int(v.get("bitrate") or 0),
        reverse=True,
    )
    for variant in mp4s:
        bitrate = int(variant.get("bitrate") or 0)
        if not duration or not bitrate or bitrate * duration / 8 < MAX_UPLOAD_BYTES * 0.9:
            return str(variant["url"])
    return str(mp4s[-1]["url"]) if mp4s else None


async def _x_media(url: str) -> MediaResult:
    match = re.search(r"/status(?:es)?/(\d+)", url)
    if not match:
        raise InvalidInput("❌ هذا رابط حساب وليس تغريدة — لمعلومات الحساب استخدم /x اسم_الحساب")
    tweet_id = match.group(1)
    items: list[MediaItem] = []
    data = await _fx_json(f"status/{tweet_id}")
    if data:
        tweet = data.get("tweet") or {}
        author = tweet.get("author") or {}
        for media in (tweet.get("media") or {}).get("all") or []:
            if media.get("type") in ("video", "gif"):
                best = _best_mp4(media.get("variants") or media.get("formats") or [], media.get("duration")) or media.get("url")
                if best:
                    items.append(MediaItem("video", url=best, duration=int(media.get("duration") or 0) or None,
                                           width=media.get("width"), height=media.get("height")))
            elif media.get("type") == "photo" and media.get("url"):
                items.append(MediaItem("photo", url=str(media["url"])))
        caption = _x_caption(
            author.get("screen_name"), author.get("name"), tweet.get("text"), tweet.get("likes"),
            tweet.get("retweets"), tweet.get("replies"), tweet.get("views"),
            _date_from_ts(tweet.get("created_timestamp")), tweet.get("url") or url,
        )
    else:
        vx = await _vx_json(f"Twitter/status/{tweet_id}")
        if not vx:
            raise InvalidInput("⚠️ تعذّر جلب التغريدة — قد تكون محذوفة أو من حساب خاص، أو الخدمة مشغولة. حاول بعد قليل.")
        for media in vx.get("media_extended") or []:
            kind = "photo" if media.get("type") == "image" else "video"
            if media.get("url"):
                duration = int((media.get("duration_millis") or 0) / 1000) or None
                items.append(MediaItem(kind, url=str(media["url"]), duration=duration))
        caption = _x_caption(
            vx.get("user_screen_name"), vx.get("user_name"), vx.get("text"), vx.get("likes"), vx.get("retweets"),
            vx.get("replies"), None, _date_from_ts(vx.get("date_epoch")), vx.get("tweetURL") or url,
        )
    if not items:
        raise InvalidInput("📭 هذه التغريدة لا تحتوي على فيديو أو صور.")
    return MediaResult(caption, items[:10])


def _x_caption(screen_name, name, text, likes, retweets, replies, views, date, url) -> str:
    stats = " • ".join(
        part for part in (
            f"❤️ {fmt_num(likes)}" if fmt_num(likes) else None,
            f"🔁 {fmt_num(retweets)}" if fmt_num(retweets) else None,
            f"💬 {fmt_num(replies)}" if fmt_num(replies) else None,
            f"👁 {fmt_num(views)}" if fmt_num(views) else None,
        ) if part
    )
    return _join([
        f"𝕏 <b>{esc(name or '')}</b> (@{esc(screen_name or '?')})",
        esc(_short(str(text or ""), 500)) if text else None,
        stats or None,
        f"📅 {date}" if date else None,
        f'🔗 <a href="{esc_attr(url)}">رابط التغريدة</a>',
    ])


# ── TikTok و Instagram عبر yt-dlp ───────────────────────────


class _YtdlpLogger:
    """تحويل رسائل yt-dlp إلى سجلات البوت بهدوء (بدلاً من طباعتها مباشرة)."""

    def debug(self, msg: str) -> None:
        pass

    def info(self, msg: str) -> None:
        pass

    def warning(self, msg: str) -> None:
        logger.debug("yt-dlp: %s", msg)

    def error(self, msg: str) -> None:
        logger.debug("yt-dlp: %s", msg)


def _ytdlp_download(url: str, tmpdir: str) -> tuple[dict, str | None]:
    """تحميل أفضل جودة ضمن حد تيليجرام (تعمل في خيط منفصل)."""
    from yt_dlp import YoutubeDL

    size = "49M"
    options = {
        "quiet": True,
        "no_warnings": True,
        "noprogress": True,
        "logger": _YtdlpLogger(),
        "noplaylist": True,
        "playlist_items": "1",
        "outtmpl": f"{tmpdir}/%(id)s.%(ext)s",
        "restrictfilenames": True,
        "format": (
            f"best[ext=mp4][filesize<{size}]/best[ext=mp4][filesize_approx<{size}]/"
            f"best[filesize<{size}]/best[filesize_approx<{size}]/best[ext=mp4]/best"
        ),
        "max_filesize": MAX_UPLOAD_BYTES,
        "socket_timeout": 20,
        "retries": 2,
        "http_headers": _BROWSER_HEADERS,
    }
    with YoutubeDL(options) as ydl:
        info = ydl.extract_info(url, download=True) or {}
        if info.get("_type") == "playlist" and info.get("entries"):
            info = next((e for e in info["entries"] if e), info)
        downloads = info.get("requested_downloads") or []
        path = downloads[0].get("filepath") if downloads else None
        if not path:
            candidate = ydl.prepare_filename(info)
            path = candidate if Path(candidate).exists() else None
    return info, path


def _ytdlp_error_text(message: str) -> str:
    text = message.lower()
    if "no video" in text:
        return "📭 هذا المنشور لا يحتوي على فيديو."
    if "private" in text or "login" in text or "cookies" in text or "empty media" in text:
        return "🔒 المنصة رفضت الطلب — قد يكون الحساب خاصاً أو المحتوى يتطلب تسجيل الدخول."
    if "unsupported url" in text:
        return "❌ هذا الرابط غير مدعوم — أرسل رابط مقطع مباشر."
    if "not available" in text or "removed" in text or "404" in text:
        return "📭 المقطع غير متاح — قد يكون محذوفاً."
    return "⚠️ تعذّر تحميل المقطع حالياً — حاول مرة أخرى بعد قليل."


async def _ytdlp_media(url: str, platform: str) -> MediaResult:
    from yt_dlp.utils import DownloadError

    tmpdir = tempfile.mkdtemp(prefix="osint_dl_")
    try:
        info, path = await asyncio.to_thread(_ytdlp_download, url, tmpdir)
    except DownloadError as exc:
        shutil.rmtree(tmpdir, ignore_errors=True)
        logger.info("📥 yt-dlp: %s", str(exc)[:200])
        raise InvalidInput(_ytdlp_error_text(str(exc))) from None
    except Exception:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise
    if not path or not Path(path).exists():
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise InvalidInput("❌ المقطع أكبر من حد تيليجرام للبوتات (50 ميغابايت).")

    icon = "🎵 TikTok" if platform == "tiktok" else "📸 Instagram"
    uploader = info.get("uploader") or info.get("channel") or ""
    handle = str(info.get("uploader_id") or info.get("channel_id") or "")
    if handle.isdigit():  # TikTok يُرجع معرّفاً رقمياً — لا فائدة من عرضه
        handle = ""
    title = info.get("description") or info.get("title") or ""
    stats = " • ".join(
        part for part in (
            f"👁 {fmt_num(info.get('view_count'))}" if fmt_num(info.get("view_count")) else None,
            f"❤️ {fmt_num(info.get('like_count'))}" if fmt_num(info.get("like_count")) else None,
            f"💬 {fmt_num(info.get('comment_count'))}" if fmt_num(info.get("comment_count")) else None,
            f"🔁 {fmt_num(info.get('repost_count'))}" if fmt_num(info.get("repost_count")) else None,
        ) if part
    )
    date = _date_from_ymd(info.get("upload_date"))
    caption = _join([
        f"{icon} <b>{esc(uploader)}</b>" + (f" (@{esc(handle)})" if handle and handle != uploader else ""),
        esc(_short(str(title), 500)) if title else None,
        stats or None,
        " • ".join(p for p in (f"📅 {date}" if date else None,
                               f"⏱️ {int(info['duration'])} ث" if info.get("duration") else None) if p) or None,
        f'🔗 <a href="{esc_attr(info.get("webpage_url") or url)}">رابط المقطع</a>',
    ])
    item = MediaItem("video", path=path, duration=int(info.get("duration") or 0) or None,
                     width=info.get("width"), height=info.get("height"))
    return MediaResult(caption, [item], tmpdir)


async def _instagram_photos(url: str) -> MediaResult | None:
    """صور ومقاطع منشور Instagram عبر vxinstagram — احتياطي عند حجب Instagram للطلبات المجهولة."""
    match = re.search(r"/(?:p|reel|reels|tv)/([A-Za-z0-9_-]+)", url)
    if not match:
        return None
    shortcode = match.group(1)

    async def probe(index: int) -> str | None:
        """كل رقم يحوّل لملف على خوادم Instagram — نقرأ وجهة التحويل فقط بدون تحميل."""
        try:
            resp = await get_client().get(
                f"https://vxinstagram.com/offload/{shortcode}/{index}", follow_redirects=False, timeout=10
            )
        except Exception:  # noqa: BLE001 — أي خطأ يعني عدم توفر هذا العنصر
            return None
        return resp.headers.get("location") if resp.is_redirect else None

    locations = await asyncio.gather(*(probe(i) for i in range(10)))
    items: list[MediaItem] = []
    seen: set[str] = set()
    for location in locations:
        if not location:
            continue
        path = location.split("?", 1)[0]
        if path in seen:  # الأرقام الزائدة تعيد نفس الملف
            continue
        seen.add(path)
        items.append(MediaItem("video" if path.lower().endswith(".mp4") else "photo", url=location))
    if not items:
        return None
    kinds = {i.kind for i in items}
    label = "مقطع" if kinds == {"video"} else "صور" if kinds == {"photo"} else "وسائط"
    caption = _join([
        f"📸 <b>{label} منشور Instagram</b>",
        f'🔗 <a href="{esc_attr(url)}">رابط المنشور</a>',
    ])
    return MediaResult(caption, items)


# ═══════════════════════════════════════════════════════════
# 📊 معلومات الحسابات
# ═══════════════════════════════════════════════════════════

_ACCOUNT_RES = {
    "tiktok": re.compile(r"tiktok\.com/@([A-Za-z0-9._]{2,24})", re.IGNORECASE),
    "instagram": re.compile(r"instagram\.com/(?!p/|reel/|reels/|tv/|stories/|explore/)([A-Za-z0-9._]{1,30})", re.IGNORECASE),
    "x": re.compile(r"(?:x|twitter)\.com/(?!i/|home|search|status)([A-Za-z0-9_]{1,15})", re.IGNORECASE),
}
_USERNAME_PATTERNS = {
    "tiktok": r"[A-Za-z0-9._]{2,24}",
    "instagram": r"[A-Za-z0-9._]{1,30}",
    "x": r"[A-Za-z0-9_]{1,15}",
}


def parse_account(text: str) -> tuple[str | None, str]:
    """استخراج (المنصة، اليوزر) من رابط حساب أو يوزر عادي."""
    for platform, pattern in _ACCOUNT_RES.items():
        match = pattern.search(text)
        if match:
            return platform, match.group(1)
    username = text.strip().lstrip("@").strip()
    if not re.fullmatch(r"[A-Za-z0-9._]{1,30}", username):
        raise InvalidInput(
            "❌ أرسل يوزر صحيح (أحرف إنجليزية وأرقام فقط) أو رابط الحساب، مثل:\n"
            "<code>khaby.lame</code> أو <code>https://www.tiktok.com/@khaby.lame</code>"
        )
    return None, username


async def tiktok_profile(username: str) -> dict | None:
    """معلومات حساب TikTok من صفحة الحساب العامة. يُرجع {'missing': True} إذا لم يوجد."""
    resp = await _fetch(f"https://www.tiktok.com/@{username}", headers=_BROWSER_HEADERS, timeout=15)
    if resp is None or resp.status_code != 200:
        return None
    match = re.search(r'id="__UNIVERSAL_DATA_FOR_REHYDRATION__"[^>]*>(.*?)</script>', resp.text, re.DOTALL)
    if not match:
        return None
    try:
        detail = json.loads(match.group(1))["__DEFAULT_SCOPE__"]["webapp.user-detail"]
    except (ValueError, KeyError, TypeError):
        return None
    if detail.get("statusCode") not in (0, None):
        return {"missing": True}
    user = (detail.get("userInfo") or {}).get("user") or {}
    stats = (detail.get("userInfo") or {}).get("stats") or {}
    if not user.get("uniqueId"):
        return {"missing": True}
    likes = stats.get("heart") if int(stats.get("heart") or 0) > 0 else stats.get("heartCount")
    bio_link = (user.get("bioLink") or {}).get("link") if isinstance(user.get("bioLink"), dict) else None
    return {
        "platform": "tiktok",
        "username": user["uniqueId"],
        "name": user.get("nickname"),
        "bio": user.get("signature"),
        "followers": stats.get("followerCount"),
        "following": stats.get("followingCount"),
        "posts": stats.get("videoCount"),
        "likes": likes,
        "verified": user.get("verified"),
        "private": user.get("privateAccount"),
        "created": _date_from_ts(user.get("createTime")),
        "avatar": user.get("avatarLarger") or user.get("avatarMedium"),
        "website": bio_link,
        "url": f"https://www.tiktok.com/@{user['uniqueId']}",
    }


async def x_profile(username: str) -> dict | None:
    """معلومات حساب X عبر FxTwitter (مع vxTwitter كاحتياطي)."""
    data = await _fx_json(username)
    if data and isinstance(data.get("user"), dict):
        user = data["user"]
        verification = user.get("verification") or {}
        avatar = str(user.get("avatar_url") or "").replace("_normal.", "_400x400.") or None
        return {
            "platform": "x",
            "username": user.get("screen_name") or username,
            "name": user.get("name"),
            "bio": user.get("description"),
            "followers": user.get("followers"),
            "following": user.get("following"),
            "posts": user.get("tweets"),
            "likes": user.get("likes"),
            "media": user.get("media_count"),
            "verified": verification.get("verified") if isinstance(verification, dict) else None,
            "private": user.get("protected"),
            "created": _date_from_twitter(user.get("joined")),
            "location": user.get("location"),
            "website": (user.get("website") or {}).get("url") if isinstance(user.get("website"), dict) else user.get("website"),
            "avatar": avatar,
            "banner": user.get("banner_url"),
            "url": f"https://x.com/{user.get('screen_name') or username}",
        }
    vx = await _vx_json(username)
    if vx and vx.get("screen_name"):
        return {
            "platform": "x",
            "username": vx["screen_name"],
            "name": vx.get("name"),
            "bio": vx.get("description"),
            "followers": vx.get("followers_count"),
            "following": vx.get("following_count"),
            "posts": vx.get("tweet_count"),
            "private": vx.get("protected"),
            "created": _date_from_twitter(vx.get("created_at")),
            "location": vx.get("location"),
            "avatar": str(vx.get("profile_image_url") or "").replace("_normal.", "_400x400.") or None,
            "url": f"https://x.com/{vx['screen_name']}",
        }
    return None


_IG_STATS_RE = re.compile(
    r"([\d.,]+\s*[KMB]?)\s+Followers?,\s*([\d.,]+\s*[KMB]?)\s+Following,\s*([\d.,]+\s*[KMB]?)\s+Posts?",
    re.IGNORECASE,
)


async def instagram_profile(username: str) -> dict | None:
    """معلومات حساب Instagram: الواجهة العامة أولاً، ثم نتائج Google (مفتاح Serper) إن حُجبت."""
    data = await _get_json(
        "https://www.instagram.com/api/v1/users/web_profile_info/",
        params={"username": username},
        headers={**_BROWSER_HEADERS, "x-ig-app-id": "936619743392459"},
        timeout=15,
    )
    user = ((data or {}).get("data") or {}).get("user") if isinstance(data, dict) else None
    if isinstance(user, dict):
        return {
            "platform": "instagram",
            "username": user.get("username") or username,
            "name": user.get("full_name"),
            "bio": user.get("biography"),
            "followers": (user.get("edge_followed_by") or {}).get("count"),
            "following": (user.get("edge_follow") or {}).get("count"),
            "posts": (user.get("edge_owner_to_timeline_media") or {}).get("count"),
            "verified": user.get("is_verified"),
            "private": user.get("is_private"),
            "category": user.get("category_name"),
            "website": user.get("external_url"),
            "avatar": user.get("profile_pic_url_hd") or user.get("profile_pic_url"),
            "url": f"https://www.instagram.com/{user.get('username') or username}/",
        }

    # احتياطي: نتائج Google المفهرسة لصفحة الحساب
    outcome = await web_search(f'site:instagram.com "{username}"')
    for item in outcome.items:
        path = re.sub(r"^https?://(?:www\.)?instagram\.com", "", item["url"]).strip("/").lower()
        if path != username.lower():
            continue
        stats = _IG_STATS_RE.search(f"{item['snippet']} {item['title']}")
        name_match = re.match(r"(.+?)\s*\(@", item["title"])
        return {
            "platform": "instagram",
            "username": username,
            "name": name_match.group(1).strip() if name_match else None,
            "followers_text": stats.group(1) if stats else None,
            "following_text": stats.group(2) if stats else None,
            "posts_text": stats.group(3) if stats else None,
            "bio": item["snippet"] if not stats else None,
            "url": f"https://www.instagram.com/{username}/",
            "source": "google",
        }
    return {"blocked": True, "no_key": outcome.error == "no_key"}


_PROFILE_FETCHERS = {"tiktok": tiktok_profile, "instagram": instagram_profile, "x": x_profile}


def _profile_section(platform: str, username: str, profile: dict | None) -> list[str | None]:
    """قسم منصة واحدة في تقرير الحساب."""
    title = PLATFORM_NAMES[platform]
    if not re.fullmatch(_USERNAME_PATTERNS[platform], username):
        return [f"<b>{title}</b>: ➖ <i>صيغة اليوزر غير مدعومة على هذه المنصة</i>"]
    if profile is None:
        return [f"<b>{title}</b>: ⚠️ <i>تعذّر الاتصال حالياً — حاول بعد قليل</i>"]
    if profile.get("missing"):
        return [f"<b>{title}</b>: ❌ <i>الحساب غير موجود</i>"]
    if profile.get("blocked"):
        hint = " — فعّل مفتاح البحث (Serper) لعرض بياناته" if profile.get("no_key") else ""
        return [f"<b>{title}</b>: 🔒 <i>المنصة تحجب الطلبات من الخوادم{hint}</i>"]

    badges = ("✅" if profile.get("verified") else "") + (" 🔒" if profile.get("private") else "")
    followers = fmt_num(profile.get("followers")) or profile.get("followers_text")
    following = fmt_num(profile.get("following")) or profile.get("following_text")
    posts = fmt_num(profile.get("posts")) or profile.get("posts_text")
    posts_label = {"tiktok": "🎬 الفيديوهات", "instagram": "🖼️ المنشورات", "x": "📝 التغريدات"}[platform]
    lines: list[str | None] = [
        f'<b>{title}</b> — <a href="{esc_attr(profile["url"])}">@{esc(profile["username"])}</a> {badges}'.rstrip(),
        _kv("الاسم", profile.get("name"), code=False),
        _kv("النبذة", _short(str(profile["bio"]), 200) if profile.get("bio") else None, code=False),
        f"• 👥 المتابِعون: <b>{esc(followers)}</b>" if followers else None,
        f"• ➡️ يتابع: <b>{esc(following)}</b>" if following else None,
        f"• {posts_label}: <b>{esc(posts)}</b>" if posts else None,
        f"• ❤️ الإعجابات: <b>{esc(fmt_num(profile.get('likes')))}</b>" if fmt_num(profile.get("likes")) else None,
        f"• 🖼️ الوسائط: <b>{esc(fmt_num(profile.get('media')))}</b>" if fmt_num(profile.get("media")) else None,
        _kv("📂 التصنيف", profile.get("category"), code=False),
        _kv("📍 الموقع", profile.get("location"), code=False),
        _kv("🔗 الرابط في البايو", profile.get("website")),
        _kv("📅 تاريخ الإنشاء", profile.get("created")),
        "• 🔒 حساب خاص" if profile.get("private") else None,
        "<i>ℹ️ من نتائج Google — قد لا تكون محدّثة لحظياً</i>" if profile.get("source") == "google" else None,
    ]
    return lines


async def accounts_lookup(query: str, only: str | None = None) -> LookupResult:
    """معلومات حسابات TikTok / Instagram / X — كل المنصات معاً أو منصة واحدة."""
    platform, username = parse_account(clean_query(query))
    platforms = [only or platform] if (only or platform) else ["tiktok", "instagram", "x"]

    async def fetch(p: str) -> dict | None:
        if not re.fullmatch(_USERNAME_PATTERNS[p], username):
            return None
        return await _safe(_PROFILE_FETCHERS[p](username), None, timeout=30)

    profiles = await asyncio.gather(*(fetch(p) for p in platforms))

    lines: list[str | None] = [f"📊 <b>معلومات الحساب:</b> <code>{esc(username)}</code>"]
    actions: list[Action] = []
    for p, profile in zip(platforms, profiles, strict=True):
        lines += [""] + _profile_section(p, username, profile)
        if not profile or profile.get("missing") or profile.get("blocked"):
            continue
        if profile.get("avatar"):
            actions.append(Action(f"🖼️ صورة {PLATFORM_NAMES[p].split()[-1] if p != 'x' else 'X'}", "photo",
                                  str(profile["avatar"]), (f"🖼️ صورة حساب @{profile['username']} — {PLATFORM_NAMES[p]}",)))
        if p == "tiktok" and not profile.get("private"):
            actions.append(Action("🎬 آخر فيديوهات TikTok", "tt_videos", profile["username"]))
        if p == "x" and profile.get("banner"):
            actions.append(Action("🏞️ غلاف X", "photo", str(profile["banner"]), (f"🏞️ غلاف حساب @{profile['username']} على X",)))
    if re.fullmatch(r"[A-Za-z0-9._-]{2,40}", username):
        actions.append(Action("🧭 فحص اليوزر في +550 موقع", "wmn", username, wide=True))
    lines += ["", "👇 الصور والفيديوهات تُرسل هنا داخل تيليجرام."]
    return LookupResult(_join(lines), actions)


async def tiktok_latest_videos(username: str, limit: int = 6) -> list[dict]:
    """آخر فيديوهات حساب TikTok (العنوان + الرابط) عبر yt-dlp."""

    def run() -> list[dict]:
        from yt_dlp import YoutubeDL

        options = {
            "quiet": True, "no_warnings": True, "noprogress": True, "logger": _YtdlpLogger(),
            "extract_flat": "in_playlist",
            "playlist_items": f"1:{limit}", "socket_timeout": 20, "http_headers": _BROWSER_HEADERS,
        }
        with YoutubeDL(options) as ydl:
            info = ydl.extract_info(f"https://www.tiktok.com/@{username}", download=False) or {}
        videos = []
        for entry in info.get("entries") or []:
            if entry and entry.get("id"):
                videos.append({
                    "title": entry.get("title") or entry.get("description") or "",
                    "url": f"https://www.tiktok.com/@{username}/video/{entry['id']}",
                    "views": entry.get("view_count"),
                })
        return videos[:limit]

    try:
        return await asyncio.wait_for(asyncio.to_thread(run), timeout=60)
    except Exception as exc:  # noqa: BLE001 — أي فشل يعني عدم توفر القائمة
        logger.info("🎬 تعذّر جلب فيديوهات TikTok: %s", str(exc)[:150])
        return []


def format_tiktok_videos(username: str, videos: list[dict]) -> str:
    if not videos:
        return f"🎬 <b>آخر فيديوهات @{esc(username)}</b>\n\n⚠️ تعذّر جلب الفيديوهات حالياً — حاول بعد قليل."
    lines = [f"🎬 <b>آخر فيديوهات @{esc(username)} على TikTok</b>", ""]
    for number, video in enumerate(videos, 1):
        views = f" — 👁 {fmt_num(video['views'])}" if fmt_num(video.get("views")) else ""
        lines.append(f'{number}. <a href="{esc_attr(video["url"])}">{esc(_short(video["title"] or "فيديو", 80))}</a>{views}')
    lines += ["", "📥 اضغط رقم الفيديو لتحميله هنا."]
    return "\n".join(lines)


# أقسام فرعية للأوامر /tiktok و /insta و /x
async def tiktok_account_lookup(query: str) -> LookupResult:
    return await accounts_lookup(query, only="tiktok")


async def instagram_account_lookup(query: str) -> LookupResult:
    return await accounts_lookup(query, only="instagram")


async def x_account_lookup(query: str) -> LookupResult:
    return await accounts_lookup(query, only="x")


# تسجيل الأقسام الجديدة في الموزّع الرئيسي
LOOKUPS.update({
    "media": media_lookup,
    "accounts": accounts_lookup,
    "acc_tiktok": tiktok_account_lookup,
    "acc_insta": instagram_account_lookup,
    "acc_x": x_account_lookup,
})
