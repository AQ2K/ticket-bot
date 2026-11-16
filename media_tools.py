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

import config
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
    download_file,
    esc,
    esc_attr,
    get_client,
    phrase,
    search_action,
    url_action,
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


def _ago(moment: datetime) -> str:
    """«منذ 3 أيام» / «منذ سنتين»..."""
    seconds = max(0, int((datetime.now(timezone.utc) - moment).total_seconds()))
    for limit, size, unit in ((3600, 60, "دقيقة"), (86400, 3600, "ساعة"), (86400 * 30, 86400, "يوم"),
                              (86400 * 365, 86400 * 30, "شهر"), (10**12, 86400 * 365, "سنة")):
        if seconds < limit:
            return f"منذ {max(1, seconds // size)} {unit}"
    return ""


def _when_text(timestamp: Any = None, ymd: Any = None) -> str | None:
    """تاريخ ووقت النشر: «2026-11-05 • 14:30 UTC (منذ 10 يوم)»."""
    try:
        moment = datetime.fromtimestamp(int(timestamp), tz=timezone.utc)
        return f"{moment:%Y-%m-%d} • {moment:%H:%M} UTC ({_ago(moment)})"
    except (TypeError, ValueError, OSError):
        date = _date_from_ymd(ymd)
        if not date:
            return None
        return f"{date} ({_ago(datetime.strptime(date, '%Y-%m-%d').replace(tzinfo=timezone.utc))})"


def _duration_text(seconds: Any) -> str | None:
    try:
        total = int(float(seconds))
    except (TypeError, ValueError):
        return None
    if total <= 0:
        return None
    hours, rest = divmod(total, 3600)
    minutes, secs = divmod(rest, 60)
    return f"{hours}:{minutes:02d}:{secs:02d}" if hours else f"{minutes}:{secs:02d}"


def _stats_block(rows: list[tuple[str, str, Any]]) -> list[str]:
    """أسطر الإحصائيات: (إيموجي، العنوان، القيمة) — تتجاهل القيم الفارغة."""
    return [f"{icon} {label}: <b>{esc(fmt_num(value))}</b>" for icon, label, value in rows if fmt_num(value)]


def _fit_caption(head: list[str | None], body: str, tail: list[str | None], limit: int = 1000) -> str:
    """بناء تعليق المقطع ضمن حد تيليجرام (1024 حرفاً) باختصار النص الأوسط عند الحاجة."""
    fixed = len(_join(head)) + len(_join(tail)) + 4
    room = max(0, limit - fixed)
    middle = esc(_short(body, room)) if body and room > 20 else None
    return _join([*head, middle, *tail])


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
SHORT_NAMES = {"tiktok": "TikTok", "instagram": "Instagram", "x": "X"}


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
        return bool(re.search(r"/(?:p|reel|reels|tv|stories)/", url))
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
    thumb: str | None = None  # صورة مصغّرة للمقطع (تمنع ظهوره متجمداً أو أسود)


@dataclass
class MediaResult:
    caption: str
    items: list[MediaItem] = field(default_factory=list)
    tmpdir: str | None = None
    source_url: str | None = None  # رابط المنشور (لزر «🎵 الصوت MP3»)
    audio_url: str | None = None  # موسيقى منشور الصور في TikTok (تُرسل كملف صوتي)
    audio_title: str | None = None
    audio_performer: str | None = None

    def cleanup(self) -> None:
        if self.tmpdir:
            shutil.rmtree(self.tmpdir, ignore_errors=True)


@dataclass
class AudioResult:
    path: str
    title: str | None
    performer: str | None
    duration: int | None
    tmpdir: str

    def cleanup(self) -> None:
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
    """تحميل مقطع/صور من الرابط حسب المنصة، ثم تجهيز المقاطع لتعمل بسلاسة في تيليجرام."""
    found = find_media_url(url)
    if not found:
        raise InvalidInput("❌ الرابط غير مدعوم — أرسل رابطاً من TikTok أو Instagram أو X.")
    platform, url = found
    if platform == "x":
        result = await _x_media(url)
    elif platform == "tiktok":
        result = await _tiktok_media(url)
    elif "/stories/" in url:
        match = re.search(r"/stories/([A-Za-z0-9._]+)", url)
        result = await instagram_stories(match.group(1) if match else "")
    else:
        try:
            result = await _ytdlp_media(url, "instagram")
        except InvalidInput as exc:
            fallback = await _instagram_photos(url)
            if not fallback:
                raise exc
            result = fallback
    result.source_url = result.source_url or url
    await _prepare_videos(result)
    return result


# ── TikTok: مقاطع الفيديو + منشورات الصور (Slideshow) ──────


async def _resolve_tiktok_url(url: str) -> str:
    """الروابط المختصرة (vm.tiktok.com) ← الرابط الكامل للمنشور."""
    if not re.search(r"//(?:vm|vt)\.tiktok\.com/|tiktok\.com/t/", url):
        return url
    try:
        resp = await get_client().get(url, headers=_BROWSER_HEADERS, timeout=15)
        return str(resp.url)
    except Exception:  # noqa: BLE001 — نكمل بالرابط الأصلي
        return url


async def _tiktok_item(url: str) -> dict | None:
    """بيانات منشور TikTok من صفحته. صفحة /video/ تحتوي بيانات الصور أيضاً بخلاف /photo/."""
    match = re.search(r"tiktok\.com/@([^/?#]+)/(?:video|photo)/(\d+)", url)
    if not match:
        return None
    page = f"https://www.tiktok.com/@{match.group(1)}/video/{match.group(2)}"
    resp = await _fetch(page, headers=_BROWSER_HEADERS, timeout=15)
    if resp is None or resp.status_code != 200:
        return None
    found = re.search(r'id="__UNIVERSAL_DATA_FOR_REHYDRATION__"[^>]*>(.*?)</script>', resp.text, re.DOTALL)
    if not found:
        return None
    try:
        detail = json.loads(found.group(1))["__DEFAULT_SCOPE__"]["webapp.video-detail"]
        return detail["itemInfo"]["itemStruct"]
    except (ValueError, KeyError, TypeError):
        return None


async def _tiktok_media(url: str) -> MediaResult:
    url = await _resolve_tiktok_url(url)
    if "/photo/" not in url:
        try:
            return await _ytdlp_media(url, "tiktok")
        except InvalidInput as exc:
            item = await _safe(_tiktok_item(url), None, timeout=20)
            if not (item and item.get("imagePost")):
                raise exc
            return await _tiktok_photos(item, url)
    item = await _safe(_tiktok_item(url), None, timeout=20)
    if not (item and (item.get("imagePost") or {}).get("images")):
        raise InvalidInput("⚠️ تعذّر جلب صور المنشور — قد يكون محذوفاً أو خاصاً. حاول بعد قليل.")
    return await _tiktok_photos(item, url)


async def _tiktok_photos(item: dict, url: str) -> MediaResult:
    """تحميل صور منشور TikTok (حتى 10) + موسيقاه، مع كل معلومات المنشور."""
    tmpdir = tempfile.mkdtemp(prefix="osint_dl_")
    images = (item.get("imagePost") or {}).get("images") or []

    async def fetch(index: int, image: dict) -> MediaItem | None:
        for candidate in (image.get("imageURL") or {}).get("urlList") or []:
            try:
                data, _ = await download_file(candidate, max_mb=10)
            except Exception:  # noqa: BLE001 — نجرب الرابط البديل
                continue
            path = f"{tmpdir}/photo_{index}.jpg"
            Path(path).write_bytes(data)
            return MediaItem("photo", path=path, width=image.get("imageWidth"), height=image.get("imageHeight"))
        return None

    photos = [p for p in await asyncio.gather(*(fetch(i, img) for i, img in enumerate(images[:10]))) if p]
    if not photos:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise InvalidInput("⚠️ تعذّر تحميل صور المنشور حالياً — حاول بعد قليل.")

    author = item.get("author") or {}
    stats = item.get("stats") or {}
    music = item.get("music") or {}
    name, handle = author.get("nickname") or "", author.get("uniqueId") or ""
    head = [f"🎵 TikTok <b>{esc(name)}</b>" + (f" (@{esc(handle)})" if handle and handle != name else "")
            + (" ✅" if author.get("verified") else "")]
    when = _when_text(item.get("createTime"))
    sound = " — ".join(p for p in (music.get("title"), music.get("authorName")) if p)
    tail = [
        "━━━━━━━━━━━━",
        f"📅 النشر: {when}" if when else None,
        *_stats_block([
            ("👁", "المشاهدات", stats.get("playCount")), ("❤️", "الإعجابات", stats.get("diggCount")),
            ("💬", "التعليقات", stats.get("commentCount")), ("🔁", "المشاركات", stats.get("shareCount")),
            ("🔖", "الحفظ", stats.get("collectCount")),
        ]),
        f"🎵 الصوت: {esc(_short(sound, 80))}" if sound else None,
        f"🖼️ الصور: {len(photos)}" + (f" من {len(images)}" if len(images) > len(photos) else ""),
        f'🔗 <a href="{esc_attr(url)}">رابط المنشور</a>',
    ]
    title = (item.get("imagePost") or {}).get("title") or ""
    body = f"{title}\n{item.get('desc') or ''}".strip() if title and title not in (item.get("desc") or "") else item.get("desc") or title
    return MediaResult(
        _fit_caption(head, body, tail), photos, tmpdir, source_url=url,
        audio_url=music.get("playUrl") or None, audio_title=music.get("title"), audio_performer=music.get("authorName"),
    )


# ── تجهيز المقاطع لتيليجرام: H.264 + تشغيل فوري + صورة مصغّرة ──

_FFMPEG = shutil.which("ffmpeg")
_FFPROBE = shutil.which("ffprobe")
_LONG_SIDE_1280 = "scale='if(gt(iw,ih),min(1280,iw),-2)':'if(gt(iw,ih),-2,min(1280,ih))'"
_THUMB_320 = "scale='if(gt(iw,ih),320,-2)':'if(gt(iw,ih),-2,320)'"
_LOUDNORM = "loudnorm=I=-14:TP=-1.5:LRA=11"


async def _run(args: list[str], timeout: float) -> tuple[int, bytes]:
    """تشغيل أمر خارجي (ffmpeg/ffprobe) بمهلة."""
    proc = await asyncio.create_subprocess_exec(
        *args, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
    )
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout)
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        return -1, b""
    return proc.returncode or 0, out


async def _probe(path: str) -> dict:
    """قراءة ترميز الفيديو وأبعاده ومدته عبر ffprobe."""
    code, out = await _run([
        _FFPROBE, "-v", "error", "-select_streams", "v:0",
        "-show_entries", "stream=codec_name,width,height:format=duration", "-of", "json", path,
    ], timeout=30)
    if code != 0:
        return {}
    try:
        data = json.loads(out or b"{}")
    except ValueError:
        return {}
    stream = (data.get("streams") or [{}])[0]
    try:
        duration = int(float((data.get("format") or {}).get("duration") or 0))
    except ValueError:
        duration = 0
    return {"codec": stream.get("codec_name"), "width": stream.get("width"),
            "height": stream.get("height"), "duration": duration or None}


async def _prepare_video(item: MediaItem, tmpdir: str, index: int) -> None:
    """تحويل المقطع لملف محلي H.264 يبدأ تشغيله فوراً (faststart) مع صورة مصغّرة وأبعاد صحيحة."""
    if item.path is None and item.url:
        try:
            data, _ = await download_file(item.url, max_mb=49)
        except Exception as exc:  # noqa: BLE001 — نُبقي الرابط ليحمّله تيليجرام بنفسه
            logger.info("📥 تعذّر تحميل المقطع محلياً: %s", exc.__class__.__name__)
            return
        item.path = f"{tmpdir}/video_{index}.mp4"
        Path(item.path).write_bytes(data)
    if not item.path or not (_FFMPEG and _FFPROBE):
        return

    info = await _probe(item.path)
    output = f"{tmpdir}/ready_{index}.mp4"
    # 🔊 الصوت: AAC بجودة 192k مع توحيد مستوى الصوت (loudnorm) حتى لا تكون المقاطع خافتة أو مزعجة
    audio = ["-c:a", "aac", "-b:a", "192k", "-ar", "44100", "-af", _LOUDNORM]
    streams = ["-map", "0:v:0", "-map", "0:a:0?"]
    if info.get("codec") and info["codec"] != "h264":
        args = [_FFMPEG, "-y", "-i", item.path, *streams, "-c:v", "libx264", "-preset", "veryfast", "-crf", "23",
                "-vf", _LONG_SIDE_1280, "-pix_fmt", "yuv420p", *audio, "-movflags", "+faststart", output]
        timeout = 240
    else:
        args = [_FFMPEG, "-y", "-i", item.path, *streams, "-c:v", "copy", *audio, "-movflags", "+faststart", output]
        timeout = 90
    code, _ = await _run(args, timeout)
    if code == 0 and Path(output).exists() and 0 < Path(output).stat().st_size <= MAX_UPLOAD_BYTES:
        item.path = output
        info = await _probe(output)
    item.width = info.get("width") or item.width
    item.height = info.get("height") or item.height
    item.duration = info.get("duration") or item.duration

    thumb = f"{tmpdir}/thumb_{index}.jpg"
    code, _ = await _run([_FFMPEG, "-y", "-ss", "0.5", "-i", item.path, "-frames:v", "1",
                          "-vf", _THUMB_320, "-q:v", "5", thumb], timeout=30)
    if code == 0 and Path(thumb).exists() and Path(thumb).stat().st_size < 200_000:
        item.thumb = thumb


async def extract_audio(url: str) -> AudioResult:
    """🎵 استخراج صوت المنشور كملف MP3 عالي الجودة (موسيقى منشور الصور أو صوت المقطع)."""
    if not _FFMPEG:
        raise InvalidInput("⚠️ استخراج الصوت غير متاح على هذا الخادم (ffmpeg غير مثبّت).")
    result = await download_media(url)
    tmpdir = tempfile.mkdtemp(prefix="osint_mp3_")
    try:
        source = None
        if result.audio_url:  # منشور صور TikTok: موسيقى المنشور نفسها
            data, _ = await download_file(result.audio_url, max_mb=30)
            source = f"{tmpdir}/music.src"
            Path(source).write_bytes(data)
        else:
            video = next((i for i in result.items if i.kind == "video" and i.path), None)
            source = video.path if video else None
        if not source:
            raise InvalidInput("📭 هذا المنشور لا يحتوي على صوت.")
        output = f"{tmpdir}/audio.mp3"
        code, _ = await _run([_FFMPEG, "-y", "-i", source, "-vn", "-c:a", "libmp3lame", "-b:a", "192k",
                              "-ar", "44100", "-af", _LOUDNORM, output], timeout=120)
        if code != 0 or not Path(output).exists() or Path(output).stat().st_size == 0:
            raise InvalidInput("📭 تعذّر استخراج الصوت — قد لا يحتوي المنشور على صوت.")
        probe = await _run([_FFPROBE, "-v", "error", "-show_entries", "format=duration", "-of", "csv=p=0", output], 30)
        try:
            duration = int(float(probe[1].decode().strip() or 0)) or None
        except ValueError:
            duration = None
        return AudioResult(output, result.audio_title, result.audio_performer, duration, tmpdir)
    except Exception:
        shutil.rmtree(tmpdir, ignore_errors=True)
        raise
    finally:
        result.cleanup()


# ── 📖 ستوريات Instagram (تتطلب جلسة دخول INSTAGRAM_SESSIONID) ──

STORIES_NEED_LOGIN_TEXT = (
    "📖 <b>ستوريات Instagram تتطلب تسجيل الدخول</b>\n\n"
    "Instagram لا يعرض الستوريات للزوار من الخوادم إطلاقاً (كل المواقع المجهولة محجوبة أو تطلب CAPTCHA).\n"
    "لتفعيلها أضف كوكي الجلسة <code>sessionid</code> من حساب Instagram <b>ثانوي</b> كسرّ في GitHub باسم "
    "<code>INSTAGRAM_SESSIONID</code> (التفاصيل في /help).\n\n"
    "🎵 ستوريات TikTok غير متاحة للزوار من خارج التطبيق."
)


def _instagram_session_headers() -> dict:
    return {
        **_BROWSER_HEADERS,
        "x-ig-app-id": "936619743392459",
        "Cookie": f"sessionid={config.INSTAGRAM_SESSIONID}",
    }


async def instagram_stories(username: str) -> MediaResult:
    """تحميل ستوريات حساب Instagram الحالية (صور ومقاطع) باستخدام جلسة الدخول المضافة."""
    if not re.fullmatch(r"[A-Za-z0-9._]{1,30}", username or ""):
        raise InvalidInput("❌ يوزر Instagram غير صالح.")
    if not config.INSTAGRAM_SESSIONID:
        raise InvalidInput(STORIES_NEED_LOGIN_TEXT)
    headers = _instagram_session_headers()
    profile = await _get_json(
        "https://www.instagram.com/api/v1/users/web_profile_info/", params={"username": username},
        headers=headers, timeout=15,
    )
    user = ((profile or {}).get("data") or {}).get("user") if isinstance(profile, dict) else None
    if not isinstance(user, dict) or not user.get("id"):
        raise InvalidInput("⚠️ تعذّر الوصول للحساب — تأكد من اليوزر، أو أن جلسة INSTAGRAM_SESSIONID ما زالت صالحة.")
    if user.get("is_private") and not user.get("followed_by_viewer"):
        raise InvalidInput("🔒 الحساب خاص — لا يمكن تحميل ستورياته إلا إذا كان حساب الجلسة يتابعه.")
    reels = await _get_json(
        "https://www.instagram.com/api/v1/feed/reels_media/", params={"reel_ids": user["id"]},
        headers=headers, timeout=20,
    )
    entries = ((((reels or {}).get("reels") or {}).get(str(user["id"])) or {}).get("items") or []) if isinstance(reels, dict) else []
    if not entries:
        raise InvalidInput(f"📭 لا توجد ستوريات حالية لـ @{esc(username)} (الستوري يختفي بعد 24 ساعة).")

    items: list[MediaItem] = []
    for entry in entries[:10]:
        videos = entry.get("video_versions") or []
        images = ((entry.get("image_versions2") or {}).get("candidates")) or []
        if videos and videos[0].get("url"):
            items.append(MediaItem("video", url=videos[0]["url"], duration=int(entry.get("video_duration") or 0) or None))
        elif images and images[0].get("url"):
            items.append(MediaItem("photo", url=images[0]["url"]))
    if not items:
        raise InvalidInput("📭 تعذّر قراءة ستوريات الحساب حالياً.")
    times = [e.get("taken_at") for e in entries[:10] if e.get("taken_at")]
    caption = _join([
        f"📖 <b>ستوريات @{esc(username)}</b>" + (f" — {esc(user.get('full_name') or '')}" if user.get("full_name") else ""),
        "━━━━━━━━━━━━",
        f"🎞️ العدد: <b>{len(items)}</b>" + (f" من {len(entries)}" if len(entries) > len(items) else ""),
        f"🕒 أحدث ستوري: {_when_text(max(times))}" if times else None,
        f'🔗 <a href="https://www.instagram.com/{esc_attr(username)}/">الحساب</a>',
    ])
    return MediaResult(caption, items, source_url=f"https://www.instagram.com/stories/{username}/")


async def _prepare_videos(result: MediaResult) -> None:
    videos = [i for i in result.items if i.kind == "video"]
    if not videos:
        return
    if result.tmpdir is None:
        result.tmpdir = tempfile.mkdtemp(prefix="osint_dl_")
    for index, item in enumerate(videos):
        try:
            await _prepare_video(item, result.tmpdir, index)
        except Exception:  # noqa: BLE001 — فشل التجهيز لا يمنع إرسال المقطع الأصلي
            logger.exception("⚠️ فشل تجهيز المقطع")


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
        verification = author.get("verification") or {}
        caption = _x_caption({
            "screen_name": author.get("screen_name"), "name": author.get("name"), "text": tweet.get("text"),
            "verified": verification.get("verified") if isinstance(verification, dict) else None,
            "followers": author.get("followers"), "timestamp": tweet.get("created_timestamp"),
            "views": tweet.get("views"), "likes": tweet.get("likes"), "retweets": tweet.get("retweets"),
            "replies": tweet.get("replies"), "quotes": tweet.get("quotes"), "bookmarks": tweet.get("bookmarks"),
            "duration": next((i.duration for i in items if i.duration), None),
            "size": next((f"{i.width}×{i.height}" for i in items if i.width and i.height), None),
            "url": tweet.get("url") or url,
        })
    else:
        vx = await _vx_json(f"Twitter/status/{tweet_id}")
        if not vx:
            raise InvalidInput("⚠️ تعذّر جلب التغريدة — قد تكون محذوفة أو من حساب خاص، أو الخدمة مشغولة. حاول بعد قليل.")
        for media in vx.get("media_extended") or []:
            kind = "photo" if media.get("type") == "image" else "video"
            if media.get("url"):
                duration = int((media.get("duration_millis") or 0) / 1000) or None
                items.append(MediaItem(kind, url=str(media["url"]), duration=duration))
        caption = _x_caption({
            "screen_name": vx.get("user_screen_name"), "name": vx.get("user_name"), "text": vx.get("text"),
            "timestamp": vx.get("date_epoch"), "likes": vx.get("likes"), "retweets": vx.get("retweets"),
            "replies": vx.get("replies"), "duration": next((i.duration for i in items if i.duration), None),
            "url": vx.get("tweetURL") or url,
        })
    if not items:
        raise InvalidInput("📭 هذه التغريدة لا تحتوي على فيديو أو صور.")
    performer = (data or {}).get("tweet", {}).get("author", {}).get("name") if data else None
    return MediaResult(caption, items[:10], audio_title=f"صوت تغريدة {tweet_id}", audio_performer=performer)


def _x_caption(t: dict) -> str:
    """تعليق تغريدة كامل: الناشر، النص، تاريخ ووقت النشر، وكل الإحصائيات."""
    badge = " ✅" if t.get("verified") else ""
    followers = f" • 👥 {esc(fmt_num(t['followers']))} متابع" if fmt_num(t.get("followers")) else ""
    head = [f"𝕏 <b>{esc(t.get('name') or '')}</b> (@{esc(t.get('screen_name') or '?')}){badge}{followers}"]
    when = _when_text(t.get("timestamp"))
    meta = " • ".join(p for p in (
        f"⏱️ المدة: {_duration_text(t.get('duration'))}" if _duration_text(t.get("duration")) else None,
        f"📐 {t['size']}" if t.get("size") else None,
    ) if p)
    tail = [
        "━━━━━━━━━━━━",
        f"📅 النشر: {when}" if when else None,
        *_stats_block([
            ("👁", "المشاهدات", t.get("views")), ("❤️", "الإعجابات", t.get("likes")),
            ("🔁", "إعادة النشر", t.get("retweets")), ("💬", "الردود", t.get("replies")),
            ("🗨️", "الاقتباسات", t.get("quotes")), ("🔖", "الحفظ", t.get("bookmarks")),
        ]),
        meta or None,
        f'🔗 <a href="{esc_attr(t.get("url") or "")}">رابط التغريدة</a>',
    ]
    return _fit_caption(head, str(t.get("text") or ""), tail)


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
        # H.264 أولاً: صيغة H.265 (HEVC) التي يفضّلها TikTok تتجمد صورتها في تيليجرام على أجهزة كثيرة
        "format": (
            f"best[vcodec^=h264][ext=mp4][filesize<{size}]/best[vcodec^=avc][ext=mp4][filesize<{size}]/"
            f"best[vcodec^=h264][filesize_approx<{size}]/best[vcodec^=avc][filesize_approx<{size}]/"
            f"best[ext=mp4][filesize<{size}]/best[filesize<{size}]/best[filesize_approx<{size}]/best[ext=mp4]/best"
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

    item = MediaItem("video", path=path, duration=int(info.get("duration") or 0) or None,
                     width=info.get("width"), height=info.get("height"))
    artists = info.get("artists") or ([info["artist"]] if info.get("artist") else [])
    return MediaResult(
        _ytdlp_caption(info, platform, url), [item], tmpdir, source_url=url,
        audio_title=info.get("track") or _short(str(info.get("description") or info.get("title") or "صوت المقطع"), 60),
        audio_performer=", ".join(artists) or info.get("channel") or info.get("uploader"),
    )


def _ytdlp_caption(info: dict, platform: str, url: str) -> str:
    """تعليق مقطع TikTok/Instagram كامل: الناشر، الوصف، تاريخ ووقت النشر، وكل الإحصائيات."""
    icon = "🎵 TikTok" if platform == "tiktok" else "📸 Instagram"
    name = info.get("channel") or info.get("uploader") or ""
    handle = str(info.get("uploader") or info.get("uploader_id") or "")
    if handle.isdigit() or handle == name:  # TikTok يُرجع أحياناً معرّفاً رقمياً — لا فائدة من عرضه
        handle = ""
    followers = f" • 👥 {esc(fmt_num(info['channel_follower_count']))} متابع" if fmt_num(info.get("channel_follower_count")) else ""
    head = [f"{icon} <b>{esc(name)}</b>" + (f" (@{esc(handle)})" if handle else "") + followers]
    when = _when_text(info.get("timestamp"), info.get("upload_date"))
    artists = info.get("artists") or ([info["artist"]] if info.get("artist") else [])
    track = info.get("track")
    sound = f"{track} — {', '.join(artists)}" if track and artists else track
    width, height = info.get("width"), info.get("height")
    meta = " • ".join(p for p in (
        f"⏱️ المدة: {_duration_text(info.get('duration'))}" if _duration_text(info.get("duration")) else None,
        f"📐 {width}×{height}" if width and height else None,
    ) if p)
    tail = [
        "━━━━━━━━━━━━",
        f"📅 النشر: {when}" if when else None,
        *_stats_block([
            ("👁", "المشاهدات", info.get("view_count")), ("❤️", "الإعجابات", info.get("like_count")),
            ("💬", "التعليقات", info.get("comment_count")), ("🔁", "المشاركات", info.get("repost_count")),
            ("🔖", "الحفظ", info.get("save_count")),
        ]),
        f"🎵 الصوت: {esc(_short(str(sound), 80))}" if sound else None,
        meta or None,
        f'🔗 <a href="{esc_attr(info.get("webpage_url") or url)}">رابط المقطع</a>',
    ]
    return _fit_caption(head, str(info.get("description") or info.get("title") or ""), tail)


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
    info = await _safe(_instagram_post_info(shortcode), None, timeout=20)
    if info:
        head = [f"📸 <b>{label} Instagram</b> — @{esc(info['user'])}" if info.get("user") else f"📸 <b>{label} Instagram</b>"]
        tail = [
            "━━━━━━━━━━━━",
            f"📅 النشر: {esc(info['date'])}" if info.get("date") else None,
            f"❤️ الإعجابات: <b>{esc(info['likes'])}</b>" if info.get("likes") else None,
            f"💬 التعليقات: <b>{esc(info['comments'])}</b>" if info.get("comments") else None,
            "<i>ℹ️ الإحصائيات من نتائج Google</i>",
            f'🔗 <a href="{esc_attr(url)}">رابط المنشور</a>',
        ]
        return MediaResult(_fit_caption(head, info.get("text") or "", tail), items)
    caption = _join([
        f"📸 <b>{label} منشور Instagram</b>",
        f'🔗 <a href="{esc_attr(url)}">رابط المنشور</a>',
    ])
    return MediaResult(caption, items)


_IG_POST_SNIPPET_RE = re.compile(
    r"([\d.,]+\s*[KMB]?)\s+likes?,\s*([\d.,]+\s*[KMB]?)\s+comments?\s*-\s*([A-Za-z0-9._]+)\s+on\s+"
    r"([A-Za-z]+\s+\d{1,2},\s+\d{4})\s*:?\s*(.*)",
    re.IGNORECASE | re.DOTALL,
)


async def _instagram_post_info(shortcode: str) -> dict | None:
    """إحصائيات منشور Instagram من نتائج Google المفهرسة (عند تفعيل مفتاح البحث)."""
    outcome = await web_search(f'"{shortcode}" site:instagram.com')
    for item in outcome.items:
        if shortcode not in item["url"]:
            continue
        match = _IG_POST_SNIPPET_RE.search(f"{item['snippet']}")
        if not match:
            continue
        date = match.group(4)
        try:
            date = datetime.strptime(re.sub(r"\s+", " ", date), "%B %d, %Y").strftime("%Y-%m-%d")
        except ValueError:
            pass
        return {"likes": match.group(1).strip(), "comments": match.group(2).strip(), "user": match.group(3),
                "date": date, "text": match.group(5).strip().strip('"“”')}
    return None


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


_TIKTOK_NOT_FOUND_CODES = {10202, 10221}  # رموز TikTok المؤكدة لـ «الحساب غير موجود»


async def _tiktok_page(username: str) -> tuple[int | None, dict | None]:
    """قراءة صفحة الحساب ← (رمز الحالة، بيانات الحساب). None = تعذّر القراءة."""
    resp = await _fetch(f"https://www.tiktok.com/@{username}", headers=_BROWSER_HEADERS, timeout=15)
    if resp is None or resp.status_code != 200:
        return None, None
    match = re.search(r'id="__UNIVERSAL_DATA_FOR_REHYDRATION__"[^>]*>(.*?)</script>', resp.text, re.DOTALL)
    if not match:
        return None, None
    try:
        detail = json.loads(match.group(1))["__DEFAULT_SCOPE__"]["webapp.user-detail"]
    except (ValueError, KeyError, TypeError):
        return None, None
    return detail.get("statusCode"), detail


async def _tiktok_oembed(username: str) -> dict | bool | None:
    """تحقق ثانٍ عبر oEmbed الرسمي: dict = موجود، False = غير موجود، None = تعذّر التحقق."""
    resp = await _fetch(
        "https://www.tiktok.com/oembed", params={"url": f"https://www.tiktok.com/@{username}"},
        headers=_BROWSER_HEADERS, timeout=15,
    )
    if resp is None:
        return None
    if resp.status_code == 400:
        return False
    if resp.status_code != 200:
        return None
    try:
        data = resp.json()
    except ValueError:
        return None
    return data if isinstance(data, dict) and data.get("author_name") else None


async def tiktok_profile(username: str) -> dict | None:
    """معلومات حساب TikTok. لا نقول «غير موجود» إلا إذا أكّد ذلك مصدران مستقلان."""
    status, detail = await _tiktok_page(username)
    user = ((detail or {}).get("userInfo") or {}).get("user") or {}
    stats = ((detail or {}).get("userInfo") or {}).get("stats") or {}
    if status in (0, None) and user.get("uniqueId"):
        return _tiktok_full_profile(user, stats)

    # الصفحة لم تُرجع البيانات (حجب مؤقت أو رمز غير معتاد) ← نتحقق عبر oEmbed
    oembed = await _tiktok_oembed(username)
    if isinstance(oembed, dict):
        author_url = str(oembed.get("author_url") or f"https://www.tiktok.com/@{username}")
        return {
            "platform": "tiktok",
            "username": author_url.rstrip("/").rsplit("@", 1)[-1] or username,
            "name": oembed.get("author_name"),
            "url": author_url,
            "partial": True,
        }
    if oembed is False and status in _TIKTOK_NOT_FOUND_CODES:
        return {"missing": True}
    return None


def _tiktok_full_profile(user: dict, stats: dict) -> dict:
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
    """معلومات حساب Instagram: الواجهة الرسمية (بجلسة الدخول إن وُجدت)، ثم نتائج Google (Serper) إن حُجبت."""
    headers = _instagram_session_headers() if config.INSTAGRAM_SESSIONID else {**_BROWSER_HEADERS, "x-ig-app-id": "936619743392459"}
    data = await _get_json(
        "https://www.instagram.com/api/v1/users/web_profile_info/",
        params={"username": username},
        headers=headers,
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

    # احتياطي: نتائج Google المفهرسة لصفحة الحساب (استعلامان لزيادة الدقة)
    no_key = False
    seen_profile = None
    for query in (f"site:instagram.com/{username}", f'site:instagram.com "{username}"'):
        outcome = await web_search(query)
        no_key = no_key or outcome.error == "no_key"
        for item in outcome.items:
            path = re.sub(r"^https?://(?:www\.)?instagram\.com", "", item["url"]).split("?")[0].strip("/")
            if path.split("/")[0].lower() != username.lower():
                continue
            seen_profile = seen_profile or item
            stats = _IG_STATS_RE.search(f"{item['snippet']} {item['title']}")
            if stats or path.lower() == username.lower():
                return _instagram_from_google(username, item, stats)
        if outcome.items and seen_profile:
            break
    if seen_profile:
        return _instagram_from_google(username, seen_profile, None)
    return {"blocked": True, "no_key": no_key}


def _instagram_from_google(username: str, item: dict, stats: re.Match | None) -> dict:
    """بناء ملف حساب Instagram من نتيجة Google (العنوان + المقتطف)."""
    name_match = re.match(r"(.+?)\s*\(@", item["title"])
    bio = None
    if not stats:
        bio = item["snippet"]
    else:
        after = item["snippet"][stats.end():]
        bio_match = re.search(r"\)\s*[:.-]?\s*(.+)$", after)
        bio = bio_match.group(1).strip() if bio_match and len(bio_match.group(1).strip()) > 3 else None
    return {
        "platform": "instagram",
        "username": username,
        "name": name_match.group(1).strip() if name_match else None,
        "followers_text": stats.group(1).strip() if stats else None,
        "following_text": stats.group(2).strip() if stats else None,
        "posts_text": stats.group(3).strip() if stats else None,
        "bio": bio,
        "url": f"https://www.instagram.com/{username}/",
        "source": "google",
    }


_PROFILE_FETCHERS = {"tiktok": tiktok_profile, "instagram": instagram_profile, "x": x_profile}


def _profile_section(platform: str, username: str, profile: dict | None) -> list[str | None]:
    """قسم منصة واحدة في تقرير الحساب."""
    title = PLATFORM_NAMES[platform]
    if not re.fullmatch(_USERNAME_PATTERNS[platform], username):
        return [f"<b>{title}</b>: ➖ <i>صيغة اليوزر غير مدعومة على هذه المنصة</i>"]
    if profile is None:
        return [f"<b>{title}</b>: ⚠️ <i>تعذّر التحقق حالياً (المنصة لم تستجب) — حاول بعد قليل</i>"]
    if profile.get("missing"):
        return [f"<b>{title}</b>: ❌ <i>لا يوجد حساب بهذا اليوزر على {SHORT_NAMES[platform]} (تم التأكد من مصدرين)</i>"]
    if profile.get("blocked"):
        if profile.get("no_key"):
            return [f"<b>{title}</b>: 🔒 <i>المنصة تحجب الطلبات من الخوادم — فعّل مفتاح البحث (Serper) لعرض بياناته</i>"]
        return [f"<b>{title}</b>: ⚠️ <i>لم يظهر الحساب في نتائج Google — قد يكون جديداً أو خاصاً أو اليوزر مكتوب بشكل مختلف</i>"]

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
        "<i>✅ الحساب موجود — تعذّر جلب الإحصائيات حالياً، حاول بعد قليل</i>" if profile.get("partial") else None,
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
    # 📖 سؤال تحميل ستوريات Instagram
    if "instagram" in platforms and re.fullmatch(_USERNAME_PATTERNS["instagram"], username):
        lines += ["", f"📖 <b>تبي أحمّل ستوريات @{esc(username)} على Instagram؟</b> اضغط الزر 👇"]
        actions.insert(0, Action("📖 نعم، حمّل ستوريات Instagram", "media",
                                 f"https://www.instagram.com/stories/{username}/", wide=True))
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


# ═══════════════════════════════════════════════════════════
# 🕵️ البحث المتقدم: TikTok / Instagram / X — Google Dorks داخل تيليجرام
# ═══════════════════════════════════════════════════════════

_ACCOUNT_CATEGORY = {"tiktok": "acc_tiktok", "instagram": "acc_insta", "x": "acc_x"}
_X_SITES = "(site:x.com OR site:twitter.com)"


def _profile_url(platform: str, username: str) -> str:
    return {
        "tiktok": f"https://www.tiktok.com/@{username}",
        "instagram": f"https://www.instagram.com/{username}/",
        "x": f"https://x.com/{username}",
    }[platform]


def _platform_dorks(platform: str, query: str, username: str | None) -> list[tuple[str, str]]:
    """استعلامات Google Dorks خاصة بكل منصة (الإشارات، التعليقات، الدويتو...)."""
    term = phrase(username or query)
    name = SHORT_NAMES[platform]
    options: list[tuple[str, str]] = []
    if platform == "tiktok":
        if username:
            options += [
                ("🎬 مقاطع ذُكر فيها الحساب", f'site:tiktok.com inurl:video "@{username}"'),
                ("💬 مقاطع فيها تعليقه/إشارته", f'site:tiktok.com inurl:video "@{username}" -inurl:/@{username}/'),
                ("🔁 دويتو / ستيتش معه", f'site:tiktok.com inurl:video ("duet with @{username}" OR "stitch with @{username}")'),
                ("📂 منشورات حسابه", f"site:tiktok.com/@{username}"),
                ("🔗 ذكر الحساب خارج TikTok", f'"tiktok.com/@{username}" -site:tiktok.com'),
            ]
        else:
            options += [
                ("🎬 الفيديوهات", f"site:tiktok.com inurl:video {term}"),
                ("#️⃣ الهاشتاقات", f"site:tiktok.com/tag {term}"),
                ("🎵 الأصوات", f"site:tiktok.com/music {term}"),
            ]
        base = "site:tiktok.com"
    elif platform == "instagram":
        if username:
            options += [
                ("🏷️ منشورات ذُكر فيها", f'site:instagram.com/p "@{username}"'),
                ("🎬 ريلز ذُكر فيها", f'site:instagram.com/reel "@{username}"'),
                ("💬 تعليقات وإشارات له", f'site:instagram.com "@{username}" -inurl:/{username}/'),
                ("📂 منشورات حسابه", f"site:instagram.com/{username}"),
                ("🔗 ذكر الحساب خارج Instagram", f'"instagram.com/{username}" -site:instagram.com'),
            ]
        else:
            options += [
                ("🖼️ المنشورات", f"site:instagram.com/p {term}"),
                ("🎬 الريلز", f"site:instagram.com/reel {term}"),
                ("#️⃣ الهاشتاقات", f"site:instagram.com/explore/tags {term}"),
            ]
        base = "site:instagram.com"
    else:
        if username:
            options += [
                (f"💬 تغريدات تذكر @{username}", f'"@{username}" {_X_SITES} inurl:status'),
                (f"↩️ ردود على @{username}", f'"to:{username}" OR "replying to @{username}" {_X_SITES}'),
                ("📂 تغريدات حسابه", f"site:x.com/{username} OR site:twitter.com/{username}"),
                ("🔗 ذكر الحساب خارج X", f'("x.com/{username}" OR "twitter.com/{username}") -site:x.com -site:twitter.com'),
            ]
        else:
            tag = re.sub(r"\s+", "", query.lstrip("#"))
            options += [
                ("📝 التغريدات", f"{_X_SITES} inurl:status {term}"),
                ("#️⃣ الهاشتاق", f'{_X_SITES} "#{tag}"'),
            ]
        base = _X_SITES
    options.append((f"🔎 كل نتائج {name}", f"{base} {term}"))
    return options


async def platform_search_lookup(query: str, platform: str) -> LookupResult:
    """البحث المتقدم في منصة واحدة — النتائج مرتبة داخل تيليجرام + رابط صفحة الحساب."""
    q = clean_query(query)
    match = re.fullmatch(r"@?([A-Za-z0-9._]{2,30})", q)
    username = match.group(1) if match and re.fullmatch(_USERNAME_PATTERNS[platform], match.group(1)) else None
    options = _platform_dorks(platform, q, username)

    # أزرار الدورك تفتح نتائجها في Google بالمتصفح مباشرة
    actions: list[Action] = [search_action(label, dork, browser=True) for label, dork in options]
    if username:
        profile = _profile_url(platform, username)
        actions.append(url_action("🔗 فتح صفحة الحساب", profile, wide=True))
        actions.append(Action("📊 معلومات الحساب", "lookup", username, (_ACCOUNT_CATEGORY[platform],)))
        if platform == "tiktok":
            actions.append(Action("🎬 آخر الفيديوهات (تحميل)", "tt_videos", username))

    likes_note = None
    if username and platform == "tiktok":
        likes_note = (
            "ℹ️ <i>«اللايكات» التي ضغطها الحساب مخفية افتراضياً في TikTok ولا تظهر لأي أداة خارجية. "
            "الأزرار أعلاه تجد المقاطع التي ذُكر أو علّق أو عمل دويتو فيها (مما فهرسه Google).</i>"
        )
    elif username and platform == "instagram":
        likes_note = (
            "ℹ️ <i>Instagram لا يُظهر إعجابات أي حساب إطلاقاً — لكن الأزرار تجد المنشورات والريلز "
            "التي ذُكر أو علّق فيها (مما فهرسه Google).</i>"
        )

    sep = "━━━━━━━━━━━━━━━━"
    header = [
        f"🕵️ <b>البحث المتقدم — {PLATFORM_NAMES[platform]}</b>",
        sep,
        f"🎯 الهدف: <code>{esc(q)}</code>",
    ]
    if username:
        header.append(f'🔗 الصفحة: <a href="{esc_attr(_profile_url(platform, username))}">{esc(_profile_url(platform, username))}</a>')
    header += [
        f"🧩 النوع: {'يوزر 👤' if username else 'اسم / كلمة / هاشتاق 🔤'}",
        sep,
        "🌐 اضغط أي زر ليفتح نتائج Google في متصفحك",
        likes_note,
    ]
    return LookupResult(_join(header), actions)


async def adv_tiktok_lookup(query: str) -> LookupResult:
    return await platform_search_lookup(query, "tiktok")


async def adv_instagram_lookup(query: str) -> LookupResult:
    return await platform_search_lookup(query, "instagram")


async def adv_x_lookup(query: str) -> LookupResult:
    return await platform_search_lookup(query, "x")


# تسجيل الأقسام الجديدة في الموزّع الرئيسي
LOOKUPS.update({
    "adv_tiktok": adv_tiktok_lookup,
    "adv_insta": adv_instagram_lookup,
    "adv_x": adv_x_lookup,
    "media": media_lookup,
    "accounts": accounts_lookup,
    "acc_tiktok": tiktok_account_lookup,
    "acc_insta": instagram_account_lookup,
    "acc_x": x_account_lookup,
})
