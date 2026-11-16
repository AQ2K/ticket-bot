"""
💎 بوت OSINT الشامل — مصادر علنية فقط
=====================================
الملف الرئيسي: تهيئة البوت، تسجيل المعالجات (Handlers)، وتوجيه المحادثات.

التشغيل:
    python main.py

مسار المحادثة:
    /start ← القائمة الرئيسية ← اختيار قسم ← (انتظار الإدخال) ← إرسال الهدف
           ← تقرير + أزرار روابط مباشرة + «🔁 بحث جديد» / «🔙 رجوع»
"""

from __future__ import annotations

import asyncio
import contextlib
import html
import logging
import re
import secrets
import time
import warnings
from collections import OrderedDict
from collections.abc import Awaitable, Callable
from functools import wraps
from pathlib import Path
from typing import Any

from telegram import (
    BotCommand,
    BotCommandScopeChat,
    InlineKeyboardButton,
    InlineKeyboardMarkup,
    InputMediaPhoto,
    InputMediaVideo,
    LinkPreviewOptions,
    Message,
    Update,
)
from telegram.constants import ChatAction, ParseMode
from telegram.error import BadRequest, Forbidden, RetryAfter, TelegramError
from telegram.ext import (
    Application,
    CallbackQueryHandler,
    CommandHandler,
    ContextTypes,
    ConversationHandler,
    Defaults,
    MessageHandler,
    PicklePersistence,
    filters,
)
from telegram.warnings import PTBUserWarning

import config
import keyboards as kb
import media_tools as media
import osint_tools as tools

# ═══════════════════════════════════════════════════════════
# 📝 السجلات
# ═══════════════════════════════════════════════════════════

logging.basicConfig(
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    level=config.LOG_LEVEL,
)
# مكتبة httpx تسجّل كل طلب (بما فيه رابط يحتوي التوكن) — نرفع مستواها لإخفائه
logging.getLogger("httpx").setLevel(logging.WARNING)
logger = logging.getLogger("osint_bot")

# تحذير معروف عند استخدام أزرار Callback داخل ConversationHandler — آمن هنا
warnings.filterwarnings("ignore", message=r".*per_message=False.*", category=PTBUserWarning)

# حالات المحادثة
WAITING_INPUT = 1

# وقت بدء التشغيل (لحساب مدة التشغيل في /stats)
START_TIME = time.time()

Handler = Callable[[Update, ContextTypes.DEFAULT_TYPE], Awaitable[object]]


class ActionStore:
    """مخزن مؤقت في الذاكرة لبيانات الأزرار.

    بيانات الزر في تيليجرام (callback_data) محدودة بـ 64 بايت، بينما استعلامات البحث أطول،
    لذلك نحفظ البيانات هنا ونضع في الزر رمزاً قصيراً فقط. كل رمز مرتبط بمستخدم واحد.
    """

    def __init__(self, limit: int = 20000) -> None:
        self._items: OrderedDict[str, tuple[int, Any]] = OrderedDict()
        self._limit = limit

    def put(self, user_id: int, value: Any) -> str:
        token = secrets.token_urlsafe(6)
        self._items[token] = (user_id, value)
        while len(self._items) > self._limit:
            self._items.popitem(last=False)
        return token

    def get(self, token: str, user_id: int) -> Any | None:
        item = self._items.get(token)
        if item is None or item[0] != user_id:
            return None
        self._items.move_to_end(token)
        return item[1]


ACTIONS = ActionStore()

# المستخدمون الذين لديهم فحص شامل (WhatsMyName) قيد التنفيذ
WMN_RUNNING: set[int] = set()

# 📥 التحميلات: تحميل واحد لكل مستخدم، وتحميلان كحد أقصى في نفس الوقت للبوت كله
DOWNLOADS_RUNNING: set[int] = set()
DOWNLOAD_SLOTS = asyncio.Semaphore(2)
_UPLOAD_TIMEOUTS = {"read_timeout": 300, "write_timeout": 300, "connect_timeout": 30, "pool_timeout": 30}


# ═══════════════════════════════════════════════════════════
# 🔧 دوال مساعدة
# ═══════════════════════════════════════════════════════════


def _register_user(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """حفظ معرّف المستخدم (للإحصائيات والرسائل الجماعية)."""
    if update.effective_user:
        context.bot_data.setdefault("users", set()).add(update.effective_user.id)


def _record_search(context: ContextTypes.DEFAULT_TYPE, category: str) -> None:
    """زيادة عدّاد عمليات البحث."""
    stats = context.bot_data.setdefault("stats", {"total": 0, "by_category": {}})
    stats["total"] = stats.get("total", 0) + 1
    by_category = stats.setdefault("by_category", {})
    by_category[category] = by_category.get(category, 0) + 1


def _first_name(update: Update) -> str:
    user = update.effective_user
    return html.escape(user.first_name) if user and user.first_name else ""


def _is_admin(update: Update) -> bool:
    return bool(update.effective_user and update.effective_user.id in config.ADMIN_IDS)


def _search_provider() -> str | None:
    """مزود البحث المفعّل داخل تيليجرام (إن وُجد مفتاح)."""
    if config.SERPER_API_KEY:
        return "Serper — Google"
    if config.BRAVE_API_KEY:
        return "Brave"
    return None


def _welcome(update: Update) -> str:
    """رسالة الترحيب — مع تنبيه للمالك إذا لم يُفعَّل البحث داخل تيليجرام بعد."""
    return kb.welcome_text(_first_name(update), setup_hint=_is_admin(update) and not _search_provider())


def _format_duration(seconds: float) -> str:
    """تحويل المدة بالثواني إلى نص عربي مقروء."""
    minutes, _ = divmod(int(seconds), 60)
    hours, minutes = divmod(minutes, 60)
    days, hours = divmod(hours, 24)
    parts = []
    if days:
        parts.append(f"{days} يوم")
    if hours:
        parts.append(f"{hours} ساعة")
    parts.append(f"{minutes} دقيقة")
    return " و ".join(parts)


async def _answer(update: Update, text: str | None = None, *, alert: bool = False) -> None:
    """الرد على ضغطة الزر لإيقاف مؤشر التحميل (مع تجاهل الأزرار القديمة جداً)."""
    if update.callback_query:
        try:
            await update.callback_query.answer(text, show_alert=alert)
        except BadRequest:
            pass


def _register(update: Update) -> Callable[[tools.Action], str]:
    """دالة تحفظ بيانات أزرار التقرير وتُرجع رموزها القصيرة."""
    user_id = update.effective_user.id
    return lambda action: ACTIONS.put(user_id, action)


async def _send(update: Update, context: ContextTypes.DEFAULT_TYPE, text: str, markup=None) -> Message:
    """إرسال رسالة جديدة في نفس المحادثة."""
    return await context.bot.send_message(update.effective_chat.id, text, reply_markup=markup)


async def _show(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    text: str,
    markup: InlineKeyboardMarkup | None,
    *,
    edit: bool = True,
) -> Message:
    """عرض شاشة: تعديل رسالة الزر الحالية إن أمكن، وإلا إرسال رسالة جديدة."""
    query = update.callback_query
    if edit and query and isinstance(query.message, Message):
        try:
            result = await query.message.edit_text(text, reply_markup=markup)
            return result if isinstance(result, Message) else query.message
        except BadRequest as exc:
            if "not modified" in str(exc).lower():
                return query.message
            logger.debug("تعذّر تعديل الرسالة، سيتم إرسال رسالة جديدة: %s", exc)
    return await context.bot.send_message(update.effective_chat.id, text, reply_markup=markup)


async def _clear_prompt_keyboard(context: ContextTypes.DEFAULT_TYPE, chat_id: int) -> None:
    """إزالة زر «رجوع» من رسالة طلب الإدخال بعد أن يرسل المستخدم الهدف."""
    message_id = context.user_data.pop("prompt_message_id", None)
    if message_id:
        try:
            await context.bot.edit_message_reply_markup(chat_id, message_id, reply_markup=None)
        except TelegramError:
            pass


def admin_only(func: Handler) -> Handler:
    """مُزخرف يقصر الأمر على المالك/المشرفين المحددين في config.py."""

    @wraps(func)
    async def wrapper(update: Update, context: ContextTypes.DEFAULT_TYPE) -> object:
        user = update.effective_user
        if user is None or user.id not in config.ADMIN_IDS:
            if update.effective_message:
                await update.effective_message.reply_text(kb.ADMIN_ONLY_TEXT)
            return None
        return await func(update, context)

    return wrapper


# ═══════════════════════════════════════════════════════════
# 🏠 القائمة الرئيسية والتنقل
# ═══════════════════════════════════════════════════════════


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """/start — عرض القائمة الرئيسية."""
    _register_user(update, context)
    context.user_data.pop("category", None)
    await _clear_prompt_keyboard(context, update.effective_chat.id)
    await update.effective_message.reply_text(
        _welcome(update), reply_markup=kb.main_menu_keyboard()
    )
    return ConversationHandler.END


async def back_to_main(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """🔙 رجوع للقائمة الرئيسية (بتعديل الرسالة، أو برسالة جديدة من شاشة النتائج)."""
    await _answer(update)
    _register_user(update, context)
    context.user_data.pop("category", None)
    edit = update.callback_query.data == kb.CB_BACK
    if not edit:
        await _clear_prompt_keyboard(context, update.effective_chat.id)
    await _show(update, context, _welcome(update), kb.main_menu_keyboard(), edit=edit)
    return ConversationHandler.END


async def choose_category(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """اختيار قسم ← طلب إدخال الهدف من المستخدم."""
    await _answer(update)
    _register_user(update, context)
    action, _, category = update.callback_query.data.partition(":")
    if category not in kb.CATEGORIES:
        return ConversationHandler.END

    # عند «🔁 بحث جديد» نرسل رسالة جديدة حتى تبقى النتائج السابقة ظاهرة
    edit = action == kb.CB_CATEGORY
    if not edit:
        await _clear_prompt_keyboard(context, update.effective_chat.id)
    message = await _show(update, context, kb.CATEGORIES[category]["prompt"], kb.back_keyboard(), edit=edit)
    context.user_data["category"] = category
    context.user_data["prompt_message_id"] = message.message_id
    return WAITING_INPUT


async def show_guide(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """📚 دليل المصادر."""
    await _answer(update)
    context.user_data.pop("category", None)
    await _show(update, context, kb.GUIDE_TEXT, kb.guide_keyboard())
    return ConversationHandler.END


async def show_adv_menu(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """🕵️ البحث المتقدم ← اختيار المنصة: TikTok / Instagram / تويتر."""
    await _answer(update)
    context.user_data.pop("category", None)
    await _show(update, context, kb.ADV_MENU_TEXT, kb.adv_menu_keyboard())
    return ConversationHandler.END


async def show_dorks_cheatsheet(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """📝 ورقة أوامر Google Dorks."""
    await _answer(update)
    await _show(update, context, kb.DORKS_CHEATSHEET_TEXT, kb.dorks_keyboard())


async def unknown_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """أي زر قديم أو غير معروف — نكتفي بإيقاف مؤشر التحميل."""
    await _answer(update)


# ═══════════════════════════════════════════════════════════
# 🔎 استقبال الهدف وتنفيذ البحث
# ═══════════════════════════════════════════════════════════


async def receive_query(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """استقبال نص المستخدم بعد اختيار قسم من القائمة ← تنفيذ البحث."""
    message = update.effective_message
    category = context.user_data.get("category")
    if category not in kb.CATEGORIES:
        await message.reply_text(kb.CHOOSE_FIRST_TEXT, reply_markup=kb.main_menu_keyboard())
        return ConversationHandler.END
    # رابط مقطع من TikTok/Instagram/X في أي قسم ← نحمّله مباشرة (هذا غالباً ما يريده المستخدم)
    if category != "media" and media.is_media_post_url(message.text or ""):
        category = "media"
    return await _run_category(update, context, category, message.text or "")


# ⚡ أوامر مباشرة: «/docs احمد محمد» ينفّذ البحث فوراً بدون المرور بالقائمة
COMMAND_CATEGORIES: dict[str, str] = {
    "dl": "media", "account": "accounts", "tiktok": "acc_tiktok", "insta": "acc_insta", "x": "acc_x",
    "dork": "dorks", "dorks": "dorks", "docs": "docs", "social": "social", "domain": "domain",
    "ip": "ip", "phone": "phone", "user": "user", "email": "email", "leaks": "leaks", "leak": "leaks",
}


async def category_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """أمر قسم: مع هدف ← بحث فوري، وبدون هدف ← طلب الهدف من المستخدم."""
    _register_user(update, context)
    message = update.effective_message
    parts = (message.text or "").split(maxsplit=1)
    command = parts[0].lstrip("/").split("@")[0].lower() if parts else ""
    category = COMMAND_CATEGORIES.get(command)
    if category is None:
        return ConversationHandler.END
    await _clear_prompt_keyboard(context, message.chat_id)
    argument = parts[1].strip() if len(parts) > 1 else ""
    if not argument:
        prompt = await message.reply_text(kb.CATEGORIES[category]["prompt"], reply_markup=kb.back_keyboard())
        context.user_data["category"] = category
        context.user_data["prompt_message_id"] = prompt.message_id
        return WAITING_INPUT
    return await _run_category(update, context, category, argument)


async def _run_category(update: Update, context: ContextTypes.DEFAULT_TYPE, category: str, text: str) -> int:
    """تنفيذ بحث قسم معيّن وعرض التقرير مع أزرار النتائج داخل تيليجرام."""
    message = update.effective_message
    context.user_data["category"] = category

    # ⏳ حماية من الإغراق: فترة انتظار بين عمليات البحث
    now = time.time()
    remaining = config.COOLDOWN_SECONDS - (now - context.user_data.get("last_lookup", 0.0))
    if remaining > 0:
        await message.reply_text(kb.cooldown_text(remaining))
        return WAITING_INPUT
    context.user_data["last_lookup"] = now

    await _clear_prompt_keyboard(context, message.chat_id)
    try:
        await context.bot.send_chat_action(message.chat_id, ChatAction.TYPING)
    except TelegramError:
        pass
    status = await message.reply_text(kb.SEARCHING_TEXT)

    try:
        result = await asyncio.wait_for(tools.run_lookup(category, text), timeout=config.LOOKUP_TIMEOUT)
    except tools.InvalidInput as exc:
        # إدخال غير صالح: نبقى في نفس القسم وننتظر إدخالاً جديداً
        context.user_data["last_lookup"] = 0.0
        await status.edit_text(f"{exc}\n\n{kb.RETRY_HINT}", reply_markup=kb.back_keyboard())
        context.user_data["prompt_message_id"] = status.message_id
        return WAITING_INPUT
    except asyncio.TimeoutError:
        logger.warning("⏱️ انتهت مهلة البحث في قسم %s", category)
        await status.edit_text(kb.TIMEOUT_TEXT, reply_markup=kb.error_keyboard(category))
        context.user_data.pop("category", None)
        return ConversationHandler.END
    except Exception:  # noqa: BLE001 — لا نسمح لأي خطأ بإيقاف المحادثة
        logger.exception("⚠️ خطأ أثناء البحث في قسم %s", category)
        await status.edit_text(kb.GENERIC_ERROR_TEXT, reply_markup=kb.error_keyboard(category))
        context.user_data.pop("category", None)
        return ConversationHandler.END

    _record_search(context, category)
    context.user_data.pop("category", None)
    try:
        await status.edit_text(
            result.text, reply_markup=kb.results_keyboard(result.actions, category, _register(update))
        )
    except BadRequest as exc:
        # احتياط: إذا رفض تيليجرام أحد الروابط، نعرض التقرير بدون أزرار الروابط
        logger.warning("تعذّر عرض أزرار النتائج: %s", exc)
        await status.edit_text(
            result.text + kb.BUTTONS_FALLBACK_NOTE, reply_markup=kb.error_keyboard(category)
        )

    # ▶️ تنفيذ تلقائي (Dork مخصص، أو نتائج الوثائق مباشرة) — النتائج في رسالة تالية.
    # البحث التلقائي الاختياري لا يُنفَّذ إلا إذا كان مفتاح البحث مفعّلاً، حتى لا تتكرر رسالة التفعيل.
    if result.autorun is not None and (not result.autorun_needs_key or _search_provider()):
        handler = ACTION_HANDLERS.get(result.autorun.kind)
        if handler is not None:
            context.user_data["last_action"] = time.time()
            try:
                await handler(update, context, result.autorun)
            except Exception:  # noqa: BLE001 — لا نسمح لأي خطأ بإيقاف المحادثة
                logger.exception("⚠️ خطأ أثناء التنفيذ التلقائي")
                with contextlib.suppress(TelegramError):
                    await _send(update, context, kb.ACTION_ERROR_TEXT)
    return ConversationHandler.END


async def non_text_input(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """المستخدم أرسل صورة/ملصق/ملف بدل النص أثناء انتظار الإدخال."""
    await update.effective_message.reply_text(kb.TEXT_ONLY_TEXT, reply_markup=kb.back_keyboard())
    return WAITING_INPUT


async def cancel(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """/cancel — إلغاء العملية الحالية."""
    context.user_data.pop("category", None)
    await _clear_prompt_keyboard(context, update.effective_chat.id)
    await update.effective_message.reply_text(kb.CANCELLED_TEXT, reply_markup=kb.main_menu_keyboard())
    return ConversationHandler.END


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/help — طريقة الاستخدام."""
    _register_user(update, context)
    is_admin = bool(update.effective_user and update.effective_user.id in config.ADMIN_IDS)
    await update.effective_message.reply_text(
        kb.help_text(is_admin, _search_provider(), bool(config.INSTAGRAM_SESSIONID)), reply_markup=kb.home_keyboard()
    )


async def fallback_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """نص عادي خارج أي قسم: رابط مقطع ← تحميل، رابط حساب ← معلومات الحساب، غير ذلك ← القائمة."""
    _register_user(update, context)
    text = update.effective_message.text or ""
    if media.find_media_url(text):
        category = "media" if media.is_media_post_url(text) else "accounts"
        await _run_category(update, context, category, text)
        return
    await update.effective_message.reply_text(kb.CHOOSE_FIRST_TEXT, reply_markup=kb.main_menu_keyboard())


# ═══════════════════════════════════════════════════════════
# 🔘 أزرار النتائج — كل النتائج تُعرض داخل تيليجرام
# ═══════════════════════════════════════════════════════════

ActionHandler = Callable[[Update, ContextTypes.DEFAULT_TYPE, tools.Action], Awaitable[None]]


async def action_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """تنفيذ زر من أزرار التقرير وعرض نتيجته في المحادثة."""
    user_id = update.effective_user.id
    action = ACTIONS.get(update.callback_query.data.partition(":")[2], user_id)
    if not isinstance(action, tools.Action):
        await _answer(update, kb.ACTION_EXPIRED_TEXT, alert=True)
        return

    # ⏳ حماية من الضغط المتكرر (يحمي أيضاً رصيد مفتاح البحث)
    now = time.time()
    remaining = config.ACTION_COOLDOWN_SECONDS - (now - context.user_data.get("last_action", 0.0))
    if remaining > 0:
        await _answer(update, kb.cooldown_text(remaining))
        return
    context.user_data["last_action"] = now

    await _answer(update)
    handler = ACTION_HANDLERS.get(action.kind)
    if handler is None:
        return
    try:
        await handler(update, context, action)
    except Exception:  # noqa: BLE001 — لا نسمح لأي خطأ في زر بإيقاف البوت
        logger.exception("⚠️ خطأ أثناء تنفيذ زر من نوع %s", action.kind)
        with contextlib.suppress(TelegramError):
            await _send(update, context, kb.ACTION_ERROR_TEXT)


async def _action_search(update: Update, context: ContextTypes.DEFAULT_TYPE, action: tools.Action) -> None:
    """🔎 بحث Google Dork وعرض النتائج كصفحات داخل تيليجرام."""
    status = await _send(update, context, kb.searching_web_text(html.escape(action.label)))
    try:
        outcome = await asyncio.wait_for(tools.web_search(action.value), timeout=40)
    except asyncio.TimeoutError:
        outcome = tools.SearchOutcome([], error="failed")
    entry = {"title": action.label, "query": action.value, "outcome": outcome, "docs": "docs" in action.extra}
    token = ACTIONS.put(update.effective_user.id, entry)
    await _render_search_page(status, update.effective_user.id, token, entry, 0)


async def _render_search_page(message: Message, user_id: int, token: str, entry: dict, page: int) -> None:
    """عرض صفحة من نتائج البحث مع أزرار التحميل والتنقل."""
    # إرشادات تفعيل البحث تظهر للمالك فقط، وبقية المستخدمين يرون رسالة مختصرة
    result = tools.format_search_page(
        entry["title"], entry["query"], entry["outcome"], page,
        show_setup_hint=user_id in config.ADMIN_IDS,
    )
    downloads = []
    if entry["docs"]:
        for number, item in result.items:
            if tools.downloadable_ext(item["url"]):
                downloads.append((number, ACTIONS.put(user_id, tools.Action("📥", "download", item["url"]))))
    markup = kb.search_page_keyboard(token, result.page, result.pages, downloads)
    try:
        await message.edit_text(result.text, reply_markup=markup)
    except BadRequest as exc:
        if "not modified" not in str(exc).lower():
            raise


async def page_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """التنقل بين صفحات نتائج البحث (بتعديل نفس الرسالة)."""
    query = update.callback_query
    _, token, page = query.data.split(":")
    entry = ACTIONS.get(token, update.effective_user.id)
    if not isinstance(entry, dict) or not isinstance(query.message, Message):
        await _answer(update, kb.ACTION_EXPIRED_TEXT, alert=True)
        return
    await _answer(update)
    await _render_search_page(query.message, update.effective_user.id, token, entry, int(page))


async def _action_subdomains(update: Update, context: ContextTypes.DEFAULT_TYPE, action: tools.Action) -> None:
    """🌿 النطاقات الفرعية (crt.sh / HackerTarget)."""
    status = await _send(update, context, kb.SUBDOMAINS_WAIT_TEXT)
    try:
        text = await asyncio.wait_for(tools.subdomains_report(action.value), timeout=60)
    except asyncio.TimeoutError:
        text = kb.ACTION_ERROR_TEXT
    await status.edit_text(text)


async def _action_urlscan(update: Update, context: ContextTypes.DEFAULT_TYPE, action: tools.Action) -> None:
    """🔬 آخر فحوصات urlscan.io + لقطة شاشة للموقع داخل المحادثة."""
    status = await _send(update, context, kb.URLSCAN_WAIT_TEXT)
    try:
        text, screenshot = await asyncio.wait_for(tools.urlscan_report(action.value), timeout=30)
    except asyncio.TimeoutError:
        text, screenshot = kb.ACTION_ERROR_TEXT, None
    await status.edit_text(text)
    if screenshot:
        with contextlib.suppress(TelegramError):
            await context.bot.send_photo(
                update.effective_chat.id,
                screenshot,
                caption=f"📸 آخر لقطة شاشة لـ <code>{html.escape(action.value)}</code> (urlscan.io)",
            )


async def _action_map(update: Update, context: ContextTypes.DEFAULT_TYPE, action: tools.Action) -> None:
    """🗺️ إرسال الموقع التقريبي كخريطة داخل تيليجرام."""
    latitude, longitude, title, address = action.extra
    await context.bot.send_venue(
        update.effective_chat.id, latitude=latitude, longitude=longitude, title=title, address=address
    )


async def _action_photo(update: Update, context: ContextTypes.DEFAULT_TYPE, action: tools.Action) -> None:
    """🖼️ إرسال صورة داخل المحادثة (مثل صورة Gravatar)."""
    caption = html.escape(action.extra[0]) if action.extra else None
    try:
        await context.bot.send_photo(update.effective_chat.id, action.value, caption=caption)
    except TelegramError:
        await _send(update, context, kb.PHOTO_FAILED_TEXT)


async def _action_lookup(update: Update, context: ContextTypes.DEFAULT_TYPE, action: tools.Action) -> None:
    """🌐 فتح تقرير من قسم آخر مباشرة (مثل تقرير IP خادم الدومين)."""
    category = action.extra[0]
    status = await _send(update, context, kb.SEARCHING_TEXT)
    try:
        result = await asyncio.wait_for(tools.run_lookup(category, action.value), timeout=config.LOOKUP_TIMEOUT)
    except tools.InvalidInput as exc:
        await status.edit_text(str(exc))
        return
    except asyncio.TimeoutError:
        await status.edit_text(kb.TIMEOUT_TEXT)
        return
    _record_search(context, category)
    await status.edit_text(
        result.text, reply_markup=kb.results_keyboard(result.actions, category, _register(update))
    )


async def _action_wmn(update: Update, context: ContextTypes.DEFAULT_TYPE, action: tools.Action) -> None:
    """🧭 فحص اليوزر في أكثر من 600 موقع (WhatsMyName) مع شريط تقدم."""
    user_id = update.effective_user.id
    if user_id in WMN_RUNNING:
        await _send(update, context, kb.WMN_BUSY_TEXT)
        return
    WMN_RUNNING.add(user_id)
    try:
        username = action.value
        status = await _send(update, context, kb.wmn_progress_text(username, 0, 0))
        last_edit = time.monotonic()

        async def progress(done: int, total: int) -> None:
            nonlocal last_edit
            if time.monotonic() - last_edit < 4:
                return
            last_edit = time.monotonic()
            with contextlib.suppress(TelegramError):
                await status.edit_text(kb.wmn_progress_text(username, done, total))

        try:
            hits, checked, total = await tools.wmn_scan(username, progress)
        except tools.InvalidInput as exc:
            await status.edit_text(str(exc))
            return
        chunks = tools.split_message(tools.format_wmn(username, hits, checked, total))
        await status.edit_text(chunks[0])
        for chunk in chunks[1:]:
            await _send(update, context, chunk)
    finally:
        WMN_RUNNING.discard(user_id)


async def _action_download(update: Update, context: ContextTypes.DEFAULT_TYPE, action: tools.Action) -> None:
    """📥 إرسال الملف نفسه داخل المحادثة."""
    url = action.value
    chat_id = update.effective_chat.id
    status = await _send(update, context, kb.DOWNLOAD_WAIT_TEXT)
    with contextlib.suppress(TelegramError):
        await context.bot.send_chat_action(chat_id, ChatAction.UPLOAD_DOCUMENT)
    caption = f"📄 {html.escape(url[:200])}"

    # 1) تيليجرام يحمّل الملف بنفسه من الرابط (يعمل مع PDF و ZIP)
    try:
        await context.bot.send_document(chat_id, document=url, caption=caption)
    except TelegramError:
        # 2) نحمّله نحن (مع حدود الحجم والأمان) ثم نرفعه
        try:
            data, filename = await asyncio.wait_for(tools.download_file(url), timeout=60)
            await context.bot.send_document(chat_id, document=data, filename=filename, caption=caption)
        except tools.InvalidInput as exc:
            error_text = str(exc)
        except Exception as exc:  # noqa: BLE001 — أخطاء الشبكة أو الرفع
            logger.warning("📥 تعذّر إرسال ملف: %s", exc.__class__.__name__)
            error_text = kb.DOWNLOAD_FAILED_TEXT
        else:
            error_text = None
        if error_text:
            await status.edit_text(error_text, reply_markup=kb.open_link_keyboard(url))
            return
    with contextlib.suppress(TelegramError):
        await status.delete()


async def _send_single_media(
    context: ContextTypes.DEFAULT_TYPE,
    chat_id: int,
    item: media.MediaItem,
    caption: str | None,
    markup: InlineKeyboardMarkup | None = None,
) -> bool:
    """إرسال مقطع أو صورة واحدة: ملف محلي، أو رابط يحمّله تيليجرام، أو نحمّله نحن ثم نرفعه."""
    try:
        if item.path:
            data, filename = Path(item.path).read_bytes(), Path(item.path).name
            if item.kind == "video":
                # الأبعاد والمدة والصورة المصغّرة تمنع ظهور المقطع متجمداً أو بمقاس خاطئ
                thumbnail = Path(item.thumb).read_bytes() if item.thumb else None
                await context.bot.send_video(
                    chat_id, data, filename=filename, caption=caption, supports_streaming=True,
                    duration=item.duration, width=item.width, height=item.height, thumbnail=thumbnail,
                    reply_markup=markup, **_UPLOAD_TIMEOUTS,
                )
            else:
                await context.bot.send_photo(
                    chat_id, data, filename=filename, caption=caption, reply_markup=markup, **_UPLOAD_TIMEOUTS
                )
            return True
        if item.kind == "video":
            await context.bot.send_video(
                chat_id, item.url, caption=caption, supports_streaming=True, reply_markup=markup, **_UPLOAD_TIMEOUTS
            )
        else:
            await context.bot.send_photo(chat_id, item.url, caption=caption, reply_markup=markup, **_UPLOAD_TIMEOUTS)
        return True
    except TelegramError as exc:
        logger.info("📤 تيليجرام لم يقبل الوسائط مباشرة: %s", exc)
    if not item.url:
        return False
    # تيليجرام يحمّل من الروابط حتى 20 ميغابايت فقط — للأكبر نحمّله نحن (حتى 49) ثم نرفعه
    try:
        data, filename = await tools.download_file(item.url, max_mb=49)
        if item.kind == "video":
            await context.bot.send_video(
                chat_id, data, filename=filename if "." in filename else "video.mp4", caption=caption,
                supports_streaming=True, duration=item.duration, reply_markup=markup, **_UPLOAD_TIMEOUTS,
            )
        else:
            await context.bot.send_photo(
                chat_id, data, filename="photo.jpg", caption=caption, reply_markup=markup, **_UPLOAD_TIMEOUTS
            )
        return True
    except Exception as exc:  # noqa: BLE001 — أخطاء الشبكة أو الرفع
        logger.warning("📤 تعذّر رفع الوسائط: %s", exc.__class__.__name__)
        return False


def _audio_markup(update: Update, result: media.MediaResult) -> InlineKeyboardMarkup | None:
    """زر «🎵 الصوت MP3» تحت المقطع (للمنشورات التي تحتوي فيديو)."""
    if not result.source_url or not any(i.kind == "video" for i in result.items):
        return None
    token = ACTIONS.put(update.effective_user.id, tools.Action("🎵", "audio", result.source_url))
    return InlineKeyboardMarkup([[InlineKeyboardButton("🎵 تحميل الصوت MP3", callback_data=f"{kb.CB_ACTION}:{token}")]])


async def _send_post_music(update: Update, context: ContextTypes.DEFAULT_TYPE, result: media.MediaResult) -> None:
    """🎵 موسيقى منشور صور TikTok تُرسل كملف صوتي بعد الصور."""
    if not result.audio_url:
        return
    try:
        data, filename = await tools.download_file(result.audio_url, max_mb=30)
        await context.bot.send_audio(
            update.effective_chat.id, data, filename=filename if "." in filename else "music.mp3",
            title=result.audio_title, performer=result.audio_performer, **_UPLOAD_TIMEOUTS,
        )
    except Exception as exc:  # noqa: BLE001 — الموسيقى إضافة اختيارية
        logger.info("🎵 تعذّر إرسال موسيقى المنشور: %s", exc.__class__.__name__)


async def _send_media(update: Update, context: ContextTypes.DEFAULT_TYPE, result: media.MediaResult) -> bool:
    """إرسال نتيجة التحميل: مقطع واحد، أو ألبوم (حتى 10 صور/مقاطع)."""
    chat_id = update.effective_chat.id
    items = result.items[:10]
    markup = _audio_markup(update, result)
    if len(items) == 1:
        sent = await _send_single_media(context, chat_id, items[0], result.caption, markup)
        if sent:
            await _send_post_music(update, context, result)
        return sent
    album = []
    for index, item in enumerate(items):
        source = Path(item.path).read_bytes() if item.path else item.url
        caption = result.caption if index == 0 else None
        if item.kind == "video":
            album.append(InputMediaVideo(
                source, caption=caption, supports_streaming=True, width=item.width, height=item.height,
                duration=item.duration, thumbnail=Path(item.thumb).read_bytes() if item.thumb else None,
            ))
        else:
            album.append(InputMediaPhoto(source, caption=caption))
    sent = False
    try:
        await context.bot.send_media_group(chat_id, album, **_UPLOAD_TIMEOUTS)
        sent = True
    except TelegramError as exc:
        logger.info("📤 تعذّر إرسال الألبوم، سيتم الإرسال واحداً واحداً: %s", exc)
        for index, item in enumerate(items):
            sent = await _send_single_media(context, chat_id, item, result.caption if index == 0 else None) or sent
    if sent:
        await _send_post_music(update, context, result)
        if markup:  # الألبوم لا يقبل أزراراً — نرسل زر الصوت في رسالة صغيرة
            with contextlib.suppress(TelegramError):
                await context.bot.send_message(chat_id, "🎵 تبي صوت المقطع؟", reply_markup=markup)
    return sent


async def _action_audio(update: Update, context: ContextTypes.DEFAULT_TYPE, action: tools.Action) -> None:
    """🎵 استخراج صوت المنشور كملف MP3 بجودة عالية وإرساله داخل المحادثة."""
    user_id = update.effective_user.id
    if user_id in DOWNLOADS_RUNNING:
        await _send(update, context, kb.MEDIA_BUSY_TEXT)
        return
    DOWNLOADS_RUNNING.add(user_id)
    audio: media.AudioResult | None = None
    try:
        status = await _send(update, context, kb.AUDIO_WAIT_TEXT)
        with contextlib.suppress(TelegramError):
            await context.bot.send_chat_action(update.effective_chat.id, ChatAction.UPLOAD_VOICE)
        try:
            async with DOWNLOAD_SLOTS:
                audio = await asyncio.wait_for(media.extract_audio(action.value), timeout=240)
        except tools.InvalidInput as exc:
            await status.edit_text(str(exc))
            return
        except asyncio.TimeoutError:
            await status.edit_text(kb.TIMEOUT_TEXT)
            return
        try:
            await context.bot.send_audio(
                update.effective_chat.id, Path(audio.path).read_bytes(), filename="audio.mp3",
                title=audio.title, performer=audio.performer, duration=audio.duration, **_UPLOAD_TIMEOUTS,
            )
            with contextlib.suppress(TelegramError):
                await status.delete()
        except TelegramError as exc:
            logger.warning("🎵 تعذّر إرسال الصوت: %s", exc)
            await status.edit_text(kb.AUDIO_FAILED_TEXT)
    finally:
        DOWNLOADS_RUNNING.discard(user_id)
        if audio is not None:
            audio.cleanup()


async def _action_media(update: Update, context: ContextTypes.DEFAULT_TYPE, action: tools.Action) -> None:
    """📥 تحميل مقطع/صور من TikTok أو Instagram أو X وإرسالها داخل المحادثة."""
    user_id = update.effective_user.id
    if user_id in DOWNLOADS_RUNNING:
        await _send(update, context, kb.MEDIA_BUSY_TEXT)
        return
    DOWNLOADS_RUNNING.add(user_id)
    result: media.MediaResult | None = None
    try:
        status = await _send(update, context, kb.MEDIA_WAIT_TEXT)
        with contextlib.suppress(TelegramError):
            await context.bot.send_chat_action(update.effective_chat.id, ChatAction.UPLOAD_VIDEO)
        try:
            async with DOWNLOAD_SLOTS:
                result = await asyncio.wait_for(media.download_media(action.value), timeout=240)
        except tools.InvalidInput as exc:
            await status.edit_text(str(exc))
            return
        except asyncio.TimeoutError:
            await status.edit_text(kb.TIMEOUT_TEXT)
            return
        if await _send_media(update, context, result):
            with contextlib.suppress(TelegramError):
                await status.delete()
        else:
            await status.edit_text(kb.MEDIA_SEND_FAILED_TEXT)
    finally:
        DOWNLOADS_RUNNING.discard(user_id)
        if result is not None:
            result.cleanup()


async def _action_tt_videos(update: Update, context: ContextTypes.DEFAULT_TYPE, action: tools.Action) -> None:
    """🎬 آخر فيديوهات حساب TikTok مع زر تحميل لكل فيديو."""
    status = await _send(update, context, kb.TT_VIDEOS_WAIT_TEXT)
    videos = await media.tiktok_latest_videos(action.value)
    user_id = update.effective_user.id
    buttons = [(n, ACTIONS.put(user_id, tools.Action("📥", "media", v["url"]))) for n, v in enumerate(videos, 1)]
    markup = kb.search_page_keyboard("-", 0, 1, buttons) if buttons else None
    await status.edit_text(media.format_tiktok_videos(action.value, videos), reply_markup=markup)


ACTION_HANDLERS: dict[str, ActionHandler] = {
    "media": _action_media,
    "audio": _action_audio,
    "tt_videos": _action_tt_videos,
    "search": _action_search,
    "subdomains": _action_subdomains,
    "urlscan": _action_urlscan,
    "map": _action_map,
    "photo": _action_photo,
    "lookup": _action_lookup,
    "wmn": _action_wmn,
    "download": _action_download,
}


# ═══════════════════════════════════════════════════════════
# 👑 أوامر المالك
# ═══════════════════════════════════════════════════════════


@admin_only
async def stats_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/stats — إحصائيات البوت."""
    users = context.bot_data.get("users", set())
    stats = context.bot_data.get("stats", {})
    await update.effective_message.reply_text(
        kb.stats_text(len(users), stats, _format_duration(time.time() - START_TIME))
    )


@admin_only
async def broadcast_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """/broadcast — رسالة جماعية (نص بعد الأمر، أو الرد على رسالة لإعادة إرسالها كما هي)."""
    message = update.effective_message
    source = message.reply_to_message
    text = re.sub(r"^/broadcast(@\w+)?\s*", "", message.text or "", count=1).strip()
    if source is None and not text:
        await message.reply_text(kb.BROADCAST_USAGE_TEXT)
        return

    users = list(context.bot_data.get("users", set()))
    status = await message.reply_text(kb.broadcast_progress_text(0, len(users)))
    # الإرسال في الخلفية حتى لا يتوقف البوت عن الرد على المستخدمين أثناءه
    context.application.create_task(
        _run_broadcast(context, users, status, message.chat_id, source.message_id if source else None, text),
        update=update,
    )


async def _run_broadcast(
    context: ContextTypes.DEFAULT_TYPE,
    users: list[int],
    status: Message,
    from_chat_id: int,
    source_message_id: int | None,
    text: str,
) -> None:
    """تنفيذ الرسالة الجماعية مع احترام حدود تيليجرام وحذف من حظر البوت."""
    sent = failed = 0
    blocked: set[int] = set()

    async def deliver(user_id: int) -> None:
        if source_message_id is not None:
            await context.bot.copy_message(user_id, from_chat_id, source_message_id)
        else:
            # نص عادي بدون تنسيق لتجنب أخطاء HTML في نص المالك
            await context.bot.send_message(user_id, text, parse_mode=None)

    for index, user_id in enumerate(users, 1):
        try:
            try:
                await deliver(user_id)
            except RetryAfter as exc:
                delay = exc.retry_after
                await asyncio.sleep((delay.total_seconds() if hasattr(delay, "total_seconds") else delay) + 1)
                await deliver(user_id)
            sent += 1
        except Forbidden:
            blocked.add(user_id)
            failed += 1
        except TelegramError as exc:
            # لا نسجّل معرّف المستخدم: سجلات GitHub Actions علنية في المستودعات العامة
            logger.warning("فشل إرسال رسالة جماعية لأحد المستخدمين: %s", exc.__class__.__name__)
            failed += 1
        await asyncio.sleep(0.05)  # ≈ 20 رسالة/ثانية — ضمن حدود تيليجرام
        if index % 25 == 0:
            try:
                await status.edit_text(kb.broadcast_progress_text(index, len(users)))
            except TelegramError:
                pass

    if blocked:
        context.bot_data.setdefault("users", set()).difference_update(blocked)
    try:
        await status.edit_text(kb.broadcast_done_text(sent, failed, len(blocked)))
    except TelegramError:
        pass


# ═══════════════════════════════════════════════════════════
# 🚨 معالجة الأخطاء العامة
# ═══════════════════════════════════════════════════════════


async def error_handler(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    """تسجيل أي خطأ غير متوقع وإبلاغ المستخدم بلطف بدل توقف البوت."""
    logger.error("⚠️ خطأ غير متوقع أثناء معالجة التحديث", exc_info=context.error)
    if isinstance(update, Update) and update.effective_message:
        try:
            await update.effective_message.reply_text(kb.GENERIC_ERROR_TEXT)
        except TelegramError:
            pass


# ═══════════════════════════════════════════════════════════
# 🚀 التهيئة والتشغيل
# ═══════════════════════════════════════════════════════════


async def post_init(application: Application) -> None:
    """يُنفَّذ بعد الاتصال بتيليجرام: تهيئة البيانات وتسجيل قائمة الأوامر."""
    application.bot_data.setdefault("users", set())
    application.bot_data.setdefault("stats", {"total": 0, "by_category": {}})

    commands = [
        BotCommand("start", "🏠 القائمة الرئيسية"),
        BotCommand("tiktok", "🎵 معلومات حساب TikTok — مثال: /tiktok khaby.lame"),
        BotCommand("insta", "📸 معلومات حساب Instagram — مثال: /insta instagram"),
        BotCommand("x", "𝕏 معلومات حساب X — مثال: /x NASA"),
        BotCommand("account", "📊 الحساب على TikTok و Instagram و X معاً"),
        BotCommand("dork", "🔎 Google Dorks — مثال: /dork اسم أو دومين"),
        BotCommand("docs", "📄 وثائق وملفات — مثال: /docs احمد محمد"),
        BotCommand("social", "🕵️ X و Instagram و TikTok — مثال: /social @user"),
        BotCommand("domain", "🌐 فحص دومين — مثال: /domain example.com"),
        BotCommand("ip", "🌐 فحص IP — مثال: /ip 8.8.8.8"),
        BotCommand("phone", "📞 تحليل رقم — مثال: /phone +966501234567"),
        BotCommand("user", "👤 فحص يوزر في +550 موقع — مثال: /user john"),
        BotCommand("email", "✉️ فحص إيميل — مثال: /email a@b.com"),
        BotCommand("leaks", "🔓 فحص التسريبات — إيميل/يوزر/هاتف/دومين"),
        BotCommand("help", "ℹ️ المساعدة وكل الأوامر"),
        BotCommand("cancel", "❌ إلغاء العملية الحالية"),
    ]
    admin_commands = commands + [
        BotCommand("stats", "📊 إحصائيات البوت"),
        BotCommand("broadcast", "📢 رسالة جماعية"),
    ]
    try:
        await application.bot.set_my_commands(commands)
    except TelegramError as exc:
        logger.warning("تعذّر تسجيل قائمة الأوامر: %s", exc)
    for admin_id in config.ADMIN_IDS:
        try:
            await application.bot.set_my_commands(admin_commands, scope=BotCommandScopeChat(admin_id))
        except TelegramError:
            # يحدث إذا لم يبدأ المالك محادثة مع البوت بعد — غير مهم
            pass
    logger.info("✅ البوت يعمل الآن: @%s", application.bot.username)


async def post_shutdown(application: Application) -> None:
    """إغلاق عميل HTTP عند إيقاف البوت."""
    await tools.close_client()
    logger.info("👋 تم إيقاف البوت.")


def build_application() -> Application:
    """إنشاء التطبيق وتسجيل جميع المعالجات."""
    config.PERSISTENCE_FILE.parent.mkdir(parents=True, exist_ok=True)
    persistence = PicklePersistence(filepath=config.PERSISTENCE_FILE, update_interval=30)
    defaults = Defaults(
        parse_mode=ParseMode.HTML,
        link_preview_options=LinkPreviewOptions(is_disabled=True),
    )
    application = (
        Application.builder()
        .token(config.BOT_TOKEN)
        .persistence(persistence)
        .defaults(defaults)
        .concurrent_updates(True)  # خدمة عدة مستخدمين في نفس الوقت
        .post_init(post_init)
        .post_shutdown(post_shutdown)
        .build()
    )

    categories = "|".join(map(re.escape, kb.CATEGORIES))
    category_pattern = rf"^(?:{kb.CB_CATEGORY}|{kb.CB_AGAIN}):(?:{categories})$"
    back_pattern = rf"^(?:{re.escape(kb.CB_BACK)}|{re.escape(kb.CB_HOME_NEW)})$"
    guide_pattern = rf"^{re.escape(kb.CB_GUIDE)}$"
    adv_pattern = rf"^{re.escape(kb.CB_ADV)}$"

    conversation = ConversationHandler(
        entry_points=[
            CallbackQueryHandler(choose_category, pattern=category_pattern),
            CommandHandler(list(COMMAND_CATEGORIES), category_command),
        ],
        states={
            WAITING_INPUT: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, receive_query),
                MessageHandler(~filters.TEXT & ~filters.COMMAND & ~filters.StatusUpdate.ALL, non_text_input),
            ],
        },
        fallbacks=[
            CallbackQueryHandler(back_to_main, pattern=back_pattern),
            CallbackQueryHandler(show_guide, pattern=guide_pattern),
            CallbackQueryHandler(show_adv_menu, pattern=adv_pattern),
            CommandHandler("cancel", cancel),
            CommandHandler("start", start),
        ],
        allow_reentry=True,  # يسمح بالانتقال لقسم آخر مباشرة
        name="osint_conversation",
        persistent=True,
    )

    application.add_handler(conversation)
    application.add_handler(CommandHandler("start", start))
    application.add_handler(CommandHandler("help", help_command))
    application.add_handler(CommandHandler("cancel", cancel))
    application.add_handler(CommandHandler("stats", stats_command))
    application.add_handler(CommandHandler("broadcast", broadcast_command))
    application.add_handler(CallbackQueryHandler(back_to_main, pattern=back_pattern))
    application.add_handler(CallbackQueryHandler(show_guide, pattern=guide_pattern))
    application.add_handler(CallbackQueryHandler(show_adv_menu, pattern=adv_pattern))
    application.add_handler(
        CallbackQueryHandler(show_dorks_cheatsheet, pattern=rf"^{re.escape(kb.CB_GUIDE_DORKS)}$")
    )
    application.add_handler(CallbackQueryHandler(action_callback, pattern=rf"^{kb.CB_ACTION}:[\w-]+$"))
    application.add_handler(CallbackQueryHandler(page_callback, pattern=rf"^{kb.CB_PAGE}:[\w-]+:\d+$"))
    application.add_handler(CallbackQueryHandler(unknown_callback))
    application.add_handler(MessageHandler(filters.TEXT & ~filters.COMMAND, fallback_text))
    application.add_error_handler(error_handler)
    return application


def main() -> None:
    if not config.BOT_TOKEN or ":" not in config.BOT_TOKEN:
        raise SystemExit(
            "❌ لم يتم ضبط توكن البوت!\n"
            "   انسخ ملف .env.example إلى .env ثم ضع التوكن بداخله:\n"
            "   BOT_TOKEN=123456789:ABCdef..."
        )
    application = build_application()
    logger.info("🚀 جاري تشغيل بوت OSINT...")
    # لا نحذف الرسائل المعلّقة: عند إعادة التشغيل الدورية على GitHub تُعالَج الرسائل
    # التي وصلت أثناء فترة التبديل بدل ضياعها
    application.run_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=False)


if __name__ == "__main__":
    main()
