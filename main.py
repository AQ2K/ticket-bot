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
import html
import logging
import re
import time
import warnings
from collections.abc import Awaitable, Callable
from functools import wraps

from telegram import BotCommand, BotCommandScopeChat, InlineKeyboardMarkup, LinkPreviewOptions, Message, Update
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


async def _answer(update: Update) -> None:
    """الرد على ضغطة الزر لإيقاف مؤشر التحميل (مع تجاهل الأزرار القديمة جداً)."""
    if update.callback_query:
        try:
            await update.callback_query.answer()
        except BadRequest:
            pass


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
        kb.welcome_text(_first_name(update)), reply_markup=kb.main_menu_keyboard()
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
    await _show(update, context, kb.welcome_text(_first_name(update)), kb.main_menu_keyboard(), edit=edit)
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
    """استقبال نص المستخدم ← تنفيذ البحث ← عرض التقرير مع أزرار الروابط."""
    message = update.effective_message
    category = context.user_data.get("category")
    if category not in kb.CATEGORIES:
        await message.reply_text(kb.CHOOSE_FIRST_TEXT, reply_markup=kb.main_menu_keyboard())
        return ConversationHandler.END

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
        result = await asyncio.wait_for(
            tools.run_lookup(category, message.text or ""), timeout=config.LOOKUP_TIMEOUT
        )
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
        await status.edit_text(result.text, reply_markup=kb.results_keyboard(result.links, category))
    except BadRequest as exc:
        # احتياط: إذا رفض تيليجرام أحد الروابط، نعرض التقرير بدون أزرار الروابط
        logger.warning("تعذّر عرض أزرار النتائج: %s", exc)
        await status.edit_text(
            result.text + kb.BUTTONS_FALLBACK_NOTE, reply_markup=kb.error_keyboard(category)
        )
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
    await update.effective_message.reply_text(kb.help_text(is_admin), reply_markup=kb.home_keyboard())


async def fallback_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """نص عادي خارج أي قسم — نذكّر المستخدم باختيار نوع البحث أولاً."""
    _register_user(update, context)
    await update.effective_message.reply_text(kb.CHOOSE_FIRST_TEXT, reply_markup=kb.main_menu_keyboard())


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
            logger.warning("فشل الإرسال إلى %s: %s", user_id, exc)
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
        BotCommand("help", "ℹ️ المساعدة"),
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

    conversation = ConversationHandler(
        entry_points=[CallbackQueryHandler(choose_category, pattern=category_pattern)],
        states={
            WAITING_INPUT: [
                MessageHandler(filters.TEXT & ~filters.COMMAND, receive_query),
                MessageHandler(~filters.TEXT & ~filters.COMMAND & ~filters.StatusUpdate.ALL, non_text_input),
            ],
        },
        fallbacks=[
            CallbackQueryHandler(back_to_main, pattern=back_pattern),
            CallbackQueryHandler(show_guide, pattern=guide_pattern),
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
    application.add_handler(
        CallbackQueryHandler(show_dorks_cheatsheet, pattern=rf"^{re.escape(kb.CB_GUIDE_DORKS)}$")
    )
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
    application.run_polling(allowed_updates=Update.ALL_TYPES, drop_pending_updates=True)


if __name__ == "__main__":
    main()
