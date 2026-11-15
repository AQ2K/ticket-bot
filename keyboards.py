"""
⌨️ واجهة المستخدم — لوحات المفاتيح والنصوص العربية
==================================================
يحتوي على:
  • بيانات الأقسام (العنوان + رسالة طلب الإدخال)
  • جميع لوحات الأزرار (InlineKeyboardMarkup)
  • منشئ أزرار الروابط الديناميكية لنتائج البحث
  • نصوص الرسائل الثابتة (الترحيب، المساعدة، الأخطاء، الدليل...)
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass

from telegram import InlineKeyboardButton as Btn
from telegram import InlineKeyboardMarkup

from osint_tools import Action


@dataclass(frozen=True)
class Link:
    """رابط خارجي ثابت (يُستخدم في دليل المصادر فقط)."""

    label: str
    url: str

# ═══════════════════════════════════════════════════════════
# 🔖 بيانات الأزرار (callback_data)
# ═══════════════════════════════════════════════════════════

CB_CATEGORY = "cat"  # cat:<قسم>   ← فتح قسم بتعديل نفس الرسالة
CB_AGAIN = "again"  # again:<قسم> ← بحث جديد برسالة جديدة (للحفاظ على النتائج السابقة)
CB_BACK = "back:main"  # رجوع للقائمة بتعديل نفس الرسالة
CB_HOME_NEW = "home:new"  # فتح القائمة برسالة جديدة
CB_GUIDE = "menu:guide"  # دليل المصادر
CB_GUIDE_DORKS = "guide:dorks"  # ورقة أوامر Google Dorks
CB_ACTION = "a"  # a:<رمز>        ← تنفيذ إجراء تُعرض نتيجته داخل تيليجرام
CB_PAGE = "p"  # p:<رمز>:<صفحة> ← التنقل بين صفحات نتائج البحث

# ═══════════════════════════════════════════════════════════
# 📂 الأقسام
# ═══════════════════════════════════════════════════════════

CATEGORIES: dict[str, dict[str, str]] = {
    "social": {
        "title": "🕵️ بحث متقدم (X / Instagram / TikTok)",
        "prompt": (
            "🕵️ <b>بحث متقدم — X / Instagram / TikTok</b>\n\n"
            "✍️ أرسل <b>اسم المستخدم</b> (مثل <code>@username</code>) أو <b>الاسم الكامل</b> "
            "أو أي كلمة مفتاحية.\n\n"
            "سأجهّز لك روابط بحث مباشرة (Google Dorks) على المنصات الثلاث."
        ),
    },
    "domain": {
        "title": "🌐 دومين",
        "prompt": (
            "🌐 <b>فحص الدومين</b>\n\n"
            "✍️ أرسل اسم النطاق، مثل: <code>example.com</code>\n\n"
            "سأجلب سجلات DNS وبيانات التسجيل (RDAP / WHOIS) ومعلومات الاستضافة "
            "مع روابط أدوات الفحص."
        ),
    },
    "ip": {
        "title": "🌐 IP",
        "prompt": (
            "🌐 <b>فحص عنوان IP</b>\n\n"
            "✍️ أرسل عنوان IPv4 أو IPv6، مثل: <code>8.8.8.8</code>\n"
            "💡 يمكنك أيضاً إرسال اسم نطاق وسأحوّله إلى IP تلقائياً.\n\n"
            "سأجلب الموقع الجغرافي التقريبي، مزود الخدمة، ASN و Reverse DNS."
        ),
    },
    "phone": {
        "title": "📞 هاتف",
        "prompt": (
            "📞 <b>تحليل رقم الهاتف</b>\n\n"
            "✍️ أرسل الرقم بالصيغة الدولية مع رمز الدولة، مثل:\n"
            "<code>+966501234567</code> أو <code>00201001234567</code>\n\n"
            "سأعرض الدولة ونوع الرقم والمشغّل الأصلي مع روابط بحث علنية."
        ),
    },
    "user": {
        "title": "👤 يوزر",
        "prompt": (
            "👤 <b>البحث عن اسم مستخدم</b>\n\n"
            "✍️ أرسل اسم المستخدم بدون مسافات، مثل: <code>john_doe</code>\n\n"
            "سأفحص وجوده على عدة منصات تلقائياً مع روابط مباشرة لباقي المنصات."
        ),
    },
    "docs": {
        "title": "🔗 رابط/ملف (Docs)",
        "prompt": (
            "🔗 <b>وثائق وملفات</b>\n\n"
            "✍️ أرسل <b>كلمة مفتاحية</b> أو اسماً أو موضوعاً للبحث عن الملفات المنشورة علناً "
            "(PDF / Word / Excel / PowerPoint).\n\n"
            "💡 لحصر البحث داخل موقع معيّن أرسل رابطه كاملاً، مثل: <code>https://example.com</code>"
        ),
    },
    "email": {
        "title": "✉️ إيميل",
        "prompt": (
            "✉️ <b>فحص البريد الإلكتروني</b>\n\n"
            "✍️ أرسل البريد الإلكتروني، مثل: <code>name@example.com</code>\n\n"
            "سأفحص نوع المزود وسجلات MX وحماية SPF/DMARC وصورة Gravatar "
            "مع روابط فحص التسريبات العلنية."
        ),
    },
}

# ═══════════════════════════════════════════════════════════
# 💬 النصوص الثابتة
# ═══════════════════════════════════════════════════════════

DISCLAIMER = "⚠️ <i>للاستخدام القانوني والأخلاقي فقط — يعتمد البوت حصراً على مصادر علنية.</i>"

SEARCHING_TEXT = "⏳ <b>جاري جمع المعلومات من المصادر العلنية...</b>\nقد يستغرق ذلك بضع ثوانٍ."

CHOOSE_FIRST_TEXT = "👇 اختر نوع البحث من القائمة أولاً، ثم أرسل الهدف المطلوب."

TEXT_ONLY_TEXT = "✍️ أرسل الهدف كنص فقط من فضلك (بدون صور أو ملفات)."

RETRY_HINT = "✍️ أرسل الهدف مرة أخرى بالصيغة الصحيحة، أو اضغط «🔙 رجوع»."

TIMEOUT_TEXT = (
    "⏱️ <b>انتهت مهلة البحث</b>\n\n"
    "بعض المصادر العلنية بطيئة حالياً. حاول مرة أخرى بعد قليل."
)

GENERIC_ERROR_TEXT = (
    "⚠️ <b>حدث خطأ غير متوقع</b>\n\n"
    "لم يتأثر البوت — حاول مرة أخرى، أو أرسل /start للعودة للقائمة الرئيسية."
)

BUTTONS_FALLBACK_NOTE = "\n\n⚠️ <i>تعذّر عرض أزرار هذه النتيجة.</i>"

ACTION_EXPIRED_TEXT = "⌛ انتهت صلاحية هذا الزر (أُعيد تشغيل البوت). ابحث من جديد من القائمة."

SUBDOMAINS_WAIT_TEXT = "🌿 <b>جاري جمع النطاقات الفرعية...</b>\nقد يستغرق ذلك حتى 30 ثانية."

URLSCAN_WAIT_TEXT = "🔬 <b>جاري جلب فحوصات urlscan.io...</b>"

DOWNLOAD_WAIT_TEXT = "📥 <b>جاري تحميل الملف وإرساله...</b>"

DOWNLOAD_FAILED_TEXT = "⚠️ تعذّر إرسال الملف داخل تيليجرام."

PHOTO_FAILED_TEXT = "⚠️ تعذّر إرسال الصورة حالياً."

WMN_BUSY_TEXT = "⏳ لديك فحص شامل قيد التنفيذ بالفعل — انتظر حتى ينتهي."

ACTION_ERROR_TEXT = "⚠️ تعذّر جلب النتائج حالياً — حاول مرة أخرى بعد قليل."


def searching_web_text(title: str) -> str:
    return f"🔎 <b>جاري البحث: {title}</b>\nستظهر النتائج هنا خلال ثوانٍ..."


def wmn_progress_text(username: str, done: int, total: int) -> str:
    if not total:
        return f"🧭 <b>جاري تحضير الفحص الشامل لليوزر</b> <code>{username}</code>...\nيستغرق الفحص عادةً من 30 إلى 90 ثانية."
    percent = int(done * 100 / total)
    filled = percent // 10
    bar = "▓" * filled + "░" * (10 - filled)
    return (
        f"🧭 <b>جاري فحص اليوزر</b> <code>{username}</code> <b>في {total} موقع...</b>\n\n"
        f"{bar} {percent}%\n"
        f"تم فحص <b>{done}</b> من <b>{total}</b>"
    )

CANCELLED_TEXT = "❌ تم إلغاء العملية الحالية.\n\n👇 اختر نوع البحث من جديد:"

ADMIN_ONLY_TEXT = "⛔ هذا الأمر مخصص لمالك البوت فقط."

BROADCAST_USAGE_TEXT = (
    "📢 <b>طريقة استخدام الرسالة الجماعية:</b>\n\n"
    "• اكتب: <code>/broadcast نص الرسالة</code>\n"
    "• أو ردّ على أي رسالة (نص/صورة/ملف) بالأمر <code>/broadcast</code> لإعادة إرسالها كما هي."
)

GUIDE_TEXT = (
    "📚 <b>دليل المصادر — أدوات OSINT العلنية</b>\n\n"
    "مجموعة مختارة من أشهر المصادر المفتوحة المجانية:\n\n"
    "🧭 <b>أطر عمل وأدلة:</b> OSINT Framework، Bellingcat Toolkit، IntelTechniques، Awesome OSINT\n"
    "🔎 <b>قواعد Google Dorks:</b> Google Hacking Database (GHDB)\n"
    "🌐 <b>الدومينات و IP:</b> crt.sh، Shodan، VirusTotal، Wayback Machine\n"
    "👤 <b>الأشخاص واليوزرات:</b> WhatsMyName، Sherlock\n"
    "🔐 <b>التسريبات:</b> Have I Been Pwned\n\n"
    "📝 اضغط «ورقة أوامر Google Dorks» لتتعلّم أهم عوامل البحث المتقدم."
)

DORKS_CHEATSHEET_TEXT = (
    "📝 <b>ورقة أوامر Google Dorks</b>\n\n"
    "<code>site:</code> — حصر النتائج في موقع أو امتداد\n"
    "   مثال: <code>site:gov.sa \"تقرير\"</code>\n"
    "<code>filetype:</code> أو <code>ext:</code> — نوع الملف\n"
    "   مثال: <code>\"ميزانية\" filetype:pdf</code>\n"
    "<code>intitle:</code> — كلمة داخل عنوان الصفحة\n"
    "<code>inurl:</code> — كلمة داخل الرابط\n"
    "<code>intext:</code> — كلمة داخل محتوى الصفحة\n"
    "<code>\"...\"</code> — تطابق حرفي للعبارة\n"
    "<code>-</code> — استبعاد كلمة أو موقع، مثل: <code>-site:x.com</code>\n"
    "<code>OR</code> — أحد الشرطين، مثل: <code>(pdf OR docx)</code>\n"
    "<code>*</code> — حرف بدل لأي كلمة\n"
    "<code>before:</code> / <code>after:</code> — تقييد بالتاريخ، مثل: <code>after:2024-01-01</code>\n\n"
    "💡 <b>أمثلة مركّبة:</b>\n"
    "• <code>site:linkedin.com/in \"مهندس\" \"الرياض\"</code>\n"
    "• <code>\"اسم الشركة\" (filetype:xls OR filetype:xlsx)</code>\n"
    "• <code>site:*.example.com -site:www.example.com</code>\n\n"
    f"{DISCLAIMER}"
)


def welcome_text(first_name: str) -> str:
    """رسالة الترحيب في القائمة الرئيسية (الاسم يجب أن يكون مُهرَّباً مسبقاً)."""
    greeting = f"مرحباً <b>{first_name}</b> 👋\n" if first_name else "مرحباً 👋\n"
    return (
        "💎 <b>بوت OSINT الشامل - مصادر علنية فقط</b>\n"
        "━━━━━━━━━━━━━━━━━━━━\n\n"
        f"{greeting}"
        "أداة لجمع المعلومات من المصادر المفتوحة (OSINT) وبناء استعلامات "
        "Google Dorks بضغطة زر.\n\n"
        "👇 <b>اختر نوع البحث:</b>\n\n"
        f"{DISCLAIMER}"
    )


def help_text(is_admin: bool) -> str:
    """رسالة المساعدة — تُظهر أوامر المالك له فقط."""
    text = (
        "ℹ️ <b>طريقة الاستخدام</b>\n\n"
        "1️⃣ أرسل /start لفتح القائمة الرئيسية.\n"
        "2️⃣ اختر نوع البحث (دومين، IP، هاتف، يوزر...).\n"
        "3️⃣ أرسل الهدف المطلوب (اسم، يوزر، رابط...).\n"
        "4️⃣ ستصلك النتيجة فوراً مع أزرار روابط تفتح مباشرة في المتصفح.\n\n"
        "<b>📋 الأوامر المتاحة:</b>\n"
        "/start — القائمة الرئيسية\n"
        "/help — المساعدة\n"
        "/cancel — إلغاء العملية الحالية\n"
    )
    if is_admin:
        text += (
            "\n<b>👑 أوامر المالك:</b>\n"
            "/stats — إحصائيات البوت\n"
            "/broadcast — إرسال رسالة جماعية لكل المستخدمين\n"
        )
    return text + f"\n{DISCLAIMER}"


def cooldown_text(remaining: float) -> str:
    return f"⏳ انتظر {max(1, round(remaining))} ثانية قبل البحث التالي."


def stats_text(users: int, stats: dict, uptime: str) -> str:
    """رسالة إحصائيات المالك."""
    by_category = stats.get("by_category", {})
    lines = [
        "📊 <b>إحصائيات البوت</b>",
        "",
        f"👥 عدد المستخدمين: <b>{users}</b>",
        f"🔎 إجمالي عمليات البحث: <b>{stats.get('total', 0)}</b>",
        f"⏱️ مدة التشغيل الحالية: <b>{uptime}</b>",
        "",
        "<b>📂 حسب القسم:</b>",
    ]
    for key, meta in CATEGORIES.items():
        lines.append(f"• {meta['title']}: <b>{by_category.get(key, 0)}</b>")
    return "\n".join(lines)


def broadcast_progress_text(done: int, total: int) -> str:
    return f"📢 جاري الإرسال... <b>{done}</b> / <b>{total}</b>"


def broadcast_done_text(sent: int, failed: int, removed: int) -> str:
    return (
        "✅ <b>اكتمل الإرسال الجماعي</b>\n\n"
        f"📨 تم الإرسال: <b>{sent}</b>\n"
        f"⚠️ فشل: <b>{failed}</b>\n"
        f"🚫 مستخدمون حظروا البوت (تم حذفهم): <b>{removed}</b>"
    )


# ═══════════════════════════════════════════════════════════
# ⌨️ لوحات الأزرار
# ═══════════════════════════════════════════════════════════


def _cat(key: str) -> Btn:
    """زر قسم من القائمة الرئيسية."""
    return Btn(CATEGORIES[key]["title"], callback_data=f"{CB_CATEGORY}:{key}")


def main_menu_keyboard() -> InlineKeyboardMarkup:
    """🏠 القائمة الرئيسية."""
    return InlineKeyboardMarkup(
        [
            [_cat("social")],
            [_cat("domain"), _cat("ip")],
            [_cat("phone"), _cat("user")],
            [_cat("docs"), _cat("email")],
            [Btn("📚 دليل المصادر", callback_data=CB_GUIDE)],
        ]
    )


def back_keyboard() -> InlineKeyboardMarkup:
    """زر الرجوع أسفل رسالة طلب الإدخال."""
    return InlineKeyboardMarkup([[Btn("🔙 رجوع", callback_data=CB_BACK)]])


def home_keyboard() -> InlineKeyboardMarkup:
    """زر فتح القائمة الرئيسية برسالة جديدة."""
    return InlineKeyboardMarkup([[Btn("🏠 القائمة الرئيسية", callback_data=CB_HOME_NEW)]])


def _nav_row(category: str) -> list[Btn]:
    """صف التنقل أسفل النتائج: بحث جديد في نفس القسم + رجوع للقائمة."""
    return [
        Btn("🔁 بحث جديد", callback_data=f"{CB_AGAIN}:{category}"),
        Btn("🔙 رجوع", callback_data=CB_HOME_NEW),
    ]


def results_keyboard(
    actions: Iterable[Action],
    category: str,
    register: Callable[[Action], str],
    columns: int = 2,
) -> InlineKeyboardMarkup:
    """🔘 بناء أزرار التقرير: كل زر يعرض نتيجته داخل تيليجرام (عدا روابط التطبيقات) + صف التنقل.

    register: دالة تحفظ بيانات الإجراء وتُرجع رمزاً قصيراً (callback_data محدود بـ 64 بايت).
    الأزرار العادية تُرتَّب في أعمدة، والأزرار العريضة (wide) تأخذ سطراً كاملاً.
    """
    rows: list[list[Btn]] = []
    pending: list[Btn] = []
    for action in actions:
        if action.kind == "url":
            button = Btn(action.label, url=action.value)
        else:
            button = Btn(action.label, callback_data=f"{CB_ACTION}:{register(action)}")
        if action.wide:
            if pending:
                rows.append(pending)
                pending = []
            rows.append([button])
            continue
        pending.append(button)
        if len(pending) == columns:
            rows.append(pending)
            pending = []
    if pending:
        rows.append(pending)
    rows.append(_nav_row(category))
    return InlineKeyboardMarkup(rows)


def error_keyboard(category: str) -> InlineKeyboardMarkup:
    """لوحة تظهر عند الخطأ أو انتهاء المهلة: إعادة المحاولة + رجوع."""
    return InlineKeyboardMarkup([_nav_row(category)])


def open_link_keyboard(url: str) -> InlineKeyboardMarkup:
    """زر احتياطي لفتح رابط الملف عند تعذّر إرساله داخل تيليجرام."""
    return InlineKeyboardMarkup([[Btn("🌐 فتح رابط الملف", url=url)]])


def search_page_keyboard(
    token: str,
    page: int,
    pages: int,
    downloads: list[tuple[int, str]],
    fallback_url: str | None = None,
) -> InlineKeyboardMarkup | None:
    """أزرار صفحة نتائج البحث: تحميل الملفات + التنقل بين الصفحات + بحث Google احتياطي عند الفشل."""
    rows: list[list[Btn]] = []
    download_buttons = [Btn(f"📥 {number}", callback_data=f"{CB_ACTION}:{tok}") for number, tok in downloads]
    rows += [download_buttons[i : i + 5] for i in range(0, len(download_buttons), 5)]
    nav = []
    if page > 0:
        nav.append(Btn("➡️ السابق", callback_data=f"{CB_PAGE}:{token}:{page - 1}"))
    if page < pages - 1:
        nav.append(Btn("التالي ⬅️", callback_data=f"{CB_PAGE}:{token}:{page + 1}"))
    if nav:
        rows.append(nav)
    if fallback_url:
        rows.append([Btn("🌐 فتح البحث في Google", url=fallback_url)])
    return InlineKeyboardMarkup(rows) if rows else None


# روابط دليل المصادر
_GUIDE_LINKS: tuple[Link, ...] = (
    Link("🧭 OSINT Framework", "https://osintframework.com/"),
    Link("📖 Google Hacking DB", "https://www.exploit-db.com/google-hacking-database"),
    Link("🧰 Bellingcat Toolkit", "https://bellingcat.gitbook.io/toolkit"),
    Link("🗺️ IntelTechniques", "https://inteltechniques.com/tools/"),
    Link("⭐ Awesome OSINT", "https://github.com/jivoi/awesome-osint"),
    Link("🕰️ Wayback Machine", "https://web.archive.org/"),
    Link("📜 crt.sh", "https://crt.sh/"),
    Link("🛰️ Shodan", "https://www.shodan.io/"),
    Link("🧪 VirusTotal", "https://www.virustotal.com/"),
    Link("👤 WhatsMyName", "https://whatsmyname.app/"),
    Link("🐍 Sherlock", "https://github.com/sherlock-project/sherlock"),
    Link("🔐 Have I Been Pwned", "https://haveibeenpwned.com/"),
)


def guide_keyboard() -> InlineKeyboardMarkup:
    """📚 لوحة دليل المصادر."""
    rows = [
        [Btn(link.label, url=link.url) for link in _GUIDE_LINKS[i : i + 2]]
        for i in range(0, len(_GUIDE_LINKS), 2)
    ]
    rows.append([Btn("📝 ورقة أوامر Google Dorks", callback_data=CB_GUIDE_DORKS)])
    rows.append([Btn("🔙 رجوع", callback_data=CB_BACK)])
    return InlineKeyboardMarkup(rows)


def dorks_keyboard() -> InlineKeyboardMarkup:
    """لوحة صفحة ورقة الأوامر."""
    return InlineKeyboardMarkup(
        [
            [Btn("📚 دليل المصادر", callback_data=CB_GUIDE), Btn("🏠 القائمة الرئيسية", callback_data=CB_BACK)],
        ]
    )
