"""
⚙️ ملف الإعدادات — بوت OSINT الشامل
====================================
يحتوي على توكن البوت ومعرّف المالك وجميع الإعدادات القابلة للتعديل.

ترتيب قراءة القيم:
  1. متغيرات البيئة (Environment Variables) إن وُجدت.
  2. ملف ‎.env‎ بجانب هذا الملف (إن وُجد).
  3. القيم الافتراضية المكتوبة هنا.

🔐 توكن البوت لا يُكتب هنا حتى لا يُرفع إلى GitHub (المستودع عام):
   انسخ ‎.env.example‎ إلى ‎.env‎ وضع التوكن بداخله — ملف ‎.env‎ مستثنى من git.
"""

from __future__ import annotations

import os
from pathlib import Path

# 📁 مجلد المشروع
BASE_DIR = Path(__file__).resolve().parent


def _load_env_file(path: Path) -> None:
    """تحميل المتغيرات من ملف ‎.env‎ (إن وُجد) دون الحاجة لأي مكتبة إضافية."""
    if not path.is_file():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        os.environ.setdefault(key.strip(), value.strip().strip('"').strip("'"))


_load_env_file(BASE_DIR / ".env")

# ═══════════════════════════════════════════════════════════
# 🔑 بيانات الاعتماد
# ═══════════════════════════════════════════════════════════

# توكن البوت من ‎@BotFather‎ — يُقرأ من ملف ‎.env‎ أو من متغيرات البيئة
BOT_TOKEN: str = os.getenv("BOT_TOKEN", "").strip()

# 👑 معرّف المالك (الأدمن) — له وحده صلاحية أوامر ‎/stats‎ و ‎/broadcast‎
OWNER_ID: int = 8876599674

# يمكن إضافة مشرفين آخرين عبر متغير البيئة ADMIN_IDS (أرقام مفصولة بفواصل)
ADMIN_IDS: frozenset[int] = frozenset(
    {OWNER_ID}
    | {int(x) for x in os.getenv("ADMIN_IDS", "").replace(" ", "").split(",") if x.isdigit()}
)

# ═══════════════════════════════════════════════════════════
# 🔎 مفاتيح البحث داخل تيليجرام (اختيارية ومجانية)
# ═══════════════════════════════════════════════════════════
# بدون مفتاح يستخدم البوت بحثاً مجانياً محدوداً (كثيراً ما تحجبه محركات البحث عن الخوادم).
# للحصول على نتائج Google كاملة داخل تيليجرام أضف أحد المفتاحين كسرّ في GitHub أو في ملف ‎.env‎:
#   • SERPER_API_KEY ← من serper.dev (2,500 بحث مجاني، بدون بطاقة بنكية) — موصى به
#   • BRAVE_API_KEY  ← من api.search.brave.com (خطة مجانية شهرية)
SERPER_API_KEY: str = os.getenv("SERPER_API_KEY", "").strip()
BRAVE_API_KEY: str = os.getenv("BRAVE_API_KEY", "").strip()

# عدد نتائج البحث في كل صفحة داخل تيليجرام
SEARCH_RESULTS_PER_PAGE: int = 5

# ═══════════════════════════════════════════════════════════
# 🛠️ إعدادات التشغيل
# ═══════════════════════════════════════════════════════════

# ملف حفظ البيانات (المستخدمون، الإحصائيات، حالة المحادثات)
PERSISTENCE_FILE: Path = BASE_DIR / "data" / "bot_data.pickle"

# المهلة القصوى لكل طلب HTTP إلى المصادر العلنية (بالثواني)
HTTP_TIMEOUT: float = 8.0

# المهلة القصوى لعملية البحث الكاملة قبل إلغائها (بالثواني)
LOOKUP_TIMEOUT: float = 30.0

# فترة الانتظار بين عمليتي بحث لنفس المستخدم (حماية من الإغراق)
COOLDOWN_SECONDS: float = 3.0

# فترة الانتظار بين ضغطات أزرار النتائج (البحث، النطاقات الفرعية...)
ACTION_COOLDOWN_SECONDS: float = 2.0

# أقصى طول مسموح لنص البحث
MAX_QUERY_LENGTH: int = 120

# 🧭 الفحص الشامل لليوزر (WhatsMyName): عدد الطلبات المتزامنة، مهلة كل موقع، والمدة القصوى
WMN_CONCURRENCY: int = 40
WMN_SITE_TIMEOUT: float = 10.0
WMN_MAX_SECONDS: float = 120.0

# 📥 أقصى حجم للملفات التي يرسلها البوت داخل تيليجرام (ميغابايت)
MAX_DOWNLOAD_MB: int = 20

# هوية المتصفح المرسلة مع الطلبات
USER_AGENT: str = "Mozilla/5.0 (compatible; OSINT-TelegramBot/1.0)"

# مستوى السجلات: DEBUG / INFO / WARNING / ERROR
LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO").upper()
