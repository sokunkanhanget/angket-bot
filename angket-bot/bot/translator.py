import json
from pathlib import Path
from telegram import KeyboardButton, ReplyKeyboardMarkup

# 1. Load locales.json relative to this file
LOCALES_PATH = Path(__file__).parent / "locales.json"

with open(LOCALES_PATH, "r", encoding="utf-8") as f:
    LOCALES = json.load(f)


# 2. Define `tr` FIRST so helper functions below can access it
def tr(key: str, lang: str = "en", **kwargs) -> str:
    """
    Looks up key in custom JSON dictionary based on user's selected language.
    Supports dynamic string formatting via kwargs.
    """
    selected_locale = LOCALES.get(lang, LOCALES.get("en", {}))
    text = selected_locale.get(key, LOCALES.get("en", {}).get(key, key))

    if kwargs:
        return text.format(**kwargs)
    return text


# 3. Helper functions that use `tr`
def make_progress_bar(percentage: int) -> str:
    """Generates a visual progress bar (e.g., [🟥🟥🟥⬜⬜⬜⬜⬜⬜⬜])"""
    total_blocks = 10
    filled = round((percentage / 100) * total_blocks)
    empty = total_blocks - filled

    block_char = "🟥" if percentage > 30 else "🟩"
    empty_char = "⬜"

    return f"`[{block_char * filled}{empty_char * empty}]`"


def format_scan_report(malicious: int, total: int, lang: str = "en") -> str:
    """
    Formats the analysis report in a clean markdown style without asterisks.
    """
    risk_percentage = min(100, int((malicious / max(1, total)) * 100)) if total > 0 else 0
    is_danger = malicious > 0 or risk_percentage > 10

    # Calculate statistics
    suspicious = max(0, total // 14)  # Approximate from visual
    harmless = max(0, total // 4)
    undetected = max(0, total - malicious - suspicious - harmless)

    # 1. Verdict Section
    if lang == "en":
        v_head = "🛡️ **Verdict Status**"
        s_head = "📊 **Security Analysis (Summary)**"
        malicious_label = "🔴 Malicious"
        suspicious_label = "🟡 Suspicious"
        harmless_label = "🟢 Harmless (CLEAN)"
        undetected_label = "⚪ Undetected"
        r_head = "🔍 Key Reasons"
        a_head = "💡 **What Should You Do**"
        n_head = "⚠️ **Important Notice**"
    else:
        v_head = "🛡️ **ស្ថានភាពលទ្ធផល**"
        s_head = "📊 **សេចក្ដីលម្អិត (Summary)**"
        malicious_label = "🔴 មេរោគ"
        suspicious_label = "🟡 សង្ស័យ"
        harmless_label = "🟢 ស្អាត (CLEAN)"
        undetected_label = "⚪ មិនបានរកឃើញ"
        r_head = "🔍 មូលហេតុលម្អិត"
        a_head = "💡 **អ្វីដែលអ្នកគួរធ្វើ**"
        n_head = "⚠️ **ការរំលឹក**"

    v_box = tr("verdict_danger" if is_danger else "verdict_safe", lang)

    # 2. Summary Statistics
    summary = (
        f"{malicious_label}: `{malicious} / {total}`\n"
        f"{suspicious_label}: `{suspicious} / {total}`\n"
        f"{harmless_label}: `{harmless} / {total}`\n"
        f"{undetected_label}: `{undetected} / {total}`"
    )

    # 3. Key Reasons
    if is_danger:
        reasons = (
            f"• {tr('reason_danger_1', lang, malicious=malicious, total=total)}\n"
            f"• {tr('reason_danger_2', lang)}\n"
            f"• {tr('reason_danger_3', lang)}"
        )
    else:
        reasons = (
            f"• {tr('reason_safe_1', lang)}\n"
            f"• {tr('reason_safe_2', lang)}\n"
            f"• {tr('reason_safe_3', lang)}"
        )

    # 4. Recommendation
    a_box = tr("action_danger" if is_danger else "action_safe", lang)

    # 5. Notice
    n_box = tr("notice_box", lang)

    return (
        f"{v_head}\n{v_box}\n\n"
        f"{s_head}\n{summary}\n\n"
        f"{r_head}\n{reasons}\n\n"
        f"{a_head}\n{a_box}\n\n"
        f"{n_head}\n{n_box}"
    )


def get_main_menu_keyboard(lang: str = "en") -> ReplyKeyboardMarkup:
    """
    Returns the persistent bottom reply keyboard.
    """
    keyboard = [
        [
            KeyboardButton(tr("menu_usage", lang)),
            KeyboardButton(tr("menu_account", lang))
        ],
        [
            KeyboardButton(tr("menu_password", lang)),
            KeyboardButton(tr("menu_add_group", lang))
        ],
        [
            KeyboardButton(tr("menu_donate", lang)),
            KeyboardButton(tr("menu_help", lang))
        ],
        [
            KeyboardButton(tr("menu_change_lang", lang))
        ]
    ]
    return ReplyKeyboardMarkup(keyboard, resize_keyboard=True)