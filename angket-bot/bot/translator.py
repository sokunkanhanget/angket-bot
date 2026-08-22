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
    Formats the analysis report matching the ScamRadar blockquote layout.
    """
    risk_percentage = min(100, int((malicious / max(1, total)) * 100)) if total > 0 else 0
    is_danger = malicious > 0 or risk_percentage > 10

    # 1. Verdict Section
    v_head = tr("section_verdict", lang)
    v_box = tr("verdict_danger" if is_danger else "verdict_safe", lang)

    # 2. Risk Level Section
    r_head = tr("section_risk", lang)
    r_label = tr("risk_label_danger" if is_danger else "risk_label_safe", lang)
    p_bar = make_progress_bar(risk_percentage)
    r_text = f"**{risk_percentage}%** {r_label}\n{p_bar}\n`0%                50%              100%`"

    # 3. Key Reasons
    k_head = tr("section_reasons", lang)
    if is_danger:
        reasons = (
            f"{tr('reason_danger_1', lang, malicious=malicious, total=total)}\n"
            f"{tr('reason_danger_2', lang)}\n"
            f"{tr('reason_danger_3', lang)}"
        )
    else:
        reasons = (
            f"{tr('reason_safe_1', lang)}\n"
            f"{tr('reason_safe_2', lang)}\n"
            f"{tr('reason_safe_3', lang)}"
        )

    # 4. What You Can Do
    a_head = tr("section_action", lang)
    a_box = tr("action_danger" if is_danger else "action_safe", lang)

    # 5. Heads Up Notice
    n_head = tr("section_notice", lang)
    n_box = tr("notice_box", lang)

    return (
        f"{v_head}\n{v_box}\n\n"
        f"{r_head}\n\n{r_text}\n\n"
        f"{k_head}\n{reasons}\n\n"
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