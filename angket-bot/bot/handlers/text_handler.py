from telegram import InlineKeyboardButton, InlineKeyboardMarkup, KeyboardButton, ReplyKeyboardMarkup, Update
from telegram.ext import ContextTypes

from bot.translator import format_scan_report, get_main_menu_keyboard, tr


def get_action_keyboard(lang: str = "en") -> ReplyKeyboardMarkup:
    """
    Returns the 3-button keyboard shown after a scan result.
    """
    keyboard = [ 
        [
            KeyboardButton(tr("btn_check_another", lang)),
            KeyboardButton(tr("btn_safety_tips", lang)),
            KeyboardButton(tr("btn_view_report", lang)),
        ]
    ]
    return ReplyKeyboardMarkup(keyboard, resize_keyboard=True)


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    lang = context.user_data.get("lang", "en")
    welcome_text = tr("welcome", lang)

    # Inline buttons for language selection ONLY on start
    inline_keyboard = InlineKeyboardMarkup([
        [
            InlineKeyboardButton("🇬🇧 English", callback_data="lang_en"),
            InlineKeyboardButton("🇰🇭 ភាសាខ្មែរ", callback_data="lang_kh"),
        ]
    ])

    await update.message.reply_text(
        welcome_text,
        parse_mode="Markdown",
        reply_markup=inline_keyboard,
    )


async def handle_language_selection(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()

    if query.data == "lang_en":
        context.user_data["lang"] = "en"
    else:
        context.user_data["lang"] = "kh"

    lang = context.user_data["lang"]
    msg = tr("lang_set_en" if lang == "en" else "lang_set_kh", lang)

    # Update inline confirmation message
    await query.edit_message_text(msg, parse_mode="Markdown")

    # Display bottom persistent grid menu after setting language
    await query.message.reply_text(
        tr("menu_prompt", lang),
        parse_mode="Markdown",
        reply_markup=get_main_menu_keyboard(lang),
    )


async def send_scan_result(
    update: Update,
    context: ContextTypes.DEFAULT_TYPE,
    malicious: int,
    total: int,
):
    lang = context.user_data.get("lang", "en")
    report_text = format_scan_report(malicious, total, lang)

    await update.message.reply_text(
        report_text,
        parse_mode="Markdown",
        reply_markup=get_action_keyboard(lang),
    )


async def handle_text(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    lang = context.user_data.get("lang", "en")
    text = update.message.text

    # Listen for bottom action keyboard buttons
    if text in [tr("btn_check_another", "en"), tr("btn_check_another", "kh")]:
        await update.message.reply_text(
            tr("menu_prompt", lang),
            parse_mode="Markdown",
            reply_markup=get_main_menu_keyboard(lang),
        )
        return

    if text in [tr("btn_safety_tips", "en"), tr("btn_safety_tips", "kh")]:
        tips_msg = (
            "📖 **Security Tips:**\n• Never download executable files (.exe, .apk) from untrusted links.\n• Always verify domain names carefully."
            if lang == "en"
            else "📖 **គន្លឹះសុវត្ថិភាព៖**\n• កុំទាញយកឯកសារ (.exe, .apk) ពីប្រភពដែលមិនច្បាស់លាស់។\n• ត្រូវពិនិត្យឈ្មោះ Domain ឱ្យបានច្បាស់លាស់ជានិច្ច។"
        )
        await update.message.reply_text(tips_msg, parse_mode="Markdown")
        return

    if text in [tr("btn_view_report", "en"), tr("btn_view_report", "kh")]:
        file_hash = context.user_data.get("last_scan_hash")
        file_name = context.user_data.get("last_scan_file", "file")
        
        if file_hash:
            vt_url = f"https://www.virustotal.com/gui/file/{file_hash}"
            msg = (
                f"📊 **View Full Report**\n\n"
                f"File: `{file_name}`\n\n"
                f"[Click here to view the full VirusTotal analysis]({vt_url})"
                if lang == "en"
                else f"📊 **មើលរបាយការណ៍ពេញលេញ**\n\n"
                f"ឯកសារ: `{file_name}`\n\n"
                f"[ចូលទៅ VirusTotal]({vt_url})"
            )
            await update.message.reply_text(msg, parse_mode="Markdown", disable_web_page_preview=True)
        else:
            msg = "No scan history available." if lang == "en" else "មិនមានប្រវត្តិស្កេនទេ។"
            await update.message.reply_text(msg, parse_mode="Markdown")
        return

    # Language Switch button handling
    if text in [tr("menu_change_lang", "en"), tr("menu_change_lang", "kh"), "🌐 Change Language", "🌐 ប្តូរភាសា"]:
        inline_keyboard = InlineKeyboardMarkup([
            [
                InlineKeyboardButton("🇬🇧 English", callback_data="lang_en"),
                InlineKeyboardButton("🇰🇭 ភាសាខ្មែរ", callback_data="lang_kh"),
            ]
        ])
        await update.message.reply_text(
            "🌐 **Select Language / សូមជ្រើសរើសភាសា៖**",
            parse_mode="Markdown",
            reply_markup=inline_keyboard,
        )
        return

    await update.message.reply_text(f"🔎 Scanning input: `{text}`", parse_mode="Markdown")