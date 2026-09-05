import logging

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.error import TelegramError
from telegram.ext import ContextTypes

from bot.detectors.file.scanner import download_and_hash, scan_file
from bot.storage.scan_log import log_scan
from bot.handlers.text_handler import get_user_lang
from bot.i18n import label, t
from bot.verdict_style import risk_style

logger = logging.getLogger(__name__)


def _virustotal_button(lang: str, sha256: str) -> InlineKeyboardButton:
    return InlineKeyboardButton(
        label(lang, "view_on_virustotal"),
        url=f"https://www.virustotal.com/gui/file/{sha256}",
    )


def _scan_result_keyboard(lang: str, original_message_id: int, malicious: int, sha256: str) -> InlineKeyboardMarkup:
    """Delete/Ignore only make sense next to an actually-malicious result -
    a clean or unknown-signature file has nothing to delete or ignore."""
    rows = []
    if malicious > 0:
        rows.append([
            InlineKeyboardButton(label(lang, "delete"), callback_data=f"delete_{original_message_id}"),
            InlineKeyboardButton(label(lang, "ignore"), callback_data="ignore"),
        ])
    rows.append([_virustotal_button(lang, sha256)])
    return InlineKeyboardMarkup(rows)


async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    document = update.message.document
    file_name = document.file_name or "unknown_file"
    user_id = update.effective_user.id
    lang = get_user_lang(context)
    message = await update.message.reply_text(
        f"📥 *Scanning `{file_name}`...*",
        parse_mode="Markdown",
    )

    try:
        sha256 = await download_and_hash(context, document.file_id)
        result = await scan_file(sha256, file_name)
    except Exception:                          # noqa: BLE001 - a download/VT failure must still get a reply, not silence
        logger.exception("File scan failed for %s", file_name)
        await message.edit_text(t(lang, "file_scan_failed"))
        return

    filename_warning = result.get("filename_warning")
    warning_block = f"\n⚠️ **{filename_warning}**\n" if filename_warning else ""

    if result["found"]:
        malicious = result["malicious"]
        total = result["total"]
        engines = result["top_engines"]
        risk_percentage = min(100, round(malicious / total * 100)) if total else 0
        risk_icon, risk_label = risk_style(risk_percentage)
        header = (
            "🚨 **RED ALERT: MALICIOUS FILE DETECTED**"
            if malicious > 0
            else "🟢 **FILE IS CLEAN**"
        )
        reply = (
            f"{header}\n\n"
            f"📄 **File:** `{file_name}`\n"
            f"{warning_block}\n"
            f"{risk_icon} **{risk_percentage}%  {risk_label.upper()}**\n\n"
            f"🔎 **Summary:**\n```\n"
            f"Malicious: {malicious}\n"
            f"Suspicious: {result['suspicious']}\n"
            f"Harmless:  {result['harmless']}\n"
            f"Undetected: {result['undetected']}/{total}\n"
            f"```\n"
            f"🧪 **Top Engines:**\n```\n"
            f"- Top 1: Microsoft - {engines['Microsoft']}\n"
            f"- Top 2: Kaspersky - {engines['Kaspersky']}\n"
            f"- Top 3: BitDefender - {engines['BitDefender']}\n"
            f"```"
        )
        keyboard = _scan_result_keyboard(lang, update.message.message_id, malicious, sha256)
        log_scan(user_id, file_name, sha256, malicious)
    else:
        reply = (
            f"⚪ **UNKNOWN FILE SIGNATURE**\n\n"
            f"📄 **File:** `{file_name}`\n"
            f"{warning_block}"
            f"🧬 **SHA-256:** `{sha256}`\n\n"
            "This file signature was not found on VirusTotal."
        )
        keyboard = InlineKeyboardMarkup([[_virustotal_button(lang, sha256)]])
        log_scan(user_id, file_name, sha256, 0)

    await message.edit_text(
        reply,
        parse_mode="Markdown",
        reply_markup=keyboard,
    )


async def handle_scan_action_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Delete/Ignore taps on a file-scan result - registered with an
    explicit pattern (see bot.py) so it can never swallow unrelated
    callbacks like the business-chat link notifications' `^u:` ones."""
    query = update.callback_query
    await query.answer()
    lang = get_user_lang(context)

    if query.data.startswith("delete_"):
        target_message_id = int(query.data.split("_", 1)[1])
        try:
            await context.bot.delete_message(chat_id=query.message.chat_id, message_id=target_message_id)
            await query.edit_message_text(t(lang, "file_deleted"))
        except TelegramError:
            # Already deleted, or the bot lacks delete permission in this
            # chat - either way, nothing more we can safely do here.
            await query.edit_message_text(t(lang, "file_deleted"))
    elif query.data == "ignore":
        await query.edit_message_text(t(lang, "file_scan_ignored"))
