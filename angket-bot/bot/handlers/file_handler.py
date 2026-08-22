import asyncio
import hashlib
import io

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.helpers import escape_markdown
from telegram.ext import ContextTypes

from bot.analysis.file_scanner import scan_vt_hash
from bot.analysis.utils import log_scan
from bot.translator import format_scan_report, tr


async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    document = update.message.document
    file_name = document.file_name or "unknown_file"
    safe_file_name = escape_markdown(file_name, version=1)
    user_id = update.effective_user.id
    lang = context.user_data.get("lang", "en")

    # Animated progress using custom dictionary
    msg_dl = tr("dl_progress", lang, file_name=safe_file_name)
    msg_scan = tr("scan_progress", lang)

    message = await update.message.reply_text(msg_dl, parse_mode="Markdown")

    await asyncio.sleep(0.5)
    await message.edit_text(msg_scan, parse_mode="Markdown")

    # Download into RAM only; no file is created on the local computer.
    file_info = await context.bot.get_file(document.file_id)
    file_data = io.BytesIO()
    await file_info.download_to_memory(file_data)
    sha256 = hashlib.sha256(file_data.getbuffer()).hexdigest()

    result = await scan_vt_hash(sha256)

    if result["found"]:
        malicious = result["malicious"]
        total = result["total"]
        reply = (
            f"📄 **File:** `{safe_file_name}`\n\n"
            f"{format_scan_report(malicious, total, lang)}"
        )

        btn_delete = tr("btn_delete", lang)
        btn_ignore = tr("btn_ignore", lang)
        btn_report = tr("btn_report", lang)

        if malicious > 0:
            keyboard = InlineKeyboardMarkup([
                [
                    InlineKeyboardButton(btn_delete, callback_data=f"delete_{update.message.message_id}"),
                    InlineKeyboardButton(btn_ignore, callback_data="ignore")
                ],
                [InlineKeyboardButton(btn_report, url=f"https://www.virustotal.com/gui/file/{sha256}")]
            ])
        else:
            keyboard = InlineKeyboardMarkup([
                [InlineKeyboardButton(btn_report, url=f"https://www.virustotal.com/gui/file/{sha256}")]
            ])

        log_scan(user_id, file_name, sha256, malicious)
    else:
        title = tr("unknown_file_title", lang)
        msg = tr("unknown_file_msg", lang)
        lbl_file = tr("lbl_file", lang)
        
        reply = (
            f"{escape_markdown(title, version=1)}\n\n"
            f"📄 **{escape_markdown(lbl_file, version=1)}:** `{safe_file_name}`\n\n"
            f"{escape_markdown(msg, version=1)}"
        )
        keyboard = None
        log_scan(user_id, file_name, sha256, 0)

    await message.edit_text(reply, parse_mode="Markdown", reply_markup=keyboard, disable_web_page_preview=True)


async def handle_button_click(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()
    lang = context.user_data.get("lang", "en")

    if query.data.startswith("delete_"):
        target_msg_id = int(query.data.split("_")[1])
        chat_id = query.message.chat_id

        try:
            await context.bot.delete_message(chat_id=chat_id, message_id=target_msg_id)
            await query.edit_message_text(tr("msg_deleted", lang))
        except Exception:
            await query.edit_message_text(tr("msg_delete_failed", lang))

    elif query.data == "ignore":
        await query.edit_message_text(tr("msg_ignored", lang))