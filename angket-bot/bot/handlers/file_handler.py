import asyncio
import hashlib
import io

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import ContextTypes

from bot.analysis.file_scanner import scan_vt_hash
from bot.analysis.utils import log_scan


async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    document = update.message.document
    file_name = document.file_name or "unknown_file"
    user_id = update.effective_user.id

    message = await update.message.reply_text(
        f"📥 *Downloading `{file_name}`...*\n`[░░░░░░░░░░]` 0%", 
        parse_mode="Markdown"
    )

    await asyncio.sleep(0.5)
    await message.edit_text(
        f"🔍 *Scanning file against 70+ antivirus engines...*\n`[█████████░]` 90%", 
        parse_mode="Markdown"
    )

    file_info = await context.bot.get_file(document.file_id)
    output = io.BytesIO()
    await file_info.download_to_memory(output)
    sha256 = hashlib.sha256(output.getvalue()).hexdigest()

    result = await scan_vt_hash(sha256)

    if result["found"]:
        malicious = result["malicious"]
        total = result["total"]
        engines = result["top_engines"]

        if malicious == 0:
            status = "🟢 **SAFE TO OPEN**"
            summary = "No security engines flagged this file as dangerous."
            keyboard = InlineKeyboardMarkup([
                [InlineKeyboardButton("🌐 View VirusTotal Report", url=f"https://www.virustotal.com/gui/file/{sha256}")]
            ])
        else:
            status = "🚨 **SUSPICIOUS FILE DETECTED**"
            summary = f"⚠️ Flagged as harmful by **{malicious} out of {total}** antivirus engines!"
            
            # Interactive action buttons
            keyboard = InlineKeyboardMarkup([
                [
                    InlineKeyboardButton("🗑️ Delete File Message", callback_data=f"delete_{update.message.message_id}"),
                    InlineKeyboardButton("⚠️ Ignore Warning", callback_data="ignore")
                ],
                [InlineKeyboardButton("🌐 View VirusTotal Report", url=f"https://www.virustotal.com/gui/file/{sha256}")]
            ])

        reply = (
            f"🛡️ **របាយការណ៍ក្នុងការវិភាគវីរុស​ (Virus) បានរួចរាល់**\n\n"
            f"📄 **File:** `{file_name}`\n"
            f"📊 **Status:** {status}\n\n"
            f"💡 **Analysis:**\n{summary}\n\n"
            f"⚙️ **Engine Checks:**\n"
            f"• **Microsoft:** {engines.get('Microsoft', 'Clean')}\n"
            f"• **Kaspersky:** {engines.get('Kaspersky', 'Clean')}\n"
            f"• **BitDefender:** {engines.get('BitDefender', 'Clean')}"
        )
        log_scan(user_id, file_name, sha256, malicious)
    else:
        reply = (
            f"⚪ **UNKNOWN FILE**\n\n"
            f"📄 **File:** `{file_name}`\n"
            "This file signature is not in VirusTotal's database yet."
        )
        keyboard = None
        log_scan(user_id, file_name, sha256, 0)

    await message.edit_text(reply, parse_mode="Markdown", reply_markup=keyboard, disable_web_page_preview=True)


# New handler function for when users click the buttons
async def handle_button_click(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    query = update.callback_query
    await query.answer()

    if query.data.startswith("delete_"):
        target_msg_id = int(query.data.split("_")[1])
        chat_id = query.message.chat_id

        try:
            # Delete the user's uploaded file message from chat
            await context.bot.delete_message(chat_id=chat_id, message_id=target_msg_id)
            await query.edit_message_text("🗑️ **Threat Removed:** The file message was deleted from chat history.")
        except Exception:
            await query.edit_message_text("⚠️ **Notice:** Please delete the file from your local downloads folder.")

    elif query.data == "ignore":
        await query.edit_message_text("⚠️ **Warning Ignored:** Do not execute unverified binary files.")