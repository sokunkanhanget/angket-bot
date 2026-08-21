import hashlib
import io

from telegram import Update
from telegram.ext import ContextTypes

from bot.analysis.file_scanner import scan_vt_hash
from bot.analysis.utils import log_scan


async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    document = update.message.document
    file_name = document.file_name or "unknown_file"
    user_id = update.effective_user.id
    message = await update.message.reply_text(
        f"📥 *Scanning `{file_name}`...*", parse_mode="Markdown"
    )

    file_info = await context.bot.get_file(document.file_id)
    output = io.BytesIO()
    await file_info.download_to_memory(output)
    sha256 = hashlib.sha256(output.getvalue()).hexdigest()
    result = await scan_vt_hash(sha256)

    if result["found"]:
        malicious = result["malicious"]
        engines = result["top_engines"]
        header = (
            "🚨 **RED ALERT: MALICIOUS FILE DETECTED**"
            if malicious > 0
            else "🟢 **FILE IS CLEAN**"
        )
        reply = (
            f"{header}\n\n"
            f"📄 **File:** `{file_name}`\n\n"
            f"🔎 **Summary:**\n```\n"
            f"Malicious: {malicious}\n"
            f"Suspicious: {result['suspicious']}\n"
            f"Harmless:  {result['harmless']}\n"
            f"Undetected: {result['undetected']}/{result['total']}\n"
            f"```\n"
            f"🧪 **Top Engines:**\n```\n"
            f"- Top 1: Microsoft - {engines['Microsoft']}\n"
            f"- Top 2: Kaspersky - {engines['Kaspersky']}\n"
            f"- Top 3: BitDefender - {engines['BitDefender']}\n"
            f"```"
        )
        log_scan(user_id, file_name, sha256, malicious)
    else:
        reply = (
            f"⚪ **UNKNOWN FILE SIGNATURE**\n\n"
            f"📄 **File:** `{file_name}`\n"
            f"🧬 **SHA-256:** `{sha256}`\n\n"
            "This file signature was not found on VirusTotal."
        )
        log_scan(user_id, file_name, sha256, 0)

    await message.edit_text(reply, parse_mode="Markdown")