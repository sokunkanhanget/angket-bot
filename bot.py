import hashlib
import io
import os
import sqlite3
from dotenv import load_dotenv
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes, MessageHandler, filters
import vt

# Load environment variables
load_dotenv()

TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_API_KEY")

# High-risk heuristic keywords
SUSPICIOUS_KEYWORDS = [
    "free bitcoin", "claim reward", "login-verify",
    "account-suspended", "bit.ly", "tinyurl.com"
]

def init_db():
    conn = sqlite3.connect("scan_logs.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS scan_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            item_name TEXT,
            sha256 TEXT,
            malicious_count INTEGER
        )
    """)
    conn.commit()
    conn.close()

def log_scan(user_id: int, item_name: str, sha256: str, malicious: int):
    conn = sqlite3.connect("scan_logs.db")
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO scan_logs (user_id, item_name, sha256, malicious_count) VALUES (?, ?, ?, ?)",
        (user_id, item_name, sha256, malicious)
    )
    conn.commit()
    conn.close()

# Fetch VirusTotal Data including Engine Details
async def scan_vt_hash(file_hash: str) -> dict:
    async with vt.Client(VIRUSTOTAL_KEY) as client:
        try:
            file_obj = await client.get_object_async(f"/files/{file_hash}")
            stats = file_obj.last_analysis_stats
            results = getattr(file_obj, "last_analysis_results", {})
            
            # Helper to extract specific engine verdict
            def get_engine_status(engine_name):
                engine_data = results.get(engine_name, {})
                category = engine_data.get("category", "undetected")
                res_name = engine_data.get("result")
                
                if category == "malicious":
                    return f"Detected ({res_name})"
                elif category == "suspicious":
                    return f"Suspicious ({res_name})"
                else:
                    return "Clean"

            top_engines = {
                "Microsoft": get_engine_status("Microsoft"),
                "Kaspersky": get_engine_status("Kaspersky"),
                "BitDefender": get_engine_status("BitDefender")
            }

            return {
                "found": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total": sum(stats.values()),
                "top_engines": top_engines
            }
        except vt.APIError as e:
            if e.code == "NotFoundError":
                return {"found": False, "error": "NotFound"}
            return {"found": False, "error": str(e)}

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(
        "🛡️ **Angket Bot**\n\n"
        "Send me a file or text string to perform a malware scan.",
        parse_mode="Markdown"
    )

async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE):
    doc = update.message.document
    file_name = doc.file_name or "unknown_file"
    user_id = update.effective_user.id
    
    msg = await update.message.reply_text(f"📥 *Scanning `{file_name}`...*", parse_mode="Markdown")
    
    file_info = await context.bot.get_file(doc.file_id)
    out = io.BytesIO()
    await file_info.download_to_memory(out)
    out.seek(0)
    
    sha256 = hashlib.sha256(out.read()).hexdigest()
    vt_res = await scan_vt_hash(sha256)
    
    if vt_res["found"]:
        mal = vt_res["malicious"]
        sus = vt_res["suspicious"]
        harm = vt_res["harmless"]
        undet = vt_res["undetected"]
        total = vt_res["total"]
        
        header = "🚨 **RED ALERT: MALICIOUS FILE DETECTED**" if mal > 0 else "🟢 **FILE IS CLEAN**"
        
        engines = vt_res["top_engines"]
        
        # Build exact layout using code blocks
        reply = (
            f"{header}\n\n"
            f"📄 **File:** `{file_name}`\n\n"
            f"🔎 **Summary:**\n"
            f"```\n"
            f"Malicious: {mal}\n"
            f"Suspicious: {sus}\n"
            f"Harmless:  {harm}\n"
            f"Undetected: {undet}/{total}\n"
            f"```\n"
            f"🧪 **Top Engines:**\n"
            f"```\n"
            f"- Top 1: Microsoft - {engines['Microsoft']}\n"
            f"- Top 2: Kaspersky - {engines['Kaspersky']}\n"
            f"- Top 3: BitDefender - {engines['BitDefender']}\n"
            f"```"
        )
        log_scan(user_id, file_name, sha256, mal)
    else:
        reply = (
            f"⚪ **UNKNOWN FILE SIGNATURE**\n\n"
            f"📄 **File:** `{file_name}`\n"
            f"🧬 **SHA-256:** `{sha256}`\n\n"
            "This file signature was not found on VirusTotal."
        )
        log_scan(user_id, file_name, sha256, 0)
        
    await msg.edit_text(reply, parse_mode="Markdown")

def main():
    if not TOKEN or not VIRUSTOTAL_KEY:
        print("Error: Missing TELEGRAM_BOT_TOKEN or VIRUSTOTAL_API_KEY in .env file.")
        return

    init_db()
    app = Application.builder().token(TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_file))

    print("🤖 Bot is running...")
    app.run_polling()

if __name__ == "__main__":
    main()