import hashlib
import io

import vt
from telegram.ext import ContextTypes

from bot.config import VIRUSTOTAL_API_KEY


async def download_and_hash(context: ContextTypes.DEFAULT_TYPE, file_id: str) -> str:
    """Download a Telegram file and return its SHA-256 hex digest, ready
    for scan_vt_hash() - shared by every flow that scans an uploaded
    file (handle_file, handle_business_message) so a future fix (e.g. a
    size guard) only needs to land in one place."""
    file_info = await context.bot.get_file(file_id)
    buf = io.BytesIO()
    await file_info.download_to_memory(buf)
    return hashlib.sha256(buf.getvalue()).hexdigest()


async def scan_vt_hash(file_hash: str) -> dict:
    async with vt.Client(VIRUSTOTAL_API_KEY) as client:
        try:
            file_obj = await client.get_object_async(f"/files/{file_hash}")
            stats = file_obj.last_analysis_stats
            results = getattr(file_obj, "last_analysis_results", {})

            def get_engine_status(engine_name: str) -> str:
                engine_data = results.get(engine_name, {})
                category = engine_data.get("category", "undetected")
                result = engine_data.get("result")
                if category == "malicious":
                    return f"Detected ({result})"
                if category == "suspicious":
                    return f"Suspicious ({result})"
                return "Clean"

            return {
                "found": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total": sum(stats.values()),
                "top_engines": {
                    "Microsoft": get_engine_status("Microsoft"),
                    "Kaspersky": get_engine_status("Kaspersky"),
                    "BitDefender": get_engine_status("BitDefender"),
                },
            }
        except vt.APIError as error:
            if error.code == "NotFoundError":
                return {"found": False, "error": "NotFound"}
            return {"found": False, "error": str(error)}