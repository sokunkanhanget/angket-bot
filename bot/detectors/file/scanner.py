import hashlib
import io

import vt
from telegram.ext import ContextTypes

from bot.config import VIRUSTOTAL_API_KEY

# Executable/script extensions - the highest-risk disguise target: a
# real attack ("invoice.pdf.exe") hides one of these behind a document-
# looking name so an unsuspecting user believes it's safe to open.
EXECUTABLE_EXTENSIONS = {
    "exe", "scr", "bat", "cmd", "com", "pif", "vbs", "vbe", "js", "jse",
    "wsf", "wsh", "msi", "ps1", "jar", "hta", "reg", "lnk", "apk",
}

# Archive/compression extensions - a lower-severity case: hiding a
# document behind an archive isn't inherently an attack (a legitimately
# compressed export exists), but this bot's hash check only ever sees
# the OUTER file - it can't look inside an archive, so the real content
# stays unverified either way.
ARCHIVE_EXTENSIONS = {"zip", "rar", "7z", "gz", "bz2", "xz", "z", "tar", "tgz"}

# Extensions this check treats as "looks like a normal document/media
# file" - the disguise target an attacker wants the user to believe
# they're opening. Only a SECOND extension chained after one of these is
# meaningful; a lone ".exe" is just an executable, not a disguise.
DOCUMENT_LIKE_EXTENSIONS = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv",
    "jpg", "jpeg", "png", "gif", "mp3", "mp4",
}


def check_filename(file_name: str) -> tuple[int, str] | None:
    """Flags the classic double-extension disguise ("invoice.pdf.exe",
    "Document.pdf.z"): a document-looking extension followed by a
    second, real extension that determines how the file actually
    behaves. Only fires when the INNER extension looks like an ordinary
    document/media type - two unrelated extensions on a file that isn't
    trying to look safe (e.g. "archive.tar.gz") isn't this pattern.
    """
    name = (file_name or "").lower()
    parts = name.rsplit(".", 2)
    if len(parts) < 3:
        return None
    _, inner_ext, outer_ext = parts
    if inner_ext not in DOCUMENT_LIKE_EXTENSIONS:
        return None
    if outer_ext in EXECUTABLE_EXTENSIONS:
        return (50, f"File name disguises an executable ('.{outer_ext}') behind a "
                    f"'.{inner_ext}' extension — a classic malware trick "
                    f"(e.g. 'invoice.pdf.exe').")
    if outer_ext in ARCHIVE_EXTENSIONS:
        return (20, f"File name hides a '.{inner_ext}' file inside a '.{outer_ext}' "
                    f"archive — this bot cannot see inside archives, so the real "
                    f"content is unverified.")
    return None


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


async def scan_file(file_hash: str, file_name: str) -> dict:
    """Single entry point for every flow that scans an uploaded file
    (handle_file, handle_text, handle_business_message) - merges the
    VirusTotal hash lookup with the filename-disguise check so neither
    signal has to be wired in separately at each of the three call
    sites. VirusTotal's `malicious` count stays purely AV-engine-derived
    (untouched by the filename heuristic, which is much weaker/fuzzier
    evidence, exactly like keyword_result never gets folded into a
    link's own score) - the filename finding rides along as its own key
    so callers can surface or reason over it without conflating the two.
    """
    result = await scan_vt_hash(file_hash)
    warning = check_filename(file_name)
    result["filename_warning"] = warning[1] if warning else None
    return result