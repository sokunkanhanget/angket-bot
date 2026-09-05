"""
bot/detectors/file/scanner.py
================================
Orchestrator: merges the offline filename-disguise check with the
online VirusTotal hash lookup into one verdict, same role pipeline.py
plays for url/offline + url/online. Re-exports check_filename and
scan_vt_hash so every existing caller (handlers, the run-angket-bot
driver, tests) keeps working unchanged after the offline/online split -
a pure file-organization change, not an API change.
"""

from __future__ import annotations

import hashlib
import io

from telegram.ext import ContextTypes

from bot.detectors.file.offline.filename_check import check_filename
from bot.detectors.file.online.virustotal import scan_vt_hash


async def download_and_hash(context: ContextTypes.DEFAULT_TYPE, file_id: str) -> str:
    """Download a Telegram file and return its SHA-256 hex digest, ready
    for scan_vt_hash() - shared by every flow that scans an uploaded
    file (handle_file, handle_business_message) so a future fix (e.g. a
    size guard) only needs to land in one place."""
    file_info = await context.bot.get_file(file_id)
    buf = io.BytesIO()
    await file_info.download_to_memory(buf)
    return hashlib.sha256(buf.getvalue()).hexdigest()


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
