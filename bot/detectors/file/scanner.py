"""
bot/detectors/file/scanner.py
================================
Orchestrator: merges the offline filename-disguise check with the
online VirusTotal hash lookup into one verdict, same role pipeline.py
plays for url/offline + url/online. Re-exports check_filename,
scan_vt_hash, and cached_result so every existing caller (handlers, the
run-angket-bot driver, tests) keeps working unchanged after the
offline/online split - a pure file-organization change, not an API
change.
"""

from __future__ import annotations

import asyncio
import hashlib
import io

from telegram.ext import ContextTypes

from bot.detectors.file.offline.filename_check import check_filename
from bot.detectors.file.online.virustotal import cached_result, scan_vt_hash


# The size guard this module's own docstring anticipated (2026-09-24,
# security review). Telegram's Bot API caps getFile downloads at 20MB
# today, so this is normally a no-op - but nothing in this process
# enforced that itself, and the whole file is buffered in RAM
# (io.BytesIO) on a 512MB Render instance where several concurrent
# uploads already add up. Checked against the size Telegram reports
# BEFORE downloading a single byte, so an oversized file costs no
# bandwidth and no memory at all.
#
# Deliberately generous rather than tight: a real 13MB file has been
# legitimately scanned in production, so anything near that would break
# real use. This guards the pathological case, it does not police
# ordinary uploads.
MAX_DOWNLOAD_BYTES = 20 * 1024 * 1024

# How many file downloads may be in flight at once, process-wide
# (2026-09-24, added together with bot.py's .concurrent_updates(10)).
#
# Raising update concurrency is safe for text/link scans - those are
# network-wait-bound and hold at most a 200KB page - but a FILE scan
# buffers the whole file in RAM (io.BytesIO below), up to
# MAX_DOWNLOAD_BYTES each. With 10 updates running concurrently, 10
# simultaneous uploads would be up to 200MB of buffers on top of a
# measured ~94MB steady-state RSS, against Render's free 512MB. This
# keeps the worst case at 3 * 20MB = 60MB instead.
#
# Deliberately in this module, not in a handler: all THREE file-scanning
# entry points (handlers/file_handler.py, text_handler.py's
# _scan_attached_file, url_handler.py's business-chat equivalent) come
# through this one function, so guarding here can't be bypassed by a
# path that forgets it. Waiting for a slot is just backpressure - the
# status animation the user is already watching keeps running.
_FILE_SCAN_SLOTS = asyncio.Semaphore(3)


class FileTooLargeError(Exception):
    """download_and_hash refused the file on size alone, before any
    download. Callers already wrap download_and_hash in a broad except
    that shows the user the generic "scan failed" message, so this needs
    no new handling at any call site to degrade correctly."""


async def download_and_hash(context: ContextTypes.DEFAULT_TYPE, file_id: str) -> str:
    """Download a Telegram file and return its SHA-256 hex digest, ready
    for scan_vt_hash() - shared by every flow that scans an uploaded
    file (handle_file, handle_business_message) so a fix like the size
    guard above only needs to land in one place."""
    file_info = await context.bot.get_file(file_id)

    # file_size can be None (Telegram doesn't always populate it); that's
    # not treated as a refusal, since the API's own 20MB ceiling still
    # applies to the download itself.
    size = getattr(file_info, "file_size", None)
    if isinstance(size, int) and size > MAX_DOWNLOAD_BYTES:
        raise FileTooLargeError(f"file is {size} bytes, over the {MAX_DOWNLOAD_BYTES}-byte scan limit")

    # Size check first, slot second: an oversized file is rejected without
    # ever occupying a slot other users are waiting for.
    async with _FILE_SCAN_SLOTS:
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

    Never raises: scan_vt_hash() itself catches every failure mode (a
    confirmed "not on VT" vs. VT itself being unreachable - see its own
    docstring for `checked`) and check_filename() is pure/local, so a
    caller always gets a real dict back, even when VirusTotal is fully
    down - handle_file's own reply-building can then use the filename
    warning as a fallback signal instead of showing nothing at all.

    filename_risk_score is the raw check_filename() severity number
    (0 when there's no warning) - kept separate from the warning text so
    a caller building its OWN risk percentage (unlike VT's
    engine-count-derived one) has a real number to show, not just prose.

    The warning is carried as a TRANSLATION KEY plus format params
    (filename_warning_key / filename_warning_params) rather than a
    finished English sentence: this layer is pure and offline and has no
    idea which language the eventual reply is in, so each display site
    renders it (see filename_check.py's docstring).
    """
    result = await scan_vt_hash(file_hash)
    warning = check_filename(file_name)
    result["filename_warning_key"] = warning[1] if warning else None
    result["filename_warning_params"] = warning[2] if warning else {}
    result["filename_risk_score"] = warning[0] if warning else 0
    return result
