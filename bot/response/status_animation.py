"""
bot/response/status_animation.py
=====================================
Shared "what is the bot doing right now" status animation - a TIMED
FAKE SEQUENCE (direct user choice, 2026-09-10): cycles through stage
labels (Checking -> Searching -> Constructing -> Formatting ->
Generating -> back to Checking) on a fixed timer while the real async
work runs concurrently, rather than being genuinely synced to actual
internal steps. Generalizes text_handler.py's original dot-only
"Checking . . ." animation (still the same concurrency shape: launched
via asyncio.create_task alongside the real work, cancelled once it's
done) to real stage names, and extends the same visibility to file
scans and the group-chat link checker, which previously showed either
no animation or nothing at all - the file-scan case is what surfaced
this: a slow/stalled file download or VirusTotal call gave zero
visual feedback beyond one static "Scanning..." message.

Confirmed this does NOT slow down the real work it runs alongside:
this task spends ~100% of its time inside asyncio.sleep (yielding to
the event loop), and the real work is itself await-based I/O (Gemini/
VirusTotal/Supabase network calls) that also spends most of its time
waiting, not computing - two mostly-idle-waiting coroutines interleave
on one event loop for free. Not a claim made in the abstract - this
project already ran the identical concurrency shape in production
(text_handler.py's dot animation) before this file existed.
"""

from __future__ import annotations

import asyncio

from bot.response.buttons import t

# Order matters - this is the actual cycle shown to the user. Keys must
# exist in bot/response/translate/*.py's TEXT dicts.
STATUS_STAGE_KEYS = [
    "status_checking",
    "status_searching",
    "status_constructing",
    "status_formatting",
    "status_generating",
]
STATUS_STAGE_INTERVAL_SECONDS = 1.5


async def animate_status(status_message, lang: str, suffix: str = "") -> None:
    """Launch via `asyncio.create_task(animate_status(...))` alongside
    the real work, then stop it with `await stop_status_animation(task)`
    (NOT a bare `task.cancel(); await task`) once that work is done -
    see stop_status_animation's own docstring for why.

    `suffix`: appended after each stage label (e.g. file_handler.py
    passes " `filename.pdf`..." so which file is in progress stays
    visible across every frame, not just the first one)."""
    i = 0
    try:
        while True:
            await asyncio.sleep(STATUS_STAGE_INTERVAL_SECONDS)
            i = (i + 1) % len(STATUS_STAGE_KEYS)
            try:
                await status_message.edit_text(
                    f"{t(lang, STATUS_STAGE_KEYS[i])}{suffix}", parse_mode="Markdown",
                )
            except Exception:
                pass  # transient edit failure (e.g. rate limit) - just skip this frame
    except asyncio.CancelledError:
        pass


async def stop_status_animation(task: asyncio.Task) -> None:
    """The correct way to stop an animate_status() task - a real, live-
    confirmed asyncio gotcha, not a hypothetical: when the real work
    this task runs alongside fails/completes on its VERY FIRST await
    (e.g. an immediately-raising mocked/real error, before the event
    loop ever gets a chance to run this task even once),
    `task.cancel()` followed by a bare `await task` re-raises
    CancelledError to the AWAITER - animate_status's own internal
    `except CancelledError` never even runs, because its coroutine
    frame never started executing at all. A bare `await animation_task`
    at every call site would then crash the handler on exactly the
    fast-failing-download case this project's file-scan work already
    cares about getting right. Centralized here once instead of
    repeating `try: await task except CancelledError: pass` at every
    call site and risking someone getting it wrong again."""
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
