"""
bot/response/status_animation.py
=====================================
Shared waiting status for scans. The message stays on the existing
"Checking" label while the real async work runs, rather than cycling
through guessed internal stages that are not synchronized with the
actual work. The task is still launched via asyncio.create_task
alongside the real work and cancelled once it is done, so all scan
surfaces keep the same concurrency and cleanup behavior.

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

# Keep this list for the existing handler call sites. Only the checking
# label is shown while a scan is waiting for its final response; the dots
# below are the only animation.
STATUS_STAGE_KEYS = [
    "status_checking",
]
CHECKING_DOTS = ("", ".", "..", "...")
STATUS_STAGE_INTERVAL_SECONDS = 1.5


async def animate_status(status_message, lang: str, suffix: str = "") -> None:
    """Launch via `asyncio.create_task(animate_status(...))` alongside
    the real work, then stop it with `await stop_status_animation(task)`
    (NOT a bare `task.cancel(); await task`) once that work is done -
    see stop_status_animation's own docstring for why.

    `suffix`: appended after the checking dots (e.g. file_handler.py
    passes " `filename.pdf`..." so which file is in progress stays
    visible throughout the animation)."""
    dot_index = 0
    try:
        while True:
            await asyncio.sleep(STATUS_STAGE_INTERVAL_SECONDS)
            dot_index = (dot_index + 1) % len(CHECKING_DOTS)
            try:
                await status_message.edit_text(
                    f"{t(lang, STATUS_STAGE_KEYS[0])}{CHECKING_DOTS[dot_index]}{suffix}",
                    parse_mode="Markdown",
                )
            except Exception:
                pass  # transient edit failure (e.g. rate limit) - skip this frame
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
