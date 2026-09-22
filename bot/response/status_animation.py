"""
bot/response/status_animation.py
=====================================
Shared waiting status for scans. The message stays on ONE label per
real phase while the corresponding real async work runs - never a
guessed internal stage list unsynchronized from the actual work (an
earlier multi-stage version was rejected for exactly that; its dead
translation keys are gone as of 2026-09-22, see translate/en.py's
status_checking/status_analyzing comment). The task is still launched
via asyncio.create_task alongside the real work and cancelled once it
is done, so all scan surfaces keep the same concurrency and cleanup
behavior.

Two-phase support (2026-09-22): the unified-check surfaces (private DM,
group /check, Business chat) genuinely have two real, discrete phases -
gathering link/file evidence (concurrent asyncio.gather), then one
sequential Gemini call - confirmed via a real code-path trace, not
guessed. The optional `phase` asyncio.Event lets a caller flip the
label at the exact real moment that boundary is crossed (right after
its own gather awaits return, right before calling analyze_unified) -
see text_handler.py's _run_full_check_and_reply and url_handler.py's
handle_business_message for the two real call sites. file_handler.py's
own animation stays single-phase (plain VirusTotal lookup, no second
real phase to surface) and passes no `phase` at all - `phase=None`
behaves exactly as before this change, always showing the phase-A label.

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

# The phase-A label, also used directly by every handler for the FIRST
# status message it sends (before the animation task even starts, so
# phase can't be set yet - always the checking label at that point).
STATUS_CHECKING_KEY = "status_checking"
CHECKING_DOTS = ("", ".", "..", "...")
# 1.5 -> 0.8 (2026-09-22, direct user spec: "faster loading animation") -
# safe to drop this far: every edit below already swallows a failed
# edit_text silently (e.g. a real Telegram rate-limit response), so a
# faster cycle degrades gracefully - worst case is a skipped frame, not
# an error surfaced to the user.
STATUS_STAGE_INTERVAL_SECONDS = 0.8


async def animate_status(status_message, lang: str, suffix: str = "", prefix: str = "",
                          phase: asyncio.Event | None = None) -> None:
    """Launch via `asyncio.create_task(animate_status(...))` alongside
    the real work, then stop it with `await stop_status_animation(task)`
    (NOT a bare `task.cancel(); await task`) once that work is done -
    see stop_status_animation's own docstring for why.

    `suffix`: appended after the checking dots (e.g. file_handler.py
    passes " `filename.pdf`..." so which file is in progress stays
    visible throughout the animation).

    `prefix`: prepended before the checking line (e.g.
    handle_business_message passes the "New Activity Detected" +
    sender header so the owner sees WHO the incoming message is from
    immediately, not just a bare "Checking" with no context, while the
    real unified check is still running).

    `phase`: optional asyncio.Event a caller flips once evidence-
    gathering is done and the real Gemini call has started - unset
    (or omitted entirely) shows "status_checking", set shows
    "status_analyzing". Checked once per frame, not once at task start,
    so the label can genuinely change mid-animation the moment the
    real code crosses that boundary."""
    dot_index = 0
    try:
        while True:
            await asyncio.sleep(STATUS_STAGE_INTERVAL_SECONDS)
            dot_index = (dot_index + 1) % len(CHECKING_DOTS)
            label_key = "status_analyzing" if (phase is not None and phase.is_set()) else STATUS_CHECKING_KEY
            try:
                await status_message.edit_text(
                    f"{prefix}{t(lang, label_key)}{CHECKING_DOTS[dot_index]}{suffix}",
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
