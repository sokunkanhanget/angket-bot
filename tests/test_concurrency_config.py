"""
tests/test_concurrency_config.py
==================================
Locks in the throughput-related wiring added 2026-09-24, after measuring
that the bot could only ever serve ONE user at a time.

python-telegram-bot defaults concurrent_updates to 1, so every update was
processed to completion before the next one started. Since a single scan
is 5-15s of almost pure network WAIT (Gemini 3-13s observed, plus
VirusTotal, Supabase, Modal and the URL trace), that left the CPU idle
while users queued - 100 people messaging at once meant the last of them
waited roughly 10 minutes. None of that was a hardware limit.

These are config assertions rather than behavior tests on purpose: the
values are load-bearing capacity decisions with real ceilings behind
them (see bot.py's own comment), and a silent revert to the default would
be invisible until it showed up as a queue in production.
"""

from unittest.mock import AsyncMock, MagicMock

import pytest
from telegram.ext import AIORateLimiter, Application


def _build_app_like_main_does():
    """Same builder chain bot.py's main() uses, minus polling - including
    going through bot.py's OWN _build_rate_limiter(), so this can't drift
    from what really ships."""
    import bot.bot as bot_module

    builder = Application.builder().token("123456:FAKE_TOKEN_FOR_THIS_TEST")
    limiter = bot_module._build_rate_limiter()
    if limiter is not None:
        builder = builder.rate_limiter(limiter)
    return builder.concurrent_updates(10).build()


def test_the_bot_processes_more_than_one_update_at_a_time():
    app = _build_app_like_main_does()

    # 1 is PTB's own default and the thing this exists to prevent.
    assert app.concurrent_updates > 1
    assert app.update_processor.max_concurrent_updates == 10


def test_a_rate_limiter_is_configured():
    # Raising concurrency makes Telegram 429s genuinely reachable:
    # status_animation.py edits every 0.8s per in-flight scan, so N
    # concurrent scans cost N*1.25 requests/sec on animation alone
    # against Telegram's ~30/sec ceiling. Without a limiter those surface
    # as ordinary errors instead of being throttled.
    app = _build_app_like_main_does()

    assert app.bot.rate_limiter is not None
    assert isinstance(app.bot.rate_limiter, AIORateLimiter)


def test_the_rate_limiter_actually_retries_flood_limits():
    # PTB's OWN default for max_retries is 0, and at 0 the retry loop
    # (`for i in range(max_retries + 1)` in
    # AIORateLimiter.process_request) runs exactly once and re-raises
    # RetryAfter instead of sleeping it off. So relying on the default
    # would give proactive throttling but NO retry - the bot would still
    # surface a failed reply on a real flood limit.
    import bot.bot as bot_module

    limiter = bot_module._build_rate_limiter()

    assert limiter is not None
    assert limiter._max_retries > 0


def test_a_missing_rate_limiter_dependency_does_not_take_the_bot_down():
    # AIORateLimiter.__init__ raises RuntimeError when the optional
    # `[rate-limiter]` extra isn't installed. Letting that propagate
    # would kill the WHOLE bot at startup over an optimization - and the
    # Render build command lives outside this repo, so the dependency
    # landing in production is not something this codebase can guarantee.
    # Every other optional dependency here degrades instead of crashing.
    import bot.bot as bot_module

    limiter_module = __import__(AIORateLimiter.__module__, fromlist=["x"])
    original = limiter_module.AIO_LIMITER_AVAILABLE
    try:
        limiter_module.AIO_LIMITER_AVAILABLE = False
        assert bot_module._build_rate_limiter() is None
    finally:
        limiter_module.AIO_LIMITER_AVAILABLE = original

    # ...and the real dependency IS present in this environment, so the
    # test above is exercising the fallback, not masking a broken install.
    assert bot_module._build_rate_limiter() is not None


def test_bot_module_really_wires_both_settings():
    """The tests above prove the builder chain works; this proves bot.py
    actually uses it, so a future edit that drops either call fails here
    rather than silently reverting capacity to the old default."""
    import inspect

    import bot.bot as bot_module

    source = inspect.getsource(bot_module)
    assert ".concurrent_updates(" in source
    assert ".rate_limiter(" in source
    assert "_build_rate_limiter()" in source


def test_concurrent_file_downloads_are_capped_tighter_than_update_concurrency():
    # A text/link scan holds at most a 200KB page, but a FILE scan
    # buffers the whole file in RAM (up to MAX_DOWNLOAD_BYTES). At 10
    # concurrent updates, 10 simultaneous uploads would be up to 200MB on
    # top of a measured ~94MB steady-state RSS, against Render's free
    # 512MB - so file downloads get their own, much tighter limit.
    from bot.detectors.file.scanner import _FILE_SCAN_SLOTS, MAX_DOWNLOAD_BYTES

    app = _build_app_like_main_does()
    slots = _FILE_SCAN_SLOTS._value

    assert slots < app.update_processor.max_concurrent_updates
    worst_case_bytes = slots * MAX_DOWNLOAD_BYTES
    assert worst_case_bytes <= 64 * 1024 * 1024, (
        f"worst-case file buffering is {worst_case_bytes / 1024 / 1024:.0f}MB, "
        "too close to the 512MB instance limit"
    )


def test_the_file_slot_guard_covers_every_scanning_entry_point():
    # The guard lives in scanner.download_and_hash rather than in a
    # handler precisely so none of the three real entry points
    # (file_handler, text_handler's _scan_attached_file, url_handler's
    # business-chat equivalent) can bypass it.
    import inspect

    from bot.detectors.file import scanner

    source = inspect.getsource(scanner.download_and_hash)
    assert "_FILE_SCAN_SLOTS" in source

    for module_name in (
        "bot.handlers.file_handler",
        "bot.handlers.text_handler",
        "bot.handlers.url_handler",
    ):
        module = __import__(module_name, fromlist=["download_and_hash"])
        assert module.download_and_hash is scanner.download_and_hash


@pytest.mark.asyncio
async def test_the_file_slot_guard_really_limits_concurrent_downloads():
    # Behavioral, not just a config assertion: proves the semaphore
    # actually holds downloads back rather than merely existing.
    import asyncio

    from bot.detectors.file import scanner

    in_flight = 0
    peak = 0

    async def _slow_download(buf):
        nonlocal in_flight, peak
        in_flight += 1
        peak = max(peak, in_flight)
        await asyncio.sleep(0.05)
        buf.write(b"bytes")
        in_flight -= 1

    def _make_context():
        context = MagicMock()
        file_info = MagicMock(file_size=1024)
        file_info.download_to_memory = AsyncMock(side_effect=_slow_download)
        context.bot.get_file = AsyncMock(return_value=file_info)
        return context

    await asyncio.gather(
        *(scanner.download_and_hash(_make_context(), f"file-{i}") for i in range(10))
    )

    # All 10 completed, but never more than the slot count at once.
    assert peak <= scanner._FILE_SCAN_SLOTS._value + 0  # semaphore ceiling
    assert peak > 1, "sanity: the test itself must actually overlap work"
