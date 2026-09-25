"""
tools/gate_loop_stall.py
==========================
Gate checker: the detector caches must not stall the asyncio event loop.

This measures the thing that actually hurts users rather than a proxy for
it. A ticker coroutine tries to wake every TICK_SECONDS; whatever the
cache work does to the loop shows up directly as a gap between ticks. In
a single-process, single-threaded bot every millisecond of that gap is a
millisecond in which no other user's scan, no Business-chat
notification, and no Telegram polling can make progress.

The number matters more here than it looks: Render's free tier gives
0.1 CPU, so a stall measured on a developer machine is roughly an order
of magnitude worse in production, and bot.py now runs up to 10 updates
concurrently.

This script is deliberately written to FAIL against the current blocking
implementation - that is gate G7's positive control. An absence check
that has never been seen to fail is not evidence.

Exit 0 and print EVENT_LOOP_UNBLOCKED_OK only when the worst observed
stall stays under MAX_STALL_SECONDS.
"""

from __future__ import annotations

import asyncio
import inspect
import sys
import time

import _gate_env  # noqa: F401 - sys.path + utf-8 stdout bootstrap

# One cache round trip per iteration, repeated enough times that a real
# per-call cost cannot hide in noise.
ITERATIONS = 40
TICK_SECONDS = 0.005
# Generous on purpose: the point is to catch tens-of-milliseconds
# blocking, not to police normal scheduler jitter. The pre-refactor
# measurement on this machine was ~3.1ms per call, so a run of 40 stacks
# far past this bound while any of it happens on the loop.
MAX_STALL_SECONDS = 0.050


async def _call(fn, *args):
    """Call a cache function whether it is sync (today) or async (after
    the refactor moves it onto asyncio.to_thread)."""
    result = fn(*args)
    if inspect.isawaitable(result):
        return await result
    return result


async def _ticker(stop: asyncio.Event, worst: list[float]) -> None:
    previous = time.perf_counter()
    while not stop.is_set():
        await asyncio.sleep(TICK_SECONDS)
        now = time.perf_counter()
        # Subtract the sleep we asked for; what remains is the loop being
        # unable to come back to us.
        worst.append(max(0.0, (now - previous) - TICK_SECONDS))
        previous = now


async def main() -> int:
    from bot.detectors.url import pipeline

    worst: list[float] = []
    stop = asyncio.Event()
    ticker = asyncio.create_task(_ticker(stop, worst))
    # Let the ticker settle so start-up cost is not attributed to the cache.
    await asyncio.sleep(0.05)
    worst.clear()

    started = time.perf_counter()
    for index in range(ITERATIONS):
        await _call(pipeline._verdict_cache_get, f"https://gate.example/probe/{index}")
    elapsed = time.perf_counter() - started

    stop.set()
    await ticker

    if not worst:
        print("FAIL: the ticker never sampled; the measurement is meaningless", file=sys.stderr)
        return 1

    worst_stall = max(worst)
    print(f"cache calls        : {ITERATIONS}")
    print(f"total wall time    : {elapsed * 1000:.1f} ms")
    print(f"worst loop stall   : {worst_stall * 1000:.2f} ms")
    print(f"allowed stall      : {MAX_STALL_SECONDS * 1000:.2f} ms")

    if worst_stall > MAX_STALL_SECONDS:
        print(
            f"FAIL: the event loop was blocked for {worst_stall * 1000:.2f} ms, "
            f"over the {MAX_STALL_SECONDS * 1000:.2f} ms budget",
            file=sys.stderr,
        )
        return 1

    print("EVENT_LOOP_UNBLOCKED_OK")
    return 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
