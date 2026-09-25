"""
tools/gate_sqlite_pool_wired.py
=================================
Gate checker: the five migrated modules must actually reference
bot/storage/sqlite_pool. Paired with gate_no_raw_sqlite.py, which only
proves the OLD mechanism is gone - on its own that would also pass if a
module simply stopped touching sqlite altogether.

Checked by import, not by grepping the source, so a mention inside a
comment cannot satisfy it.
"""

from __future__ import annotations

import importlib
import sys

import _gate_env  # noqa: F401 - sys.path + utf-8 stdout bootstrap

MIGRATED_MODULES = (
    "bot.detectors.url.pipeline",
    "bot.detectors.url.online.cert_info",
    "bot.detectors.url.online.domain_info",
    "bot.detectors.url.online.threat_intel",
    "bot.detectors.file.online.virustotal",
)


def main() -> int:
    from bot.storage import sqlite_pool

    missing = []
    for name in MIGRATED_MODULES:
        module = importlib.import_module(name)
        if getattr(module, "sqlite_pool", None) is not sqlite_pool:
            missing.append(name)

    if missing:
        print("FAIL: these modules do not use sqlite_pool: " + ", ".join(missing), file=sys.stderr)
        return 1
    print("SQLITE_POOL_WIRED_OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
