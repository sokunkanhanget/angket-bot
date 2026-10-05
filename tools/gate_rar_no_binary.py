"""
tools/gate_rar_no_binary.py
=============================
Gate checker: content_check.py must list RAR archives with NO external
binary available - Render's free instance has no unrar, 7z or bsdtar, so
anything that silently shells out would pass locally (this machine has
WinRAR) and fail in production.

Since 2026-10-05 RAR is read by content_check.py's own header walker, not
the rarfile library (which parsed a whole hostile directory before any cap
applied - a reproduced out-of-memory). This gate still empties PATH so any
future regression that reaches for a binary fails here, and checks the
walker against the real WinRAR-built fixtures: RAR4 and RAR5, plain,
entry-encrypted and header-encrypted, plus a benign negative control.
"""

from __future__ import annotations

import os
import shutil
import sys

import _gate_env  # noqa: F401 - sys.path + utf-8 stdout bootstrap

FIXTURES = _gate_env.REPO_ROOT / "tests" / "fixtures" / "content"


def main() -> int:
    os.environ["PATH"] = ""
    leaked = [tool for tool in ("unrar", "rar", "7z", "bsdtar", "unar") if shutil.which(tool)]
    if leaked:
        print(f"FAIL: could not hide external tools: {leaked}", file=sys.stderr)
        return 1

    from bot.detectors.file.offline.content_check import inspect_content

    expectations = {
        "disguised_entry_rar5.rar": "content_archive_disguised_entry",
        "disguised_entry_rar4.rar": "content_archive_disguised_entry",
        "executable_entry.rar": "content_archive_executable",
        "encrypted_entries.rar": "content_archive_encrypted",
        "encrypted_headers.rar": "content_archive_encrypted",
    }
    for fixture, expected_key in expectations.items():
        keys = {f["key"] for f in inspect_content((FIXTURES / fixture).read_bytes(), "x.rar")}
        if expected_key not in keys:
            print(f"FAIL: {fixture} gave {sorted(keys)}, expected {expected_key}", file=sys.stderr)
            return 1

    if inspect_content((FIXTURES / "benign_documents.rar").read_bytes(), "x.rar"):
        print("FAIL: benign RAR produced a finding", file=sys.stderr)
        return 1

    print("RAR_LISTING_WITHOUT_BINARY_OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
