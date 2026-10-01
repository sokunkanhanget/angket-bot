"""
tools/gate_rar_no_binary.py
=============================
Gate checker: content_check.py must list RAR archives with NO external
binary available - Render's free instance has no unrar, 7z or bsdtar, so
anything that silently shells out would pass locally (this machine has
WinRAR) and fail in production.

Rather than trusting that rarfile happens not to need a tool, this makes
every tool rarfile could reach for unfindable: PATH is emptied and each of
rarfile's tool-name settings is pointed at a path that does not exist. The
listing must still work on both RAR4 and RAR5, and encrypted headers must
still be detected.
"""

from __future__ import annotations

import os
import shutil
import sys

import _gate_env  # noqa: F401 - sys.path + utf-8 stdout bootstrap

FIXTURES = _gate_env.REPO_ROOT / "tests" / "fixtures" / "content"


def main() -> int:
    os.environ["PATH"] = ""
    import rarfile

    for setting in ("UNRAR_TOOL", "SEVENZIP_TOOL", "SEVENZIP2_TOOL", "BSDTAR_TOOL", "UNAR_TOOL"):
        if hasattr(rarfile, setting):
            setattr(rarfile, setting, "Z:/definitely/not/installed")

    leaked = [tool for tool in ("unrar", "rar", "7z", "bsdtar", "unar") if shutil.which(tool)]
    if leaked:
        print(f"FAIL: could not hide external tools: {leaked}", file=sys.stderr)
        return 1

    from bot.detectors.file.offline.content_check import inspect_content

    expectations = {
        "disguised_entry_rar5.rar": "content_archive_disguised_entry",
        "disguised_entry_rar4.rar": "content_archive_disguised_entry",
        "executable_entry.rar": "content_archive_executable",
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
