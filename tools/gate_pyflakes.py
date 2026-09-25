"""
tools/gate_pyflakes.py
========================
Gate checker: pyflakes must report nothing beyond the one long-standing
finding this repo already carries.

That finding is scanner.py re-exporting `cached_result` for its callers,
which pyflakes reads as an unused import. It predates this work and is
excluded by name rather than by count, so a NEW unused import cannot
hide behind the same allowance.
"""

from __future__ import annotations

import subprocess
import sys

import _gate_env  # noqa: F401 - sys.path + utf-8 stdout bootstrap

KNOWN_PRE_EXISTING = "virustotal.cached_result"


def main() -> int:
    completed = subprocess.run(
        [sys.executable, "-m", "pyflakes", "bot/"],
        cwd=_gate_env.REPO_ROOT,
        capture_output=True,
        text=True,
    )
    findings = [
        line for line in completed.stdout.strip().splitlines()
        if line.strip() and KNOWN_PRE_EXISTING not in line
    ]
    if findings:
        print("FAIL: new pyflakes findings:", file=sys.stderr)
        for line in findings:
            print("  " + line, file=sys.stderr)
        return 1
    print("PYFLAKES_BASELINE_OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
