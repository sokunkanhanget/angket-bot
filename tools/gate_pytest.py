"""
tools/gate_pytest.py
======================
Gate checker: the whole suite must pass.

Prints a success-only token rather than letting the gate match pytest's
own output, because "passed" also appears in "1 failed, 759 passed" -
the ledger linter flags that as a weak expectation, correctly.
"""

from __future__ import annotations

import subprocess
import sys

import _gate_env  # noqa: F401 - sys.path + utf-8 stdout bootstrap


def main() -> int:
    completed = subprocess.run(
        [sys.executable, "-m", "pytest", "-q"],
        cwd=_gate_env.REPO_ROOT,
        text=True,
    )
    if completed.returncode != 0:
        print(f"FAIL: pytest exited {completed.returncode}", file=sys.stderr)
        return 1
    print("PYTEST_ALL_GREEN")
    return 0


if __name__ == "__main__":
    sys.exit(main())
