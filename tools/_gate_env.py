"""
tools/_gate_env.py
====================
Shared bootstrap for the gate checker scripts.

Every other verification in this repo is invoked as
`PYTHONPATH=. PYTHONIOENCODING=utf-8 .venv/Scripts/python ...` from Git
Bash. The unlazy gate checker does not use Git Bash - it resolves a
shell itself and lands on `cmd.exe` on Windows, where `VAR=value cmd` is
not valid syntax and the whole command fails before Python ever starts
("'PYTHONPATH' is not recognized as an internal or external command").

Rather than depend on a particular shell, each gate script imports this
first and gets the same two guarantees the env prefix used to provide:
the repository root on sys.path, and UTF-8 stdout. That makes the checks
runnable from cmd.exe, Git Bash, PowerShell or CI without change, which
is what the skill means by preferring repository-owned scripts over
shell-specific invocations.
"""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

for _stream in (sys.stdout, sys.stderr):
    try:
        _stream.reconfigure(encoding="utf-8")
    except (AttributeError, ValueError):  # pragma: no cover - already utf-8, or not a real tty
        pass
