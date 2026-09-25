"""
tools/gate_no_raw_sqlite.py
=============================
Gate checker: none of the five detector caches may open its own sqlite
connection any more. They must borrow a pooled, per-thread connection
from bot/storage/sqlite_pool.py instead.

AST-based rather than text matching, so a `sqlite3.connect` mentioned in
a comment, a docstring or a string literal can neither satisfy nor break
this gate - only a real call node counts.
"""

from __future__ import annotations

import ast
import sys

import _gate_env  # noqa: F401 - sys.path + utf-8 stdout bootstrap

MIGRATED_MODULES = (
    "bot/detectors/url/pipeline.py",
    "bot/detectors/url/online/cert_info.py",
    "bot/detectors/url/online/domain_info.py",
    "bot/detectors/url/online/threat_intel.py",
    "bot/detectors/file/online/virustotal.py",
)


def _raw_connect_calls(path):
    source = (_gate_env.REPO_ROOT / path).read_text(encoding="utf-8")
    for node in ast.walk(ast.parse(source)):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "connect"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "sqlite3"
        ):
            yield node.lineno


def main() -> int:
    offenders = [
        f"{path}:{line}" for path in MIGRATED_MODULES for line in _raw_connect_calls(path)
    ]
    if offenders:
        print("FAIL: raw sqlite3.connect remains at " + ", ".join(offenders), file=sys.stderr)
        return 1
    print("SQLITE_POOL_MIGRATION_OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
