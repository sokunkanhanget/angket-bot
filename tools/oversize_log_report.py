"""
tools/oversize_log_report.py
==============================
Summarise the bot's `[oversize-file]` log lines (ledger item B7).

Why: option B scores a deceptively named file that is too large to scan as
high risk. The decision court scored it without production data - there is no
labeled file corpus, so the false-positive rate is unknowable until these
lines are counted. Each line carries only a reason, a size BUCKET and a
`disguised` flag (scanner.unscannable_file_result); this reads them back.

Usage:
    python tools/oversize_log_report.py render-log.txt
    type render-log.txt | python tools/oversize_log_report.py

Copy the log out of Render (service -> Logs, search `[oversize-file]`) into a
file first. Nothing is fetched or sent anywhere.

Two things it reports beyond counts:
  - the share of events where the disguise rule fired (disguised=True), which
    is the number to compare against "were those real attacks?";
  - any `[oversize-file]` line that does NOT match the exact expected shape.
    The line is meant to carry no file name, id, hash or exact size, so an
    unexpected extra field is a possible privacy regression and is counted
    (never printed back).
"""

from __future__ import annotations

import re
import sys
from collections import Counter

_STRICT = re.compile(
    r"\[oversize-file\] reason=(?P<reason>[a-z_]+) size=(?P<size>[A-Za-z0-9\-]+) disguised=(?P<disguised>True|False)\s*$"
)
_TIMESTAMP = re.compile(r"^(\d{4}-\d{2}-\d{2}[T ][\d:.]+Z?)")


def summarize(lines) -> dict:
    reasons: Counter = Counter()
    sizes: Counter = Counter()
    disguised = total = unexpected = 0
    first = last = None

    for line in lines:
        if "[oversize-file]" not in line:
            continue
        stamp = _TIMESTAMP.match(line)
        if stamp:
            first = first or stamp.group(1)
            last = stamp.group(1)
        match = _STRICT.search(line)
        if match is None:
            unexpected += 1
            continue
        total += 1
        reasons[match["reason"]] += 1
        sizes[match["size"]] += 1
        disguised += match["disguised"] == "True"

    return {
        "total": total, "disguised": disguised, "unexpected": unexpected,
        "reasons": dict(reasons), "sizes": dict(sizes), "first": first, "last": last,
    }


def format_report(summary: dict) -> str:
    total, disguised = summary["total"], summary["disguised"]
    if total == 0 and summary["unexpected"] == 0:
        return ("No [oversize-file] lines found. Either no oversize file has arrived since "
                "this build was deployed, or the log window did not cover one.")

    out = [f"oversize events : {total}"]
    if summary["first"]:
        out.append(f"window          : {summary['first']}  ->  {summary['last']}")
    out.append(f"by reason       : {summary['reasons']}")
    out.append(f"by size         : {summary['sizes']}")
    share = f"{disguised / total:.0%}" if total else "n/a"
    out.append(f"rule fired      : {disguised} of {total} ({share}) had a disguised name")

    if summary["unexpected"]:
        out.append(
            f"\nWARNING: {summary['unexpected']} [oversize-file] line(s) do not match the expected "
            "shape. The line should carry only reason, size bucket and a disguised flag. "
            "An extra field may be a privacy regression - inspect scanner.unscannable_file_result."
        )
    if disguised:
        out.append(
            "\nREVIEW: each disguised=True line is the high-risk rule firing. Logs hold no file "
            "names by design, so check these against the senders/users who reported them. If they "
            "turn out to be legitimate files (e.g. 'report.xlsx.zip' from a colleague), reopen "
            "the rule: GATES-oversize.md item B7."
        )
    return "\n".join(out)


def main(argv: list[str]) -> int:
    if len(argv) > 1:
        with open(argv[1], encoding="utf-8", errors="replace") as handle:
            summary = summarize(handle)
    else:
        summary = summarize(sys.stdin)
    print(format_report(summary))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
