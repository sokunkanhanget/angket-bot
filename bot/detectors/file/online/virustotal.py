"""
bot/detectors/file/online/virustotal.py
==========================================
Real network call - a live VirusTotal hash lookup. Moved out of
scanner.py so the offline (filename heuristic) and online (this) halves
of file scanning are as clearly separated as url/offline vs url/online
already are.
"""

from __future__ import annotations

import vt

from bot.config import VIRUSTOTAL_API_KEY


async def scan_vt_hash(file_hash: str) -> dict:
    """`checked` is the important field callers need that didn't exist
    before: `found: False` used to mean ONE thing - "VirusTotal has never
    seen this hash" - whether that was actually true (a confirmed
    NotFoundError) or VirusTotal itself was down/rate-limited/unreachable
    (any other APIError, or a raw connection failure this used to let
    propagate uncaught past this function entirely). A caller showing
    "this file's signature isn't on VirusTotal" during a real VT outage
    is actively misleading - it reads as a real (if weak) safety signal
    when there's actually no signal at all. `checked=True` means VT was
    actually reached and gave a real answer (found True or False);
    `checked=False` means it wasn't, and `found` is meaningless either way.
    """
    try:
        async with vt.Client(VIRUSTOTAL_API_KEY) as client:
            file_obj = await client.get_object_async(f"/files/{file_hash}")
            stats = file_obj.last_analysis_stats
            results = getattr(file_obj, "last_analysis_results", {})

            def get_engine_status(engine_name: str) -> str:
                engine_data = results.get(engine_name, {})
                category = engine_data.get("category", "undetected")
                result = engine_data.get("result")
                if category == "malicious":
                    return f"Detected ({result})"
                if category == "suspicious":
                    return f"Suspicious ({result})"
                return "Clean"

            return {
                "checked": True,
                "found": True,
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "total": sum(stats.values()),
                "top_engines": {
                    "Microsoft": get_engine_status("Microsoft"),
                    "Kaspersky": get_engine_status("Kaspersky"),
                    "BitDefender": get_engine_status("BitDefender"),
                },
            }
    except vt.APIError as error:
        if error.code == "NotFoundError":
            return {"checked": True, "found": False}
        return {"checked": False, "found": False, "error": str(error)}
    except Exception as error:  # noqa: BLE001 - a connection-level failure (network down,
        # DNS, timeout - anything below the vt.APIError layer) must still
        # come back as "VT couldn't be checked", not crash the caller.
        return {"checked": False, "found": False, "error": str(error)}
