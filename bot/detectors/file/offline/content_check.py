"""
bot/detectors/file/offline/content_check.py
=============================================
Local, offline inspection of a file's actual BYTES - added 2026-10-01 so
file detection no longer rests entirely on VirusTotal knowing the hash.

Why: hash lookup is the weakest antivirus method against new malware.
Changing one byte or repacking an archive produces a hash nobody has seen,
and malware aimed at one country's users is exactly the kind VirusTotal
has not seen yet. The bot already downloads every file into memory to
hash it; until now it threw those bytes away. This module looks at them.

What it checks (each returns a finding on bot/response/risk_scale.py's
shared bands - medium from 25, high from 60):

  85  disguised executable  - bytes are a Windows/Linux/macOS program or an
                              Android app, but the name claims a document
  85  right-to-left trick   - a hidden U+202E-style control character fakes
                              the visible extension ("invoice‮fdp.exe")
  85  disguised entry       - an archive holds "x.pdf.exe" or an RLO name
  70  archive executable    - an archive holds a program or script
  70  PDF /Launch           - the PDF asks the reader to start a program
  50  Office macros         - VBA project inside a .docm/.xlsm/.doc/.xls
  45  encrypted archive     - password-protected contents cannot be checked
  45  PDF JavaScript        - embedded /JavaScript or /JS action
  30  disguised archive     - name claims a document, bytes are ZIP/RAR/7z

These are HEURISTICS, not malware detection. A finding means "this file
carries a known warning sign", never "this file is malware", and finding
nothing proves nothing - which is why a file with no antivirus answer and
no finding is reported as "unverified", not safe (see file_risk.py).

Safety properties, because the input is attacker-controlled by design:
  - Nothing is ever extracted or executed. Archives are LISTED only, from
    their own directory records.
  - Work is bounded: the caller caps input at MAX_DOWNLOAD_BYTES (20MB),
    archives are read for at most MAX_ARCHIVE_ENTRIES names, and ZIPs that
    declare more than that in their end-of-central-directory record are
    not parsed at all.
  - Every byte scan is a linear str/bytes search or a regex with no nested
    quantifiers - this repo already shipped one real ReDoS on attacker
    HTML (network.py, 2026-09-24), so no backtracking patterns here.
  - Any parse failure yields no finding rather than an exception: a corrupt
    file must not crash the scan, and must not be scored as a finding
    either.
  - RAR is listed with `rarfile`, pure Python, verified 2026-10-01 to list
    RAR4 and RAR5 entries with no unrar/7z/bsdtar binary present - Render
    has none.

Known limits, stated rather than hidden: nested archives are not opened;
a RAR whose HEADERS are encrypted (-hp) shows no entry names at all, only
that it is password-protected; PDF names written with #xx hex escapes
(e.g. /J#61vaScript) are not decoded; 7z is recognised but not listed.

Like filename_check.py, findings carry a TRANSLATION KEY plus params, not
finished text - this layer does not know which language the reply is in.
"""

from __future__ import annotations

import io
import logging
import re
import struct
import zipfile

from bot.detectors.file.offline.filename_check import DOCUMENT_LIKE_EXTENSIONS, EXECUTABLE_EXTENSIONS

logger = logging.getLogger(__name__)

MAX_ARCHIVE_ENTRIES = 2000

# Bidirectional-override and isolate characters. Rendered names flip
# around these, so "invoice‮fdp.exe" displays as "invoiceexe.pdf".
_BIDI_CONTROLS = {"‪", "‫", "‬", "‭", "‮",
                  "⁦", "⁧", "⁨", "⁩"}

# Extensions a legitimately-zipped Office/OpenDocument file uses. A ZIP
# under one of these names is normal, not a disguise.
_ZIP_BASED_DOCUMENTS = {"docx", "docm", "xlsx", "xlsm", "pptx", "pptm",
                        "odt", "ods", "odp", "epub"}

_PDF_LAUNCH = re.compile(rb"/Launch(?![A-Za-z0-9])")
_PDF_JAVASCRIPT = re.compile(rb"/(?:JavaScript|JS)(?![A-Za-z0-9])")
# OLE directory entries are UTF-16LE.
_OLE_VBA_MARKER = "_VBA_PROJECT".encode("utf-16-le")


def _finding(score: int, key: str, **params) -> dict:
    return {"score": score, "key": key, "params": params}


def _ext(name: str) -> str:
    parts = name.rsplit(".", 1)
    return parts[1].lower() if len(parts) == 2 else ""


def _executable_type(data: bytes) -> str | None:
    """Program format from magic bytes, or None. Requires the full PE
    header rather than bare "MZ", which also starts plenty of non-program
    data."""
    if data[:2] == b"MZ" and len(data) >= 0x40:
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if pe_offset + 4 <= len(data) and data[pe_offset:pe_offset + 4] == b"PE\x00\x00":
            return "Windows EXE"
    if data[:4] == b"\x7fELF":
        return "Linux ELF"
    if data[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return "macOS Mach-O"
    return None


def _archive_type(data: bytes) -> str | None:
    if data[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return "ZIP"
    if data[:7] == b"Rar!\x1a\x07\x00" or data[:8] == b"Rar!\x1a\x07\x01\x00":
        return "RAR"
    if data[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    return None


def _zip_declared_entries(data: bytes) -> int | None:
    """Entry count from the end-of-central-directory record, read BEFORE
    zipfile parses the whole directory - so a ZIP declaring a huge number
    of entries is refused without paying to parse them."""
    eocd = data.rfind(b"PK\x05\x06", max(0, len(data) - 65557))
    if eocd < 0 or eocd + 12 > len(data):
        return None
    return struct.unpack_from("<H", data, eocd + 10)[0]


def _list_zip(data: bytes) -> tuple[list[str], bool] | None:
    declared = _zip_declared_entries(data)
    if declared is None or declared > MAX_ARCHIVE_ENTRIES:
        return None
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        infos = archive.infolist()[:MAX_ARCHIVE_ENTRIES]
        names = [info.filename for info in infos]
        encrypted = any(info.flag_bits & 0x1 for info in infos)
    return names, encrypted


def _list_rar(data: bytes) -> tuple[list[str], bool] | None:
    import rarfile  # deferred: only paid when a RAR actually arrives

    with rarfile.RarFile(io.BytesIO(data)) as archive:
        infos = archive.infolist()[:MAX_ARCHIVE_ENTRIES]
        names = [info.filename for info in infos]
        # needs_password() is True both for encrypted entries and for a
        # header-encrypted archive, which lists no names at all.
        encrypted = archive.needs_password() or any(info.needs_password() for info in infos)
    return names, encrypted


def _entry_findings(names: list[str], encrypted: bool) -> list[dict]:
    findings: list[dict] = []
    disguised = None
    executable = None
    for raw in names:
        name = raw.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
        lowered = name.lower()
        if any(ch in name for ch in _BIDI_CONTROLS):
            disguised = disguised or name
            continue
        parts = lowered.rsplit(".", 2)
        if len(parts) == 3 and parts[1] in DOCUMENT_LIKE_EXTENSIONS and parts[2] in EXECUTABLE_EXTENSIONS:
            disguised = disguised or name
        elif _ext(lowered) in EXECUTABLE_EXTENSIONS:
            executable = executable or name
    if disguised:
        findings.append(_finding(85, "content_archive_disguised_entry", entry=disguised))
    elif executable:
        findings.append(_finding(70, "content_archive_executable", entry=executable))
    if encrypted:
        findings.append(_finding(45, "content_archive_encrypted"))
    return findings


def _pdf_findings(data: bytes) -> list[dict]:
    if b"%PDF-" not in data[:1024]:
        return []
    findings = []
    if _PDF_LAUNCH.search(data):
        findings.append(_finding(70, "content_pdf_launch"))
    if _PDF_JAVASCRIPT.search(data):
        findings.append(_finding(45, "content_pdf_javascript"))
    return findings


def _inspect(data: bytes, file_name: str) -> list[dict]:
    name = file_name or ""
    claimed = _ext(name)
    findings: list[dict] = []

    if any(ch in name for ch in _BIDI_CONTROLS):
        findings.append(_finding(85, "content_rtlo_filename"))

    program = _executable_type(data)
    if program and claimed not in EXECUTABLE_EXTENSIONS:
        findings.append(_finding(85, "content_disguised_executable",
                                 claimed_ext=claimed or "?", real_type=program))

    archive = _archive_type(data)
    if archive:
        listing = None
        if archive == "ZIP":
            listing = _list_zip(data)
        elif archive == "RAR":
            listing = _list_rar(data)

        names, encrypted = listing if listing else ([], False)
        lowered_names = {n.lower() for n in names}
        is_apk = "androidmanifest.xml" in lowered_names and "classes.dex" in lowered_names
        is_office = "[content_types].xml" in lowered_names or "mimetype" in lowered_names

        if is_apk and claimed != "apk":
            findings.append(_finding(85, "content_disguised_executable",
                                     claimed_ext=claimed or "?", real_type="Android APK"))
        elif is_office:
            if any(n.endswith("vbaproject.bin") for n in lowered_names):
                findings.append(_finding(50, "content_office_macros"))
        else:
            if claimed in DOCUMENT_LIKE_EXTENSIONS and claimed not in _ZIP_BASED_DOCUMENTS:
                findings.append(_finding(30, "content_disguised_archive",
                                         claimed_ext=claimed, real_type=archive))
            findings.extend(_entry_findings(names, encrypted))

    if data[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" and _OLE_VBA_MARKER in data:
        findings.append(_finding(50, "content_office_macros"))

    findings.extend(_pdf_findings(data))
    return findings


def inspect_content(data: bytes | None, file_name: str) -> list[dict]:
    """Findings for these bytes, strongest first; [] when nothing is found
    or the bytes could not be parsed. Never raises.

    CPU-bound and run on attacker-supplied input, so callers on the event
    loop must hand this to asyncio.to_thread (scanner.scan_file does)."""
    if not data:
        return []
    try:
        findings = _inspect(data, file_name)
    except Exception:                          # noqa: BLE001 - a corrupt file is not a finding
        logger.debug("Content inspection could not parse %r", file_name, exc_info=True)
        return []
    # One finding per key: the strongest instance is the one worth saying.
    best: dict[str, dict] = {}
    for finding in findings:
        if finding["key"] not in best or finding["score"] > best[finding["key"]]["score"]:
            best[finding["key"]] = finding
    return sorted(best.values(), key=lambda f: -f["score"])
