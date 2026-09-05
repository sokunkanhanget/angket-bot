"""
bot/detectors/file/offline/filename_check.py
================================================
Pure filename-pattern check - no network, deterministic, instant. Moved
out of scanner.py so the offline (filename heuristic) and online
(VirusTotal API) halves of file scanning are as clearly separated as
url/offline vs url/online already are.
"""

from __future__ import annotations

# Executable/script extensions - the highest-risk disguise target: a
# real attack ("invoice.pdf.exe") hides one of these behind a document-
# looking name so an unsuspecting user believes it's safe to open.
EXECUTABLE_EXTENSIONS = {
    "exe", "scr", "bat", "cmd", "com", "pif", "vbs", "vbe", "js", "jse",
    "wsf", "wsh", "msi", "ps1", "jar", "hta", "reg", "lnk", "apk",
}

# Archive/compression extensions - a lower-severity case: hiding a
# document behind an archive isn't inherently an attack (a legitimately
# compressed export exists), but this bot's hash check only ever sees
# the OUTER file - it can't look inside an archive, so the real content
# stays unverified either way.
ARCHIVE_EXTENSIONS = {"zip", "rar", "7z", "gz", "bz2", "xz", "z", "tar", "tgz"}

# Extensions this check treats as "looks like a normal document/media
# file" - the disguise target an attacker wants the user to believe
# they're opening. Only a SECOND extension chained after one of these is
# meaningful; a lone ".exe" is just an executable, not a disguise.
DOCUMENT_LIKE_EXTENSIONS = {
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "txt", "csv",
    "jpg", "jpeg", "png", "gif", "mp3", "mp4",
}


def check_filename(file_name: str) -> tuple[int, str] | None:
    """Flags the classic double-extension disguise ("invoice.pdf.exe",
    "Document.pdf.z"): a document-looking extension followed by a
    second, real extension that determines how the file actually
    behaves. Only fires when the INNER extension looks like an ordinary
    document/media type - two unrelated extensions on a file that isn't
    trying to look safe (e.g. "archive.tar.gz") isn't this pattern.
    """
    name = (file_name or "").lower()
    parts = name.rsplit(".", 2)
    if len(parts) < 3:
        return None
    _, inner_ext, outer_ext = parts
    if inner_ext not in DOCUMENT_LIKE_EXTENSIONS:
        return None
    if outer_ext in EXECUTABLE_EXTENSIONS:
        return (50, f"File name disguises an executable ('.{outer_ext}') behind a "
                    f"'.{inner_ext}' extension — a classic malware trick "
                    f"(e.g. 'invoice.pdf.exe').")
    if outer_ext in ARCHIVE_EXTENSIONS:
        return (20, f"File name hides a '.{inner_ext}' file inside a '.{outer_ext}' "
                    f"archive — this bot cannot see inside archives, so the real "
                    f"content is unverified.")
    return None
