"""
bot/detectors/file/offline/filename_check.py
================================================
Pure filename-pattern check - no network, deterministic, instant. Moved
out of scanner.py so the offline (filename heuristic) and online
(VirusTotal API) halves of file scanning are as clearly separated as
url/offline vs url/online already are.

Returns a TRANSLATION KEY plus format params, not a finished English
sentence. This layer has no idea who is going to read its output (a
private DM in Khmer, a business owner's notification, the offline
reasoning fallback), and it must stay pure/offline, so the language
choice belongs to whichever display site renders it - see
bot/response/translate/. Previously this returned pre-formatted English,
which is how English ended up inside otherwise fully-Khmer file-scan
replies.
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


def _double_extension_disguise(name: str) -> tuple[int, str, dict] | None:
    """Flags the classic double-extension disguise ("invoice.pdf.exe",
    "Document.pdf.z"): a document-looking extension followed by a
    second, real extension that determines how the file actually
    behaves. Only fires when the INNER extension looks like an ordinary
    document/media type - two unrelated extensions on a file that isn't
    trying to look safe (e.g. "archive.tar.gz") isn't this pattern.
    """
    parts = name.rsplit(".", 2)
    if len(parts) < 3:
        return None
    _, inner_ext, outer_ext = parts
    if inner_ext not in DOCUMENT_LIKE_EXTENSIONS:
        return None
    if outer_ext in EXECUTABLE_EXTENSIONS:
        return (50, "filename_warning_double_extension_executable",
                {"outer_ext": outer_ext, "inner_ext": inner_ext})
    if outer_ext in ARCHIVE_EXTENSIONS:
        return (20, "filename_warning_double_extension_archive",
                {"outer_ext": outer_ext, "inner_ext": inner_ext})
    return None


def _lone_executable_extension(name: str) -> tuple[int, str, dict] | None:
    """A bare executable/script extension with no document-like disguise
    at all ('setup.exe', 'invoice.apk') - a weaker signal than the
    double-extension trick above (nothing here pretends to be something
    else), but still real and worth flagging on its own: an unsolicited
    executable/installer/script is one of this bot's core scam vectors
    (fake banking apps, fake "invoice viewer" installers) even when
    VirusTotal has nothing to say about this exact file yet. Scored
    below the disguise case (35 < 50, so "suspicious" not "dangerous")
    since a bare installer someone genuinely meant to share also looks
    like this - the double-extension trick is the one pattern that's
    inherently deceptive.
    """
    parts = name.rsplit(".", 1)
    if len(parts) < 2:
        return None
    ext = parts[1]
    if ext in EXECUTABLE_EXTENSIONS:
        return (35, "filename_warning_lone_executable", {"ext": ext})
    return None


def check_filename(file_name: str) -> tuple[int, str, dict] | None:
    """Pure filename-pattern check: the double-extension disguise trick
    first (most specific / highest severity), falling back to a bare
    risky extension with no disguise at all. Returns the first
    (score, translation_key, format_params) that fires, or None when
    nothing about the name looks off - see this module's docstring for
    why the caller renders the text rather than this layer.
    """
    name = (file_name or "").lower()
    return _double_extension_disguise(name) or _lone_executable_extension(name)
