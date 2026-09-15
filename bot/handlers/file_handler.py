import asyncio
import logging

from telegram import Update
from telegram.ext import ContextTypes

from bot.detectors.file.scanner import cached_result, download_and_hash, scan_file
from bot.storage.scan_log import log_scan
from bot.storage import subscription
from bot.handlers.text_handler import get_user_lang
from bot.response.translate import DEFAULT_LANG
from bot.response.buttons import t
from bot.response.verdict_style import DISCLAIMER_SPACER, LEVEL_TO_VERDICT, defang_domains, risk_style, scan_type_label, summary_sentence, verdict_style
from bot.response.status_animation import STATUS_STAGE_KEYS, animate_status, stop_status_animation

logger = logging.getLogger(__name__)


# Translation keys rather than literal strings. The file checker never
# calls Gemini at all, so unlike the text/link surfaces it had no path
# that produced text in the user's language - every reason and
# recommendation here was fixed English sitting inside a reply whose
# labels were already fully translated.
_FILE_RECOMMENDATION_KEYS = {
    "dangerous": [
        "rec_file_dangerous_do_not_open",
        "rec_file_dangerous_already_opened",
        "rec_file_dangerous_delete_block",
    ],
    "suspicious": [
        "rec_file_suspicious_verify_sender",
        "rec_file_suspicious_scan_first",
    ],
    "safe": [
        "rec_file_safe_no_signals",
        "rec_file_safe_trusted_senders",
    ],
    "uncertain": [
        "rec_file_uncertain_caution",
        "rec_file_uncertain_verify_sender",
    ],
}


def filename_warning_text(result: dict, lang: str) -> str | None:
    """Render scanner.py's (key, params) filename warning in `lang`, or
    None when the name raised nothing. Shared with context_engine.py's
    offline fallback, which shows the same warning as its own evidence -
    one renderer so the two surfaces can't drift apart."""
    key = result.get("filename_warning_key")
    if not key:
        return None
    return t(lang, key).format(**(result.get("filename_warning_params") or {}))


def _classify_file_result(result: dict, lang: str = DEFAULT_LANG) -> tuple[str, int | None, list[str]]:
    """(level, risk_percentage, reasons) from a merged scan_file() result.
    risk_percentage is None only for the genuinely-no-signal case (no VT
    match/reachability AND no filename warning) - same "nothing to base
    a number on" honesty pipeline.py's own risk_style(None) -> "N/A"
    already uses elsewhere, rather than inventing a fake number.

    VirusTotal's own finding always takes priority when it actually has
    one (checked AND found) - the filename heuristic only decides the
    verdict when VT has NOTHING real to say, exactly matching
    scanner.py's own "VT's malicious count stays untouched by the
    filename heuristic" principle, just extended to the reverse case.

    `lang` renders the reasons. Engine counts, file extensions and the
    example engine's detection name are real evidence and stay verbatim
    in every language.
    """
    reasons: list[str] = []
    filename_warning = filename_warning_text(result, lang)
    filename_score = result.get("filename_risk_score", 0)

    if result.get("checked") and result.get("found"):
        malicious, total = result["malicious"], result["total"]
        if malicious > 0:
            pct = min(100, round(malicious / total * 100)) if total else 100
            reasons.append(t(lang, "reason_file_engines_flag").format(
                malicious=malicious, total=total,
                top_engine=result["top_engines"]["Microsoft"],
            ))
            if filename_warning:
                reasons.append(filename_warning)
            return "dangerous", pct, reasons

        if filename_warning:
            reasons.append(t(lang, "reason_file_clean_but_name_suspect").format(total=total))
            reasons.append(filename_warning)
            return ("dangerous" if filename_score >= 50 else "suspicious"), filename_score, reasons
        reasons.append(t(lang, "reason_file_no_engine_flags").format(total=total))
        return "safe", 0, reasons

    # Either VirusTotal has genuinely never seen this hash before, or it
    # couldn't be reached at all right now - either way, there's no real
    # AV signal, only whatever the file's NAME suggests. Direct user spec
    # (2026-09-11): don't tell the user a specific backend service is
    # down/unreachable - just state the real limitation (no antivirus
    # engine data backing this particular result) without naming why.
    if not result.get("checked"):
        reasons.append(t(lang, "reason_file_name_only"))
    else:
        reasons.append(t(lang, "reason_file_never_seen"))

    if filename_warning:
        reasons.append(filename_warning)
        return ("dangerous" if filename_score >= 50 else "suspicious"), filename_score, reasons

    # No VT signal AND nothing about the name looks off - the filename
    # check DID run and found nothing, so this isn't "we have no idea"
    # (the old "uncertain"/None here), it's "nothing we checked flagged
    # it", the same honest "safe" this function already returns when VT
    # itself confirms a clean file. Direct user spec: a single unavailable
    # service (VT) shouldn't be enough to blank out a real verdict when
    # the offline check already ran.
    reasons.append(t(lang, "reason_file_no_name_flags"))
    return "safe", 0, reasons


def _with_disclaimer(message: str, lang: str = DEFAULT_LANG) -> str:
    """Append the standard disclaimer to a file-scan failure message."""
    return f"{message}\n\n{DISCLAIMER_SPACER}{t(lang, 'verdict_disclaimer')}"


def _format_file_verdict(level: str, pct: int | None, reasons: list[str], lang: str = DEFAULT_LANG) -> str:
    """Format the file verdict using the shared scan-response layout."""
    verdict = LEVEL_TO_VERDICT[level]
    verdict_icon, verdict_label = verdict_style(verdict, lang)
    risk_icon, risk_label = risk_style(pct, lang)
    recs = [t(lang, key) for key in _FILE_RECOMMENDATION_KEYS[level]]

    lines = [
        f"{verdict_icon} *{t(lang, 'verdict_label')}: {verdict_label}*",
        f"📁 *{t(lang, 'type_label')}: {scan_type_label(has_text=False, has_link=False, has_file=True)}*",
        summary_sentence(verdict, pct, lang),
        "",
        f"{risk_icon} *{risk_label.upper()}*" if pct is None else f"{risk_icon} *{pct}%  {risk_label.upper()}*",
        "",
        f"🔍 *{t(lang, 'key_reasons_header')}*",
    ]
    lines += [f"• {defang_domains(r, style='markdown')}" for r in reasons]
    lines += [
        "",
        f"💡 *{t(lang, 'what_to_do_header')}*",
    ]
    lines += [f"✓ {defang_domains(r, style='markdown')}" for r in recs]
    lines += [
        DISCLAIMER_SPACER,
        t(lang, "verdict_disclaimer"),
    ]
    return "\n".join(lines)


async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    document = update.message.document
    file_name = document.file_name or "unknown_file"
    user_id = update.effective_user.id
    lang = get_user_lang(context)

    status_suffix = f" `{file_name}`..."
    message = await update.message.reply_text(
        f"{t(lang, STATUS_STAGE_KEYS[0])}{status_suffix}", parse_mode="Markdown",
    )
    animation_task = asyncio.create_task(animate_status(message, lang, status_suffix))

    try:
        sha256 = await download_and_hash(context, document.file_id)
    except Exception:                          # noqa: BLE001
        logger.exception("File download failed for %s", file_name)
        await stop_status_animation(animation_task)
        await message.edit_text(_with_disclaimer(t(lang, "file_scan_failed"), lang))
        return

    # Quota gate moved AFTER hashing (every other quota gate in this
    # project fires first, but this one genuinely can't - whether the
    # scan is even chargeable depends on the hash itself). A hash
    # already in file_vt_cache (7-day TTL, see virustotal.py) costs no
    # live VT call either way, so a repeat upload of an already-known
    # file is never blocked or charged - only a genuinely new hash pays
    # quota.
    already_cached = cached_result(sha256) is not None
    if not already_cached and not subscription.can_scan_file(user_id):
        await stop_status_animation(animation_task)
        await message.edit_text(
            t(lang, "daily_file_limit_reached").format(limit=subscription.FREEMIUM_DAILY_FILES)
        )
        return

    try:
        result = await scan_file(sha256, file_name)
    except Exception:                          # noqa: BLE001
        logger.exception("Unexpected error scanning %s", file_name)
        await stop_status_animation(animation_task)
        await message.edit_text(_with_disclaimer(t(lang, "file_scan_failed"), lang))
        return

    await stop_status_animation(animation_task)

    if not already_cached:
        subscription.record_file_scan(user_id)

    level, risk_percentage, reasons = _classify_file_result(result, lang)
    reply = _format_file_verdict(level, risk_percentage, reasons, lang)
    await asyncio.to_thread(log_scan, user_id, file_name, sha256, result.get("malicious", 0))

    await message.edit_text(reply, parse_mode="Markdown")
