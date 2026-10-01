import asyncio
import logging

from telegram import Update
from telegram.error import BadRequest
from telegram.ext import ContextTypes

from bot.detectors.file.file_risk import file_risk, has_antivirus_answer
from bot.detectors.file.scanner import cached_result, download_and_hash, scan_file
from bot.storage.scan_log import log_scan
from bot.storage import subscription
from bot.handlers.text_handler import get_user_lang
from bot.response.translate import DEFAULT_LANG
from bot.response.buttons import t
from bot.response.verdict_style import DISCLAIMER_SPACER, LEVEL_TO_VERDICT, defang_domains, risk_style, scan_type_label, summary_sentence, verdict_style
from bot.response.status_animation import STATUS_CHECKING_KEY, animate_status, stop_status_animation

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


def content_finding_texts(result: dict, lang: str) -> list[str]:
    """Rendered local-inspection findings (offline/content_check.py),
    strongest first. Shared with context_engine.py's offline fallback for
    the same reason filename_warning_text is."""
    findings = sorted(result.get("content_findings") or [], key=lambda f: -f.get("score", 0))
    return [t(lang, f["key"]).format(**(f.get("params") or {})) for f in findings]


# How many offline warnings (filename + content) a single reply shows.
# The strongest ones carry the verdict; a long tail of weaker ones only
# buries them.
_MAX_LOCAL_REASONS = 3


def _local_reasons(result: dict, lang: str) -> list[str]:
    warnings = []
    filename_warning = filename_warning_text(result, lang)
    if filename_warning:
        warnings.append((result.get("filename_risk_score", 0), filename_warning))
    findings = sorted(result.get("content_findings") or [], key=lambda f: -f.get("score", 0))
    for finding, text in zip(findings, content_finding_texts(result, lang)):
        warnings.append((finding.get("score", 0), text))
    warnings.sort(key=lambda pair: -pair[0])
    return [text for _score, text in warnings[:_MAX_LOCAL_REASONS]]


def _classify_file_result(result: dict, lang: str = DEFAULT_LANG) -> tuple[str, int | None, list[str]]:
    """(level, risk_percentage, reasons) from a merged scan_file() result.

    The verdict itself comes from bot/detectors/file/file_risk.py, which
    the unified text+file path also uses - this function only explains it.
    risk_percentage is None only for "uncertain": no antivirus answer and
    no offline signal strong enough to stand on. That reads as "UNABLE TO
    VERIFY", replacing the old flat "safe, 0%" (2026-10-01) - see
    file_risk.file_risk for why "VirusTotal has never seen it" must not
    read as safe.

    Engine counts, file extensions, archive entry names and the example
    engine's detection name are real evidence and stay verbatim in every
    language.
    """
    level, pct = file_risk(result)
    reasons: list[str] = []
    local = _local_reasons(result, lang)

    if has_antivirus_answer(result):
        malicious, total = result.get("malicious", 0), result.get("total", 0)
        if malicious > 0:
            reasons.append(t(lang, "reason_file_engines_flag").format(
                malicious=malicious, total=total,
                top_engine=result["top_engines"]["Microsoft"],
            ))
        elif local:
            reasons.append(t(lang, "reason_file_clean_but_name_suspect").format(total=total))
        else:
            reasons.append(t(lang, "reason_file_no_engine_flags").format(total=total))
        return level, pct, reasons + local

    # No antivirus answer. Direct user spec (2026-09-11), kept: never name
    # WHICH backend was unavailable, only the real limitation.
    reasons.append(t(lang, "reason_file_name_only" if not result.get("checked") else "reason_file_never_seen"))
    if local:
        return level, pct, reasons + local
    reasons.append(t(lang, "reason_file_no_local_findings"))
    return level, pct, reasons


def _with_disclaimer(message: str, lang: str = DEFAULT_LANG) -> str:
    """Append the standard disclaimer to a file-scan failure message."""
    return f"{message}\n\n{DISCLAIMER_SPACER}{t(lang, 'verdict_disclaimer')}"


def _format_file_verdict(level: str, pct: int | None, reasons: list[str], lang: str = DEFAULT_LANG) -> str:
    """Format the file verdict using the shared scan-response layout."""
    # An unverified file (no number) reads "UNABLE TO VERIFY", not
    # "SUSPICIOUS": nothing accused it, nothing vouched for it either.
    verdict = None if pct is None else LEVEL_TO_VERDICT[level]
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
    lang = await get_user_lang(context, user_id)

    status_suffix = f" `{file_name}`..."
    status_text = f"{t(lang, STATUS_CHECKING_KEY)}{status_suffix}"
    try:
        message = await update.message.reply_text(status_text, parse_mode="Markdown")
    except BadRequest:
        # A FILENAME is attacker-controlled too, and this send had no
        # error handling at all (2026-09-24 security review): a document
        # named "inv`oice.pdf" raised BadRequest here and killed the
        # handler outright, before the file was even hashed - the user
        # just got nothing, with only _on_error's log line to show for
        # it. Same failure mode, and same plain-text retry, as
        # url_handler's own two Markdown sends; this was the third and
        # last unguarded one.
        logger.warning(
            "File status send failed to parse as Markdown (likely Markdown "
            "syntax in the filename) - retrying as plain text"
        )
        message = await update.message.reply_text(status_text)
    animation_task = asyncio.create_task(animate_status(message, lang, status_suffix))

    try:
        sha256 = await download_and_hash(context, document.file_id, document.file_name or "")
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
    already_cached = await asyncio.to_thread(cached_result, sha256) is not None
    if not already_cached and not await subscription.can_scan_file(user_id):
        await stop_status_animation(animation_task)
        # Direct user spec (2026-09-15): tell them once, not on every
        # file they try to send while still over today's limit - see
        # should_notify_file_limit's own docstring. The scan itself is
        # blocked either way; only whether we SAY so is conditional.
        if await subscription.should_notify_file_limit(user_id):
            await message.edit_text(
                t(lang, "daily_file_limit_reached").format(
                    limit=subscription.FREEMIUM_DAILY_FILES,
                    reset_time=subscription.reset_time_display(),
                ),
                parse_mode="HTML",
            )
        else:
            await message.delete()
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
        await subscription.record_file_scan(user_id)

    level, risk_percentage, reasons = _classify_file_result(result, lang)
    reply = _format_file_verdict(level, risk_percentage, reasons, lang)
    await asyncio.to_thread(log_scan, user_id, file_name, sha256, result.get("malicious", 0))

    await message.edit_text(reply, parse_mode="Markdown")
