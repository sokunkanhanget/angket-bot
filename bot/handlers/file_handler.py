import asyncio
import logging

from telegram import Update
from telegram.ext import ContextTypes

from bot.detectors.file.scanner import download_and_hash, scan_file
from bot.storage.scan_log import log_scan
from bot.storage import subscription
from bot.handlers.text_handler import get_user_lang
from bot.response.translate import DEFAULT_LANG
from bot.response.buttons import t
from bot.response.verdict_style import DISCLAIMER_SPACER, LEVEL_TO_VERDICT, defang_domains, risk_style, scan_type_label, summary_sentence, verdict_style
from bot.response.status_animation import STATUS_STAGE_KEYS, animate_status, stop_status_animation

logger = logging.getLogger(__name__)


_FILE_RECOMMENDATIONS = {
    "dangerous": [
        "Do not open this file, run it, or extract its contents.",
        "If you already opened it, disconnect from the internet and run a full antivirus scan.",
        "Delete the file and block/report whoever sent it.",
    ],
    "suspicious": [
        "Don't open this file until you've verified it with the sender through another channel.",
        "If you must open it, scan it with your own antivirus software first.",
    ],
    "safe": [
        "No strong threat signals were found, but stay cautious with any unexpected attachment.",
        "Only open files from senders you actually trust.",
    ],
    "uncertain": [
        "Treat this file with caution until it can be properly checked.",
        "Verify the sender through another channel before opening it.",
    ],
}


def _classify_file_result(result: dict) -> tuple[str, int | None, list[str]]:
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
    """
    reasons: list[str] = []
    filename_warning = result.get("filename_warning")
    filename_score = result.get("filename_risk_score", 0)

    if result.get("checked") and result.get("found"):
        malicious, total = result["malicious"], result["total"]
        if malicious > 0:
            pct = min(100, round(malicious / total * 100)) if total else 100
            reasons.append(
                f"{malicious} of {total} security engines on VirusTotal flag this file as "
                f"malicious (e.g. Microsoft: {result['top_engines']['Microsoft']})."
            )
            if filename_warning:
                reasons.append(filename_warning)
            return "dangerous", pct, reasons

        if filename_warning:
            reasons.append(
                f"VirusTotal found no threats in this exact file ({total} engines checked), "
                f"but its name is still worth a second look."
            )
            reasons.append(filename_warning)
            return ("dangerous" if filename_score >= 50 else "suspicious"), filename_score, reasons
        reasons.append(f"No security engine out of {total} on VirusTotal flags this file.")
        return "safe", 0, reasons

    if not result.get("checked"):
        reasons.append(
            "VirusTotal could not be reached right now, so this result is based on the "
            "file name only, not a real antivirus scan."
        )
    else:
        reasons.append("This file's signature has never been seen by VirusTotal before — no track record either way.")

    if filename_warning:
        reasons.append(filename_warning)
        return ("dangerous" if filename_score >= 50 else "suspicious"), filename_score, reasons

    return "uncertain", None, reasons


def _with_disclaimer(message: str, lang: str = DEFAULT_LANG) -> str:
    """Append the standard disclaimer to a file-scan failure message."""
    return f"{message}\n\n{DISCLAIMER_SPACER}\n{t(lang, 'verdict_disclaimer')}"


def _format_file_verdict(level: str, pct: int | None, reasons: list[str], lang: str = DEFAULT_LANG) -> str:
    """Format the file verdict using the shared scan-response layout."""
    verdict = LEVEL_TO_VERDICT[level]
    verdict_icon, verdict_label = verdict_style(verdict, lang)
    risk_icon, risk_label = risk_style(pct, lang)
    recs = _FILE_RECOMMENDATIONS[level]

    lines = [
        f"{verdict_icon} *{t(lang, 'verdict_label')}: {verdict_label}*",
        f"🗁 *{t(lang, 'type_label')}: {scan_type_label(has_text=False, has_link=False, has_file=True)}*",
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
        "",
        DISCLAIMER_SPACER,
        t(lang, "verdict_disclaimer"),
    ]
    return "\n".join(lines)


async def handle_file(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    document = update.message.document
    file_name = document.file_name or "unknown_file"
    user_id = update.effective_user.id
    lang = get_user_lang(context)

    if not subscription.can_scan_file(user_id):
        await update.message.reply_text(
            t(lang, "daily_file_limit_reached").format(limit=subscription.FREEMIUM_DAILY_FILES)
        )
        return

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

    try:
        result = await scan_file(sha256, file_name)
    except Exception:                          # noqa: BLE001
        logger.exception("Unexpected error scanning %s", file_name)
        await stop_status_animation(animation_task)
        await message.edit_text(_with_disclaimer(t(lang, "file_scan_failed"), lang))
        return

    await stop_status_animation(animation_task)

    subscription.record_file_scan(user_id)

    level, risk_percentage, reasons = _classify_file_result(result)
    reply = _format_file_verdict(level, risk_percentage, reasons, lang)
    log_scan(user_id, file_name, sha256, result.get("malicious", 0))

    await message.edit_text(reply, parse_mode="Markdown")
