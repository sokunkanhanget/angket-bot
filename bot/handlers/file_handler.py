import logging

from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.error import TelegramError
from telegram.ext import ContextTypes

from bot.detectors.file.scanner import download_and_hash, scan_file
from bot.storage.scan_log import log_scan
from bot.storage import subscription
from bot.handlers.text_handler import get_user_lang
from bot.i18n import label, t
from bot.verdict_style import SECTION_DIVIDER

logger = logging.getLogger(__name__)


# Same shape as bot/detectors/url/pipeline.py's own _VERDICT_SENTENCES/
# _RECOMMENDATIONS - not imported from there (those are that module's
# own private constants for LINK verdicts specifically), but matching
# the exact structure so handle_file's reply reads like the same
# product as the link/text checkers, per direct user request. "uncertain"
# is the one level neither of pipeline.py's own maps has - files
# genuinely can end up with no real signal either way (a brand-new
# hash VirusTotal has never seen, no filename disguise, or a VT outage
# with nothing else to go on) - see _classify_file_result below.
_FILE_VERDICT_SENTENCES = {
    "dangerous": "This file is 🔴 *DANGEROUS* — do not open it.",
    "suspicious": "This file is 🟠 *SUSPICIOUS* — proceed with caution.",
    "safe": "This file is 🟢 *SAFE*.",
    "uncertain": "This file is ⚪ *UNCERTAIN* — not enough information for a real verdict.",
}

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


def _risk_percent_and_label(pct: int) -> tuple[int, str]:
    pct = min(max(pct, 0), 100)
    if pct <= 30:
        return pct, "Low Risk"
    if pct <= 60:
        return pct, "Medium Risk"
    return pct, "High Risk"


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

        # VT has actually scanned this EXACT file before and found nothing -
        # real, fairly strong evidence, even if the filename still looks off.
        if filename_warning:
            reasons.append(
                f"VirusTotal found no threats in this exact file ({total} engines checked), "
                f"but its name is still worth a second look."
            )
            reasons.append(filename_warning)
            return ("dangerous" if filename_score >= 50 else "suspicious"), filename_score, reasons
        reasons.append(f"No security engine out of {total} on VirusTotal flags this file.")
        return "safe", 0, reasons

    # Either VirusTotal has genuinely never seen this hash before, or it
    # couldn't be reached at all right now - either way, there's no real
    # AV signal, only whatever the file's NAME suggests.
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


def _format_file_verdict(file_name: str, level: str, pct: int | None, reasons: list[str]) -> str:
    """Same section layout as pipeline.py's format_verdict_full (link
    checker) - Scanned target / Risk / Reasons / What Can You Do / the
    same disclaimer line - per direct user request that this reply read
    like the url/text checkers' output, not a raw VirusTotal data dump."""
    verdict_sentence = _FILE_VERDICT_SENTENCES[level]
    recs = _FILE_RECOMMENDATIONS[level]

    lines = [
        "📡 *Angket Bot - File Scanner*",
        "",
        "📄 *Scanned File*",
        f"`{file_name}`",
        "",
        "🛡️ *Risk*",
        verdict_sentence,
    ]
    if pct is not None:
        _, risk_label = _risk_percent_and_label(pct)
        lines.append(f"{pct}% estimated risk — {risk_label}")
    else:
        lines.append("N/A — no real signal to estimate a percentage from")
    lines += ["", "🔍 *Reasons*"]
    lines += [f"- {r}" for r in reasons]
    lines += [
        "",
        "💡 *What Can You Do?*",
    ]
    lines += [f"- {r}" for r in recs]
    lines += [
        "",
        SECTION_DIVIDER,
        "ⓘ Bot can make mistakes. Please check carefully.",
    ]
    return "\n".join(lines)


def _virustotal_button(lang: str, sha256: str) -> InlineKeyboardButton:
    return InlineKeyboardButton(
        label(lang, "view_on_virustotal"),
        url=f"https://www.virustotal.com/gui/file/{sha256}",
    )


def _scan_result_keyboard(lang: str, original_message_id: int, level: str, sha256: str) -> InlineKeyboardMarkup:
    """Delete/Ignore only make sense next to an actually-dangerous result -
    a clean/suspicious/uncertain file has nothing to delete or ignore.
    Gated on the CLASSIFIED level now (which can come from the filename
    heuristic alone when VT has nothing to say), not just VT's raw
    malicious count - see _classify_file_result."""
    rows = []
    if level == "dangerous":
        rows.append([
            InlineKeyboardButton(label(lang, "delete"), callback_data=f"delete_{original_message_id}"),
            InlineKeyboardButton(label(lang, "ignore"), callback_data="ignore"),
        ])
    rows.append([_virustotal_button(lang, sha256)])
    return InlineKeyboardMarkup(rows)


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

    message = await update.message.reply_text(
        f"📥 *Scanning `{file_name}`...*",
        parse_mode="Markdown",
    )

    try:
        sha256 = await download_and_hash(context, document.file_id)
    except Exception:                          # noqa: BLE001 - a Telegram-side download failure must still get a reply
        logger.exception("File download failed for %s", file_name)
        await message.edit_text(t(lang, "file_scan_failed"))
        return

    # scan_file() isn't SUPPOSED to raise - a VirusTotal outage comes back
    # as a real dict (checked=False), not an exception, which is what
    # makes the fallback-instead-of-silence verdict below possible at
    # all (see scan_file/scan_vt_hash's own docstrings). This try/except
    # is defense-in-depth for a genuinely unexpected bug in that chain,
    # not the normal "VT is down" path anymore - that path is now a real
    # degraded verdict, not a generic failure message.
    try:
        result = await scan_file(sha256, file_name)
    except Exception:                          # noqa: BLE001 - must never break the reply path
        logger.exception("Unexpected error scanning %s", file_name)
        await message.edit_text(t(lang, "file_scan_failed"))
        return

    subscription.record_file_scan(user_id)

    level, risk_percentage, reasons = _classify_file_result(result)
    reply = _format_file_verdict(file_name, level, risk_percentage, reasons)
    keyboard = _scan_result_keyboard(lang, update.message.message_id, level, sha256)
    log_scan(user_id, file_name, sha256, result.get("malicious", 0))

    await message.edit_text(
        reply,
        parse_mode="Markdown",
        reply_markup=keyboard,
    )


async def handle_scan_action_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Delete/Ignore taps on a file-scan result - registered with an
    explicit pattern (see bot.py) so it can never swallow unrelated
    callbacks like the business-chat link notifications' `^u:` ones."""
    query = update.callback_query
    await query.answer()
    lang = get_user_lang(context)

    if query.data.startswith("delete_"):
        target_message_id = int(query.data.split("_", 1)[1])
        try:
            await context.bot.delete_message(chat_id=query.message.chat_id, message_id=target_message_id)
            await query.edit_message_text(t(lang, "file_deleted"))
        except TelegramError:
            # Already deleted, or the bot lacks delete permission in this
            # chat - either way, nothing more we can safely do here.
            await query.edit_message_text(t(lang, "file_deleted"))
    elif query.data == "ignore":
        await query.edit_message_text(t(lang, "file_scan_ignored"))
