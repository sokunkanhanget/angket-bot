import json
import logging

from google.genai import types

from bot.config.config import GEMINI_MODEL
from bot.detectors.text.online.gemini_retry import build_clients, generate_content_with_backup
from bot.detectors.text.offline.keyword import analyze_text
# Deliberate cross-module reuse of context_engine's offline fallback
# (leading underscore is this project's "internal to its own reasoning
# module" convention, not real Python privacy) - see _fallback's own
# docstring below for why duplicating that logic here would be worse.
from bot.context_engine.context_engine import _grounded_fallback
from bot.storage import subscription
from bot.storage import health_alerts

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "You are a security analyst detecting scams, phishing, and fraud in Telegram "
    "messages, links, files, and URLs. Analyze the content and return a structured "
    "assessment a non-technical user can act on.\n\n"

    "Check for these and any other scam or fraud indicators, even if not listed below:\n"
    "- Urgency/pressure/fear tactics ('act now', 'account suspended', 'legal action')\n"
    "- Requests for passwords, OTPs, PINs, seed phrases, or payment/card details\n"
    "- Unrealistic offers (easy money, guaranteed returns, unsolicited jobs/prizes)\n"
    "- Impersonation (fake bank, company, government, courier, or known contact)\n"
    "- Suspicious links (misspelled/lookalike domains, shorteners, odd TLDs, IP-based URLs)\n"
    "- Suspicious files (executables, disguised extensions, macro-enabled docs, APKs)\n"
    "- Poor grammar, generic greetings, mismatched sender name/number\n"
    "- Pressure to move off-platform, stay secret, or act without verifying\n"
    "- Advance-fee requests (pay first to unlock a bigger reward/refund/delivery)\n"
    "- Known patterns: lottery/prize, romance/relationship, crypto/investment, "
    "fake job/task, tech support, impersonation/authority, package/delivery, "
    "loan/debt, charity, account-verification, sextortion/blackmail\n"
    "- Anything else that seems deceptive or manipulative, even if it doesn't "
    "match a pattern above\n\n"

    "Also weigh context: who it claims to be from, what it asks the user to do, "
    "and whether that's reasonable given the relationship or situation.\n\n"

    "If evidence is insufficient, use 'Uncertain' instead of guessing, with a "
    "low-medium risk_percentage.\n\n"

    "risk_percentage scale: 0-20 none, 21-40 low, 41-60 medium, 61-85 high, "
    "86-100 near-certain scam.\n\n"

    "key_reasons: specific, reference actual message details, not generic claims.\n"
    "recommendations: concrete actions (e.g. 'don't click the link', 'verify via "
    "official website', 'block sender'), not vague advice.\n\n"

    "Be evidence-based — don't flag content just for mentioning money, links, or "
    "jobs without real red flags.\n\n"

    "Respond only per the JSON schema, no extra commentary."
)

_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {
            "type": "string",
            "enum": ["Scam", "Not a Scam", "Uncertain"],
            "description": "Overall classification of the content."
        },
        "risk_level": {
            "type": "string",
            "enum": ["Low", "Medium", "High"],
            "description": "Categorical risk level derived from risk_percentage."
        },
        "risk_percentage": {
            "type": "integer",
            "description": "Estimated likelihood (0-100) that this content is a scam or malicious."
        },
        "key_reasons": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Specific, evidence-based reasons supporting the verdict, referencing actual content details."
        },
        "recommendations": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Concrete, actionable next steps the user should take."
        },
    },
    "required": [
        "verdict",
        "risk_level",
        "risk_percentage",
        "key_reasons",
        "recommendations",
    ],
}

_client, _backup_client = build_clients()


def _risk_label(risk_percentage: int | None) -> str:
    if risk_percentage is None:
        return "Unknown"
    if risk_percentage <= 30:
        return "Low"
    if risk_percentage <= 60:
        return "Medium"
    return "High"


async def _fallback(reason: str, error: str, text: str) -> dict:
    """Gemini unavailable (no key / budget exhausted / call failed) ->
    degrade to the SAME offline evidence context_engine.py's unified path
    already falls back to, instead of a blank "Uncertain, N/A risk" with
    no real reasons. This group-chat path only ever has message text (no
    link/file evidence - that's handle_url's own separate reply), so
    link_verdicts/file_verdict are empty/None; _grounded_fallback already
    handles that shape (keyword match + offline scam-pattern similarity
    only) - see its own docstring in context_engine.py. Direct user spec
    (2026-09-11): a single unavailable online service (Gemini here, VT
    for files) shouldn't blank a verdict out to "unknown" when other real
    detectors already ran and have something to say.

    key_reasons here is flattened to plain strings - unlike
    context_engine.py's {text, source}-object schema (format_unified_
    response's contract), this function's only real caller
    (format_analysis_response) has always expected plain strings, same
    as Gemini's own live JSON response above."""
    keyword_result = analyze_text(text)
    fallback = await _grounded_fallback(reason, text, keyword_result, [], None)
    return {
        "verdict": fallback["verdict"],
        "risk_level": _risk_label(fallback["risk_percentage"]),
        "risk_percentage": fallback["risk_percentage"],
        "key_reasons": [r["text"] for r in fallback["key_reasons"]],
        "recommendations": fallback["recommendations"],
        "error": error,
    }


async def analyze_text_with_llm(text: str, user_id: int | None = None) -> dict:
    """`user_id`: when given, gates on the Freemium daily token budget
    and records real usage afterward - see context_engine.py's
    analyze_unified for the same pattern applied to the private-DM/
    business-chat path. None skips both, same reasoning as there."""
    if not _client:
        return await _fallback("LLM analysis is not configured.", "missing_api_key", text)

    if user_id is not None and not subscription.has_token_budget(user_id):
        return await _fallback("Daily AI token budget exhausted.", "token_budget_exhausted", text)

    try:
        response = await generate_content_with_backup(
            _client, _backup_client,
            model=GEMINI_MODEL,
            contents=text,
            config=types.GenerateContentConfig(
                system_instruction=_SYSTEM_PROMPT,
                response_mime_type="application/json",
                response_schema=_RESPONSE_SCHEMA,
            ),
        )
        if user_id is not None and response.usage_metadata is not None:
            subscription.record_token_usage(user_id, response.usage_metadata.total_token_count or 0)
        data = json.loads(response.text)
        risk_percentage = max(0, min(100, int(data.get("risk_percentage", 0))))
        return {
            "verdict": data.get("verdict", "Uncertain"),
            "risk_level": data.get("risk_level", "Unknown"),
            "risk_percentage": risk_percentage,
            "key_reasons": data.get("key_reasons", []),
            "recommendations": data.get("recommendations", []),
        }
    except Exception as error:
        logger.exception("Gemini text analysis failed")
        health_alerts.record_failure("Gemini", str(error))
        await health_alerts.maybe_alert("Gemini", str(error))
        return await _fallback(
            "LLM analysis failed, please try again later.", str(error), text
        )
