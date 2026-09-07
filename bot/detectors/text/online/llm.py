import json
import logging

from google import genai
from google.genai import types

from bot.config import GEMINI_API_KEY, GEMINI_MODEL
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

_client = genai.Client(api_key=GEMINI_API_KEY) if GEMINI_API_KEY else None


def _unavailable(reason: str, error: str) -> dict:
    return {
        "verdict": "Uncertain",
        "risk_level": "Unknown",
        "risk_percentage": None,
        "key_reasons": [reason],
        "recommendations": [],
        "error": error,
    }


async def analyze_text_with_llm(text: str, user_id: int | None = None) -> dict:
    """`user_id`: when given, gates on the Freemium daily token budget
    and records real usage afterward - see context_engine.py's
    analyze_unified for the same pattern applied to the private-DM/
    business-chat path. None skips both, same reasoning as there."""
    if not _client:
        return _unavailable("LLM analysis is not configured.", "missing_api_key")

    if user_id is not None and not subscription.has_token_budget(user_id):
        return _unavailable("Daily AI token budget exhausted.", "token_budget_exhausted")

    try:
        response = await _client.aio.models.generate_content(
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
        return _unavailable(
            "LLM analysis failed, please try again later.", str(error)
        )
