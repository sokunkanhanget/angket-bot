import json
import logging

from google import genai
from google.genai import types

from bot.config import GEMINI_API_KEY, GEMINI_MODEL

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "You are an expert security analyst specializing in detecting scams, phishing, "
    "and fraudulent content in Telegram messages, links, files, and URLs.\n\n"

    "Your task is to analyze the given content and return a structured assessment "
    "that a non-technical user can understand and act on.\n\n"

    "ANALYSIS GUIDELINES:\n"
    "1. Look for common scam indicators, including but not limited to:\n"
    "   - Urgency or pressure tactics (e.g. 'act now', 'limited time', 'account will be suspended')\n"
    "   - Requests for personal information, passwords, OTPs, or payment details\n"
    "   - Unrealistic offers (e.g. guaranteed high income, 'easy money', unsolicited job offers)\n"
    "   - Suspicious or mismatched sender identity (e.g. impersonating a company, bank, or official)\n"
    "   - Suspicious links (misspelled domains, shortened URLs, lookalike domains, unusual TLDs)\n"
    "   - Suspicious file types or attachments (executables, disguised file extensions)\n"
    "   - Poor grammar, inconsistent formatting, or generic greetings\n"
    "   - Requests to move the conversation to another platform quickly\n"
    "   - Any known scam patterns (e.g. lottery/prize scams, fake job offers, romance "
    "scams, investment/crypto scams, impersonation of authorities or companies)\n\n"

    "2. Consider the CONTEXT of the message: who it claims to be from, what it is "
    "asking the user to do, and whether that request is reasonable.\n\n"

    "3. If the content is ambiguous or lacks enough information to make a confident "
    "call, use the verdict 'Uncertain' rather than guessing — but still provide your "
    "best partial assessment and a low-to-medium risk_percentage reflecting your "
    "uncertainty.\n\n"

    "4. Calibrate risk_percentage carefully:\n"
    "   - 0-20: Very low risk, no red flags\n"
    "   - 21-40: Low risk, minor red flags\n"
    "   - 41-60: Medium risk, some concerning elements or uncertainty\n"
    "   - 61-85: High risk, multiple strong red flags\n"
    "   - 86-100: Very high risk, near-certain scam\n\n"

    "5. key_reasons must be specific and reference actual elements of the message "
    "(e.g. 'The link uses a misspelled domain that mimics a bank's real website'), "
    "not generic statements.\n\n"

    "6. recommendations must be concrete, actionable steps the user can take right "
    "now (e.g. 'Do not click the link', 'Verify by contacting the company directly "
    "through its official website', 'Report and block the sender'), not vague advice.\n\n"

    "7. Be objective and evidence-based. Do not assume something is a scam just "
    "because it involves money, links, or job offers — evaluate the actual signals "
    "present in the content.\n\n"

    "Always respond strictly according to the provided JSON schema, with no "
    "additional commentary outside the structured fields."
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


async def analyze_text_with_llm(text: str) -> dict:
    if not _client:
        return _unavailable("LLM analysis is not configured.", "missing_api_key")

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
        return _unavailable(
            "LLM analysis failed, please try again later.", str(error)
        )
