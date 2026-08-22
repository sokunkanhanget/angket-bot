import json
import logging

from google import genai
from google.genai import types

from bot.config import GEMINI_API_KEY, GEMINI_MODEL

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "You are a security analyst who reviews Telegram messages for scam and phishing "
    "attempts. Read the message and produce a verdict, a risk level, the key reasons "
    "behind your verdict, and clear recommendations for what the user can do next."
)

_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["Scam", "Not a Scam", "Uncertain"]},
        "risk_level": {"type": "string", "enum": ["Low", "Medium", "High"]},
        "risk_percentage": {"type": "integer"},
        "key_reasons": {"type": "array", "items": {"type": "string"}},
        "recommendations": {"type": "array", "items": {"type": "string"}},
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
