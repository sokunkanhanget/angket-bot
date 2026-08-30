"""
bot/context_engine.py
=======================
Unified reasoning: merges the keyword/LLM text scan (text_analyzer.py +
llm_analyzer.py) and the full link-checking pipeline
(url_checker/pipeline.py) into ONE Gemini call, so a message combining
suspicious wording with a link is judged as a whole instead of by two
independent checks that never see each other's evidence.

Productionizes next-gen-test/concepts/context-engineering/context_engine.py,
using the REAL evidence sources (the full lexical + network + domain-age
+ TLS-cert-age + VirusTotal + vector-similarity pipeline) instead of the
prototype's simplified lexical-only stand-in.

Why this exists: bot/route.py used to suppress the text/LLM scanner
whenever a private-chat message contained a link, purely to avoid a
duplicate reply. That meant a text-only scam (e.g. a "send money now,
don't call" family-emergency scam) that happened to include ANY link -
including a lexically clean one - lost its text reasoning entirely and
fell back to a link-only verdict with no idea the surrounding message
is a scam. Verified live: the same "Hi Mom" scam scored 95% ("Scam")
through the text-only path, but only 40% ("Suspicious") once a clean,
unreachable link was added, purely because the link takeover silently
disabled the smarter check. See context-engineering-design.doc for the
full design history reviewed with the team.
"""

from __future__ import annotations

import json
import logging

from google import genai
from google.genai import types

from bot.config import GEMINI_API_KEY, GEMINI_MODEL

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "You are a security analyst who reviews Telegram messages for scam and "
    "phishing attempts. The message may come with SYSTEM-GATHERED EVIDENCE - "
    "a keyword prescan and/or full link-safety findings (lexical patterns, "
    "network/redirect tracing, domain registration age, TLS certificate "
    "age, VirusTotal, and similarity to known phishing/brand patterns) "
    "collected by other tools before you. Treat that evidence as reliable "
    "ground truth: do not contradict a link already found 'dangerous' or "
    "'suspicious'. But a link's technical evidence looking clean does NOT "
    "mean the message is safe - weigh how the surrounding text uses that "
    "link too: urgency, impersonation, requests for money or credentials, "
    "or instructions not to verify with the sender are strong scam signals "
    "on their own. Weigh the message text and the evidence together and "
    "produce ONE unified verdict, risk percentage, key reasons, and "
    "recommendations for the message as a whole."
)

_RESPONSE_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {"type": "string", "enum": ["Scam", "Not a Scam", "Uncertain"]},
        "risk_percentage": {"type": "integer"},
        "key_reasons": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "text": {"type": "string"},
                    "source": {
                        "type": "string",
                        "enum": ["message_text", "link_evidence", "keyword_match"],
                    },
                },
                "required": ["text", "source"],
            },
        },
        "recommendations": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["verdict", "risk_percentage", "key_reasons", "recommendations"],
}

_client = genai.Client(api_key=GEMINI_API_KEY) if GEMINI_API_KEY else None


def _build_contents(text: str, keyword_result: dict, link_verdicts: list[dict]) -> str:
    evidence = {
        "keyword_prescan": keyword_result,
        "link_findings": [
            {
                "host": v.get("host"),
                "level": v.get("level"),
                "score": v.get("score"),
                "reasons": v.get("reasons"),
            }
            for v in link_verdicts
        ],
    }
    return (
        "SYSTEM-GATHERED EVIDENCE (not written by the user; already verified - "
        "treat as ground truth, do not re-derive it):\n"
        f"{json.dumps(evidence, ensure_ascii=False)}\n\n"
        "USER MESSAGE TO ANALYZE:\n"
        f"{text}"
    )


def _grounded_fallback(reason: str, keyword_result: dict, link_verdicts: list[dict]) -> dict:
    """No API key / call failed -> degrade to real local evidence, matching
    llm_analyzer.py's and the prototype's fallback shape rather than a
    bare error message."""
    reasons = [{"text": reason, "source": "message_text"}]
    if keyword_result.get("suspicious"):
        reasons.append({
            "text": f"Matched suspicious keywords: {', '.join(keyword_result['matches'])}.",
            "source": "keyword_match",
        })
    for v in link_verdicts:
        if v.get("level") != "safe":
            detail = v["reasons"][0] if v.get("reasons") else f"{v.get('host')} flagged {v.get('level')}"
            reasons.append({"text": f"{v.get('host')}: {detail}", "source": "link_evidence"})

    worst = max((v.get("score", 0) for v in link_verdicts), default=0)
    return {
        "verdict": "Uncertain",
        "risk_percentage": min(worst, 100) if link_verdicts else None,
        "key_reasons": reasons,
        "recommendations": [],
    }


async def analyze_unified(text: str, keyword_result: dict, link_verdicts: list[dict]) -> dict:
    """One Gemini call reasoning over the message text AND every link's
    full pipeline verdict together -> one verdict dict."""
    if not _client:
        return _grounded_fallback("LLM analysis is not configured.", keyword_result, link_verdicts)

    try:
        response = await _client.aio.models.generate_content(
            model=GEMINI_MODEL,
            contents=_build_contents(text, keyword_result, link_verdicts),
            config=types.GenerateContentConfig(
                system_instruction=_SYSTEM_PROMPT,
                response_mime_type="application/json",
                response_schema=_RESPONSE_SCHEMA,
            ),
        )
        data = json.loads(response.text)
        if data.get("risk_percentage") is not None:
            data["risk_percentage"] = max(0, min(100, int(data["risk_percentage"])))
        return data
    except Exception as error:                      # noqa: BLE001 - must never break the reply path
        logger.exception("Unified context-engine analysis failed")
        return _grounded_fallback(
            "LLM analysis failed, please try again later.", keyword_result, link_verdicts
        )
