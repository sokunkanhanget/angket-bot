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

from bot.config import GEMINI_API_KEY, GEMINI_MODEL, SCAM_PATTERN_THRESHOLD
from bot.url_checker.features.offline.vectors import nearest as vector_nearest

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "You are a security analyst who reviews Telegram messages for scam and "
    "phishing attempts. The message may come with SYSTEM-GATHERED EVIDENCE - "
    "a keyword prescan, full link-safety findings (lexical patterns, "
    "network/redirect tracing, domain registration age, TLS certificate "
    "age, VirusTotal, and similarity to known phishing/brand patterns), "
    "and/or a VirusTotal file-scan result for an attached file - collected "
    "by other tools before you. Treat that evidence as reliable ground "
    "truth: do not contradict a link or file already found 'dangerous' or "
    "'suspicious'. But a link or file's technical evidence looking clean "
    "does NOT mean the message is safe - weigh how the surrounding text "
    "uses it too: urgency, impersonation, requests for money or "
    "credentials, or instructions not to verify with the sender are strong "
    "scam signals on their own. Weigh the message text and all available "
    "evidence together and produce ONE unified verdict, risk percentage, "
    "key reasons, and recommendations for the message as a whole."
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
                        "enum": ["message_text", "link_evidence", "keyword_match", "file_evidence"],
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


def _build_contents(
    text: str,
    keyword_result: dict,
    link_verdicts: list[dict],
    file_verdict: dict | None,
) -> str:
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
    if file_verdict is not None:
        evidence["file_finding"] = file_verdict
    return (
        "SYSTEM-GATHERED EVIDENCE (not written by the user; already verified - "
        "treat as ground truth, do not re-derive it):\n"
        f"{json.dumps(evidence, ensure_ascii=False)}\n\n"
        "USER MESSAGE TO ANALYZE:\n"
        f"{text}"
    )


async def _grounded_fallback(
    reason: str,
    text: str,
    keyword_result: dict,
    link_verdicts: list[dict],
    file_verdict: dict | None = None,
) -> dict:
    """No API key / call failed -> degrade to real local evidence instead
    of a bare error message. Uses the offline scam-message pattern
    similarity (see features/offline/scam_patterns.py) as an extra local
    signal alongside the keyword prescan, so a degraded-mode check is
    meaningfully better than the crude keyword list alone - but ONLY to
    add suspicion, never to clear a message (see SCAM_PATTERN_THRESHOLD).
    """
    reasons = [{"text": reason, "source": "message_text"}]

    if keyword_result.get("suspicious"):
        reasons.append({
            "text": f"Matched suspicious keywords: {', '.join(keyword_result['matches'])}.",
            "source": "keyword_match",
        })

    pattern_similarity = 0.0
    if text:
        # This runs inside the LAST-RESORT fallback (Gemini already
        # failed) - a DB/network error here (Supabase unreachable, pool
        # exhausted, etc.) must never propagate, or the user gets ZERO
        # reply instead of a degraded one. Same defensive pattern as
        # pipeline.py's _safe_nearest.
        try:
            pattern_hits = await vector_nearest(text, k=1, kinds=("scam_pattern",))
        except Exception:                       # noqa: BLE001 - DB trouble must not kill the fallback
            logger.exception("Offline scam-pattern lookup failed")
            pattern_hits = []
        if pattern_hits and pattern_hits[0][0] >= SCAM_PATTERN_THRESHOLD:
            pattern_similarity, _kind, _key, category = pattern_hits[0]
            reasons.append({
                "text": f"Message text closely matches a known '{category}' scam script "
                        f"(offline pattern match, {pattern_similarity:.2f} similarity).",
                "source": "message_text",
            })

    for v in link_verdicts:
        if v.get("level") != "safe":
            detail = v["reasons"][0] if v.get("reasons") else f"{v.get('host')} flagged {v.get('level')}"
            reasons.append({"text": f"{v.get('host')}: {detail}", "source": "link_evidence"})

    file_flagged = bool(file_verdict and file_verdict.get("malicious", 0) > 0)
    if file_flagged:
        reasons.append({
            "text": f"VirusTotal: {file_verdict['malicious']} engine(s) flag the attached file as malicious.",
            "source": "file_evidence",
        })

    # Derived from whatever evidence actually got appended above (index 0
    # is always the base `reason` disclaimer, not evidence) - not
    # hand-tracked, so a future evidence source can't add a reason and
    # forget to also flag concern.
    has_concern = len(reasons) > 1

    worst_link_score = max((v.get("score", 0) for v in link_verdicts), default=0)
    pattern_score = int(pattern_similarity * 100)
    risk_percentage = None
    if link_verdicts or file_verdict is not None or pattern_score:
        # A confident offline pattern match must show up in the risk
        # number too, not just the reasons list - otherwise a near-exact
        # scam-script match with no link/file renders as "N/A Unknown
        # Risk" right next to an "Uncertain" verdict, undercutting
        # exactly the signal this fallback exists to surface.
        risk_percentage = 100 if file_flagged else max(min(worst_link_score, 100), pattern_score)

    if file_flagged:
        verdict = "Scam"
    elif has_concern:
        verdict = "Uncertain"
    else:
        verdict = "Not a Scam"

    reasons.append({
        "text": "Full AI reasoning was unavailable for this check - this result uses "
                "offline pattern matching only and may be less accurate than usual.",
        "source": "message_text",
    })

    return {
        "verdict": verdict,
        "risk_percentage": risk_percentage,
        "key_reasons": reasons,
        "recommendations": [],
    }


async def analyze_unified(
    text: str,
    keyword_result: dict,
    link_verdicts: list[dict],
    file_verdict: dict | None = None,
) -> dict:
    """One Gemini call reasoning over the message text, every link's full
    pipeline verdict, and an optional file-scan result together -> one
    verdict dict."""
    if not _client:
        return await _grounded_fallback(
            "LLM analysis is not configured.", text, keyword_result, link_verdicts, file_verdict
        )

    try:
        response = await _client.aio.models.generate_content(
            model=GEMINI_MODEL,
            contents=_build_contents(text, keyword_result, link_verdicts, file_verdict),
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
    except Exception:                                # noqa: BLE001 - must never break the reply path
        logger.exception("Unified context-engine analysis failed")
        return await _grounded_fallback(
            "LLM analysis failed, please try again later.", text, keyword_result, link_verdicts, file_verdict
        )
