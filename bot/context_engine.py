"""
bot/context_engine.py
=======================
Unified reasoning: merges the keyword/LLM text scan (detectors/text/
keyword.py + detectors/text/llm.py) and the full link-checking pipeline
(detectors/url/pipeline.py) into ONE Gemini call, so a message combining
suspicious wording with a link is judged as a whole instead of by two
independent checks that never see each other's evidence.

Productionizes next-gen-test/concepts/context-engineering/context_engine.py,
using the REAL evidence sources (the full lexical + network + domain-age
+ TLS-cert-age + VirusTotal + vector-similarity pipeline) instead of the
prototype's simplified lexical-only stand-in.

Why this exists: bot.py's TEXT_FILTER (formerly a standalone bot/route.py)
used to suppress the text/LLM scanner whenever a private-chat message
contained a link, purely to avoid a
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
from bot.i18n import DEFAULT_LANG
from bot.detectors.text.scam_patterns import nearest_scam_pattern

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "You are a security analyst who reviews Telegram messages for scam and "
    "phishing attempts. The message may come with SYSTEM-GATHERED EVIDENCE - "
    "a keyword prescan, full link-safety findings (lexical patterns, "
    "network/redirect tracing, domain registration age, TLS certificate "
    "age, VirusTotal, and similarity to known phishing/brand patterns), "
    "a similarity score against known scam-MESSAGE scripts (family "
    "emergency, lottery, account verification, romance, investment, job "
    "offer, authority impersonation), and/or a VirusTotal file-scan "
    "result for an attached file - collected by other tools before you. "
    "Treat that evidence as reliable ground truth: do not contradict a "
    "link or file already found dangerous or suspicious. Symmetrically, "
    "a link's system-computed level already reflects the net weight of "
    "its own listed reasons - if a link's level is 'safe', do not "
    "re-litigate or amplify its individual technical reasons (e.g. "
    "certificate age, missing HTTPS) into an independent scam signal on "
    "your own; those were already weighed into that safe verdict, and a "
    "site being one day old or served over plain HTTP is routine for "
    "plenty of real sites, not proof of impersonation by itself. But a "
    "link or file's technical evidence looking clean does NOT mean the message "
    "is safe - weigh how the surrounding text uses it too: urgency, "
    "impersonation, requests for money or credentials, or instructions "
    "not to verify with the sender are strong scam signals on their own, "
    "and a high scam-script similarity score is corroborating evidence "
    "even on its own, but a LOW similarity score does not clear a "
    "message - plenty of real scams don't match any known script. Weigh "
    "the message text and all available evidence together and produce "
    "ONE unified verdict, risk percentage, key reasons, and "
    "recommendations for the message as a whole."
)

# Private DM / Business chat only - the fixed labels around this content
# (VERDICT/risk headers, etc.) are translated separately via i18n.py
# (see verdict_style.py, text_handler.py's format_unified_response) -
# this only asks Gemini to write its OWN dynamic text (key_reasons/
# recommendations) in the user's chosen language, since that content is
# generated fresh every call and can't be pre-translated the way a fixed
# label can. Group chat (format_analysis_response) never calls this with
# anything but the default - out of scope, see bot.py's TEXT_FILTER.
_LANGUAGE_NAMES = {"en": "English", "km": "Khmer (Central Khmer, in the Khmer script)"}


def _system_prompt(lang: str) -> str:
    language_name = _LANGUAGE_NAMES.get(lang, _LANGUAGE_NAMES[DEFAULT_LANG])
    if lang == DEFAULT_LANG:
        return _SYSTEM_PROMPT
    return _SYSTEM_PROMPT + (
        f" Write every key_reasons[].text and every recommendations[] entry in "
        f"natural, fluent {language_name} - not a stiff word-for-word "
        f"translation. The evidence and the user's own message may be in a "
        f"different language than this; read and reason over them as given, "
        f"just WRITE your output in {language_name}. The \"verdict\" field "
        f"itself must still be exactly one of the three fixed English enum "
        f"values (\"Scam\", \"Not a Scam\", \"Uncertain\") - that field is a "
        f"machine-read code, never shown to the user directly, so it does not "
        f"get translated."
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
    pattern_match: tuple[float, str] | None = None,
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
    if pattern_match is not None:
        similarity, category = pattern_match
        evidence["scam_pattern_similarity"] = {
            "closest_known_scam_category": category,
            "similarity": round(similarity, 3),
        }
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
    similarity (see detectors/text/scam_patterns.py) as an extra local
    signal alongside the keyword prescan, so a degraded-mode check is
    meaningfully better than the crude keyword list alone - but ONLY to
    add suspicion, never to clear a message (see SCAM_PATTERN_THRESHOLD).

    `reason` is a diagnostic string for logs only (why the live call
    wasn't used) - it never reaches the user. The caller instead shows
    a single, properly translated `ai_unavailable_notice` (see
    text_handler.py's format_unified_response), so a degraded reply in
    Khmer doesn't mix in raw English boilerplate.
    """
    logger.info("Falling back to offline detection: %s", reason)
    reasons: list[dict] = []

    if keyword_result.get("suspicious"):
        reasons.append({
            "text": f"Matched suspicious keywords: {', '.join(keyword_result['matches'])}.",
            "source": "keyword_match",
        })

    pattern_similarity = 0.0
    if text:
        # No longer a DB call - nearest_scam_pattern is a local, in-memory
        # search (see scam_patterns.py), so unlike the old Supabase-backed
        # lookup this can't fail from a broken connection/exhausted pool.
        # One less way for this LAST-RESORT fallback (Gemini already
        # failed) to itself fail.
        pattern_hits = nearest_scam_pattern(text, k=1)
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
    if file_verdict and file_verdict.get("filename_warning"):
        reasons.append({"text": file_verdict["filename_warning"], "source": "file_evidence"})

    # Derived from whatever evidence actually got appended above - not
    # hand-tracked, so a future evidence source can't add a reason and
    # forget to also flag concern.
    has_concern = len(reasons) > 0

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

    return {
        "verdict": verdict,
        "risk_percentage": risk_percentage,
        "key_reasons": reasons,
        "recommendations": [],
        # Tells the caller's formatter to show one clean, properly
        # translated notice instead of expecting AI-authored reasons/
        # recommendations text (there are none - this IS the no-AI path).
        "ai_unavailable": True,
    }


def _reconcile_with_evidence(
    data: dict,
    link_verdicts: list[dict],
    file_verdict: dict | None,
    pattern_match: tuple[float, str] | None = None,
) -> dict:
    """Hard safety net over Gemini's own verdict: the system prompt only
    ASKS the model not to contradict evidence already found dangerous/
    malicious, but nothing enforced that - a message crafted to talk the
    model out of a correct verdict (prompt injection) or a plain model
    misjudgment could otherwise slip through as "Not a Scam" sitting
    right next to evidence that says otherwise. Mirrors the same
    escalation rule _grounded_fallback already hard-codes (malicious
    file -> Scam, any non-safe link -> at least Uncertain, near-exact
    scam-script match -> at least Uncertain), applied here as a
    correction on top of the model's own answer instead of building the
    verdict from scratch.

    Only ever escalates (weakens a false "safe" claim), never downgrades
    a verdict the model raised on its own - the model may have reasoned
    about surrounding text this function knows nothing about.
    """
    file_flagged = bool(file_verdict and file_verdict.get("malicious", 0) > 0)
    worst_link_score = max((v.get("score", 0) for v in link_verdicts), default=0)
    link_flagged = any(v.get("level") != "safe" for v in link_verdicts)
    pattern_similarity, pattern_category = pattern_match or (0.0, None)
    pattern_flagged = pattern_similarity >= SCAM_PATTERN_THRESHOLD

    verdict = data.get("verdict")
    reasons = list(data.get("key_reasons") or [])
    risk = data.get("risk_percentage")

    if file_flagged and verdict != "Scam":
        logger.warning(
            "context_engine: Gemini returned verdict=%r despite a malicious file "
            "finding - overriding to Scam", verdict,
        )
        data["verdict"] = "Scam"
        data["risk_percentage"] = 100
        reasons.append({
            "text": "Overridden: the attached file was independently confirmed malicious "
                    "by VirusTotal, regardless of the message text.",
            "source": "file_evidence",
        })
        data["key_reasons"] = reasons
    elif verdict == "Not a Scam" and (link_flagged or pattern_flagged):
        logger.warning(
            "context_engine: Gemini returned verdict='Not a Scam' despite "
            "link_flagged=%s pattern_flagged=%s (pattern=%r sim=%.2f) - "
            "overriding to Uncertain",
            link_flagged, pattern_flagged, pattern_category, pattern_similarity,
        )
        data["verdict"] = "Uncertain"
        data["risk_percentage"] = max(risk or 0, min(worst_link_score, 100), int(pattern_similarity * 100))
        if link_flagged:
            reasons.append({
                "text": "Overridden: at least one link in this message was independently "
                        "flagged suspicious or dangerous, regardless of the message text.",
                "source": "link_evidence",
            })
        if pattern_flagged:
            reasons.append({
                "text": f"Overridden: message text closely matches a known '{pattern_category}' "
                        f"scam script ({pattern_similarity:.2f} similarity), regardless of the "
                        f"model's own reading of it.",
                "source": "message_text",
            })
        data["key_reasons"] = reasons

    return data


async def analyze_unified(
    text: str,
    keyword_result: dict,
    link_verdicts: list[dict],
    file_verdict: dict | None = None,
    lang: str = DEFAULT_LANG,
) -> dict:
    """One Gemini call reasoning over the message text, every link's full
    pipeline verdict, and an optional file-scan result together -> one
    verdict dict. `lang` only affects the live Gemini path's dynamic
    key_reasons/recommendations text (see _system_prompt) - the fallback
    below has no such text to translate (it's the already-degraded path,
    no live AI at all), it just sets `ai_unavailable: True` so the
    caller's formatter shows one fixed, translated notice instead. The
    fixed labels around whatever either path returns are always
    translated separately by the caller (verdict_style.py/i18n.py)."""
    # Only surfaced to the model once it clears the same calibrated
    # SCAM_PATTERN_THRESHOLD the fallback already trusts - a low,
    # near-every-message similarity number would just be noise in the
    # evidence blob, not a real signal worth Gemini's attention.
    pattern_match = None
    if text:
        pattern_hits = nearest_scam_pattern(text, k=1)
        if pattern_hits and pattern_hits[0][0] >= SCAM_PATTERN_THRESHOLD:
            pattern_match = (pattern_hits[0][0], pattern_hits[0][3])

    if not _client:
        return await _grounded_fallback(
            "LLM analysis is not configured.", text, keyword_result, link_verdicts, file_verdict
        )

    try:
        response = await _client.aio.models.generate_content(
            model=GEMINI_MODEL,
            contents=_build_contents(text, keyword_result, link_verdicts, file_verdict, pattern_match),
            config=types.GenerateContentConfig(
                system_instruction=_system_prompt(lang),
                response_mime_type="application/json",
                response_schema=_RESPONSE_SCHEMA,
                # No `tools` are ever passed here, so automatic function
                # calling was never actually in play - but the SDK still
                # warns "Direct use of AFC in AsyncModels.generate_content
                # is not recommended" on every single call by default.
                # Explicitly disabling it (rather than migrating to the
                # SDK's AsyncChat.send_message wrapper, a bigger structural
                # change for a call that's genuinely one-shot, not a real
                # multi-turn conversation) silences the warning without
                # changing any actual behavior - confirmed live before
                # this change: the exact same call, with only this field
                # added, prints nothing where it used to warn every time.
                automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True),
            ),
        )
        data = json.loads(response.text)
        if data.get("risk_percentage") is not None:
            data["risk_percentage"] = max(0, min(100, int(data["risk_percentage"])))
        return _reconcile_with_evidence(data, link_verdicts, file_verdict, pattern_match)
    except Exception:                                # noqa: BLE001 - must never break the reply path
        logger.exception("Unified context-engine analysis failed")
        return await _grounded_fallback(
            "LLM analysis failed, please try again later.", text, keyword_result, link_verdicts, file_verdict
        )
