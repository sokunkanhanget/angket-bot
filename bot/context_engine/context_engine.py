"""
bot/context_engine/context_engine.py
=======================================
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
import re

from google.genai import types

from bot.config.config import GEMINI_MODEL, SCAM_PATTERN_THRESHOLD, BGE_M3_PATTERN_THRESHOLD
from bot.detectors.text.online.gemini_retry import build_clients, generate_content_with_backup
from bot.response.translate import DEFAULT_LANG
from bot.detectors.text.offline.scam_patterns import nearest_scam_pattern, nearest_scam_pattern_live
from bot.storage import subscription
from bot.storage import health_alerts

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
    "This evidence is a MIX of two tiers, and you must weigh them "
    "differently. CONFIRMED evidence - a VirusTotal detection on a link, "
    "or a VirusTotal malicious result on a file - must never be "
    "contradicted, downgraded, or explained away: if it says malicious, "
    "the verdict is Scam regardless of how innocent the message reads. "
    "HEURISTIC evidence is everything the bot computed itself (lexical "
    "URL patterns, domain and TLS certificate age, brand-keyword page "
    "matches, phishing/brand/seen vector similarity). Each link finding "
    "carries a \"confirmed\" flag; a finding with \"confirmed\": false is "
    "a strong but fallible signal that can be wrong. A brand-new domain, "
    "a fresh certificate, plain HTTP, or a page that merely names a bank "
    "are routine for legitimate sites and are not proof of a scam by "
    "themselves. You MAY apply judgment to a heuristic-only finding: "
    "when the message and its context give a POSITIVE reason to believe "
    "the link is legitimate (a known company's own site, no fraudulent "
    "claims, no request for money or credentials, no pressure to act), "
    "you may treat a heuristic-only 'suspicious' finding as a prompt to "
    "verify rather than proof of a scam, and lower the risk accordingly. "
    "Do NOT clear a heuristic finding merely because the wording is "
    "smooth - downgrade only on a real, stated reason to trust the "
    "destination, never on the absence of red flags alone. Symmetrically, "
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
    "message - plenty of real scams don't match any known script. When "
    "a link finding names a specific host or domain (e.g. a redirect "
    "destination, or the real target behind mismatched display text), "
    "state that exact domain in your own key_reasons text rather than "
    "generalizing it away (\"redirects to an external site\") - the "
    "specific domain is exactly what lets a reader judge it for "
    "themselves, and omitting it removes real information the evidence "
    "already gave you. If the evidence includes a \"sender_identity\" "
    "field (the VERIFIED sender's own name/username - only ever present "
    "for Business-chat automation, where the sender is a real connected "
    "customer, never spoofable the way a plain chat display name is), "
    "and a link finding's mismatched-display or redirect-destination "
    "domain is a plausible variation of that same name, you may treat "
    "that as a mitigating signal weakening the 'deceptive redirect' "
    "reading (e.g. someone's own vanity domain forwarding to their own "
    "portfolio) - but this alone does not clear a heuristic finding; "
    "still weigh it against the rest of the evidence and message intent "
    "normally, the same as any other positive-context signal. Weigh "
    "the message text and all available evidence together and produce "
    "ONE unified verdict, risk percentage, key reasons, and "
    "recommendations for the message as a whole."
)

# Private DM / Business chat only - the fixed labels around this content
# (VERDICT/risk headers, etc.) are translated separately via
# bot/response/translate/ (see verdict_style.py, text_handler.py's
# format_unified_response) -
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

_client, _backup_client = build_clients()

# A risk_percentage this high reads to a user as near-certainty. That's
# only defensible when backed by independently-confirmed evidence (a
# real VirusTotal detection) - not when it's Gemini's own reading of a
# page (e.g. "this impersonates Telegram") or an offline similarity
# heuristic (lexical/domain-age/vector-pattern match), however
# confident that reasoning sounds. A wrong 95% is a much bigger
# trust/liability hit than a wrong 80% - confirmed live: broryat.tech
# scored 60 on the offline pipeline (no HTTPS + young domain + a brand-
# impersonation keyword match, none of it VT-confirmed) but Gemini's
# own holistic read pushed it to 95%, which overclaims certainty the
# evidence doesn't actually back. Applied uniformly to both the live
# Gemini path (_reconcile_with_evidence) and the offline fallback
# (_grounded_fallback) so the same policy holds regardless of which
# path produced the number.
UNCORROBORATED_RISK_CAP = 80


# --- Deterministic short-circuit for the one genuinely context-free,
# high-variance case ------------------------------------------------------
# A BARE link (no message text to reason about) whose ONLY adverse signal
# is that it doesn't resolve / can't be reached carries almost no
# information: it's equally consistent with a typo, a transient outage,
# and dead-or-pre-launch phishing infrastructure. Handing that to Gemini
# produced wildly different risk numbers between otherwise-identical calls
# (observed 30 vs 80 on the same non-resolving host), because there is
# nothing there to reason about - the model is weighing pure noise. A
# fixed, honest "couldn't verify, be cautious" is more consistent, saves a
# token-budgeted Gemini call, and never claims false certainty. This ONLY
# ever replaces that pure-noise case: anything with real message text, a
# hard signal, a VirusTotal detection, a scam-script match, or a second
# link falls through to Gemini exactly as before.
UNVERIFIABLE_DEAD_LINK_RISK = 30
# Max score a link can reach from connectivity failure alone:
# 25 (no DNS resolution) + 15 (server unreachable) + 5 (plain HTTP).
# Above this, some real content/scam signal must have contributed, so it
# is NOT a pure dead link - see bot/detectors/url/pipeline.py.
_CONNECTIVITY_ONLY_MAX = 45
# Stable substrings of the pipeline's own connectivity reasons. Matched
# loosely so a wording tweak in the pipeline simply disables this
# optimization (falls back to Gemini) rather than misfiring.
_CONNECTIVITY_REASON_MARKERS = ("does not resolve", "could not be reached")

_URL_LIKE = re.compile(r"https?://\S+|www\.\S+", re.IGNORECASE)
_DOMAINISH = re.compile(r"[^\s]+\.[^\s]{2,}")


def _message_is_only_links(text: str, link_verdicts: list[dict]) -> bool:
    """True when the message has no real content to reason about beyond
    the link(s) themselves - i.e. a bare pasted URL. Strips URLs, the
    known link hosts, and any bare-domain tokens, then checks that no
    wordy content remains. Unicode-aware, so a Khmer sentence around the
    link correctly counts as real context and keeps this from firing."""
    if not text or not text.strip():
        return True
    leftover = _URL_LIKE.sub(" ", text)
    for v in link_verdicts:
        host = v.get("host")
        if host:
            leftover = leftover.replace(host, " ")
    leftover = _DOMAINISH.sub(" ", leftover)
    return not re.sub(r"[^\w]", "", leftover, flags=re.UNICODE).strip()


def _unverifiable_dead_link(
    text: str,
    link_verdicts: list[dict],
    file_verdict: dict | None,
    pattern_match: tuple[float, str] | None,
) -> dict | None:
    """Return a fixed 'couldn't verify' verdict for the pure dead-link,
    no-context case, or None to let the normal Gemini path run. Written
    to fail SAFE: every condition that isn't clearly met returns None, so
    this can only ever replace the ambiguous-noise case, never suppress a
    real signal."""
    if file_verdict and file_verdict.get("malicious", 0) > 0:
        return None
    if pattern_match is not None:
        return None
    if len(link_verdicts) != 1:
        return None
    v = link_verdicts[0]
    # Only the middle "suspicious" band: a 'safe' link needs no caution,
    # a 'dangerous' one is too strong to short-circuit as mere noise.
    if v.get("level") != "suspicious":
        return None
    if _has_confirmed_evidence(link_verdicts, file_verdict):
        return None
    if v.get("score", 0) > _CONNECTIVITY_ONLY_MAX:
        return None
    reasons = v.get("reasons") or []
    if not any(any(m in r for m in _CONNECTIVITY_REASON_MARKERS) for r in reasons):
        return None
    if not _message_is_only_links(text, link_verdicts):
        return None

    logger.info("deterministic dead-link short-circuit for %s (score=%s)",
                v.get("host"), v.get("score"))
    return {
        "verdict": "Uncertain",
        "risk_percentage": UNVERIFIABLE_DEAD_LINK_RISK,
        "key_reasons": [{
            "text": "This link could not be verified: its address does not resolve or the "
                    "server can't be reached, and the message has no other text to judge it "
                    "by. That is a weak caution, not proof of a scam - dead links, typos and "
                    "temporarily offline pages look the same from here.",
            "source": "link_evidence",
        }],
        "recommendations": [
            "Don't enter any login or payment details on this link until you have confirmed it is genuine.",
            "If someone sent it to you, check through a channel you trust that they really meant to.",
        ],
    }


def _has_confirmed_evidence(link_verdicts: list[dict], file_verdict: dict | None) -> bool:
    """True only for evidence an independent third party actually
    verified - a real VirusTotal detection on the link or the file.
    Deliberately excludes offline pipeline evidence (lexical patterns,
    domain/TLS age, vector-similarity brand/phish/seen matches) and
    scam-script pattern similarity - those are heuristics this bot
    computed itself, not outside confirmation, however strongly they
    point the same direction."""
    if file_verdict and file_verdict.get("malicious", 0) > 0:
        return True
    return any(
        "VirusTotal" in reason
        for v in link_verdicts
        for reason in (v.get("reasons") or [])
    )


def _build_contents(
    text: str,
    keyword_result: dict,
    link_verdicts: list[dict],
    file_verdict: dict | None,
    pattern_match: tuple[float, str] | None = None,
    sender_identity: dict | None = None,
) -> str:
    evidence = {
        "keyword_prescan": keyword_result,
        "link_findings": [
            {
                "host": v.get("host"),
                "level": v.get("level"),
                "score": v.get("score"),
                "reasons": v.get("reasons"),
                # Same rule as _has_confirmed_evidence - an independent
                # third party (VirusTotal) actually verified this finding,
                # vs. everything else here being a heuristic the bot
                # computed itself. The system prompt explains how to
                # weigh the two differently.
                "confirmed": any("VirusTotal" in r for r in (v.get("reasons") or [])),
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
    if sender_identity is not None:
        # Business-chat automation only (see analyze_unified's own
        # docstring and the system prompt) - private DM/group chat never
        # pass this, so this field is simply absent there, not empty.
        evidence["sender_identity"] = sender_identity
    return (
        "SYSTEM-GATHERED EVIDENCE (not written by the user; already gathered - "
        "do not re-derive it. Each link finding carries a \"confirmed\" flag - "
        "see the system prompt for how to weigh confirmed vs heuristic evidence):\n"
        f"{json.dumps(evidence, ensure_ascii=False)}\n\n"
        "USER MESSAGE TO ANALYZE:\n"
        f"{text}"
    )


# Same voice/tone as pipeline.py's own _RECOMMENDATIONS (dangerous/
# suspicious/safe) - this fallback's verdict vocabulary is Scam/
# Uncertain/Not a Scam instead, matching every other surface's.
_FALLBACK_RECOMMENDATIONS = {
    "Scam": [
        "Do not click any links, open any files, or share personal or financial details.",
        "Block and report the sender - this pattern matches known scam tactics.",
    ],
    "Uncertain": [
        "Don't share personal details, click links, or send money until you're sure this is legitimate.",
        "Verify with the sender through a separate channel before acting.",
    ],
    "Not a Scam": [
        "No strong scam signals were found, but stay cautious with anything unexpected.",
    ],
}


async def _grounded_fallback(
    reason: str,
    text: str,
    keyword_result: dict,
    link_verdicts: list[dict],
    file_verdict: dict | None = None,
) -> dict:
    """Also imported directly by bot/detectors/text/online/llm.py (the
    separate group-chat text-only Gemini call) - the leading underscore
    is this module's own "internal to its reasoning pipeline" convention,
    not real Python privacy; that reuse is deliberate (see llm.py's
    _fallback docstring) rather than duplicating this logic a second
    time. Keep both call shapes in mind before changing this signature.

    No API key / call failed -> degrade to real local evidence instead
    of a bare error message. Uses the offline scam-message pattern
    similarity (see detectors/text/scam_patterns.py) as an extra local
    signal alongside the keyword prescan, so a degraded-mode check is
    meaningfully better than the crude keyword list alone - but ONLY to
    add suspicion, never to clear a message (see SCAM_PATTERN_THRESHOLD).

    `reason` is a diagnostic string for logs only (why the live call
    wasn't used) - it never reaches the user. Direct user spec
    (2026-09-11): the reply shows this fallback's OWN real key_reasons/
    recommendations as if it were any other verdict, not a generic "AI
    reasoning was unavailable" admission - `ai_unavailable` stays in the
    returned dict (useful for logs/tests) but the formatters no longer
    branch the DISPLAY on it.
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
                "text": f"Message text closely matches a known '{category}' scam script.",
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
        if not _has_confirmed_evidence(link_verdicts, file_verdict):
            risk_percentage = min(risk_percentage, UNCORROBORATED_RISK_CAP)

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
        # list(...) - _FALLBACK_RECOMMENDATIONS[verdict] is a shared
        # module-level constant; handing back the same list object by
        # reference would let any future in-place mutation by a caller
        # (e.g. appending a translated hint) permanently corrupt it for
        # every subsequent fallback reply for the life of the process.
        "recommendations": list(_FALLBACK_RECOMMENDATIONS[verdict]),
        # Internal/log-only now - see this function's own docstring for
        # why the formatters no longer special-case display on this.
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

    The "Not a Scam" -> "Uncertain" escalation below is tiered the same
    way the system prompt now is: it only force-fires on a CONFIRMED
    (VirusTotal) flagged link, not a heuristic-only one. A heuristic
    finding (lexical/domain-age/brand-keyword/vector-similarity) can be
    wrong - see UNCORROBORATED_RISK_CAP's docstring for the broryat.tech
    false positive that motivated this - so once the system prompt
    explicitly allows Gemini to weigh a heuristic-only finding against
    real, positive context and deliberately call it "Not a Scam", this
    safety net must not immediately reverse that judgment call. A
    CONFIRMED (VirusTotal) finding is never allowed to be reasoned away
    this way, matching the file-malicious override just above.
    """
    file_flagged = bool(file_verdict and file_verdict.get("malicious", 0) > 0)
    worst_link_score = max((v.get("score", 0) for v in link_verdicts), default=0)
    confirmed_link_flagged = any(
        v.get("level") != "safe" and any("VirusTotal" in r for r in (v.get("reasons") or []))
        for v in link_verdicts
    )
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
    elif verdict == "Not a Scam" and (confirmed_link_flagged or pattern_flagged):
        logger.warning(
            "context_engine: Gemini returned verdict='Not a Scam' despite "
            "confirmed_link_flagged=%s pattern_flagged=%s (pattern=%r sim=%.2f) - "
            "overriding to Uncertain",
            confirmed_link_flagged, pattern_flagged, pattern_category, pattern_similarity,
        )
        data["verdict"] = "Uncertain"
        data["risk_percentage"] = max(risk or 0, min(worst_link_score, 100), int(pattern_similarity * 100))
        if confirmed_link_flagged:
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

    # Final, uniform policy step regardless of which branch above (or
    # neither) produced this number: a risk_percentage this high must be
    # backed by independently-confirmed evidence, not just Gemini's own
    # reasoning or an offline similarity heuristic - see
    # UNCORROBORATED_RISK_CAP's docstring. Runs last so it also catches
    # Gemini's own risk_percentage when neither override branch fired.
    if isinstance(data.get("risk_percentage"), int) and not _has_confirmed_evidence(link_verdicts, file_verdict):
        data["risk_percentage"] = min(data["risk_percentage"], UNCORROBORATED_RISK_CAP)

    return data


async def analyze_unified(
    text: str,
    keyword_result: dict,
    link_verdicts: list[dict],
    file_verdict: dict | None = None,
    lang: str = DEFAULT_LANG,
    user_id: int | None = None,
    sender_identity: dict | None = None,
) -> dict:
    """One Gemini call reasoning over the message text, every link's full
    pipeline verdict, and an optional file-scan result together -> one
    verdict dict. `lang` only affects the live Gemini path's dynamic
    key_reasons/recommendations text (see _system_prompt) - the fallback
    below has no such text to translate (it's the already-degraded path,
    no live AI at all), it just sets `ai_unavailable: True` so the
    caller's formatter shows one fixed, translated notice instead. The
    fixed labels around whatever either path returns are always
    translated separately by the caller (verdict_style.py, which reaches
    into bot/response/translate/ and bot/response/buttons.py).

    `user_id`: when given, gates on the Freemium daily token budget
    (bot/storage/subscription.py) and records real usage from Gemini's
    own usage_metadata after a successful call. None (the default) skips
    both - callers that don't have a real per-user identity (there
    currently are none in production, but this keeps the function
    usable standalone/in tests without forcing every caller to pass one)
    just always get the live path if the client is configured.

    `sender_identity`: {"name": ..., "username": ...} for the VERIFIED
    sender, e.g. {"name": sender.full_name, "username": sender.username}.
    Business-chat automation ONLY (see the system prompt for why) - lets
    Gemini treat a link's mismatched/redirect domain as less suspicious
    when it plausibly matches the sender's own name (a real false
    positive this fixed: a customer's own vanity-domain-to-Vercel-
    portfolio redirect scored 65-80% "Scam" before this). Never pass
    this for private DM/group chat - a plain chat display name is
    trivially spoofable, unlike a Business connection's verified
    customer identity, so the same leniency there would be exploitable."""
    # Only surfaced to the model once it clears the same calibrated
    # SCAM_PATTERN_THRESHOLD the fallback already trusts - a low,
    # near-every-message similarity number would just be noise in the
    # evidence blob, not a real signal worth Gemini's attention.
    pattern_match = None
    if text:
        # The live path prefers bge-m3 (genuinely Khmer-capable) when
        # enabled, with a safe, automatic fallback to the fast hashed
        # scheme baked into nearest_scam_pattern_live itself - see
        # scam_patterns.py. _grounded_fallback below deliberately keeps
        # calling the plain synchronous nearest_scam_pattern() instead:
        # that path only runs once Gemini has ALREADY failed, and it
        # exists specifically to answer fast without depending on
        # anything else that could also be down (Ollama included) -
        # adding a possible embedding-timeout wait to an "everything's
        # already on fire" fallback would work against its own purpose.
        pattern_hits, used_bge_m3 = await nearest_scam_pattern_live(text, k=1)
        # bge-m3 runs measurably hotter than the hashed scheme (real
        # benign text can score ~0.59) - reusing SCAM_PATTERN_THRESHOLD
        # for it would false-positive on ordinary messages, so the
        # threshold has to match whichever scheme actually ran, not
        # just whether the feature flag is on (bge-m3 can still fall
        # back to the hashed scheme mid-call if Ollama drops out).
        threshold = BGE_M3_PATTERN_THRESHOLD if used_bge_m3 else SCAM_PATTERN_THRESHOLD
        if pattern_hits and pattern_hits[0][0] >= threshold:
            pattern_match = (pattern_hits[0][0], pattern_hits[0][3])

    # Deterministic short-circuit BEFORE the Gemini call (and before the
    # budget check - it costs no tokens): a bare, non-resolving/unreachable
    # link with no other signal is pure noise the model just guesses on.
    # Returns a fixed "couldn't verify" verdict, or None to proceed normally.
    dead_link = _unverifiable_dead_link(text, link_verdicts, file_verdict, pattern_match)
    if dead_link is not None:
        return dead_link

    if not _client:
        return await _grounded_fallback(
            "LLM analysis is not configured.", text, keyword_result, link_verdicts, file_verdict
        )

    if user_id is not None and not subscription.has_token_budget(user_id):
        # Same graceful-degradation path as "Gemini isn't configured" -
        # the offline signals (keyword/link/file verdicts, scam-pattern
        # similarity) still produce a real answer, just without live AI
        # reasoning, exactly like an actual Gemini outage would.
        return await _grounded_fallback(
            "Daily AI token budget exhausted.", text, keyword_result, link_verdicts, file_verdict
        )

    try:
        response = await generate_content_with_backup(
            _client, _backup_client,
            model=GEMINI_MODEL,
            contents=_build_contents(
                text, keyword_result, link_verdicts, file_verdict, pattern_match, sender_identity,
            ),
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
        if user_id is not None and response.usage_metadata is not None:
            subscription.record_token_usage(user_id, response.usage_metadata.total_token_count or 0)
        data = json.loads(response.text)
        if data.get("risk_percentage") is not None:
            data["risk_percentage"] = max(0, min(100, int(data["risk_percentage"])))
        return _reconcile_with_evidence(data, link_verdicts, file_verdict, pattern_match)
    except Exception as error:                       # noqa: BLE001 - must never break the reply path
        logger.exception("Unified context-engine analysis failed")
        health_alerts.record_failure("Gemini", str(error))
        await health_alerts.maybe_alert("Gemini", str(error))
        return await _grounded_fallback(
            "LLM analysis failed, please try again later.", text, keyword_result, link_verdicts, file_verdict
        )
