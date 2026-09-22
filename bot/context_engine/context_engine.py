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

from bot.config.config import GEMINI_MODEL, SCAM_PATTERN_THRESHOLD, BGE_M3_PATTERN_THRESHOLD, GEMINI_EMBED_PATTERN_THRESHOLD
from bot.detectors.text.online.gemini_retry import GeminiCircuitOpenError, build_clients, generate_content_with_backup
from bot.response.translate import DEFAULT_LANG
from bot.response.buttons import t
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


# Appended to _SYSTEM_PROMPT for any non-default lang - split out as its
# own constant so _system_prompt itself is just a 1-line concatenation.
_NON_DEFAULT_LANG_SUFFIX_TEMPLATE = (
    " Write every key_reasons[].text and every recommendations[] entry in "
    "natural, fluent {language_name} - not a stiff word-for-word "
    "translation. The evidence and the user's own message may be in a "
    "different language than this; read and reason over them as given, "
    "just WRITE your output in {language_name}. The \"verdict\" field "
    "itself must still be exactly one of the three fixed English enum "
    "values (\"Scam\", \"Not a Scam\", \"Uncertain\") - that field is a "
    "machine-read code, never shown to the user directly, so it does not "
    "get translated."
)


def _system_prompt(lang: str) -> str:
    if lang == DEFAULT_LANG:
        return _SYSTEM_PROMPT
    language_name = _LANGUAGE_NAMES.get(lang, _LANGUAGE_NAMES[DEFAULT_LANG])
    return _SYSTEM_PROMPT + _NON_DEFAULT_LANG_SUFFIX_TEMPLATE.format(language_name=language_name)

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
    link correctly counts as real context and keeps this from firing.

    Real bug fixed 2026-09-19: this used to strip each verdict's bare
    `host` only, never the verdict's own `raw` (the exact matched URL,
    path/query included - see lexical.check_url's "raw" key). A schemeless
    shortened link with a path (e.g. "bit.ly/promo123") never matches
    _URL_LIKE at all (no http://, no www.), so stripping only "bit.ly"
    left "/promo123" behind - and since it has no dot, _DOMAINISH doesn't
    catch it either - so the leftover "promo123" made this wrongly return
    False for a message that really is nothing but a bare link. That, in
    turn, disqualified the message from both the dead-link short-circuit
    (_dead_link_disqualified) and the free trusted-bare-link notice
    (_trusted_bare_link_verdict), silently forcing an unnecessary live
    Gemini call - in private DM and in Business chat automation alike,
    since both route through this same function. pipeline.py's own
    sibling shape-check, bare_trusted_link(), already strips the FULL
    matched URL for exactly this reason - this now matches it."""
    if not text or not text.strip():
        return True
    leftover = _URL_LIKE.sub(" ", text)
    for v in link_verdicts:
        raw = v.get("raw")
        if raw:
            leftover = leftover.replace(raw, " ")
        host = v.get("host")
        if host:
            leftover = leftover.replace(host, " ")
    leftover = _DOMAINISH.sub(" ", leftover)
    return not re.sub(r"[^\w]", "", leftover, flags=re.UNICODE).strip()


def _single_link_or_none(link_verdicts: list[dict]) -> dict | None:
    """The one link verdict, only when there's exactly one - both
    deterministic short-circuits below (_unverifiable_dead_link,
    _trusted_bare_link_verdict) only ever apply to a genuinely bare
    single-link message, and used to each inline this same
    len-check-then-unwrap."""
    if len(link_verdicts) != 1:
        return None
    return link_verdicts[0]


def _dead_link_disqualified(
    v: dict, link_verdicts: list[dict], file_verdict: dict | None,
    pattern_match: tuple[float, str] | None, text: str,
) -> bool:
    """True when ANY condition rules out the dead-link short-circuit -
    written to fail SAFE, so a caller only treats `v` as the pure-noise
    case when every one of these returns False."""
    if file_verdict and file_verdict.get("malicious", 0) > 0:
        return True
    if pattern_match is not None:
        return True
    # Only the middle "suspicious" band: a 'safe' link needs no caution,
    # a 'dangerous' one is too strong to short-circuit as mere noise.
    if v.get("level") != "suspicious":
        return True
    if _has_confirmed_evidence(link_verdicts, file_verdict):
        return True
    if v.get("score", 0) > _CONNECTIVITY_ONLY_MAX:
        return True
    reasons = v.get("reasons") or []
    if not any(any(m in r for m in _CONNECTIVITY_REASON_MARKERS) for r in reasons):
        return True
    return not _message_is_only_links(text, link_verdicts)


def _dead_link_verdict(host, lang: str) -> dict:
    return {
        "verdict": "Uncertain",
        "risk_percentage": UNVERIFIABLE_DEAD_LINK_RISK,
        "key_reasons": [{
            "text": t(lang, "reason_dead_link"),
            "source": "link_evidence",
        }],
        "recommendations": [
            t(lang, "rec_dead_link_no_credentials"),
            t(lang, "rec_dead_link_check_sender"),
        ],
    }


def _unverifiable_dead_link(
    text: str,
    link_verdicts: list[dict],
    file_verdict: dict | None,
    pattern_match: tuple[float, str] | None,
    lang: str = DEFAULT_LANG,
) -> dict | None:
    """Return a fixed 'couldn't verify' verdict for the pure dead-link,
    no-context case, or None to let the normal Gemini path run. Written
    to fail SAFE: every condition that isn't clearly met returns None, so
    this can only ever replace the ambiguous-noise case, never suppress a
    real signal.

    `lang` matters because this path never reaches Gemini, and Gemini is
    what normally writes key_reasons/recommendations in the user's own
    language - so without translating here, a Khmer user got an
    otherwise-Khmer reply with an English reason and recommendations
    inside it."""
    v = _single_link_or_none(link_verdicts)
    if v is None or _dead_link_disqualified(v, link_verdicts, file_verdict, pattern_match, text):
        return None

    logger.info("deterministic dead-link short-circuit for %s (score=%s)",
                v.get("host"), v.get("score"))
    return _dead_link_verdict(v.get("host"), lang)


def _trusted_link_disqualified(
    v: dict, link_verdicts: list[dict], file_verdict: dict | None,
    keyword_result: dict, pattern_match: tuple[float, str] | None, text: str,
) -> bool:
    """True when ANY condition rules out the trusted-bare-link
    short-circuit - same fail-safe shape as _dead_link_disqualified."""
    if file_verdict is not None:
        return True
    if keyword_result.get("suspicious"):
        return True
    if pattern_match is not None:
        return True
    if not v.get("trusted_brand") or v.get("level") != "safe":
        return True
    return not _message_is_only_links(text, link_verdicts)


def _trusted_link_verdict(v: dict, lang: str) -> dict:
    host = v.get("host")
    return {
        "verdict": "Not a Scam",
        "risk_percentage": v.get("score", 0),
        "key_reasons": [{
            "text": t(lang, "reason_trusted_brand").format(host=host),
            "source": "link_evidence",
        }],
        "recommendations": _fallback_recommendations("Not a Scam", lang),
        # Direct user spec (2026-09-16): every caller renders this as
        # verdict_style.trusted_link_notice(host, lang) instead of the
        # normal full VERDICT/KEY REASONS/WHAT TO DO template - the
        # existing keys above stay populated too (tests, and anything
        # that reads a plain verdict dict, keep working unchanged), this
        # is purely an additional marker for callers that know to check it.
        "trusted_link_notice_host": host,
    }


def _trusted_bare_link_verdict(
    text: str,
    link_verdicts: list[dict],
    file_verdict: dict | None,
    keyword_result: dict,
    pattern_match: tuple[float, str] | None,
    lang: str = DEFAULT_LANG,
) -> dict | None:
    """Return a fixed 'Not a Scam' verdict for a bare link to an exact
    PROTECTED_BRANDS domain (pipeline.py's is_official_brand gate), or
    None to let the normal Gemini path run. Same fail-safe shape as
    _unverifiable_dead_link above: every condition that isn't clearly
    met returns None, so this can only ever replace the "obviously
    nothing here" case, never suppress a real signal - notably it still
    requires the link's OWN verdict to have come back 'safe' after the
    real network/redirect trace (pipeline.py keeps that trace even for
    trusted domains specifically so an open-redirect or subdomain
    takeover still gets caught and pushes the level off 'safe').

    Exists so a bare trusted link costs neither quota nor a live Gemini
    call - the handler-level quota gate has its own matching shape check
    (pipeline.py's bare_trusted_link) so it never even reaches this
    point for a message that would end up paying anyway.
    """
    v = _single_link_or_none(link_verdicts)
    if v is None or _trusted_link_disqualified(v, link_verdicts, file_verdict, keyword_result, pattern_match, text):
        return None

    logger.info("deterministic trusted-brand short-circuit for %s", v.get("host"))
    return _trusted_link_verdict(v, lang)


def _link_is_vt_confirmed(v: dict) -> bool:
    """True when one link finding's own reasons include a real
    VirusTotal detection - vs. everything else being a heuristic this
    bot computed itself. Shared by _has_confirmed_evidence, _build_contents,
    and _reconcile_with_evidence, which each used to derive this same
    `any("VirusTotal" in r for r in ...)` expression independently."""
    return any("VirusTotal" in r for r in (v.get("reasons") or []))


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
    return any(_link_is_vt_confirmed(v) for v in link_verdicts)


def _evidence_dict(
    keyword_result: dict,
    link_verdicts: list[dict],
    file_verdict: dict | None,
    pattern_match: tuple[float, str] | None,
    sender_identity: dict | None,
) -> dict:
    """The SYSTEM-GATHERED EVIDENCE payload _build_contents sends Gemini -
    split out so that function is just "build this dict, then template
    it into a string"."""
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
                "confirmed": _link_is_vt_confirmed(v),
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
    return evidence


def _build_contents(
    text: str,
    keyword_result: dict,
    link_verdicts: list[dict],
    file_verdict: dict | None,
    pattern_match: tuple[float, str] | None = None,
    sender_identity: dict | None = None,
) -> str:
    evidence = _evidence_dict(keyword_result, link_verdicts, file_verdict, pattern_match, sender_identity)
    return (
        "SYSTEM-GATHERED EVIDENCE (not written by the user; already gathered - "
        "do not re-derive it. Each link finding carries a \"confirmed\" flag - "
        "see the system prompt for how to weigh confirmed vs heuristic evidence):\n"
        f"{json.dumps(evidence, ensure_ascii=False)}\n\n"
        "USER MESSAGE TO ANALYZE:\n"
        f"{text}"
    )


# Same voice/tone as pipeline.py's own _RECOMMENDATION_KEYS (dangerous/
# suspicious/safe) - this fallback's verdict vocabulary is Scam/
# Uncertain/Not a Scam instead, matching every other surface's.
#
# Translation keys rather than literal strings: every path that uses
# these bypasses Gemini, and Gemini is what normally writes
# recommendations in the user's own language, so these were the source of
# raw English appearing inside otherwise-Khmer replies.
_FALLBACK_RECOMMENDATION_KEYS = {
    "Scam": ["rec_scam_no_interaction", "rec_scam_block_report"],
    "Uncertain": ["rec_uncertain_hold_off", "rec_uncertain_verify_sender"],
    "Not a Scam": ["rec_safe_stay_cautious"],
}


def _fallback_recommendations(verdict: str, lang: str) -> list[str]:
    """A fresh list every call, so no caller can mutate shared state -
    the same reason the old code wrapped its constant in list()."""
    return [t(lang, key) for key in _FALLBACK_RECOMMENDATION_KEYS[verdict]]


def _fallback_keyword_reason(keyword_result: dict, lang: str) -> dict | None:
    if not keyword_result.get("suspicious"):
        return None
    return {
        "text": t(lang, "reason_keyword_match").format(
            matches=", ".join(keyword_result["matches"])),
        "source": "keyword_match",
    }


def _fallback_pattern_reason(text: str, lang: str) -> tuple[dict | None, float]:
    """(reason, similarity) - similarity is 0.0 when nothing matched.
    Returned separately from the reason since analyze_url-style risk
    aggregation downstream needs the raw number, not just the rendered
    text."""
    if not text:
        return None, 0.0
    # No longer a DB call - nearest_scam_pattern is a local, in-memory
    # search (see scam_patterns.py), so unlike the old Supabase-backed
    # lookup this can't fail from a broken connection/exhausted pool.
    # One less way for this LAST-RESORT fallback (Gemini already
    # failed) to itself fail.
    pattern_hits = nearest_scam_pattern(text, k=1)
    if not pattern_hits or pattern_hits[0][0] < SCAM_PATTERN_THRESHOLD:
        return None, 0.0
    similarity, _kind, _key, category = pattern_hits[0]
    return {
        "text": t(lang, "reason_scam_script").format(category=category),
        "source": "message_text",
    }, similarity


def _fallback_link_reasons(link_verdicts: list[dict], lang: str) -> list[dict]:
    reasons = []
    for v in link_verdicts:
        if v.get("level") != "safe":
            detail = v["reasons"][0] if v.get("reasons") else f"{v.get('host')} flagged {v.get('level')}"
            reasons.append({
                "text": t(lang, "reason_link_flagged").format(host=v.get("host"), detail=detail),
                "source": "link_evidence",
            })
    return reasons


def _fallback_file_reasons(file_verdict: dict | None, lang: str) -> tuple[list[dict], bool, int]:
    """(reasons, file_flagged, filename_score)."""
    reasons: list[dict] = []
    file_flagged = bool(file_verdict and file_verdict.get("malicious", 0) > 0)
    if file_flagged:
        reasons.append({
            "text": t(lang, "reason_file_malicious").format(count=file_verdict["malicious"]),
            "source": "file_evidence",
        })
    filename_score = 0
    if file_verdict:
        # Imported here, not at module scope: file_handler.py imports
        # text_handler.py, which would make this a real import cycle at
        # load time. The renderer is shared rather than duplicated so the
        # file reply and this fallback can't word the same warning
        # differently.
        from bot.handlers.file_handler import filename_warning_text

        warning = filename_warning_text(file_verdict, lang)
        if warning:
            reasons.append({"text": warning, "source": "file_evidence"})
        filename_score = file_verdict.get("filename_risk_score", 0)
    return reasons, file_flagged, filename_score


async def _grounded_fallback(
    reason: str,
    text: str,
    keyword_result: dict,
    link_verdicts: list[dict],
    file_verdict: dict | None = None,
    lang: str = DEFAULT_LANG,
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

    `lang` is what makes that spec actually work for a Khmer user. Since
    the reply now shows this path's own reasons as if they were any other
    verdict's, they have to be written in the user's language like any
    other verdict's are - Gemini writes its own in the right language,
    but by definition it never ran here. Defaults to DEFAULT_LANG for
    llm.py's group-chat caller, which has no language wiring at all.
    """
    logger.info("Falling back to offline detection: %s", reason)
    reasons: list[dict] = []

    keyword_reason = _fallback_keyword_reason(keyword_result, lang)
    if keyword_reason:
        reasons.append(keyword_reason)

    pattern_reason, pattern_similarity = _fallback_pattern_reason(text, lang)
    if pattern_reason:
        reasons.append(pattern_reason)

    reasons.extend(_fallback_link_reasons(link_verdicts, lang))

    file_reasons, file_flagged, filename_score = _fallback_file_reasons(file_verdict, lang)
    reasons.extend(file_reasons)

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
        #
        # filename_score included here too (found by code review,
        # 2026-09-16): a file with only a filename-warning (not a VT
        # malicious hit) made has_concern True -> verdict "Uncertain"
        # while contributing nothing to this number, rendering as
        # "Uncertain / 0%". file_handler.py's own _classify_file_result
        # already uses this exact same filename_risk_score field as the
        # percentage for the identical filename-only-warning case (see
        # scanner.py's filename_risk_score / filename_check.py) - reusing
        # it here instead of inventing a new number keeps the two
        # surfaces consistent.
        risk_percentage = 100 if file_flagged else max(min(worst_link_score, 100), pattern_score, filename_score)
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
        # _fallback_recommendations builds a fresh list each call, so no
        # caller's in-place mutation can corrupt shared module state for
        # every subsequent fallback reply for the life of the process.
        "recommendations": _fallback_recommendations(verdict, lang),
        # Internal/log-only now - see this function's own docstring for
        # why the formatters no longer special-case display on this.
        "ai_unavailable": True,
    }


class _EvidenceFlags:
    """Bundles the 5 evidence flags _reconcile_with_evidence's two
    override branches each need - a plain attribute-holder rather than a
    dict so callers get typo-safe `.file_flagged` access."""

    __slots__ = ("file_flagged", "worst_link_score", "confirmed_link_flagged",
                 "pattern_similarity", "pattern_category", "pattern_flagged")

    def __init__(self, file_flagged, worst_link_score, confirmed_link_flagged,
                 pattern_similarity, pattern_category, pattern_flagged):
        self.file_flagged = file_flagged
        self.worst_link_score = worst_link_score
        self.confirmed_link_flagged = confirmed_link_flagged
        self.pattern_similarity = pattern_similarity
        self.pattern_category = pattern_category
        self.pattern_flagged = pattern_flagged


def _classify_evidence(
    link_verdicts: list[dict], file_verdict: dict | None,
    pattern_match: tuple[float, str] | None,
) -> _EvidenceFlags:
    """Pure "read the evidence" step, independent of Gemini's own `data`
    - split out of _reconcile_with_evidence so its two override branches
    below are just flag checks instead of re-deriving these inline."""
    pattern_similarity, pattern_category = pattern_match or (0.0, None)
    return _EvidenceFlags(
        file_flagged=bool(file_verdict and file_verdict.get("malicious", 0) > 0),
        worst_link_score=max((v.get("score", 0) for v in link_verdicts), default=0),
        confirmed_link_flagged=any(
            v.get("level") != "safe" and _link_is_vt_confirmed(v)
            for v in link_verdicts
        ),
        pattern_similarity=pattern_similarity,
        pattern_category=pattern_category,
        pattern_flagged=pattern_similarity >= SCAM_PATTERN_THRESHOLD,
    )


def _override_for_malicious_file(data: dict, lang: str) -> None:
    """Mutates `data` in place - a malicious file finding always wins,
    regardless of what Gemini said."""
    logger.warning(
        "context_engine: Gemini returned verdict=%r despite a malicious file "
        "finding - overriding to Scam", data.get("verdict"),
    )
    data["verdict"] = "Scam"
    data["risk_percentage"] = 100
    reasons = list(data.get("key_reasons") or [])
    reasons.append({
        "text": t(lang, "reason_override_file"),
        "source": "file_evidence",
    })
    data["key_reasons"] = reasons


def _override_for_flagged_evidence(data: dict, evidence: "_EvidenceFlags", lang: str) -> None:
    """Mutates `data` in place - escalates a "Not a Scam" Gemini verdict
    to "Uncertain" when a CONFIRMED link or a scam-script pattern match
    contradicts it."""
    logger.warning(
        "context_engine: Gemini returned verdict='Not a Scam' despite "
        "confirmed_link_flagged=%s pattern_flagged=%s (pattern=%r sim=%.2f) - "
        "overriding to Uncertain",
        evidence.confirmed_link_flagged, evidence.pattern_flagged,
        evidence.pattern_category, evidence.pattern_similarity,
    )
    data["verdict"] = "Uncertain"
    data["risk_percentage"] = max(
        data.get("risk_percentage") or 0,
        min(evidence.worst_link_score, 100),
        int(evidence.pattern_similarity * 100),
    )
    reasons = list(data.get("key_reasons") or [])
    if evidence.confirmed_link_flagged:
        reasons.append({
            "text": t(lang, "reason_override_link"),
            "source": "link_evidence",
        })
    if evidence.pattern_flagged:
        # The similarity number used to be shown here as
        # "(0.54 similarity)". Dropped: internal detection-method and
        # confidence details must never reach the user (the same
        # suffix was removed from _grounded_fallback's own
        # scam-script reason for this reason, but this override path
        # kept it). The substantive finding - which known scam script
        # it matches - is unchanged.
        reasons.append({
            "text": t(lang, "reason_override_scam_script").format(category=evidence.pattern_category),
            "source": "message_text",
        })
    data["key_reasons"] = reasons


def _reconcile_with_evidence(
    data: dict,
    link_verdicts: list[dict],
    file_verdict: dict | None,
    pattern_match: tuple[float, str] | None = None,
    lang: str = DEFAULT_LANG,
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
    evidence = _classify_evidence(link_verdicts, file_verdict, pattern_match)

    verdict = data.get("verdict")

    if evidence.file_flagged and verdict != "Scam":
        _override_for_malicious_file(data, lang)
    elif verdict == "Not a Scam" and (evidence.confirmed_link_flagged or evidence.pattern_flagged):
        _override_for_flagged_evidence(data, evidence, lang)

    # Final, uniform policy step regardless of which branch above (or
    # neither) produced this number: a risk_percentage this high must be
    # backed by independently-confirmed evidence, not just Gemini's own
    # reasoning or an offline similarity heuristic - see
    # UNCORROBORATED_RISK_CAP's docstring. Runs last so it also catches
    # Gemini's own risk_percentage when neither override branch fired.
    if isinstance(data.get("risk_percentage"), int) and not _has_confirmed_evidence(link_verdicts, file_verdict):
        data["risk_percentage"] = min(data["risk_percentage"], UNCORROBORATED_RISK_CAP)

    return data


async def _compute_pattern_match(text: str) -> tuple[float, str] | None:
    """(similarity, category) once it clears the calibrated pattern
    threshold, else None - only surfaced to the model once confident, so
    a low, near-every-message similarity number doesn't become noise in
    the evidence blob. Split out of analyze_unified."""
    if not text:
        return None
    # The live path is a 3-tier chain: bge-m3 (Modal, primary, genuinely
    # Khmer-capable) -> Gemini's own embedding API (secondary fallback,
    # 2026-09-21) -> the fast hashed scheme, all baked into
    # nearest_scam_pattern_live itself - see scam_patterns.py.
    # _grounded_fallback deliberately keeps calling the plain synchronous
    # nearest_scam_pattern() instead: that path only runs once Gemini has
    # ALREADY failed, and it exists specifically to answer fast without
    # depending on anything else that could also be down - adding a
    # possible embedding-timeout wait (bge-m3 OR the Gemini fallback) to
    # an "everything's already on fire" fallback would work against its
    # own purpose.
    pattern_hits, pattern_source = await nearest_scam_pattern_live(text, k=1)
    # Each tier runs measurably hotter than the last (real benign text
    # can score ~0.59 on bge-m3) - reusing one tier's threshold for
    # another would false-positive on ordinary messages, so the
    # threshold has to match whichever tier actually answered, not
    # just which flag/key is configured (a call can fall through
    # tiers mid-call if the preferred one drops out).
    threshold = {
        "bge_m3": BGE_M3_PATTERN_THRESHOLD,
        "gemini": GEMINI_EMBED_PATTERN_THRESHOLD,
    }.get(pattern_source, SCAM_PATTERN_THRESHOLD)
    if pattern_hits and pattern_hits[0][0] >= threshold:
        return pattern_hits[0][0], pattern_hits[0][3]
    return None


async def _degrade(
    reason: str, text: str, keyword_result: dict, link_verdicts: list[dict],
    file_verdict: dict | None, lang: str,
) -> dict:
    """Thin wrapper collapsing analyze_unified's 4 identical
    _grounded_fallback(...) call sites (only `reason` ever varied) into
    one, found duplicated during code review."""
    return await _grounded_fallback(reason, text, keyword_result, link_verdicts, file_verdict, lang)


async def _call_gemini(
    text: str, keyword_result: dict, link_verdicts: list[dict], file_verdict: dict | None,
    pattern_match: tuple[float, str] | None, sender_identity: dict | None,
    lang: str, user_id: int | None,
) -> dict:
    """The actual live Gemini call + usage recording + response parsing/
    clamping - split out of analyze_unified's try body. Raises exactly
    what generate_content_with_backup raises (GeminiCircuitOpenError or
    any other Exception); the caller's except clauses are unchanged."""
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
        await subscription.record_token_usage(user_id, response.usage_metadata.total_token_count or 0)
    data = json.loads(response.text)
    if data.get("risk_percentage") is not None:
        data["risk_percentage"] = max(0, min(100, int(data["risk_percentage"])))
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
    verdict dict. `lang` reaches EVERY path that produces reasons or
    recommendations, not just the live Gemini one: the live path asks
    Gemini to write its dynamic text in that language (see
    _system_prompt), and the four Gemini-bypassing paths
    (_unverifiable_dead_link, _trusted_bare_link_verdict,
    _grounded_fallback, _reconcile_with_evidence's overrides) look their
    fixed text up in bot/response/translate/. Before that, those four
    emitted raw English into an otherwise fully-translated Khmer reply -
    and since the degraded path deliberately presents its own reasons as
    if they were any other verdict's, that English was indistinguishable
    from a normal result rather than obviously a fallback. The fixed
    labels AROUND whatever any path returns are translated separately by
    the caller (verdict_style.py).

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
    pattern_match = await _compute_pattern_match(text)

    # Deterministic short-circuit BEFORE the Gemini call (and before the
    # budget check - it costs no tokens): a bare, non-resolving/unreachable
    # link with no other signal is pure noise the model just guesses on.
    # Returns a fixed "couldn't verify" verdict, or None to proceed normally.
    dead_link = _unverifiable_dead_link(text, link_verdicts, file_verdict, pattern_match, lang)
    if dead_link is not None:
        return dead_link

    # Same idea, opposite end of the confidence spectrum: a bare link to
    # a verified official domain that already came back 'safe' after the
    # real redirect trace needs no LLM opinion either. Costs no tokens
    # and (via the handler-level quota gate's matching shape check)
    # costs the sender no quota.
    trusted = _trusted_bare_link_verdict(
        text, link_verdicts, file_verdict, keyword_result, pattern_match, lang,
    )
    if trusted is not None:
        return trusted

    if not _client:
        return await _degrade("LLM analysis is not configured.",
                               text, keyword_result, link_verdicts, file_verdict, lang)

    if user_id is not None and not await subscription.has_token_budget(user_id):
        # Same graceful-degradation path as "Gemini isn't configured" -
        # the offline signals (keyword/link/file verdicts, scam-pattern
        # similarity) still produce a real answer, just without live AI
        # reasoning, exactly like an actual Gemini outage would.
        return await _degrade("Daily AI token budget exhausted.",
                               text, keyword_result, link_verdicts, file_verdict, lang)

    try:
        data = await _call_gemini(
            text, keyword_result, link_verdicts, file_verdict, pattern_match,
            sender_identity, lang, user_id,
        )
        return _reconcile_with_evidence(data, link_verdicts, file_verdict, pattern_match, lang)
    except GeminiCircuitOpenError as error:
        # The circuit breaker already recorded and logged the real
        # failure pattern that opened it - this call was never actually
        # attempted, so it's not new information for health_alerts'
        # "N failures in the last hour" count, and skipping the network
        # round trip to maybe_alert keeps this path fast, matching the
        # whole point of the breaker (skip real work while Gemini is
        # known-down).
        logger.info("Unified context-engine analysis skipped: %s", error)
        return await _degrade("LLM analysis skipped: Gemini circuit open.",
                               text, keyword_result, link_verdicts, file_verdict, lang)
    except Exception as error:                       # noqa: BLE001 - must never break the reply path
        logger.exception("Unified context-engine analysis failed")
        health_alerts.record_failure("Gemini", str(error))
        await health_alerts.maybe_alert("Gemini", str(error))
        return await _degrade("LLM analysis failed, please try again later.",
                               text, keyword_result, link_verdicts, file_verdict, lang)
