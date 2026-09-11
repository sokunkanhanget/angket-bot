"""
tests/test_context_engine.py
==============================
Offline tests for the unified reasoning fallback (no GEMINI_API_KEY
configured / call failure), the live-Gemini success/error paths (mocked
- see _FakeClient below), and the evidence-reconciliation safety net
that overrides a Gemini verdict that contradicts hard evidence. A real
live call still only happens via the run-angket-bot skill's driver -
_FakeClient here proves the parsing/clamping/reconciliation logic
around that call without touching the real network.

_grounded_fallback and vectors.seed() are both async now (the
scam-pattern lookup goes through the Postgres-backed vector store) -
every test here uses the shared `fake_vector_store` fixture from
tests/conftest.py so no test hits the real network.
"""

import json

import pytest

import bot.context_engine.context_engine as ce
from bot.context_engine.context_engine import _grounded_fallback, _reconcile_with_evidence, _system_prompt, analyze_unified


class _FakeResponse:
    def __init__(self, text):
        self.text = text


class _FakeModels:
    def __init__(self, response_text=None, raises=None):
        self._response_text = response_text
        self._raises = raises
        self.last_kwargs = None

    async def generate_content(self, **kwargs):
        self.last_kwargs = kwargs
        if self._raises is not None:
            raise self._raises
        return _FakeResponse(self._response_text)


class _FakeAio:
    def __init__(self, response_text=None, raises=None):
        self.models = _FakeModels(response_text, raises)


class _FakeClient:
    """Stands in for genai.Client - only the .aio.models.generate_content
    surface analyze_unified actually calls."""

    def __init__(self, response_text=None, raises=None):
        self.aio = _FakeAio(response_text, raises)


@pytest.mark.asyncio
async def test_grounded_fallback_includes_keyword_and_link_evidence(fake_vector_store):
    keyword_result = {"suspicious": True, "matches": ["urgent"]}
    link_verdicts = [
        {"host": "free-prize-winner.tk", "level": "dangerous", "score": 80,
         "reasons": ["Domain ends in .tk, a free TLD heavily used for scams."]},
        {"host": "example.com", "level": "safe", "score": 0, "reasons": []},
    ]

    result = await _grounded_fallback("LLM analysis is not configured.", "", keyword_result, link_verdicts)

    assert result["verdict"] == "Uncertain"
    assert result["risk_percentage"] == 80
    sources = {r["source"] for r in result["key_reasons"]}
    assert "keyword_match" in sources
    assert "link_evidence" in sources
    # the safe link must not add a reason
    assert not any("example.com" in r["text"] for r in result["key_reasons"])


@pytest.mark.asyncio
async def test_grounded_fallback_caps_uncorroborated_link_risk(fake_vector_store):
    # Same UNCORROBORATED_RISK_CAP policy as the live-Gemini path
    # (_reconcile_with_evidence) applies here too - a purely offline
    # heuristic score (no VT confirmation) must not read as near-certain.
    keyword_result = {"suspicious": False, "matches": []}
    link_verdicts = [{"host": "free-prize-winner.tk", "level": "dangerous", "score": 95, "reasons": []}]

    result = await _grounded_fallback("x", "", keyword_result, link_verdicts)

    assert result["risk_percentage"] == ce.UNCORROBORATED_RISK_CAP


@pytest.mark.asyncio
async def test_grounded_fallback_does_not_cap_when_virustotal_confirms_the_link(fake_vector_store):
    keyword_result = {"suspicious": False, "matches": []}
    link_verdicts = [{"host": "evil.tk", "level": "dangerous", "score": 95,
                       "reasons": ["2 security engines on VirusTotal flag this link as malicious."]}]

    result = await _grounded_fallback("x", "", keyword_result, link_verdicts)

    assert result["risk_percentage"] == 95


@pytest.mark.asyncio
async def test_grounded_fallback_returns_not_a_scam_when_nothing_found(fake_vector_store):
    # No keyword match, no link, no file, no scam-pattern hit - the
    # fallback must confidently say "Not a Scam" rather than a vague
    # "Uncertain" that would spam a business owner on every mundane
    # message during a Gemini outage.
    result = await _grounded_fallback("x", "hey, are we still on for lunch tomorrow?",
                                       {"suspicious": False, "matches": []}, [])
    assert result["verdict"] == "Not a Scam"
    assert result["risk_percentage"] is None


@pytest.mark.asyncio
async def test_grounded_fallback_returns_real_verdict_appropriate_recommendations(fake_vector_store):
    # 2026-09-11 spec: the fallback's own recommendations, not an empty
    # list papered over by a generic "AI unavailable" notice at display
    # time - each verdict level gets real, distinct advice.
    keyword_result = {"suspicious": True, "matches": ["urgent"]}
    link_verdicts = [{"host": "evil.tk", "level": "dangerous", "score": 90, "reasons": ["bad"]}]
    scam_result = await _grounded_fallback("x", "", keyword_result, link_verdicts)
    assert scam_result["verdict"] in ("Scam", "Uncertain")
    assert scam_result["recommendations"]  # never empty for a real concern

    safe_result = await _grounded_fallback("x", "hey, lunch tomorrow?", {"suspicious": False, "matches": []}, [])
    assert safe_result["verdict"] == "Not a Scam"
    assert safe_result["recommendations"]  # "Not a Scam" still gets real advice, not []


@pytest.mark.asyncio
async def test_grounded_fallback_recommendations_are_not_the_shared_constant(fake_vector_store):
    # Regression (found by /code-review): _grounded_fallback used to
    # return _FALLBACK_RECOMMENDATIONS[verdict] BY REFERENCE - the same
    # list object every call. Nothing mutates it today, but the first
    # future caller that does (e.g. appending a translated hint) would
    # permanently corrupt that verdict's recommendations for every
    # subsequent fallback reply for the life of the process. Two separate
    # calls for the same verdict must return independent list objects.
    keyword_result = {"suspicious": False, "matches": []}
    first = await _grounded_fallback("x", "hey, lunch tomorrow?", keyword_result, [])
    second = await _grounded_fallback("x", "hey, lunch tomorrow?", keyword_result, [])

    assert first["verdict"] == "Not a Scam"
    assert second["verdict"] == "Not a Scam"
    assert first["recommendations"] == second["recommendations"]
    assert first["recommendations"] is not second["recommendations"]

    first["recommendations"].append("mutated by caller")
    assert "mutated by caller" not in second["recommendations"]


@pytest.mark.asyncio
async def test_grounded_fallback_flags_malicious_file(fake_vector_store):
    file_verdict = {"found": True, "malicious": 5, "suspicious": 0, "total": 70}
    result = await _grounded_fallback("x", "", {"suspicious": False, "matches": []}, [], file_verdict)

    assert result["verdict"] == "Scam"
    assert result["risk_percentage"] == 100
    assert any(r["source"] == "file_evidence" for r in result["key_reasons"])


@pytest.mark.asyncio
async def test_grounded_fallback_ignores_clean_file(fake_vector_store):
    file_verdict = {"found": True, "malicious": 0, "suspicious": 0, "total": 70}
    result = await _grounded_fallback("x", "", {"suspicious": False, "matches": []}, [], file_verdict)

    assert result["verdict"] == "Not a Scam"
    assert not any(r["source"] == "file_evidence" for r in result["key_reasons"])
    # Regression (found by /code-review's removed-behavior audit): a
    # scanned-but-clean file must show a coherent "0% Low Risk", not
    # "N/A Unknown Risk" - the equivalent safe-link-only case already
    # produces risk_percentage=0, so this must match for consistency.
    assert result["risk_percentage"] == 0


@pytest.mark.asyncio
async def test_grounded_fallback_flags_near_exact_scam_script(seeded_vectors):
    # Regression/calibration: a near-verbatim repeat of a seeded scam
    # script must be caught even with zero keyword matches and no link -
    # this is exactly the "Hi Mom" case that motivated context_engine.py
    # in the first place, now also covered in DEGRADED (no-LLM) mode.
    text = ("Mom, this is urgent, I lost my phone and I'm texting from a friend's. "
            "I need you to send $800 right now to help me, don't call, just trust me "
            "on this one time.")

    result = await _grounded_fallback("x", text, {"suspicious": False, "matches": []}, [])

    assert result["verdict"] == "Uncertain"
    assert any(
        r["source"] == "message_text" and "scam script" in r["text"]
        for r in result["key_reasons"]
    )
    # Regression (found by /code-review's removed-behavior audit): a
    # confident offline pattern match must show up in the risk NUMBER
    # too, not just the reasons list, or the owner-DM shows "Uncertain"
    # right next to "N/A Unknown Risk" - undercutting the exact signal
    # this fallback exists to surface.
    assert result["risk_percentage"] is not None
    assert result["risk_percentage"] >= 50  # matches SCAM_PATTERN_THRESHOLD


@pytest.mark.asyncio
async def test_grounded_fallback_pattern_match_not_diluted_by_a_safe_link(seeded_vectors):
    # A confident scam-script match plus an unrelated SAFE link must not
    # have its risk number dragged down to the link's low score.
    text = ("Mom, this is urgent, I lost my phone and I'm texting from a friend's. "
            "I need you to send $800 right now to help me, don't call, just trust me "
            "on this one time.")
    link_verdicts = [{"host": "example.com", "level": "safe", "score": 5, "reasons": []}]

    result = await _grounded_fallback("x", text, {"suspicious": False, "matches": []}, link_verdicts)

    assert result["risk_percentage"] >= 50


@pytest.mark.asyncio
async def test_grounded_fallback_does_not_flag_paraphrased_or_benign_text(seeded_vectors):
    # Calibrated live (calibrate_scam_patterns.py): paraphrased scam
    # variants and genuinely benign messages both score well below
    # SCAM_PATTERN_THRESHOLD with this embedding scheme - the threshold
    # is deliberately conservative (only near-exact script repeats),
    # so both must come back "Not a Scam" here, not a false positive.
    for text in (
        "hey, are we still on for lunch tomorrow?",
        "what time do you open tomorrow? also do you have parking nearby?",
        "join my exclusive trading group, I turned a small amount into a lot in a month, message me now",
    ):
        result = await _grounded_fallback("x", text, {"suspicious": False, "matches": []}, [])
        assert result["verdict"] == "Not a Scam", f"false positive on: {text!r}"


@pytest.mark.asyncio
async def test_analyze_unified_degrades_without_api_key(fake_vector_store, monkeypatch):
    # No API key configured -> must return the grounded fallback, never
    # raise and never return a bare "not configured" verdict with no
    # local evidence attached.
    import bot.context_engine.context_engine as ce
    monkeypatch.setattr(ce, "_client", None)

    keyword_result = {"suspicious": True, "matches": ["free bitcoin"]}
    link_verdicts = []

    result = await analyze_unified("free bitcoin now!!!", keyword_result, link_verdicts)

    assert result["verdict"] == "Uncertain"
    assert any(r["source"] == "keyword_match" for r in result["key_reasons"])


@pytest.mark.asyncio
async def test_grounded_fallback_survives_pathological_text():
    # Historical regression, reported live as "private chat gives no
    # reply at all": _grounded_fallback's scam-pattern lookup used to go
    # through Supabase (vector_nearest), and a broken connection there
    # had nowhere left to go from this LAST-RESORT path (Gemini already
    # failed) - it propagated out of handle_text uncaught, zero reply.
    # nearest_scam_pattern (scam_patterns.py) is now a local, in-memory
    # search with no DB involved at all, so that specific failure mode no
    # longer exists - this test instead confirms the fallback still
    # survives the kind of input that's most likely to trip up the local
    # embed()/cosine() math itself (empty-after-normalization text).
    result = await _grounded_fallback(
        "LLM analysis failed, please try again later.",
        "!!!???...",  # tokenizes to nothing meaningful - edge case for embed()
        {"suspicious": False, "matches": []},
        [],
    )

    assert result["verdict"] == "Not a Scam"


# --- live-Gemini path (mocked _client) -------------------------------

@pytest.mark.asyncio
async def test_analyze_unified_returns_parsed_response_on_success(monkeypatch):
    # risk_percentage kept below UNCORROBORATED_RISK_CAP on purpose - this
    # test is about parsing passthrough, not the cap policy (see the
    # dedicated test_reconcile_caps_* tests below for that).
    fake_response = {
        "verdict": "Scam",
        "risk_percentage": 75,
        "key_reasons": [{"text": "Urgent request for money.", "source": "message_text"}],
        "recommendations": ["Do not send money."],
    }
    monkeypatch.setattr(ce, "_client", _FakeClient(response_text=json.dumps(fake_response)))

    result = await analyze_unified("send money now", {"suspicious": False, "matches": []}, [])

    assert result["verdict"] == "Scam"
    assert result["risk_percentage"] == 75
    assert result["key_reasons"] == fake_response["key_reasons"]


@pytest.mark.asyncio
async def test_analyze_unified_includes_scam_pattern_evidence_in_the_live_call(monkeypatch):
    # The gap this whole change closes: the offline scam-pattern
    # similarity check used to be consulted ONLY in _grounded_fallback -
    # the live Gemini call never saw it. Confirms it's now actually in
    # the prompt content sent to the model, not just computed and
    # discarded.
    fake_response = {"verdict": "Scam", "risk_percentage": 90, "key_reasons": [], "recommendations": []}
    fake_client = _FakeClient(response_text=json.dumps(fake_response))
    monkeypatch.setattr(ce, "_client", fake_client)

    text = ("Mom, this is urgent, I lost my phone and I'm texting from a friend's. "
            "I need you to send $800 right now to help me, don't call, just trust me "
            "on this one time.")
    await analyze_unified(text, {"suspicious": False, "matches": []}, [])

    contents = fake_client.aio.models.last_kwargs["contents"]
    assert "scam_pattern_similarity" in contents
    assert "family_emergency" in contents


@pytest.mark.asyncio
async def test_analyze_unified_omits_scam_pattern_evidence_below_threshold(monkeypatch):
    # A low, meaningless similarity score shouldn't be presented to the
    # model as if it were signal - only surfaced once it clears the same
    # calibrated SCAM_PATTERN_THRESHOLD the fallback already trusts.
    fake_response = {"verdict": "Not a Scam", "risk_percentage": 5, "key_reasons": [], "recommendations": []}
    fake_client = _FakeClient(response_text=json.dumps(fake_response))
    monkeypatch.setattr(ce, "_client", fake_client)

    await analyze_unified("hey, are we still on for lunch tomorrow?", {"suspicious": False, "matches": []}, [])

    contents = fake_client.aio.models.last_kwargs["contents"]
    assert "scam_pattern_similarity" not in contents


@pytest.mark.asyncio
async def test_analyze_unified_clamps_out_of_range_risk_percentage(monkeypatch):
    # Schema says "integer" but doesn't itself bound 0-100 - the model
    # could still return something out of range. A VT-confirmed link is
    # included so this test isn't also exercising UNCORROBORATED_RISK_CAP
    # (covered separately below) - it's purely about the 0-100 clamp.
    fake_response = {
        "verdict": "Scam", "risk_percentage": 150,
        "key_reasons": [], "recommendations": [],
    }
    monkeypatch.setattr(ce, "_client", _FakeClient(response_text=json.dumps(fake_response)))
    link_verdicts = [{"host": "evil.tk", "level": "dangerous", "score": 90,
                       "reasons": ["2 security engines on VirusTotal flag this link as malicious."]}]

    result = await analyze_unified("x", {"suspicious": False, "matches": []}, link_verdicts)

    assert result["risk_percentage"] == 100


@pytest.mark.asyncio
async def test_analyze_unified_falls_back_on_malformed_json(fake_vector_store, monkeypatch):
    # response_mime_type + response_schema are supposed to guarantee
    # valid JSON, but nothing guarantees the SDK/model never violates
    # that - must degrade gracefully, not crash the reply path.
    monkeypatch.setattr(ce, "_client", _FakeClient(response_text="not valid json"))

    result = await analyze_unified("x", {"suspicious": False, "matches": []}, [])

    # ai_unavailable is internal/log-only (2026-09-11 spec) - the reply
    # shows _grounded_fallback's own real key_reasons/recommendations,
    # not a generic notice - see format_unified_response's docstring.
    assert result["ai_unavailable"] is True


@pytest.mark.asyncio
async def test_analyze_unified_falls_back_when_api_raises(fake_vector_store, monkeypatch):
    monkeypatch.setattr(ce, "_client", _FakeClient(raises=RuntimeError("Gemini API unavailable")))

    result = await analyze_unified("x", {"suspicious": False, "matches": []}, [])

    assert result["ai_unavailable"] is True


# --- evidence-reconciliation safety net -------------------------------
# Gemini's own verdict is only ever ESCALATED here, never trusted blindly
# when it contradicts hard evidence already independently verified -
# closes the gap where a message crafted to talk the model out of a
# correct verdict (or a plain model misjudgment) could otherwise reach
# the user as a false "Not a Scam"/"safe" answer sitting right next to
# evidence that says otherwise.

def test_reconcile_escalates_to_scam_when_gemini_misses_a_malicious_file():
    data = {"verdict": "Not a Scam", "risk_percentage": 10, "key_reasons": [], "recommendations": []}
    file_verdict = {"found": True, "malicious": 3, "suspicious": 0, "total": 70}

    result = _reconcile_with_evidence(data, [], file_verdict)

    assert result["verdict"] == "Scam"
    assert result["risk_percentage"] == 100
    assert any(r["source"] == "file_evidence" and "Overridden" in r["text"] for r in result["key_reasons"])


def test_reconcile_escalates_to_uncertain_when_gemini_misses_a_dangerous_link():
    # Escalation now requires a CONFIRMED (VirusTotal) flagged link, not
    # just any non-safe level - see test_reconcile_does_not_escalate_on_a_
    # heuristic_only_flagged_link below for the other half of this tier.
    data = {"verdict": "Not a Scam", "risk_percentage": 5, "key_reasons": [], "recommendations": []}
    link_verdicts = [{"host": "free-prize-winner.tk", "level": "dangerous", "score": 80,
                       "reasons": ["5 security engines on VirusTotal flag this link as malicious."]}]

    result = _reconcile_with_evidence(data, link_verdicts, None)

    assert result["verdict"] == "Uncertain"
    assert result["risk_percentage"] == 80
    assert any(r["source"] == "link_evidence" and "Overridden" in r["text"] for r in result["key_reasons"])


def test_reconcile_does_not_escalate_on_a_heuristic_only_flagged_link():
    # The other half of the tier: a heuristic-only finding (no VirusTotal
    # confirmation) is exactly what the system prompt now tells Gemini it
    # MAY apply judgment to. If Gemini deliberately weighed the message's
    # positive context and called it "Not a Scam" anyway, this safety net
    # must not immediately reverse that - only a CONFIRMED finding (or a
    # scam-script pattern match) forces the override. Confirmed live: the
    # broryat.tech false positive (a heuristic brand-keyword match on a
    # legitimate site) is exactly the case this must no longer clobber.
    data = {"verdict": "Not a Scam", "risk_percentage": 20, "key_reasons": [], "recommendations": []}
    link_verdicts = [{"host": "broryat.tech", "level": "suspicious", "score": 60,
                       "reasons": ["Domain registered 58 days ago - still very young."]}]

    result = _reconcile_with_evidence(data, link_verdicts, None)

    assert result["verdict"] == "Not a Scam"
    assert result["risk_percentage"] == 20
    assert result["key_reasons"] == []


def test_reconcile_escalates_when_gemini_misses_a_near_exact_scam_script():
    # No link, no file - pattern match ALONE must be enough to override
    # a false "Not a Scam", same as the fallback already trusts it to be.
    data = {"verdict": "Not a Scam", "risk_percentage": 5, "key_reasons": [], "recommendations": []}

    result = _reconcile_with_evidence(data, [], None, pattern_match=(0.69, "family_emergency"))

    assert result["verdict"] == "Uncertain"
    assert result["risk_percentage"] == 69
    assert any(
        r["source"] == "message_text" and "family_emergency" in r["text"] and "Overridden" in r["text"]
        for r in result["key_reasons"]
    )


def test_reconcile_leaves_a_correct_verdict_untouched():
    # Gemini already agrees with the evidence - must not add a spurious
    # "Overridden" reason or otherwise change an already-correct answer.
    data = {
        "verdict": "Scam", "risk_percentage": 95,
        "key_reasons": [{"text": "Urgent money request.", "source": "message_text"}],
        "recommendations": [],
    }
    file_verdict = {"found": True, "malicious": 3, "suspicious": 0, "total": 70}

    result = _reconcile_with_evidence(data, [], file_verdict)

    assert result["risk_percentage"] == 95
    assert not any("Overridden" in r["text"] for r in result["key_reasons"])


def test_reconcile_does_not_downgrade_a_verdict_the_model_raised_on_its_own():
    # The model may have reasoned about surrounding text this function
    # knows nothing about (e.g. a text-only scam with a merely
    # low-score/safe link) - only ever escalates, never downgrades TO
    # MATCH WEAKER EVIDENCE. A VT-confirmed file is included so this
    # stays clear of UNCORROBORATED_RISK_CAP (a deliberate, different
    # kind of reduction - see the dedicated cap test below) and purely
    # tests the non-downgrade behavior.
    data = {
        "verdict": "Scam", "risk_percentage": 90,
        "key_reasons": [{"text": "Classic family-emergency scam wording.", "source": "message_text"}],
        "recommendations": [],
    }
    link_verdicts = [{"host": "example.com", "level": "safe", "score": 0, "reasons": []}]
    file_verdict = {"found": True, "malicious": 2, "suspicious": 0, "total": 70}

    result = _reconcile_with_evidence(data, link_verdicts, file_verdict)

    assert result["verdict"] == "Scam"
    assert result["risk_percentage"] == 90


def test_reconcile_caps_uncorroborated_risk_even_when_the_model_raised_it_itself():
    # The one deliberate exception to "never downgrades": a risk this
    # high must be backed by independently-confirmed evidence (real
    # VirusTotal detection), not just Gemini's own reading of the text -
    # see UNCORROBORATED_RISK_CAP's docstring. Same scenario as the
    # non-downgrade test above, minus the VT-confirmed file.
    data = {
        "verdict": "Scam", "risk_percentage": 90,
        "key_reasons": [{"text": "Classic family-emergency scam wording.", "source": "message_text"}],
        "recommendations": [],
    }
    link_verdicts = [{"host": "example.com", "level": "safe", "score": 0, "reasons": []}]

    result = _reconcile_with_evidence(data, link_verdicts, None)

    assert result["verdict"] == "Scam"  # verdict itself is untouched, only the number is capped
    assert result["risk_percentage"] == ce.UNCORROBORATED_RISK_CAP


def test_reconcile_does_not_cap_risk_when_virustotal_confirms_the_link():
    # The cap must not fire once there IS independent confirmation - a
    # real VT hit on the link is exactly the evidence that justifies a
    # high-confidence number.
    data = {"verdict": "Scam", "risk_percentage": 95, "key_reasons": [], "recommendations": []}
    link_verdicts = [{"host": "evil.tk", "level": "dangerous", "score": 90,
                       "reasons": ["2 security engines on VirusTotal flag this link as malicious."]}]

    result = _reconcile_with_evidence(data, link_verdicts, None)

    assert result["risk_percentage"] == 95


def test_reconcile_does_not_further_escalate_an_already_uncertain_verdict():
    # The escalation branch is specifically `verdict == "Not a Scam"`,
    # not `verdict != "Scam"` - a model that already said "Uncertain"
    # must be left alone even with a flagged link present, not pushed
    # further. Guards against a future narrowing/widening of this
    # condition going unnoticed.
    data = {"verdict": "Uncertain", "risk_percentage": 40, "key_reasons": [], "recommendations": []}
    link_verdicts = [{"host": "free-prize-winner.tk", "level": "dangerous", "score": 80, "reasons": []}]

    result = _reconcile_with_evidence(data, link_verdicts, None)

    assert result["verdict"] == "Uncertain"
    assert result["risk_percentage"] == 40
    assert result["key_reasons"] == []


def test_reconcile_escalates_on_a_merely_suspicious_link_not_just_dangerous():
    # Every other link-escalation test uses level="dangerous" - the real
    # condition is `level != "safe"`, which "suspicious" must also
    # satisfy. Pins that the check isn't accidentally narrowed to only
    # the most severe level. VT-confirmed so this stays clear of the new
    # confirmed-only escalation tier (see the heuristic-only test above).
    data = {"verdict": "Not a Scam", "risk_percentage": 5, "key_reasons": [], "recommendations": []}
    link_verdicts = [{"host": "sketchy-deal.tk", "level": "suspicious", "score": 45,
                       "reasons": ["1 security engine on VirusTotal flags this link as malicious."]}]

    result = _reconcile_with_evidence(data, link_verdicts, None)

    assert result["verdict"] == "Uncertain"
    assert result["risk_percentage"] == 45


def test_reconcile_risk_aggregation_picks_the_worst_of_several_links():
    # worst_link_score = max(...) - a message with one safe link and one
    # dangerous link must escalate to the dangerous one's score, not an
    # average and not just the first item in the list. The dangerous link
    # is VT-confirmed so the escalation actually fires (the confirmed-only
    # tier - see test_reconcile_does_not_escalate_on_a_heuristic_only_
    # flagged_link) - this test is purely about max-not-average aggregation.
    data = {"verdict": "Not a Scam", "risk_percentage": 5, "key_reasons": [], "recommendations": []}
    link_verdicts = [
        {"host": "example.com", "level": "safe", "score": 5, "reasons": []},
        {"host": "free-prize-winner.tk", "level": "dangerous", "score": 75,
         "reasons": ["2 security engines on VirusTotal flag this link as malicious."]},
    ]

    result = _reconcile_with_evidence(data, link_verdicts, None)

    assert result["verdict"] == "Uncertain"
    assert result["risk_percentage"] == 75


@pytest.mark.asyncio
async def test_analyze_unified_applies_reconciliation_end_to_end(monkeypatch):
    # The full live-path wiring, not just the helper in isolation -
    # confirms analyze_unified actually calls _reconcile_with_evidence
    # on a real (mocked) Gemini response.
    fake_response = {
        "verdict": "Not a Scam", "risk_percentage": 5,
        "key_reasons": [], "recommendations": [],
    }
    monkeypatch.setattr(ce, "_client", _FakeClient(response_text=json.dumps(fake_response)))
    file_verdict = {"found": True, "malicious": 5, "suspicious": 0, "total": 70}

    result = await analyze_unified("here's the invoice you asked for", {"suspicious": False, "matches": []}, [], file_verdict)

    assert result["verdict"] == "Scam"
    assert result["risk_percentage"] == 100


# --- language-aware live path (private DM / business chat translation) --

def test_system_prompt_defaults_to_the_base_prompt_for_english():
    assert _system_prompt("en") == ce._SYSTEM_PROMPT


def test_system_prompt_adds_a_khmer_instruction():
    prompt = _system_prompt("km")
    assert prompt != ce._SYSTEM_PROMPT
    assert prompt.startswith(ce._SYSTEM_PROMPT)
    assert "Khmer" in prompt
    # the verdict enum itself must stay English - it's a machine-read
    # code (verdict_style.py/reconciliation match on the exact strings),
    # never shown to the user directly.
    assert "not get translated" in prompt or "never shown to the user" in prompt


@pytest.mark.asyncio
async def test_analyze_unified_sends_the_khmer_instruction_to_gemini(monkeypatch):
    fake_response = {"verdict": "Not a Scam", "risk_percentage": 5, "key_reasons": [], "recommendations": []}
    fake_client = _FakeClient(response_text=json.dumps(fake_response))
    monkeypatch.setattr(ce, "_client", fake_client)

    await analyze_unified("x", {"suspicious": False, "matches": []}, [], lang="km")

    system_instruction = fake_client.aio.models.last_kwargs["config"].system_instruction
    assert "Khmer" in system_instruction


@pytest.mark.asyncio
async def test_analyze_unified_defaults_to_english_system_prompt(monkeypatch):
    fake_response = {"verdict": "Not a Scam", "risk_percentage": 5, "key_reasons": [], "recommendations": []}
    fake_client = _FakeClient(response_text=json.dumps(fake_response))
    monkeypatch.setattr(ce, "_client", fake_client)

    await analyze_unified("x", {"suspicious": False, "matches": []}, [])  # no lang passed

    system_instruction = fake_client.aio.models.last_kwargs["config"].system_instruction
    assert system_instruction == ce._SYSTEM_PROMPT


# --- Deterministic dead-link short-circuit --------------------------------
# A bare, non-resolving/unreachable link with no message context is pure
# noise Gemini just guesses on (observed 30 vs 80 on the same host). These
# pin the fixed short-circuit and, crucially, that it fails SAFE - any real
# signal or context makes it fall through to the normal Gemini path.

def _dead_link(**over):
    v = {"host": "jam.example.com", "level": "suspicious", "score": 40,
         "reasons": ["The host name does not resolve in DNS at all — nothing is really there."]}
    v.update(over)
    return v


def test_dead_link_no_context_short_circuits_to_fixed_uncertain():
    result = ce._unverifiable_dead_link("http://jam.example.com", [_dead_link()], None, None)

    assert result is not None
    assert result["verdict"] == "Uncertain"
    assert result["risk_percentage"] == ce.UNVERIFIABLE_DEAD_LINK_RISK  # fixed, not model-derived
    assert result["key_reasons"][0]["source"] == "link_evidence"


def test_dead_link_short_circuit_is_deterministic():
    # The whole point: identical input -> identical output every time.
    a = ce._unverifiable_dead_link("http://jam.example.com", [_dead_link()], None, None)
    b = ce._unverifiable_dead_link("http://jam.example.com", [_dead_link()], None, None)
    assert a == b


def test_dead_link_with_real_message_text_falls_through():
    # Real words around the link = something for Gemini to reason about.
    result = ce._unverifiable_dead_link(
        "Hey is this legit? http://jam.example.com", [_dead_link()], None, None)
    assert result is None


def test_dead_link_but_virustotal_confirmed_falls_through():
    v = _dead_link(reasons=["6 security engines on VirusTotal flag this link as malicious."], score=45)
    assert ce._unverifiable_dead_link("http://jam.example.com", [v], None, None) is None


def test_dead_link_but_dangerous_level_falls_through():
    assert ce._unverifiable_dead_link(
        "http://jam.example.com", [_dead_link(level="dangerous", score=80)], None, None) is None


def test_dead_link_with_high_score_falls_through():
    # A connectivity failure that somehow scores above the ceiling means a
    # real content signal also contributed - not a pure dead link.
    assert ce._unverifiable_dead_link(
        "http://jam.example.com", [_dead_link(score=70)], None, None) is None


def test_dead_link_with_a_scam_pattern_match_falls_through():
    assert ce._unverifiable_dead_link(
        "http://jam.example.com", [_dead_link()], None, (0.71, "lottery")) is None


def test_two_links_fall_through():
    assert ce._unverifiable_dead_link(
        "http://jam.example.com http://x.example.org", [_dead_link(), _dead_link(host="x.example.org")],
        None, None) is None


def test_resolvable_suspicious_link_without_connectivity_reason_falls_through():
    # "suspicious" for some OTHER reason (young domain) is not the dead-link
    # case and must still go to Gemini.
    v = _dead_link(reasons=["Domain registered 10 days ago — still very young."])
    assert ce._unverifiable_dead_link("http://jam.example.com", [v], None, None) is None


def test_message_is_only_links_detects_bare_vs_contextful():
    links = [{"host": "jam.example.com"}]
    assert ce._message_is_only_links("http://jam.example.com", links) is True
    assert ce._message_is_only_links("  jam.example.com  ", links) is True
    assert ce._message_is_only_links("check this http://jam.example.com", links) is False
    # Khmer context around the link must count as real content.
    assert ce._message_is_only_links("តើនេះជាការបោកទេ http://jam.example.com", links) is False
