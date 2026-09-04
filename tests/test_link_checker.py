"""
tests/test_pipeline.py
==========================
Offline unit tests for the link-checking pipeline. No network access
is needed: network/domain checks are exercised via monkeypatched
fakes so the merged-verdict logic can be verified deterministically.
"""

import asyncio
import datetime

import pytest
from telegram import Chat, Message, MessageEntity

from bot.detectors.url import pipeline
from bot.detectors.url.online import network, threat_intel
from bot.detectors.url.offline import vectors
from bot.detectors.url.offline.lexical import (
    check_anchor_mismatch,
    check_url,
    domain_entropy,
    extract_urls,
    has_malformed_protocol,
    registered_domain,
)
from bot.handlers.url_handler import extract_text_link_entities


# --- lexical analyzer (existing behaviour, still intact) ---------------

def test_extract_urls_finds_bare_and_full_links():
    urls = extract_urls("see https://ababank.com or bit.ly/x9 and mail me")
    assert any("ababank.com" in u for u in urls)
    assert any("bit.ly" in u for u in urls)


def test_extract_urls_preserves_userinfo_credential_trick():
    # Regression: extract_urls() used to silently truncate past '@'
    # (treating it as pure URL syntax), handing check_url() only the
    # real destination and losing the exact evidence its own '@'
    # check depends on - making that check permanently unreachable via
    # normal message scanning. The classic trick: a real-looking brand
    # domain before '@', the actual destination after it.
    urls = extract_urls("go to real-bank.com@evil-site.tk now")
    assert urls == ["real-bank.com@evil-site.tk"]  # one match, not truncated to "evil-site.tk"

    v = check_url(urls[0])
    assert v["host"] == "evil-site.tk"  # that's genuinely where a click would land
    assert any("trick to hide the real destination" in r for r in v["reasons"])


def test_extract_urls_userinfo_trick_works_bare_too():
    # No scheme, no path - still must not be silently dropped, since
    # extract_urls() already treats bare domains as checkable links
    # elsewhere; "abab@nk.com" also happens to de-leet to
    # "ababank.com" ('@' -> 'a'), a second, independent red flag on
    # top of the '@' trick itself.
    urls = extract_urls("abab@nk.com")
    assert urls == ["abab@nk.com"]
    v = check_url(urls[0])
    assert v["level"] != "safe"


def test_check_url_flags_raw_ip():
    v = check_url("http://192.168.13.37/login")
    assert v["level"] != "safe"


def test_registered_domain_handles_multi_level_suffix():
    assert registered_domain("www.bank.com.kh") == "bank.com.kh"
    assert registered_domain("mail.google.com") == "google.com"


# --- URL string entropy ---------------------------------------------------

def test_domain_entropy_higher_for_diverse_characters():
    # Not a claim that entropy alone separates random from real (it
    # doesn't reliably at domain-name lengths - see the digit-gating
    # test below) - just checking the raw math does what it says.
    assert domain_entropy("aaaaaaaa") == 0.0
    assert domain_entropy("ab12cd34") > domain_entropy("aaaacccc")


def test_check_url_flags_digit_mixed_random_domain():
    v = check_url("http://xk4j9fzqp2m.tk/login")
    assert any("randomly generated" in r for r in v["reasons"])


def test_check_url_does_not_flag_real_words_as_random():
    # The false-positive case entropy-alone would get wrong: a real
    # dictionary word can have higher raw character diversity than a
    # short random string, but it never mixes digits into the name.
    for url in (
        "https://ababank.com",
        "https://subscription-service.com",
        "https://verification-portal.com",
    ):
        v = check_url(url)
        assert not any("randomly generated" in r for r in v["reasons"]), url


def test_check_url_skips_entropy_when_already_a_brand_disguise():
    # "paypal-4x7k9m2p" clears both the length and digit-mix gates and
    # would score above the entropy threshold on its own (verified:
    # ~3.46 bits/char) - but since the brand-buried check already
    # fires on it, it should get that ONE reason, not a second
    # redundant "looks random" reason stacked on top.
    v = check_url("http://paypal-4x7k9m2p.com/login")
    reasons_text = " ".join(v["reasons"])
    assert "PayPal" in reasons_text
    assert "randomly generated" not in reasons_text


# --- anchor-text mismatch (Telegram text_link entities) -------------------

def test_check_anchor_mismatch_flags_url_shaped_display_text():
    result = check_anchor_mismatch("https://ababank.com", "http://ababank-secure-login.tk/verify")
    assert result is not None
    points, reason = result
    assert points > 0
    assert "ababank.com" in reason
    assert "ababank-secure-login.tk" in reason


def test_check_anchor_mismatch_ignores_ordinary_link_text():
    # "Click here" isn't URL-shaped, so there's nothing to compare -
    # this must NOT flag every normal hyperlink in existence.
    assert check_anchor_mismatch("Click here for your account", "http://ababank-secure-login.tk/verify") is None


def test_check_anchor_mismatch_allows_matching_domains():
    assert check_anchor_mismatch("https://ababank.com/login", "https://ababank.com/login?ref=sms") is None


# --- malformed-protocol links (mentor-flagged: "http//"/"https//") -------

def test_has_malformed_protocol_flags_missing_colon():
    assert has_malformed_protocol("check this out http//free-prize-winner.tk/claim")
    assert has_malformed_protocol("go to https//free-prize-winner.tk/claim now")


def test_has_malformed_protocol_ignores_well_formed_links():
    assert not has_malformed_protocol("visit http://ababank.com safely")
    assert not has_malformed_protocol("visit https://ababank.com safely")
    assert not has_malformed_protocol("plain text with no link at all")


# --- embeddings & vector search -----------------------------------------

def test_embed_is_normalized_and_deterministic():
    a = vectors.embed("secure-login-verify-account.tk")
    b = vectors.embed("secure-login-verify-account.tk")
    norm = sum(v * v for v in a.values()) ** 0.5
    assert a == b
    assert pytest.approx(norm, abs=1e-6) == 1.0


def test_cosine_similarity_orders_phish_above_unrelated():
    phish = vectors.embed("ababank-secure-login.verify-account.tk")
    pattern = vectors.embed("acledabank-secure-login.verify-account.tk")
    unrelated = vectors.embed("cooking-recipes-chocolate-cake.blog")

    sim_phish = vectors.cosine(phish, pattern)
    sim_other = vectors.cosine(phish, unrelated)
    assert sim_phish > sim_other


@pytest.mark.asyncio
async def test_vector_store_roundtrip(fake_vector_store):
    # upsert_vector/nearest are async and Postgres-backed now (see
    # tests/conftest.py) - fake_vector_store implements the exact same
    # contract in-memory with the real embed()/cosine() math, so this
    # still tests a genuine write-then-read round trip, offline.
    await fake_vector_store.upsert_vector("phish", "fake-a.tk", "ababank-secure-login.tk")
    await fake_vector_store.upsert_vector("brand", "ababank.com", "ababank.com", "ABA Bank")

    hits = await fake_vector_store.nearest("ababank-secure-login.tk", k=2)
    kinds = [kind for _, kind, _, _ in hits]
    assert "phish" in kinds
    # Querying the official domain itself must rank the brand vector first.
    hits = await fake_vector_store.nearest("ababank.com", k=1)
    assert hits[0][2] == "ababank.com"
    assert hits[0][0] == pytest.approx(1.0, abs=1e-5)


@pytest.mark.asyncio
async def test_ensure_seeded_survives_a_db_failure(monkeypatch):
    # Regression found by /code-review: seed_vectors() used to be called
    # directly at every handler call site with zero exception handling -
    # a Supabase outage on the first message after a restart would crash
    # handle_text/handle_url/handle_business_message uncaught, giving the
    # user/owner zero reply. ensure_seeded() must
    # swallow the failure and leave bot_data unmarked so the next
    # message simply retries.
    async def _boom():
        raise RuntimeError("Supabase unreachable")

    monkeypatch.setattr(vectors, "seed", _boom)

    bot_data = {}
    await vectors.ensure_seeded(bot_data)  # must not raise

    assert "_vectors_seeded" not in bot_data


@pytest.mark.asyncio
async def test_ensure_seeded_is_idempotent_once_it_succeeds(fake_vector_store, monkeypatch):
    bot_data = {}
    await vectors.ensure_seeded(bot_data)
    assert bot_data["_vectors_seeded"] is True

    # A second call must not re-seed (no-op if already marked done).
    called = {"n": 0}

    async def _spy():
        called["n"] += 1

    monkeypatch.setattr(vectors, "seed", _spy)
    await vectors.ensure_seeded(bot_data)

    assert called["n"] == 0


# --- MinHash LSH ---------------------------------------------------------

def test_minhash_detects_near_duplicate_pages():
    body = "<html>" + ("buy now cheap watches limited offer " * 200) + "</html>"
    slightly_different = body.replace("cheap", "cheaper") + "<p>footer</p>"
    different = "<html>" + ("weather forecast today sunny mild " * 200) + "</html>"

    sig_a = vectors.minhash_signature(body)
    sig_dup = vectors.minhash_signature(slightly_different)
    sig_diff = vectors.minhash_signature(different)

    # Tiny texts make MinHash sensitive, so a single-word edit costs
    # more similarity here than it would on real full pages.
    assert vectors.minhash_similarity(sig_a, sig_dup) > 0.6
    assert vectors.minhash_similarity(sig_a, sig_diff) < 0.3


# --- page text extraction -------------------------------------------------

def test_extract_page_text_strips_scripts():
    html = "<html><head><title>ABA Bank - Login</title></head>" \
           "<body><script>evil()</script><p>Welcome please log in</p></body></html>"
    text = network.extract_page_text(html)
    assert "ABA Bank" in text
    assert "evil()" not in text


# --- form/password field detection -----------------------------------------

def test_has_password_field_detects_login_form():
    html = '<form><input type="text" name="u"><input type="password" name="p"></form>'
    assert network.has_password_field(html)


def test_has_password_field_false_when_absent():
    assert not network.has_password_field("<form><input type='text'></form>")


def test_find_form_actions_extracts_targets():
    html = '<form action="https://attacker.tk/steal"></form><form action="/login"></form>'
    assert network.find_form_actions(html) == ["https://attacker.tk/steal", "/login"]


# --- caption blindness fix (photo/document TEXT_LINK entities) -----------

def _caption_message(caption: str, entities: list[MessageEntity]) -> Message:
    return Message(
        message_id=1,
        date=datetime.datetime.now(),
        chat=Chat(id=1, type=Chat.PRIVATE),
        caption=caption,
        caption_entities=entities,
        text=None,
    )


def test_extract_text_link_entities_reads_caption_entities():
    # Regression: a photo/document caption hides its TEXT_LINK entity in
    # message.caption_entities, not message.entities - a message with no
    # .text used to make this helper (and handle_url entirely) blind to
    # a "Click here"-style deceptive link attached to a file/photo.
    caption = "Click here"
    entity = MessageEntity(
        type=MessageEntity.TEXT_LINK, offset=0, length=len(caption),
        url="http://free-prize-winner.tk/claim",
    )
    message = _caption_message(caption, [entity])

    assert extract_text_link_entities(message) == [
        ("Click here", "http://free-prize-winner.tk/claim")
    ]


def test_extract_text_link_entities_empty_for_plain_caption():
    message = _caption_message("just a normal caption, no link", [])
    assert extract_text_link_entities(message) == []


# --- orchestrator merge logic (network faked) -----------------------------

@pytest.fixture(autouse=True)
def _no_real_tls_handshakes(monkeypatch):
    """cert_issued_days_ago does a REAL TLS handshake (ssl/socket, up to
    an 8s timeout per unresolvable host) - autouse so every test in this
    file gets a fast, deterministic stub without each one needing to
    remember it, the same way domain_age_days/resolve_host are stubbed
    per-test below. Individual tests can still override this via their
    own monkeypatch.setattr if they specifically want to test cert-age
    scoring.
    """
    async def fake_cert_age(host, port=443):
        return None
    monkeypatch.setattr(pipeline, "cert_issued_days_ago", fake_cert_age)


class _FakeNet:
    def __init__(self, **overrides):
        self.result = {
            "requested_url": "http://bit.ly/x9",
            "final_url": "http://bit.ly/x9",
            "redirect_chain": [],
            "cross_domain_redirect": False,
            "reachable": False,
            "status": None,
            "tls_valid": None,
            "server": None,
            "content_type": None,
            "page_html": "",
            "page_text": "",
            "error": None,
        }
        self.result.update(overrides)


# seeded_vectors fixture now lives in tests/conftest.py (shared, and
# backed by an in-memory fake store since url_vectors moved to
# Supabase Postgres - see that file's docstring for why).


def _stub_out_network(monkeypatch, tls_valid=True):
    """Minimal network/DNS/age stubs for tests that only care about the
    lexical/anchor-mismatch signal, not the network layer."""
    async def fake_trace(url):
        return _FakeNet(reachable=True, status=200, tls_valid=tls_valid).result

    async def fake_age(host):
        return None

    async def fake_resolve(host):
        return ["103.1.2.3"]

    monkeypatch.setattr(pipeline.network, "trace", fake_trace)
    monkeypatch.setattr(pipeline, "domain_age_days", fake_age)
    monkeypatch.setattr(pipeline, "resolve_host", fake_resolve)


def test_analyze_url_flags_cross_domain_credential_exfiltration(seeded_vectors, monkeypatch):
    # The actual "form action inspection" case: a login form that's
    # visually on the scanned page but POSTs the password somewhere
    # else entirely - the pattern a fake login page needs to work.
    fake = _FakeNet(
        reachable=True, status=200, tls_valid=True,
        final_url="http://ababank-login.tk/",
        page_html='<form action="https://attacker-collect.tk/steal" method="post">'
                   '<input type="password" name="pass"></form>',
        page_text="please enter your password to continue",
    )

    async def fake_trace(url):
        return fake.result

    async def fake_age(host):
        return None

    async def fake_resolve(host):
        return ["1.2.3.4"]

    monkeypatch.setattr(pipeline.network, "trace", fake_trace)
    monkeypatch.setattr(pipeline, "domain_age_days", fake_age)
    monkeypatch.setattr(pipeline, "resolve_host", fake_resolve)
    monkeypatch.setattr(pipeline, "VIRUSTOTAL_API_KEY", None)

    verdict = asyncio.run(pipeline.analyze_url("http://ababank-login.tk/"))

    assert any("credential-theft pattern" in r for r in verdict["reasons"])
    assert any("attacker-collect.tk" in r for r in verdict["reasons"])


def test_analyze_url_does_not_flag_same_origin_login_form(seeded_vectors, monkeypatch):
    # A login form that submits back to its own page/domain is
    # completely normal - must not be flagged just for existing.
    fake = _FakeNet(
        reachable=True, status=200, tls_valid=True,
        final_url="https://www.some-real-shop.com/",
        page_html='<form action="/login" method="post">'
                   '<input type="password" name="pass"></form>'
                   + ("Welcome to our shop. " * 30),  # clear the near-dup length gate
        page_text="Welcome to our shop, please log in. " * 30,
    )

    async def fake_trace(url):
        return fake.result

    async def fake_age(host):
        return 900

    async def fake_resolve(host):
        return ["1.2.3.4"]

    monkeypatch.setattr(pipeline.network, "trace", fake_trace)
    monkeypatch.setattr(pipeline, "domain_age_days", fake_age)
    monkeypatch.setattr(pipeline, "resolve_host", fake_resolve)
    monkeypatch.setattr(pipeline, "VIRUSTOTAL_API_KEY", None)

    verdict = asyncio.run(pipeline.analyze_url("https://www.some-real-shop.com/"))

    assert not any("credential-theft pattern" in r for r in verdict["reasons"])


def test_analyze_url_flags_brand_page_spoof(seeded_vectors, monkeypatch):
    # _brand_page_spoof: the page CLAIMS to be a protected brand (ABA
    # Bank mentioned 3+ times) while living on an unrelated domain -
    # the semantic-impersonation case lexical/vector checks alone can't
    # prove. Zero prior coverage on this detector.
    #
    # Domain deliberately does NOT itself contain "ababank" (unlike
    # e.g. "ababank-secure-verify.tk") - this isolates the PAGE-CONTENT
    # detector from the separate URL-TEXT brand/typosquat detector
    # (already covered by test_check_anchor_mismatch_*), which would
    # otherwise also fire and make it unclear which detector produced
    # the flag. The brand keyword itself is matched WITHOUT a space
    # (PROTECTED_BRANDS' "ababank.com" splits to "ababank") - real
    # phishing page text won't always have that exact casing/spacing,
    # but this pins the detector's actual current matching behavior.
    fake = _FakeNet(
        reachable=True, status=200, tls_valid=True,
        final_url="http://totally-unrelated-domain.tk/",
        page_text="Welcome to AbaBank online banking. AbaBank keeps your money safe. "
                   "Log in to your AbaBank account now.",
    )

    async def fake_trace(url):
        return fake.result

    async def fake_age(host):
        return None

    async def fake_resolve(host):
        return ["1.2.3.4"]

    monkeypatch.setattr(pipeline.network, "trace", fake_trace)
    monkeypatch.setattr(pipeline, "domain_age_days", fake_age)
    monkeypatch.setattr(pipeline, "resolve_host", fake_resolve)
    monkeypatch.setattr(pipeline, "VIRUSTOTAL_API_KEY", None)

    verdict = asyncio.run(pipeline.analyze_url("http://totally-unrelated-domain.tk/"))

    assert any("ABA Bank" in r and "not the official" in r for r in verdict["reasons"])


def test_analyze_url_does_not_flag_brand_spoof_below_the_mention_threshold(seeded_vectors, monkeypatch):
    # Negative case: 2 mentions is below BRAND_PAGE_SPOOF_MIN (3) - must
    # NOT fire, or this detector would false-positive on any page that
    # merely references a bank's name in passing (e.g. a news article).
    # Same no-space "AbaBank" keyword form as the positive test above,
    # so this genuinely tests the count-threshold boundary (2 vs 3), not
    # just "a space breaks matching" (which the positive test's fix
    # already covers separately).
    fake = _FakeNet(
        reachable=True, status=200, tls_valid=True,
        final_url="http://some-news-site.example/",
        page_text="AbaBank announced new hours today. AbaBank customers should note the change.",
    )

    async def fake_trace(url):
        return fake.result

    async def fake_age(host):
        return None

    async def fake_resolve(host):
        return ["1.2.3.4"]

    monkeypatch.setattr(pipeline.network, "trace", fake_trace)
    monkeypatch.setattr(pipeline, "domain_age_days", fake_age)
    monkeypatch.setattr(pipeline, "resolve_host", fake_resolve)
    monkeypatch.setattr(pipeline, "VIRUSTOTAL_API_KEY", None)

    verdict = asyncio.run(pipeline.analyze_url("http://some-news-site.example/"))

    assert not any("not the official" in r for r in verdict["reasons"])


def test_analyze_url_caps_stacked_network_signals_at_max_network_points(seeded_vectors, monkeypatch):
    # All four network-derived signals add_network() can currently apply
    # sum to EXACTLY MAX_NETWORK_POINTS (20+10+5+10=45) - today's code has
    # no way to organically exceed the cap, only reach it exactly. This
    # pins that exact boundary with real arithmetic (not just "score went
    # up"), so a FUTURE new network signal added without updating the cap
    # constant would show up as a silent score change here. Zero prior
    # coverage on this cap existed before this test.
    #
    # final_url is deliberately a lexically-CLEAN domain so the separate
    # cross-domain-redirect "rescore" (checks the final URL's own lexical
    # score, added directly to `score`, NOT through add_network/the cap)
    # contributes exactly 0 - isolating the network-points cap from that
    # unrelated addition.
    lexical_base = pipeline.check_url("http://bit.ly/x9")["score"]
    assert lexical_base == 30  # known constant for bit.ly (shortener + no-HTTPS)
    assert pipeline.check_url("https://step-final.harmless-example.com/")["score"] == 0

    fake = _FakeNet(
        reachable=True, status=500, tls_valid=False,
        final_url="https://step-final.harmless-example.com/",
        redirect_chain=[(301, "http://bit.ly/x9"), (301, "http://step2.example.com/"),
                         (301, "http://step3.example.com/"),
                         (301, "https://step-final.harmless-example.com/")],
        cross_domain_redirect=True,
    )

    async def fake_trace(url):
        return fake.result

    async def fake_age(host):
        return None

    async def fake_resolve(host):
        return ["1.2.3.4"]

    monkeypatch.setattr(pipeline.network, "trace", fake_trace)
    monkeypatch.setattr(pipeline, "domain_age_days", fake_age)
    monkeypatch.setattr(pipeline, "resolve_host", fake_resolve)
    monkeypatch.setattr(pipeline, "VIRUSTOTAL_API_KEY", None)

    verdict = asyncio.run(pipeline.analyze_url("http://bit.ly/x9"))

    network_reason_phrases = [
        "redirects to a different domain", "hops before landing",
        "served over plain HTTP", "answered HTTP 500",
    ]
    fired = [p for p in network_reason_phrases if any(p in r for r in verdict["reasons"])]
    assert fired == network_reason_phrases  # all four still reported...
    # ...and the total is exactly lexical_base + capped-network(45) +
    # rescore(0) - proves the cap is the real, exact ceiling, not just
    # "some" cap somewhere.
    assert verdict["score"] == lexical_base + 45


def test_analyze_url_skips_live_vt_lookup_for_a_lexically_clean_url(seeded_vectors, monkeypatch):
    # VT quota gate: live=(score > 0). A lexically-clean URL that
    # resolves fine with no red flags must call VT with live=False
    # (cache-only, no quota spent) - the actual quota-protection the
    # docstring claims, not just "VT gets skipped for official brands."
    seen_live = {}

    async def spy_lookup(url, key, live=True):
        seen_live["value"] = live
        return None

    async def fake_trace(url):
        return _FakeNet(reachable=True, status=200, tls_valid=True,
                        page_text="a perfectly ordinary page").result

    async def fake_age(host):
        return 2000

    async def fake_resolve(host):
        return ["1.2.3.4"]

    monkeypatch.setattr(pipeline.threat_intel, "lookup", spy_lookup)
    monkeypatch.setattr(pipeline.network, "trace", fake_trace)
    monkeypatch.setattr(pipeline, "domain_age_days", fake_age)
    monkeypatch.setattr(pipeline, "resolve_host", fake_resolve)
    monkeypatch.setattr(pipeline, "VIRUSTOTAL_API_KEY", "fake-key")

    asyncio.run(pipeline.analyze_url("https://some-ordinary-blog.com/"))

    assert seen_live == {"value": False}


def test_check_message_full_sees_link_hidden_entirely_behind_entity_text(seeded_vectors, monkeypatch):
    # The message's VISIBLE text has no URL in it at all ("Click here")
    # - extract_urls() alone would return zero verdicts here, exactly
    # the invisible-link blind spot this closes. The real destination
    # only exists in the Telegram TEXT_LINK entity, passed as hidden_links.
    _stub_out_network(monkeypatch)
    assert extract_urls("Click here") == []

    verdicts = asyncio.run(pipeline.check_message_full(
        "Click here",
        hidden_links=[("Click here", "http://free-prize-winner.tk/claim")],
    ))

    assert len(verdicts) == 1
    assert verdicts[0]["host"] == "free-prize-winner.tk"


def test_check_message_full_scores_anchor_text_mismatch(seeded_vectors, monkeypatch):
    # Display text claims the official bank domain; the entity's real
    # url goes somewhere else entirely - the deceptive case the
    # mismatch check specifically targets. Two verdicts come back: the
    # visible display text ("https://ababank.com" is real text in the
    # message) gets its own normal check, and the hidden entity's
    # actual destination gets analyzed separately with the mismatch
    # reason attached.
    _stub_out_network(monkeypatch)

    verdicts = asyncio.run(pipeline.check_message_full(
        "https://ababank.com",
        hidden_links=[("https://ababank.com", "http://ababank-secure-login.tk/verify")],
    ))

    assert len(verdicts) == 2
    phishing = next(v for v in verdicts if v["host"] == "ababank-secure-login.tk")
    assert phishing["level"] == "dangerous"
    assert any("not the real destination" in r for r in phishing["reasons"])


def test_check_message_full_does_not_duplicate_a_link_already_visible(seeded_vectors, monkeypatch):
    # If the same url is already in the visible text, the hidden_links
    # entry for it must not produce a second, duplicate verdict.
    _stub_out_network(monkeypatch)

    verdicts = asyncio.run(pipeline.check_message_full(
        "check https://ababank.com please",
        hidden_links=[("https://ababank.com", "https://ababank.com")],
    ))

    assert len(verdicts) == 1


def test_analyze_url_does_not_flag_near_dup_on_degenerate_page_text(seeded_vectors, monkeypatch):
    # Regression test for a real false positive hit live: a bot-blocked
    # /CAPTCHA/JS-only page (common on sites with real anti-bot defenses
    # - this exact case was Amazon) returns near-empty text after
    # tag-stripping. MinHash on near-empty text is degenerate - two
    # completely UNRELATED sites that both happen to return "\n" as
    # their page text used to hash to ~100% "similar", with zero actual
    # content in common, and Amazon got flagged as near-identical to an
    # unrelated typosquat domain purely because of this.
    vectors.store_page_signature("totally-unrelated-site.tk", "\n")

    async def near_empty_trace(url):
        return _FakeNet(reachable=True, status=200, tls_valid=True,
                         final_url="https://www.amazon.com/",
                         page_html="<html></html>", page_text="\n").result

    async def fake_age(host):
        return None

    async def fake_resolve(host):
        return ["103.1.2.3"]

    monkeypatch.setattr(pipeline.network, "trace", near_empty_trace)
    monkeypatch.setattr(pipeline, "domain_age_days", fake_age)
    monkeypatch.setattr(pipeline, "resolve_host", fake_resolve)

    verdict = asyncio.run(pipeline.analyze_url("https://www.amazon.com/"))

    assert not any("near-identical" in r for r in verdict["reasons"])


def test_analyze_url_does_not_flag_near_dup_on_generic_challenge_page(seeded_vectors, monkeypatch):
    # A second, sneakier version of the same bug: a bot-challenge page
    # (Cloudflare "Checking your browser...", reCAPTCHA wall) is real,
    # non-empty text - not caught by an empty-text guard alone - but
    # it's IDENTICAL boilerplate across countless unrelated sites.
    # Confirmed live: linkedin.com's real 191-char challenge page still
    # spuriously matched another site's copy of the same text.
    challenge_page = "Checking your browser before accessing the site.\n" \
                      "This process is automatic. Please wait a moment."
    vectors.store_page_signature("totally-unrelated-site.tk", challenge_page)

    async def challenge_trace(url):
        return _FakeNet(reachable=True, status=200, tls_valid=True,
                         final_url="https://www.linkedin.com/",
                         page_html="<html></html>", page_text=challenge_page).result

    async def fake_age(host):
        return None

    async def fake_resolve(host):
        return ["103.1.2.3"]

    monkeypatch.setattr(pipeline.network, "trace", challenge_trace)
    monkeypatch.setattr(pipeline, "domain_age_days", fake_age)
    monkeypatch.setattr(pipeline, "resolve_host", fake_resolve)

    verdict = asyncio.run(pipeline.analyze_url("https://www.linkedin.com/"))

    assert not any("near-identical" in r for r in verdict["reasons"])


def test_analyze_url_merges_network_signals(seeded_vectors, monkeypatch):
    fake = _FakeNet(
        reachable=True, status=200, tls_valid=True,
        final_url="http://free-prize-winner.tk/claim",
        redirect_chain=[(301, "http://bit.ly/x9")],
        cross_domain_redirect=True,
    )
    async def fake_trace(url):
        return fake.result

    async def fake_age(host):
        return 5          # registered 5 days ago

    async def fake_resolve(host):
        return ["103.1.2.3"]

    monkeypatch.setattr(pipeline.network, "trace", fake_trace)
    monkeypatch.setattr(pipeline, "domain_age_days", fake_age)
    monkeypatch.setattr(pipeline, "resolve_host", fake_resolve)

    verdict = asyncio.run(pipeline.analyze_url("http://bit.ly/x9"))

    assert verdict["level"] in ("suspicious", "dangerous")
    joined = " ".join(verdict["reasons"])
    assert "redirects to a different domain" in joined
    assert "registered only" in joined
    assert any("final destination" in d for d in verdict["detail"])


def test_analyze_url_survives_total_network_failure(seeded_vectors, monkeypatch):
    async def boom(url):
        raise RuntimeError("network down")

    async def none_resolve(host):
        return None

    async def none_age(host):
        return None

    monkeypatch.setattr(pipeline.network, "trace", boom)
    monkeypatch.setattr(pipeline, "resolve_host", none_resolve)
    monkeypatch.setattr(pipeline, "domain_age_days", none_age)

    verdict = asyncio.run(pipeline.analyze_url("example.com"))
    assert "does not resolve" in " ".join(verdict["reasons"])


def test_analyze_url_flags_malformed_protocol(seeded_vectors, monkeypatch):
    async def dead_net(url):
        return _FakeNet(error="connection refused").result

    async def none_resolve(host):
        return None

    async def none_age(host):
        return None

    monkeypatch.setattr(pipeline.network, "trace", dead_net)
    monkeypatch.setattr(pipeline, "resolve_host", none_resolve)
    monkeypatch.setattr(pipeline, "domain_age_days", none_age)

    clean = asyncio.run(pipeline.analyze_url("ababank.com"))
    malformed = asyncio.run(pipeline.analyze_url("ababank.com", malformed_protocol=True))

    assert malformed["score"] > clean["score"]
    assert any("malformed protocol" in r for r in malformed["reasons"])
    assert not any("malformed protocol" in r for r in clean["reasons"])


@pytest.mark.asyncio
async def test_check_message_full_detects_malformed_protocol_in_the_raw_text(seeded_vectors, monkeypatch):
    # Regression for the mentor-flagged signal: URL_REGEX's own optional
    # scheme group silently drops "http//"/"https//" (see
    # has_malformed_protocol's docstring), so analyze_url alone never
    # sees it unless check_message_full checks the RAW text itself and
    # threads the flag through.
    async def dead_net(url):
        return _FakeNet(error="connection refused").result

    async def none_resolve(host):
        return None

    async def none_age(host):
        return None

    monkeypatch.setattr(pipeline.network, "trace", dead_net)
    monkeypatch.setattr(pipeline, "resolve_host", none_resolve)
    monkeypatch.setattr(pipeline, "domain_age_days", none_age)

    verdicts = await pipeline.check_message_full("claim now http//free-prize-winner.tk/claim")

    assert len(verdicts) == 1
    assert any("malformed protocol" in r for r in verdicts[0]["reasons"])


# --- exact-match verdict cache (mentor-flagged: "same" not "similar") -----

def test_analyze_url_second_call_hits_cache_and_skips_network(seeded_vectors, monkeypatch):
    calls = {"trace": 0}

    async def counting_trace(url):
        calls["trace"] += 1
        return _FakeNet(reachable=True, status=200, tls_valid=True).result

    async def fake_age(host):
        return None

    async def fake_resolve(host):
        return ["103.1.2.3"]

    monkeypatch.setattr(pipeline.network, "trace", counting_trace)
    monkeypatch.setattr(pipeline, "domain_age_days", fake_age)
    monkeypatch.setattr(pipeline, "resolve_host", fake_resolve)

    first = asyncio.run(pipeline.analyze_url("http://free-prize-winner.tk/claim"))
    assert calls["trace"] == 1

    second = asyncio.run(pipeline.analyze_url("http://free-prize-winner.tk/claim"))
    assert calls["trace"] == 1  # no second live fetch - served from cache
    assert second["score"] == first["score"]
    assert second["reasons"] == first["reasons"]


def test_analyze_url_cache_is_keyed_exactly_not_by_similarity(seeded_vectors, monkeypatch):
    # The whole point of "same" not "similar": a lookalike domain must
    # run its own full check, never inherit another URL's cached verdict.
    calls = {"trace": 0}

    async def counting_trace(url):
        calls["trace"] += 1
        return _FakeNet(reachable=True, status=200, tls_valid=True).result

    async def fake_age(host):
        return None

    async def fake_resolve(host):
        return ["103.1.2.3"]

    monkeypatch.setattr(pipeline.network, "trace", counting_trace)
    monkeypatch.setattr(pipeline, "domain_age_days", fake_age)
    monkeypatch.setattr(pipeline, "resolve_host", fake_resolve)

    asyncio.run(pipeline.analyze_url("http://ababank-secure-login.tk/verify"))
    assert calls["trace"] == 1

    asyncio.run(pipeline.analyze_url("http://ababank-secure-login2.tk/verify"))
    assert calls["trace"] == 2  # different URL - must NOT reuse the cache


def test_analyze_url_official_brand_never_uses_the_cache(seeded_vectors, monkeypatch):
    calls = {"trace": 0}

    async def counting_trace(url):
        calls["trace"] += 1
        return _FakeNet(reachable=True, status=200, tls_valid=True,
                         final_url="https://www.google.com/").result

    async def fake_age(host):
        return 10000

    async def fake_resolve(host):
        return ["8.8.8.8"]

    monkeypatch.setattr(pipeline.network, "trace", counting_trace)
    monkeypatch.setattr(pipeline, "domain_age_days", fake_age)
    monkeypatch.setattr(pipeline, "resolve_host", fake_resolve)

    asyncio.run(pipeline.analyze_url("https://www.google.com/"))
    asyncio.run(pipeline.analyze_url("https://www.google.com/"))
    assert calls["trace"] == 2  # official brand always re-checked live, never cached


def test_analyze_url_message_context_signals_apply_fresh_on_a_cache_hit(seeded_vectors, monkeypatch):
    # malformed_protocol/display_text must never get baked into the
    # cached verdict - two different messages linking the same URL can
    # have different framing.
    async def fake_trace(url):
        return _FakeNet(reachable=True, status=200, tls_valid=True).result

    async def fake_age(host):
        return None

    async def fake_resolve(host):
        return ["103.1.2.3"]

    monkeypatch.setattr(pipeline.network, "trace", fake_trace)
    monkeypatch.setattr(pipeline, "domain_age_days", fake_age)
    monkeypatch.setattr(pipeline, "resolve_host", fake_resolve)

    plain = asyncio.run(pipeline.analyze_url("http://free-prize-winner.tk/x"))
    malformed = asyncio.run(pipeline.analyze_url(
        "http://free-prize-winner.tk/x", malformed_protocol=True))

    assert malformed["score"] == plain["score"] + 15
    assert any("malformed protocol" in r for r in malformed["reasons"])
    assert not any("malformed protocol" in r for r in plain["reasons"])


# --- self-learning memory (Telegram links -> future reference) -----------

def test_flagged_link_is_remembered_for_future(seeded_vectors, monkeypatch):
    """A dangerous-looking link must be stored as kind='seen' with its
    verdict level, so the vector store grows as the bot scans Telegram
    traffic."""
    async def dead_net(url):
        return _FakeNet(error="connection refused").result

    async def none_resolve(host):
        return ["1.2.3.4"]

    async def old_domain(host):
        return 2000

    monkeypatch.setattr(pipeline.network, "trace", dead_net)
    monkeypatch.setattr(pipeline, "resolve_host", none_resolve)
    monkeypatch.setattr(pipeline, "domain_age_days", old_domain)

    verdict = asyncio.run(pipeline.analyze_url("http://ababank-secure-login-verify-account.tk"))

    seen_rows = [
        (kind, key, label) for (kind, key), (label, _vec) in seeded_vectors.rows.items()
        if kind == "seen"
    ]
    assert seen_rows, "flagged link was not remembered"
    assert seen_rows[0][2] == verdict["level"]


def test_second_lookalike_link_matches_first_flagged(seeded_vectors, monkeypatch):
    """The whole point of storing seen links: check a scam link once,
    then a lookalike must earn extra points via similarity to it."""
    async def dead_net(url):
        return _FakeNet(error="connection refused").result

    async def none_resolve(host):
        return None                      # unresolvable -> +25 both times

    async def unknown_age(host):
        return None                      # no RDAP data -> age-neutral

    monkeypatch.setattr(pipeline.network, "trace", dead_net)
    monkeypatch.setattr(pipeline, "resolve_host", none_resolve)
    monkeypatch.setattr(pipeline, "domain_age_days", unknown_age)

    first = asyncio.run(pipeline.analyze_url(
        "http://ababank-secure-login-verify-account.tk"))
    assert first["score"] > 0            # flagged the first time by lexical rules

    second = asyncio.run(pipeline.analyze_url(
        "http://ababank-secure-login-verify-account2.tk"))

    joined = " ".join(second["reasons"])
    assert "previously flagged" in joined
    assert second["score"] >= first["score"] + 20   # memory made it stricter
    assert any("similarity" in d and "earlier flagged link" in d for d in second["detail"])


# --- false-positive regressions (the google.com incident) ----------------

def test_official_brand_survives_plain_http_www_and_poisoned_memory(seeded_vectors, monkeypatch):
    """google.com over plain http redirecting to www.google.com must stay
    SAFE even if the memory store already contains a poisoned 'dangerous'
    seen-row for google (which a past bug created)."""
    # Poison the memory exactly like the bug did.
    seeded_vectors.rows[("seen", "http://www.google.com/")] = (
        "dangerous", vectors.embed("http://www.google.com/")
    )

    async def fake_trace(url):
        return _FakeNet(
            reachable=True, status=200,
            final_url="http://www.google.com/",
            redirect_chain=[(301, "http://google.com")],
            cross_domain_redirect=False,     # same registrable domain!
            tls_valid=False,                 # plain HTTP, NOT a cert failure
        ).result

    async def fake_resolve(host):
        return ["142.250.4.100"]

    async def old_age(host):
        return 10000

    monkeypatch.setattr(pipeline.network, "trace", fake_trace)
    monkeypatch.setattr(pipeline, "resolve_host", fake_resolve)
    monkeypatch.setattr(pipeline, "domain_age_days", old_age)

    v = asyncio.run(pipeline.analyze_url("google.com"))

    assert v["level"] == "safe"
    assert "previously flagged" not in " ".join(v["reasons"])
    assert "certificate is invalid" not in " ".join(v["reasons"])
    assert "warning signs" not in " ".join(v["reasons"])      # www hop ignored


def test_cross_domain_shortener_still_rescored(seeded_vectors, monkeypatch):
    """Guard the guard: a REAL cross-domain redirect must still rescore."""
    async def fake_trace(url):
        return _FakeNet(
            reachable=True, status=200,
            final_url="http://free-prize-winner.tk/claim",
            redirect_chain=[(301, "http://bit.ly/x9")],
            cross_domain_redirect=True,
            tls_valid=True,
        ).result

    async def fake_resolve(host):
        return ["1.2.3.4"]

    async def old_age(host):
        return 3000

    monkeypatch.setattr(pipeline.network, "trace", fake_trace)
    monkeypatch.setattr(pipeline, "resolve_host", fake_resolve)
    monkeypatch.setattr(pipeline, "domain_age_days", old_age)

    v = asyncio.run(pipeline.analyze_url("http://bit.ly/x9"))
    assert v["level"] != "safe"
    assert any("final destination" in d for d in v["detail"])


# --- Flow 3: VirusTotal threat intelligence -------------------------------

def test_vt_score_thresholds():
    # Many engines -> strongest signal
    assert threat_intel.score({"malicious": 12, "suspicious": 0, "total": 94})[0] == 50
    # A couple of engines -> strong but not max
    assert threat_intel.score({"malicious": 2, "suspicious": 0, "total": 94})[0] == 40
    # Single engine -> moderate (could be false positive)
    assert threat_intel.score({"malicious": 1, "suspicious": 0, "total": 94})[0] == 25
    # Only suspicious -> mild
    assert threat_intel.score({"malicious": 0, "suspicious": 3, "total": 94})[0] == 15
    # Clean or empty -> no opinion
    assert threat_intel.score({"malicious": 0, "suspicious": 0, "total": 94}) is None
    assert threat_intel.score({}) is None


def test_vt_cache_roundtrip(tmp_path, monkeypatch):
    db = str(tmp_path / "vt.db")
    monkeypatch.setattr(threat_intel, "SCAN_LOG_DB", db)

    assert threat_intel._cache_get("abc") is None
    threat_intel._cache_put("abc", {"malicious": 3, "suspicious": 1, "total": 90})
    hit = threat_intel._cache_get("abc")
    assert hit == {"malicious": 3, "suspicious": 1, "total": 90}


def test_vt_lookup_prefers_cache_and_needs_key(tmp_path, monkeypatch):
    db = str(tmp_path / "vt2.db")
    monkeypatch.setattr(threat_intel, "SCAN_LOG_DB", db)

    url = "http://cached-example.com/"
    threat_intel._cache_put(threat_intel._url_identifier(url),
                            {"malicious": 7, "suspicious": 0, "total": 80})

    class _ForbiddenClient:
        def __init__(self, *a, **k):
            raise AssertionError("HTTP client must not be constructed on a cache hit")

    monkeypatch.setattr(threat_intel.httpx, "AsyncClient", _ForbiddenClient)

    # Cache hit: no HTTP at all, even with live=False.
    stats = asyncio.run(threat_intel.lookup(url, api_key="dummy", live=False))
    assert stats["malicious"] == 7

    # No API key configured -> always None, no exception.
    assert asyncio.run(threat_intel.lookup("x", api_key=None)) is None


def test_analyze_url_uses_vt_verdict(seeded_vectors, monkeypatch):
    """VT flagging a URL must add points + reason in the merged verdict."""
    async def fake_lookup(url, key, live=True):
        return {"malicious": 10, "suspicious": 1, "total": 94}

    async def clean_trace(url):
        return _FakeNet(reachable=True, status=200, tls_valid=True,
                        page_text="hello world page").result

    async def fine_resolve(host):
        return ["1.2.3.4"]

    async def old_age(host):
        return 4000

    monkeypatch.setattr(pipeline.threat_intel, "lookup", fake_lookup)
    monkeypatch.setattr(pipeline.network, "trace", clean_trace)
    monkeypatch.setattr(pipeline, "resolve_host", fine_resolve)
    monkeypatch.setattr(pipeline, "domain_age_days", old_age)
    monkeypatch.setattr(pipeline, "VIRUSTOTAL_API_KEY", "fake-key")

    v = asyncio.run(pipeline.analyze_url("some-unknown-site.example"))

    assert "VirusTotal" in " ".join(v["reasons"])
    assert any("VirusTotal" in d for d in v["detail"])
    assert v["level"] != "safe"


def test_vt_skipped_for_official_brands(seeded_vectors, monkeypatch):
    """Quota guard: official brand domains must never trigger a lookup."""
    called = {"n": 0}

    async def spy_lookup(url, key, live=True):
        called["n"] += 1
        return None

    async def clean_trace(url):
        return _FakeNet(reachable=True, status=200, tls_valid=True).result

    async def fine_resolve(host):
        return ["1.2.3.4"]

    async def old_age(host):
        return 5000

    monkeypatch.setattr(pipeline.threat_intel, "lookup", spy_lookup)
    monkeypatch.setattr(pipeline.network, "trace", clean_trace)
    monkeypatch.setattr(pipeline, "resolve_host", fine_resolve)
    monkeypatch.setattr(pipeline, "domain_age_days", old_age)
    monkeypatch.setattr(pipeline, "VIRUSTOTAL_API_KEY", "fake-key")

    v = asyncio.run(pipeline.analyze_url("https://www.google.com/search?q=test"))
    assert called["n"] == 0
    assert v["level"] == "safe"


# --- input validation ------------------------------------------------------

def test_web_urls_rejects_non_http_schemes():
    text = "click javascript:alert(1) or data:text/html,x or https://fine.example"
    urls = pipeline._web_urls(text)
    assert urls == ["https://fine.example"]


def test_web_urls_caps_link_count_per_message():
    many = " ".join(f"site{i}.example" for i in range(20))
    urls = pipeline._web_urls(many)
    assert len(urls) == pipeline.MAX_URLS_PER_MESSAGE


def test_web_urls_allows_bare_domains():
    # bare domains get http:// assumed later; no scheme to reject
    assert pipeline._web_urls("check bit.ly/x9 please") == ["bit.ly/x9"]


