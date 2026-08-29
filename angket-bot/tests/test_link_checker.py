"""
tests/test_pipeline.py
==========================
Offline unit tests for the link-checking pipeline. No network access
is needed: network/domain checks are exercised via monkeypatched
fakes so the merged-verdict logic can be verified deterministically.
"""

import asyncio

import pytest

from bot.url_checker import pipeline
from bot.url_checker.features import network, threat_intel, vectors
from bot.url_checker.features.lexical import (
    check_anchor_mismatch,
    check_url,
    domain_entropy,
    extract_urls,
    registered_domain,
)


# --- lexical analyzer (existing behaviour, still intact) ---------------

def test_extract_urls_finds_bare_and_full_links():
    urls = extract_urls("see https://ababank.com or bit.ly/x9 and mail me")
    assert any("ababank.com" in u for u in urls)
    assert any("bit.ly" in u for u in urls)


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


def test_vector_store_roundtrip(tmp_path, monkeypatch):
    db = tmp_path / "vectors.db"
    _use_tmp_db(monkeypatch, str(db))

    vectors.upsert_vector("phish", "fake-a.tk", "ababank-secure-login.tk")
    vectors.upsert_vector("brand", "ababank.com", "ababank.com", "ABA Bank")

    hits = vectors.nearest("ababank-secure-login.tk", k=2)
    kinds = [kind for _, kind, _, _ in hits]
    assert "phish" in kinds
    # Querying the official domain itself must rank the brand vector first.
    hits = vectors.nearest("ababank.com", k=1)
    assert hits[0][2] == "ababank.com"
    assert hits[0][0] == pytest.approx(1.0, abs=1e-5)


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


# --- orchestrator merge logic (network faked) -----------------------------

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


@pytest.fixture
def seeded_vectors(tmp_path, monkeypatch):
    """Isolate every SQLite-touching module to a temp DB, then seed."""
    db = str(tmp_path / "test_scan.db")
    _use_tmp_db(monkeypatch, db)
    vectors.seed()
    return db


def _use_tmp_db(monkeypatch, db_path):
    # Both modules do `from bot.config import SCAN_LOG_DB` at import
    # time, so patch each module's own binding, not bot.config.
    monkeypatch.setattr(vectors, "SCAN_LOG_DB", db_path)
    monkeypatch.setattr("bot.url_checker.features.domain_info.SCAN_LOG_DB", db_path)


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


# --- self-learning memory (Telegram links -> future reference) -----------

def test_flagged_link_is_remembered_for_future(seeded_vectors, monkeypatch):
    """A dangerous-looking link must be stored as kind='seen' with its
    verdict level, so the DB grows as the bot scans Telegram traffic."""
    import sqlite3

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

    conn = sqlite3.connect(seeded_vectors)
    try:
        rows = conn.execute(
            "select kind, key, label from url_vectors where kind = 'seen'").fetchall()
    finally:
        conn.close()
    assert rows, "flagged link was not remembered"
    assert rows[0][2] == verdict["level"]


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
    SAFE even if the memory DB already contains a poisoned 'dangerous'
    seen-row for google (which a past bug created)."""
    import sqlite3

    # Poison the memory exactly like the bug did.
    conn = sqlite3.connect(seeded_vectors)
    try:
        conn.execute(
            "insert or replace into url_vectors(kind, key, label, vec, added_at) "
            "values ('seen', ?, ?, ?, datetime('now'))",
            ("http://www.google.com/",
             vectors._pack(vectors.embed("http://www.google.com/")),
             "dangerous"),
        )
        conn.commit()
    finally:
        conn.close()

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

from bot.url_checker.features import threat_intel


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


