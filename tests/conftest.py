"""
tests/conftest.py
===================
Shared fixtures. The url_vectors similarity store moved from SQLite to
Supabase Postgres+pgvector (see bot/detectors/url/offline/vectors.py) -
a real, shared, external database, so the old "isolate to a tmp_path
SQLite file" strategy no longer applies (there's no per-test local file
to isolate to, and hitting the real network from the offline unit suite
would be slow, flaky, and pollute shared data).

`seeded_vectors` replaces that isolation with an in-memory fake store
that implements the exact same async contract (upsert_vector/nearest)
using the REAL, unchanged embed()/cosine() math - so tests still get a
genuine write-then-read round trip (this matters: several tests are
specifically about vector-memory behavior, e.g. "a flagged link is
remembered" / "a lookalike link matches it later") without any network
dependency. `seed()` is reimplemented against the fake store the same
way, from the same real PROTECTED_BRANDS/PHISH_PATTERNS/SCAM_MESSAGE_PATTERNS
seed data the real seed() uses.
"""

from datetime import datetime, timezone

import pytest
import pytest_asyncio

from bot.detectors.url.offline import vectors
from bot.storage import scan_log
from bot.storage import subscription


class _FakeVectorStore:
    """In-memory stand-in for the Postgres url_vectors table."""

    def __init__(self):
        self.rows: dict[tuple[str, str], tuple[str | None, dict[int, float]]] = {}

    async def upsert_vector(self, kind: str, key: str, text: str, label: str | None = None) -> None:
        self.rows[(kind, key.lower())] = (label, vectors.embed(text))

    async def nearest(self, text: str, k: int = 3, kinds: tuple[str, ...] | None = None):
        q = vectors.embed(text)
        if not q:
            return []
        scored = []
        for (kind, key), (label, vec) in self.rows.items():
            if kinds and kind not in kinds:
                continue
            scored.append((vectors.cosine(q, vec), kind, key, label))
        scored.sort(key=lambda t: t[0], reverse=True)
        return scored[:k]

    async def seed(self) -> None:
        # Sourced from the SAME row-building helpers the real seed()
        # uses (vectors._brand_and_phish_rows / scam_patterns._seed_rows)
        # instead of a hand-duplicated copy of PROTECTED_BRANDS/
        # PHISH_PATTERNS/SCAM_MESSAGE_PATTERNS - so this fake can't
        # silently drift from what production actually seeds.
        from bot.detectors.text.offline import scam_patterns

        for kind, key, text, label in vectors._brand_and_phish_rows() + scam_patterns._seed_rows():
            await self.upsert_vector(kind, key, text, label)


@pytest.fixture
def fake_vector_store(monkeypatch):
    """Patches every import site of upsert_vector/nearest with the fake
    store. Returns the store itself for tests that want to poison/inspect
    it directly (e.g. simulating corrupted memory)."""
    store = _FakeVectorStore()

    monkeypatch.setattr(vectors, "upsert_vector", store.upsert_vector)
    monkeypatch.setattr(vectors, "nearest", store.nearest)
    monkeypatch.setattr(vectors, "seed", store.seed)

    # context_engine.py's scam-pattern lookup (nearest_scam_pattern, in
    # scam_patterns.py) is a LOCAL in-memory search over the real
    # SCAM_MESSAGE_PATTERNS data - it never touches url_vectors (fake or
    # real) at all, so there's nothing to patch for it here.

    return store


@pytest_asyncio.fixture
async def seeded_vectors(fake_vector_store, tmp_path, monkeypatch):
    """Same name/shape tests already use - now backed by the in-memory
    fake instead of a real SQLite tmp file for url_vectors specifically,
    already seeded. Still isolates the SQLite-backed pieces that DIDN'T
    move (MinHash page dedup, domain-age cache, and pipeline.py's
    exact-match link-verdict cache) to a tmp file, exactly like the old
    fixture did - only the url_vectors table's backend changed, not
    whether SQLite-touching tests should hit the real scan_logs.db.
    Without patching pipeline.SCAN_LOG_DB too, an earlier test in the
    same run could cache a URL's verdict for real, and a later test
    reusing that same URL would get a stale cache hit instead of
    exercising the code it meant to test."""
    db = str(tmp_path / "test_scan.db")
    monkeypatch.setattr(vectors, "SCAN_LOG_DB", db)
    monkeypatch.setattr("bot.detectors.url.online.domain_info.SCAN_LOG_DB", db)
    monkeypatch.setattr("bot.detectors.url.pipeline.SCAN_LOG_DB", db)

    await fake_vector_store.seed()
    return fake_vector_store


@pytest.fixture(scope="session", autouse=True)
def isolated_scan_log_db(tmp_path_factory):
    """bot.storage.scan_log does its own `from bot.config.config import SCAN_LOG_DB`,
    binding a SEPARATE module-level name from the copies pipeline.py/
    domain_info.py/cert_info.py/vectors.py each bind the same way - so
    seeded_vectors patching THOSE never touches this one. Nothing else in
    the suite isolates it, so any test whose code path reaches
    log_scan()/log_url_scan() (e.g. handle_business_message, once a link or
    file verdict comes back) falls through to whatever real scan_logs.db
    happens to sit in the repo root/cwd - which may be missing the
    url_scan_logs table entirely (exactly the "no such table" failure this
    fixture exists to prevent), or worse, silently write real rows into a
    developer's local db. autouse so every test gets an isolated db with
    both tables already created via init_db()/init_url_db(), matching the
    isolate-and-initialize pattern used for every sibling SQLite-backed
    piece in this file - whether or not a given test explicitly asks for
    it.

    Session-scoped (not per-test): init_db()/init_url_db() are idempotent
    `CREATE TABLE IF NOT EXISTS` calls and no test in the suite asserts on
    scan-log row counts or otherwise depends on the tables starting empty
    per test, so re-running the same init 191 times bought nothing but
    ~4s of real sqlite3.connect()-to-a-new-file overhead. Plain attribute
    assignment instead of monkeypatch since monkeypatch itself is
    function-scoped and can't back a session-scoped fixture; there's
    nothing to restore since no other real value should ever fill this
    slot inside a test run.
    """
    db = str(tmp_path_factory.mktemp("scan_log") / "test_scan_log.db")
    scan_log.SCAN_LOG_DB = db
    scan_log.init_db()
    scan_log.init_url_db()
    # subscription.py no longer has a SCAN_LOG_DB attribute at all -
    # daily_usage/trial_status moved to Supabase Postgres (2026-09-22,
    # see fake_subscription_store above). This isolation gap doesn't
    # apply to it anymore.
    # virustotal.py's own file_vt_cache table (added alongside the
    # link-checker's bare-trusted-link fast path) binds SCAN_LOG_DB the
    # same separate `from bot.config.config import SCAN_LOG_DB` way - same
    # gap, otherwise test_virustotal.py's own scan_vt_hash tests would
    # write real cache rows into whatever real scan_logs.db sits in the repo.
    from bot.detectors.file.online import virustotal
    virustotal.SCAN_LOG_DB = db
    return db


class _FakeSubscriptionStore:
    """In-memory stand-in for Supabase's daily_usage/user_state tables
    (bot/storage/subscription.py moved off SQLite onto Postgres,
    2026-09-22 - Render's free tier wipes local SQLite on every deploy,
    which used to silently reset every quota counter and Business
    owner's trial clock). Limit/tier logic (FREEMIUM_*, _limits_for,
    is_paid_user, _today) is NOT reimplemented here - every method calls
    straight through to the real subscription module functions, so this
    can't silently drift from production behavior and a test's
    `monkeypatch.setattr(subscription, "is_paid_user", ...)` still takes
    effect exactly as it did against the old SQLite-backed functions."""

    def __init__(self):
        self.daily_usage: dict[tuple[int, object], dict] = {}
        self.user_state: dict[int, dict] = {}

    def _row(self, user_id: int) -> dict:
        return self.daily_usage.setdefault(
            (user_id, subscription._today()),
            {"files_used": 0, "links_messages_used": 0, "tokens_used": 0,
             "file_limit_notified": False, "links_messages_limit_notified": False},
        )

    def _state(self, user_id: int) -> dict:
        return self.user_state.setdefault(
            user_id, {"trial_started_at": None, "notified_trial_ended": False, "lang": None},
        )

    async def can_scan_file(self, user_id: int) -> bool:
        max_files, _, _ = await subscription._limits_for(user_id)
        return self._row(user_id)["files_used"] < max_files

    async def record_file_scan(self, user_id: int) -> None:
        self._row(user_id)["files_used"] += 1

    async def can_scan_link_or_message(self, user_id: int) -> bool:
        _, max_links, _ = await subscription._limits_for(user_id)
        return self._row(user_id)["links_messages_used"] < max_links

    async def record_link_or_message_scan(self, user_id: int) -> None:
        self._row(user_id)["links_messages_used"] += 1

    async def has_token_budget(self, user_id: int) -> bool:
        _, _, max_tokens = await subscription._limits_for(user_id)
        return self._row(user_id)["tokens_used"] < max_tokens

    async def record_token_usage(self, user_id: int, tokens: int) -> None:
        if tokens > 0:
            self._row(user_id)["tokens_used"] += tokens

    async def should_notify_file_limit(self, user_id: int) -> bool:
        row = self._row(user_id)
        if row["file_limit_notified"]:
            return False
        row["file_limit_notified"] = True
        return True

    async def should_notify_link_limit(self, user_id: int) -> bool:
        row = self._row(user_id)
        if row["links_messages_limit_notified"]:
            return False
        row["links_messages_limit_notified"] = True
        return True

    async def usage_summary(self, user_id: int) -> dict:
        max_files, max_links, max_tokens = await subscription._limits_for(user_id)
        row = self._row(user_id)
        return {
            "files_used": row["files_used"], "files_limit": max_files,
            "links_messages_used": row["links_messages_used"], "links_messages_limit": max_links,
            "tokens_used": row["tokens_used"], "tokens_limit": max_tokens,
        }

    async def ensure_trial_started(self, user_id: int) -> None:
        state = self._state(user_id)
        if state["trial_started_at"] is None:
            state["trial_started_at"] = datetime.now(timezone.utc)

    async def live_detect_trial_days_left(self, user_id: int) -> int:
        started = self.user_state.get(user_id, {}).get("trial_started_at")
        if started is None:
            return subscription.FREEMIUM_TRIAL_DAYS
        elapsed_days = (datetime.now(timezone.utc) - started).days
        return max(subscription.FREEMIUM_TRIAL_DAYS - elapsed_days, 0)

    async def live_detect_allowed(self, user_id: int) -> bool:
        if await subscription.is_paid_user(user_id):
            return True
        return await self.live_detect_trial_days_left(user_id) > 0

    async def should_notify_live_detect_ended(self, user_id: int) -> bool:
        state = self.user_state.get(user_id)
        if state is None or state["notified_trial_ended"]:
            return False
        state["notified_trial_ended"] = True
        return True

    async def get_stored_lang(self, user_id: int) -> str | None:
        return self.user_state.get(user_id, {}).get("lang")

    async def set_stored_lang(self, user_id: int, lang: str) -> None:
        self._state(user_id)["lang"] = lang


@pytest.fixture(autouse=True)
def fake_subscription_store(monkeypatch):
    """Autouse (unlike fake_vector_store, which is opt-in): quota/budget
    checks gate nearly every real handler path this suite exercises
    (handle_file, handle_text, analyze_unified, analyze_text_with_llm,
    handle_business_message all call into subscription.py, often
    incidentally to what a given test is actually checking) - the old
    SQLite-backed _reset_subscription_usage fixture was autouse for the
    exact same reason. Without this, most of the suite would either hit
    the real Supabase pool (slow, and daily_usage/user_state may not
    even exist there yet) or silently rely on subscription.py's own
    fail-open error handling on every call - technically harmless
    (never blocks a test), but a real, unnecessary network round trip
    per call, on nearly every test in the suite.

    Returns the store itself for tests that want to seed/inspect state
    directly (e.g. simulating a trial started 8 days ago) instead of
    the old raw `sub._connect()` SQL inserts."""
    store = _FakeSubscriptionStore()
    for name in (
        "can_scan_file", "record_file_scan", "can_scan_link_or_message",
        "record_link_or_message_scan", "has_token_budget", "record_token_usage",
        "should_notify_file_limit", "should_notify_link_limit",
        "should_notify_live_detect_ended", "usage_summary", "ensure_trial_started",
        "live_detect_trial_days_left", "live_detect_allowed",
        "get_stored_lang", "set_stored_lang",
    ):
        monkeypatch.setattr(subscription, name, getattr(store, name))
    return store


@pytest.fixture(autouse=True)
def _no_real_bge_m3_network_calls(monkeypatch):
    """CONFIRMED REAL BUG, not a hypothetical (2026-09-21): the real .env
    now has USE_BGE_M3_EMBEDDINGS=true (bge-m3 is genuinely live in
    production, hosted on Modal - see bge_m3_embed.py's module
    docstring). scam_patterns.py's nearest_scam_pattern_live() does a
    FRESH `from bot.config.config import USE_BGE_M3_EMBEDDINGS` inside
    its own function body on every call (not a one-time module-level
    bind), so it reads the real .env value live, even inside "unit"
    tests. test_context_engine.py calls analyze_unified() directly
    (multiple tests) with nothing mocking the pattern-match path - full
    suite runtime measurably jumped (~65s -> ~108s) once the real flag
    flipped on, confirming those tests started making real network calls
    to the Modal endpoint. Same bug class as _no_real_admin_alerts above:
    a global env-derived flag silently causing real side effects inside
    tests that never intended to touch it. Patches the SOURCE module's
    attribute (not scam_patterns.py's own binding, since there isn't
    one - it re-imports fresh every call), so this works regardless of
    which module ends up reading it.

    Also neutralizes the Gemini-embedding SECOND-TIER fallback added the
    same day (gemini_embed.py) - nearest_scam_pattern_live() tries that
    tier unconditionally whenever bge-m3's tier doesn't answer (flag off
    counts as "didn't answer" too), so forcing USE_BGE_M3_EMBEDDINGS off
    alone isn't enough to keep tests offline anymore; without this,
    disabling bge-m3 for tests would just redirect the same real-network-
    call bug onto Gemini's embedding API instead. Different fix shape
    though: gemini_embed.py builds its client ONCE at module import time
    (`_client = build_client(GEMINI_API_KEY_EMBEDDING)`, not a fresh
    per-call import like USE_BGE_M3_EMBEDDINGS above), so patching the
    config attribute after import wouldn't touch the already-built
    client - this patches gemini_embed's own already-bound `_client`
    directly, which embed_gemini()'s own `if _client is None: return
    None` early-return already treats as "unavailable"."""
    from bot.config import config
    from bot.detectors.text.online import gemini_embed
    monkeypatch.setattr(config, "USE_BGE_M3_EMBEDDINGS", False)
    monkeypatch.setattr(gemini_embed, "_client", None)


@pytest.fixture(autouse=True)
def _no_real_admin_alerts(monkeypatch):
    """CONFIRMED REAL BUG, not a hypothetical (2026-09-11): several tests
    (test_link_checker.py's Supabase-outage tests, e.g.
    test_analyze_url_marks_evidence_degraded_when_supabase_down_and_result_uncertain)
    monkeypatch a LOW-level call (vectors.nearest) to raise, then exercise
    the REAL pipeline.analyze_url() above it to verify the resulting
    verdict - they never touch health_alerts at all directly. But
    _safe_nearest()'s except block calls the REAL health_alerts.
    record_failure()/maybe_alert() on that same real exception, and
    maybe_alert() was never mocked in those tests - only test_health_alerts.py's
    OWN tests were careful to fake ADMIN_CHAT_ID/httpx. The result: running
    those 3 tests together (any full-suite or single-file run) sent REAL
    "Supabase pool exhausted" Telegram messages to the REAL admin group
    using the REAL bot token from .env, repeatedly, all session - the
    exact alerts that derailed a live debugging session before the actual
    cause (this) was found.

    ADMIN_CHAT_ID=None makes maybe_alert()'s own early-return fire
    unconditionally, so no test can ever reach the real httpx call by
    accident, no matter how indirectly it's triggered. Tests that
    deliberately exercise the real alert-sending path (test_health_alerts.py)
    already monkeypatch their own ADMIN_CHAT_ID locally, which overrides
    this default for their own scope - this fixture only closes the gap
    for every OTHER test that doesn't expect to touch alerting at all."""
    from bot.storage import health_alerts
    monkeypatch.setattr(health_alerts, "ADMIN_CHAT_ID", None)


@pytest.fixture(autouse=True)
def _reset_gemini_circuit_breaker():
    """Same class of gap as _no_real_admin_alerts above, this time for
    gemini_retry.py's circuit breaker (2026-09-16). Its consecutive-
    failure counter and open-until deadline are module-level globals,
    shared across the WHOLE test run, not just tests that mention it by
    name - test_context_engine.py and test_llm_analyzer.py both call the
    real generate_content_with_backup() with a fake client that raises,
    many times, across many tests. Three such failures in a row with no
    success in between - purely a question of test EXECUTION ORDER, not
    of any single test's own correctness - opens the real breaker, and a
    later, unrelated test then gets GeminiCircuitOpenError from a call
    it expected to fail/succeed normally. Confirmed as a real latent gap
    (not hypothetical): the full suite passes today only because no 3
    failing tests currently happen to run back to back, which is not a
    property any test actually asserts or protects."""
    import bot.detectors.text.online.gemini_retry as gemini_retry
    gemini_retry._consecutive_failures = 0
    gemini_retry._circuit_open_until = 0.0
    # Same cross-test-leakage class again: the primary-pool round-robin
    # index (2026-09-22) is also a module-level global shared across the
    # whole run - reset so which pool slot a test's single-client list
    # lands on never depends on how many prior tests already called
    # generate_content_with_backup().
    gemini_retry._rr_index = 0

    # Same gap, same fix, for gemini_embed.py's OWN independent breaker
    # (2026-09-22) - separate module-level globals, separate state, same
    # cross-test-leakage risk (test_scam_patterns_gemini.py and
    # test_gemini_embed.py both exercise real failures against it).
    import bot.detectors.text.online.gemini_embed as gemini_embed
    gemini_embed._consecutive_failures = 0
    gemini_embed._circuit_open_until = 0.0


@pytest.fixture(autouse=True)
def _reset_dns_resolution_cache():
    """safe_net._resolve_all_sync's per-host cache (2026-09-16) is a
    module-level dict with a 5s TTL, shared across the WHOLE test run -
    a test that monkeypatches socket.getaddrinfo/safe_net._resolve_all_sync
    to raise or return a specific value for some host, then a LATER,
    unrelated test happening to reuse that same hostname string within
    5 real wall-clock seconds, would get the FIRST test's cached result
    instead of exercising its own mocked behavior. Cleared before every
    test, same defensive pattern as _reset_gemini_circuit_breaker above."""
    from bot.detectors.url.online import safe_net
    safe_net._resolution_cache.clear()


@pytest.fixture(autouse=True)
def _reset_embedding_index_build_cooldown():
    """scam_patterns.py's failed-index-build negative cache (2026-09-24)
    is module-level state with a 60s window, so it leaks across tests
    exactly like the circuit breakers above do - and it bit immediately:
    a test that simulates "Modal and Gemini are both down" sets the
    cooldown, and the NEXT test, which supplies a perfectly good fake
    embedding client, was then refused a build for the next 60 real
    seconds and saw a None index.

    Only the COOLDOWN is reset here, not the built indexes themselves -
    those are a legitimate cross-test cache (building one costs 30 real
    embedding calls) and tests that care already monkeypatch them
    directly."""
    from bot.detectors.text.offline import scam_patterns
    scam_patterns._bge_m3_index_retry_after = 0.0
    scam_patterns._gemini_index_retry_after = 0.0
