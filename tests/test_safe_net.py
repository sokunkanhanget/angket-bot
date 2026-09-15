"""
tests/test_safe_net.py
=======================
SSRF protection (bot/detectors/url/online/safe_net.py) - blocking every
outbound connection this bot makes to a user-supplied host from
reaching a private, loopback, link-local, reserved, unspecified, or
multicast address, or the cloud metadata IP 169.254.169.254.

Runs against a real local HTTP server and real sockets, not mocks -
the whole point of this guard is what happens at the actual TCP
connect, which a mocked resolver/transport could hide a real gap in.
"""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from bot.detectors.url.online import cert_info, network, safe_net


# --- is_blocked_ip -------------------------------------------------------

@pytest.mark.parametrize("ip", [
    "127.0.0.1", "127.255.255.255",             # loopback
    "10.0.0.1", "10.255.255.255",                # private (10/8)
    "192.168.1.1", "192.168.255.255",            # private (192.168/16)
    "172.16.0.1", "172.31.255.255",              # private (172.16/12)
    "169.254.169.254",                           # cloud metadata (link-local too)
    "169.254.1.1",                               # link-local, general
    "0.0.0.0",                                   # unspecified
    "224.0.0.1",                                 # multicast
    "::1",                                       # IPv6 loopback
    "fe80::1",                                   # IPv6 link-local
    "fc00::1",                                   # IPv6 private (unique local)
    "fd00:ec2::254",                             # IPv6 cloud metadata equivalent
])
def test_is_blocked_ip_true_for_every_internal_or_reserved_address(ip):
    assert safe_net.is_blocked_ip(ip) is True


@pytest.mark.parametrize("ip", [
    "93.184.216.34",       # example.com's real IP at time of writing
    "8.8.8.8",              # Google public DNS
    "2606:4700:4700::1111",  # Cloudflare public DNS, IPv6
])
def test_is_blocked_ip_false_for_real_public_addresses(ip):
    assert safe_net.is_blocked_ip(ip) is False


def test_is_blocked_ip_fails_closed_on_garbage_input():
    assert safe_net.is_blocked_ip("not-an-ip-at-all") is True
    assert safe_net.is_blocked_ip("") is True


# --- is_host_allowlisted / SSRF_ALLOWED_HOSTS ----------------------------

def test_allowlist_is_empty_by_default():
    assert safe_net.is_host_allowlisted("127.0.0.1") is False
    assert safe_net.is_host_allowlisted("anything.internal") is False


def test_allowlist_matches_exact_hostname_case_insensitively(monkeypatch):
    monkeypatch.setattr(safe_net, "SSRF_ALLOWED_HOSTS", frozenset({"internal.example"}))
    assert safe_net.is_host_allowlisted("internal.example") is True
    assert safe_net.is_host_allowlisted("INTERNAL.EXAMPLE") is True
    assert safe_net.is_host_allowlisted("other.example") is False


# --- first_safe_ip_sync ---------------------------------------------------

def test_first_safe_ip_sync_blocks_a_literal_private_ip():
    with pytest.raises(safe_net.BlockedAddressError):
        safe_net.first_safe_ip_sync("127.0.0.1", 80)


def test_first_safe_ip_sync_blocks_the_metadata_ip():
    with pytest.raises(safe_net.BlockedAddressError):
        safe_net.first_safe_ip_sync("169.254.169.254", 80)


def test_first_safe_ip_sync_allows_a_real_public_ip():
    assert safe_net.first_safe_ip_sync("93.184.216.34", 443) == "93.184.216.34"


def test_first_safe_ip_sync_blocks_unresolvable_host():
    with pytest.raises(safe_net.BlockedAddressError):
        safe_net.first_safe_ip_sync("this-domain-does-not-exist-xyzabc123.invalid", 80)


def test_first_safe_ip_sync_respects_the_allowlist(monkeypatch):
    monkeypatch.setattr(safe_net, "SSRF_ALLOWED_HOSTS", frozenset({"127.0.0.1"}))
    assert safe_net.first_safe_ip_sync("127.0.0.1", 80) == "127.0.0.1"


def test_first_safe_ip_sync_picks_a_safe_ip_when_host_resolves_to_several(monkeypatch):
    # A host with mixed resolved addresses (some blocked, some not) must
    # still get a usable, safe IP back rather than being blocked outright
    # just because ONE of its addresses is bad.
    monkeypatch.setattr(safe_net, "_resolve_all_sync",
                        lambda host, port: ["127.0.0.1", "93.184.216.34"])
    assert safe_net.first_safe_ip_sync("mixed.example", 443) == "93.184.216.34"


def test_first_safe_ip_sync_blocks_when_every_resolved_ip_is_bad(monkeypatch):
    monkeypatch.setattr(safe_net, "_resolve_all_sync",
                        lambda host, port: ["127.0.0.1", "10.0.0.1"])
    with pytest.raises(safe_net.BlockedAddressError):
        safe_net.first_safe_ip_sync("all-internal.example", 443)


# --- network.trace() end to end: real sockets, real blocking ------------

@pytest.mark.asyncio
async def test_trace_blocks_loopback():
    result = await network.trace("http://127.0.0.1:9/definitely-nothing-here")
    assert result["reachable"] is False
    assert "blocked" in (result["error"] or "").lower()


@pytest.mark.asyncio
async def test_trace_blocks_a_private_10_address():
    result = await network.trace("http://10.0.0.5/")
    assert result["reachable"] is False
    assert "blocked" in (result["error"] or "").lower()


@pytest.mark.asyncio
async def test_trace_blocks_a_private_192_168_address():
    result = await network.trace("http://192.168.1.1/")
    assert result["reachable"] is False
    assert "blocked" in (result["error"] or "").lower()


@pytest.mark.asyncio
async def test_trace_blocks_a_private_172_16_address():
    result = await network.trace("http://172.16.0.1/")
    assert result["reachable"] is False
    assert "blocked" in (result["error"] or "").lower()


@pytest.mark.asyncio
async def test_trace_blocks_cloud_metadata_ip():
    result = await network.trace("http://169.254.169.254/latest/meta-data/")
    assert result["reachable"] is False
    assert "blocked" in (result["error"] or "").lower()


@pytest.mark.asyncio
async def test_trace_blocks_ipv6_loopback():
    result = await network.trace("http://[::1]:9/")
    assert result["reachable"] is False
    assert "blocked" in (result["error"] or "").lower()


@pytest.mark.asyncio
async def test_trace_does_not_flag_a_blocked_target_as_a_tls_certificate_problem():
    # A blocked SSRF target is a connection-refused case, not a
    # certificate problem - pipeline.py scores tls_valid is False as a
    # STRONGER signal (30 points, "connections are not secure") than a
    # plain unreachable host (15 points). Confusing the two would
    # mis-score a blocked internal target as if its cert were invalid.
    result = await network.trace("https://127.0.0.1:9/")
    assert result["tls_valid"] is None


@pytest.mark.asyncio
async def test_trace_does_not_hang_forever_on_a_stuck_resolver(monkeypatch):
    # Regression: first_safe_ip_sync's own DNS resolution has no timeout
    # of its own, same gap Priority 2 fixed in domain_info.resolve_host -
    # reintroduced here in the SSRF check's own resolution step. A
    # hung/slow resolver must degrade THIS connection, not stall the
    # whole scan up to the OS default (20-30s).
    import time

    def hangs(host, port):
        time.sleep(2)  # well past DNS_TIMEOUT below; no need for a real 30s hang
        return ["203.0.113.5"]

    monkeypatch.setattr(safe_net, "_resolve_all_sync", hangs)
    monkeypatch.setattr(safe_net, "DNS_TIMEOUT", 0.2)

    started = time.perf_counter()
    result = await network.trace("http://hung-resolver.example/")
    elapsed = time.perf_counter() - started

    assert result["reachable"] is False
    assert elapsed < 1.0  # nowhere near the 2s hang


@pytest.mark.asyncio
async def test_cert_issued_days_ago_does_not_hang_forever_on_a_stuck_resolver(monkeypatch, tmp_path):
    import time

    monkeypatch.setattr(cert_info, "SCAN_LOG_DB", str(tmp_path / "cert.db"))

    def hangs(host, port):
        time.sleep(2)  # well past DNS_TIMEOUT below; no need for a real 30s hang
        return ["203.0.113.5"]

    monkeypatch.setattr(safe_net, "_resolve_all_sync", hangs)
    monkeypatch.setattr(safe_net, "DNS_TIMEOUT", 0.2)
    monkeypatch.setattr(cert_info, "TIMEOUT", 0.2)  # the connect-step bound this wait_for also adds on top of

    started = time.perf_counter()
    result = await cert_info.cert_issued_days_ago("hung-resolver.example")
    elapsed = time.perf_counter() - started

    assert result is None
    assert elapsed < 1.0  # nowhere near the 2s hang


@pytest.mark.asyncio
async def test_trace_still_works_on_a_real_public_site():
    # The guard must not be so broad it breaks ordinary scans.
    result = await network.trace("https://example.com")
    assert result["reachable"] is True
    assert result["status"] == 200


@pytest.mark.asyncio
async def test_trace_blocks_a_public_host_that_redirects_to_an_internal_target():
    # The hardest real case: a legitimate-looking first hop whose
    # SERVER decides where the next hop goes. follow_redirects=True
    # hands host control to the far end - each hop must be
    # independently validated, not just the URL the user actually typed.
    class _RedirectToLoopback(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            self.send_response(302)
            # A different hostname than the allowlisted first hop below,
            # so this proves the SECOND connection is genuinely
            # revalidated on its own - not riding along on the first
            # hop's already-checked name.
            self.send_header("Location", "http://localhost:9/internal-only")
            self.end_headers()

    server = ThreadingHTTPServer(("127.0.0.1", 0), _RedirectToLoopback)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        # Allowlist ONLY the first hop's exact host, proving the second
        # hop is blocked on its own merits, not by inheriting an
        # allowlist that would have covered it too.
        import bot.detectors.url.online.safe_net as sn
        original = sn.SSRF_ALLOWED_HOSTS
        sn.SSRF_ALLOWED_HOSTS = frozenset({"127.0.0.1"})
        try:
            result = await network.trace(f"http://127.0.0.1:{port}/start")
        finally:
            sn.SSRF_ALLOWED_HOSTS = original
    finally:
        server.shutdown()
        thread.join(timeout=5)

    assert result["reachable"] is False
    assert "blocked" in (result["error"] or "").lower()


# --- cert_info.py: the raw-socket TLS connect path -----------------------

@pytest.mark.asyncio
async def test_cert_issued_days_ago_blocks_loopback(monkeypatch, tmp_path):
    monkeypatch.setattr(cert_info, "SCAN_LOG_DB", str(tmp_path / "cert.db"))
    assert await cert_info.cert_issued_days_ago("127.0.0.1") is None


@pytest.mark.asyncio
async def test_cert_issued_days_ago_blocks_metadata_ip(monkeypatch, tmp_path):
    monkeypatch.setattr(cert_info, "SCAN_LOG_DB", str(tmp_path / "cert.db"))
    assert await cert_info.cert_issued_days_ago("169.254.169.254") is None


@pytest.mark.asyncio
async def test_cert_issued_days_ago_blocks_private_10_address(monkeypatch, tmp_path):
    monkeypatch.setattr(cert_info, "SCAN_LOG_DB", str(tmp_path / "cert.db"))
    assert await cert_info.cert_issued_days_ago("10.0.0.5") is None


@pytest.mark.asyncio
async def test_cert_issued_days_ago_still_works_on_a_real_public_host(monkeypatch, tmp_path):
    monkeypatch.setattr(cert_info, "SCAN_LOG_DB", str(tmp_path / "cert.db"))
    age = await cert_info.cert_issued_days_ago("example.com")
    assert age is not None
    assert age >= 0


def test_get_cert_sync_does_not_leak_a_blocked_address_into_the_cache(monkeypatch, tmp_path):
    # A blocked target must degrade the SAME WAY a genuine handshake
    # failure does (None), not raise and not get cached as if a real
    # connection attempt happened.
    monkeypatch.setattr(cert_info, "SCAN_LOG_DB", str(tmp_path / "cert.db"))
    assert cert_info._get_cert_sync("127.0.0.1") is None
