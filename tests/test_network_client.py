"""
tests/test_network_client.py
============================
The shared httpx client behind network.trace().

trace() used to build a brand-new httpx.AsyncClient for every link
check. The dominant cost was not the connection pool but the SSLContext:
httpx.AsyncClient(verify=True) loads the whole system CA store on
construction, measured at 320-490ms on this machine, paid before any
network I/O on every single scan.

These tests run against a real local HTTP server rather than mocks, so
they exercise the actual client, the actual cookie handling, and the
actual failure path.
"""

import asyncio
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from bot.detectors.url.online import network, safe_net


class _Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):           # keep pytest output clean
        pass

    def do_GET(self):
        self.server.seen_cookies.append(self.headers.get("Cookie"))
        body = b"<html><title>probe</title><body>probe page body</body></html>"
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(body)))
        # A site that tries to set a session cookie. On a shared client
        # this is exactly what must NOT survive into the next scan.
        self.send_header("Set-Cookie", "session=super-secret-value; Path=/")
        self.end_headers()
        self.wfile.write(body)


@pytest.fixture
def local_server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    server.seen_cookies = []
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=5)


@pytest.fixture(autouse=True)
def reset_shared_client(monkeypatch):
    """Never let one test's client leak into another's assertions."""
    # These tests deliberately run a real local HTTP server on
    # 127.0.0.1 to exercise the real client/cookie/failure behavior -
    # unrelated to what the SSRF guard exists to test (that's
    # tests/test_safe_net.py's job). Loopback is blocked by default now
    # (see safe_net.py), so this test module's own local server needs
    # the explicit opt-out, same as a real self-hosted deployment would
    # use for a legitimate internal target.
    monkeypatch.setattr(safe_net, "SSRF_ALLOWED_HOSTS", frozenset({"127.0.0.1"}))
    asyncio.run(network.aclose())
    yield
    asyncio.run(network.aclose())


def _base(server) -> str:
    return f"http://127.0.0.1:{server.server_address[1]}"


def test_the_same_client_is_reused_across_traces(local_server):
    async def run():
        first = await network.trace(f"{_base(local_server)}/one")
        client_after_first = network._get_client()
        second = await network.trace(f"{_base(local_server)}/two")
        return first, second, client_after_first, network._get_client()

    first, second, client_a, client_b = asyncio.run(run())

    assert first["reachable"] and second["reachable"]
    assert client_a is client_b


def test_a_scanned_sites_cookie_is_never_replayed_to_the_next_scan(local_server):
    # The one real hazard of sharing a client. httpx calls
    # self.cookies.extract_cookies(response) on every response, against
    # the client's own jar, with no per-request override - so without
    # network._NoStoreCookieJar the second scan below would arrive
    # carrying the first site's session cookie. One site's response must
    # never be able to influence another site's verdict.
    async def run():
        await network.trace(f"{_base(local_server)}/one")
        await network.trace(f"{_base(local_server)}/two")
        return list(network._get_client().cookies.jar)

    stored_cookies = asyncio.run(run())

    assert local_server.seen_cookies == [None, None]
    assert stored_cookies == []


def test_a_failed_trace_does_not_break_the_shared_client(local_server):
    # Port 1 is reliably closed; the point is that the failure is
    # reported as an unreachable-but-scorable result and the shared
    # client survives it for the next caller.
    async def run():
        ok_before = await network.trace(f"{_base(local_server)}/before")
        client_before = network._get_client()
        broken = await network.trace("http://127.0.0.1:1/definitely-closed")
        ok_after = await network.trace(f"{_base(local_server)}/after")
        return ok_before, broken, ok_after, client_before, network._get_client()

    ok_before, broken, ok_after, client_before, client_after = asyncio.run(run())

    assert broken["reachable"] is False
    assert broken["error"]
    assert ok_before["reachable"] and ok_after["reachable"]
    assert client_before is client_after
    assert not client_after.is_closed


def test_aclose_releases_the_client_and_a_later_trace_rebuilds_it(local_server):
    async def run():
        await network.trace(f"{_base(local_server)}/one")
        first = network._get_client()
        await network.aclose()
        cleared = network._client is None
        after = await network.trace(f"{_base(local_server)}/two")
        return first, cleared, after, network._get_client()

    first, cleared, after, rebuilt = asyncio.run(run())

    assert cleared
    assert after["reachable"]
    assert rebuilt is not first
    assert not rebuilt.is_closed


def test_client_is_rebuilt_if_it_was_closed_without_aclose(local_server):
    # Defensive: if anything closes the client out from under us, the
    # next scan must rebuild rather than raise on a closed client.
    async def run():
        await network.trace(f"{_base(local_server)}/one")
        stale = network._get_client()
        await stale.aclose()
        result = await network.trace(f"{_base(local_server)}/two")
        return stale, result, network._get_client()

    stale, result, rebuilt = asyncio.run(run())

    assert result["reachable"]
    assert rebuilt is not stale
