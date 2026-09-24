"""
bot/detectors/url/online/safe_net.py
======================================
SSRF protection shared by every real outbound connection this bot makes
to a USER-SUPPLIED host.

Two real targets, both fixed here:

  * network.py's trace() - the link checker's page fetch. A user can
    send any URL; without this, `http://169.254.169.254/latest/
    meta-data/` (or a normal-looking public link that redirects there)
    would be fetched from wherever the bot happens to be hosted.
  * cert_info.py's TLS certificate connect - a raw socket.connect to
    the same kind of user-supplied host, on a different code path, so
    it needs its own guard rather than trusting network.py's transport
    to somehow cover it.

domain_info.py needed NO change: its RDAP lookup always connects to the
fixed, trusted rdap.org (the scanned domain is only ever a PATH segment
in that request, e.g. "https://rdap.org/domain/evil.tk" - never the
connection target), and plain DNS resolution (socket.getaddrinfo) only
talks to the configured resolver, never to the target host at all -
there is no outbound connection to a user-supplied host on that path
for this module to guard.

Why hostname-string checking is not enough: DNS rebinding. A hostname
can resolve to a public IP the first time it's checked and a private
one moments later, at actual connect time - a string check on the host
alone has no way to see that. The real fix has to happen where the
socket actually connects, validating the IP that connection is about to
use, not the name that was typed, and then USING that exact validated
IP for the real connection rather than re-resolving the name again
afterward - a second lookup is exactly the window an attacker's DNS
answer could change in. first_safe_ip_sync (used by both call sites)
does the resolve-validate-return-the-IP step atomically for this
reason.
"""

from __future__ import annotations

import asyncio
import time
import ipaddress
import logging
import socket

import httpcore
import httpx
from httpx._transports.default import create_ssl_context

from bot.config.config import SSRF_ALLOWED_HOSTS

logger = logging.getLogger(__name__)

# Same bound class as domain_info.DNS_TIMEOUT - first_safe_ip_sync's own
# resolution step (socket.getaddrinfo) has no timeout of its own, same
# gap that constant exists to close elsewhere. Callers that invoke this
# from async code (_ValidatingNetworkBackend.connect_tcp, cert_info's
# cert_issued_days_ago) must bound it themselves with asyncio.wait_for -
# this module can't do that internally, since first_safe_ip_sync is
# itself synchronous and typically already running inside a worker
# thread with no event loop of its own to wait_for against.
DNS_TIMEOUT = 5.0

# 169.254.169.254 is already covered by is_link_local (169.254.0.0/16),
# listed explicitly anyway per the exact spec this was written against,
# so the reason is visible without having to know that range by heart.
# The IPv6 form covers AWS IMDS's IPv6 equivalent the same way.
_CLOUD_METADATA_IPS = frozenset({"169.254.169.254", "fd00:ec2::254"})


class BlockedAddressError(httpcore.ConnectError):
    """Raised from inside the network backend so httpx/httpcore surface
    it through their own normal ConnectError handling - every caller
    that already catches connection failures (network.trace's broad
    `except Exception`, cert_info's `_get_cert_sync`) needs no new
    except clause, it just degrades exactly like any other unreachable
    host. Subclassing httpcore.ConnectError (rather than a plain
    Exception) keeps it inside httpx's own retry/error taxonomy instead
    of looking like an unrelated crash."""


def is_blocked_ip(ip_str: str) -> bool:
    """True if `ip_str` must never be connected to - private, loopback,
    link-local, reserved, unspecified, multicast, or a known cloud
    metadata address. Malformed input is treated as blocked (fail
    closed), not as "not blocked" - a caller with a genuinely unparsable
    IP string has no business connecting to it either way."""
    if ip_str in _CLOUD_METADATA_IPS:
        return True
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return True
    return (
        ip.is_private or ip.is_loopback or ip.is_link_local
        or ip.is_reserved or ip.is_unspecified or ip.is_multicast
    )


def is_host_allowlisted(host: str) -> bool:
    """SSRF_ALLOWED_HOSTS opt-out - exact hostname match, case-insensitive,
    empty (nothing allowed) by default. Checked by hostname, not by
    resolved IP: this is for a self-hosted deployment that KNOWINGLY
    wants to scan one specific internal name, not a way to bulk-exempt
    addresses."""
    return (host or "").strip().lower() in SSRF_ALLOWED_HOSTS


# Both raised by socket.getaddrinfo() for a genuinely bad host, just
# from two unrelated causes: gaierror is the resolver saying "no such
# host"; UnicodeError (confirmed live: UnicodeEncodeError, "'idna' codec
# can't encode... label too long") is Python's OWN idna codec refusing
# to even ATTEMPT the lookup for a hostname with a label over 63
# characters - a real, common shape (long garbage subdomains are a
# standard phishing-link pattern). Only socket.gaierror was originally
# caught here, so that link shape crashed instead of degrading -
# pipeline.py's asyncio.gather(return_exceptions=True) hid the crash for
# the one production path that goes through it, but silently dropped
# the DNS/cert-age signal with no log trace, and any other caller
# (including several of this module's own tests, which call these
# functions directly) got a real unhandled exception.
_UNRESOLVABLE_ERRORS = (socket.gaierror, UnicodeError)


# Real inefficiency, found by code review (2026-09-16): network.py's
# SSRF check, cert_info.py's SSRF check, and domain_info.py's plain DNS
# lookup all independently resolve the SAME host for the SAME scan -
# pipeline.py's asyncio.gather runs all three concurrently with no
# sharing, so one link costs 3 real getaddrinfo calls (each its own
# to_thread worker) where 1 would do. A short-lived cache closes this:
# resolved IPs for a hostname don't depend on the `port` argument at all
# (getaddrinfo's port only matters for service-name lookups, never for
# WHICH addresses come back), so this is keyed by host alone and shared
# by every caller in this process, including domain_info.py's own
# resolution (see that module's _resolve_sync).
#
# Deliberately short (a few seconds, not a real DNS TTL respected) -
# long enough to cover one scan's own concurrent lookups, short enough
# that staleness is a non-issue for what this data is used for (SSRF
# validation always re-checks whatever IP is actually used to connect;
# this cache only saves repeating the LOOKUP itself). No lock: a
# concurrent cache miss from two threads at once just means one wasted
# extra lookup, not an incorrect result - not worth the complexity of
# guarding a pure optimization.
_RESOLUTION_CACHE_TTL_SECONDS = 5.0
_RESOLUTION_CACHE_MAX_ENTRIES = 256
_resolution_cache: dict[str, tuple[float, list[str]]] = {}


def _resolve_all_sync(host: str, port: int) -> list[str]:
    """Every IP `host` resolves to, as plain strings. Raises one of
    _UNRESOLVABLE_ERRORS on a genuinely unresolvable host - left to the
    caller, same contract as domain_info._resolve_sync, rather than
    swallowed here where a caller couldn't tell "didn't resolve" apart
    from "resolved to something blocked"."""
    key = host.lower()
    now = time.monotonic()
    cached = _resolution_cache.get(key)
    if cached is not None:
        cached_at, ips = cached
        if now - cached_at < _RESOLUTION_CACHE_TTL_SECONDS:
            return ips

    infos = socket.getaddrinfo(host, port)
    result = sorted({info[4][0] for info in infos})
    _resolution_cache[key] = (now, result)

    # Expired entries were never actually removed before (2026-09-24,
    # found by a performance review) - only overwritten if the SAME host
    # came back within the window. Every distinct hostname the bot ever
    # resolved therefore stayed forever, and this bot resolves whatever
    # arbitrary domains strangers send it, so the dict grew without
    # bound for the life of the process on a 512MB instance.
    #
    # Swept only when the cache is already larger than any real 5s
    # window could justify, so the common path stays a plain dict
    # insert: entries live 5 seconds, so a genuinely busy moment holds
    # maybe a few dozen, never hundreds.
    if len(_resolution_cache) > _RESOLUTION_CACHE_MAX_ENTRIES:
        for stale_key in [
            k for k, (at, _) in _resolution_cache.items()
            if now - at >= _RESOLUTION_CACHE_TTL_SECONDS
        ]:
            del _resolution_cache[stale_key]
    return result


def _resolve_candidates_sync(host: str, port: int) -> list[str]:
    """Every candidate IP for `host`, unfiltered - a literal IP as its own
    single-item list, otherwise every _resolve_all_sync result. Raises
    BlockedAddressError when a hostname is genuinely unresolvable.

    Split out of safe_ips_sync, which used to inline this literal-vs-
    hostname resolution twice (once per allowlist branch) - unifying it
    here leaves safe_ips_sync itself as just "get candidates, then decide
    allowlist-bypass vs blocked-IP-filter." Verified behavior-identical
    against the previous version for every combination."""
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        return [str(literal)]

    try:
        candidates = _resolve_all_sync(host, port)
    except _UNRESOLVABLE_ERRORS as error:
        raise BlockedAddressError(f"unresolvable: {host}") from error
    if not candidates:
        raise BlockedAddressError(f"unresolvable: {host}")
    return candidates


def safe_ips_sync(host: str, port: int) -> list[str]:
    """Every resolved IP for `host` that is NOT blocked, in resolved
    order. Raises BlockedAddressError when unresolvable, allowlisted-
    but-unresolvable, or every resolved IP is blocked.

    Returns the full candidate list (not just one) so a caller can retry
    each in turn, same as socket.create_connection/httpcore's own
    default backend both already do natively - see
    network.py's _ValidatingNetworkBackend.connect_tcp and
    cert_info.py's _get_cert_sync for the two real retry loops.

    Callers MUST use these exact IPs for the real connection and never
    re-resolve `host` again - see this module's own docstring for why
    that's what actually closes the DNS-rebinding gap."""
    candidates = _resolve_candidates_sync(host, port)

    if is_host_allowlisted(host):
        return candidates

    safe = [candidate for candidate in candidates if not is_blocked_ip(candidate)]
    if safe:
        return safe

    logger.info("SSRF guard blocked %s - every resolved address is internal/reserved: %s",
                host, candidates)
    raise BlockedAddressError(f"blocked: internal or reserved address ({host})")


def first_safe_ip_sync(host: str, port: int) -> str:
    """First safe IP only - see safe_ips_sync's own docstring for why a
    caller that actually opens a connection should use safe_ips_sync and
    try each candidate instead of just this one. Kept as a thin wrapper
    (rather than removed) since a caller that only needs ONE validated
    IP - not a connect-and-retry loop - has no reason to handle a list."""
    return safe_ips_sync(host, port)[0]


class _ValidatingNetworkBackend(httpcore.AnyIOBackend):
    """httpx's real connection point for network.py's shared client.

    httpcore calls connect_tcp(host=<original request hostname>, port,
    ...) for EVERY new TCP connection it opens - including a redirect
    hop to a different host, which needs its own new connection and
    therefore goes through this same check again for free (see
    httpcore's AsyncHTTPConnection._connect: it passes
    self._origin.host, the CURRENT request's own host, not something
    cached from an earlier hop). TLS SNI and the Host header are
    untouched by substituting the IP here: httpcore's own connection
    code reads the server_hostname for TLS and httpx builds the Host
    header from the request's URL, both independently of whatever
    address connect_tcp actually opened a socket to - confirmed by
    reading httpcore._async.connection.AsyncHTTPConnection._connect
    directly rather than assumed.
    """

    async def connect_tcp(self, host, port, timeout=None, local_address=None, socket_options=None):
        # httpcore's real AnyIOBackend.connect_tcp bounds DNS resolution
        # and the TCP connect TOGETHER under one shared timeout budget
        # (confirmed against httpcore 1.0.9 source - resolving a hostname
        # is part of what anyio.connect_tcp does internally). This
        # `deadline`, shared across both helpers below, restores that
        # single combined budget instead of giving DNS and connect each
        # their own separate one (which would double worst-case latency
        # per hop, on every redirect up to MAX_REDIRECTS=10).
        budget = timeout if timeout is not None else DNS_TIMEOUT
        deadline = time.monotonic() + budget
        safe_ips = await self._resolve_safe_ips(host, port, budget)
        return await self._connect_to_first_reachable(
            safe_ips, port, deadline, timeout, local_address, socket_options,
        )

    async def _resolve_safe_ips(self, host, port, budget):
        # safe_ips_sync's own DNS resolution has no timeout of its own
        # (see DNS_TIMEOUT's comment) - bounded here the same way
        # domain_info.resolve_host bounds the equivalent unbounded
        # getaddrinfo call, so a hung resolver degrades this ONE
        # connection attempt instead of hanging the whole scan.
        try:
            return await asyncio.wait_for(
                asyncio.to_thread(safe_ips_sync, host, port), timeout=budget,
            )
        except asyncio.TimeoutError as error:
            raise BlockedAddressError(f"DNS resolution timed out: {host}") from error

    async def _connect_to_first_reachable(self, candidates, port, deadline, timeout,
                                           local_address, socket_options):
        # Tries each candidate in turn (matching socket.create_connection/
        # httpcore's own default backend), all under the SAME overall
        # deadline set by connect_tcp rather than a fresh budget per
        # candidate - a host with many bad IPs can't cost N times the
        # configured timeout.
        last_error: Exception | None = None
        for candidate in candidates:
            remaining = timeout
            if timeout is not None:
                remaining = max(deadline - time.monotonic(), 0.0)
            try:
                return await super().connect_tcp(
                    candidate, port, timeout=remaining, local_address=local_address,
                    socket_options=socket_options,
                )
            except Exception as error:                  # noqa: BLE001 - try the next candidate
                last_error = error
        raise last_error


class SafeAsyncHTTPTransport(httpx.AsyncHTTPTransport):
    """httpx.AsyncHTTPTransport with every TCP connection validated via
    _ValidatingNetworkBackend, for network.py's shared client.

    Deliberately does NOT call super().__init__() and then swap out
    self._pool afterward - that would mean building a real
    httpcore.AsyncConnectionPool (opening whatever its default backend
    needs) just to immediately throw it away, and it would leave a
    window where self._pool briefly exists unvalidated. Reimplements
    the same non-proxy construction httpx.AsyncHTTPTransport.__init__
    itself uses (confirmed by reading that method directly), with
    network_backend added - this project never proxies outbound scan
    requests, so the proxy/SOCKS branches that real constructor also
    handles are intentionally not reimplemented here.
    """

    def __init__(
        self,
        verify: bool = True,
        http1: bool = True,
        http2: bool = False,
        limits: httpx.Limits = httpx._config.DEFAULT_LIMITS,
        retries: int = 0,
        socket_options=None,
    ) -> None:
        ssl_context = create_ssl_context(verify=verify, cert=None, trust_env=True)
        self._pool = httpcore.AsyncConnectionPool(
            ssl_context=ssl_context,
            max_connections=limits.max_connections,
            max_keepalive_connections=limits.max_keepalive_connections,
            keepalive_expiry=limits.keepalive_expiry,
            http1=http1,
            http2=http2,
            retries=retries,
            socket_options=socket_options,
            network_backend=_ValidatingNetworkBackend(),
        )
