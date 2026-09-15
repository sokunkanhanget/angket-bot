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


def _resolve_all_sync(host: str, port: int) -> list[str]:
    """Every IP `host` resolves to, as plain strings. Raises
    socket.gaierror on a genuinely unresolvable host - left to the
    caller, same contract as domain_info._resolve_sync, rather than
    swallowed here where a caller couldn't tell "didn't resolve" apart
    from "resolved to something blocked"."""
    infos = socket.getaddrinfo(host, port)
    return sorted({info[4][0] for info in infos})


def first_safe_ip_sync(host: str, port: int) -> str:
    """Resolve `host` and return the first IP that is NOT blocked.
    Raises BlockedAddressError if the host is unresolvable, allowlisted-
    but-unresolvable, or every resolved IP is blocked - callers
    (_ValidatingNetworkBackend.connect_tcp, cert_info's own connect
    helper) are expected to let that surface as a normal connection
    failure, not catch it and retry with something else.

    The caller MUST use this returned IP for the real connection and
    never re-resolve `host` itself afterward - see this module's
    docstring for why that's the part that actually closes the DNS
    rebinding gap, not just checking the host once somewhere earlier.
    """
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None

    if is_host_allowlisted(host):
        if literal is not None:
            return str(literal)
        try:
            candidates = _resolve_all_sync(host, port)
        except socket.gaierror as error:
            raise BlockedAddressError(f"unresolvable: {host}") from error
        if not candidates:
            raise BlockedAddressError(f"unresolvable: {host}")
        return candidates[0]

    if literal is not None:
        if is_blocked_ip(str(literal)):
            raise BlockedAddressError(f"blocked: internal or reserved address ({host})")
        return str(literal)

    try:
        candidates = _resolve_all_sync(host, port)
    except socket.gaierror as error:
        raise BlockedAddressError(f"unresolvable: {host}") from error

    for candidate in candidates:
        if not is_blocked_ip(candidate):
            return candidate

    logger.info("SSRF guard blocked %s - every resolved address is internal/reserved: %s",
                host, candidates)
    raise BlockedAddressError(f"blocked: internal or reserved address ({host})")


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
        # first_safe_ip_sync's own DNS resolution has no timeout of its
        # own (see DNS_TIMEOUT's comment) - bounded here the same way
        # domain_info.resolve_host bounds the equivalent unbounded
        # getaddrinfo call, so a hung resolver degrades this ONE
        # connection attempt instead of hanging the whole scan.
        try:
            safe_ip = await asyncio.wait_for(
                asyncio.to_thread(first_safe_ip_sync, host, port), timeout=DNS_TIMEOUT,
            )
        except asyncio.TimeoutError as error:
            raise BlockedAddressError(f"DNS resolution timed out: {host}") from error
        return await super().connect_tcp(
            safe_ip, port, timeout=timeout, local_address=local_address,
            socket_options=socket_options,
        )


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
