"""
bot/detectors/url/online/network.py
=====================================
Asynchronous network verification for links — the "Async I/O" and
"Network & HTTPS / Redirect Chains / Header Verification / DOM
Parsing" rows of the research notes.

Uses httpx, which is already a hard dependency of
python-telegram-bot, so this adds zero new packages.

What one `trace()` gives the scorer:
  * full redirect chain (who redirects where, across which domains)
  * final landing URL — shorteners get re-scored against THIS, not
    the t.co/bit.ly front
  * TLS handshake validity (self-signed / expired cert => flag)
  * status code + selected response headers
  * a bounded slice of page HTML for downstream vector/LSH analysis

Everything is timeout-bounded so a dead link can't stall the bot's
event loop; total worst-case latency is ~2 x TIMEOUT seconds.
"""

from __future__ import annotations

import logging
import re
from http.cookiejar import CookieJar
from urllib.parse import urlsplit

import httpx

from bot.detectors.url.online import safe_net

logger = logging.getLogger(__name__)

TIMEOUT = httpx.Timeout(10.0, connect=5.0)
MAX_REDIRECTS = 10
MAX_PAGE_BYTES = 200_000          # enough for title + visible text of most pages
USER_AGENT = ("Mozilla/5.0 (compatible; AngketBotLinkChecker/1.0; "
              "+https://telegram.me) AppleWebKit/537.36")

# Bounded so a burst of links in a busy group can't open an unlimited
# number of sockets. keepalive connections are what make the reuse
# worthwhile in the first place - a second link to the same host inside
# the expiry window skips connect + TLS handshake entirely.
LIMITS = httpx.Limits(max_connections=20, max_keepalive_connections=10,
                      keepalive_expiry=30.0)

class _NoStoreCookieJar(CookieJar):
    """A cookie jar that holds nothing and sends nothing, ever.

    This is the one real hazard in sharing a client across scans. httpx
    calls `self.cookies.extract_cookies(response)` on EVERY response -
    unconditionally, on the client's own jar, with no per-request
    override (verified directly in httpx 0.28.1's
    AsyncClient._send_single_request, not assumed). A shared client would
    therefore accumulate one scanned site's Set-Cookie state and replay
    it to the next, unrelated site - which can genuinely change what that
    site serves, and so change the page text the vector/MinHash signals
    score. Two verdicts must never be able to influence each other that
    way.

    The link checker makes a single scoring GET and never needs a
    session, so the correct jar here is one that stores and sends
    nothing at all. httpx uses a CookieJar passed as `cookies=` directly
    as its jar (Cookies.__init__'s final `else: self.jar = cookies`
    branch), so this subclass survives client construction instead of
    being copied into a plain jar.
    """

    def extract_cookies(self, response, request):
        return None

    def add_cookie_header(self, request):
        return None


_client: httpx.AsyncClient | None = None


def _get_client() -> httpx.AsyncClient:
    """One shared client for every trace(), created on first use.

    trace() used to build a brand-new httpx.AsyncClient per link check,
    so every single scan paid fresh connection-pool setup and a full TLS
    handshake with no keep-alive reuse across scans - repeated in full
    for every link in a burst, which is exactly the group-chat case.
    """
    global _client
    if _client is None or _client.is_closed:
        _client = httpx.AsyncClient(
            follow_redirects=True,
            timeout=TIMEOUT,
            headers={"User-Agent": USER_AGENT},
            max_redirects=MAX_REDIRECTS,
            cookies=_NoStoreCookieJar(),
            # SSRF guard (see safe_net.py's module docstring): every TCP
            # connection this client opens - including a redirect hop to
            # a different host, which needs its own new connection and
            # so gets re-checked automatically - is validated against
            # private/loopback/link-local/reserved/metadata addresses
            # before it's made, not just checked against the hostname
            # string, which DNS rebinding would sail straight past.
            #
            # Dead kwargs, found by code review (2026-09-16): AsyncClient
            # builds its own transport from verify=/limits= only when NO
            # transport= is given (confirmed against httpx 0.28.1's
            # Client._init_transport - it returns `transport` immediately
            # when one is passed, never touching verify/limits at all).
            # Passing verify=True/limits=LIMITS here alongside transport=
            # silently did nothing - the real verify/limits that matter
            # are the ones passed into SafeAsyncHTTPTransport below.
            transport=safe_net.SafeAsyncHTTPTransport(verify=True, limits=LIMITS),
        )
    return _client


async def aclose() -> None:
    """Close the shared client. Wired into bot.py's post_shutdown so the
    sockets are released on a clean stop instead of being torn down by
    interpreter exit."""
    global _client
    if _client is not None and not _client.is_closed:
        try:
            await _client.aclose()
        except Exception:                      # noqa: BLE001 - shutdown must not raise
            logger.debug("Shared httpx client close failed", exc_info=True)
    _client = None

def _strip_tags(html: str) -> str:
    """Linear replacement for the old _TAG_RE = r"<[^>]+>" .sub(" ", ...).

    That pattern was catastrophic for the SAME reason the two below it
    were: on input holding many "<" and no ">", `[^>]+` scans to EOF and
    backtracks at every single "<", which is O(n^2). It was the larger
    half of the real 20.96s measured on a hostile page - fixing only the
    script/style pattern still left 1.73s here."""
    out: list[str] = []
    i = 0
    while True:
        open_at = html.find("<", i)
        if open_at == -1:
            out.append(html[i:])
            return "".join(out)
        close_at = html.find(">", open_at + 1)
        if close_at == -1:
            # No closing ">" anywhere after this - the old regex matched
            # nothing from here on, so the remainder stays verbatim.
            out.append(html[i:])
            return "".join(out)
        out.append(html[i:open_at])
        out.append(" ")
        i = close_at + 1
_PASSWORD_INPUT_RE = re.compile(r'<input\b[^>]*\btype\s*=\s*["\']password["\']', re.IGNORECASE)
_FORM_ACTION_RE = re.compile(r'<form\b[^>]*\baction\s*=\s*["\']([^"\']*)["\']', re.IGNORECASE)


def _host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


# Both of these used to be plain backtracking regexes:
#   _TITLE_RE       = r"<title[^>]*>(.*?)</title>"
#   _SCRIPT_STYLE_RE = r"<(script|style)\b.*?</\1>"
# Both were CONFIRMED catastrophic (ReDoS) on attacker-controlled page
# HTML, which this function is fed by design - trace() downloads an
# arbitrary user-supplied URL and passes the body straight here. A lazy
# `.*?` restarts its scan-to-EOF at every one of N unterminated
# `<script` tokens, which is O(n^2): a page of `"<script " * 25000`
# (exactly MAX_PAGE_BYTES, so the size cap does NOT help) measured
# 20.96s of solid CPU on this machine, against 0.0014s for a normal
# page of the same size. python-telegram-bot is single-threaded async,
# so that is 21 REAL seconds during which every other user's scan,
# every Business-chat notification, and Telegram polling itself are all
# frozen - triggerable by anyone who can send the bot a link.
#
# Replaced with index-based scanning below. Every str.find() starts at a
# monotonically increasing offset, so the whole pass is O(n) with no
# backtracking, and the observable output is unchanged (verified against
# the old patterns on real HTML).
_SCRIPT_STYLE_TAGS = ("<script", "<style")


def _strip_script_style(html: str) -> str:
    """Drops <script>/<style> blocks, matching the old regex's semantics
    exactly - including its quirks, deliberately:

    - an UNCLOSED <script> is left in place (the old regex simply
      didn't match it; _TAG_RE below then strips the tag itself), and
    - matching is non-greedy, so the block ends at the FIRST following
      close tag, not the last.

    The `\\b` the old pattern had after the tag name is preserved by the
    _is_word_char check - "<scriptfoo>" was never a script tag and
    still isn't."""
    lowered = html.lower()
    out: list[str] = []
    i = 0

    while True:
        open_at = -1
        open_tag = ""
        for tag in _SCRIPT_STYLE_TAGS:
            found = lowered.find(tag, i)
            if found != -1 and (open_at == -1 or found < open_at):
                open_at, open_tag = found, tag

        if open_at == -1:
            out.append(html[i:])
            return "".join(out)

        after = open_at + len(open_tag)
        if after < len(html) and (html[after].isalnum() or html[after] == "_"):
            # "<scriptfoo" - not a real script tag, same as the old \b.
            out.append(html[i:after])
            i = after
            continue

        close_at = lowered.find("</" + open_tag[1:], after)
        if close_at == -1:
            # Unclosed: the old regex found no match at all from here on
            # (any later open tag would have had no close either), so
            # everything that remains is emitted verbatim.
            out.append(html[i:])
            return "".join(out)

        close_end = lowered.find(">", close_at)
        close_end = len(html) if close_end == -1 else close_end + 1
        out.append(html[i:open_at])
        out.append(" ")
        i = close_end


def _extract_title(html: str) -> str:
    """First <title>...</title>'s contents, or "" - the linear
    equivalent of the old _TITLE_RE.search()."""
    lowered = html.lower()
    open_at = lowered.find("<title")
    if open_at == -1:
        return ""
    open_end = lowered.find(">", open_at)
    if open_end == -1:
        return ""
    close_at = lowered.find("</title", open_end + 1)
    if close_at == -1:
        return ""
    return html[open_end + 1:close_at].strip()


def extract_page_text(html: str) -> str:
    """Title + tag-stripped body text, for embedding and MinHash."""
    title = _extract_title(html)
    body = _strip_tags(_strip_script_style(html))
    return f"{title}\n{re.sub(r'\s+', ' ', body).strip()}"


def has_password_field(html: str) -> bool:
    """Regex, not a real DOM parser - good enough to answer "is there a
    login form on this page" without pulling in BeautifulSoup/lxml."""
    return bool(_PASSWORD_INPUT_RE.search(html or ""))


def find_form_actions(html: str) -> list[str]:
    """Every <form action="..."> target on the page, in source order.

    The classic credential-theft pattern: a login form that visually
    sits on ababank.com but actually POSTs the password somewhere else
    entirely. A relative action ("/login", "", "#") submits back to the
    same page/origin - completely normal, not flagged here. Only an
    ABSOLUTE action pointing at a different registrable domain than the
    page itself is the tell, which the caller (pipeline.py) checks.
    """
    return _FORM_ACTION_RE.findall(html or "")


async def trace(raw_url: str) -> dict:
    """Follow a link with redirects, collect every signal we can see.

    Never raises: any failure becomes reachable=False + an error note,
    because an unreachable link is still a scorable verdict.
    """
    normalized = raw_url if "://" in raw_url else f"http://{raw_url}"
    result = {
        "requested_url": normalized,
        "final_url": normalized,
        "redirect_chain": [],       # [(status, url)] per hop taken
        "cross_domain_redirect": False,
        "reachable": False,
        "status": None,
        "tls_valid": None,          # None = not attempted (e.g. plain http)
        "server": None,
        "content_type": None,
        "page_html": "",
        "page_text": "",
        "error": None,
    }

    try:
        # Shared client (see _get_client): the per-request streaming and
        # MAX_PAGE_BYTES cap below are unchanged, only the client's
        # lifetime is.
        client = _get_client()
        # Stream so a 2 GB download can't blow up memory; we stop
        # reading once we have MAX_PAGE_BYTES.
        async with client.stream("GET", normalized) as response:
            chunks: list[bytes] = []
            size = 0
            async for chunk in response.aiter_bytes():
                chunks.append(chunk)
                size += len(chunk)
                if size >= MAX_PAGE_BYTES:
                    break
            _capture(response, result, history=response.history or [], body=b"".join(chunks))
    except httpx.TooManyRedirects as exc:
        result["error"] = "Redirect loop or too many hops"
        result["redirect_chain"] = [
            (h.status_code, str(h.url)) for h in getattr(exc.request, "history", []) or []
        ]
        return result
    except Exception as exc:                   # noqa: BLE001 - DNS down, timeouts...
        msg = str(exc).lower()
        result["error"] = f"{exc.__class__.__name__}: {exc}"
        # httpx folds certificate failures into ConnectError, so sniff
        # the message instead of relying on exception type.
        if "certificate" in msg or "ssl" in msg or "tls" in msg:
            result["tls_valid"] = False
        return result

    ctype = result["content_type"] or ""
    if "html" in ctype or ctype.startswith("text/"):
        html = result["page_html"]
        result["page_text"] = extract_page_text(html)

    return result


def _capture(response: httpx.Response, result: dict, history: list, body: bytes) -> None:
    """Copy everything we need off the live response before the
    stream context closes."""
    result["reachable"] = True
    result["status"] = response.status_code
    result["final_url"] = str(response.url)
    result["server"] = response.headers.get("server")
    result["content_type"] = (response.headers.get("content-type") or "").split(";")[0] or None
    result["page_html"] = body[:MAX_PAGE_BYTES].decode("utf-8", errors="replace")

    if not history:
        result["tls_valid"] = urlsplit(result["final_url"]).scheme == "https"
        return

    result["redirect_chain"] = [(h.status_code, str(h.url)) for h in history]
    first_host = _host(str(history[0].url))
    last_host = _host(result["final_url"])
    result["tls_valid"] = urlsplit(result["final_url"]).scheme == "https"

    # A hop that changes the registrable domain is where scams hide:
    # bit.ly/x9k2 -> free-iphone-winner.tk
    from bot.detectors.url.offline.lexical import registered_domain
    if registered_domain(first_host) != registered_domain(last_host):
        result["cross_domain_redirect"] = True


