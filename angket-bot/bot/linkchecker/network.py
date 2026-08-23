"""
bot/linkchecker/network.py
==============================
Asynchronous network verification for links â€” the "Async I/O" and
"Network & HTTPS / Redirect Chains / Header Verification / DOM
Parsing" rows of the research notes.

Uses httpx, which is already a hard dependency of
python-telegram-bot, so this adds zero new packages.

What one `trace()` gives the scorer:
  * full redirect chain (who redirects where, across which domains)
  * final landing URL â€” shorteners get re-scored against THIS, not
    the t.co/bit.ly front
  * TLS handshake validity (self-signed / expired cert => flag)
  * status code + selected response headers
  * a bounded slice of page HTML for downstream vector/LSH analysis

Everything is timeout-bounded so a dead link can't stall the bot's
event loop; total worst-case latency is ~2 x TIMEOUT seconds.
"""

from __future__ import annotations

import asyncio
import re
from urllib.parse import urlsplit

import httpx

TIMEOUT = httpx.Timeout(10.0, connect=5.0)
MAX_REDIRECTS = 10
MAX_PAGE_BYTES = 200_000          # enough for title + visible text of most pages
USER_AGENT = ("Mozilla/5.0 (compatible; AngketBotLinkChecker/1.0; "
              "+https://telegram.me) AppleWebKit/537.36")

_TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)
_SCRIPT_STYLE_RE = re.compile(r"<(script|style)\b.*?</\1>", re.IGNORECASE | re.DOTALL)
_TAG_RE = re.compile(r"<[^>]+>")


def _host(url: str) -> str:
    return (urlsplit(url).hostname or "").lower()


def extract_page_text(html: str) -> str:
    """Title + tag-stripped body text, for embedding and MinHash."""
    title_match = _TITLE_RE.search(html)
    title = title_match.group(1).strip() if title_match else ""
    body = _TAG_RE.sub(" ", _SCRIPT_STYLE_RE.sub(" ", html))
    return f"{title}\n{re.sub(r'\s+', ' ', body).strip()}"


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
        async with httpx.AsyncClient(
            follow_redirects=True,
            timeout=TIMEOUT,
            headers={"User-Agent": USER_AGENT},
            verify=True,                       # invalid certs raise -> flagged below
            max_redirects=MAX_REDIRECTS,
        ) as client:
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
    from bot.linkchecker.lexical import registered_domain
    if registered_domain(first_host) != registered_domain(last_host):
        result["cross_domain_redirect"] = True


async def trace_many(urls: list[str]) -> list[dict]:
    """Trace several URLs concurrently â€” the distributed-crawling spirit
    of the research notes on a single-process scale."""
    return list(await asyncio.gather(*(trace(u) for u in urls)))

