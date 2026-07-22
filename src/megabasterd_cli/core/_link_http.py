"""Shared HTTP plumbing and SSRF target validation for the link services.

Extracted from `link_services.py` so ELC, DLC and MegaCrypter share ONE
implementation of: the proxy-policy guard, bounded response reading, the
validate-every-redirect-hop POST loop, and the anti-SSRF target check.

The dependency runs one way only - `link_services` imports from here, never the
reverse, and this module imports nothing from the package's own modules - so
there is no import cycle. `link_services` re-exports these names, so their
public paths (`core.link_services.NAME`) are unchanged.
"""

from __future__ import annotations

import contextlib
import ipaddress
import json
from urllib.parse import urljoin, urlparse


def _require_selector(selector, caller: str):
    """Refuse to guess a proxy policy.

    Defaulting to `ProxySelector()` here made force_smart_proxy depend on every
    caller remembering to pass it: one omission (MegaDownloader's MegaCrypter
    hop) silently opened a direct socket. A missing policy is now a programming
    error, caught before any request is built.
    """
    if selector is None:
        raise ValueError(
            f"{caller}() requires an explicit selector: omitting it would silently "
            "disable force_smart_proxy for this request. Pass "
            "ProxySelector.from_config(cfg), or ProxySelector(force=False) to opt out."
        )
    return selector


class PayloadTooLargeError(ValueError):
    """An untrusted payload or response exceeded the size we are willing to buffer."""


# Real ELC / MegaCrypter replies are a few KB.
MAX_SERVICE_RESPONSE_BYTES = 2_000_000


STREAM_CHUNK_BYTES = 65536


def read_bounded_bytes(response, limit: int, what: str = "Service") -> bytes:
    """Return the body, refusing to buffer more than `limit` bytes.

    Must be used with `stream=True`. Touching `response.text` or
    `response.json()` first is useless as a defence - by then `requests` has
    already read the whole body AND transparently inflated any
    `Content-Encoding: gzip`, which makes every response its own decompression
    bomb. `iter_content` yields the DECODED bytes, so the cap applies to what
    actually lands in memory.

    The chunk size is capped at `limit + 1` so a small cap cannot buffer a full
    64 KiB block before noticing: overshoot is always at most one byte past the
    cap or one block, whichever is smaller.

    `core.api` and `core.upload_transport` wrap this to translate
    `PayloadTooLargeError` into the exception type their own callers catch.
    """
    total = 0
    parts: list[bytes] = []
    for block in response.iter_content(chunk_size=min(STREAM_CHUNK_BYTES, limit + 1)):
        total += len(block)
        if total > limit:
            close = getattr(response, "close", None)
            if close is not None:
                close()
            raise PayloadTooLargeError(f"{what} response is unexpectedly large")
        parts.append(block)
    return b"".join(parts)


def read_bounded_text(response, limit: int, what: str = "Service") -> str:
    """`read_bounded_bytes` decoded with the response's own declared encoding."""
    raw = read_bounded_bytes(response, limit, what)
    encoding = getattr(response, "encoding", None) or "utf-8"
    return raw.decode(encoding, errors="replace")


def _read_bounded_json(response, limit: int, what: str):
    text = read_bounded_text(response, limit, what)
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{what} returned non-JSON data: {text[:120]}") from exc


# Maximum number of HTTPS redirects any link-service POST will follow.
MAX_SERVICE_REDIRECTS = 5


def _post_validated(
    url: str,
    validate,  # Callable[[str], None] - raises on a destination we refuse
    selector,  # ProxySelector
    timeout: int,
    what: str,
    max_redirects: int = MAX_SERVICE_REDIRECTS,
    **post_kwargs,
):
    """POST without automatic redirects, re-validating every hop.

    The ONE hop loop shared by all three link services. `validate_safe_target`
    (or, for DLC, the stricter same-origin check) used to run once on the
    initial URL while `requests` was left to follow redirects itself, so an
    attacker-named host could answer 307 and have the credential body re-POSTed
    to loopback, link-local or RFC1918. Redirects are therefore followed by
    hand: `allow_redirects=False`, validate, then connect.

    Returns `(response, picked_proxy)`. The proxy is NOT credited here - only
    the caller knows whether the body proved usable - but a transport failure
    is blamed on it immediately, since that is unambiguous. The proxy is
    selected per hop, so a redirect can never downgrade to a direct request,
    and the reply is requested with `stream=True` so the caller can bound the
    body while reading it.
    """
    import requests

    current = url
    for _ in range(max_redirects + 1):
        # Validate before connecting: covers the initial URL and every redirect.
        validate(current)
        request_proxies, picked = selector.select()
        try:
            resp = requests.post(
                current,
                timeout=timeout,
                proxies=request_proxies,
                allow_redirects=False,
                stream=True,
                **post_kwargs,
            )
        except requests.RequestException:
            selector.report_failure(picked)
            raise
        status = getattr(resp, "status_code", 200)
        if status in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location") if hasattr(resp, "headers") else None
            with contextlib.suppress(Exception):
                resp.close()
            if not location:
                raise ValueError(f"{what} redirect is missing a Location header")
            # Resolve relative redirects against the current URL; the next loop
            # iteration validates the result before any request is sent.
            current = urljoin(current, location.strip())
            continue
        return resp, picked
    raise ValueError(f"{what} exceeded the maximum number of redirects")


def _close_quietly(response) -> None:
    """Return the connection to the pool even when the response was rejected."""
    with contextlib.suppress(Exception):
        response.close()


def _normalize_host(host: str) -> str:
    """Normalize a hostname for exact origin comparison.

    Lowercases, strips a single trailing dot, and converts to ASCII/IDNA so a
    Unicode lookalike or trailing-dot variant cannot be mistaken for an approved
    host. IP literals and un-encodable values are returned lowercased unchanged
    (they simply will not match the domain allowlist).
    """
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return ""
    try:
        # idna encoding maps Unicode lookalikes to punycode; pure-ASCII hosts
        # are returned unchanged.
        return host.encode("idna").decode("ascii")
    except (UnicodeError, ValueError):
        return host


class UnsafeTargetError(ValueError):
    """A link payload named a destination we refuse to contact."""


def validate_safe_target(url: str, *, what: str) -> None:
    """Reject any destination an untrusted link payload must not reach.

    ELC and MegaCrypter both take their service URL from the LINK ITSELF, so a
    crafted link could previously point them at `http://127.0.0.1`, a cloud
    metadata address, or an RFC1918 host - and the resolver would happily POST
    the user's ELC credentials or link password there.

    Enforces: HTTPS only; no embedded userinfo; a real host; and, for literal
    IPs, globally routable only (blocks loopback, private, link-local -
    including 169.254.169.254 - reserved, multicast and unspecified, for both
    IPv4 and IPv6).

    Hostname-based targets still resolve through DNS at connect time; this is
    the same limitation the DLC allowlist works around by pinning an approved
    origin, and is documented rather than silently assumed away.
    """
    parts = urlparse(url or "")
    if parts.scheme != "https":
        raise UnsafeTargetError(f"Refusing to contact a non-HTTPS {what} endpoint")
    if parts.username or parts.password:
        raise UnsafeTargetError(f"Refusing {what} endpoint with embedded credentials")
    raw_host = parts.hostname or ""
    if not _normalize_host(raw_host):
        raise UnsafeTargetError(f"Refusing {what} endpoint without a host")
    try:
        ip = ipaddress.ip_address(raw_host)
    except ValueError:
        ip = None
    if ip is not None and not ip.is_global:
        raise UnsafeTargetError(f"Refusing {what} endpoint at a non-global IP address")
