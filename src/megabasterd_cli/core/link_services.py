"""Resolution of third-party link services: ELC, DLC, and MegaCrypter.

Split out of `links.py`, which had grown to ~1000 lines mixing two unrelated
responsibilities. `links.py` is now pure, offline parsing (regexes, key
unwrapping, local container decryption); everything here talks to a REMOTE
service over HTTP and therefore selects a proxy, validates the response, and
enforces the force-proxy policy.

The dependency runs one way only - this module imports from `links`, never the
reverse - so there is no import cycle.
"""

from __future__ import annotations

import contextlib
import ipaddress
import json
import re
from typing import Any
from urllib.parse import urljoin, urlparse

from .links import (
    MAX_MEGACRYPTER_PBKDF2_ITERATIONS,
    ElcPayload,
    LinkType,
    MegaCrypterInfo,
    ParsedLink,
    _aes_cbc_nopadding_decrypt,
    _aes_cbc_pkcs7_decrypt,
    _std_b64_decode,
    _std_b64_encode,
    parse_link,
)


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


# A real ELC link carries a few KB of gzip. Both ends are bounded because the
# ratio between them is attacker-chosen: deflate reaches ~1029:1, so capping the
# input alone still allows a 1 MiB link to inflate to a gigabyte.
MAX_ELC_COMPRESSED_BYTES = 1 << 20  # 1 MiB taken straight from the pasted link
MAX_ELC_DECOMPRESSED_BYTES = 8 << 20  # 8 MiB after inflation
# Real ELC / MegaCrypter replies are a few KB.
MAX_SERVICE_RESPONSE_BYTES = 2_000_000


def _read_bounded(response, limit: int, what: str) -> str:
    """Return the body as text, refusing to buffer more than `limit` bytes.

    Must be used with `stream=True`. Touching `response.text` or
    `response.json()` first is useless as a defence - by then `requests` has
    already read the whole body AND transparently inflated any
    `Content-Encoding: gzip`, which makes every response its own decompression
    bomb. `iter_content` yields the DECODED bytes, so the cap applies to what
    actually lands in memory.
    """
    total = 0
    parts: list[bytes] = []
    for block in response.iter_content(chunk_size=65536):
        total += len(block)
        if total > limit:
            close = getattr(response, "close", None)
            if close is not None:
                close()
            raise PayloadTooLargeError(f"{what} response is unexpectedly large")
        parts.append(block)
    encoding = getattr(response, "encoding", None) or "utf-8"
    return b"".join(parts).decode(encoding, errors="replace")


def _read_bounded_json(response, limit: int, what: str):
    text = _read_bounded(response, limit, what)
    try:
        return json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"{what} returned non-JSON data: {text[:120]}") from exc


def _gunzip_bounded(payload: bytes) -> bytes:
    """Inflate a gzip member, giving up once the OUTPUT passes the cap.

    `gzip.decompress` decides how much memory to allocate from data the link
    supplies, so a 544 KB link expanded to 400 MiB before any credential was
    even looked up. `decompressobj().decompress(data, max_length)` stops at the
    limit instead and parks the rest in `unconsumed_tail`, which is how an
    over-large member is detected without ever materialising it.
    """
    import zlib

    if len(payload) > MAX_ELC_COMPRESSED_BYTES:
        raise PayloadTooLargeError("Compressed ELC payload is unexpectedly large")
    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
    try:
        out = decompressor.decompress(payload, MAX_ELC_DECOMPRESSED_BYTES)
    except zlib.error as exc:
        raise ValueError(f"Corrupt ELC payload: {exc}") from exc
    if decompressor.unconsumed_tail:
        raise PayloadTooLargeError("ELC payload expands beyond the allowed size")
    if not decompressor.eof:
        raise ValueError("Truncated ELC payload")
    return out


def decode_elc_payload(parsed: ParsedLink) -> ElcPayload:
    """Decode the local envelope of a `mega://elc?...` link.

    The envelope contains encrypted MEGA link fragments, the ELC service URL,
    and a token that must be sent to that service with the user's ELC account.
    """
    from .crypto import b64_url_decode

    if parsed.type != LinkType.ELC_CONTAINER or not parsed.elc_blob:
        raise ValueError("Not an ELC container link")

    raw = b64_url_decode(parsed.elc_blob)
    if len(raw) < 1:
        raise ValueError("ELC payload is empty")
    marker = raw[0]
    if marker not in (0x70, 0xB9):
        raise ValueError("Bad ELC marker")
    payload = raw[1:]
    if marker == 0x70:
        payload = _gunzip_bounded(payload)

    offset = 0

    def take(n: int) -> bytes:
        nonlocal offset
        if offset + n > len(payload):
            raise ValueError("Truncated ELC payload")
        part = payload[offset : offset + n]
        offset += n
        return part

    link_len = int.from_bytes(take(4), "little", signed=False)
    encrypted_links = take(link_len)
    url_len = int.from_bytes(take(2), "little", signed=False)
    service_url = take(url_len).decode("utf-8").strip()
    if "http" not in service_url:
        raise ValueError("Bad ELC service URL")
    token_len = int.from_bytes(take(2), "little", signed=False)
    data_token = take(token_len).decode("utf-8")
    return ElcPayload(encrypted_links, service_url, data_token)


def resolve_elc_links(
    parsed: ParsedLink,
    accounts: dict[str, dict[str, str]] | None = None,
    user: str | None = None,
    api_key: str | None = None,
    timeout: int = 30,
    selector=None,  # ProxySelector | None
) -> list[str]:
    """Resolve an ELC container to normal MEGA URLs.

    `accounts` is keyed by ELC service host and each value may contain
    `user` plus either `api_key` or `apikey`. Explicit `user`/`api_key`
    arguments override configured accounts.
    """
    import requests

    selector = _require_selector(selector, "resolve_elc_links")

    payload = decode_elc_payload(parsed)
    # The service URL comes from the untrusted link payload: validate it before
    # any credential is looked up, let alone sent.
    validate_safe_target(payload.service_url, what="ELC service")
    host = urlparse(payload.service_url).netloc.lower()
    account = (accounts or {}).get(host) or (accounts or {}).get(host.split(":")[0]) or {}
    user = user or account.get("user")
    api_key = api_key or account.get("api_key") or account.get("apikey")
    if not user or not api_key:
        raise ValueError(f"No ELC credentials configured for host {host!r}")

    request_proxies, picked = selector.select()

    response = requests.post(
        payload.service_url,
        data={
            "OPERATION_TYPE": "D",
            "DATA": payload.data_token,
            "USER": user,
            "APIKEY": api_key,
        },
        headers={"User-Agent": "MegaBasterd-CLI/1.0"},
        timeout=timeout,
        proxies=request_proxies,
        stream=True,
    )
    selector.report_success(picked)
    response.raise_for_status()
    body = _read_bounded_json(response, MAX_SERVICE_RESPONSE_BYTES, "ELC server")

    dec_pass = body.get("d") if isinstance(body, dict) else None
    if not dec_pass:
        raise ValueError(f"ELC server did not return a decrypt key: {body}")

    key_material = _std_b64_decode(str(dec_pass))
    if len(key_material) < 24:
        raise ValueError("ELC decrypt key is too short")
    key = key_material[:16]
    iv = bytearray(16)
    iv[:8] = key_material[16:24]
    decrypted = _aes_cbc_nopadding_decrypt(payload.encrypted_links, key, bytes(iv))
    text = decrypted.rstrip(b"\x00").decode("utf-8", errors="replace").strip()

    links: list[str] = []
    for part in (p.strip() for p in text.split("|")):
        if not part:
            continue
        low = part.lower()
        if low.startswith(("http://", "https://", "mega://", "mc://")):
            links.append(part)
        else:
            links.append("https://mega.nz/" + part.lstrip("/"))
    return links


DLC_SERVICE_URL = "https://service.jdownloader.org/dlcrypt/service.php"
DLC_REV = "34065"
DLC_MASTER_KEY = bytes.fromhex("447E787351E60E2C6A96B3964BE0C9BD")
# Cap the DLC service response to avoid unbounded memory use on a hostile or
# malfunctioning endpoint. Real responses are a few KB.
MAX_DLC_RESPONSE_BYTES = 2_000_000
# Maximum number of HTTPS redirects the DLC resolver will follow.
MAX_DLC_REDIRECTS = 5
# Exact approved DLC service origins as (normalized host, port). Only the
# official JDownloader DLC service is allowed; any other initial endpoint is
# refused to prevent SSRF, even if it uses HTTPS and resolves publicly.
_APPROVED_DLC_ORIGINS = frozenset({("service.jdownloader.org", 443)})


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


def _dlc_origin(url: str) -> tuple[str, int]:
    """Return the (normalized host, effective port) of a DLC URL (https => 443)."""
    parts = urlparse(url)
    return _normalize_host(parts.hostname or ""), (parts.port or 443)


def _validate_dlc_target(url: str, approved_host: str, approved_port: int) -> None:
    """Reject any DLC URL that is not same-origin HTTPS with the approved host.

    Enforces: https only; no embedded credentials; a real host; literal IPs must
    be globally routable (blocks loopback/private/link-local/reserved/multicast/
    unspecified); and the normalized host+port must match the approved origin.
    This prevents SSRF via cross-host redirects even when the redirect uses
    HTTPS, and resists trailing-dot / IDN-lookalike bypasses.
    """
    parts = urlparse(url)
    if parts.scheme != "https":
        raise ValueError("Refusing to contact a non-HTTPS DLC URL")
    if parts.username or parts.password:
        raise ValueError("Refusing DLC URL with embedded credentials")
    raw_host = parts.hostname or ""
    host = _normalize_host(raw_host)
    if not host:
        raise ValueError("Refusing DLC URL without a host")
    try:
        ip = ipaddress.ip_address(raw_host)
    except ValueError:
        ip = None
    if ip is not None and not ip.is_global:
        raise ValueError("Refusing DLC URL to a non-global IP address")
    if host != approved_host or (parts.port or 443) != approved_port:
        raise ValueError("Refusing cross-origin DLC redirect")


def _dlc_post(
    service_url: str,
    body: str,
    headers: dict[str, str],
    timeout: int,
    selector=None,  # ProxySelector | None
    max_redirects: int = MAX_DLC_REDIRECTS,
):
    """POST to the DLC service, following only same-origin HTTPS redirects.

    Automatic redirect following is disabled. Before every request (including
    each redirect hop) the target is validated to be the same HTTPS origin as
    the approved service URL (same host and port, no credentials, globally
    routable). An unsafe destination is rejected before any request is issued to
    it, so the DLC payload is never sent to a cross-host or downgraded target.
    TLS verification, timeout, proxies, and the response-size limit are
    preserved on every hop.
    """
    import requests

    approved_host, approved_port = _dlc_origin(service_url)
    # The initial endpoint must be an explicitly approved origin (anti-SSRF).
    # Run per-target checks first so scheme/credential/IP problems get a precise
    # error, then enforce the exact-origin allowlist.
    selector = _require_selector(selector, "_dlc_post")
    _validate_dlc_target(service_url, approved_host, approved_port)
    if (approved_host, approved_port) not in _APPROVED_DLC_ORIGINS:
        raise ValueError("Refusing DLC request to an unapproved service endpoint")
    current = service_url
    for _ in range(max_redirects + 1):
        # Validate before connecting: covers the initial URL and every redirect.
        _validate_dlc_target(current, approved_host, approved_port)
        # Select per hop, so a redirect can never downgrade to a direct request.
        request_proxies, _picked = selector.select()
        resp = requests.post(
            current,
            data=body,
            headers=headers,
            timeout=timeout,
            proxies=request_proxies,
            allow_redirects=False,
            stream=True,
        )
        status = getattr(resp, "status_code", 200)
        if status in (301, 302, 303, 307, 308):
            location = resp.headers.get("Location") if hasattr(resp, "headers") else None
            with contextlib.suppress(Exception):
                resp.close()
            if not location:
                raise ValueError("DLC redirect is missing a Location header")
            # Resolve relative redirects against the current HTTPS URL; the next
            # loop iteration validates it before any request is sent.
            current = urljoin(current, location.strip())
            continue
        return resp
    raise ValueError("DLC service exceeded the maximum number of redirects")


def decrypt_dlc_container(
    data: str | bytes,
    timeout: int = 30,
    service_url: str = DLC_SERVICE_URL,
    selector=None,  # ProxySelector | None
) -> list[str]:
    """Decrypt a JDownloader DLC container and return the contained URLs."""
    from Crypto.Cipher import AES

    selector = _require_selector(selector, "decrypt_dlc_container")

    text = data.decode("utf-8", errors="ignore") if isinstance(data, bytes) else data
    text = "".join(text.split())
    if len(text) <= 88:
        raise ValueError("DLC data is too short")

    dlc_id = text[-88:]
    enc_dlc_data = text[:-88].strip()
    response = _dlc_post(
        service_url,
        f"destType=jdtc6&b=JD&srcType=dlc&data={dlc_id}&v={DLC_REV}",
        {
            "User-Agent": "Mozilla/5.0 (X11; U; Linux amd64; rv:44.0) Gecko/20100101 Firefox/44.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "de,en-gb;q=0.7, en;q=0.3",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Charset": "ISO-8859-1,utf-8;q=0.7,*;q=0.7",
            "Cache-Control": "no-cache",
            "rev": DLC_REV,
        },
        timeout,
        selector,
    )
    response.raise_for_status()
    # Treat the third-party response as untrusted: bound it WHILE reading. The
    # previous `len(response.text) > MAX` check was inert - `response.text` had
    # already buffered and gzip-inflated the entire body before it ran.
    text = _read_bounded(response, MAX_DLC_RESPONSE_BYTES, "DLC service")
    m = re.search(r"<\s*rc\s*>(.+?)<\s*/\s*rc\s*>", text, re.IGNORECASE | re.DOTALL)
    if not m:
        raise ValueError("DLC service did not return a key")

    encrypted_key = _std_b64_decode(m.group(1))
    decrypted_key_text = AES.new(DLC_MASTER_KEY, AES.MODE_ECB).decrypt(encrypted_key)
    decrypted_key = decrypted_key_text.rstrip(b"\x00").strip().decode("utf-8")
    key = _std_b64_decode(decrypted_key)

    decrypted_data = _aes_cbc_nopadding_decrypt(_std_b64_decode(enc_dlc_data), key, key)
    xml_b64 = decrypted_data.rstrip(b"\x00").strip()
    xml = _std_b64_decode(xml_b64.decode("utf-8")).decode("utf-8", errors="replace")

    links: list[str] = []
    for file_block in re.findall(r"<\s*file\s*>(.+?)<\s*/\s*file\s*>", xml, re.I | re.S):
        for encoded_url in re.findall(r"<\s*url\s*>(.+?)<\s*/\s*url\s*>", file_block, re.I | re.S):
            links.append(_std_b64_decode(encoded_url).decode("utf-8", errors="replace"))
    return links


def _megacrypter_link(parsed: ParsedLink) -> str:
    if parsed.type != LinkType.MEGACRYPTER or not parsed.crypter_server or not parsed.crypter_token:
        raise ValueError("Not a MegaCrypter link")
    return f"mc://{parsed.crypter_server}/{parsed.crypter_token}"


def _megacrypter_api_url(parsed: ParsedLink) -> str:
    return f"https://{parsed.crypter_server}/api"


def _post_megacrypter(
    parsed: ParsedLink,
    # `Any`, not `object`: these are heterogeneous JSON values on their
    # way to `requests.post(json=...)`, and `object` is not JSON-compatible.
    payload: dict[str, Any],
    timeout: int,
    selector=None,  # ProxySelector | None
) -> dict:
    import requests

    selector = _require_selector(selector, "_post_megacrypter")
    # The MegaCrypter host comes from the link itself, so a crafted mc:// link
    # must not aim a password-bearing POST at loopback or a metadata service.
    api_url = _megacrypter_api_url(parsed)
    validate_safe_target(api_url, what="MegaCrypter server")

    request_proxies, picked = selector.select()

    response = requests.post(
        api_url,
        json=payload,
        timeout=timeout,
        proxies=request_proxies,
        stream=True,
    )
    selector.report_success(picked)
    response.raise_for_status()
    body = _read_bounded_json(response, MAX_SERVICE_RESPONSE_BYTES, "MegaCrypter server")
    if not isinstance(body, dict):
        raise ValueError(f"Unexpected MegaCrypter response: {body!r}")
    err = body.get("error") or body.get("err")
    if err not in (None, "", False, 0):
        raise ValueError(f"MegaCrypter error: {err}")
    return body


def _inline_url_from_body(body: dict) -> str | None:
    inline = (
        body.get("url")
        or body.get("link")
        or body.get("mega_url")
        or body.get("megaurl")
        or body.get("mega_link")
    )
    return str(inline) if inline else None


def _decrypt_megacrypter_field(value: str | None, key: bytes, iv: bytes) -> bytes | None:
    if not value:
        return None
    return _aes_cbc_pkcs7_decrypt(_std_b64_decode(value), key, iv)


def _decrypt_megacrypter_password_info(body: dict, password: str | None) -> tuple[dict, str | None]:
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA256
    from Crypto.Protocol.KDF import PBKDF2
    from Crypto.Util.Padding import unpad

    pass_value = body.get("pass")
    if pass_value is None or pass_value == "":
        return body, None
    if not isinstance(pass_value, str):
        raise ValueError("Malformed MegaCrypter password descriptor")
    if not password:
        raise ValueError("MegaCrypter link requires a password")

    parts = pass_value.split("#")
    if len(parts) != 4:
        raise ValueError("Malformed MegaCrypter password descriptor")
    iteration_power = int(parts[0])
    if iteration_power < 0:
        raise ValueError("Malformed MegaCrypter password descriptor")
    iterations = 2**iteration_power
    if iterations > MAX_MEGACRYPTER_PBKDF2_ITERATIONS:
        raise ValueError("MegaCrypter password descriptor requests too many iterations")
    key_check = _std_b64_decode(parts[1])
    salt = _std_b64_decode(parts[2])
    iv = _std_b64_decode(parts[3])
    info_key = PBKDF2(
        password.encode("utf-8"),  # type: ignore[arg-type]  # bytes ok
        salt,
        dkLen=32,
        count=iterations,
        hmac_hash_module=SHA256,
    )
    try:
        check = unpad(AES.new(info_key, AES.MODE_CBC, iv).decrypt(key_check), 16)
    except Exception as exc:  # noqa: BLE001
        raise ValueError("Wrong MegaCrypter password") from exc
    if check != info_key:
        raise ValueError("Wrong MegaCrypter password")

    decrypted = dict(body)
    key_bytes = _decrypt_megacrypter_field(str(body.get("key") or ""), info_key, iv)
    if key_bytes is not None:
        from .crypto import b64_url_encode

        decrypted["key"] = b64_url_encode(key_bytes)
    name_bytes = _decrypt_megacrypter_field(str(body.get("name") or ""), info_key, iv)
    if name_bytes is not None:
        decrypted["name"] = name_bytes.decode("utf-8", errors="replace")
    path_value = body.get("path")
    if isinstance(path_value, str) and path_value:
        path_bytes = _decrypt_megacrypter_field(path_value, info_key, iv)
        if path_bytes is not None:
            decrypted["path"] = path_bytes.decode("utf-8", errors="replace")
    return decrypted, _std_b64_encode(info_key)


def get_megacrypter_info(
    parsed: ParsedLink,
    timeout: int = 30,
    password: str | None = None,
    reverse: str | None = None,
    selector=None,  # ProxySelector | None
) -> MegaCrypterInfo:
    """Fetch and decrypt MegaCrypter metadata."""
    selector = _require_selector(selector, "get_megacrypter_info")
    link = _megacrypter_link(parsed)
    payload: dict[str, object] = {"m": "info", "link": link}
    if reverse:
        payload["reverse"] = reverse
    body = _post_megacrypter(parsed, payload, timeout=timeout, selector=selector)

    inline_url = _inline_url_from_body(body)
    body, pass_hash = _decrypt_megacrypter_password_info(body, password)

    size_value = body.get("size")
    try:
        size = int(str(size_value)) if size_value not in (None, False, "") else None
    except (TypeError, ValueError):
        size = None

    expire = body.get("expire")
    noexpire_token = None
    if isinstance(expire, str) and expire:
        parts = expire.split("#")
        noexpire_token = parts[1] if len(parts) > 1 else expire

    name = body.get("name")
    path = body.get("path")
    if isinstance(path, str) and path and not isinstance(path, bool) and isinstance(name, str):
        name = path + name

    return MegaCrypterInfo(
        name=str(name) if isinstance(name, str) else None,
        size=size,
        key=str(body.get("key")) if body.get("key") else None,
        pass_hash=pass_hash,
        noexpire_token=noexpire_token,
        inline_url=inline_url,
        raw=body,
    )


def get_megacrypter_download_url(
    parsed: ParsedLink,
    info: MegaCrypterInfo | None = None,
    timeout: int = 30,
    password: str | None = None,
    sid: str | None = None,
    reverse: str | None = None,
    selector=None,  # ProxySelector | None
) -> str:
    """Ask MegaCrypter for the temporary CDN URL, decrypting it if needed."""
    selector = _require_selector(selector, "get_megacrypter_download_url")
    if info is None:
        info = get_megacrypter_info(
            parsed, timeout=timeout, password=password, reverse=reverse, selector=selector
        )
    payload: dict[str, object] = {"m": "dl", "link": _megacrypter_link(parsed)}
    if info.noexpire_token:
        payload["noexpire"] = info.noexpire_token
    if sid:
        payload["sid"] = sid
    if reverse:
        payload["reverse"] = reverse

    body = _post_megacrypter(parsed, payload, timeout=timeout, selector=selector)
    dl_url = body.get("url")
    if not dl_url:
        raise ValueError(f"MegaCrypter did not return a download URL: {body}")
    dl_url = str(dl_url)
    if info.pass_hash:
        pass_iv = body.get("pass")
        if not pass_iv:
            raise ValueError("MegaCrypter encrypted URL response is missing pass IV")
        decrypted = _aes_cbc_pkcs7_decrypt(
            _std_b64_decode(dl_url),
            _std_b64_decode(info.pass_hash),
            _std_b64_decode(str(pass_iv)),
        )
        dl_url = decrypted.decode("utf-8", errors="replace")
    return dl_url


def resolve_megacrypter_link(
    parsed: ParsedLink,
    timeout: int = 30,
    password: str | None = None,
    selector=None,  # ProxySelector | None
) -> ParsedLink:
    """Resolve a MegaCrypter link when the server exposes an underlying MEGA URL."""
    from ..proxy.selector import ProxyRequiredError

    selector = _require_selector(selector, "resolve_megacrypter_link")
    if parsed.type != LinkType.MEGACRYPTER:
        raise ValueError("Not a MegaCrypter link")

    last_body: dict | str | None = None
    for method in ("info", "openlink", "dl"):
        payload: dict[str, object] = {"m": method, "link": _megacrypter_link(parsed)}
        if password:
            payload["password"] = password
            payload["pass"] = password
        try:
            body = _post_megacrypter(parsed, payload, timeout=timeout, selector=selector)
        except (ProxyRequiredError, UnsafeTargetError):
            # Policy refusals, not server errors: swallowing them here would let
            # the caller fall back to another (possibly unproxied, or unsafe)
            # resolution path, and would report "server exposed no link" for
            # what is really a refusal to contact that host at all.
            raise
        except Exception as exc:  # noqa: BLE001
            last_body = f"{type(exc).__name__}: {exc}"
            continue
        last_body = body

        inline = _inline_url_from_body(body)
        if inline:
            try:
                return parse_link(inline)
            except ValueError:
                pass

        try:
            info_body, _ = _decrypt_megacrypter_password_info(body, password)
        except ValueError:
            raise
        file_id = info_body.get("file_id") or info_body.get("id")
        file_key = info_body.get("file_key") or info_body.get("key")
        if file_id and file_key:
            try:
                return parse_link(f"https://mega.nz/file/{file_id}#{file_key}")
            except ValueError:
                pass

    raise ValueError(
        "MegaCrypter server did not expose an underlying MEGA link " f"(last response: {last_body})"
    )
