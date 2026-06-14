"""Parse MEGA share links.

Supported URL families:

Modern (since 2020):
    https://mega.nz/file/<id>#<key>
    https://mega.nz/folder/<id>#<key>
    https://mega.nz/folder/<id>#<key>/file/<id>
    https://mega.nz/folder/<id>#<key>/folder/<sub>

Legacy (still common in older posts):
    https://mega.nz/#!<id>!<key>
    https://mega.nz/#F!<id>!<key>
    https://mega.nz/#F!<id>@<sub>!<key>           (folder inside a folder share)
    https://mega.nz/#F*<file>!<folder>!<key>      (file inside a folder share, compact)

Password-protected:
    https://mega.nz/#P!<encoded-blob>

Encrypted-link containers (third-party):
    mega://enc?<b64>         (file, AES-256-CBC with static key #1)
    mega://enc2?<b64>        (file, AES-256-CBC with static key #2)
    mega://fenc?<b64>        (folder, key #1)
    mega://fenc2?<b64>       (folder, key #2)
    mega://elc?<b64>         (ELC container; needs host credentials)

MegaCrypter (third-party host):
    mc://<server>/<token>
    https://<server>/!<token>
"""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse


class LinkType(str, Enum):
    FILE = "file"
    FOLDER = "folder"
    FILE_IN_FOLDER = "file_in_folder"
    FOLDER_IN_FOLDER = "folder_in_folder"
    PASSWORD_PROTECTED = "password_protected"
    MEGACRYPTER = "megacrypter"
    ENCRYPTED_CONTAINER = "encrypted_container"  # mega://enc/fenc
    ELC_CONTAINER = "elc_container"  # mega://elc


@dataclass
class ParsedLink:
    """A parsed MEGA share link."""

    type: LinkType
    public_id: str
    key: str | None = None
    subpath: str | None = None  # File/folder handle inside a folder share
    encrypted_blob: str | None = None  # For password-protected links
    crypter_server: str | None = None  # For MegaCrypter links
    crypter_token: str | None = None
    container_variant: str | None = None  # enc, enc2, fenc, fenc2
    container_blob: str | None = None  # base64 ciphertext for mega://enc
    elc_blob: str | None = None  # base64 payload for mega://elc

    @property
    def is_folder(self) -> bool:
        return self.type in (LinkType.FOLDER, LinkType.FOLDER_IN_FOLDER)

    @property
    def needs_password(self) -> bool:
        return self.type == LinkType.PASSWORD_PROTECTED


@dataclass
class ElcPayload:
    """Decoded ELC envelope before the server returns the decrypt key."""

    encrypted_links: bytes
    service_url: str
    data_token: str


@dataclass
class MegaCrypterInfo:
    """Metadata returned by a MegaCrypter server."""

    name: str | None = None
    size: int | None = None
    key: str | None = None
    pass_hash: str | None = None
    noexpire_token: str | None = None
    inline_url: str | None = None
    raw: dict = field(default_factory=dict)


MAX_MEGACRYPTER_PBKDF2_ITERATIONS = 200_000


# Modern format patterns
_RE_MODERN_FILE = re.compile(
    r"^https?://mega(?:\.co)?\.nz/file/([^#?/]+)(?:#([^!?/]+))?(?:!(.+))?$"
)
_RE_MODERN_FOLDER = re.compile(
    r"^https?://mega(?:\.co)?\.nz/folder/([^#?/]+)(?:#([^!?/]+))?"
    r"(?:/(?P<kind>file|folder)/(?P<inner>[^#?/]+))?$"
)
_RE_PASSWORD = re.compile(r"^https?://mega(?:\.co)?\.nz/#P!(.+)$")

# Legacy format patterns
_RE_LEGACY_FILE = re.compile(r"^https?://mega(?:\.co)?\.nz/#!([^!]+)!(.+)$")
# Folder share, optionally with an explicit @subfolder (#F!<id>@<sub>!<key>) or
# an ambiguous trailer (#F!<id>!<key>!<handle>). Legacy MEGA links used the
# trailer for both files and folders; parse it as FILE_IN_FOLDER and let callers
# that have the folder listing resolve the handle's real node type at runtime.
_RE_LEGACY_FOLDER = re.compile(
    r"^https?://mega(?:\.co)?\.nz/#F!(?P<id>[^!@]+)(?:@(?P<sub>[^!]+))?!"
    r"(?P<key>[^!]+)(?:!(?P<trailer>.+))?$"
)
# Compact file-in-folder form: #F*<file_id>!<folder_id>!<key>
_RE_LEGACY_FOLDER_FILE_COMPACT = re.compile(
    r"^https?://mega(?:\.co)?\.nz/#F\*(?P<file>[^!]+)!(?P<folder>[^!]+)!(?P<key>.+)$"
)
# "Node" link form used by alternate MEGA clients: #N!<file>!<folder>!<key>.
# Semantically identical to #F*<file>!<folder>!<key>.
_RE_LEGACY_NODE = re.compile(
    r"^https?://mega(?:\.co)?\.nz/#N!(?P<file>[^!]+)!(?P<folder>[^!]+)!(?P<key>.+)$"
)

# MegaCrypter custom scheme: mc://server/token
_RE_MC_SCHEME = re.compile(r"^mc://([^/]+)/(.+)$")
_RE_MC_HTTP = re.compile(r"^https?://([^/]+)/!([A-Za-z0-9_\-]+)$")

# Encrypted-link container: mega://(f?)enc[2]?...
_RE_ENC_CONTAINER = re.compile(
    r"^mega://(?P<variant>f?enc[0-9]?)\?(?P<blob>[A-Za-z0-9+/=_\-]+)\s*$",
    re.IGNORECASE,
)
_RE_ELC_CONTAINER = re.compile(
    r"^mega://elc\?(?P<blob>[A-Za-z0-9+/=,_\-]+)\s*$",
    re.IGNORECASE,
)


def parse_link(url: str) -> ParsedLink:
    """Parse a MEGA share link into its components.

    Raises ValueError if the URL is not a recognizable MEGA link.
    """
    url = url.strip()
    try:
        parsed_url = urlparse(url)
        host = parsed_url.netloc.lower()
        if host.endswith("mega.nz") or host.endswith("mega.co.nz"):
            url = url.rstrip("/")
    except Exception:
        pass

    # Password-protected
    m = _RE_PASSWORD.match(url)
    if m:
        return ParsedLink(
            type=LinkType.PASSWORD_PROTECTED,
            public_id="",
            encrypted_blob=m.group(1),
        )

    # Encrypted link container: mega://enc?..., mega://fenc?... (and the
    # numbered variants 2/3 used historically).
    m = _RE_ENC_CONTAINER.match(url)
    if m:
        return ParsedLink(
            type=LinkType.ENCRYPTED_CONTAINER,
            public_id="",
            container_variant=m.group("variant").lower(),
            container_blob=m.group("blob"),
        )

    # ELC encrypted link container. Unlike mega://enc, this can contain more
    # than one link and requires credentials for the ELC host embedded inside
    # the payload, so resolution is a separate network step.
    m = _RE_ELC_CONTAINER.match(url)
    if m:
        return ParsedLink(
            type=LinkType.ELC_CONTAINER,
            public_id="",
            elc_blob=m.group("blob"),
        )

    # MegaCrypter native scheme
    m = _RE_MC_SCHEME.match(url)
    if m:
        return ParsedLink(
            type=LinkType.MEGACRYPTER,
            public_id="",
            crypter_server=m.group(1),
            crypter_token=m.group(2),
        )

    # Modern folder (may include a /file/<id> or /folder/<sub> trailer)
    m = _RE_MODERN_FOLDER.match(url)
    if m:
        folder_id = m.group(1)
        key = m.group(2)
        kind = m.group("kind")
        inner = m.group("inner")
        if kind == "file" and inner:
            return ParsedLink(
                type=LinkType.FILE_IN_FOLDER,
                public_id=folder_id,
                key=key,
                subpath=inner,
            )
        if kind == "folder" and inner:
            return ParsedLink(
                type=LinkType.FOLDER_IN_FOLDER,
                public_id=folder_id,
                key=key,
                subpath=inner,
            )
        return ParsedLink(type=LinkType.FOLDER, public_id=folder_id, key=key)

    # Modern file
    m = _RE_MODERN_FILE.match(url)
    if m:
        return ParsedLink(
            type=LinkType.FILE,
            public_id=m.group(1),
            key=m.group(2),
            subpath=m.group(3),
        )

    # Legacy compact file-in-folder: #F*<file>!<folder>!<key>
    m = _RE_LEGACY_FOLDER_FILE_COMPACT.match(url)
    if m:
        return ParsedLink(
            type=LinkType.FILE_IN_FOLDER,
            public_id=m.group("folder"),
            key=m.group("key"),
            subpath=m.group("file"),
        )

    # Alternate "node" form: #N!<file>!<folder>!<key>
    m = _RE_LEGACY_NODE.match(url)
    if m:
        return ParsedLink(
            type=LinkType.FILE_IN_FOLDER,
            public_id=m.group("folder"),
            key=m.group("key"),
            subpath=m.group("file"),
        )

    # Legacy folder (with optional @subfolder and trailing file handle)
    m = _RE_LEGACY_FOLDER.match(url)
    if m:
        folder_id = m.group("id")
        sub = m.group("sub")
        key = m.group("key")
        trailer = m.group("trailer")
        if trailer:
            # `#F!<id>!<key>!<file_handle>` → file inside a folder share
            return ParsedLink(
                type=LinkType.FILE_IN_FOLDER,
                public_id=folder_id,
                key=key,
                subpath=trailer,
            )
        if sub:
            return ParsedLink(
                type=LinkType.FOLDER_IN_FOLDER,
                public_id=folder_id,
                key=key,
                subpath=sub,
            )
        return ParsedLink(type=LinkType.FOLDER, public_id=folder_id, key=key)

    # Legacy file
    m = _RE_LEGACY_FILE.match(url)
    if m:
        return ParsedLink(
            type=LinkType.FILE,
            public_id=m.group(1),
            key=m.group(2),
        )

    # Generic MegaCrypter-over-HTTPS fallback (not mega.nz)
    m = _RE_MC_HTTP.match(url)
    if m and "mega.nz" not in url and "mega.co.nz" not in url:
        return ParsedLink(
            type=LinkType.MEGACRYPTER,
            public_id="",
            crypter_server=m.group(1),
            crypter_token=m.group(2),
        )

    raise ValueError(f"Not a recognizable MEGA link: {url!r}")


def is_mega_url(url: str) -> bool:
    """Quick check whether a URL looks like a MEGA link of any supported flavour."""
    try:
        parsed = urlparse(url)
    except Exception:
        return False
    host = parsed.netloc.lower()
    if host.endswith("mega.nz") or host.endswith("mega.co.nz"):
        return True
    low = url.lower()
    return (
        low.startswith("mc://")
        or low.startswith("mega://enc")
        or low.startswith("mega://fenc")
        or low.startswith("mega://elc")
    )


def normalize_link(url: str) -> str:
    """Return the link in modern format if possible."""
    p = parse_link(url)
    if p.type == LinkType.FILE:
        base = f"https://mega.nz/file/{p.public_id}"
        return f"{base}#{p.key}" if p.key else base
    if p.type == LinkType.FOLDER:
        base = f"https://mega.nz/folder/{p.public_id}"
        return f"{base}#{p.key}" if p.key else base
    if p.type == LinkType.FILE_IN_FOLDER:
        return f"https://mega.nz/folder/{p.public_id}#{p.key}/file/{p.subpath}"
    if p.type == LinkType.FOLDER_IN_FOLDER:
        return f"https://mega.nz/folder/{p.public_id}#{p.key}/folder/{p.subpath}"
    return url


def resolve_password_link(parsed: ParsedLink, password: str) -> ParsedLink:
    """Convert a password-protected ParsedLink into a normal file/folder link."""
    from .crypto import b64_url_encode, decrypt_password_link

    if parsed.type != LinkType.PASSWORD_PROTECTED or not parsed.encrypted_blob:
        raise ValueError("Not a password-protected link")
    node_type, public_handle, raw_key = decrypt_password_link(parsed.encrypted_blob, password)
    public_id = b64_url_encode(public_handle)
    key_str = b64_url_encode(raw_key)
    return ParsedLink(
        type=LinkType.FILE if node_type == 0 else LinkType.FOLDER,
        public_id=public_id,
        key=key_str,
    )


# Static keys / IV used by the mega://enc / mega://fenc family. These are the
# same constants the original MegaBasterd Java client uses (see
# CryptTools.decryptMegaDownloaderLink). The ciphertext is base64-encoded
# AES-256-CBC with the indicated key + a fixed IV, no padding.
_ENC_KEYS = {
    "1": bytes.fromhex("6B316F36416C2D316B7A3F217A30357958585858585858585858585858585858"),
    "2": bytes.fromhex("ED1F4C200B35139806B260563B3D3876F011B4750F3A1A4A5EFD0BBE67554B44"),
}
_ENC_IV = bytes.fromhex("79F10A01844A0B27FF5B2D4E0ED3163E")


def resolve_encrypted_container_link(parsed: ParsedLink) -> ParsedLink:
    """Decrypt a `mega://enc?...` / `mega://fenc?...` URL into a normal MEGA link.

    Tries both static keys (the variant number isn't always present) and
    returns the first decoded result that parses as a real MEGA link.
    """
    import base64

    from Crypto.Cipher import AES

    if parsed.type != LinkType.ENCRYPTED_CONTAINER or not parsed.container_blob:
        raise ValueError("Not an encrypted container link")

    raw = parsed.container_blob
    raw = raw.replace("-", "+").replace("_", "/").replace(",", "")
    raw += "=" * ((4 - len(raw) % 4) % 4)
    try:
        ct = base64.b64decode(raw)
    except Exception as exc:
        raise ValueError(f"mega://{parsed.container_variant} blob is not valid base64") from exc

    # AES-CBC NoPadding requires the ciphertext to be a multiple of 16 bytes.
    if len(ct) % 16 != 0:
        ct = ct[: len(ct) - (len(ct) % 16)]
    if not ct:
        raise ValueError("mega://enc blob is empty after padding trim")

    variant = parsed.container_variant or ""
    # Choose initial key preference based on the trailing digit (1 or 2).
    order = ["2", "1"] if variant.endswith("2") else ["1", "2"]

    last_error: Exception | None = None
    for key_id in order:
        cipher = AES.new(_ENC_KEYS[key_id], AES.MODE_CBC, _ENC_IV)
        try:
            plain = cipher.decrypt(ct)
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            continue
        # The plaintext is a UTF-8 MEGA URL with trailing null bytes (NoPadding).
        text = plain.rstrip(b"\x00").decode("utf-8", errors="replace").strip()
        # Heuristic check: the text should start with a known MEGA prefix.
        if (
            text.startswith("https://mega")
            or text.startswith("http://mega")
            or text.startswith("mega.nz")
        ):
            if text.startswith("mega.nz"):
                text = "https://" + text
            try:
                return parse_link(text)
            except ValueError as exc:
                last_error = exc
                continue
    raise ValueError(
        f"Could not decrypt mega://{parsed.container_variant} blob " f"(last error: {last_error})"
    )


def _std_b64_decode(data: str) -> bytes:
    data = data.strip().replace("-", "+").replace("_", "/").replace(",", "")
    data += "=" * ((4 - len(data) % 4) % 4)
    return base64.b64decode(data)


def _std_b64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _aes_cbc_nopadding_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    from Crypto.Cipher import AES

    if len(data) % 16:
        raise ValueError("AES-CBC/NoPadding input length is not a multiple of 16")
    return AES.new(key, AES.MODE_CBC, iv).decrypt(data)


def _aes_cbc_pkcs7_decrypt(data: bytes, key: bytes, iv: bytes) -> bytes:
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import unpad

    return unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(data), 16)


def decode_elc_payload(parsed: ParsedLink) -> ElcPayload:
    """Decode the local envelope of a `mega://elc?...` link.

    The envelope contains encrypted MEGA link fragments, the ELC service URL,
    and a token that must be sent to that service with the user's ELC account.
    """
    import gzip

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
        payload = gzip.decompress(payload)

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
    proxies: dict[str, str] | None = None,
) -> list[str]:
    """Resolve an ELC container to normal MEGA URLs.

    `accounts` is keyed by ELC service host and each value may contain
    `user` plus either `api_key` or `apikey`. Explicit `user`/`api_key`
    arguments override configured accounts.
    """
    import requests

    payload = decode_elc_payload(parsed)
    host = urlparse(payload.service_url).netloc.lower()
    account = (accounts or {}).get(host) or (accounts or {}).get(host.split(":")[0]) or {}
    user = user or account.get("user")
    api_key = api_key or account.get("api_key") or account.get("apikey")
    if not user or not api_key:
        raise ValueError(f"No ELC credentials configured for host {host!r}")

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
        proxies=proxies,
    )
    response.raise_for_status()
    try:
        body = response.json()
    except json.JSONDecodeError as exc:
        raise ValueError(f"ELC server returned non-JSON data: {response.text[:120]}") from exc

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


def decrypt_dlc_container(
    data: str | bytes,
    timeout: int = 30,
    service_url: str = DLC_SERVICE_URL,
    proxies: dict[str, str] | None = None,
) -> list[str]:
    """Decrypt a JDownloader DLC container and return the contained URLs."""
    import requests
    from Crypto.Cipher import AES

    text = data.decode("utf-8", errors="ignore") if isinstance(data, bytes) else data
    text = "".join(text.split())
    if len(text) <= 88:
        raise ValueError("DLC data is too short")

    dlc_id = text[-88:]
    enc_dlc_data = text[:-88].strip()
    response = requests.post(
        service_url,
        data=f"destType=jdtc6&b=JD&srcType=dlc&data={dlc_id}&v={DLC_REV}",
        headers={
            "User-Agent": "Mozilla/5.0 (X11; U; Linux amd64; rv:44.0) Gecko/20100101 Firefox/44.0",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "de,en-gb;q=0.7, en;q=0.3",
            "Accept-Encoding": "gzip, deflate",
            "Accept-Charset": "ISO-8859-1,utf-8;q=0.7,*;q=0.7",
            "Cache-Control": "no-cache",
            "rev": DLC_REV,
        },
        timeout=timeout,
        proxies=proxies,
    )
    response.raise_for_status()
    # Refuse a response that was redirected down to plaintext HTTP.
    final_url = getattr(response, "url", "") or ""
    if final_url.startswith("http://"):
        raise ValueError("DLC service redirected to insecure HTTP; refusing")
    # Treat the third-party response as untrusted: bound its size before parsing.
    if len(response.text) > MAX_DLC_RESPONSE_BYTES:
        raise ValueError("DLC service response is unexpectedly large")
    m = re.search(r"<\s*rc\s*>(.+?)<\s*/\s*rc\s*>", response.text, re.IGNORECASE | re.DOTALL)
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
    payload: dict[str, object],
    timeout: int,
    proxies: dict[str, str] | None = None,
) -> dict:
    import requests

    response = requests.post(
        _megacrypter_api_url(parsed),
        json=payload,
        timeout=timeout,
        proxies=proxies,
    )
    response.raise_for_status()
    body = response.json()
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
        password.encode("utf-8"),
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
    proxies: dict[str, str] | None = None,
) -> MegaCrypterInfo:
    """Fetch and decrypt MegaCrypter metadata."""
    link = _megacrypter_link(parsed)
    payload: dict[str, object] = {"m": "info", "link": link}
    if reverse:
        payload["reverse"] = reverse
    body = _post_megacrypter(parsed, payload, timeout=timeout, proxies=proxies)

    inline_url = _inline_url_from_body(body)
    body, pass_hash = _decrypt_megacrypter_password_info(body, password)

    size_value = body.get("size")
    try:
        size = int(size_value) if size_value not in (None, False, "") else None
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
    proxies: dict[str, str] | None = None,
) -> str:
    """Ask MegaCrypter for the temporary CDN URL, decrypting it if needed."""
    if info is None:
        info = get_megacrypter_info(
            parsed, timeout=timeout, password=password, reverse=reverse, proxies=proxies
        )
    payload: dict[str, object] = {"m": "dl", "link": _megacrypter_link(parsed)}
    if info.noexpire_token:
        payload["noexpire"] = info.noexpire_token
    if sid:
        payload["sid"] = sid
    if reverse:
        payload["reverse"] = reverse

    body = _post_megacrypter(parsed, payload, timeout=timeout, proxies=proxies)
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
) -> ParsedLink:
    """Resolve a MegaCrypter link when the server exposes an underlying MEGA URL."""
    if parsed.type != LinkType.MEGACRYPTER:
        raise ValueError("Not a MegaCrypter link")

    last_body: dict | str | None = None
    for method in ("info", "openlink", "dl"):
        payload: dict[str, object] = {"m": method, "link": _megacrypter_link(parsed)}
        if password:
            payload["password"] = password
            payload["pass"] = password
        try:
            body = _post_megacrypter(parsed, payload, timeout=timeout)
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
