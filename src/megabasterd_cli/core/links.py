"""Parse MEGA share links (offline).

Everything here is pure: regex parsing, key unwrapping, and LOCAL container
decryption, with no network access. Resolving a link against a remote service
(ELC, DLC, MegaCrypter) lives in `link_services.py`, which imports from this
module - never the reverse.

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
    mega://elc?<b64>         (ELC container; resolved in link_services.py)

MegaCrypter (third-party host; resolved in link_services.py):
    mc://<server>/<token>
    https://<server>/!<token>
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from enum import Enum
from urllib.parse import urlparse

from .errors import MegaError


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
        """Compatibility surface retained for the 1.x series."""
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


# Backwards-compatible re-exports.
#
# These six used to live here and were moved to `link_services.py`, which
# imports from this module - so a top-level `from .link_services import ...`
# would be a cycle. PEP 562 module __getattr__ resolves them on first access
# instead, once both modules are fully loaded.
_MOVED_TO_LINK_SERVICES = frozenset(
    {
        "decode_elc_payload",
        "resolve_elc_links",
        "decrypt_dlc_container",
        "get_megacrypter_info",
        "get_megacrypter_download_url",
        "resolve_megacrypter_link",
    }
)

__all__ = [
    "ElcPayload",
    "LinkType",
    "MAX_MEGACRYPTER_PBKDF2_ITERATIONS",
    "MegaCrypterInfo",
    "ParsedLink",
    "is_mega_url",
    "normalize_link",
    "parse_link",
    "resolve_encrypted_container_link",
    "resolve_password_link",
    *sorted(_MOVED_TO_LINK_SERVICES),
]


def __getattr__(name: str):
    if name in _MOVED_TO_LINK_SERVICES:
        from . import link_services

        return getattr(link_services, name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


def __dir__() -> list[str]:
    return sorted({*globals(), *__all__})


def require_link_key(parsed, what: str) -> str:
    """Return the link's decryption key, or fail with a message that says so.

    `ParsedLink.key` is genuinely optional - a MEGA link can be pasted without
    its `#fragment`. Callers that need to decrypt were passing it straight to
    `str_to_a32`, which raised a `TypeError` about NoneType from deep inside
    the crypto layer instead of telling the user their link is missing a key.
    """
    if not parsed.key:
        raise MegaError(
            message=f"{what} needs a link that includes its decryption key (the part after '#')"
        )
    return str(parsed.key)


def normalize_link(url: str) -> str:
    """Return the link in modern format if possible.

    Compatibility surface retained for the 1.x series.
    """
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
