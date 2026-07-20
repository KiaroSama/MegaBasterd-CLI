"""Turn a user-supplied link into everything a transfer needs to start.

A public link is not directly downloadable: it may be a password wrapper, an
encrypted container, a MegaCrypter token, a plain file, or a file inside a
public folder share. Each of those resolves to the same five facts - a CDN
URL, a declared size, the AES key/nonce/MAC-IV, a destination path, and a
resolver closure that can mint a FRESH CDN URL when the current one expires.

Everything here is resolution only: no chunk plan, no destination claim, no
worker threads. The declared size is passed through untouched and is
validated by the caller before any allocation happens.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from ..utils.helpers import ensure_within_directory, sanitize_filename
from .crypto import b64_url_decode, bytes_to_a32, decrypt_attributes, unpack_file_key
from .download_verify import DeclaredSizeError
from .errors import TransferError
from .link_services import (
    get_megacrypter_download_url,
    get_megacrypter_info,
    resolve_megacrypter_link,
)
from .links import (
    LinkType,
    parse_link,
    require_link_key,
    resolve_encrypted_container_link,
    resolve_password_link,
)

log = logging.getLogger(__name__)


def decode_link_key(key: str, expected_len: int, what: str) -> bytes:
    """Decode a user-supplied link key, refusing a truncated one.

    `bytes_to_a32` zero-pads to a word boundary - `derive_key_legacy` depends
    on that - so a key that lost one base64 character (42 chars, 31 bytes)
    still produced exactly 8 uint32s and passed `unpack_file_key`'s length
    guard. The user got a DIFFERENT AES key with no error at all: it surfaced
    later as "File MAC verification failed", or as silent garbage on disk when
    integrity verification was off. The length has to be checked here, at the
    parse boundary, where the expected size is actually known.
    """
    raw = b64_url_decode(key)
    if len(raw) != expected_len:
        raise ValueError(
            f"{what} key decodes to {len(raw)} bytes, expected {expected_len}; "
            "the link's key is truncated or corrupt"
        )
    return raw


@dataclass
class ResolvedSource:
    """The inputs `MegaDownloader._run_download` needs, all resolved."""

    cdn_url: str
    file_size: object  # A CLAIM from the remote; validated by the caller.
    aes_key: bytes
    nonce: bytes
    mac_iv_a32: list[int]
    destination: Path
    url_resolver: Callable[[], str]


def resolve_download_source(
    dl,  # MegaDownloader
    url: str,
    output_dir: Path,
    password: str | None,
    rename_to: str | None,
) -> ResolvedSource:
    """Resolve `url` down to a concrete, downloadable source."""
    parsed = parse_link(url)

    # Transparently resolve password / MegaCrypter wrappers down to a
    # standard file/folder link.
    if parsed.type == LinkType.PASSWORD_PROTECTED:
        if not password:
            raise ValueError("This link is password-protected; supply password=")
        parsed = resolve_password_link(parsed, password)
    elif parsed.type == LinkType.ENCRYPTED_CONTAINER:
        parsed = resolve_encrypted_container_link(parsed)
    elif parsed.type == LinkType.MEGACRYPTER:
        mc_parsed = parsed
        try:
            parsed = resolve_megacrypter_link(
                parsed,
                timeout=dl.timeout,
                password=password,
                selector=dl._selector,
            )
        except ValueError as exc:
            return _resolve_megacrypter_direct(
                dl, mc_parsed, output_dir, password, rename_to, cause=exc
            )

    if parsed.type not in (LinkType.FILE, LinkType.FILE_IN_FOLDER):
        raise ValueError(f"Link is not a single-file link: {parsed.type}")

    if parsed.type == LinkType.FILE_IN_FOLDER:
        info, key_a32, encrypted_attrs = _resolve_folder_file(dl, parsed)
    else:
        info = dl._get_with_quota_wait(lambda: dl.api.get_public_file_info(parsed.public_id))
        if "g" not in info:
            raise TransferError(message=f"No download URL returned: {info}")
        key_a32 = bytes_to_a32(
            decode_link_key(require_link_key(parsed, "download"), 32, "File link")
        )
        encrypted_attrs = b64_url_decode(info.get("at", "") or "")

    cdn_url = info["g"]
    # NOTE: a missing/garbage "s" is refused here rather than downstream, so
    # the caller never sees a size it cannot validate.
    try:
        file_size = int(info["s"])
    except (KeyError, TypeError, ValueError) as exc:
        raise DeclaredSizeError(
            message=f"Upstream did not declare a usable file size: {info.get('s')!r}"
        ) from exc
    aes_key, nonce, mac_iv_a32 = unpack_file_key(key_a32)

    # Decrypt the filename
    attrs = decrypt_attributes(encrypted_attrs, aes_key)
    original_name = (attrs or {}).get("n") or (
        parsed.subpath if parsed.subpath else parsed.public_id
    )
    filename = rename_to or sanitize_filename(original_name)
    destination = output_dir / filename
    ensure_within_directory(output_dir, destination)
    destination.parent.mkdir(parents=True, exist_ok=True)

    # Resolver that re-fetches a fresh CDN URL when the existing one expires
    if parsed.type == LinkType.FILE_IN_FOLDER:
        _resolver_folder_id = parsed.public_id
        _resolver_file_handle = parsed.subpath

        def _resolver() -> str:
            fresh = dl.api.request(
                {"a": "g", "g": 1, "n": _resolver_file_handle},
                extra_params={"n": _resolver_folder_id},
            )
            if "g" not in fresh:
                raise TransferError(message=f"Resolver got no URL: {fresh}")
            return str(fresh["g"])

    else:
        _resolver_public_id = parsed.public_id

        def _resolver() -> str:
            fresh = dl.api.get_public_file_info(_resolver_public_id)
            if "g" not in fresh:
                raise TransferError(message=f"Resolver got no URL: {fresh}")
            return str(fresh["g"])

    return ResolvedSource(
        cdn_url=cdn_url,
        file_size=file_size,
        aes_key=aes_key,
        nonce=nonce,
        mac_iv_a32=mac_iv_a32,
        destination=destination,
        url_resolver=_resolver,
    )


def _resolve_folder_file(dl, parsed) -> tuple[dict, list[int], bytes]:
    """Resolve a node inside a public folder share.

    The public_id is the FOLDER's handle, not the file's; we must look up the
    file in the folder listing to get its wrapped key, and request the CDN URL
    with `n=<folder_id>` as an extra parameter.
    """
    from .crypto import aes_key_wrap_decrypt

    folder_id = parsed.public_id
    file_handle = parsed.subpath
    if not file_handle:
        raise ValueError("FILE_IN_FOLDER link is missing the file handle")
    folder_key = decode_link_key(require_link_key(parsed, "download"), 16, "Folder link")

    listing = dl._get_with_quota_wait(lambda: dl.api.get_public_folder_listing(folder_id))
    file_raw = next(
        (n for n in listing.get("f", []) if n.get("h") == file_handle and n.get("t") == 0),
        None,
    )
    if file_raw is None:
        raise TransferError(message=f"File {file_handle!r} not in folder share {folder_id!r}")

    raw_k = file_raw.get("k", "") or ""
    _, wrapped = raw_k.split(":", 1) if ":" in raw_k else ("", raw_k)
    if not wrapped:
        raise TransferError(message=f"Empty wrapped key on {file_handle!r}")
    key_bytes = aes_key_wrap_decrypt(b64_url_decode(wrapped), folder_key)
    key_a32 = bytes_to_a32(key_bytes[:32])

    info = dl._get_with_quota_wait(
        lambda: dl.api.request(
            {"a": "g", "g": 1, "n": file_handle},
            extra_params={"n": folder_id},
        )
    )
    if "g" not in info:
        raise TransferError(message=f"No download URL returned for folder-file: {info}")
    return info, key_a32, b64_url_decode(file_raw.get("a", "") or "")


def _resolve_megacrypter_direct(
    dl,
    mc_parsed,
    output_dir: Path,
    password: str | None,
    rename_to: str | None,
    cause: Exception,
) -> ResolvedSource:
    """Fallback when a MegaCrypter link will not unwrap to a mega.nz link.

    The crypter itself then serves the bytes, so its metadata endpoint supplies
    the key/size and its download endpoint supplies (and re-mints) the URL.
    """
    mc_info = get_megacrypter_info(
        mc_parsed,
        timeout=dl.timeout,
        password=password,
        selector=dl._selector,
    )
    if not mc_info.key or mc_info.size is None:
        raise ValueError("MegaCrypter metadata is missing key or size") from cause
    cdn_url = get_megacrypter_download_url(
        mc_parsed,
        info=mc_info,
        timeout=dl.timeout,
        password=password,
        selector=dl._selector,
    )
    key_a32 = bytes_to_a32(decode_link_key(mc_info.key, 32, "MegaCrypter file"))
    aes_key, nonce, mac_iv_a32 = unpack_file_key(key_a32)
    filename = rename_to or sanitize_filename(
        mc_info.name or mc_parsed.crypter_token or "megacrypter"
    )
    output_dir.mkdir(parents=True, exist_ok=True)
    destination = output_dir / filename
    ensure_within_directory(output_dir, destination)

    def _resolver() -> str:
        return get_megacrypter_download_url(
            mc_parsed,
            info=mc_info,
            timeout=dl.timeout,
            password=password,
            selector=dl._selector,
        )

    return ResolvedSource(
        cdn_url=cdn_url,
        file_size=mc_info.size,
        aes_key=aes_key,
        nonce=nonce,
        mac_iv_a32=mac_iv_a32,
        destination=destination,
        url_resolver=_resolver,
    )
