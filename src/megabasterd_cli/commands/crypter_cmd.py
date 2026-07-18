"""`mb crypter` — local pre-upload encryption / post-download decryption."""

from __future__ import annotations

from pathlib import Path

import click

from ..core.crypter import CrypterError, decrypt_file, encrypt_file
from ..core.links import LinkType, decrypt_dlc_container, parse_link, resolve_elc_links
from ..proxy.selector import ProxySelector
from ..ui.prompts import ask_password, print_error, print_info, print_success
from ..utils.helpers import format_bytes


@click.group("crypter", short_help="Encrypt/decrypt local files with a passphrase.")
def crypter_cmd() -> None:
    """Add a passphrase-based encryption layer to local files."""


@crypter_cmd.command("encrypt", short_help="Encrypt a local file with a passphrase.")
@click.argument("source", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("destination", type=click.Path(dir_okay=False, path_type=Path))
@click.option("--password", default=None, help="Passphrase (prompt if omitted).")
@click.option(
    "--chunk-size-kb",
    type=int,
    default=64,
    help="Encryption chunk size in KB.",
)
def crypter_encrypt(
    source: Path, destination: Path, password: str | None, chunk_size_kb: int
) -> None:
    """Encrypt SOURCE -> DESTINATION using AES-256-GCM."""
    password = password or ask_password("Crypter passphrase")
    try:
        size_before = source.stat().st_size

        def _on_progress(done: int, total: int) -> None:
            pass

        encrypt_file(
            source,
            destination,
            password,
            chunk_size=chunk_size_kb * 1024,
            on_progress=_on_progress,
        )
        size_after = destination.stat().st_size
        print_success(
            f"Encrypted {source.name} ({format_bytes(size_before)}) "
            f"-> {destination.name} ({format_bytes(size_after)})"
        )
    except CrypterError as exc:
        print_error(f"Encryption failed: {exc}")


@crypter_cmd.command("decrypt", short_help="Decrypt a Crypter-encoded file.")
@click.argument("source", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.argument("destination", type=click.Path(dir_okay=False, path_type=Path))
@click.option("--password", default=None, help="Passphrase (prompt if omitted).")
def crypter_decrypt(source: Path, destination: Path, password: str | None) -> None:
    """Decrypt SOURCE -> DESTINATION."""
    password = password or ask_password("Crypter passphrase")
    try:
        decrypt_file(source, destination, password)
        size_after = destination.stat().st_size
        print_success(f"Decrypted {source.name} -> {destination.name} ({format_bytes(size_after)})")
    except CrypterError as exc:
        print_error(f"Decryption failed: {exc}")


# ---------------------------------------------------------------------------
# MegaCrypter share-link helpers (querying / creating mc:// links)
# ---------------------------------------------------------------------------


@crypter_cmd.command("make-link", short_help="Register a MEGA link with a MegaCrypter server.")
@click.argument("mega_url")
@click.option("--server", default=None, help="MegaCrypter server hostname.")
@click.option(
    "--password",
    default=None,
    help="Second-layer password applied to the mc:// link (used by the server "
    "to gate access; not the same as MEGA's #P! password).",
)
@click.option("--description", default=None, help="Optional description shown by the server.")
@click.option(
    "--no-expire",
    "no_expire",
    is_flag=True,
    help="Ask the server to keep the link alive indefinitely.",
)
@click.option(
    "--reverse",
    "reverse",
    is_flag=True,
    help="Enable reverse-mode: the MegaCrypter server proxies the download "
    "itself, hiding the underlying MEGA URL from the client.",
)
@click.option(
    "--max-downloads",
    type=int,
    default=None,
    help="Limit how many times the resulting link can be used.",
)
@click.pass_context
def crypter_make_link(
    ctx: click.Context,
    mega_url: str,
    server: str | None,
    password: str | None,
    description: str | None,
    no_expire: bool,
    reverse: bool,
    max_downloads: int | None,
) -> None:
    """Submit MEGA_URL to a MegaCrypter server and print the returned `mc://` link."""
    import requests

    cfg = ctx.obj["config"]
    server = server or cfg.megacrypter_server
    if not server:
        print_error(
            "No MegaCrypter server set. Use --server or "
            "`mb config set megacrypter_server <host>`."
        )
        return

    try:
        parse_link(mega_url)
    except ValueError:
        print_error("MEGA_URL must be a valid MEGA link.")
        return

    payload: dict[str, object] = {"m": "add", "link": mega_url}
    if password:
        payload["password"] = password
        # Some servers also accept the older field name `pass`.
        payload["pass"] = password
    if description:
        payload["description"] = description
    if no_expire:
        payload["noexpire"] = True
        payload["no_expire"] = True
    if reverse:
        payload["reverse"] = True
    if max_downloads is not None:
        payload["max_downloads"] = max_downloads

    api_url = f"https://{server}/api"
    selector = ProxySelector.from_config(cfg)
    try:
        request_proxies, _picked = selector.select()
        resp = requests.post(
            api_url, json=payload, timeout=cfg.timeout_seconds, proxies=request_proxies
        )
        resp.raise_for_status()
        body = resp.json()
    except Exception as exc:
        print_error(f"MegaCrypter request failed: {exc}")
        return

    link = body.get("link") or body.get("url") or body.get("mc_url")
    if not link:
        print_error(f"Unexpected MegaCrypter response: {body}")
        return
    print_success("Created MegaCrypter link:")
    click.echo(link)


@crypter_cmd.command("resolve", short_help="Resolve a MegaCrypter link to its underlying MEGA URL.")
@click.argument("mc_url")
@click.option(
    "--password",
    default=None,
    help="Second-layer password if the link was created with --password.",
)
@click.pass_context
def crypter_resolve(ctx: click.Context, mc_url: str, password: str | None) -> None:
    """Print the MEGA URL hidden behind an `mc://` / MegaCrypter link."""
    from ..core.links import resolve_megacrypter_link

    cfg = ctx.obj["config"]
    try:
        parsed = parse_link(mc_url)
    except ValueError as exc:
        print_error(str(exc))
        return
    if parsed.type != LinkType.MEGACRYPTER:
        print_error("URL is not a MegaCrypter link.")
        return
    try:
        resolved = resolve_megacrypter_link(
            parsed,
            timeout=cfg.timeout_seconds,
            password=password,
            selector=ProxySelector.from_config(cfg),
        )
    except ValueError as exc:
        print_error(f"Resolve failed: {exc}")
        return
    print_info(f"Resolved to: {resolved.public_id}")
    if resolved.type == LinkType.FILE:
        click.echo(f"https://mega.nz/file/{resolved.public_id}#{resolved.key}")
    elif resolved.type == LinkType.FOLDER:
        click.echo(f"https://mega.nz/folder/{resolved.public_id}#{resolved.key}")


@crypter_cmd.command("elc-resolve", short_help="Resolve a mega://elc container.")
@click.argument("elc_url")
@click.option("--user", "elc_user", default=None, help="ELC account user.")
@click.option("--api-key", "elc_api_key", default=None, help="ELC API key.")
@click.pass_context
def crypter_elc_resolve(
    ctx: click.Context,
    elc_url: str,
    elc_user: str | None,
    elc_api_key: str | None,
) -> None:
    """Print the MEGA URLs contained in an ELC link container."""
    cfg = ctx.obj["config"]
    try:
        parsed = parse_link(elc_url)
    except ValueError as exc:
        print_error(str(exc))
        return
    if parsed.type != LinkType.ELC_CONTAINER:
        print_error("URL is not an ELC container.")
        return
    try:
        links = resolve_elc_links(
            parsed,
            accounts=cfg.elc_accounts,
            user=elc_user,
            api_key=elc_api_key,
            timeout=cfg.timeout_seconds,
            selector=ProxySelector.from_config(cfg),
        )
    except Exception as exc:  # noqa: BLE001
        print_error(f"ELC resolve failed: {exc}")
        return
    for link in links:
        click.echo(link)


@crypter_cmd.command("dlc-resolve", short_help="Resolve a JDownloader .dlc container.")
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.pass_context
def crypter_dlc_resolve(ctx: click.Context, path: Path) -> None:
    """Print the URLs contained in a DLC file."""
    cfg = ctx.obj["config"]
    try:
        links = decrypt_dlc_container(
            path.read_bytes(),
            timeout=cfg.timeout_seconds,
            selector=ProxySelector.from_config(cfg),
        )
    except Exception as exc:  # noqa: BLE001
        print_error(f"DLC resolve failed: {exc}")
        return
    for link in links:
        click.echo(link)
