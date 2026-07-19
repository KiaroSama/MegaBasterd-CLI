"""`mb info` — inspect a MEGA link without downloading."""

from __future__ import annotations

import click

from ..core.api import MegaAPIClient
from ..core.crypto import (
    a32_to_bytes,
    aes_key_wrap_decrypt,
    b64_url_decode,
    bytes_to_a32,
    decrypt_attributes,
    str_to_a32,
    unpack_file_key,
)
from ..core.errors import MegaError
from ..core.link_services import get_megacrypter_info, resolve_elc_links, resolve_megacrypter_link
from ..core.links import LinkType, parse_link, require_link_key, resolve_password_link
from ..proxy.selector import ProxySelector
from ..ui.prompts import print_error
from ..ui.theme import SafeTable, make_console
from ..utils.helpers import format_bytes

_console = make_console()


@click.command("info", short_help="Show public MEGA link metadata; no account or MFA needed.")
@click.argument("url")
@click.option("--password", default=None, help="Password for protected links.")
@click.option("--elc-user", default=None, help="ELC account user for mega://elc links.")
@click.option("--elc-api-key", default=None, help="ELC API key for mega://elc links.")
@click.pass_context
def info_cmd(
    ctx: click.Context,
    url: str,
    password: str | None,
    elc_user: str | None,
    elc_api_key: str | None,
) -> None:
    """Resolve a public URL and print metadata. No account or MFA needed."""
    cfg = ctx.obj["config"]
    try:
        parsed = parse_link(url)
    except ValueError as exc:
        print_error(str(exc))
        return

    if parsed.type == LinkType.ELC_CONTAINER:
        cfg = ctx.obj["config"]
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
            print_error(f"ELC resolution failed: {exc}")
            return
        for link in links:
            click.echo(f"\n{link}")
            ctx.invoke(
                info_cmd,
                url=link,
                password=password,
                elc_user=elc_user,
                elc_api_key=elc_api_key,
            )
        return

    if parsed.type == LinkType.PASSWORD_PROTECTED:
        if not password:
            print_error("Link is password-protected; supply --password.")
            return
        try:
            parsed = resolve_password_link(parsed, password)
        except ValueError as exc:
            print_error(str(exc))
            return
    elif parsed.type == LinkType.ENCRYPTED_CONTAINER:
        from ..core.links import resolve_encrypted_container_link

        try:
            parsed = resolve_encrypted_container_link(parsed)
        except ValueError as exc:
            print_error(str(exc))
            return
    elif parsed.type == LinkType.MEGACRYPTER:
        try:
            parsed = resolve_megacrypter_link(
                parsed,
                timeout=cfg.timeout_seconds,
                password=password,
                selector=ProxySelector.from_config(cfg),
            )
        except ValueError as exc:
            try:
                mc_info = get_megacrypter_info(
                    parsed,
                    timeout=cfg.timeout_seconds,
                    password=password,
                    selector=ProxySelector.from_config(cfg),
                )
            except ValueError:
                print_error(str(exc))
                return
            table = SafeTable(
                show_header=False,
                title="MegaCrypter info",
                border_style="mb.table.border",
            )
            table.add_column("Field", style="mb.info")
            table.add_column("Value", style="mb.value")
            table.add_row("Type", "MegaCrypter file")
            if mc_info.name:
                table.add_row("Name", mc_info.name)
            if mc_info.size is not None:
                table.add_row("Size", format_bytes(mc_info.size))
            table.add_row("File key", "available" if mc_info.key else "missing")
            if mc_info.noexpire_token:
                table.add_row("No-expire token", "available")
            _console.print(table)
            return

    api = MegaAPIClient(
        timeout=cfg.timeout_seconds,
        proxy_pool=ProxySelector.from_config(cfg).pool,
        force_proxy=cfg.force_smart_proxy,
    )
    table = SafeTable(show_header=False, title="Link info", border_style="mb.table.border")
    table.add_column("Field", style="mb.info")
    table.add_column("Value", style="mb.value")

    try:
        if parsed.type in (LinkType.FOLDER, LinkType.FOLDER_IN_FOLDER):
            listing = api.get_public_folder_listing(parsed.public_id)
            raw_nodes = listing.get("f", [])
            if parsed.type == LinkType.FOLDER_IN_FOLDER and parsed.subpath:
                children: dict[str, list[str]] = {}
                by_handle = {n.get("h"): n for n in raw_nodes}
                for n in raw_nodes:
                    children.setdefault(n.get("p", ""), []).append(n.get("h", ""))
                keep = {parsed.subpath}
                stack = [parsed.subpath]
                while stack:
                    current = stack.pop()
                    for child in children.get(current, []):
                        if child and child not in keep:
                            keep.add(child)
                            stack.append(child)
                raw_nodes = [n for n in raw_nodes if n.get("h") in keep]
                if parsed.subpath not in by_handle:
                    print_error(
                        f"Subfolder {parsed.subpath!r} not found in folder {parsed.public_id!r}"
                    )
                    return
                table.add_row("Type", "Folder (inside folder share)")
                table.add_row("Subfolder handle", parsed.subpath)
            else:
                table.add_row("Type", "Folder share")
            table.add_row("Public ID", parsed.public_id)
            table.add_row("Node count", str(len(raw_nodes)))
            file_count = sum(1 for n in raw_nodes if n.get("t") == 0)
            total_size = sum(int(n.get("s", 0) or 0) for n in raw_nodes if n.get("t") == 0)
            table.add_row("Files", str(file_count))
            table.add_row("Total size", format_bytes(total_size))
        elif parsed.type == LinkType.FILE_IN_FOLDER:
            # Look up the file inside the parent folder listing, using the
            # folder share key to unwrap the file's key.
            folder_id = parsed.public_id
            file_handle = parsed.subpath
            folder_key = a32_to_bytes(str_to_a32(require_link_key(parsed, "link info")))
            listing = api.get_public_folder_listing(folder_id)
            raw_nodes = listing.get("f", [])
            file_raw = next(
                (n for n in raw_nodes if n.get("h") == file_handle and n.get("t") == 0), None
            )
            if file_raw is None:
                folder_raw = next(
                    (n for n in raw_nodes if n.get("h") == file_handle and n.get("t") == 1),
                    None,
                )
                if folder_raw is None:
                    print_error(f"Node {file_handle!r} not found in folder {folder_id!r}")
                    return
                # Reached only via `folder_raw`, which was found BY this
                # handle, so it cannot be None here.
                assert file_handle is not None
                subtree_children: dict[str, list[str]] = {}
                for n in raw_nodes:
                    subtree_children.setdefault(n.get("p", ""), []).append(n.get("h", ""))
                keep = {file_handle}
                stack = [file_handle]
                while stack:
                    current = stack.pop()
                    for child in subtree_children.get(current, []):
                        if child and child not in keep:
                            keep.add(child)
                            stack.append(child)
                subtree = [n for n in raw_nodes if n.get("h") in keep]
                table.add_row("Type", "Folder (inside folder share)")
                table.add_row("Folder ID", folder_id)
                table.add_row("Subfolder handle", file_handle or "?")
                table.add_row("Node count", str(len(subtree)))
                file_count = sum(1 for n in subtree if n.get("t") == 0)
                total_size = sum(int(n.get("s", 0) or 0) for n in subtree if n.get("t") == 0)
                table.add_row("Files", str(file_count))
                table.add_row("Total size", format_bytes(total_size))
                _console.print(table)
                return
            raw_k = file_raw.get("k", "") or ""
            _, wrapped = raw_k.split(":", 1) if ":" in raw_k else ("", raw_k)
            key_bytes = aes_key_wrap_decrypt(b64_url_decode(wrapped), folder_key)
            aes_key, _, _ = unpack_file_key(bytes_to_a32(key_bytes[:32]))
            attrs = decrypt_attributes(b64_url_decode(file_raw.get("a", "") or ""), aes_key) or {}
            table.add_row("Type", "File (in folder share)")
            table.add_row("Name", attrs.get("n", "?"))
            table.add_row("Folder ID", folder_id)
            table.add_row("File handle", file_handle or "?")
            table.add_row("Size", format_bytes(int(file_raw.get("s", 0) or 0)))
        else:
            info = api.get_public_file_info(parsed.public_id)
            if not parsed.key:
                table.add_row("Type", "File")
                table.add_row("Public ID", parsed.public_id)
                table.add_row("Size", format_bytes(int(info.get("s", 0))))
                _console.print(table)
                return
            aes_key, _nonce, _mac = unpack_file_key(
                str_to_a32(require_link_key(parsed, "link info"))
            )
            attrs = decrypt_attributes(b64_url_decode(info.get("at", "") or ""), aes_key) or {}
            table.add_row("Type", "File")
            table.add_row("Name", attrs.get("n", "?"))
            table.add_row("Public ID", parsed.public_id)
            table.add_row("Size", format_bytes(int(info.get("s", 0))))
            if "fa" in info:
                table.add_row("File attributes", info["fa"])
    except MegaError as exc:
        print_error(f"Lookup failed: {exc}")
        return
    finally:
        # Every branch above returns early; the client is only ever used
        # inside this block, so release its sockets on all of them.
        api.close()

    _console.print(table)
