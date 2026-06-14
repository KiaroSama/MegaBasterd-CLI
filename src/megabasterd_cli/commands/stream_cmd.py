"""`mb stream` - start a local HTTP server that streams a MEGA file."""

from __future__ import annotations

import click

from ..core.api import MegaAPIClient
from ..core.links import LinkType, parse_link, resolve_elc_links
from ..streaming.server import StreamingServer
from ..ui.prompts import print_error, print_info


@click.command("stream", short_help="Stream a MEGA file over a local HTTP server.")
@click.argument("url")
@click.option("-p", "--port", type=int, default=None, help="Local HTTP port.")
@click.option("-H", "--host", default=None, help="Bind host.")
@click.option("--password", default=None, help="Password for protected links.")
@click.option(
    "--token",
    "auth_token",
    default=None,
    help="Require this access token. Auto-generated when binding a non-loopback host.",
)
@click.option(
    "--allow-query-token",
    is_flag=True,
    default=False,
    help="Also accept the token via ?token= (insecure: leaks into logs/history). "
    "Off by default; the Authorization: Bearer header is always accepted.",
)
@click.option("--proxy", default=None, help="HTTP/SOCKS proxy URL for upstream MEGA traffic.")
@click.option("--elc-user", default=None, help="ELC account user for mega://elc links.")
@click.option("--elc-api-key", default=None, help="ELC API key for mega://elc links.")
@click.pass_context
def stream(
    ctx: click.Context,
    url: str,
    port: int | None,
    host: str | None,
    password: str | None,
    auth_token: str | None,
    allow_query_token: bool,
    proxy: str | None,
    elc_user: str | None,
    elc_api_key: str | None,
) -> None:
    """Start a local HTTP server that streams a MEGA file with HTTP Range support.

    Point VLC/mpv/your browser at http://127.0.0.1:<port>/ to play the file
    without downloading it first.
    """
    cfg = ctx.obj["config"]
    try:
        parsed = parse_link(url)
    except ValueError as e:
        print_error(str(e))
        return
    proxies = {"http": proxy, "https": proxy} if proxy else None
    if parsed.type == LinkType.ELC_CONTAINER:
        try:
            links = resolve_elc_links(
                parsed,
                accounts=cfg.elc_accounts,
                user=elc_user,
                api_key=elc_api_key,
                timeout=cfg.timeout_seconds,
                proxies=proxies,
            )
        except Exception as exc:  # noqa: BLE001
            print_error(f"ELC resolution failed: {exc}")
            return
        if not links:
            print_error("ELC container did not contain any links.")
            return
        url = links[0]
        parsed = parse_link(url)

    if parsed.type not in (
        LinkType.FILE,
        LinkType.FILE_IN_FOLDER,
        LinkType.PASSWORD_PROTECTED,
        LinkType.MEGACRYPTER,
    ):
        print_error("Stream supports single-file links only.")
        return

    port = port or cfg.streaming_port
    host = host or cfg.streaming_host

    # A non-loopback bind exposes decrypted content to other hosts, so it must
    # never run unauthenticated. Generate a strong ephemeral token if none was
    # supplied. The token is shown on the console but never written to logs.
    from ..streaming.server import is_loopback_host

    if not is_loopback_host(host) and not auth_token:
        import secrets

        auth_token = secrets.token_urlsafe(24)
        print_info("Non-loopback bind detected: stream access now requires a token.")

    if allow_query_token:
        print_info(
            "WARNING: --allow-query-token enables ?token= access, which can leak "
            "into logs and history. Prefer the Authorization: Bearer header."
        )

    from ..proxy.runtime import effective_pool_for_cmd

    proxy_pool = effective_pool_for_cmd(cfg, proxy)
    api = MegaAPIClient(
        timeout=cfg.timeout_seconds,
        proxies=proxies,
        proxy_pool=proxy_pool,
        force_proxy=cfg.force_smart_proxy,
    )
    server = StreamingServer(
        api=api,
        host=host,
        port=port,
        proxies=proxies,
        auth_token=auth_token,
        allow_query_token=allow_query_token,
    )
    try:
        server.set_source(url, password=password)
    except Exception as exc:  # noqa: BLE001
        print_error(f"Stream setup failed: {exc}")
        server.server_close()
        return

    bound_host, bound_port = server.server_address
    display_host = host if bound_host in ("0.0.0.0", "::") else bound_host
    base_url = f"http://{display_host}:{bound_port}/"
    if auth_token and allow_query_token:
        print_info(f"Streaming at {base_url}?token={auth_token}  (Ctrl+C to stop)")
    else:
        print_info(f"Streaming at {base_url}  (Ctrl+C to stop)")
    if auth_token:
        # Shown once on the console only; never written to logs.
        print_info(f"Access token (send as 'Authorization: Bearer {auth_token}').")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print_info("Stopping...")
        server.shutdown()
