"""`mb proxy` - manage the Smart Proxy pool."""

from __future__ import annotations

import json
from pathlib import Path

import click
from rich.table import Table

from ..proxy.runtime import _load_persisted_pool, _pool_path
from ..proxy.smart_proxy import SmartProxyPool
from ..ui.prompts import confirm, print_error, print_info, print_success
from ..ui.theme import make_console

_console = make_console()


def _load_pool() -> SmartProxyPool:
    """Load the on-disk pool. Kept for backwards-compatibility with any
    external caller; new code should import `effective_pool` from
    `proxy.runtime` instead, since that also merges `smart_proxy_url`.
    """
    return _load_persisted_pool()


def _save_pool(pool: SmartProxyPool) -> None:
    path = _pool_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    data = {"proxies": [e.url for e in pool.list()]}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


@click.group("proxy", short_help="Manage the Smart Proxy pool.")
def proxy_cmd() -> None:
    """Add, remove, list proxies in the Smart Proxy pool."""


@proxy_cmd.command("list", short_help="List all proxies in the pool.")
@click.option(
    "--config-urls/--no-config-urls",
    default=True,
    help="Also show URLs from the `smart_proxy_url` config field (default on).",
)
@click.pass_context
def proxy_list(ctx: click.Context, config_urls: bool) -> None:
    cfg = ctx.obj["config"]
    pool = _load_pool()
    persisted = {e.url for e in pool.list()}
    if config_urls:
        from ..proxy.runtime import _urls_from_config

        for url in _urls_from_config(cfg):
            pool.add(url)
    entries = pool.list()
    if not entries:
        _console.print("[mb.dim]No proxies stored.[/mb.dim]")
        return
    table = Table(
        title="Smart Proxy Pool",
        show_header=True,
        header_style="mb.table.header",
        border_style="mb.table.border",
    )
    table.add_column("URL", style="mb.path")
    table.add_column("Successes", justify="right", style="mb.success")
    table.add_column("Failures", justify="right", style="mb.error")
    table.add_column("Status")
    table.add_column("Source", style="mb.muted")
    for e in entries:
        status = "OK" if e.is_available else "Cooldown"
        source = "persisted" if e.url in persisted else "config"
        table.add_row(e.url, str(e.successes), str(e.failures), status, source)
    _console.print(table)


@proxy_cmd.command("add", short_help="Add one or more proxies.")
@click.argument("urls", nargs=-1, required=True)
def proxy_add(urls: tuple[str, ...]) -> None:
    pool = _load_pool()
    for u in urls:
        pool.add(u)
    _save_pool(pool)
    print_success(f"Added {len(urls)} proxy/proxies.")


@proxy_cmd.command("remove", short_help="Remove a proxy by URL.")
@click.argument("url")
def proxy_remove(url: str) -> None:
    pool = _load_pool()
    if pool.remove(url):
        _save_pool(pool)
        print_success(f"Removed {url}")
    else:
        print_error(f"Not found: {url}")


@proxy_cmd.command("clear", short_help="Remove all proxies.")
def proxy_clear() -> None:
    if not confirm("Clear the entire proxy pool?", default=False):
        return
    pool = SmartProxyPool()
    _save_pool(pool)
    print_success("Proxy pool cleared.")


@proxy_cmd.command("import", short_help="Import proxies from a text file (one per line).")
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def proxy_import(path: Path) -> None:
    pool = _load_pool()
    added = 0
    with open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            pool.add(line)
            added += 1
    _save_pool(pool)
    print_success(f"Imported {added} proxy/proxies.")


# Default public proxy-list endpoints. Each one returns plain text, one
# host:port per line. The fetched entries get the supplied scheme prefix.
_DEFAULT_FETCH_SOURCES = {
    "http": [
        "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=10000",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/http.txt",
    ],
    "socks4": [
        "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks4&timeout=10000",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks4.txt",
    ],
    "socks5": [
        "https://api.proxyscrape.com/v2/?request=getproxies&protocol=socks5&timeout=10000",
        "https://raw.githubusercontent.com/TheSpeedX/PROXY-List/master/socks5.txt",
    ],
}


@proxy_cmd.command("serve", short_help="Run a local CONNECT proxy that tunnels to MEGA.")
@click.option("-p", "--port", type=int, default=None, help="TCP port to bind on 127.0.0.1.")
@click.option(
    "--password",
    default=None,
    help="Basic-Auth password clients must present (else uses config value).",
)
@click.option(
    "--any-port",
    is_flag=True,
    help="Allow CONNECT to any TCP port (default: 443 only).",
)
@click.pass_context
def proxy_serve(ctx: click.Context, port: int | None, password: str | None, any_port: bool) -> None:
    """Run a local HTTPS CONNECT proxy that only forwards traffic to mega.nz.

    Configure any HTTP client to point at http://127.0.0.1:<port> as its HTTPS
    proxy (with the supplied Basic-Auth credentials) to route MEGA traffic
    through this process.
    """
    from ..proxy.connect_proxy import MegaConnectProxy

    cfg = ctx.obj["config"]
    port = port or cfg.connect_proxy_port
    password = password or cfg.connect_proxy_password
    if not password:
        print_error(
            "No proxy password set. Use --password or "
            "`mb config set connect_proxy_password <secret>`."
        )
        return

    proxy = MegaConnectProxy(
        password=password,
        port=port,
        allow_any_port=any_port or cfg.connect_proxy_allow_any_port,
    )
    proxy.start()
    print_success(f"MEGA CONNECT proxy running on 127.0.0.1:{port}")
    print_info("Configure other apps to use this address as an HTTPS proxy.")
    print_info("Press Ctrl+C to stop.")
    try:
        import threading

        threading.Event().wait()
    except KeyboardInterrupt:
        proxy.stop()
        print_info("Stopped.")


@proxy_cmd.command("fetch", short_help="Auto-fetch free proxies from a public list.")
@click.option(
    "--protocol",
    type=click.Choice(["http", "socks4", "socks5"]),
    default="http",
    show_default=True,
)
@click.option("--source", default=None, help="Override the source URL.")
@click.option(
    "--limit",
    type=int,
    default=200,
    show_default=True,
    help="Maximum number of proxies to add from the fetched list.",
)
@click.option("--timeout", type=int, default=20, show_default=True)
def proxy_fetch(protocol: str, source: str | None, limit: int, timeout: int) -> None:
    """Pull a list of free proxies from a public source and add them to the pool."""
    import requests

    sources = [source] if source else _DEFAULT_FETCH_SOURCES.get(protocol, [])
    if not sources:
        print_error(f"No fetch source configured for protocol {protocol}")
        return

    pool = _load_pool()
    added = 0
    errors: list[str] = []
    for url in sources:
        try:
            resp = requests.get(url, timeout=timeout)
            resp.raise_for_status()
        except Exception as exc:  # noqa: BLE001
            errors.append(f"{url}: {exc}")
            continue
        for raw in resp.text.splitlines():
            line = raw.strip()
            if not line:
                continue
            if added >= limit:
                break
            if "://" not in line:
                line = f"{protocol}://{line}"
            pool.add(line)
            added += 1
        if added >= limit:
            break

    if added == 0:
        print_error(f"No proxies fetched. Errors: {errors}")
        return

    _save_pool(pool)
    print_success(f"Fetched {added} {protocol} proxy/proxies.")
    if errors:
        for e in errors:
            print_error(e)
