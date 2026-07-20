"""`mb proxy` - manage the Smart Proxy pool."""

from __future__ import annotations

import json
import re
from contextlib import contextmanager
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

import click
from rich.table import Table

from ..proxy.runtime import _load_persisted_pool, _pool_path
from ..queue.storage import atomic_write_text
from ..ui.prompts import confirm, print_error, print_info, print_success, print_warn
from ..ui.theme import make_console
from ..utils.filelock import FileLock
from ..utils.redaction import REDACTED, redact_text

_console = make_console()

# Matches the other persisted stores (config, queue, state): long enough for a
# concurrent `mb proxy add` to finish, short enough to fail with a clear error.
_POOL_LOCK_TIMEOUT_SECONDS = 10.0
# Cap on a fetched proxy list. The URL is user-supplied and may be hostile, so
# the body is streamed and cut off instead of being read into memory whole.
MAX_FETCH_BYTES = 4 * 1024 * 1024


@contextmanager
def pool_transaction():
    """Hold the lock across the WHOLE read-modify-write, then save.

    Locking only the write made the write atomic and the transaction not.
    Every command did `_load_pool()` outside the lock, mutated that snapshot,
    and saved it - so two concurrent `proxy add` processes both read the same
    pool and the second save silently discarded the first one's entry, with
    the lock dutifully held the entire time.

    Yield the pool, mutate it, and the save happens here on a clean exit. The
    lock and the write are inline because this is their only caller - a named
    `_write_pool_locked` whose docstring had to say "the caller MUST already
    hold the lock" is a precondition nobody can now get wrong.
    """
    path = _pool_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    lock = FileLock(
        path.parent / (path.name + ".lock"),
        message=(
            f"Could not lock the proxy pool within {_POOL_LOCK_TIMEOUT_SECONDS:.0f}s; "
            "another proxy command is holding it. Retry after it finishes."
        ),
    )
    lock.acquire(timeout=_POOL_LOCK_TIMEOUT_SECONDS)
    try:
        # Re-read INSIDE the lock: this is what makes the loser of a race
        # observe the winner's write instead of overwriting it.
        pool = _load_persisted_pool()
        yield pool
        payload = json.dumps({"proxies": [e.url for e in pool.list()]}, indent=2)
        atomic_write_text(path, payload)
    finally:
        lock.release()


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
    pool = _load_persisted_pool()
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
        # A proxy URL routinely carries `user:pass@`; the table is printed to a
        # terminal that gets screenshotted and pasted into bug reports.
        table.add_row(redact_text(e.url), str(e.successes), str(e.failures), status, source)
    _console.print(table)


@proxy_cmd.command("add", short_help="Add one or more proxies.")
@click.argument("urls", nargs=-1, required=True)
def proxy_add(urls: tuple[str, ...]) -> None:
    with pool_transaction() as pool:
        for u in urls:
            pool.add(u)
    print_success(f"Added {len(urls)} proxy/proxies.")


@proxy_cmd.command("remove", short_help="Remove a proxy by URL.")
@click.argument("url")
def proxy_remove(url: str) -> None:
    # Matching uses the RAW url; only what reaches the terminal is redacted.
    # A proxy URL routinely carries `user:pass@`, and both branches used to
    # print it verbatim.
    shown = redact_text(url)
    removed = False
    with pool_transaction() as pool:
        removed = pool.remove(url)
    if removed:
        print_success(f"Removed {shown}")
    else:
        print_error(f"Not found: {shown}")


@proxy_cmd.command("clear", short_help="Remove all proxies.")
def proxy_clear() -> None:
    if not confirm("Clear the entire proxy pool?", default=False):
        return
    with pool_transaction() as pool:
        for entry in list(pool.list()):
            pool.remove(entry.url)
    print_success("Proxy pool cleared.")


@proxy_cmd.command("import", short_help="Import proxies from a text file (one per line).")
@click.argument("path", type=click.Path(exists=True, dir_okay=False, path_type=Path))
def proxy_import(path: Path) -> None:
    added = 0
    with pool_transaction() as pool, open(path, encoding="utf-8") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            pool.add(line)
            added += 1
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

        # A bare `Event().wait()` is not interruptible by Ctrl-C on Windows,
        # so the wait is polled: the KeyboardInterrupt is delivered between
        # timeouts and shutdown actually runs.
        forever = threading.Event()
        while not forever.wait(0.5):
            pass
    except KeyboardInterrupt:
        print_info("Stopped.")
    finally:
        # Any exit path must release the listener and the accepted sockets.
        proxy.stop()


# Query parameters whose value is credential-ish. Deliberately wider than the
# exact names `redact_text` knows, because a signed URL names its signature
# `sig`, `X-Amz-Signature`, `hmac`, ... and any of them identifies the caller.
_SECRETISH_PARAM = re.compile(r"(?i)(token|key|sig|hmac|secret|auth|pass|cred|session|sid|nonce)")


def _url_secrets(url: str) -> list[str]:
    """The literal secret substrings of a source URL, longest first.

    `redact_text` recognises secrets by SHAPE (`user:pass@host`, `token=x`).
    An exception message routinely echoes the same value stripped of that
    shape - urllib3 reports a bare `user:hunter2@host` with no scheme, and a
    signed query value can sit under any parameter name - and then no pattern
    matches. Here the raw values are known, so they are also removed by
    identity, after the shape pass.

    Short values are skipped: substituting a 4-character string everywhere
    would mangle ordinary words in the message for no real protection.
    """
    parsed = urlsplit(url)
    values = [parsed.password or "", parsed.username or ""]
    values += [v for k, v in parse_qsl(parsed.query) if _SECRETISH_PARAM.search(k)]
    return sorted({v for v in values if len(v) >= 5}, key=len, reverse=True)


def _scrub(text: str, secrets: list[str]) -> str:
    """Shape-based redaction first, then removal of known literal values."""
    text = redact_text(text)
    for secret in secrets:
        text = text.replace(secret, REDACTED)
    return text


def _safe_source(url: str) -> str:
    """The source URL as it may be shown: host and path kept, secrets gone."""
    return _scrub(url, _url_secrets(url))


def _safe_fetch_error(url: str, exc: BaseException, secrets: list[str]) -> str:
    """A structured, display-safe line for one failed source.

    Never `f"{url}: {exc}"`: both halves repeat whatever secret the user put in
    `--source`. The exception is reduced to its class name plus a scrubbed
    message so the failure stays diagnosable without the credential.

    `secrets` covers EVERY source of this run, not only the one that failed: a
    redirect or fallback makes the error for source A quote source B's URL.
    """
    return f"{_safe_source(url)}: {type(exc).__name__}: {_scrub(str(exc), secrets)}"


def _read_capped(resp) -> str:
    """Read at most MAX_FETCH_BYTES of a streamed response body.

    `resp.text` buffers the whole body, so a proxy-list URL — which the user
    may have copied from anywhere — could stream gigabytes into memory. The
    partial final line is dropped so truncation cannot invent a mangled entry.
    """
    chunks: list[bytes] = []
    total = 0
    for chunk in resp.iter_content(chunk_size=65536):
        if not chunk:
            continue
        chunks.append(chunk)
        total += len(chunk)
        if total >= MAX_FETCH_BYTES:
            break
    body = b"".join(chunks)
    if total >= MAX_FETCH_BYTES:
        print_warn(f"Proxy list truncated at {MAX_FETCH_BYTES} bytes.")
        body = body.rpartition(b"\n")[0]
    return body.decode("utf-8", errors="replace")


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
@click.pass_context
def proxy_fetch(
    ctx: click.Context, protocol: str, source: str | None, limit: int, timeout: int
) -> None:
    """Pull a list of free proxies from a public source and add them to the pool."""
    import requests

    sources = [source] if source else _DEFAULT_FETCH_SOURCES.get(protocol, [])
    if not sources:
        print_error(f"No fetch source configured for protocol {protocol}")
        return

    # No pool read here: the egress proxy for the fetch comes from the
    # selector below, and the pool that gets WRITTEN is re-read inside the
    # transaction, so there is nothing to load up front.
    fetched: list[str] = []
    # Fetching the proxy list is itself outbound traffic, so it obeys the same
    # policy: under force mode it routes through an already-known proxy and is
    # refused when none exists (bootstrap a first proxy with `mb proxy add`).
    from ..proxy.selector import ProxyRequiredError, ProxySelector

    selector = ProxySelector.from_config(ctx.obj["config"])
    added = 0
    errors: list[str] = []
    # Every source in this run is user-supplied, and any of them can surface in
    # any error message, so they are scrubbed as one set.
    secrets = sorted(
        {s for u in sources for s in _url_secrets(u)},
        key=len,
        reverse=True,
    )
    for url in sources:
        try:
            request_proxies, _picked = selector.select()
            resp = requests.get(url, timeout=timeout, proxies=request_proxies, stream=True)
            try:
                resp.raise_for_status()
                body = _read_capped(resp)
            finally:
                resp.close()
        except ProxyRequiredError as exc:
            print_error(redact_text(str(exc)))
            ctx.exit(1)
        except Exception as exc:  # noqa: BLE001
            # Sanitized at APPEND time, not at print time: `errors` is the one
            # thing that outlives this frame, so a future consumer of it
            # (machine output, a log line) cannot reintroduce the leak.
            errors.append(_safe_fetch_error(url, exc, secrets))
            continue
        for raw in body.splitlines():
            line = raw.strip()
            if not line:
                continue
            if added >= limit:
                break
            if "://" not in line:
                line = f"{protocol}://{line}"
            fetched.append(line)
            added += 1
        if added >= limit:
            break

    if added == 0:
        # One line per source. The old `Errors: {errors}` printed a Python repr
        # of raw exception strings - the source URL and its credentials twice.
        print_error(f"No proxies fetched ({len(errors)} source error(s)).")
        for e in errors:
            print_error(e)
        return

    # The lock is taken only for the merge, never across the network fetch -
    # holding it for a multi-second HTTP round trip would stall every other
    # proxy command for no benefit.
    with pool_transaction() as live:
        for url in fetched:
            live.add(url)
    print_success(f"Fetched {added} {protocol} proxy/proxies.")
    if errors:
        for e in errors:
            print_error(e)
