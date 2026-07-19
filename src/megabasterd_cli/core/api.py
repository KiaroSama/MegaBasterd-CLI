"""Low-level MEGA API client.

This module handles raw JSON-RPC requests to MEGA's API endpoints. Higher-level
operations (login, file listing, transfers) build on top of this.

MEGA uses a simple request/response JSON protocol:
- POST https://g.api.mega.co.nz/cs
- Body is a JSON array of command objects
- Response is a JSON array of result objects (or a single negative int on error)

The session ID (`sid`) and a sequence number (`sn`) are passed as query params.
"""

from __future__ import annotations

import json
import logging
import random
import time
from typing import Any

import requests
from tenacity import Retrying, retry_if_exception_type, stop_after_attempt, wait_exponential

from ..proxy.selector import ProxySelector
from .errors import MegaError, RateLimitError, raise_for_code

# --- Retry policy -----------------------------------------------------------
# Actions whose replay has no side effects. Everything NOT listed here is
# treated as MUTATING, so a newly added command can never accidentally inherit
# unsafe retries by omission.
READ_ONLY_ACTIONS = frozenset(
    {
        "ug",  # user info
        "uq",  # quota / storage usage
        "g",  # file download URL (public or owned)
        "f",  # folder / node listing
        "us0",  # pre-login salt lookup
        # `us` (login) is retryable on purpose: it creates no user-visible
        # state, returns the same credentials for the same inputs, and a
        # flaky network would otherwise fail logins that are safe to repeat.
        "us",
    }
)
# Deliberately NOT read-only, so they take the mutating path:
#   p   register uploaded node / create folder   d   delete (to trash)
#   m   move node                                a   rename / set attributes
#   l   export or unexport a public link         u   request an upload slot
#   sml log out (destroys the session)


# Bounded backoff shared by both retry paths. Read at call time so tests can
# neutralize the sleeps without touching the policy itself.
RETRY_ATTEMPTS = 5
RETRY_WAIT = wait_exponential(multiplier=2, min=2, max=30)


def _retrying(retry_on: tuple) -> Retrying:
    return Retrying(
        retry=retry_if_exception_type(retry_on),
        stop=stop_after_attempt(RETRY_ATTEMPTS),
        wait=RETRY_WAIT,
        reraise=True,
    )


class HashcashBudgetExceededError(MegaError):
    """One request spent its whole hashcash allowance without getting through.

    The 402 retry loop solves a FRESH challenge per attempt, so a per-solve
    timeout was multiplied by the attempt count: an attacker-chosen easiness
    could hold a single API call for minutes of full-CPU work. The budget is
    now computed once per request and shared by every attempt.
    """


class AmbiguousMutationError(MegaError):
    """A state-changing request failed after it may already have been applied.

    Raised instead of silently replaying the command. The caller must reconcile
    the remote state (or ask the user) before issuing another mutation.
    """


def _actions_of(commands) -> set[str]:
    payload = commands if isinstance(commands, list) else [commands]
    actions = set()
    for command in payload:
        if isinstance(command, dict):
            action = command.get("a")
            actions.add(action if isinstance(action, str) else "<unknown>")
        else:
            actions.add("<unknown>")
    return actions


def is_mutating(commands) -> bool:
    """True unless EVERY action in the batch is known to be side-effect free."""
    return not _actions_of(commands) <= READ_ONLY_ACTIONS


log = logging.getLogger(__name__)


API_BASE_URL = "https://g.api.mega.co.nz"
DEFAULT_TIMEOUT = 30
DEFAULT_APP_KEY = "BdARkQSQ"

# A MEGA `f` listing for a huge account is the largest legitimate response and
# stays well under this. Anything bigger is a proxy error page, a redirect
# chain or a hostile body, and must not be handed to the JSON parser.
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
RESPONSE_CHUNK_BYTES = 64 * 1024

# Total wall-clock one request may spend on hashcash, ACROSS all 402 retries.
# hashcash.DEFAULT_TIMEOUT_S is the per-solve cap for direct callers; this is
# the cap for the whole phase, so extra attempts cost patience, not minutes.
HASHCASH_TOTAL_BUDGET_S = 30.0

# HTTP statuses that are the PROXY's own refusal rather than MEGA's answer.
# Every other 4xx/5xx came from the origin and says nothing about proxy health:
# blaming the proxy for those is how three MEGA-side 503s used to put a
# blameless proxy on a 60s cooldown (and, under force_smart_proxy, turned the
# next call into a ProxyRequiredError).
PROXY_FAULT_STATUSES = frozenset({407})


def _parse_body(response) -> Any:
    """Return the parsed JSON body, or raise MegaError if it is not usable.

    Guards the boundary in the order that costs least: declared size, then
    content type, then the actual parse. A captive portal answering HTTP 200
    with an HTML login page fails here with a typed, actionable error instead
    of surfacing later as `Error: 'p'` from the CLI catch-all.
    """
    headers = getattr(response, "headers", None) or {}
    declared = str(headers.get("Content-Length") or "")
    if declared.isdigit() and int(declared) > MAX_RESPONSE_BYTES:
        raise MegaError(
            message=f"MEGA API response too large ({declared} bytes); refusing to parse it"
        )
    content_type = str(headers.get("Content-Type") or "")
    if content_type and "json" not in content_type.lower():
        raise MegaError(
            message=(
                f"MEGA API returned {content_type!r} instead of JSON "
                "(a proxy or captive portal may have replaced the response)"
            )
        )
    try:
        return json.loads(_read_bounded(response))
    except ValueError as exc:
        raise MegaError(message="MEGA API returned a body that is not valid JSON") from exc


def _read_bounded(response) -> str:
    """Return the body as text, refusing to buffer more than MAX_RESPONSE_BYTES.

    Requires `stream=True`. Reading `response.content`/`.json()` first and
    checking the length afterwards is no defence at all: by then `requests` has
    downloaded the whole body AND transparently inflated any
    `Content-Encoding: gzip`, so a bomb is fully materialised before the cap is
    consulted. `iter_content` yields the DECODED bytes, so the cap applies to
    what actually lands in memory and an oversized body is dropped mid-read.
    """
    total = 0
    parts: list[bytes] = []
    for block in response.iter_content(chunk_size=RESPONSE_CHUNK_BYTES):
        total += len(block)
        if total > MAX_RESPONSE_BYTES:
            response.close()
            raise MegaError(message="MEGA API response too large; refusing to parse it")
        parts.append(block)
    encoding = getattr(response, "encoding", None) or "utf-8"
    return b"".join(parts).decode(encoding, errors="replace")


def default_user_agent() -> str:
    """Default User-Agent derived from the package version (no drift)."""
    from .. import __version__

    return f"MegaBasterd-CLI/{__version__}"


# Backward-compatible module constant (kept for imports; now version-accurate).
USER_AGENT = default_user_agent()


class MegaAPIClient:
    """Stateful client for the MEGA JSON-RPC API.

    Holds a session ID (after login), maintains a sequence counter, and
    automatically retries transient errors.
    """

    def __init__(
        self,
        timeout: int = DEFAULT_TIMEOUT,
        proxies: dict[str, str] | None = None,
        api_base: str = API_BASE_URL,
        proxy_pool=None,  # SmartProxyPool | None
        force_proxy: bool = False,
        user_agent: str | None = None,
    ):
        self.timeout = timeout
        self.api_base = api_base.rstrip("/")
        self.user_agent = user_agent or default_user_agent()
        self._sid: str | None = None
        self._seq = random.randint(0, 0xFFFFFFFF)
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": self.user_agent})
        if proxies:
            self._session.proxies.update(proxies)
        # Smart proxy pool: if set, each API request also picks a proxy and
        # reports back to the pool. `force_proxy` disallows direct connections.
        self.proxy_pool = proxy_pool
        self.force_proxy = force_proxy
        self._static_proxies = dict(proxies) if proxies else None
        # Non-secret identity instrumentation: lets tests and -vv runs prove
        # that independent parallel transfers use distinct client/session
        # objects (never log SIDs or keys here).
        log.debug("MegaAPIClient created client_id=%s session_id=%s", id(self), id(self._session))

    def clone(self) -> MegaAPIClient:
        """Return an independent client sharing configuration and SID.

        The clone owns its own `requests.Session` and sequence counter, so
        parallel transfers never share mutable HTTP/sequence state. The proxy
        pool object is intentionally shared (it is explicitly thread-safe).
        """
        dup = MegaAPIClient(
            timeout=self.timeout,
            proxies=self._static_proxies,
            api_base=self.api_base,
            proxy_pool=self.proxy_pool,
            force_proxy=self.force_proxy,
            user_agent=self.user_agent,
        )
        dup.set_session(self._sid)
        return dup

    def _request_proxies(self) -> tuple[dict[str, str] | None, str | None]:
        """Per-request proxy decision, delegated to the shared selector."""
        return ProxySelector(
            pool=self.proxy_pool, static=self._static_proxies, force=self.force_proxy
        ).select()

    # ------------------------------------------------------------------
    # Session
    # ------------------------------------------------------------------
    @property
    def session_id(self) -> str | None:
        return self._sid

    def set_session(self, sid: str | None) -> None:
        self._sid = sid

    def clear_session(self) -> None:
        self._sid = None

    def close(self) -> None:
        self._session.close()

    def __enter__(self) -> MegaAPIClient:
        return self

    def __exit__(self, *exc_info) -> None:
        self.close()

    # ------------------------------------------------------------------
    # Requests
    # ------------------------------------------------------------------
    def _build_url(self, extra_params: dict[str, str] | None = None) -> str:
        self._seq += 1
        params = [f"id={self._seq}", f"ak={DEFAULT_APP_KEY}"]
        if self._sid:
            params.append(f"sid={self._sid}")
        if extra_params:
            for k, v in extra_params.items():
                params.append(f"{k}={v}")
        return f"{self.api_base}/cs?" + "&".join(params)

    def request(
        self,
        commands: list[dict[str, Any]] | dict[str, Any],
        extra_params: dict[str, str] | None = None,
    ) -> Any:
        """Send an API request under the retry policy its actions deserve.

        Read-only actions keep bounded retries on any transport error. A
        MUTATING action is never blindly replayed after the server may already
        have committed it: see `_send_mutating`.
        """
        if is_mutating(commands):
            return self._send_mutating(commands, extra_params)
        return self._send_retrying(commands, extra_params)

    def _send_mutating(
        self,
        commands: list[dict[str, Any]] | dict[str, Any],
        extra_params: dict[str, str] | None = None,
    ) -> Any:
        """Send a state-changing request with provably-safe retries only.

        Retried:
          * RateLimitError - MEGA rate-limiting (-4) means the server DECLINED to
            process the command, so nothing was committed;
          * ConnectTimeout - the connection was never established, so the
            request was never sent.

        Not retried: a read timeout or a connection dropped mid-flight. Those
        are ambiguous - the server may have applied the change already - and
        replaying them is how duplicate nodes, double imports and double moves
        happen. The caller gets AmbiguousMutationError and decides.
        """
        try:
            return _retrying((RateLimitError, requests.ConnectTimeout))(
                self._send, commands, extra_params
            )
        except requests.ConnectTimeout:
            raise
        except (requests.ConnectionError, requests.Timeout) as exc:
            action = ",".join(sorted(_actions_of(commands)))
            log.warning(
                "Mutating request %r failed ambiguously (%s); not retrying",
                action,
                type(exc).__name__,
            )
            raise AmbiguousMutationError(
                message=(
                    f"The connection failed while a state-changing request ({action}) was "
                    "in flight, so MEGA may or may not have applied it. It was NOT retried "
                    "automatically; re-check the remote state before trying again."
                )
            ) from exc

    def _send_retrying(
        self,
        commands: list[dict[str, Any]] | dict[str, Any],
        extra_params: dict[str, str] | None = None,
    ) -> Any:
        """Bounded retries for read-only actions: replay is free of side effects."""
        return _retrying((RateLimitError, requests.ConnectionError, requests.Timeout))(
            self._send, commands, extra_params
        )

    def _send(
        self,
        commands: list[dict[str, Any]] | dict[str, Any],
        extra_params: dict[str, str] | None = None,
    ) -> Any:
        """Send a JSON-RPC request and return the parsed response.

        If a single command is sent, the single result is returned.
        If a list of commands is sent, a list of results is returned.
        Negative API codes are converted into MegaError exceptions.

        If MEGA replies HTTP 402 with an `X-Hashcash` challenge, the request is
        transparently retried with a solved nonce.
        """
        single = not isinstance(commands, list)
        payload = [commands] if single else commands

        url = self._build_url(extra_params)
        log.debug("MEGA API request: %s -> %s", url, payload)

        extra_headers: dict[str, str] = {}
        request_proxies, picked_proxy = self._request_proxies()
        # ONE deadline for the whole hashcash phase. Computed here, not per
        # attempt, so three challenges cost one budget between them.
        hashcash_deadline = time.monotonic() + HASHCASH_TOTAL_BUDGET_S
        try:
            for _attempt in range(3):  # Initial request plus up to two hashcash retries
                response = self._session.post(
                    url,
                    json=payload,
                    timeout=self.timeout,
                    headers=extra_headers,
                    proxies=request_proxies,
                    stream=True,
                )
                if response.status_code == 402 and "X-Hashcash" in response.headers:
                    from .hashcash import build_solution_header

                    challenge = response.headers["X-Hashcash"]
                    response.close()  # nothing in this body is read; free the connection
                    remaining = hashcash_deadline - time.monotonic()
                    if remaining <= 0:
                        raise HashcashBudgetExceededError(
                            message=(
                                "MEGA kept demanding hashcash proof-of-work and the "
                                f"{HASHCASH_TOTAL_BUDGET_S:g}s budget for this request ran out"
                            )
                        )
                    log.info("Solving MEGA hashcash challenge: %s", challenge.split(":", 2)[:2])
                    try:
                        extra_headers["X-Hashcash"] = build_solution_header(
                            challenge, timeout=remaining
                        )
                    except TimeoutError as exc:
                        raise HashcashBudgetExceededError(
                            message=(
                                "The MEGA hashcash challenge was not solved within the "
                                f"{HASHCASH_TOTAL_BUDGET_S:g}s budget for this request"
                            )
                        ) from exc
                    continue
                break
            response.raise_for_status()
        except (requests.ConnectionError, requests.Timeout):
            self._blame_proxy(picked_proxy)
            raise
        except requests.HTTPError as exc:
            status = getattr(getattr(exc, "response", None), "status_code", None)
            if status in PROXY_FAULT_STATUSES:
                self._blame_proxy(picked_proxy)
            raise

        # The proxy is only credited once the body is proven usable: a captive
        # portal answering 200 with HTML was otherwise rewarded on every
        # request, and SmartProxyPool.pick weights by success ratio - so the
        # broken proxy became progressively PREFERRED.
        try:
            data = _parse_body(response)
        except MegaError:
            self._blame_proxy(picked_proxy)
            raise
        if picked_proxy and self.proxy_pool is not None:
            self.proxy_pool.report_success(picked_proxy)

        log.debug("MEGA API response: %s", data)

        # Top-level negative integer = global error
        if isinstance(data, int) and not isinstance(data, bool):
            raise_for_code(data)
            raise MegaError(data)

        if not isinstance(data, list):
            raise MegaError(
                message=(
                    "MEGA API returned a "
                    f"{type(data).__name__} where an array of results was expected"
                )
            )

        # Each element may be a negative integer error.
        results = []
        for item in data:
            if isinstance(item, int) and not isinstance(item, bool) and item < 0:
                raise_for_code(item)
            results.append(item)

        if single and not results:
            raise MegaError(message="MEGA API returned an empty result array")
        return results[0] if single else results

    def _blame_proxy(self, picked_proxy: str | None) -> None:
        """Count a failure against the proxy that actually caused it."""
        if picked_proxy and self.proxy_pool is not None:
            self.proxy_pool.report_failure(picked_proxy)

    # ------------------------------------------------------------------
    # Convenience methods for common API actions
    # ------------------------------------------------------------------
    def get_user_info(self) -> dict:
        """Get account info (requires session)."""
        return self.request({"a": "ug"})

    def get_account_quota(self) -> dict:
        """Get bandwidth and storage quota usage."""
        return self.request({"a": "uq", "strg": 1, "xfer": 1, "pro": 1})

    def get_public_file_info(self, public_id: str) -> dict:
        """Get metadata for a public file link (returns size, encrypted attrs, download URL)."""
        return self.request({"a": "g", "g": 1, "p": public_id})

    def get_public_folder_listing(self, public_id: str) -> dict:
        """Get the node listing inside a public folder."""
        return self.request({"a": "f", "c": 1, "r": 1, "ca": 1}, extra_params={"n": public_id})

    def get_download_url(self, file_handle: str) -> dict:
        """Get a download URL for a file you own (uses session)."""
        return self.request({"a": "g", "g": 1, "n": file_handle})

    def request_upload(self, size: int) -> dict:
        """Get an upload URL slot for a file of the given size."""
        return self.request({"a": "u", "s": size})

    def complete_upload(
        self,
        target_handle: str,
        upload_token: str,
        encrypted_attrs: str,
        wrapped_key: str,
    ) -> dict:
        """Tell MEGA that an upload is complete and register the new node."""
        return self.request(
            {
                "a": "p",
                "t": target_handle,
                "n": [
                    {
                        "h": upload_token,
                        "t": 0,  # 0 = file
                        "a": encrypted_attrs,
                        "k": wrapped_key,
                    }
                ],
            }
        )

    # ------------------------------------------------------------------
    # Node mutations (folder create, delete, move, rename, export)
    # ------------------------------------------------------------------
    def create_folder(
        self,
        parent_handle: str,
        encrypted_attrs: str,
        wrapped_key: str,
    ) -> dict:
        """Create a new folder under `parent_handle`."""
        return self.request(
            {
                "a": "p",
                "t": parent_handle,
                "n": [
                    {
                        "h": "xxxxxxxx",  # MEGA replaces with the real handle
                        "t": 1,  # 1 = folder
                        "a": encrypted_attrs,
                        "k": wrapped_key,
                    }
                ],
            }
        )

    def delete_node(self, handle: str) -> Any:
        """Move a node into the user's trash (or empty the trash if it IS trash)."""
        return self.request({"a": "d", "n": handle})

    def move_node(self, handle: str, new_parent: str) -> Any:
        """Move a node to a different parent folder."""
        return self.request({"a": "m", "n": handle, "t": new_parent})

    def rename_node(self, handle: str, encrypted_attrs: str, wrapped_key: str) -> Any:
        """Update a node's encrypted attributes (and optionally its key)."""
        return self.request({"a": "a", "n": handle, "attr": encrypted_attrs, "key": wrapped_key})

    def export_node(self, handle: str) -> Any:
        """Get a public link handle for an owned node.

        Returns the 8-byte public handle (base64). The full public URL is built
        on the client side using the node key.
        """
        return self.request({"a": "l", "n": handle})

    def remove_export(self, handle: str) -> Any:
        """Disable the public link on an owned node."""
        return self.request({"a": "l", "n": handle, "d": 1})

    def import_node_from_share(
        self,
        target_parent: str,
        source_handle: str,
        encrypted_attrs: str,
        wrapped_key: str,
        share_handle: str,
        node_type: int = 0,
    ) -> dict:
        """Import a node from a shared folder into the user's own tree.

        `node_type` must be 0 (file) or 1 (folder). Callers iterating the
        listing should set it from the source node's `t` field — otherwise
        MEGA records every imported node as a file, which destroys folder
        hierarchy.
        """
        if node_type not in (0, 1):
            raise ValueError(f"node_type must be 0 or 1, got {node_type!r}")
        return self.request(
            {
                "a": "p",
                "t": target_parent,
                "n": [
                    {
                        "h": source_handle,
                        "t": node_type,
                        "a": encrypted_attrs,
                        "k": wrapped_key,
                    }
                ],
                "sm": 1,
            },
            extra_params={"n": share_handle},
        )

    def login_with_mfa(self, email: str, password_hash: str, mfa_code: str) -> dict:
        """Login including a TOTP/MFA code for accounts that require 2FA."""
        return self.request(
            {"a": "us", "user": email.lower(), "uh": password_hash, "mfa": mfa_code}
        )
