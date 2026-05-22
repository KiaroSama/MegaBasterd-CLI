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

import logging
import random
from typing import Any

import requests
from tenacity import retry, retry_if_exception_type, stop_after_attempt, wait_exponential

from .errors import MegaError, RateLimitError, raise_for_code

log = logging.getLogger(__name__)


API_BASE_URL = "https://g.api.mega.co.nz"
DEFAULT_TIMEOUT = 30
USER_AGENT = "MegaBasterd-CLI/1.0"
DEFAULT_APP_KEY = "BdARkQSQ"


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
    ):
        self.timeout = timeout
        self.api_base = api_base.rstrip("/")
        self._sid: str | None = None
        self._seq = random.randint(0, 0xFFFFFFFF)
        self._session = requests.Session()
        self._session.headers.update({"User-Agent": USER_AGENT})
        if proxies:
            self._session.proxies.update(proxies)
        # Smart proxy pool: if set, each API request also picks a proxy and
        # reports back to the pool. `force_proxy` disallows direct connections.
        self.proxy_pool = proxy_pool
        self.force_proxy = force_proxy
        self._static_proxies = dict(proxies) if proxies else None

    def _request_proxies(self) -> tuple[dict[str, str] | None, str | None]:
        """Per-request proxy decision for API calls (mirrors downloader logic).

        Precedence:
          1. Pool pick (smart proxy)
          2. Static proxies (from manual --proxy)
          3. Refuse if force_proxy is on, else direct
        """
        if self.proxy_pool is not None:
            entry = self.proxy_pool.pick()
            if entry is not None:
                return {"http": entry.url, "https": entry.url}, entry.url
        if self._static_proxies:
            return self._static_proxies, None
        if self.force_proxy:
            raise MegaError(
                message="force_smart_proxy is on but no proxy is available "
                "for an API call (pool empty, no --proxy)"
            )
        return None, None

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

    @retry(
        retry=retry_if_exception_type((RateLimitError, requests.ConnectionError, requests.Timeout)),
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=2, min=2, max=30),
        reraise=True,
    )
    def request(
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
        try:
            for _attempt in range(3):  # Initial request plus up to two hashcash retries
                response = self._session.post(
                    url,
                    json=payload,
                    timeout=self.timeout,
                    headers=extra_headers,
                    proxies=request_proxies,
                )
                if response.status_code == 402 and "X-Hashcash" in response.headers:
                    from .hashcash import build_solution_header

                    challenge = response.headers["X-Hashcash"]
                    log.info("Solving MEGA hashcash challenge: %s", challenge.split(":", 2)[:2])
                    extra_headers["X-Hashcash"] = build_solution_header(challenge)
                    continue
                break
            response.raise_for_status()
        except (requests.ConnectionError, requests.Timeout):
            if picked_proxy and self.proxy_pool is not None:
                self.proxy_pool.report_failure(picked_proxy)
            raise
        except requests.HTTPError:
            if picked_proxy and self.proxy_pool is not None:
                self.proxy_pool.report_failure(picked_proxy)
            raise
        if picked_proxy and self.proxy_pool is not None:
            self.proxy_pool.report_success(picked_proxy)

        data = response.json()
        log.debug("MEGA API response: %s", data)

        # Top-level negative integer = global error
        if isinstance(data, int):
            raise_for_code(data)
            raise MegaError(data)

        # Each element may be a negative integer error.
        results = []
        for item in data:
            if isinstance(item, int) and item < 0:
                raise_for_code(item)
            results.append(item)

        return results[0] if single else results

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
