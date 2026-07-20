"""High-level MEGA client: login, session management, file/folder operations.

The behaviour lives in cohesive sibling modules; this module composes them
into `MegaClient` and stays the import surface every caller uses:

* `responses`     - response-shape guards (`_expect_mapping`, ...)
* `nodes`         - `MegaNode`, node decryption, listings and lookups
* `auth`          - `MegaSession`, login, RSA session-ID decoding, teardown
* `cloud`         - mkdir / delete / move / rename / empty trash
* `shares`        - public link export and share import
* `session_store` - encrypted session file persistence
"""

from __future__ import annotations

import logging

from .api import MegaAPIClient
from .auth import AuthOperations, MegaSession
from .cloud import CloudOperations
from .nodes import MegaNode
from .session_store import SessionPersistence
from .shares import ShareOperations

__all__ = [
    "MegaClient",
    "MegaNode",
    "MegaSession",
]

log = logging.getLogger(__name__)


class MegaClient(AuthOperations, CloudOperations, ShareOperations, SessionPersistence):
    """High-level MEGA client.

    Wraps MegaAPIClient and adds login, session restoration, and node decryption.
    """

    def __init__(self, api: MegaAPIClient | None = None):
        self.api = api or MegaAPIClient()
        self.session: MegaSession | None = None
        self._node_cache: list[MegaNode] | None = None
