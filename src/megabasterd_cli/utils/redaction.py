"""Central secret redaction for machine output, config display, and logs.

One place decides what a secret looks like so every user-facing surface
(JSONL records, `config show/get`, warnings) redacts the same way. Redaction
is recursive: it walks nested dicts/lists/tuples, not only top-level fields.
"""

from __future__ import annotations

import re

REDACTED = "<redacted>"
REDACTED_KEY = "#<key>"

# Config/field names whose VALUE is always a secret, wherever they appear
# (top level or nested inside elc_accounts / structured records).
SECRET_FIELD_NAMES = frozenset(
    {
        "connect_proxy_password",
        "password",
        "api_key",
        "apikey",
        "vault_passphrase",
        "passphrase",
        "mfa",
        "mfa_code",
        "sid",
        "session_id",
        "master_key",
        "aes_key",
        "file_key",
        "token",
        "access_token",
        "secret",
    }
)

# MEGA link with a #<key> fragment (file/folder/legacy). Keep the public id,
# drop the key material.
_MEGA_LINK_KEY = re.compile(r"(mega(?:\.co)?\.nz/[^\s#]*)#[^\s\"']+", re.IGNORECASE)
# Secret-bearing query parameters anywhere in a string.
_SECRET_QUERY = re.compile(
    r"(?i)\b(sid|token|access_token|api_key|apikey|password|passphrase|mfa)=([^&\s\"']+)"
)
# mega:// wrappers (elc/enc/fenc) also carry key material after a fragment.
_MEGA_SCHEME_KEY = re.compile(r"(mega://[^\s#]*)#[^\s\"']+", re.IGNORECASE)

# Fields whose value is an INTENTIONAL public link the caller wants emitted
# in full (a share link the user asked to generate). These keep their key
# fragment; secret query params are still scrubbed.
LINK_OUTPUT_FIELDS = frozenset({"share_link", "public_link"})


def redact_link(value: str) -> str:
    """Strip the key fragment from a MEGA URL for on-screen summaries."""
    if "#" in value:
        base, _fragment = value.split("#", 1)
        return f"{base}#<key>"
    return value


def redact_text(value: str) -> str:
    """Redact secret substrings inside an arbitrary string.

    Handles MEGA link keys, mega:// wrappers, and secret query parameters —
    the shapes that leak through ``str(exc)`` into machine/log output.
    """
    value = _MEGA_LINK_KEY.sub(r"\1#<key>", value)
    value = _MEGA_SCHEME_KEY.sub(r"\1#<key>", value)
    value = _SECRET_QUERY.sub(lambda m: f"{m.group(1)}=<redacted>", value)
    return value


def sanitize(value, _field: str | None = None):
    """Recursively redact secrets in a JSON-serializable structure.

    A value whose *field name* is a known secret is replaced wholesale;
    intentional link-output fields keep their key fragment; all other strings
    are scrubbed for embedded secret substrings and containers are walked
    element by element.
    """
    field = _field.lower() if _field is not None else None
    if field is not None and field in SECRET_FIELD_NAMES:
        return REDACTED if value is not None else None
    if isinstance(value, dict):
        return {k: sanitize(v, _field=str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [sanitize(v) for v in value]
    if isinstance(value, str):
        if field in LINK_OUTPUT_FIELDS:
            # Keep the full public link; only strip secret query params.
            return _SECRET_QUERY.sub(lambda m: f"{m.group(1)}=<redacted>", value)
        return redact_text(value)
    return value
