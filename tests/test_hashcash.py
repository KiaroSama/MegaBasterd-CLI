"""Tests for the MEGA hashcash proof-of-work solver."""

import base64
import hashlib
import struct

import pytest

from megabasterd_cli.core.hashcash import (
    BUF_SIZE,
    PREFIX_BYTES,
    REPEAT,
    TOKEN_BYTES,
    HashcashChallenge,
    build_solution_header,
    parse_challenge,
    solve,
)


def _encode_b64url(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii").rstrip("=").replace("+", "-").replace("/", "_")


def test_parse_challenge_roundtrip():
    token = b"A" * TOKEN_BYTES
    header = f"1:255:{_encode_b64url(token)}"
    ch = parse_challenge(header)
    assert ch.version == 1
    assert ch.easiness == 255
    assert ch.token == token


def test_parse_challenge_rejects_malformed():
    with pytest.raises(ValueError):
        parse_challenge("not-a-challenge")
    with pytest.raises(ValueError):
        parse_challenge("1:nope:" + _encode_b64url(b"A" * TOKEN_BYTES))


def test_solve_easy_challenge_finds_nonce():
    # Easiness 0 → threshold = 1 << 3 = 8, expect a hit within a few seconds.
    # Use a deterministic token so the test is reproducible.
    token = b"\x01" * TOKEN_BYTES
    challenge = HashcashChallenge(version=1, easiness=192, token=token)
    nonce = solve(challenge, timeout=30.0, workers=4)
    assert len(nonce) == PREFIX_BYTES

    # Independently verify the nonce
    digest = hashlib.sha256(nonce + token * REPEAT).digest()
    head = struct.unpack(">I", digest[:4])[0]
    assert head <= challenge.threshold


def test_build_solution_header_format():
    token = b"\x02" * TOKEN_BYTES
    header = f"1:192:{_encode_b64url(token)}"
    solution = build_solution_header(header, timeout=30.0)
    parts = solution.split(":")
    assert len(parts) == 4
    assert parts[0] == "1"
    assert parts[1] == "192"


def test_threshold_increases_with_easiness():
    low = HashcashChallenge(version=1, easiness=0, token=b"\0" * TOKEN_BYTES).threshold
    high = HashcashChallenge(version=1, easiness=255, token=b"\0" * TOKEN_BYTES).threshold
    assert high > low
