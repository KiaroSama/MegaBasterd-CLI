# SPDX-License-Identifier: GPL-3.0-or-later
"""Generate synthetic transfer vectors from a verified 1.x source checkout.

Run with Python -I. This is offline migration tooling, not a runtime dependency.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import logging
import os
from pathlib import Path
import sys
import time
import types

sys.dont_write_bytecode = True


def load_source(root: Path, hashes: dict[str, str]) -> tuple[types.ModuleType, types.ModuleType]:
    source = root / "src" / "megabasterd_cli" / "core"
    for name in ("crypto", "chunks"):
        actual = hashlib.sha256((source / f"{name}.py").read_bytes()).hexdigest()
        if actual != hashes[name]:
            raise ValueError(f"Source oracle hash mismatch: {name}")
    package = types.ModuleType("transfer_oracle")
    package.__path__ = [str(source)]
    sys.modules[package.__name__] = package
    modules = []
    for name in ("crypto", "chunks"):
        key = f"{package.__name__}.{name}"
        spec = importlib.util.spec_from_file_location(key, source / f"{name}.py")
        if spec is None or spec.loader is None:
            raise ValueError(f"Could not load verified source: {name}")
        module = importlib.util.module_from_spec(spec)
        sys.modules[key] = module
        spec.loader.exec_module(module)
        modules.append(module)
    return modules[0], modules[1]


def write_or_check(path: Path, content: bytes, check: bool) -> None:
    if check or path.exists():
        if path.read_bytes() != content:
            raise ValueError(f"Fixture bytes differ: {path.name}")
    else:
        with path.open("xb") as stream:
            stream.write(content)


def generate(root: Path, provenance: Path, output: Path, check: bool) -> None:
    original = json.loads(provenance.read_text(encoding="utf-8"))["provenance"]
    crypto, chunks = load_source(root, original["source_sha256"])
    from Crypto import __version__ as crypto_version

    if sys.version.split()[0] != original["python"] or crypto_version != original["pycryptodome"]:
        raise ValueError("Oracle runtime differs from the pinned baseline")
    output.mkdir(parents=True, exist_ok=True)
    key, nonce = bytes(range(16)), bytes(range(8))
    vectors = []
    for size in (0, 17, 131089):
        plain = bytes((index * 13 + 7) % 256 for index in range(size))
        schedule = list(chunks.iter_chunks(size))
        macs = [chunks.chunk_mac(plain[c.offset:c.end], key, nonce) for c in schedule]
        mac = chunks.condense_mac(chunks.combine_chunk_macs(macs, key))
        raw_key = crypto.a32_to_bytes(crypto.pack_file_key(key, nonce, mac))
        ciphertext = crypto.make_ctr_cipher(key, nonce).encrypt(plain)
        if crypto.make_ctr_cipher(key, nonce).decrypt(ciphertext) != plain:
            raise ValueError("Source transfer cipher round trip failed")
        name = f"ciphertext-{size}.bin"
        write_or_check(output / name, ciphertext, check)
        vectors.append({
            "size": size,
            "raw_key": raw_key.hex(),
            "aes_key": key.hex(),
            "nonce": nonce.hex(),
            "plaintext_sha256": hashlib.sha256(plain).hexdigest(),
            "ciphertext": name,
            "ciphertext_sha256": hashlib.sha256(ciphertext).hexdigest(),
            "chunks": [{"index": c.index, "offset": c.offset, "size": c.size, "mac": m.hex()}
                       for c, m in zip(schedule, macs, strict=True)],
        })
    fixture = {
        "provenance": {**original, "python": sys.version.split()[0], "pycryptodome": crypto_version},
        "plaintext_recipe": "byte(i) = (13*i + 7) % 256",
        "vectors": vectors,
    }
    write_or_check(output / "vectors.json", (json.dumps(fixture, ensure_ascii=True, indent=2) + "\n").encode("utf-8"), check)
    logging.info("Fixture sizes=0,17,131089 source_only=true checked=%s", check)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--provenance", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--check", action="store_true", help="Verify existing bytes without overwriting")
    args = parser.parse_args()
    directory = Path(__file__).resolve().parents[2] / "Logs" / "oracle"
    try:
        directory.mkdir(parents=True, exist_ok=True)
        stamp = time.strftime("%Y-%m-%d_%H-%M-%S_UTC", time.gmtime())
        path = directory / f"transfer_fixture_{stamp}_{os.getpid()}.log"
        stream = path.open("x", encoding="utf-8", newline="\n")
        handler = logging.StreamHandler(stream)
        formatter = logging.Formatter("[%(asctime)s UTC] [%(levelname)s] [ORACLE] %(message)s", "%Y-%m-%d %H:%M:%S")
        formatter.converter = time.gmtime
        handler.setFormatter(formatter)
        logging.getLogger().addHandler(handler)
        logging.getLogger().setLevel(logging.INFO)
    except OSError:
        logging.basicConfig(level=logging.INFO, format="[%(levelname)s] [ORACLE] %(message)s")
        print("Warning: oracle file logging unavailable", file=sys.stderr)
        stream = None
    try:
        logging.info("Started offline source-only transfer fixture generation")
        generate(args.source_root.resolve(), args.provenance.resolve(), args.output.resolve(), args.check)
        logging.info("Finished exit_code=0")
        return 0
    except (OSError, ValueError, ImportError, KeyError):
        logging.exception("Fixture generation failed exit_code=1; preserve partial output for inspection")
        return 1
    finally:
        logging.shutdown()
        if stream is not None:
            stream.close()


if __name__ == "__main__":
    raise SystemExit(main())
