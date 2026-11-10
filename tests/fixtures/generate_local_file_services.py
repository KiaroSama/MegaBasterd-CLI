"""Synthetic source-oracle fixtures; run with an existing interpreter using -I."""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import struct
import sys
import tempfile
import types
from pathlib import Path


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError("Cannot load the reviewed source oracle")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True, type=Path)
    args = parser.parse_args()
    root = args.root.resolve(strict=True)
    source = root / "src/megabasterd_cli/core"
    package = types.ModuleType("local_oracle")
    package.__path__ = [str(source)]
    sys.modules["local_oracle"] = package
    crypter = load("local_oracle.crypter", source / "crypter.py")
    splitter = load("local_oracle.splitter", source / "splitter.py")
    thumbnail = load("local_oracle.thumbnail", source / "thumbnail.py")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from PIL import Image

    target = root / "tests/fixtures/local_file_services.json"
    if target.exists() and json.loads(target.read_text(encoding="utf-8")).get("source_baseline") != "c4559ec":
        raise FileExistsError("Refusing to replace an unrelated oracle fixture")
    fixture = {"source_baseline": "c4559ec", "synthetic_only": True, "mbcr": []}
    with tempfile.TemporaryDirectory(prefix="local-oracle-", dir=target.parent) as directory:
        scratch = Path(directory)
        password = "synthetic-test-passphrase-é"
        for label, payload in (("empty", b""), ("multi", bytes(range(73)))):
            plain, encrypted, recovered = (scratch / name for name in ("plain", "enc", "out"))
            plain.write_bytes(payload)
            counter = 0
            original = crypter.os.urandom

            def deterministic(size: int) -> bytes:
                nonlocal counter
                counter += 1
                return bytes((counter * 17 + i) % 256 for i in range(size))

            crypter.os.urandom = deterministic
            try:
                crypter.encrypt_file(plain, encrypted, password, chunk_size=16)
            finally:
                crypter.os.urandom = original
            crypter.decrypt_file(encrypted, recovered, password)
            assert recovered.read_bytes() == payload
            fixture["mbcr"].append({"name": label, "version": 2, "password": password,
                                    "plaintext_hex": payload.hex(), "blob_hex": encrypted.read_bytes().hex()})
        salt = bytes(range(16))
        key = crypter._derive_key(password, salt)
        payload = b"legacy individually authenticated chunks"
        blob = crypter.MAGIC + b"\x01" + salt + struct.pack(">I", 16)
        cipher = AESGCM(key)
        for index, offset in enumerate(range(0, len(payload), 16)):
            nonce = bytes([index + 1]) * 12
            block = nonce + cipher.encrypt(nonce, payload[offset:offset + 16], None)
            blob += struct.pack(">I", len(block)) + block
        blob += b"\0" * 4
        (scratch / "enc").write_bytes(blob)
        crypter.decrypt_file(scratch / "enc", scratch / "out", password)
        assert (scratch / "out").read_bytes() == payload
        fixture["mbcr"].append({"name": "legacy", "version": 1, "password": password,
                                "plaintext_hex": payload.hex(), "blob_hex": blob.hex()})
        payload = bytes(range(256)) * 4096 + b"odd tail"
        (scratch / "split.bin").write_bytes(payload)
        split = splitter.split_file(scratch / "split.bin", 1)
        merged = splitter.merge_parts(split.parts[1], output=scratch / "merged")
        assert merged.read_bytes() == payload
        fixture["split"] = {"pattern_repeats": 4096, "tail_hex": b"odd tail".hex(),
                            "part_names": [part.name for part in split.parts],
                            "part_sizes": [part.stat().st_size for part in split.parts],
                            "sha1_file": (scratch / "split.bin.sha1").read_text(encoding="ascii"),
                            "total_bytes": split.total_bytes}
        fixture["images"] = []
        for label, dimensions, mode in (("wide", (500, 100), "RGB"), ("small", (23, 17), "RGB"),
                                         ("alpha", (80, 120), "RGBA"), ("tall", (100, 500), "P"),
                                         ("odd-aspect", (501, 333), "RGB")):
            png, jpg = scratch / "synthetic.png", scratch / "thumbnail.jpg"
            color = 3 if mode == "P" else ((60, 120, 180, 0) if mode == "RGBA" else (60, 120, 180))
            image = Image.new(mode, dimensions, color)
            image.save(png, "PNG")
            assert thumbnail.create_thumbnail(png, jpg)
            with Image.open(jpg) as output:
                fixture["images"].append({"name": label, "input_png_hex": png.read_bytes().hex(),
                                           "width": output.width, "height": output.height,
                                           "mode": output.mode, "jpeg_sha256": hashlib.sha256(jpg.read_bytes()).hexdigest()})
    with target.open("w", encoding="utf-8", newline="\n") as output:
        json.dump(fixture, output, indent=2, ensure_ascii=False)
        output.write("\n")
    print("Synthetic source fixtures generated; Rust/real-codec parity remains CI-pending.")


if __name__ == "__main__":
    main()
