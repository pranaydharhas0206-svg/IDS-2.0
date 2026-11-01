"""Cryptographic hashing for evidence integrity verification."""

import hashlib
from pathlib import Path

CHUNK_SIZE = 1024 * 1024


def sha256_file(path: Path) -> str:
    """Return the SHA-256 hex digest of a file, streamed in chunks."""
    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_file(path: Path, expected_hash: str) -> bool:
    """Recompute a file's hash and compare against a previously recorded value."""
    return sha256_file(path) == expected_hash
