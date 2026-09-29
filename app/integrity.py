"""
Phase 4: file integrity checking.

Two independent checks exist in SafeVault, deliberately layered:

1. AT-REST check (this module): SHA-256 of the ciphertext blob on disk,
   compared against `File.encrypted_hash` recorded at upload time. Requires
   NO password. Can run any time — on every download, or as a periodic scan
   over the whole uploads/ folder (useful for the Phase 6 admin panel).
   Catches: disk corruption, a file swapped/modified out-of-band, bit rot.

2. POST-DECRYPT check (in crypto_engine.decrypt_bytes): SHA-256 of the
   recovered PLAINTEXT, compared against `File.file_hash`. Requires the
   correct password, since you need the plaintext to hash it. This is
   defense-in-depth on top of AES-GCM's own auth tag — belt and suspenders,
   not strictly required, but cheap and makes tampering detection explicit
   and loggable rather than implicit in "decrypt() raised an exception".

Neither check can tell you *why* something failed (wrong password vs.
tampering) — see crypto_engine.DecryptionError for why that's intentional.
This module only answers "does the ciphertext on disk match what we stored
at upload time?" — a yes/no, independent of any password.
"""

import hashlib
from dataclasses import dataclass


def sha256_of_file(file_path: str, chunk_size: int = 65536) -> str:
    """Compute the SHA-256 hex digest of a file on disk, streaming it in
    chunks so this works fine on large files without loading them fully
    into memory."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()


@dataclass
class IntegrityResult:
    ok: bool
    expected_hash: str
    actual_hash: str

    def __bool__(self):
        return self.ok


def verify_file_at_rest(file_path: str, expected_encrypted_hash: str) -> IntegrityResult:
    """
    Check whether the ciphertext currently on disk still matches the hash
    recorded when it was uploaded. Does NOT require a password and does NOT
    decrypt anything — safe to run on every file, anytime.

    Use this:
      - before attempting a decrypt, to fail fast with a clear message
      - in a periodic admin/background scan across all stored files
      - in tests, to simulate and detect manual file corruption (Phase 8)
    """
    actual_hash = sha256_of_file(file_path)
    return IntegrityResult(
        ok=(actual_hash == expected_encrypted_hash),
        expected_hash=expected_encrypted_hash,
        actual_hash=actual_hash,
    )
