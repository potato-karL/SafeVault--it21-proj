"""
Core encryption engine for SafeVault.

Deliberately has ZERO Flask/DB imports — this module should be fully testable
from a plain Python shell or CLI script before it's ever wired into a route.

Design choices (documented here so they end up in your project report too):

- AES-256-GCM, not CBC. GCM is authenticated encryption: it gives you
  confidentiality AND integrity/authenticity in one primitive. A wrong
  password OR a tampered ciphertext both surface as the same failure
  (InvalidTag) at decrypt time — no separate HMAC needed.
- Key derivation: PBKDF2HMAC-SHA256 from the `cryptography` library, using
  a random 16-byte salt per file and a high iteration count (config.py).
  This key is derived fresh every time from (password + salt) and is never
  stored anywhere.
- Nonce (GCM's "IV"): 12 bytes, generated fresh per encryption with
  os.urandom. NEVER reuse a nonce with the same key — since we derive a new
  key per file (new salt), and generate a new nonce per encryption, this is
  not a concern here even across many files from the same user.
- Salt and nonce are NOT secret. They're stored alongside the ciphertext
  (see app/models/file.py) purely so decryption can reconstruct the exact
  key and parameters used at encryption time.
- Integrity hash: SHA-256 of the PLAINTEXT, computed before encryption.
  This lets Phase 4 verify decryption succeeded correctly (hash matches ->
  no corruption) independently of the GCM tag check.
"""

import os
import hashlib

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag

SALT_SIZE = 16      # bytes
NONCE_SIZE = 12      # bytes — standard/recommended size for AES-GCM
KEY_SIZE = 32      # bytes -> AES-256
DEFAULT_ITERATIONS = 390_000  # matches config.KDF_ITERATIONS; passed explicitly so
                              # this module has no dependency on Flask's config


class DecryptionError(Exception):
    """Raised when decryption fails — wrong password OR tampered/corrupted
    ciphertext. Callers should treat both cases identically: fail cleanly,
    log it, never crash the app, never reveal which of the two it was."""


def generate_salt() -> bytes:
    return os.urandom(SALT_SIZE)


def generate_nonce() -> bytes:
    return os.urandom(NONCE_SIZE)


def derive_key(password: str, salt: bytes, iterations: int = DEFAULT_ITERATIONS) -> bytes:
    """Derive a 32-byte AES-256 key from a password + salt via PBKDF2-HMAC-SHA256."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=iterations,
    )
    return kdf.derive(password.encode("utf-8"))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def encrypt_bytes(plaintext: bytes, password: str, iterations: int = DEFAULT_ITERATIONS):
    """
    Encrypt raw bytes with a password.

    Returns a dict with everything needed to store + later decrypt:
        {
            "ciphertext": bytes,     # includes the GCM auth tag, appended by AESGCM
            "salt": bytes,
            "nonce": bytes,
            "file_hash": str,        # SHA-256 hex digest of the PLAINTEXT
            "encrypted_hash": str,   # SHA-256 hex digest of the CIPHERTEXT (at-rest check)
        }
    """
    salt = generate_salt()
    nonce = generate_nonce()
    key = derive_key(password, salt, iterations)

    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, associated_data=None)

    return {
        "ciphertext": ciphertext,
        "salt": salt,
        "nonce": nonce,
        "file_hash": sha256_hex(plaintext),
        "encrypted_hash": sha256_hex(ciphertext),
    }


def decrypt_bytes(
    ciphertext: bytes,
    password: str,
    salt: bytes,
    nonce: bytes,
    expected_file_hash: str | None = None,
    iterations: int = DEFAULT_ITERATIONS,
) -> bytes:
    """
    Decrypt bytes previously produced by encrypt_bytes().

    Raises DecryptionError if:
      - the password is wrong, or
      - the ciphertext/salt/nonce was tampered with or corrupted (GCM tag
        check fails), or
      - (if expected_file_hash is given) the decrypted plaintext's SHA-256
        doesn't match what was recorded at encryption time.

    All three cases raise the SAME exception type/message on purpose —
    don't let an attacker distinguish "wrong password" from "corrupted file"
    from the outside.
    """
    key = derive_key(password, salt, iterations)
    aesgcm = AESGCM(key)

    try:
        plaintext = aesgcm.decrypt(nonce, ciphertext, associated_data=None)
    except InvalidTag as exc:
        raise DecryptionError(
            "Decryption failed: wrong password or corrupted/tampered file."
        ) from exc

    if expected_file_hash is not None:
        actual_hash = sha256_hex(plaintext)
        if actual_hash != expected_file_hash:
            # Extremely unlikely to reach this branch given GCM already
            # authenticated the ciphertext, but kept as a defense-in-depth
            # / documentation of the Phase 4 integrity check.
            raise DecryptionError(
                "Decryption failed: wrong password or corrupted/tampered file."
            )

    return plaintext
