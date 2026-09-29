"""
Standalone CLI test for the SafeVault encryption engine.

Run with:  python scripts/test_crypto.py

Covers exactly the scenarios listed in Phase 8 of the project plan, but
run right now against the engine directly (no Flask, no DB, no HTTP) so
bugs get caught here rather than three layers deep in a route handler.
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.crypto_engine import encrypt_bytes, decrypt_bytes, DecryptionError


def section(title):
    print(f"\n{'=' * 60}\n{title}\n{'=' * 60}")


def main():
    sample_text = (
        b"This is a confidential SafeVault test document.\n"
        b"If you can read this after decrypting, round-tripping works."
    )
    password = "correct-horse-battery-staple"
    wrong_password = "not-the-right-password"

    # --- Test 1: Encrypt / decrypt round trip -----------------------------
    section("Test 1: Encrypt then decrypt with the CORRECT password")
    result = encrypt_bytes(sample_text, password)
    print(f"Plaintext size:  {len(sample_text)} bytes")
    print(f"Ciphertext size: {len(result['ciphertext'])} bytes (includes 16-byte GCM tag)")
    print(f"Salt (hex):      {result['salt'].hex()}")
    print(f"Nonce (hex):     {result['nonce'].hex()}")
    print(f"SHA-256:         {result['file_hash']}")

    recovered = decrypt_bytes(
        ciphertext=result["ciphertext"],
        password=password,
        salt=result["salt"],
        nonce=result["nonce"],
        expected_file_hash=result["file_hash"],
    )
    assert recovered == sample_text, "Round-trip FAILED: recovered text doesn't match original!"
    print("PASS: decrypted plaintext matches original exactly.")

    # --- Test 2: Wrong password should fail cleanly, not crash -----------
    section("Test 2: Decrypt with the WRONG password (should fail cleanly)")
    try:
        decrypt_bytes(
            ciphertext=result["ciphertext"],
            password=wrong_password,
            salt=result["salt"],
            nonce=result["nonce"],
            expected_file_hash=result["file_hash"],
        )
        print("FAIL: decryption should have raised DecryptionError but didn't!")
    except DecryptionError as e:
        print(f"PASS: raised DecryptionError as expected -> {e}")

    # --- Test 3: Corrupted ciphertext should be caught (integrity check) -
    section("Test 3: Tamper with the ciphertext (simulates corruption/attack)")
    tampered = bytearray(result["ciphertext"])
    tampered[0] ^= 0xFF  # flip bits in the first byte
    try:
        decrypt_bytes(
            ciphertext=bytes(tampered),
            password=password,
            salt=result["salt"],
            nonce=result["nonce"],
            expected_file_hash=result["file_hash"],
        )
        print("FAIL: decryption should have detected tampering but didn't!")
    except DecryptionError as e:
        print(f"PASS: tampering detected -> {e}")

    # --- Test 4: Different plaintexts / passwords never reuse a key+nonce -
    section("Test 4: Two encryptions of the same plaintext use different salt/nonce")
    result_a = encrypt_bytes(sample_text, password)
    result_b = encrypt_bytes(sample_text, password)
    assert result_a["salt"] != result_b["salt"], "FAIL: salts collided!"
    assert result_a["nonce"] != result_b["nonce"], "FAIL: nonces collided!"
    assert result_a["ciphertext"] != result_b["ciphertext"], "FAIL: identical ciphertexts!"
    print("PASS: salt, nonce, and ciphertext all differ across separate encryptions.")

    section("All crypto engine tests completed.")


if __name__ == "__main__":
    main()
