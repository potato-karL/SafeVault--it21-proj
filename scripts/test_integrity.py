"""
Standalone CLI test for Phase 4: file integrity checking.

Run with:  python scripts/test_integrity.py

This simulates the real lifecycle of a stored file:
  1. Encrypt some data and write the ciphertext to disk (like upload does).
  2. Verify the at-rest hash matches right after writing (sanity check).
  3. Manually corrupt bytes ON DISK (simulating disk corruption or tampering
     that happens to the stored file itself, independent of any decrypt
     attempt) — this is the exact scenario from Phase 8's test plan.
  4. Confirm the at-rest integrity check catches it WITHOUT needing a
     password or attempting decryption.
  5. Confirm that attempting to decrypt the corrupted file also fails
     cleanly (defense in depth — two independent checks catch the same
     problem for two different reasons).
"""

import sys
import os
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app.crypto_engine import encrypt_bytes, decrypt_bytes, DecryptionError
from app.integrity import verify_file_at_rest, sha256_of_file


def section(title):
    print(f"\n{'=' * 60}\n{title}\n{'=' * 60}")


def main():
    password = "vault-password-42"
    plaintext = b"Sensitive report contents that must not be silently corrupted."

    with tempfile.TemporaryDirectory() as tmpdir:
        stored_path = os.path.join(tmpdir, "0001.enc")

        # --- Step 1: Encrypt and write to disk, like the upload route will
        section("Step 1: Encrypt and write ciphertext to disk")
        result = encrypt_bytes(plaintext, password)
        with open(stored_path, "wb") as f:
            f.write(result["ciphertext"])
        print(f"Wrote {os.path.getsize(stored_path)} bytes to {stored_path}")
        print(f"Recorded encrypted_hash: {result['encrypted_hash']}")

        # --- Step 2: Verify integrity immediately (should pass) ----------
        section("Step 2: Verify at-rest integrity right after writing (expect OK)")
        check = verify_file_at_rest(stored_path, result["encrypted_hash"])
        print(f"Match: {check.ok}")
        assert check.ok, "FAIL: freshly written file should match its own hash!"
        print("PASS: at-rest hash matches immediately after upload.")

        # --- Step 3: Corrupt the file ON DISK -----------------------------
        section("Step 3: Manually corrupt the stored file on disk")
        with open(stored_path, "r+b") as f:
            f.seek(5)
            byte = f.read(1)
            f.seek(5)
            f.write(bytes([byte[0] ^ 0xFF]))
        print("Flipped one byte at offset 5 in the stored file (simulates corruption).")

        # --- Step 4: At-rest check should now catch it, no password needed
        section("Step 4: Re-run at-rest integrity check (expect MISMATCH, no password used)")
        check = verify_file_at_rest(stored_path, result["encrypted_hash"])
        print(f"Expected hash: {check.expected_hash}")
        print(f"Actual hash:   {check.actual_hash}")
        print(f"Match: {check.ok}")
        assert not check.ok, "FAIL: corruption should have been detected but wasn't!"
        print("PASS: at-rest check caught the corruption without needing a password.")

        # --- Step 5: Decrypt attempt should ALSO fail (defense in depth) -
        section("Step 5: Attempting to decrypt the corrupted file (expect clean failure)")
        with open(stored_path, "rb") as f:
            corrupted_ciphertext = f.read()
        try:
            decrypt_bytes(
                corrupted_ciphertext, password, result["salt"], result["nonce"],
                expected_file_hash=result["file_hash"],
            )
            print("FAIL: decrypt should have raised DecryptionError but didn't!")
        except DecryptionError as e:
            print(f"PASS: decrypt also failed cleanly -> {e}")

        section("All Phase 4 integrity tests completed.")


if __name__ == "__main__":
    main()
