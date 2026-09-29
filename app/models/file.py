from datetime import datetime, timezone

from app import db


class File(db.Model):
    __tablename__ = "files"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)

    original_filename = db.Column(db.String(255), nullable=False)
    # Randomly generated name used on disk, so we never trust user input for paths
    # and never leak the real filename via the filesystem.
    stored_filename = db.Column(db.String(255), unique=True, nullable=False)

    # Stored as hex strings for readability in the DB; convert to bytes with
    # bytes.fromhex() when used in the crypto engine (Phase 3).
    salt = db.Column(db.String(64), nullable=False)   # 16 bytes -> 32 hex chars
    iv = db.Column(db.String(64), nullable=False)     # 12 or 16 bytes depending on mode

    # SHA-256 of the PLAINTEXT file, computed before encryption.
    # Decided here (and documented) so Phase 4 has an unambiguous rule to follow:
    # hashing the plaintext lets us verify correct decryption + detect tampering
    # of the ciphertext on disk in one check.
    file_hash = db.Column(db.String(64), nullable=False)

    # SHA-256 of the CIPHERTEXT as stored on disk, computed at encryption time.
    # This is the Phase 4 at-rest integrity check: it lets you verify a stored
    # file hasn't been corrupted/tampered with WITHOUT needing the user's
    # password (e.g. a periodic admin integrity scan). It's a defense-in-depth
    # addition — AES-GCM's auth tag already catches ciphertext tampering at
    # decrypt time, but that check only runs when someone tries to decrypt.
    # This one can run anytime, on every file, on a schedule.
    encrypted_hash = db.Column(db.String(64), nullable=False)

    file_size_bytes = db.Column(db.Integer, nullable=True)
    uploaded_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def __repr__(self) -> str:
        return f"<File {self.original_filename!r} owner_id={self.user_id}>"
