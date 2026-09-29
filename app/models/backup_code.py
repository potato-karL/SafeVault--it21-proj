from datetime import datetime, timezone
from werkzeug.security import generate_password_hash, check_password_hash
import secrets

from app import db


class BackupCode(db.Model):
    __tablename__ = "backup_codes"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=False, index=True)
    code_hash = db.Column(db.String(255), nullable=False)
    is_used = db.Column(db.Boolean, nullable=False, default=False)
    used_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def set_code(self, raw_code: str) -> None:
        clean_code = raw_code.strip().upper().replace("-", "")
        self.code_hash = generate_password_hash(clean_code, method="pbkdf2:sha256", salt_length=16)

    def check_code(self, raw_code: str) -> bool:
        clean_code = raw_code.strip().upper().replace("-", "")
        return check_password_hash(self.code_hash, clean_code)

    @classmethod
    def generate_codes_for_user(cls, user_id: int, count: int = 8) -> list:
        """Generates `count` single-use backup recovery codes for the user.
        Deletes existing backup codes first, stores hashes in DB, and returns
        the list of raw plaintext codes (formatted as XXXX-XXXX) so they can be shown once."""
        cls.query.filter_by(user_id=user_id).delete()
        raw_codes = []
        for _ in range(count):
            token = secrets.token_hex(4).upper()
            formatted_code = f"{token[:4]}-{token[4:]}"
            raw_codes.append(formatted_code)

            entry = cls(user_id=user_id)
            entry.set_code(formatted_code)
            db.session.add(entry)

        db.session.commit()
        return raw_codes

    @classmethod
    def verify_and_consume(cls, user_id: int, raw_code: str) -> bool:
        """Finds an unused backup code matching raw_code, marks it as used, and commits."""
        unused_codes = cls.query.filter_by(user_id=user_id, is_used=False).all()
        for code_entry in unused_codes:
            if code_entry.check_code(raw_code):
                code_entry.is_used = True
                code_entry.used_at = datetime.now(timezone.utc)
                db.session.commit()
                return True
        return False
