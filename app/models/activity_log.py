from datetime import datetime, timezone

from app import db

# Keep this list in sync with every call site that writes a log entry.
VALID_ACTIONS = {
    "login", "logout", "register",
    "upload", "encrypt", "decrypt", "download", "delete", "preview",
    "reset_password", "backup_code",
}
VALID_STATUSES = {"success", "fail"}


class ActivityLog(db.Model):
    __tablename__ = "activity_logs"

    id = db.Column(db.Integer, primary_key=True)

    # Nullable because a failed login with a bad/unknown username still needs
    # to be logged, and there's no valid user_id to attach it to.
    user_id = db.Column(db.Integer, db.ForeignKey("users.id"), nullable=True, index=True)

    action = db.Column(db.String(20), nullable=False)
    status = db.Column(db.String(10), nullable=False, default="success")
    detail = db.Column(db.String(255), nullable=True)  # e.g. "bad password", filename
    ip_address = db.Column(db.String(45), nullable=True)  # long enough for IPv6

    timestamp = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    @staticmethod
    def record(user_id, action, status="success", detail=None, ip_address=None):
        """Convenience helper — call this from every route that needs to log
        a sensitive action instead of constructing ActivityLog() by hand.
        Commits immediately so a log entry isn't lost if a later step in the
        same request raises an exception.
        """
        assert action in VALID_ACTIONS, f"Unknown action: {action}"
        assert status in VALID_STATUSES, f"Unknown status: {status}"

        entry = ActivityLog(
            user_id=user_id,
            action=action,
            status=status,
            detail=detail,
            ip_address=ip_address,
        )
        db.session.add(entry)
        db.session.commit()
        return entry

    def __repr__(self) -> str:
        return f"<ActivityLog {self.action} {self.status} user_id={self.user_id}>"
