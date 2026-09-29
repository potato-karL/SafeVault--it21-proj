from datetime import datetime, timezone

from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

from app import db


class User(UserMixin, db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)

    # This is the AUTH password hash only (PBKDF2 via Werkzeug).
    # Do NOT reuse this for deriving file-encryption keys — see Phase 3 notes.
    password_hash = db.Column(db.String(255), nullable=False)

    role = db.Column(db.String(20), nullable=False, default="user")  # 'user' | 'admin'
    is_active_account = db.Column(db.Boolean, nullable=False, default=True)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    # --- Brute-force lockout state ---
    # Counts consecutive failed attempts; reset to 0 on any successful login.
    failed_login_attempts = db.Column(db.Integer, nullable=False, default=0)
    # Set to a future UTC timestamp once the lockout threshold is hit.
    # NULL/None means "not currently locked".
    locked_until = db.Column(db.DateTime, nullable=True)

    # --- Storage quota management ---
    # Storage quota in bytes (NULL = no limit, 0 = no uploads allowed)
    storage_quota_bytes = db.Column(db.BigInteger, nullable=True, default=None)
    # Current storage usage in bytes (updated on upload/delete)
    current_storage_bytes = db.Column(db.BigInteger, nullable=False, default=0)
    # Track when quota was last updated
    quota_updated_at = db.Column(db.DateTime, nullable=True)

    # --- Two-factor auth (TOTP) ---
    # Secret is only meaningful once totp_enabled is True; it's generated
    # at setup time and never displayed again after the user confirms it.
    totp_secret = db.Column(db.String(32), nullable=True)
    totp_enabled = db.Column(db.Boolean, nullable=False, default=False)

    files = db.relationship(
        "File", backref="owner", lazy=True, cascade="all, delete-orphan"
    )
    activity_logs = db.relationship(
        "ActivityLog", backref="user", lazy=True, cascade="all, delete-orphan"
    )
    backup_codes = db.relationship(
        "BackupCode", backref="user", lazy=True, cascade="all, delete-orphan"
    )

    def set_password(self, raw_password: str) -> None:
        # PBKDF2-SHA256 with a strong iteration count; Werkzeug picks sane defaults,
        # but we pin the method explicitly so it's obvious in code review.
        self.password_hash = generate_password_hash(
            raw_password, method="pbkdf2:sha256", salt_length=16
        )

    def check_password(self, raw_password: str) -> bool:
        return check_password_hash(self.password_hash, raw_password)

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    # --- Lockout helpers ---
    # Kept on the model (rather than duplicated in the route) so any future
    # caller — CLI script, admin "unlock" action, API — enforces the exact
    # same rule.

    def is_locked_out(self) -> bool:
        """True if the account is currently within its lockout window."""
        if self.locked_until is None:
            return False
        now = datetime.now(timezone.utc)
        locked_until = self.locked_until
        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)
        return now < locked_until

    def register_failed_login(self, max_attempts: int, lockout_minutes: int) -> None:
        """Increment the failed-attempt counter and lock the account once
        `max_attempts` consecutive failures have been reached."""
        from datetime import timedelta

        # A lock that has already expired shouldn't carry a stale counter
        # forward forever — but we still count *this* new failure.
        if self.locked_until is not None and not self.is_locked_out():
            self.failed_login_attempts = 0
            self.locked_until = None

        self.failed_login_attempts += 1
        if self.failed_login_attempts >= max_attempts:
            self.locked_until = datetime.now(timezone.utc) + timedelta(minutes=lockout_minutes)

    def reset_failed_logins(self) -> None:
        """Call on every successful login."""
        self.failed_login_attempts = 0
        self.locked_until = None

    def lockout_seconds_remaining(self) -> int:
        if not self.is_locked_out():
            return 0
        locked_until = self.locked_until
        if locked_until.tzinfo is None:
            locked_until = locked_until.replace(tzinfo=timezone.utc)
        delta = locked_until - datetime.now(timezone.utc)
        return max(0, int(delta.total_seconds()))

    # --- IP monitoring helpers ---
    
    def get_known_ips(self) -> set:
        """Return set of IP addresses this user has successfully logged in from."""
        from app.models.activity_log import ActivityLog
        
        known_ips = db.session.query(ActivityLog.ip_address).filter(
            ActivityLog.user_id == self.id,
            ActivityLog.action == "login",
            ActivityLog.status == "success",
            ActivityLog.ip_address.isnot(None)
        ).distinct().all()
        
        return {ip[0] for ip in known_ips if ip[0]}
    
    def is_new_ip(self, ip_address: str) -> bool:
        """Check if this IP address has never been used for successful login before."""
        if not ip_address:
            return False
        return ip_address not in self.get_known_ips()
    
    def get_last_login_ip(self) -> str | None:
        """Get the IP address of the most recent successful login (excluding current session)."""
        from app.models.activity_log import ActivityLog
        
        last_login = ActivityLog.query.filter(
            ActivityLog.user_id == self.id,
            ActivityLog.action == "login",
            ActivityLog.status == "success",
            ActivityLog.ip_address.isnot(None)
        ).order_by(ActivityLog.timestamp.desc()).offset(1).first()  # Skip the current login
        
        return last_login.ip_address if last_login else None

    # --- Storage quota helpers ---
    
    def has_storage_quota(self) -> bool:
        """Check if user has a storage quota limit set."""
        return self.storage_quota_bytes is not None
    
    def get_storage_quota_mb(self) -> float | None:
        """Get storage quota in MB. None if no quota set."""
        if self.storage_quota_bytes is None:
            return None
        return self.storage_quota_bytes / (1024 * 1024)
    
    def get_current_storage_mb(self) -> float:
        """Get current storage usage in MB."""
        return self.current_storage_bytes / (1024 * 1024)
    
    def get_storage_usage_percent(self) -> float | None:
        """Get storage usage as percentage. None if no quota set."""
        if not self.has_storage_quota() or self.storage_quota_bytes == 0:
            return None
        return (self.current_storage_bytes / self.storage_quota_bytes) * 100
    
    def can_upload_file(self, file_size_bytes: int) -> bool:
        """Check if user can upload a file of given size without exceeding quota."""
        if not self.has_storage_quota():
            return True  # No quota = unlimited
        if self.storage_quota_bytes == 0:
            return False  # Zero quota = no uploads
        return (self.current_storage_bytes + file_size_bytes) <= self.storage_quota_bytes
    
    def get_available_storage_bytes(self) -> int | None:
        """Get available storage in bytes. None if no quota set."""
        if not self.has_storage_quota():
            return None
        return max(0, self.storage_quota_bytes - self.current_storage_bytes)
    
    def update_storage_usage(self) -> None:
        """Recalculate current storage usage from actual file records."""
        from app.models.file import File
        total_bytes = db.session.query(db.func.sum(File.file_size_bytes)).filter_by(user_id=self.id).scalar() or 0
        self.current_storage_bytes = total_bytes
        db.session.commit()
    
    def add_file_to_storage(self, file_size_bytes: int) -> None:
        """Add file size to current storage usage."""
        self.current_storage_bytes += file_size_bytes
    
    def remove_file_from_storage(self, file_size_bytes: int) -> None:
        """Remove file size from current storage usage."""
        self.current_storage_bytes = max(0, self.current_storage_bytes - file_size_bytes)
    
    def is_near_quota_limit(self) -> bool:
        """Check if user is approaching their storage quota limit."""
        if not self.has_storage_quota():
            return False
        
        from flask import current_app
        warning_threshold = current_app.config.get('QUOTA_WARNING_THRESHOLD_PERCENT', 80)
        usage_percent = self.get_storage_usage_percent()
        
        return usage_percent is not None and usage_percent >= warning_threshold
    
    def is_over_quota_limit(self) -> bool:
        """Check if user has exceeded their storage quota."""
        if not self.has_storage_quota():
            return False
        
        return self.current_storage_bytes > self.storage_quota_bytes
    
    def is_at_critical_quota(self) -> bool:
        """Check if user is at critical quota level (near 100%)."""
        if not self.has_storage_quota():
            return False
        
        from flask import current_app
        critical_threshold = current_app.config.get('QUOTA_CRITICAL_THRESHOLD_PERCENT', 90)
        usage_percent = self.get_storage_usage_percent()
        
        return usage_percent is not None and usage_percent >= critical_threshold

    def set_storage_quota(self, quota_mb: float | None, updated_by_admin_id: int | None = None) -> None:
        """Set storage quota in MB. None for unlimited."""
        if quota_mb is None:
            self.storage_quota_bytes = None
        else:
            self.storage_quota_bytes = int(quota_mb * 1024 * 1024)
        
        self.quota_updated_at = datetime.now(timezone.utc)
        
        # Log the quota change via AuditLogger (admin-initiated action)
        if updated_by_admin_id:
            try:
                from app.utils.audit_logger import AuditLogger
                quota_str = f"{quota_mb}MB" if quota_mb is not None else "unlimited"
                AuditLogger.log_admin_action(
                    action='quota_update',
                    description=f"Storage quota set to {quota_str} for user '{self.username}' (id={self.id})",
                    target_type='user',
                    target_id=self.id
                )
            except Exception:
                pass  # Never let logging failures block the actual quota update


    # UserMixin already provides is_authenticated / is_anonymous / get_id.
    # We override is_active so a deactivated account can't log in even with
    # a valid session cookie.
    @property
    def is_active(self) -> bool:
        return self.is_active_account

    def __repr__(self) -> str:
        return f"<User {self.username!r} role={self.role!r}>"
