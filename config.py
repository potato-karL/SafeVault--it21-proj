import os
import pytz
from datetime import timezone, timedelta

BASE_DIR = os.path.abspath(os.path.dirname(__file__))


class Config:
    # In production, load this from an environment variable, never hardcode it.
    SECRET_KEY = os.environ.get("SAFEVAULT_SECRET_KEY", "dev-only-change-me")

    # On Railway, DATABASE_URL is injected automatically when you add a
    # PostgreSQL service. Locally it falls back to SQLite for development.
    _db_url = os.environ.get("DATABASE_URL", "")
    # Railway (and some older Heroku configs) still emit postgres:// — SQLAlchemy
    # requires postgresql://, so fix it here.
    if _db_url.startswith("postgres://"):
        _db_url = _db_url.replace("postgres://", "postgresql://", 1)
    SQLALCHEMY_DATABASE_URI = _db_url or "sqlite:///" + os.path.join(
        BASE_DIR, "instance", "safevault.db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False

    UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
    MAX_CONTENT_LENGTH = 25 * 1024 * 1024  # 25 MB upload limit

    # Allowed file extensions for upload (defense-in-depth, not the only check)
    ALLOWED_EXTENSIONS = {
        "txt", "pdf", "png", "jpg", "jpeg", "gif",
        "docx", "xlsx", "csv", "zip", "log",
    }

    # PBKDF2 iteration count for the *encryption* key derivation (Phase 3).
    # This is intentionally separate from the password-hash iterations Werkzeug uses.
    KDF_ITERATIONS = 390_000

    # --- Login brute-force lockout policy ---
    MAX_LOGIN_ATTEMPTS = 5
    LOCKOUT_MINUTES = 15

    # Set FORCE_HTTPS=true once you're deployed behind real TLS
    # (e.g. nginx/Caddy terminating certs in front of this app).
    # Leave false for local http://127.0.0.1 development.
    FORCE_HTTPS = os.environ.get("SAFEVAULT_FORCE_HTTPS", "false").lower() == "true"

    # --- Session timeout configuration ---
    # Session lifetime: 30 minutes of inactivity before auto-logout
    PERMANENT_SESSION_LIFETIME = 1800  # 30 minutes in seconds
    SESSION_COOKIE_SECURE = FORCE_HTTPS  # Only send cookie over HTTPS in production
    SESSION_COOKIE_HTTPONLY = True  # Prevent JavaScript access to session cookie
    SESSION_COOKIE_SAMESITE = "Lax"  # CSRF protection

    # --- IP Auto-ban configuration ---
    # Number of failed login attempts from same IP before auto-ban
    IP_AUTO_BAN_ATTEMPTS = int(os.environ.get("SAFEVAULT_IP_AUTO_BAN_ATTEMPTS", "10"))
    # Duration of automatic IP ban in minutes
    IP_AUTO_BAN_DURATION_MINUTES = int(os.environ.get("SAFEVAULT_IP_AUTO_BAN_DURATION", "60"))
    # Time window in minutes to count failed attempts (rolling window)
    IP_FAILED_ATTEMPTS_WINDOW_MINUTES = int(os.environ.get("SAFEVAULT_IP_WINDOW_MINUTES", "30"))

    # --- Backup and Export configuration ---
    BACKUP_DIRECTORY = os.path.join(BASE_DIR, "backups")
    EXPORT_DIRECTORY = os.path.join(BASE_DIR, "exports")
    
    # Application version for backup metadata
    VERSION = "2.0.0"

    # --- Storage quota configuration ---
    # Default storage quota for new users (in MB, None = unlimited)
    DEFAULT_USER_STORAGE_QUOTA_MB = os.environ.get("SAFEVAULT_DEFAULT_QUOTA_MB")
    if DEFAULT_USER_STORAGE_QUOTA_MB is not None:
        try:
            DEFAULT_USER_STORAGE_QUOTA_MB = float(DEFAULT_USER_STORAGE_QUOTA_MB)
        except ValueError:
            DEFAULT_USER_STORAGE_QUOTA_MB = None
    
    # Global storage alert thresholds (when to warn about total disk usage)
    GLOBAL_STORAGE_WARNING_THRESHOLD_GB = float(os.environ.get("SAFEVAULT_GLOBAL_WARNING_GB", "10"))
    GLOBAL_STORAGE_CRITICAL_THRESHOLD_GB = float(os.environ.get("SAFEVAULT_GLOBAL_CRITICAL_GB", "20"))
    
    # Storage quota enforcement settings
    QUOTA_WARNING_THRESHOLD_PERCENT = float(os.environ.get("SAFEVAULT_QUOTA_WARNING_PERCENT", "80"))
    QUOTA_CRITICAL_THRESHOLD_PERCENT = float(os.environ.get("SAFEVAULT_QUOTA_CRITICAL_PERCENT", "90"))

    # --- Timezone configuration ---
    # Default timezone for displaying timestamps (auto-detect system timezone)
    TIMEZONE = os.environ.get("SAFEVAULT_TIMEZONE", "Asia/Manila")  # Default to UTC+8
    
    @staticmethod
    def get_local_timezone():
        """Get the configured timezone object."""
        try:
            return pytz.timezone(Config.TIMEZONE)
        except pytz.exceptions.UnknownTimeZoneError:
            return pytz.UTC
