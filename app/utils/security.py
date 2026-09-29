import os
import uuid

import magic
from flask import current_app


# Maps allowed extensions to the MIME types libmagic should actually detect
# for that content. This catches the classic attack of renaming a malicious
# file to *.txt or *.png — the extension check alone can't see that.
_EXPECTED_MIME_PREFIXES = {
    "txt": ("text/",),
    "log": ("text/",),
    "csv": ("text/", "application/csv"),
    "pdf": ("application/pdf",),
    "png": ("image/png",),
    "jpg": ("image/jpeg",),
    "jpeg": ("image/jpeg",),
    "gif": ("image/gif",),
    "docx": ("application/zip", "application/vnd.openxmlformats"),  # docx is a zip container
    "xlsx": ("application/zip", "application/vnd.openxmlformats"),
    "zip": ("application/zip",),
}


def allowed_file(filename: str) -> bool:
    """Extension allow-list check. This is defense-in-depth, NOT the only
    safeguard — files are also stored under a randomly generated name
    (never the original), so even a disallowed or spoofed extension can't
    be used to influence a path or get executed as a script by the server.
    """
    if "." not in filename:
        return False
    ext = filename.rsplit(".", 1)[1].lower()
    return ext in current_app.config["ALLOWED_EXTENSIONS"]


def content_matches_extension(file_bytes: bytes, filename: str) -> bool:
    """Sniff the actual file content with libmagic and check it's plausible
    for the claimed extension. Blocks the "malware.exe renamed to
    report.txt" trick that an extension-only check can't catch.

    Deliberately lenient (prefix match, not exact) since MIME detection for
    things like docx/xlsx varies by libmagic version. This is a second
    layer on top of allowed_file(), not a replacement for it.
    """
    ext = filename.rsplit(".", 1)[1].lower() if "." in filename else ""
    expected_prefixes = _EXPECTED_MIME_PREFIXES.get(ext)
    if not expected_prefixes:
        # No mapping for this extension — fall back to the extension check only.
        return True

    detected_mime = magic.from_buffer(file_bytes, mime=True)
    return any(detected_mime.startswith(prefix) for prefix in expected_prefixes)


def generate_stored_filename(original_filename: str) -> str:
    """Generate a random, collision-resistant filename for disk storage.
    Never derived from user input — prevents path traversal and avoids
    leaking the real filename via directory listings or logs."""
    ext = ""
    if "." in original_filename:
        ext = "." + original_filename.rsplit(".", 1)[1].lower()
    return f"{uuid.uuid4().hex}{ext}"


def upload_path_for(stored_filename: str) -> str:
    return os.path.join(current_app.config["UPLOAD_FOLDER"], stored_filename)


def generate_reset_token(user_id: int) -> str:
    """Generate a cryptographically signed password reset token valid for 30 minutes."""
    from itsdangerous import URLSafeTimedSerializer
    serializer = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
    return serializer.dumps({"user_id": user_id}, salt="safevault-password-reset")


def verify_reset_token(token: str, max_age_sec: int = 1800) -> int | None:
    """Verify signed token; returns user_id if valid and not expired, else None."""
    from itsdangerous import URLSafeTimedSerializer, SignatureExpired, BadSignature
    serializer = URLSafeTimedSerializer(current_app.config["SECRET_KEY"])
    try:
        data = serializer.loads(token, salt="safevault-password-reset", max_age=max_age_sec)
        return data.get("user_id")
    except (SignatureExpired, BadSignature):
        return None


def calculate_password_strength(password: str) -> int:
    """Calculate password strength score (0-4) based on complexity criteria.
    
    Returns:
        0-1: Weak (fails basic requirements)
        2: Fair (basic requirements met)
        3: Good (strong enough for encryption)
        4: Excellent (maximum entropy)
    """
    if not password or len(password) < 6:
        return 0
    
    score = 0
    
    # Length scoring
    if len(password) >= 8:
        score += 1
    if len(password) >= 12:
        score += 1
    
    # Complexity scoring
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)
    
    if has_upper and has_lower:
        score += 1
    if has_digit:
        score += 1
    if has_special:
        score += 1
    
    # Cap at 4 (excellent) - need at least length and some complexity
    return min(4, score) if score > 0 else (1 if len(password) >= 6 else 0)


def is_password_strong_enough(password: str, min_score: int = 3) -> tuple[bool, str]:
    """Check if password meets minimum strength requirements.
    
    Args:
        password: The password to validate
        min_score: Minimum acceptable strength score (default 3 = "Good")
    
    Returns:
        (is_valid, error_message) tuple
    """
    score = calculate_password_strength(password)
    
    if score < min_score:
        if len(password) < 8:
            return False, "Password must be at least 8 characters long."
        
        # Check what's missing
        missing = []
        if not any(c.isupper() for c in password):
            missing.append("uppercase letter")
        if not any(c.islower() for c in password):
            missing.append("lowercase letter")
        if not any(c.isdigit() for c in password):
            missing.append("number")
        if not any(not c.isalnum() for c in password):
            missing.append("special character")
        
        if len(password) < 12:
            return False, f"Password needs to be stronger. Add: {', '.join(missing[:2])} or use 12+ characters."
        else:
            return False, f"Password needs more complexity. Add: {', '.join(missing[:2])}."
    
    return True, ""


def get_client_ip(request) -> str:
    """Get the real client IP address, accounting for proxies and load balancers."""
    # Check common proxy headers in order of preference
    if request.headers.get('X-Forwarded-For'):
        # X-Forwarded-For can contain multiple IPs, take the first (original client)
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP').strip()
    elif request.headers.get('CF-Connecting-IP'):  # Cloudflare
        return request.headers.get('CF-Connecting-IP').strip()
    else:
        return request.remote_addr or 'unknown'


def is_ip_blocked(ip_address: str) -> tuple[bool, str | None]:
    """Check if an IP address is blocked.
    
    Returns:
        (is_blocked, reason) tuple
    """
    if not ip_address or ip_address == 'unknown':
        return False, None
    
    from app.models.ip_blocklist import IPBlocklist
    
    if IPBlocklist.is_ip_blocked(ip_address):
        blocked_entry = IPBlocklist.query.filter_by(ip_address=ip_address).first()
        reason = blocked_entry.reason if blocked_entry else "IP address is blocked"
        return True, reason
    
    return False, None


def auto_ban_ip_if_needed(ip_address: str, failed_attempts: int) -> bool:
    """Automatically ban an IP if it exceeds the failure threshold.
    
    Args:
        ip_address: The IP address to potentially ban
        failed_attempts: Number of failed attempts from this IP
    
    Returns:
        True if IP was banned, False otherwise
    """
    if not ip_address or ip_address == 'unknown':
        return False
    
    # Get thresholds from config
    from flask import current_app
    max_attempts = current_app.config.get('IP_AUTO_BAN_ATTEMPTS', 10)
    ban_duration = current_app.config.get('IP_AUTO_BAN_DURATION_MINUTES', 60)
    
    if failed_attempts >= max_attempts:
        from app.models.ip_blocklist import IPBlocklist
        
        # Check if already blocked to avoid duplicate entries
        if not IPBlocklist.is_ip_blocked(ip_address):
            IPBlocklist.block_ip(
                ip_address=ip_address,
                reason=f"Automatically banned after {failed_attempts} failed login attempts",
                is_automatic=True,
                failed_attempts=failed_attempts,
                duration_minutes=ban_duration
            )
            return True
    
    return False


def check_failed_attempts_for_ip(ip_address: str, time_window_minutes: int = None) -> int:
    """Count failed login attempts from an IP in the specified time window."""
    if not ip_address or ip_address == 'unknown':
        return 0
    
    # Use config default if no window specified
    if time_window_minutes is None:
        from flask import current_app
        time_window_minutes = current_app.config.get('IP_FAILED_ATTEMPTS_WINDOW_MINUTES', 30)
    
    from datetime import datetime, timezone, timedelta
    from app.models.activity_log import ActivityLog
    
    since = datetime.now(timezone.utc) - timedelta(minutes=time_window_minutes)
    
    failed_count = ActivityLog.query.filter(
        ActivityLog.ip_address == ip_address,
        ActivityLog.action == "login",
        ActivityLog.status == "fail",
        ActivityLog.timestamp >= since
    ).count()
    
    return failed_count


def cleanup_expired_ip_blocks() -> int:
    """Remove expired IP blocks and return count of cleaned up entries."""
    from app.models.ip_blocklist import IPBlocklist
    return IPBlocklist.cleanup_expired_blocks()

