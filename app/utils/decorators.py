from functools import wraps

from flask import abort, request, flash, redirect, url_for, current_app
from flask_login import current_user

# @login_required already comes from flask_login — import that directly in
# routes. This module only adds what Flask-Login doesn't provide.


def admin_required(view_func):
    """Restrict a route to authenticated users with role == 'admin'.

    Always stack this UNDER @login_required, e.g.:

        @app.route("/admin")
        @login_required
        @admin_required
        def admin_panel():
            ...

    so an anonymous user gets redirected to login (via Flask-Login) rather
    than a bare 403.
    """

    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)
        return view_func(*args, **kwargs)

    return wrapped


def ip_block_check(f):
    """Decorator to check if the requesting IP is blocked."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from app.utils.security import get_client_ip, is_ip_blocked
        
        client_ip = get_client_ip(request)
        is_blocked, reason = is_ip_blocked(client_ip)
        
        if is_blocked:
            # Log the blocked attempt
            from app.models.activity_log import ActivityLog
            ActivityLog.log_activity(
                action="access_blocked",
                status="blocked",
                ip_address=client_ip,
                details=f"Access denied: {reason}"
            )
            
            # Return 403 Forbidden for blocked IPs
            abort(403)
        
        return f(*args, **kwargs)
    return decorated_function


def rate_limit_check(max_attempts: int = 5, window_minutes: int = 15):
    """Decorator to check rate limiting for specific endpoints.
    
    Args:
        max_attempts: Maximum attempts allowed in the time window
        window_minutes: Time window in minutes
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from app.utils.security import get_client_ip, check_failed_attempts_for_ip
            
            client_ip = get_client_ip(request)
            failed_attempts = check_failed_attempts_for_ip(client_ip, window_minutes)
            
            if failed_attempts >= max_attempts:
                # Log the rate limit hit
                from app.models.activity_log import ActivityLog
                ActivityLog.log_activity(
                    action="rate_limit_exceeded",
                    status="blocked",
                    ip_address=client_ip,
                    details=f"Rate limit exceeded: {failed_attempts} attempts in {window_minutes} minutes"
                )
                
                abort(429)  # Too Many Requests
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


def storage_quota_check(f):
    """Decorator to check if user has sufficient storage quota for uploads."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_authenticated:
            return f(*args, **kwargs)  # Let auth decorator handle this
        
        # Only check for file upload endpoints
        if request.method == 'POST' and request.files:
            total_size = 0
            for file in request.files.values():
                if file and file.filename:
                    # Get file size by seeking to end
                    file.seek(0, 2)  # Seek to end
                    size = file.tell()
                    file.seek(0)  # Reset to beginning
                    total_size += size
            
            if total_size > 0 and not current_user.can_upload_file(total_size):
                quota_mb = current_user.get_storage_quota_mb()
                used_mb = current_user.get_current_storage_mb()
                available_bytes = current_user.get_available_storage_bytes()
                available_mb = available_bytes / (1024 * 1024) if available_bytes else 0
                
                flash(
                    f"Upload would exceed your storage quota. "
                    f"Quota: {quota_mb:.1f}MB, Used: {used_mb:.1f}MB, "
                    f"Available: {available_mb:.1f}MB, Upload size: {total_size/(1024*1024):.1f}MB",
                    "error"
                )
                return redirect(url_for('files.upload'))
        
        return f(*args, **kwargs)
    return decorated_function
