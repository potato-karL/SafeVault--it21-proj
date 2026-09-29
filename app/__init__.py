import os
from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager
from flask_wtf import CSRFProtect
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config import Config

db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = "auth.login"
login_manager.login_message_category = "warning"
csrf = CSRFProtect()

# Applies globally by IP; individual routes (e.g. login) layer a tighter
# limit on top via @limiter.limit(...) decorators.
limiter = Limiter(key_func=get_remote_address, default_limits=["200 per hour"])


def create_app(config_class=Config):
    app = Flask(__name__, template_folder="../templates", static_folder="../static")
    app.config.from_object(config_class)

    # Configure permanent session lifetime (auto-logout after inactivity)
    from datetime import timedelta
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(seconds=app.config['PERMANENT_SESSION_LIFETIME'])

    # Make sure instance/ and uploads/ exist even on a fresh checkout
    os.makedirs(os.path.join(app.root_path, "..", "instance"), exist_ok=True)
    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

    db.init_app(app)
    login_manager.init_app(app)
    csrf.init_app(app)
    limiter.init_app(app)

    # --- Talisman: forces HTTPS + sets security headers (HSTS, CSP, etc.) ---
    # force_https is OFF by default here because local dev runs on plain
    # HTTP (127.0.0.1:5000) — flip FORCE_HTTPS=true in your environment
    # once you're behind real TLS (see config.py). CSP is intentionally
    # permissive for the CDN assets this app already loads (Bootstrap,
    # Google Fonts, Chart.js) and allows inline scripts for interactivity.
    # Tighten it in production if you self-host assets and use nonces.
    csp = {
        "default-src": "'self'",
        "script-src": ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net"],
        "style-src": ["'self'", "'unsafe-inline'", "https://cdn.jsdelivr.net", "https://fonts.googleapis.com"],
        "font-src": ["'self'", "https://fonts.gstatic.com", "https://cdn.jsdelivr.net"],
        "img-src": ["'self'", "data:"],
        "connect-src": ["'self'", "https://cdn.jsdelivr.net"],
    }
    Talisman(
        app,
        force_https=app.config["FORCE_HTTPS"],
        strict_transport_security=app.config["FORCE_HTTPS"],
        content_security_policy=csp,
        session_cookie_secure=app.config["FORCE_HTTPS"],
    )

    # --- IP Blocking Middleware ---
    @app.before_request
    def check_ip_blocklist():
        """Check if requesting IP is blocked before processing any request."""
        from flask import request, abort, render_template
        from flask_login import current_user
        from app.utils.security import get_client_ip, is_ip_blocked
        from app.models.activity_log import ActivityLog
        from app.utils.session_manager import SessionManager
        
        # Skip IP checks for static files and error pages
        if request.endpoint and (
            request.endpoint == 'static' or 
            request.endpoint.startswith('error')
        ):
            return
        
        client_ip = get_client_ip(request)
        is_blocked, reason = is_ip_blocked(client_ip)
        
        if is_blocked:
            # Log the blocked attempt
            ActivityLog.log_activity(
                action="access_blocked",
                status="blocked", 
                ip_address=client_ip,
                details=f"Blocked request to {request.endpoint}: {reason}"
            )
            
            # Return custom blocked page instead of generic 403
            return render_template('errors/blocked.html', reason=reason), 403
        
        # Update session activity for authenticated users
        if current_user.is_authenticated:
            try:
                SessionManager.update_session_activity()
            except Exception as e:
                app.logger.error(f"Error updating session activity: {e}")

    # Import models so SQLAlchemy knows about them before create_all()
    from app.models.user import User
    from app.models.file import File
    from app.models.activity_log import ActivityLog
    from app.models.backup_code import BackupCode
    from app.models.ip_blocklist import IPBlocklist
    from app.models.user_session import UserSession
    from app.models.audit_log import AuditLog
    from app.models.system_health import SystemHealthMetric, SystemAlert

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    with app.app_context():
        db.create_all()

    from app.routes.auth import auth_bp
    app.register_blueprint(auth_bp)

    from app.routes.files import files_bp
    app.register_blueprint(files_bp)

    from app.routes.admin import admin_bp
    app.register_blueprint(admin_bp)

    from app.error_handlers import register_error_handlers
    register_error_handlers(app)

    # Register timezone template filters
    from app.utils.timezone_helper import format_local_time, utc_to_local
    
    @app.template_filter('localtime')
    def localtime_filter(dt, format_str="%Y-%m-%d %H:%M:%S"):
        """Convert UTC datetime (or ISO string) to local time string."""
        if dt is None:
            return ''
        # Handle ISO format strings coming from audit_viewer
        if isinstance(dt, str):
            try:
                from datetime import datetime, timezone
                # Handle both 'Z' suffix and '+00:00' suffix
                dt = dt.replace('Z', '+00:00')
                dt = datetime.fromisoformat(dt)
            except (ValueError, AttributeError):
                return dt  # Return as-is if unparseable
        return format_local_time(dt, format_str)
    
    @app.template_filter('localdatetime')
    def localdatetime_filter(dt):
        """Convert UTC datetime (or ISO string) to local datetime object."""
        if dt is None:
            return None
        if isinstance(dt, str):
            try:
                from datetime import datetime
                dt = dt.replace('Z', '+00:00')
                dt = datetime.fromisoformat(dt)
            except (ValueError, AttributeError):
                return None
        return utc_to_local(dt)

    return app
