"""
Enhanced Audit Log Model for SafeVault
Provides comprehensive audit trail tracking for all system activities
"""

from datetime import datetime, timezone
from app import db
from flask import request, session
from flask_login import current_user
import json
import uuid

# Comprehensive list of audit actions
AUDIT_ACTIONS = {
    # Authentication actions
    'auth_login', 'auth_logout', 'auth_register', 'auth_password_change',
    'auth_2fa_setup', 'auth_2fa_disable', 'auth_2fa_verify', 'auth_backup_code_use',
    'auth_backup_codes_regenerate',
    'auth_password_reset_request', 'auth_password_reset_complete',

    # File operations
    'file_upload', 'file_download', 'file_decrypt', 'file_encrypt', 'file_delete',
    'file_preview', 'file_share', 'file_rename', 'file_move',

    # Admin operations
    'admin_user_create', 'admin_user_delete', 'admin_user_disable', 'admin_user_enable',
    'admin_user_role_change', 'admin_user_unlock',
    'admin_quota_change', 'admin_bulk_quota_change',
    'admin_ip_block', 'admin_ip_unblock', 'admin_ip_cleanup',
    'admin_session_terminate', 'admin_bulk_operation', 'admin_system_config',
    'admin_backup_create', 'admin_backup_delete', 'admin_backup_cleanup', 'admin_backup_restore',
    'admin_export_create', 'admin_export_delete', 'admin_export_cleanup', 'admin_export_download',

    # Security events
    'security_login_failed', 'security_account_locked', 'security_ip_blocked',
    'security_suspicious_activity', 'security_session_hijack', 'security_brute_force',

    # System events
    'system_startup', 'system_shutdown', 'system_backup', 'system_restore',
    'system_maintenance', 'system_error', 'system_cleanup',

    # Data events
    'data_export', 'data_import', 'data_migration', 'data_purge',

    # Settings changes
    'settings_security', 'settings_storage', 'settings_notification', 'settings_system'
}

AUDIT_LEVELS = {
    'info': 1,      # General information
    'warning': 2,   # Warning conditions
    'error': 3,     # Error conditions
    'critical': 4,  # Critical security events
    'debug': 0      # Debug information
}

class AuditLog(db.Model):
    __tablename__ = 'audit_logs'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    
    # Basic audit information
    timestamp = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    action = db.Column(db.String(50), nullable=False, index=True)
    category = db.Column(db.String(20), nullable=False, index=True)  # auth, file, admin, security, system
    level = db.Column(db.String(10), nullable=False, default='info', index=True)
    status = db.Column(db.String(20), nullable=False, default='success')
    
    # Actor information (who performed the action)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True, index=True)
    username = db.Column(db.String(80), nullable=True)  # Cache for performance
    session_id = db.Column(db.String(36), db.ForeignKey('user_sessions.id'), nullable=True)
    
    # Context information (where/how)
    ip_address = db.Column(db.String(45), nullable=True, index=True)
    user_agent = db.Column(db.Text, nullable=True)
    endpoint = db.Column(db.String(100), nullable=True)  # Flask route endpoint
    method = db.Column(db.String(10), nullable=True)  # HTTP method
    
    # Target information (what was affected)
    target_type = db.Column(db.String(50), nullable=True)  # user, file, system, setting
    target_id = db.Column(db.String(100), nullable=True)  # ID of affected object
    target_name = db.Column(db.String(255), nullable=True)  # Name/description of target
    
    # Event details
    description = db.Column(db.Text, nullable=True)  # Human readable description
    details = db.Column(db.Text, nullable=True)  # JSON encoded additional details
    
    # Security context
    risk_level = db.Column(db.Integer, nullable=False, default=0)  # 0-100
    is_suspicious = db.Column(db.Boolean, nullable=False, default=False)
    
    # Additional metadata
    duration_ms = db.Column(db.Integer, nullable=True)  # Operation duration
    result_code = db.Column(db.String(20), nullable=True)  # Application-specific result code
    
    # Relationships
    user = db.relationship('User', backref='audit_logs', lazy=True)
    session = db.relationship('UserSession', backref='audit_logs', lazy=True)
    
    def __init__(self, action, **kwargs):
        self.id = str(uuid.uuid4())
        self.action = action
        self.category = self._determine_category(action)
        self.timestamp = datetime.now(timezone.utc)
        
        # Auto-populate common fields from Flask context
        self._populate_from_request()
        
        # Set provided fields
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
    
    def _determine_category(self, action):
        """Automatically determine category from action name"""
        if action.startswith('auth_'):
            return 'authentication'
        elif action.startswith('file_'):
            return 'file'
        elif action.startswith('admin_'):
            return 'administration'
        elif action.startswith('security_'):
            return 'security'
        elif action.startswith('system_'):
            return 'system'
        elif action.startswith('data_'):
            return 'data'
        elif action.startswith('settings_'):
            return 'settings'
        else:
            return 'general'
    
    def _populate_from_request(self):
        """Auto-populate fields from Flask request context if available"""
        try:
            if request:
                self.ip_address = self._get_client_ip()
                self.user_agent = request.headers.get('User-Agent', '')
                self.endpoint = request.endpoint
                self.method = request.method
                
            # Get current user info
            if current_user and current_user.is_authenticated:
                self.user_id = current_user.id
                self.username = current_user.username
                
                # Get session ID if available
                if 'session_tracking_id' in session:
                    self.session_id = session['session_tracking_id']
                    
        except Exception:
            # Outside request context or other error - ignore
            pass
    
    def _get_client_ip(self):
        """Get client IP from request, handling proxies"""
        if 'X-Forwarded-For' in request.headers:
            return request.headers['X-Forwarded-For'].split(',')[0].strip()
        elif 'X-Real-IP' in request.headers:
            return request.headers['X-Real-IP']
        else:
            return request.remote_addr or '127.0.0.1'
    
    def set_details(self, details_dict):
        """Set details as JSON"""
        if details_dict:
            self.details = json.dumps(details_dict, default=str)
    
    def get_details(self):
        """Get details as dictionary"""
        if self.details:
            try:
                return json.loads(self.details)
            except (json.JSONDecodeError, TypeError):
                return {}
        return {}
    
    def calculate_risk_level(self):
        """Calculate risk level based on action and context"""
        base_risk = 0
        
        # Base risk by category
        if self.category == 'security':
            base_risk = 50
        elif self.category == 'administration':
            base_risk = 40
        elif self.category == 'authentication':
            base_risk = 30
        elif self.category == 'file':
            base_risk = 20
        
        # Increase risk for failed operations
        if self.status != 'success':
            base_risk += 20
        
        # Increase risk for critical actions
        critical_actions = [
            'admin_user_delete', 'admin_system_config', 'security_ip_blocked',
            'auth_password_reset_complete', 'file_delete'
        ]
        if self.action in critical_actions:
            base_risk += 20
        
        # Increase risk for suspicious indicators
        if self.is_suspicious:
            base_risk += 30
        
        self.risk_level = min(base_risk, 100)
        return self.risk_level
    
    @classmethod
    def log(cls, action, **kwargs):
        """
        Convenience method to create and save audit log entry
        
        Args:
            action: The action being logged
            **kwargs: Additional fields (level, status, description, target_type, etc.)
        
        Returns:
            AuditLog: The created audit log entry
        """
        # Validate action
        if action not in AUDIT_ACTIONS:
            raise ValueError(f"Invalid audit action: {action}")
        
        # Create audit log entry
        audit_log = cls(action=action, **kwargs)
        
        # Calculate risk level if not provided
        if 'risk_level' not in kwargs:
            audit_log.calculate_risk_level()
        
        # Save to database
        try:
            db.session.add(audit_log)
            db.session.commit()
            return audit_log
        except Exception as e:
            db.session.rollback()
            # Log to application logger as fallback
            from flask import current_app
            current_app.logger.error(f"Failed to save audit log: {e}")
            raise
    
    @classmethod
    def log_auth_event(cls, action, status='success', description=None, level=None, **kwargs):
        """Log authentication-related event"""
        if level is None:
            level = 'warning' if status != 'success' else 'info'
        return cls.log(
            action=action,
            status=status,
            description=description,
            level=level,
            **kwargs
        )
    
    @classmethod
    def log_file_event(cls, action, file_id=None, filename=None, status='success', **kwargs):
        """Log file operation event"""
        return cls.log(
            action=action,
            status=status,
            target_type='file',
            target_id=str(file_id) if file_id else None,
            target_name=filename,
            **kwargs
        )
    
    @classmethod
    def log_admin_event(cls, action, target_user_id=None, target_username=None, level='warning', **kwargs):
        """Log admin operation event"""
        return cls.log(
            action=action,
            target_type='user' if target_user_id else 'system',
            target_id=str(target_user_id) if target_user_id else None,
            target_name=target_username,
            level=level,
            **kwargs
        )
    
    @classmethod
    def log_security_event(cls, action, level='warning', is_suspicious=False, **kwargs):
        """Log security-related event"""
        return cls.log(
            action=action,
            level=level,
            is_suspicious=is_suspicious,
            **kwargs
        )
    
    @classmethod
    def log_system_event(cls, action, **kwargs):
        """Log system-level event"""
        return cls.log(
            action=action,
            target_type='system',
            level='info',
            **kwargs
        )
    
    @classmethod
    def search(cls, **filters):
        """
        Search audit logs with filters
        
        Args:
            user_id: Filter by user ID
            action: Filter by action
            category: Filter by category
            level: Filter by level
            start_date: Filter by start date
            end_date: Filter by end date
            ip_address: Filter by IP address
            status: Filter by status
            limit: Limit results (default 100)
            offset: Offset for pagination (default 0)
        
        Returns:
            Query object for further processing
        """
        query = cls.query
        
        # Apply filters
        if 'user_id' in filters:
            query = query.filter(cls.user_id == filters['user_id'])
        
        if 'action' in filters:
            if isinstance(filters['action'], list):
                query = query.filter(cls.action.in_(filters['action']))
            else:
                query = query.filter(cls.action == filters['action'])
        
        if 'category' in filters:
            query = query.filter(cls.category == filters['category'])
        
        if 'level' in filters:
            query = query.filter(cls.level == filters['level'])
        
        if 'status' in filters:
            query = query.filter(cls.status == filters['status'])
        
        if 'start_date' in filters:
            query = query.filter(cls.timestamp >= filters['start_date'])
        
        if 'end_date' in filters:
            query = query.filter(cls.timestamp <= filters['end_date'])
        
        if 'ip_address' in filters:
            query = query.filter(cls.ip_address == filters['ip_address'])
        
        if 'is_suspicious' in filters:
            query = query.filter(cls.is_suspicious == filters['is_suspicious'])
        
        if 'risk_level_min' in filters:
            query = query.filter(cls.risk_level >= filters['risk_level_min'])
        
        # Order by timestamp descending
        query = query.order_by(cls.timestamp.desc())
        
        # Apply pagination
        limit = filters.get('limit', 100)
        offset = filters.get('offset', 0)
        
        return query.limit(limit).offset(offset)
    
    @classmethod
    def get_stats(cls, start_date=None, end_date=None):
        """Get audit log statistics"""
        from sqlalchemy import func
        
        query = db.session.query(cls)
        
        if start_date:
            query = query.filter(cls.timestamp >= start_date)
        if end_date:
            query = query.filter(cls.timestamp <= end_date)
        
        stats = {
            'total_events': query.count(),
            'by_category': dict(query.with_entities(cls.category, func.count(cls.id)).group_by(cls.category).all()),
            'by_level': dict(query.with_entities(cls.level, func.count(cls.id)).group_by(cls.level).all()),
            'by_status': dict(query.with_entities(cls.status, func.count(cls.id)).group_by(cls.status).all()),
            'failed_events': query.filter(cls.status != 'success').count(),
            'suspicious_events': query.filter(cls.is_suspicious == True).count(),
            'high_risk_events': query.filter(cls.risk_level >= 70).count()
        }
        
        return stats
    
    @classmethod
    def cleanup_old_entries(cls, days=90):
        """Remove audit log entries older than specified days"""
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
        old_entries = cls.query.filter(cls.timestamp < cutoff_date).all()
        
        count = len(old_entries)
        for entry in old_entries:
            db.session.delete(entry)
        
        db.session.commit()
        return count
    
    def to_dict(self):
        """Convert audit log to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'action': self.action,
            'category': self.category,
            'level': self.level,
            'status': self.status,
            'user_id': self.user_id,
            'username': self.username,
            'ip_address': self.ip_address,
            'endpoint': self.endpoint,
            'method': self.method,
            'target_type': self.target_type,
            'target_id': self.target_id,
            'target_name': self.target_name,
            'description': self.description,
            'details': self.get_details(),
            'risk_level': self.risk_level,
            'is_suspicious': self.is_suspicious,
            'duration_ms': self.duration_ms
        }
    
    def __repr__(self):
        return f'<AuditLog {self.action} {self.status} user={self.username}>'


# Import at bottom to avoid circular imports
from datetime import timedelta