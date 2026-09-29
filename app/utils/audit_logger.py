"""
Audit Logger Utility for SafeVault
Provides easy-to-use functions for logging audit events throughout the application
"""

from flask import current_app
from app.models.audit_log import AuditLog
from datetime import datetime
import time
import functools

class AuditLogger:
    """Centralized audit logging utility"""
    
    @staticmethod
    def log_auth_success(action, description=None, **kwargs):
        """Log successful authentication event"""
        try:
            return AuditLog.log_auth_event(
                action=action,
                status='success',
                description=description,
                **kwargs
            )
        except Exception as e:
            current_app.logger.error(f"Audit logging failed: {e}")
    
    @staticmethod
    def log_auth_failure(action, description=None, **kwargs):
        """Log failed authentication event"""
        try:
            return AuditLog.log_auth_event(
                action=action,
                status='failed',
                description=description,
                level='warning',
                **kwargs
            )
        except Exception as e:
            current_app.logger.error(f"Audit logging failed: {e}")
    
    @staticmethod
    def log_file_operation(action, file_id=None, filename=None, status='success', **kwargs):
        """Log file operation"""
        try:
            return AuditLog.log_file_event(
                action=action,
                file_id=file_id,
                filename=filename,
                status=status,
                **kwargs
            )
        except Exception as e:
            current_app.logger.error(f"Audit logging failed: {e}")
    
    @staticmethod
    def log_admin_action(action, target_user_id=None, target_username=None, description=None, **kwargs):
        """Log administrative action"""
        try:
            return AuditLog.log_admin_event(
                action=action,
                target_user_id=target_user_id,
                target_username=target_username,
                description=description,
                **kwargs
            )
        except Exception as e:
            current_app.logger.error(f"Audit logging failed: {e}")
    
    @staticmethod
    def log_security_event(action, description=None, is_suspicious=False, level='warning', **kwargs):
        """Log security-related event"""
        try:
            return AuditLog.log_security_event(
                action=action,
                description=description,
                is_suspicious=is_suspicious,
                level=level,
                **kwargs
            )
        except Exception as e:
            current_app.logger.error(f"Audit logging failed: {e}")
    
    @staticmethod
    def log_system_event(action, description=None, **kwargs):
        """Log system-level event"""
        try:
            return AuditLog.log_system_event(
                action=action,
                description=description,
                **kwargs
            )
        except Exception as e:
            current_app.logger.error(f"Audit logging failed: {e}")


def audit_trail(action=None, category='general', description=None, log_args=False, log_result=False):
    """
    Decorator to automatically audit function calls
    
    Args:
        action: Override action name (defaults to function name)
        category: Audit category 
        description: Static description
        log_args: Whether to log function arguments
        log_result: Whether to log function result
    
    Example:
        @audit_trail(action='admin_user_delete', category='administration')
        def delete_user(user_id):
            # function implementation
            pass
    """
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            audit_action = action or f"{category}_{func.__name__}"
            
            # Prepare audit details
            details = {}
            if log_args and (args or kwargs):
                details['function_args'] = {
                    'args': [str(arg) for arg in args],
                    'kwargs': {k: str(v) for k, v in kwargs.items()}
                }
            
            try:
                # Execute function
                result = func(*args, **kwargs)
                
                # Calculate duration
                duration_ms = int((time.time() - start_time) * 1000)
                
                # Log result if requested
                if log_result and result is not None:
                    details['function_result'] = str(result)[:500]  # Truncate long results
                
                # Log successful audit
                AuditLog.log(
                    action=audit_action,
                    status='success',
                    description=description,
                    duration_ms=duration_ms,
                    details=details if details else None
                )
                
                return result
                
            except Exception as e:
                # Calculate duration for failed operation
                duration_ms = int((time.time() - start_time) * 1000)
                
                # Log failed audit
                details['error'] = str(e)
                AuditLog.log(
                    action=audit_action,
                    status='failed',
                    description=f"Function failed: {str(e)}",
                    duration_ms=duration_ms,
                    level='error',
                    details=details if details else None
                )
                
                # Re-raise the exception
                raise
                
        return wrapper
    return decorator


class AuditContext:
    """Context manager for audit logging with automatic duration tracking"""
    
    def __init__(self, action, description=None, **kwargs):
        self.action = action
        self.description = description
        self.kwargs = kwargs
        self.start_time = None
        self.audit_log = None
    
    def __enter__(self):
        self.start_time = time.time()
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        duration_ms = int((time.time() - self.start_time) * 1000)
        
        if exc_type is None:
            # Success
            self.audit_log = AuditLog.log(
                action=self.action,
                status='success',
                description=self.description,
                duration_ms=duration_ms,
                **self.kwargs
            )
        else:
            # Failure
            self.audit_log = AuditLog.log(
                action=self.action,
                status='failed',
                description=f"{self.description} - Error: {str(exc_val)}" if self.description else f"Error: {str(exc_val)}",
                duration_ms=duration_ms,
                level='error',
                **self.kwargs
            )
    
    def add_detail(self, key, value):
        """Add detail to the audit context"""
        if not hasattr(self, '_details'):
            self._details = {}
        self._details[key] = value
        self.kwargs['details'] = self._details
    
    def set_target(self, target_type, target_id, target_name=None):
        """Set target information for the audit"""
        self.kwargs.update({
            'target_type': target_type,
            'target_id': str(target_id),
            'target_name': target_name
        })


# Convenience functions for common audit patterns
def audit_login_attempt(username, success=True, method='password', failure_reason=None):
    """Audit login attempt"""
    if success:
        return AuditLogger.log_auth_success(
            'auth_login',
            description=f"Successful login via {method}",
            target_type='user',
            target_name=username
        )
    else:
        return AuditLogger.log_auth_failure(
            'security_login_failed',
            description=f"Failed login attempt: {failure_reason}",
            target_type='user',
            target_name=username,
            is_suspicious=True
        )

def audit_file_access(action, filename, file_id=None, success=True, error=None):
    """Audit file access operation"""
    return AuditLogger.log_file_operation(
        action=f"file_{action}",
        file_id=file_id,
        filename=filename,
        status='success' if success else 'failed',
        description=f"File {action}: {filename}" + (f" - Error: {error}" if error else "")
    )

def audit_admin_operation(action, target_user_id=None, target_username=None, description=None, success=True):
    """Audit administrative operation"""
    return AuditLogger.log_admin_action(
        action=f"admin_{action}",
        target_user_id=target_user_id,
        target_username=target_username,
        description=description,
        status='success' if success else 'failed',
        level='warning'
    )

def audit_security_incident(incident_type, description, is_critical=False, **kwargs):
    """Audit security incident"""
    return AuditLogger.log_security_event(
        action=f"security_{incident_type}",
        description=description,
        is_suspicious=True,
        level='critical' if is_critical else 'warning',
        **kwargs
    )

def audit_system_operation(operation, description=None, **kwargs):
    """Audit system-level operation"""
    return AuditLogger.log_system_event(
        action=f"system_{operation}",
        description=description,
        **kwargs
    )