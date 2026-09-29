"""
Bulk User Management Operations for SafeVault
Provides efficient bulk operations for user administration
"""

from datetime import datetime, timezone, timedelta
from flask import current_app
from app import db
from app.models.user import User
from app.models.user_session import UserSession
from app.models.file import File
from app.utils.audit_logger import AuditLogger
from app.utils.session_manager import SessionManager
import csv
import io
import json
from sqlalchemy import func
from werkzeug.security import generate_password_hash
import secrets
import string

class BulkUserOperations:
    """Handles bulk user management operations"""
    
    @staticmethod
    def bulk_disable_users(user_ids, reason="Administrative action"):
        """
        Bulk disable multiple users
        
        Args:
            user_ids: List of user IDs to disable
            reason: Reason for disabling users
            
        Returns:
            dict: Operation results
        """
        try:
            if not user_ids:
                return {'error': 'No users specified'}
            
            results = {
                'success': True,
                'processed': 0,
                'disabled': 0,
                'already_disabled': 0,
                'errors': [],
                'user_details': []
            }
            
            for user_id in user_ids:
                try:
                    user = User.query.get(user_id)
                    if not user:
                        results['errors'].append(f"User {user_id} not found")
                        continue
                    
                    results['processed'] += 1
                    
                    if not user.is_active_account:
                        results['already_disabled'] += 1
                        results['user_details'].append({
                            'user_id': user_id,
                            'username': user.username,
                            'action': 'already_disabled'
                        })
                        continue
                    
                    # Disable user
                    user.is_active_account = False
                    
                    # Terminate all user sessions
                    SessionManager.terminate_user_sessions(user_id, exclude_current=False)
                    
                    results['disabled'] += 1
                    results['user_details'].append({
                        'user_id': user_id,
                        'username': user.username,
                        'action': 'disabled'
                    })
                    
                    # Log the action
                    AuditLogger.log_admin_action(
                        'admin_user_bulk_disable',
                        target_user_id=user_id,
                        target_username=user.username,
                        description=f"User disabled via bulk operation: {reason}"
                    )
                    
                except Exception as e:
                    results['errors'].append(f"Error disabling user {user_id}: {str(e)}")
            
            # Commit all changes
            db.session.commit()
            
            # Log bulk operation summary
            AuditLogger.log_admin_action(
                'admin_bulk_operation_complete',
                description=f"Bulk disable operation: {results['disabled']} users disabled, "
                          f"{results['already_disabled']} already disabled, {len(results['errors'])} errors"
            )
            
            return results
            
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Bulk disable operation failed: {e}")
            return {'error': f'Bulk disable operation failed: {str(e)}'}
    
    @staticmethod
    def bulk_enable_users(user_ids, reason="Administrative action"):
        """
        Bulk enable multiple users
        
        Args:
            user_ids: List of user IDs to enable
            reason: Reason for enabling users
            
        Returns:
            dict: Operation results
        """
        try:
            if not user_ids:
                return {'error': 'No users specified'}
            
            results = {
                'success': True,
                'processed': 0,
                'enabled': 0,
                'already_enabled': 0,
                'errors': [],
                'user_details': []
            }
            
            for user_id in user_ids:
                try:
                    user = User.query.get(user_id)
                    if not user:
                        results['errors'].append(f"User {user_id} not found")
                        continue
                    
                    results['processed'] += 1
                    
                    if user.is_active_account:
                        results['already_enabled'] += 1
                        results['user_details'].append({
                            'user_id': user_id,
                            'username': user.username,
                            'action': 'already_enabled'
                        })
                        continue
                    
                    # Enable user
                    user.is_active_account = True
                    
                    # Reset failed login attempts
                    user.reset_failed_logins()
                    
                    results['enabled'] += 1
                    results['user_details'].append({
                        'user_id': user_id,
                        'username': user.username,
                        'action': 'enabled'
                    })
                    
                    # Log the action
                    AuditLogger.log_admin_action(
                        'admin_user_bulk_enable',
                        target_user_id=user_id,
                        target_username=user.username,
                        description=f"User enabled via bulk operation: {reason}"
                    )
                    
                except Exception as e:
                    results['errors'].append(f"Error enabling user {user_id}: {str(e)}")
            
            # Commit all changes
            db.session.commit()
            
            # Log bulk operation summary
            AuditLogger.log_admin_action(
                'admin_bulk_operation_complete',
                description=f"Bulk enable operation: {results['enabled']} users enabled, "
                          f"{results['already_enabled']} already enabled, {len(results['errors'])} errors"
            )
            
            return results
            
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Bulk enable operation failed: {e}")
            return {'error': f'Bulk enable operation failed: {str(e)}'}
    
    @staticmethod
    def bulk_reset_passwords(user_ids, password_length=12, notify_users=False):
        """
        Bulk reset passwords for multiple users
        
        Args:
            user_ids: List of user IDs to reset passwords for
            password_length: Length of generated passwords
            notify_users: Whether to notify users (placeholder for future email integration)
            
        Returns:
            dict: Operation results including new passwords
        """
        try:
            if not user_ids:
                return {'error': 'No users specified'}
            
            results = {
                'success': True,
                'processed': 0,
                'reset': 0,
                'errors': [],
                'user_credentials': [],
                'password_list': []
            }
            
            for user_id in user_ids:
                try:
                    user = User.query.get(user_id)
                    if not user:
                        results['errors'].append(f"User {user_id} not found")
                        continue
                    
                    results['processed'] += 1
                    
                    # Generate new password
                    new_password = BulkUserOperations._generate_secure_password(password_length)
                    
                    # Set new password
                    user.set_password(new_password)
                    
                    # Reset failed login attempts
                    user.reset_failed_logins()
                    
                    # Terminate all existing sessions (force re-login)
                    SessionManager.terminate_user_sessions(user_id, exclude_current=False)
                    
                    results['reset'] += 1
                    credential_info = {
                        'user_id': user_id,
                        'username': user.username,
                        'email': user.email,
                        'new_password': new_password,
                        'reset_at': datetime.now(timezone.utc).isoformat()
                    }
                    results['user_credentials'].append(credential_info)
                    results['password_list'].append(f"{user.username}: {new_password}")
                    
                    # Log the action (without password)
                    AuditLogger.log_admin_action(
                        'admin_user_bulk_password_reset',
                        target_user_id=user_id,
                        target_username=user.username,
                        description="Password reset via bulk operation"
                    )
                    
                except Exception as e:
                    results['errors'].append(f"Error resetting password for user {user_id}: {str(e)}")
            
            # Commit all changes
            db.session.commit()
            
            # Log bulk operation summary
            AuditLogger.log_admin_action(
                'admin_bulk_operation_complete',
                description=f"Bulk password reset operation: {results['reset']} passwords reset, {len(results['errors'])} errors"
            )
            
            return results
            
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Bulk password reset operation failed: {e}")
            return {'error': f'Bulk password reset operation failed: {str(e)}'}
    
    @staticmethod
    def bulk_clear_sessions(user_ids, reason="Administrative action"):
        """
        Bulk clear sessions for multiple users
        
        Args:
            user_ids: List of user IDs to clear sessions for
            reason: Reason for clearing sessions
            
        Returns:
            dict: Operation results
        """
        try:
            if not user_ids:
                return {'error': 'No users specified'}
            
            results = {
                'success': True,
                'processed': 0,
                'sessions_cleared': 0,
                'total_sessions': 0,
                'errors': [],
                'user_details': []
            }
            
            for user_id in user_ids:
                try:
                    user = User.query.get(user_id)
                    if not user:
                        results['errors'].append(f"User {user_id} not found")
                        continue
                    
                    results['processed'] += 1
                    
                    # Get active sessions count before clearing
                    active_sessions = UserSession.get_active_sessions_for_user(user_id)
                    session_count = len(active_sessions)
                    
                    if session_count > 0:
                        # Clear all sessions
                        cleared_count = SessionManager.terminate_user_sessions(user_id, exclude_current=False)
                        
                        results['sessions_cleared'] += 1
                        results['total_sessions'] += cleared_count
                        
                        results['user_details'].append({
                            'user_id': user_id,
                            'username': user.username,
                            'sessions_terminated': cleared_count
                        })
                        
                        # Log the action
                        AuditLogger.log_admin_action(
                            'admin_user_bulk_session_clear',
                            target_user_id=user_id,
                            target_username=user.username,
                            description=f"Sessions cleared via bulk operation ({cleared_count} sessions): {reason}"
                        )
                    else:
                        results['user_details'].append({
                            'user_id': user_id,
                            'username': user.username,
                            'sessions_terminated': 0
                        })
                    
                except Exception as e:
                    results['errors'].append(f"Error clearing sessions for user {user_id}: {str(e)}")
            
            # Log bulk operation summary
            AuditLogger.log_admin_action(
                'admin_bulk_operation_complete',
                description=f"Bulk session clear operation: {results['total_sessions']} sessions cleared "
                          f"for {results['sessions_cleared']} users, {len(results['errors'])} errors"
            )
            
            return results
            
        except Exception as e:
            current_app.logger.error(f"Bulk session clear operation failed: {e}")
            return {'error': f'Bulk session clear operation failed: {str(e)}'}
    
    @staticmethod
    def bulk_delete_users(user_ids, confirm_deletion=False, delete_files=False):
        """
        Bulk delete multiple users (DESTRUCTIVE OPERATION)
        
        Args:
            user_ids: List of user IDs to delete
            confirm_deletion: Must be True to actually delete
            delete_files: Whether to also delete user files
            
        Returns:
            dict: Operation results
        """
        if not confirm_deletion:
            return {'error': 'Must confirm deletion - this is a destructive operation'}
        
        try:
            if not user_ids:
                return {'error': 'No users specified'}
            
            results = {
                'success': True,
                'processed': 0,
                'deleted': 0,
                'files_deleted': 0,
                'errors': [],
                'user_details': []
            }
            
            for user_id in user_ids:
                try:
                    user = User.query.get(user_id)
                    if not user:
                        results['errors'].append(f"User {user_id} not found")
                        continue
                    
                    results['processed'] += 1
                    username = user.username
                    
                    # Get file count before deletion
                    user_files = File.query.filter_by(user_id=user_id).all()
                    file_count = len(user_files)
                    
                    # Delete user files if requested
                    if delete_files and file_count > 0:
                        for file_record in user_files:
                            try:
                                # Delete physical file
                                import os
                                file_path = file_record.get_file_path()
                                if os.path.exists(file_path):
                                    os.remove(file_path)
                                
                                # Delete file record
                                db.session.delete(file_record)
                                results['files_deleted'] += 1
                                
                            except Exception as e:
                                current_app.logger.error(f"Error deleting file {file_record.id}: {e}")
                    
                    # Clear all user sessions
                    SessionManager.terminate_user_sessions(user_id, exclude_current=False)
                    
                    # Delete user record
                    db.session.delete(user)
                    
                    results['deleted'] += 1
                    results['user_details'].append({
                        'user_id': user_id,
                        'username': username,
                        'files_deleted': file_count if delete_files else 0
                    })
                    
                    # Log the action
                    AuditLogger.log_admin_action(
                        'admin_user_bulk_delete',
                        target_user_id=user_id,
                        target_username=username,
                        description=f"User deleted via bulk operation (files deleted: {delete_files})"
                    )
                    
                except Exception as e:
                    results['errors'].append(f"Error deleting user {user_id}: {str(e)}")
            
            # Commit all changes
            db.session.commit()
            
            # Log bulk operation summary
            AuditLogger.log_admin_action(
                'admin_bulk_operation_complete',
                description=f"Bulk delete operation: {results['deleted']} users deleted, "
                          f"{results['files_deleted']} files deleted, {len(results['errors'])} errors"
            )
            
            return results
            
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Bulk delete operation failed: {e}")
            return {'error': f'Bulk delete operation failed: {str(e)}'}
    
    @staticmethod
    def export_user_data(user_ids=None, format='csv', include_files=False):
        """
        Export user data for backup or compliance
        
        Args:
            user_ids: List of specific user IDs (None for all users)
            format: Export format ('csv' or 'json')
            include_files: Whether to include file information
            
        Returns:
            tuple: (content, filename)
        """
        try:
            # Get users
            if user_ids:
                users = User.query.filter(User.id.in_(user_ids)).all()
            else:
                users = User.query.all()
            
            if format == 'csv':
                return BulkUserOperations._export_users_csv(users, include_files)
            elif format == 'json':
                return BulkUserOperations._export_users_json(users, include_files)
            else:
                raise ValueError(f"Unsupported export format: {format}")
                
        except Exception as e:
            current_app.logger.error(f"User data export failed: {e}")
            raise
    
    @staticmethod
    def _export_users_csv(users, include_files):
        """Export users to CSV format"""
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        headers = [
            'User ID', 'Username', 'Email', 'Is Active', 'Is Admin', 'Created At',
            'Last Login', 'Storage Used', 'Storage Quota', 'Failed Logins',
            'Is Locked Out', '2FA Enabled'
        ]
        
        if include_files:
            headers.extend(['File Count', 'Total File Size'])
        
        writer.writerow(headers)
        
        # Write user data
        for user in users:
            row = [
                user.id,
                user.username,
                user.email,
                user.is_active_account,
                user.is_admin,
                user.created_at.isoformat() if user.created_at else '',
                user.last_login.isoformat() if user.last_login else '',
                user.current_storage_bytes or 0,
                user.storage_quota_bytes or 0,
                user.failed_login_attempts or 0,
                user.is_locked_out(),
                user.totp_enabled
            ]
            
            if include_files:
                file_count = File.query.filter_by(user_id=user.id).count()
                total_size = db.session.query(func.sum(File.size)).filter_by(user_id=user.id).scalar() or 0
                row.extend([file_count, total_size])
            
            writer.writerow(row)
        
        csv_content = output.getvalue()
        output.close()
        
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        filename = f'safevault_users_export_{timestamp}.csv'
        
        # Log export
        AuditLogger.log_admin_action(
            'admin_user_data_export',
            description=f"User data exported to CSV ({len(users)} users)"
        )
        
        return csv_content, filename
    
    @staticmethod
    def _export_users_json(users, include_files):
        """Export users to JSON format"""
        export_data = {
            'export_info': {
                'exported_at': datetime.now(timezone.utc).isoformat(),
                'total_users': len(users),
                'includes_files': include_files,
                'safevault_version': '1.0'
            },
            'users': []
        }
        
        for user in users:
            user_data = {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'is_active': user.is_active_account,
                'is_admin': user.is_admin,
                'created_at': user.created_at.isoformat() if user.created_at else None,
                'last_login': user.last_login.isoformat() if user.last_login else None,
                'storage_used_bytes': user.current_storage_bytes or 0,
                'storage_quota_bytes': user.storage_quota_bytes or 0,
                'failed_login_attempts': user.failed_login_attempts or 0,
                'is_locked_out': user.is_locked_out(),
                'totp_enabled': user.totp_enabled,
                'last_login_ip': user.last_login_ip
            }
            
            if include_files:
                files = File.query.filter_by(user_id=user.id).all()
                user_data['files'] = [
                    {
                        'id': f.id,
                        'filename': f.filename,
                        'size': f.size,
                        'uploaded_at': f.uploaded_at.isoformat() if f.uploaded_at else None,
                        'mime_type': f.mime_type,
                        'hash_value': f.hash_value
                    }
                    for f in files
                ]
                user_data['file_count'] = len(files)
                user_data['total_file_size'] = sum(f.size for f in files)
            
            export_data['users'].append(user_data)
        
        json_content = json.dumps(export_data, indent=2, default=str)
        
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        filename = f'safevault_users_export_{timestamp}.json'
        
        # Log export
        AuditLogger.log_admin_action(
            'admin_user_data_export',
            description=f"User data exported to JSON ({len(users)} users)"
        )
        
        return json_content, filename
    
    @staticmethod
    def _generate_secure_password(length=12):
        """Generate a secure random password"""
        alphabet = string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(secrets.choice(alphabet) for _ in range(length))
    
    @staticmethod
    def get_user_statistics():
        """Get user statistics for bulk operations dashboard"""
        try:
            stats = {
                'total_users': User.query.count(),
                'active_users': User.query.filter_by(is_active_account=True).count(),
                'inactive_users': User.query.filter_by(is_active_account=False).count(),
                'admin_users': User.query.filter_by(is_admin=True).count(),
                'locked_users': User.query.filter(User.failed_login_attempts >= 3).count(),
                'users_with_2fa': User.query.filter_by(totp_enabled=True).count(),
                'recent_users': User.query.filter(
                    User.created_at >= datetime.now(timezone.utc) - timedelta(days=30)
                ).count(),
                'users_with_files': db.session.query(User.id).join(File).distinct().count(),
                'users_with_quota': User.query.filter(User.storage_quota_bytes.isnot(None)).count()
            }
            
            return stats
            
        except Exception as e:
            current_app.logger.error(f"Error getting user statistics: {e}")
            return {}
    
    @staticmethod
    def validate_bulk_operation(user_ids, operation_type):
        """
        Validate bulk operation before execution
        
        Args:
            user_ids: List of user IDs
            operation_type: Type of operation ('disable', 'enable', 'delete', etc.)
            
        Returns:
            dict: Validation results
        """
        try:
            validation = {
                'valid': True,
                'warnings': [],
                'errors': [],
                'user_count': len(user_ids) if user_ids else 0,
                'admin_users': [],
                'active_sessions': 0
            }
            
            if not user_ids:
                validation['valid'] = False
                validation['errors'].append('No users selected')
                return validation
            
            # Check each user
            for user_id in user_ids:
                user = User.query.get(user_id)
                if not user:
                    validation['errors'].append(f"User {user_id} not found")
                    continue
                
                # Check for admin users
                if user.is_admin:
                    validation['admin_users'].append({
                        'id': user.id,
                        'username': user.username
                    })
                    validation['warnings'].append(f"User {user.username} is an admin")
                
                # Count active sessions
                active_sessions = UserSession.get_active_sessions_for_user(user_id)
                validation['active_sessions'] += len(active_sessions)
            
            # Operation-specific validations
            if operation_type == 'delete':
                if validation['admin_users']:
                    validation['warnings'].append("Deleting admin users - ensure other admins exist")
                
                validation['warnings'].append("User deletion is permanent and cannot be undone")
            
            if validation['errors']:
                validation['valid'] = False
            
            return validation
            
        except Exception as e:
            current_app.logger.error(f"Bulk operation validation failed: {e}")
            return {
                'valid': False,
                'errors': [f'Validation failed: {str(e)}'],
                'warnings': [],
                'user_count': 0,
                'admin_users': [],
                'active_sessions': 0
            }