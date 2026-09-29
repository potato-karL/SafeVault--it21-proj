"""
Advanced Session Management for SafeVault
Provides comprehensive session monitoring, management, and security features
"""

from datetime import datetime, timezone, timedelta
from flask import current_app, request
from app import db
from app.models.user_session import UserSession
from app.models.user import User
from app.utils.audit_logger import AuditLogger
from app.utils.session_manager import SessionManager
from sqlalchemy import func, desc, and_, or_
import json

class SessionManagement:
    """Handles advanced session management operations"""
    
    @staticmethod
    def get_all_active_sessions(filters=None):
        """
        Get all active sessions with filtering and pagination
        
        Args:
            filters: Dictionary of filter criteria
            
        Returns:
            dict: Session data with pagination info
        """
        try:
            filters = filters or {}
            
            # Start with active sessions
            query = UserSession.query.filter_by(is_active=True)
            
            # Apply filters
            query = SessionManagement._apply_session_filters(query, filters)
            
            # Get total count
            total_count = query.count()
            
            # Apply sorting
            sort_by = filters.get('sort_by', 'last_activity')
            sort_order = filters.get('sort_order', 'desc')
            
            if sort_by == 'username':
                # Join with User table for username sorting
                query = query.join(User, UserSession.user_id == User.id)
                if sort_order == 'desc':
                    query = query.order_by(desc(User.username))
                else:
                    query = query.order_by(User.username)
            elif hasattr(UserSession, sort_by):
                sort_column = getattr(UserSession, sort_by)
                if sort_order == 'desc':
                    query = query.order_by(desc(sort_column))
                else:
                    query = query.order_by(sort_column)
            
            # Apply pagination
            page = filters.get('page', 1)
            per_page = min(filters.get('per_page', 25), 100)
            
            paginated = query.paginate(
                page=page,
                per_page=per_page,
                error_out=False
            )
            
            # Format session data
            sessions_data = []
            for session in paginated.items:
                session_data = SessionManagement._format_session_data(session)
                sessions_data.append(session_data)
            
            return {
                'sessions': sessions_data,
                'pagination': {
                    'page': paginated.page,
                    'pages': paginated.pages,
                    'per_page': paginated.per_page,
                    'total': paginated.total,
                    'has_next': paginated.has_next,
                    'has_prev': paginated.has_prev,
                    'next_num': paginated.next_num,
                    'prev_num': paginated.prev_num
                },
                'total_count': total_count,
                'filters_applied': SessionManagement._get_applied_filters(filters)
            }
            
        except Exception as e:
            current_app.logger.error(f"Error getting active sessions: {e}")
            return {
                'error': str(e),
                'sessions': [],
                'pagination': {},
                'total_count': 0
            }
    
    @staticmethod
    def _apply_session_filters(query, filters):
        """Apply filters to session query"""
        
        # User filter
        if 'user_id' in filters:
            query = query.filter(UserSession.user_id == filters['user_id'])
        
        if 'username' in filters:
            query = query.join(User, UserSession.user_id == User.id).filter(
                User.username.ilike(f"%{filters['username']}%")
            )
        
        # IP address filter
        if 'ip_address' in filters:
            query = query.filter(UserSession.ip_address.ilike(f"%{filters['ip_address']}%"))
        
        # Device type filter
        if 'device_type' in filters:
            query = query.filter(UserSession.device_type == filters['device_type'])
        
        # Location filter
        if 'country' in filters:
            query = query.filter(UserSession.country == filters['country'])
        
        # Suspicious sessions filter
        if 'is_suspicious' in filters:
            is_suspicious = filters['is_suspicious'] in ['true', '1', True]
            query = query.filter(UserSession.is_suspicious == is_suspicious)
        
        # Risk level filter
        if 'min_risk_level' in filters:
            try:
                min_risk = int(filters['min_risk_level'])
                query = query.filter(UserSession.risk_score >= min_risk)
            except (ValueError, TypeError):
                pass
        
        # Login method filter
        if 'login_method' in filters:
            query = query.filter(UserSession.login_method == filters['login_method'])
        
        # Time range filters
        if 'created_after' in filters:
            try:
                created_after = datetime.fromisoformat(filters['created_after'].replace('Z', '+00:00'))
                query = query.filter(UserSession.created_at >= created_after)
            except (ValueError, AttributeError):
                pass
        
        if 'last_activity_after' in filters:
            try:
                activity_after = datetime.fromisoformat(filters['last_activity_after'].replace('Z', '+00:00'))
                query = query.filter(UserSession.last_activity >= activity_after)
            except (ValueError, AttributeError):
                pass
        
        # Idle sessions (no activity for X minutes)
        if 'idle_minutes' in filters:
            try:
                idle_minutes = int(filters['idle_minutes'])
                cutoff_time = datetime.now(timezone.utc) - timedelta(minutes=idle_minutes)
                query = query.filter(UserSession.last_activity <= cutoff_time)
            except (ValueError, TypeError):
                pass
        
        return query
    
    @staticmethod
    def _format_session_data(session):
        """Format session data for display"""
        try:
            # Calculate session duration
            duration = datetime.now(timezone.utc) - session.created_at
            duration_str = SessionManagement._format_duration(duration)
            
            # Calculate idle time
            idle_duration = datetime.now(timezone.utc) - session.last_activity
            idle_str = SessionManagement._format_duration(idle_duration)
            
            return {
                'id': session.id,
                'user_id': session.user_id,
                'username': session.user.username if session.user else 'Unknown',
                'user_email': session.user.email if session.user else 'Unknown',
                'created_at': session.created_at.isoformat(),
                'last_activity': session.last_activity.isoformat(),
                'ip_address': session.ip_address,
                'device_summary': session.get_device_summary(),
                'location_summary': session.get_location_summary(),
                'login_method': session.login_method,
                'is_suspicious': session.is_suspicious,
                'risk_score': session.risk_score,
                'duration': duration_str,
                'idle_time': idle_str,
                'device_type': session.device_type,
                'browser_family': session.browser_family,
                'os_family': session.os_family,
                'country': session.country,
                'region': session.region,
                'city': session.city
            }
            
        except Exception as e:
            current_app.logger.error(f"Error formatting session data: {e}")
            return {
                'id': session.id,
                'error': 'Error formatting session data'
            }
    
    @staticmethod
    def _format_duration(duration):
        """Format timedelta as human-readable string"""
        if duration.days > 0:
            return f"{duration.days}d {duration.seconds // 3600}h"
        elif duration.seconds >= 3600:
            return f"{duration.seconds // 3600}h {(duration.seconds % 3600) // 60}m"
        elif duration.seconds >= 60:
            return f"{duration.seconds // 60}m"
        else:
            return f"{duration.seconds}s"
    
    @staticmethod
    def _get_applied_filters(filters):
        """Get summary of applied filters"""
        applied = []
        
        if 'username' in filters:
            applied.append(f"Username: {filters['username']}")
        
        if 'ip_address' in filters:
            applied.append(f"IP: {filters['ip_address']}")
        
        if 'device_type' in filters:
            applied.append(f"Device: {filters['device_type']}")
        
        if 'country' in filters:
            applied.append(f"Country: {filters['country']}")
        
        if 'is_suspicious' in filters:
            suspicious = 'Yes' if filters['is_suspicious'] in ['true', '1', True] else 'No'
            applied.append(f"Suspicious: {suspicious}")
        
        if 'login_method' in filters:
            applied.append(f"Login method: {filters['login_method']}")
        
        return applied
    
    @staticmethod
    def terminate_session(session_id, reason="Administrative action"):
        """
        Terminate a specific session
        
        Args:
            session_id: Session ID to terminate
            reason: Reason for termination
            
        Returns:
            dict: Operation result
        """
        try:
            session = UserSession.query.filter_by(id=session_id, is_active=True).first()
            
            if not session:
                return {'error': 'Session not found or already terminated'}
            
            # Get user info for logging
            user = session.user
            username = user.username if user else 'Unknown'
            
            # Terminate the session
            session.terminate()
            
            # Log the action
            AuditLogger.log_admin_action(
                'admin_session_terminate',
                target_user_id=session.user_id,
                target_username=username,
                description=f"Session {session_id} terminated by admin: {reason}"
            )
            
            return {
                'success': True,
                'session_id': session_id,
                'username': username,
                'message': f'Session terminated for user {username}'
            }
            
        except Exception as e:
            current_app.logger.error(f"Error terminating session {session_id}: {e}")
            return {'error': f'Failed to terminate session: {str(e)}'}
    
    @staticmethod
    def terminate_user_sessions(user_id, exclude_current=True, reason="Administrative action"):
        """
        Terminate all sessions for a specific user
        
        Args:
            user_id: User ID
            exclude_current: Whether to exclude current admin session
            reason: Reason for termination
            
        Returns:
            dict: Operation result
        """
        try:
            user = User.query.get(user_id)
            if not user:
                return {'error': 'User not found'}
            
            # Get current session ID if excluding current
            current_session_id = None
            if exclude_current and request:
                from flask import session as flask_session
                current_session_id = flask_session.get('session_tracking_id')
            
            # Get active sessions
            active_sessions = UserSession.get_active_sessions_for_user(user_id)
            
            if exclude_current and current_session_id:
                active_sessions = [s for s in active_sessions if s.id != current_session_id]
            
            terminated_count = 0
            for session in active_sessions:
                session.terminate()
                terminated_count += 1
            
            # Log the action
            AuditLogger.log_admin_action(
                'admin_user_sessions_terminate',
                target_user_id=user_id,
                target_username=user.username,
                description=f"All sessions terminated for user {user.username} ({terminated_count} sessions): {reason}"
            )
            
            return {
                'success': True,
                'user_id': user_id,
                'username': user.username,
                'terminated_count': terminated_count,
                'message': f'Terminated {terminated_count} sessions for user {user.username}'
            }
            
        except Exception as e:
            current_app.logger.error(f"Error terminating user sessions for {user_id}: {e}")
            return {'error': f'Failed to terminate user sessions: {str(e)}'}
    
    @staticmethod
    def bulk_terminate_sessions(session_ids, reason="Bulk administrative action"):
        """
        Terminate multiple sessions
        
        Args:
            session_ids: List of session IDs to terminate
            reason: Reason for termination
            
        Returns:
            dict: Operation results
        """
        try:
            results = {
                'success': True,
                'processed': 0,
                'terminated': 0,
                'errors': [],
                'session_details': []
            }
            
            for session_id in session_ids:
                try:
                    result = SessionManagement.terminate_session(session_id, reason)
                    results['processed'] += 1
                    
                    if 'error' in result:
                        results['errors'].append(f"Session {session_id}: {result['error']}")
                    else:
                        results['terminated'] += 1
                        results['session_details'].append({
                            'session_id': session_id,
                            'username': result.get('username', 'Unknown')
                        })
                
                except Exception as e:
                    results['errors'].append(f"Session {session_id}: {str(e)}")
            
            # Log bulk operation
            AuditLogger.log_admin_action(
                'admin_bulk_session_terminate',
                description=f"Bulk session termination: {results['terminated']} sessions terminated, {len(results['errors'])} errors"
            )
            
            return results
            
        except Exception as e:
            current_app.logger.error(f"Bulk session termination failed: {e}")
            return {'error': f'Bulk termination failed: {str(e)}'}
    
    @staticmethod
    def flag_session_suspicious(session_id, reason="Administrative review"):
        """
        Flag a session as suspicious
        
        Args:
            session_id: Session ID to flag
            reason: Reason for flagging
            
        Returns:
            dict: Operation result
        """
        try:
            session = UserSession.query.filter_by(id=session_id).first()
            
            if not session:
                return {'error': 'Session not found'}
            
            # Flag as suspicious
            session.is_suspicious = True
            session.risk_score = min(session.risk_score + 30, 100)
            db.session.commit()
            
            # Log the action
            AuditLogger.log_security_event(
                'security_session_flagged',
                description=f"Session {session_id} flagged as suspicious by admin: {reason}",
                is_suspicious=True
            )
            
            return {
                'success': True,
                'session_id': session_id,
                'message': f'Session flagged as suspicious'
            }
            
        except Exception as e:
            current_app.logger.error(f"Error flagging session {session_id}: {e}")
            db.session.rollback()
            return {'error': f'Failed to flag session: {str(e)}'}
    
    @staticmethod
    def get_session_statistics():
        """Get session statistics for dashboard"""
        try:
            now = datetime.now(timezone.utc)
            
            stats = {
                'total_active': UserSession.query.filter_by(is_active=True).count(),
                'suspicious_sessions': UserSession.query.filter_by(
                    is_active=True, 
                    is_suspicious=True
                ).count(),
                'high_risk_sessions': UserSession.query.filter(
                    UserSession.is_active == True,
                    UserSession.risk_score > 70
                ).count(),
                'sessions_today': UserSession.query.filter(
                    UserSession.created_at >= now.replace(hour=0, minute=0, second=0, microsecond=0)
                ).count(),
                'unique_users_active': db.session.query(UserSession.user_id).filter_by(
                    is_active=True
                ).distinct().count(),
                'device_breakdown': SessionManagement._get_device_breakdown(),
                'location_breakdown': SessionManagement._get_location_breakdown(),
                'login_method_breakdown': SessionManagement._get_login_method_breakdown(),
                'idle_sessions': SessionManagement._get_idle_sessions_count()
            }
            
            return stats
            
        except Exception as e:
            current_app.logger.error(f"Error getting session statistics: {e}")
            return {}
    
    @staticmethod
    def _get_device_breakdown():
        """Get breakdown of sessions by device type"""
        try:
            result = db.session.query(
                UserSession.device_type,
                func.count(UserSession.id).label('count')
            ).filter_by(is_active=True).group_by(UserSession.device_type).all()
            
            return {device_type or 'Unknown': count for device_type, count in result}
            
        except Exception as e:
            return {}
    
    @staticmethod
    def _get_location_breakdown():
        """Get breakdown of sessions by country"""
        try:
            result = db.session.query(
                UserSession.country,
                func.count(UserSession.id).label('count')
            ).filter_by(is_active=True).group_by(UserSession.country).limit(10).all()
            
            return {country or 'Unknown': count for country, count in result}
            
        except Exception as e:
            return {}
    
    @staticmethod
    def _get_login_method_breakdown():
        """Get breakdown of sessions by login method"""
        try:
            result = db.session.query(
                UserSession.login_method,
                func.count(UserSession.id).label('count')
            ).filter_by(is_active=True).group_by(UserSession.login_method).all()
            
            return {method or 'Unknown': count for method, count in result}
            
        except Exception as e:
            return {}
    
    @staticmethod
    def _get_idle_sessions_count():
        """Get count of idle sessions (no activity for 30+ minutes)"""
        try:
            cutoff_time = datetime.now(timezone.utc) - timedelta(minutes=30)
            return UserSession.query.filter(
                UserSession.is_active == True,
                UserSession.last_activity <= cutoff_time
            ).count()
            
        except Exception as e:
            return 0
    
    @staticmethod
    def cleanup_idle_sessions(idle_minutes=60):
        """
        Clean up idle sessions (optional automatic cleanup)
        
        Args:
            idle_minutes: Minutes of inactivity before cleanup
            
        Returns:
            dict: Cleanup results
        """
        try:
            cutoff_time = datetime.now(timezone.utc) - timedelta(minutes=idle_minutes)
            
            idle_sessions = UserSession.query.filter(
                UserSession.is_active == True,
                UserSession.last_activity <= cutoff_time
            ).all()
            
            cleaned_count = 0
            for session in idle_sessions:
                session.terminate()
                cleaned_count += 1
            
            # Log cleanup
            if cleaned_count > 0:
                AuditLogger.log_system_event(
                    'system_idle_session_cleanup',
                    description=f"Cleaned up {cleaned_count} idle sessions (idle > {idle_minutes} minutes)"
                )
            
            return {
                'success': True,
                'cleaned_count': cleaned_count,
                'cutoff_time': cutoff_time.isoformat()
            }
            
        except Exception as e:
            current_app.logger.error(f"Error cleaning up idle sessions: {e}")
            return {'error': f'Cleanup failed: {str(e)}'}
    
    @staticmethod
    def export_session_data(filters=None, format='csv'):
        """Export session data for analysis"""
        try:
            # Get all sessions (remove pagination for export)
            export_filters = filters.copy() if filters else {}
            export_filters.pop('page', None)
            export_filters.pop('per_page', None)
            
            session_data = SessionManagement.get_all_active_sessions(export_filters)
            
            if format == 'csv':
                return SessionManagement._export_sessions_csv(session_data)
            elif format == 'json':
                return SessionManagement._export_sessions_json(session_data)
            else:
                raise ValueError(f"Unsupported export format: {format}")
                
        except Exception as e:
            raise Exception(f"Session export failed: {str(e)}")
    
    @staticmethod
    def _export_sessions_csv(session_data):
        """Export sessions to CSV format"""
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'Session ID', 'Username', 'Email', 'IP Address', 'Device Type',
            'Browser', 'OS', 'Country', 'Region', 'City', 'Login Method',
            'Created At', 'Last Activity', 'Duration', 'Idle Time',
            'Is Suspicious', 'Risk Score'
        ])
        
        # Write data
        for session in session_data.get('sessions', []):
            writer.writerow([
                session['id'],
                session['username'],
                session['user_email'],
                session['ip_address'],
                session['device_type'] or '',
                session['browser_family'] or '',
                session['os_family'] or '',
                session['country'] or '',
                session['region'] or '',
                session['city'] or '',
                session['login_method'] or '',
                session['created_at'],
                session['last_activity'],
                session['duration'],
                session['idle_time'],
                session['is_suspicious'],
                session['risk_score']
            ])
        
        csv_content = output.getvalue()
        output.close()
        
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        filename = f'active_sessions_export_{timestamp}.csv'
        
        return csv_content, filename
    
    @staticmethod
    def _export_sessions_json(session_data):
        """Export sessions to JSON format"""
        export_data = {
            'export_info': {
                'exported_at': datetime.now(timezone.utc).isoformat(),
                'total_sessions': session_data.get('total_count', 0),
                'filters_applied': session_data.get('filters_applied', [])
            },
            'sessions': session_data.get('sessions', [])
        }
        
        json_content = json.dumps(export_data, indent=2, default=str)
        
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        filename = f'active_sessions_export_{timestamp}.json'
        
        return json_content, filename


# Global session management instance
session_management = SessionManagement()