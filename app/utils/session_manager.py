"""
Session Manager for SafeVault
Handles user session tracking and management
"""

from flask import session, request, current_app
from flask_login import current_user
from app.models.user_session import UserSession
from app import db
import uuid
from datetime import datetime, timezone, timedelta
import hashlib

class SessionManager:
    """Manages user sessions with advanced tracking"""
    
    @staticmethod
    def create_user_session(user_id, login_method='password'):
        """Create a new user session with tracking"""
        try:
            # Generate or get session ID
            if 'session_tracking_id' not in session:
                session['session_tracking_id'] = str(uuid.uuid4())
            
            session_id = session['session_tracking_id']
            
            # Check if session already exists (avoid duplicates)
            existing_session = UserSession.query.filter_by(id=session_id).first()
            if existing_session:
                existing_session.update_activity()
                existing_session.login_method = login_method
                db.session.commit()
                return existing_session
            
            # Create new session
            user_session = UserSession.create_session(
                session_id=session_id,
                user_id=user_id,
                request=request
            )
            user_session.login_method = login_method
            
            # Set session expiry (configurable)
            session_timeout = current_app.config.get('SESSION_TIMEOUT_HOURS', 24)
            user_session.expires_at = datetime.now(timezone.utc) + timedelta(hours=session_timeout)
            
            db.session.commit()
            
            # Store in Flask session for quick access
            session['user_session_id'] = session_id
            session.permanent = True
            
            current_app.logger.info(f"Created session {session_id} for user {user_id} via {login_method}")
            return user_session
            
        except Exception as e:
            current_app.logger.error(f"Error creating user session: {e}")
            db.session.rollback()
            return None
    
    @staticmethod
    def update_session_activity():
        """Update current session's last activity"""
        try:
            if not current_user.is_authenticated:
                return
            
            session_id = session.get('session_tracking_id')
            if not session_id:
                return
            
            user_session = UserSession.query.filter_by(id=session_id).first()
            if user_session and user_session.is_active:
                user_session.update_activity()
                
        except Exception as e:
            current_app.logger.error(f"Error updating session activity: {e}")
    
    @staticmethod
    def get_current_session():
        """Get current user's session object"""
        try:
            if not current_user.is_authenticated:
                return None
            
            session_id = session.get('session_tracking_id')
            if not session_id:
                return None
            
            return UserSession.query.filter_by(
                id=session_id, 
                user_id=current_user.id,
                is_active=True
            ).first()
            
        except Exception as e:
            current_app.logger.error(f"Error getting current session: {e}")
            return None
    
    @staticmethod
    def terminate_current_session():
        """Terminate the current session"""
        try:
            user_session = SessionManager.get_current_session()
            if user_session:
                user_session.terminate()
                current_app.logger.info(f"Terminated session {user_session.id}")
            
            # Clear Flask session data
            session.pop('session_tracking_id', None)
            session.pop('user_session_id', None)
            
        except Exception as e:
            current_app.logger.error(f"Error terminating current session: {e}")
    
    @staticmethod
    def terminate_user_sessions(user_id, exclude_current=True):
        """Terminate all sessions for a user"""
        try:
            current_session_id = None
            if exclude_current and current_user.is_authenticated and current_user.id == user_id:
                current_session_id = session.get('session_tracking_id')
            
            terminated_count = UserSession.terminate_user_sessions(user_id, current_session_id)
            current_app.logger.info(f"Terminated {terminated_count} sessions for user {user_id}")
            return terminated_count
            
        except Exception as e:
            current_app.logger.error(f"Error terminating user sessions: {e}")
            return 0
    
    @staticmethod
    def get_user_sessions(user_id, active_only=True):
        """Get sessions for a specific user"""
        try:
            if active_only:
                return UserSession.get_active_sessions_for_user(user_id)
            else:
                return UserSession.query.filter_by(user_id=user_id).order_by(UserSession.last_activity.desc()).all()
                
        except Exception as e:
            current_app.logger.error(f"Error getting user sessions: {e}")
            return []
    
    @staticmethod
    def is_suspicious_session(user_session):
        """Check if a session is suspicious based on various factors"""
        if not user_session:
            return False
        
        # Already marked as suspicious
        if user_session.is_suspicious:
            return True
        
        # High risk score
        if user_session.risk_score > 70:
            return True
        
        # Multiple sessions from different locations (would need to compare with other active sessions)
        user_sessions = SessionManager.get_user_sessions(user_session.user_id, active_only=True)
        if len(user_sessions) > 5:  # Too many concurrent sessions
            return True
        
        # Check for conflicting geographic locations
        countries = set()
        for s in user_sessions:
            if s.country:
                countries.add(s.country)
        
        if len(countries) > 2:  # Sessions from more than 2 countries
            return True
        
        return False
    
    @staticmethod
    def flag_session_suspicious(session_id, reason="Manual flag"):
        """Flag a session as suspicious"""
        try:
            user_session = UserSession.query.filter_by(id=session_id).first()
            if user_session:
                user_session.is_suspicious = True
                user_session.risk_score = min(user_session.risk_score + 50, 100)
                db.session.commit()
                current_app.logger.warning(f"Flagged session {session_id} as suspicious: {reason}")
                return True
            return False
            
        except Exception as e:
            current_app.logger.error(f"Error flagging session as suspicious: {e}")
            return False
    
    @staticmethod
    def cleanup_old_sessions():
        """Clean up expired and old inactive sessions"""
        try:
            # Remove expired sessions
            expired_count = UserSession.cleanup_expired()
            
            # Remove old inactive sessions (older than 30 days)
            cutoff_date = datetime.now(timezone.utc) - timedelta(days=30)
            old_sessions = UserSession.query.filter(
                UserSession.is_active == False,
                UserSession.last_activity < cutoff_date
            ).all()
            
            for session in old_sessions:
                db.session.delete(session)
            
            db.session.commit()
            
            total_cleaned = expired_count + len(old_sessions)
            current_app.logger.info(f"Cleaned up {total_cleaned} old sessions")
            return total_cleaned
            
        except Exception as e:
            current_app.logger.error(f"Error during session cleanup: {e}")
            return 0
    
    @staticmethod
    def get_session_stats():
        """Get session statistics for admin dashboard"""
        try:
            stats = {
                'total_active_sessions': UserSession.query.filter_by(is_active=True).count(),
                'total_sessions_today': UserSession.query.filter(
                    UserSession.created_at >= datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
                ).count(),
                'suspicious_sessions': UserSession.query.filter_by(is_suspicious=True, is_active=True).count(),
                'high_risk_sessions': UserSession.query.filter(
                    UserSession.risk_score > 70,
                    UserSession.is_active == True
                ).count(),
                'mobile_sessions': UserSession.query.filter_by(device_type='mobile', is_active=True).count(),
                'desktop_sessions': UserSession.query.filter_by(device_type='pc', is_active=True).count()
            }
            return stats
            
        except Exception as e:
            current_app.logger.error(f"Error getting session stats: {e}")
            return {}
    
    @staticmethod
    def generate_session_fingerprint():
        """Generate a unique fingerprint for the current request"""
        try:
            # Combine various request attributes to create a fingerprint
            fingerprint_data = [
                request.headers.get('User-Agent', ''),
                request.headers.get('Accept-Language', ''),
                request.headers.get('Accept-Encoding', ''),
                SessionManager._get_client_ip(),
            ]
            
            # Create hash of combined data
            fingerprint_string = '|'.join(fingerprint_data)
            return hashlib.sha256(fingerprint_string.encode()).hexdigest()[:16]
            
        except Exception as e:
            current_app.logger.error(f"Error generating session fingerprint: {e}")
            return None
    
    @staticmethod
    def _get_client_ip():
        """Get client IP from request, handling proxies"""
        if 'X-Forwarded-For' in request.headers:
            return request.headers['X-Forwarded-For'].split(',')[0].strip()
        elif 'X-Real-IP' in request.headers:
            return request.headers['X-Real-IP']
        else:
            return request.remote_addr or '127.0.0.1'