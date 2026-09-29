"""
User Session Model for SafeVault
Tracks active user sessions with device info and security details
"""

from datetime import datetime, timezone
from app import db
import user_agents
import geoip2.database
import os

class UserSession(db.Model):
    __tablename__ = 'user_sessions'
    
    id = db.Column(db.String(36), primary_key=True)  # Flask session ID
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Session tracking
    created_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    last_activity = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    expires_at = db.Column(db.DateTime, nullable=True)
    is_active = db.Column(db.Boolean, nullable=False, default=True)
    
    # Request info
    ip_address = db.Column(db.String(45), nullable=False)  # IPv6 support
    user_agent = db.Column(db.Text, nullable=True)
    
    # Parsed device info
    device_type = db.Column(db.String(50), nullable=True)  # mobile, tablet, pc
    device_brand = db.Column(db.String(50), nullable=True)
    device_model = db.Column(db.String(100), nullable=True)
    
    # Browser info
    browser_family = db.Column(db.String(50), nullable=True)
    browser_version = db.Column(db.String(50), nullable=True)
    
    # OS info
    os_family = db.Column(db.String(50), nullable=True)
    os_version = db.Column(db.String(50), nullable=True)
    
    # Geographic info (optional)
    country = db.Column(db.String(2), nullable=True)  # ISO country code
    region = db.Column(db.String(100), nullable=True)
    city = db.Column(db.String(100), nullable=True)
    
    # Security flags
    login_method = db.Column(db.String(20), nullable=True, default='password')  # password, 2fa, backup_code
    is_suspicious = db.Column(db.Boolean, nullable=False, default=False)
    risk_score = db.Column(db.Integer, nullable=False, default=0)  # 0-100
    
    # Relationships
    user = db.relationship('User', backref='sessions', lazy=True)
    
    def __init__(self, session_id, user_id, ip_address, user_agent=None, **kwargs):
        self.id = session_id
        self.user_id = user_id
        self.ip_address = ip_address
        self.user_agent = user_agent
        
        # Parse user agent if provided
        if user_agent:
            self._parse_user_agent(user_agent)
        
        # Set geographic info if GeoIP database available
        self._set_geographic_info(ip_address)
        
        # Set additional fields
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
    
    def _parse_user_agent(self, user_agent_string):
        """Parse user agent string to extract device and browser info"""
        try:
            ua = user_agents.parse(user_agent_string)
            
            # Device info
            if ua.is_mobile:
                self.device_type = 'mobile'
            elif ua.is_tablet:
                self.device_type = 'tablet'
            elif ua.is_pc:
                self.device_type = 'pc'
            else:
                self.device_type = 'unknown'
            
            # Browser info
            self.browser_family = ua.browser.family
            self.browser_version = ua.browser.version_string
            
            # OS info
            self.os_family = ua.os.family
            self.os_version = ua.os.version_string
            
            # Device details (for mobile devices)
            if hasattr(ua.device, 'brand') and ua.device.brand:
                self.device_brand = ua.device.brand
            if hasattr(ua.device, 'model') and ua.device.model:
                self.device_model = ua.device.model
                
        except Exception as e:
            print(f"Error parsing user agent: {e}")
    
    def _set_geographic_info(self, ip_address):
        """Set geographic info using GeoIP database (if available)"""
        try:
            # Skip private/local IPs
            if ip_address in ['127.0.0.1', 'localhost'] or ip_address.startswith('192.168.') or ip_address.startswith('10.'):
                return
            
            # Check if GeoIP database exists
            geoip_path = os.path.join(os.path.dirname(__file__), '..', '..', 'geoip', 'GeoLite2-City.mmdb')
            if not os.path.exists(geoip_path):
                return
            
            with geoip2.database.Reader(geoip_path) as reader:
                response = reader.city(ip_address)
                self.country = response.country.iso_code
                self.region = response.subdivisions.most_specific.name
                self.city = response.city.name
                
        except Exception as e:
            # GeoIP lookup failed - not critical
            pass
    
    def update_activity(self):
        """Update last activity timestamp"""
        self.last_activity = datetime.now(timezone.utc)
        db.session.commit()
    
    def calculate_risk_score(self):
        """Calculate session risk score based on various factors"""
        risk = 0
        
        # New device/browser (simplified check)
        if self.device_type == 'unknown':
            risk += 10
        
        # Unusual location (would need historical data)
        # This is a placeholder - real implementation would compare with user's typical locations
        if not self.country:
            risk += 5
        
        # Very old browser versions (simplified)
        if self.browser_family and 'IE' in self.browser_family:
            risk += 20
        
        # Mobile device on admin actions (could be suspicious)
        if self.device_type == 'mobile':
            risk += 5
        
        self.risk_score = min(risk, 100)
        return self.risk_score
    
    def is_expired(self):
        """Check if session has expired"""
        if not self.expires_at:
            return False
        return datetime.now(timezone.utc) > self.expires_at
    
    def terminate(self):
        """Mark session as terminated"""
        self.is_active = False
        db.session.commit()
    
    def get_device_summary(self):
        """Get human-readable device summary"""
        parts = []
        
        if self.os_family:
            os_str = self.os_family
            if self.os_version:
                os_str += f" {self.os_version}"
            parts.append(os_str)
        
        if self.browser_family:
            browser_str = self.browser_family
            if self.browser_version:
                browser_str += f" {self.browser_version}"
            parts.append(browser_str)
        
        if self.device_brand and self.device_model:
            parts.append(f"{self.device_brand} {self.device_model}")
        elif self.device_type:
            parts.append(self.device_type.title())
        
        return " • ".join(parts) if parts else "Unknown Device"
    
    def get_location_summary(self):
        """Get human-readable location summary"""
        parts = []
        if self.city:
            parts.append(self.city)
        if self.region and self.region != self.city:
            parts.append(self.region)
        if self.country:
            parts.append(self.country)
        
        return ", ".join(parts) if parts else f"IP: {self.ip_address}"
    
    @classmethod
    def create_session(cls, session_id, user_id, request):
        """Create a new session from Flask request object"""
        ip_address = cls._get_client_ip(request)
        user_agent = request.headers.get('User-Agent', '')
        
        session = cls(
            session_id=session_id,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent
        )
        
        session.calculate_risk_score()
        db.session.add(session)
        db.session.commit()
        
        return session
    
    @staticmethod
    def _get_client_ip(request):
        """Get client IP from request, handling proxies"""
        # Check for forwarded IP (behind proxy)
        if 'X-Forwarded-For' in request.headers:
            return request.headers['X-Forwarded-For'].split(',')[0].strip()
        elif 'X-Real-IP' in request.headers:
            return request.headers['X-Real-IP']
        else:
            return request.remote_addr or '127.0.0.1'
    
    @classmethod
    def cleanup_expired(cls):
        """Remove expired and inactive sessions"""
        now = datetime.now(timezone.utc)
        expired_sessions = cls.query.filter(
            db.or_(
                cls.expires_at < now,
                db.and_(cls.is_active == False, cls.last_activity < now)
            )
        ).all()
        
        for session in expired_sessions:
            db.session.delete(session)
        
        db.session.commit()
        return len(expired_sessions)
    
    @classmethod
    def get_active_sessions_for_user(cls, user_id):
        """Get all active sessions for a user"""
        return cls.query.filter_by(user_id=user_id, is_active=True).order_by(cls.last_activity.desc()).all()
    
    @classmethod
    def terminate_user_sessions(cls, user_id, exclude_session_id=None):
        """Terminate all sessions for a user (optionally excluding current session)"""
        query = cls.query.filter_by(user_id=user_id, is_active=True)
        if exclude_session_id:
            query = query.filter(cls.id != exclude_session_id)
        
        sessions = query.all()
        for session in sessions:
            session.terminate()
        
        return len(sessions)
    
    def to_dict(self):
        """Convert session to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'user_id': self.user_id,
            'created_at': self.created_at.isoformat(),
            'last_activity': self.last_activity.isoformat(),
            'is_active': self.is_active,
            'ip_address': self.ip_address,
            'device_summary': self.get_device_summary(),
            'location_summary': self.get_location_summary(),
            'login_method': self.login_method,
            'risk_score': self.risk_score,
            'is_suspicious': self.is_suspicious
        }
    
    def __repr__(self):
        return f'<UserSession {self.id} for User {self.user_id}>'