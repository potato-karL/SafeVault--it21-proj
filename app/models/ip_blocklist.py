from datetime import datetime, timezone, timedelta
from typing import Optional

from app import db


class IPBlocklist(db.Model):
    __tablename__ = "ip_blocklist"

    id = db.Column(db.Integer, primary_key=True)
    ip_address = db.Column(db.String(45), unique=True, nullable=False, index=True)  # IPv4/IPv6
    
    # Blocking details
    blocked_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    blocked_until = db.Column(db.DateTime, nullable=True)  # NULL = permanent ban
    reason = db.Column(db.String(255), nullable=False)
    
    # Ban type and metadata
    is_automatic = db.Column(db.Boolean, default=True, nullable=False)  # Auto vs manual ban
    failed_attempts = db.Column(db.Integer, default=0, nullable=False)  # Count that triggered auto-ban
    
    # Admin tracking
    blocked_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    unblocked_by_user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    unblocked_at = db.Column(db.DateTime, nullable=True)
    
    # Relationships
    blocked_by = db.relationship('User', foreign_keys=[blocked_by_user_id], backref='ips_blocked')
    unblocked_by = db.relationship('User', foreign_keys=[unblocked_by_user_id], backref='ips_unblocked')

    @classmethod
    def is_ip_blocked(cls, ip_address: str) -> bool:
        """Check if an IP address is currently blocked."""
        if not ip_address:
            return False
            
        blocked_ip = cls.query.filter_by(ip_address=ip_address).first()
        if not blocked_ip:
            return False
            
        # Check if it's permanently blocked (blocked_until is None)
        if blocked_ip.blocked_until is None:
            return True
            
        # Check if temporary block is still active
        now = datetime.now(timezone.utc)
        blocked_until = blocked_ip.blocked_until
        if blocked_until.tzinfo is None:
            blocked_until = blocked_until.replace(tzinfo=timezone.utc)
            
        return now < blocked_until

    @classmethod
    def block_ip(
        cls, 
        ip_address: str, 
        reason: str, 
        is_automatic: bool = True,
        failed_attempts: int = 0,
        duration_minutes: Optional[int] = None,
        blocked_by_user_id: Optional[int] = None
    ) -> 'IPBlocklist':
        """Block an IP address with optional duration."""
        # Remove existing entry if it exists
        existing = cls.query.filter_by(ip_address=ip_address).first()
        if existing:
            db.session.delete(existing)
        
        # Calculate blocked_until timestamp
        blocked_until = None
        if duration_minutes:
            blocked_until = datetime.now(timezone.utc) + timedelta(minutes=duration_minutes)
        
        blocked_ip = cls(
            ip_address=ip_address,
            reason=reason,
            is_automatic=is_automatic,
            failed_attempts=failed_attempts,
            blocked_until=blocked_until,
            blocked_by_user_id=blocked_by_user_id
        )
        
        db.session.add(blocked_ip)
        db.session.commit()
        return blocked_ip

    @classmethod
    def unblock_ip(cls, ip_address: str, unblocked_by_user_id: Optional[int] = None) -> bool:
        """Unblock an IP address. Returns True if IP was blocked and unblocked."""
        blocked_ip = cls.query.filter_by(ip_address=ip_address).first()
        if not blocked_ip:
            return False
            
        blocked_ip.unblocked_at = datetime.now(timezone.utc)
        blocked_ip.unblocked_by_user_id = unblocked_by_user_id
        
        db.session.delete(blocked_ip)
        db.session.commit()
        return True

    @classmethod
    def get_blocked_ips(cls, include_expired: bool = False):
        """Get all currently blocked IPs."""
        query = cls.query
        
        if not include_expired:
            now = datetime.now(timezone.utc)
            query = query.filter(
                db.or_(
                    cls.blocked_until.is_(None),  # Permanent bans
                    cls.blocked_until > now       # Active temporary bans
                )
            )
        
        return query.order_by(cls.blocked_at.desc()).all()

    @classmethod
    def cleanup_expired_blocks(cls) -> int:
        """Remove expired temporary IP blocks. Returns count of removed entries."""
        now = datetime.now(timezone.utc)
        expired = cls.query.filter(
            cls.blocked_until.isnot(None),
            cls.blocked_until <= now
        ).all()
        
        count = len(expired)
        for blocked_ip in expired:
            db.session.delete(blocked_ip)
        
        db.session.commit()
        return count

    def is_expired(self) -> bool:
        """Check if this IP block has expired."""
        if self.blocked_until is None:
            return False  # Permanent block never expires
            
        now = datetime.now(timezone.utc)
        blocked_until = self.blocked_until
        if blocked_until.tzinfo is None:
            blocked_until = blocked_until.replace(tzinfo=timezone.utc)
            
        return now >= blocked_until

    def time_remaining(self) -> Optional[timedelta]:
        """Get time remaining on block. None for permanent blocks or expired blocks."""
        if self.blocked_until is None or self.is_expired():
            return None
            
        now = datetime.now(timezone.utc)
        blocked_until = self.blocked_until
        if blocked_until.tzinfo is None:
            blocked_until = blocked_until.replace(tzinfo=timezone.utc)
            
        return blocked_until - now

    def __repr__(self) -> str:
        return f"<IPBlocklist {self.ip_address} blocked_at={self.blocked_at}>"