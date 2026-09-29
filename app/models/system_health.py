"""
System Health Model for SafeVault
Tracks server metrics, performance, and system health indicators
"""

from datetime import datetime, timezone, timedelta
from app import db
import json
import uuid
import os
import psutil
import platform
from sqlalchemy import func

class SystemHealthMetric(db.Model):
    __tablename__ = 'system_health_metrics'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    
    # CPU Metrics
    cpu_percent = db.Column(db.Float, nullable=True)  # Overall CPU usage %
    cpu_count = db.Column(db.Integer, nullable=True)  # Number of CPU cores
    load_average_1m = db.Column(db.Float, nullable=True)  # 1-minute load average
    load_average_5m = db.Column(db.Float, nullable=True)  # 5-minute load average
    load_average_15m = db.Column(db.Float, nullable=True)  # 15-minute load average
    
    # Memory Metrics
    memory_total = db.Column(db.BigInteger, nullable=True)  # Total memory in bytes
    memory_available = db.Column(db.BigInteger, nullable=True)  # Available memory in bytes
    memory_used = db.Column(db.BigInteger, nullable=True)  # Used memory in bytes
    memory_percent = db.Column(db.Float, nullable=True)  # Memory usage %
    memory_cached = db.Column(db.BigInteger, nullable=True)  # Cached memory in bytes
    
    # Disk Metrics
    disk_total = db.Column(db.BigInteger, nullable=True)  # Total disk space in bytes
    disk_used = db.Column(db.BigInteger, nullable=True)  # Used disk space in bytes
    disk_free = db.Column(db.BigInteger, nullable=True)  # Free disk space in bytes
    disk_percent = db.Column(db.Float, nullable=True)  # Disk usage %
    
    # Database Metrics
    database_size = db.Column(db.BigInteger, nullable=True)  # Database file size in bytes
    database_connections = db.Column(db.Integer, nullable=True)  # Active connections
    
    # Network Metrics
    network_bytes_sent = db.Column(db.BigInteger, nullable=True)  # Total bytes sent
    network_bytes_recv = db.Column(db.BigInteger, nullable=True)  # Total bytes received
    network_packets_sent = db.Column(db.BigInteger, nullable=True)  # Total packets sent
    network_packets_recv = db.Column(db.BigInteger, nullable=True)  # Total packets received
    
    # Application Metrics
    active_sessions = db.Column(db.Integer, nullable=True)  # Active user sessions
    total_users = db.Column(db.Integer, nullable=True)  # Total registered users
    total_files = db.Column(db.Integer, nullable=True)  # Total uploaded files
    total_storage_used = db.Column(db.BigInteger, nullable=True)  # Total storage used by files
    
    # Performance Metrics
    response_time_avg = db.Column(db.Float, nullable=True)  # Average response time in ms
    error_rate = db.Column(db.Float, nullable=True)  # Error rate %
    uptime_seconds = db.Column(db.BigInteger, nullable=True)  # System uptime in seconds
    
    # Process Metrics
    process_count = db.Column(db.Integer, nullable=True)  # Number of running processes
    thread_count = db.Column(db.Integer, nullable=True)  # Number of threads
    
    # Health Status
    status = db.Column(db.String(20), nullable=False, default='healthy')  # healthy, warning, critical
    alerts = db.Column(db.Text, nullable=True)  # JSON array of active alerts
    
    def __init__(self, **kwargs):
        self.id = str(uuid.uuid4())
        self.timestamp = datetime.now(timezone.utc)
        
        # Set provided fields
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)
    
    @classmethod
    def collect_current_metrics(cls):
        """Collect current system metrics and return a new SystemHealthMetric instance"""
        try:
            metrics = cls()
            
            # CPU Metrics
            metrics.cpu_percent = psutil.cpu_percent(interval=1)
            metrics.cpu_count = psutil.cpu_count()
            
            # Load average (Unix/Linux only)
            try:
                if hasattr(os, 'getloadavg'):
                    load_avg = os.getloadavg()
                    metrics.load_average_1m = load_avg[0]
                    metrics.load_average_5m = load_avg[1]
                    metrics.load_average_15m = load_avg[2]
            except (OSError, AttributeError):
                pass
            
            # Memory Metrics
            memory = psutil.virtual_memory()
            metrics.memory_total = memory.total
            metrics.memory_available = memory.available
            metrics.memory_used = memory.used
            metrics.memory_percent = memory.percent
            if hasattr(memory, 'cached'):
                metrics.memory_cached = memory.cached
            
            # Disk Metrics (for the root/main partition)
            try:
                disk_usage = psutil.disk_usage('/')
                metrics.disk_total = disk_usage.total
                metrics.disk_used = disk_usage.used
                metrics.disk_free = disk_usage.free
                metrics.disk_percent = (disk_usage.used / disk_usage.total) * 100
            except (OSError, PermissionError):
                # Fallback for Windows - use current directory
                try:
                    disk_usage = psutil.disk_usage('.')
                    metrics.disk_total = disk_usage.total
                    metrics.disk_used = disk_usage.used
                    metrics.disk_free = disk_usage.free
                    metrics.disk_percent = (disk_usage.used / disk_usage.total) * 100
                except:
                    pass
            
            # Database Metrics
            metrics._collect_database_metrics()
            
            # Network Metrics
            try:
                network = psutil.net_io_counters()
                metrics.network_bytes_sent = network.bytes_sent
                metrics.network_bytes_recv = network.bytes_recv
                metrics.network_packets_sent = network.packets_sent
                metrics.network_packets_recv = network.packets_recv
            except:
                pass
            
            # Application Metrics
            metrics._collect_application_metrics()
            
            # System Metrics
            try:
                metrics.uptime_seconds = int(psutil.boot_time())
                metrics.process_count = len(psutil.pids())
            except:
                pass
            
            # Calculate health status and alerts
            metrics._calculate_health_status()
            
            return metrics
            
        except Exception as e:
            from flask import current_app
            current_app.logger.error(f"Error collecting system metrics: {e}")
            # Return a minimal metrics object with error status
            metrics = cls()
            metrics.status = 'critical'
            metrics.set_alerts([{'type': 'error', 'message': f'Failed to collect metrics: {str(e)}'}])
            return metrics
    
    def _collect_database_metrics(self):
        """Collect database-specific metrics"""
        try:
            # Database file size
            db_path = os.path.join('instance', 'safevault.db')
            if os.path.exists(db_path):
                self.database_size = os.path.getsize(db_path)
            
            # Database connections (for SQLite, this is typically 1)
            self.database_connections = 1
            
        except Exception as e:
            pass
    
    def _collect_application_metrics(self):
        """Collect SafeVault application-specific metrics"""
        try:
            from app.models.user_session import UserSession
            from app.models.user import User
            from app.models.file import File
            
            # Active sessions
            self.active_sessions = UserSession.query.filter_by(is_active=True).count()
            
            # User metrics
            self.total_users = User.query.count()
            
            # File metrics
            self.total_files = File.query.count()
            
            # Calculate total storage used
            result = db.session.query(func.sum(File.size)).scalar()
            self.total_storage_used = result or 0
            
        except Exception as e:
            pass
    
    def _calculate_health_status(self):
        """Calculate overall health status and generate alerts"""
        alerts = []
        status = 'healthy'
        
        # CPU alerts
        if self.cpu_percent and self.cpu_percent > 90:
            alerts.append({
                'type': 'cpu_critical',
                'message': f'CPU usage critical: {self.cpu_percent:.1f}%',
                'severity': 'critical'
            })
            status = 'critical'
        elif self.cpu_percent and self.cpu_percent > 75:
            alerts.append({
                'type': 'cpu_warning',
                'message': f'CPU usage high: {self.cpu_percent:.1f}%',
                'severity': 'warning'
            })
            if status == 'healthy':
                status = 'warning'
        
        # Memory alerts
        if self.memory_percent and self.memory_percent > 90:
            alerts.append({
                'type': 'memory_critical',
                'message': f'Memory usage critical: {self.memory_percent:.1f}%',
                'severity': 'critical'
            })
            status = 'critical'
        elif self.memory_percent and self.memory_percent > 80:
            alerts.append({
                'type': 'memory_warning',
                'message': f'Memory usage high: {self.memory_percent:.1f}%',
                'severity': 'warning'
            })
            if status == 'healthy':
                status = 'warning'
        
        # Disk alerts
        if self.disk_percent and self.disk_percent > 95:
            alerts.append({
                'type': 'disk_critical',
                'message': f'Disk usage critical: {self.disk_percent:.1f}%',
                'severity': 'critical'
            })
            status = 'critical'
        elif self.disk_percent and self.disk_percent > 85:
            alerts.append({
                'type': 'disk_warning',
                'message': f'Disk usage high: {self.disk_percent:.1f}%',
                'severity': 'warning'
            })
            if status == 'healthy':
                status = 'warning'
        
        # Database size alerts (if > 1GB warn, > 5GB critical)
        if self.database_size:
            db_size_gb = self.database_size / (1024**3)
            if db_size_gb > 5:
                alerts.append({
                    'type': 'database_critical',
                    'message': f'Database size critical: {db_size_gb:.2f}GB',
                    'severity': 'critical'
                })
                status = 'critical'
            elif db_size_gb > 1:
                alerts.append({
                    'type': 'database_warning',
                    'message': f'Database size large: {db_size_gb:.2f}GB',
                    'severity': 'warning'
                })
                if status == 'healthy':
                    status = 'warning'
        
        self.status = status
        self.set_alerts(alerts)
    
    def set_alerts(self, alerts_list):
        """Set alerts as JSON"""
        if alerts_list:
            self.alerts = json.dumps(alerts_list)
        else:
            self.alerts = None
    
    def get_alerts(self):
        """Get alerts as list of dictionaries"""
        if self.alerts:
            try:
                return json.loads(self.alerts)
            except (json.JSONDecodeError, TypeError):
                return []
        return []
    
    @classmethod
    def get_latest_metrics(cls):
        """Get the most recent system health metrics"""
        return cls.query.order_by(cls.timestamp.desc()).first()
    
    @classmethod
    def get_metrics_history(cls, hours=24, limit=100):
        """Get system health metrics history"""
        start_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        return cls.query.filter(
            cls.timestamp >= start_time
        ).order_by(cls.timestamp.desc()).limit(limit).all()
    
    @classmethod
    def get_average_metrics(cls, hours=24):
        """Get average metrics over a time period"""
        start_time = datetime.now(timezone.utc) - timedelta(hours=hours)
        
        result = db.session.query(
            func.avg(cls.cpu_percent).label('avg_cpu'),
            func.avg(cls.memory_percent).label('avg_memory'),
            func.avg(cls.disk_percent).label('avg_disk'),
            func.max(cls.cpu_percent).label('max_cpu'),
            func.max(cls.memory_percent).label('max_memory'),
            func.max(cls.disk_percent).label('max_disk'),
            func.count(cls.id).label('sample_count')
        ).filter(cls.timestamp >= start_time).first()
        
        if result:
            return {
                'avg_cpu': round(result.avg_cpu or 0, 2),
                'avg_memory': round(result.avg_memory or 0, 2),
                'avg_disk': round(result.avg_disk or 0, 2),
                'max_cpu': round(result.max_cpu or 0, 2),
                'max_memory': round(result.max_memory or 0, 2),
                'max_disk': round(result.max_disk or 0, 2),
                'sample_count': result.sample_count
            }
        return None
    
    @classmethod
    def cleanup_old_metrics(cls, days=30):
        """Remove metrics older than specified days"""
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=days)
        old_metrics = cls.query.filter(cls.timestamp < cutoff_date).all()
        
        count = len(old_metrics)
        for metric in old_metrics:
            db.session.delete(metric)
        
        db.session.commit()
        return count
    
    @classmethod
    def collect_and_store(cls):
        """Collect current metrics and store in database"""
        try:
            metrics = cls.collect_current_metrics()
            db.session.add(metrics)
            db.session.commit()
            return metrics
        except Exception as e:
            from flask import current_app
            current_app.logger.error(f"Failed to collect and store metrics: {e}")
            db.session.rollback()
            return None
    
    def format_size(self, bytes_value):
        """Format bytes into human readable string"""
        if bytes_value is None:
            return "N/A"
        
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if bytes_value < 1024.0:
                return f"{bytes_value:.2f} {unit}"
            bytes_value /= 1024.0
        return f"{bytes_value:.2f} PB"
    
    def to_dict(self):
        """Convert metrics to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'cpu_percent': self.cpu_percent,
            'cpu_count': self.cpu_count,
            'memory_total': self.memory_total,
            'memory_used': self.memory_used,
            'memory_percent': self.memory_percent,
            'memory_total_formatted': self.format_size(self.memory_total),
            'memory_used_formatted': self.format_size(self.memory_used),
            'disk_total': self.disk_total,
            'disk_used': self.disk_used,
            'disk_free': self.disk_free,
            'disk_percent': self.disk_percent,
            'disk_total_formatted': self.format_size(self.disk_total),
            'disk_used_formatted': self.format_size(self.disk_used),
            'disk_free_formatted': self.format_size(self.disk_free),
            'database_size': self.database_size,
            'database_size_formatted': self.format_size(self.database_size),
            'active_sessions': self.active_sessions,
            'total_users': self.total_users,
            'total_files': self.total_files,
            'total_storage_used': self.total_storage_used,
            'total_storage_used_formatted': self.format_size(self.total_storage_used),
            'uptime_seconds': self.uptime_seconds,
            'process_count': self.process_count,
            'status': self.status,
            'alerts': self.get_alerts(),
            'network_bytes_sent': self.network_bytes_sent,
            'network_bytes_recv': self.network_bytes_recv,
            'load_average_1m': self.load_average_1m,
            'load_average_5m': self.load_average_5m,
            'load_average_15m': self.load_average_15m
        }
    
    def __repr__(self):
        return f'<SystemHealthMetric {self.timestamp} {self.status}>'


class SystemAlert(db.Model):
    __tablename__ = 'system_alerts'
    
    id = db.Column(db.String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc), index=True)
    
    alert_type = db.Column(db.String(50), nullable=False, index=True)
    severity = db.Column(db.String(20), nullable=False, default='warning')  # info, warning, critical
    title = db.Column(db.String(255), nullable=False)
    message = db.Column(db.Text, nullable=False)
    
    # Alert status
    is_active = db.Column(db.Boolean, nullable=False, default=True, index=True)
    acknowledged = db.Column(db.Boolean, nullable=False, default=False)
    acknowledged_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    acknowledged_at = db.Column(db.DateTime, nullable=True)
    
    # Resolution
    resolved = db.Column(db.Boolean, nullable=False, default=False)
    resolved_at = db.Column(db.DateTime, nullable=True)
    
    # Additional data
    alert_metadata = db.Column(db.Text, nullable=True)  # JSON encoded additional data
    
    # Relationships
    acknowledged_by_user = db.relationship('User', backref='acknowledged_alerts', lazy=True)
    
    @classmethod
    def create_alert(cls, alert_type, title, message, severity='warning', **metadata):
        """Create a new system alert"""
        alert = cls(
            alert_type=alert_type,
            severity=severity,
            title=title,
            message=message
        )
        
        if metadata:
            alert.metadata = json.dumps(metadata)
        
        db.session.add(alert)
        db.session.commit()
        
        # Log to audit trail
        from app.utils.audit_logger import AuditLogger
        AuditLogger.log_system_event(
            'system_alert_created',
            description=f"System alert created: {title}",
            level='warning' if severity != 'critical' else 'critical'
        )
        
        return alert
    
    def acknowledge(self, user_id):
        """Acknowledge the alert"""
        self.acknowledged = True
        self.acknowledged_by = user_id
        self.acknowledged_at = datetime.now(timezone.utc)
        db.session.commit()
    
    def resolve(self):
        """Mark alert as resolved"""
        self.resolved = True
        self.resolved_at = datetime.now(timezone.utc)
        self.is_active = False
        db.session.commit()
    
    @classmethod
    def get_active_alerts(cls):
        """Get all active alerts"""
        return cls.query.filter_by(is_active=True).order_by(cls.timestamp.desc()).all()
    
    @classmethod
    def get_unacknowledged_alerts(cls):
        """Get all unacknowledged active alerts"""
        return cls.query.filter_by(is_active=True, acknowledged=False).order_by(cls.timestamp.desc()).all()
    
    def to_dict(self):
        """Convert alert to dictionary for JSON serialization"""
        return {
            'id': self.id,
            'timestamp': self.timestamp.isoformat(),
            'alert_type': self.alert_type,
            'severity': self.severity,
            'title': self.title,
            'message': self.message,
            'is_active': self.is_active,
            'acknowledged': self.acknowledged,
            'acknowledged_by': self.acknowledged_by,
            'acknowledged_at': self.acknowledged_at.isoformat() if self.acknowledged_at else None,
            'resolved': self.resolved,
            'resolved_at': self.resolved_at.isoformat() if self.resolved_at else None,
            'metadata': json.loads(self.metadata) if self.metadata else {}
        }
    
    def __repr__(self):
        return f'<SystemAlert {self.alert_type} {self.severity}>'