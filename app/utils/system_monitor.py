"""
System Monitor Utility for SafeVault
Manages system health monitoring and alerting
"""

import threading
import time
from datetime import datetime, timezone, timedelta
from flask import current_app
from app.models.system_health import SystemHealthMetric, SystemAlert
from app.utils.audit_logger import AuditLogger
from app import db

class SystemMonitor:
    """Manages system health monitoring"""
    
    def __init__(self):
        self.monitoring_active = False
        self.monitor_thread = None
        self.collection_interval = 300  # 5 minutes default
    
    def start_monitoring(self, interval_seconds=300):
        """Start background system monitoring"""
        if self.monitoring_active:
            return False
        
        self.collection_interval = interval_seconds
        self.monitoring_active = True
        
        self.monitor_thread = threading.Thread(
            target=self._monitoring_loop,
            daemon=True,
            name='SystemMonitor'
        )
        self.monitor_thread.start()
        
        current_app.logger.info(f"System monitoring started with {interval_seconds}s interval")
        return True
    
    def stop_monitoring(self):
        """Stop background system monitoring"""
        if not self.monitoring_active:
            return False
        
        self.monitoring_active = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=10)
        
        current_app.logger.info("System monitoring stopped")
        return True
    
    def _monitoring_loop(self):
        """Main monitoring loop"""
        while self.monitoring_active:
            try:
                # Collect and store metrics
                metrics = SystemHealthMetric.collect_and_store()
                
                if metrics and metrics.status != 'healthy':
                    self._process_alerts(metrics)
                
                # Sleep for the specified interval
                time.sleep(self.collection_interval)
                
            except Exception as e:
                current_app.logger.error(f"System monitoring error: {e}")
                time.sleep(60)  # Wait 1 minute before retrying on error
    
    def _process_alerts(self, metrics):
        """Process and create alerts based on metrics"""
        alerts = metrics.get_alerts()
        
        for alert in alerts:
            if alert['severity'] == 'critical':
                self._create_system_alert(
                    alert_type=alert['type'],
                    title=f"Critical System Alert: {alert['message']}",
                    message=alert['message'],
                    severity='critical',
                    metric_id=metrics.id
                )
    
    def _create_system_alert(self, alert_type, title, message, severity, **metadata):
        """Create a system alert if it doesn't already exist"""
        # Check if similar alert already exists and is active
        existing = SystemAlert.query.filter_by(
            alert_type=alert_type,
            is_active=True
        ).first()
        
        if not existing:
            SystemAlert.create_alert(
                alert_type=alert_type,
                title=title,
                message=message,
                severity=severity,
                **metadata
            )
    
    @staticmethod
    def get_system_status():
        """Get current system status summary"""
        latest_metrics = SystemHealthMetric.get_latest_metrics()
        active_alerts = SystemAlert.get_active_alerts()
        
        if not latest_metrics:
            return {
                'status': 'unknown',
                'message': 'No metrics available',
                'alerts_count': len(active_alerts),
                'last_check': None
            }
        
        return {
            'status': latest_metrics.status,
            'message': f'System {latest_metrics.status}',
            'alerts_count': len(active_alerts),
            'critical_alerts': len([a for a in active_alerts if a.severity == 'critical']),
            'last_check': latest_metrics.timestamp.isoformat(),
            'cpu_percent': latest_metrics.cpu_percent,
            'memory_percent': latest_metrics.memory_percent,
            'disk_percent': latest_metrics.disk_percent,
            'active_sessions': latest_metrics.active_sessions
        }

# Global monitor instance
system_monitor = SystemMonitor()