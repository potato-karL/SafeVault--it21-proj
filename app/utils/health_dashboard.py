"""
System Health Dashboard for SafeVault
Provides real-time system monitoring, alerting, and dashboard capabilities
"""

from datetime import datetime, timezone, timedelta
from flask import current_app
from app.models.system_health import SystemHealthMetric, SystemAlert
from app.models.user_session import UserSession
from app.models.user import User
from app.models.file import File
from app.models.audit_log import AuditLog
from app.utils.system_monitor import system_monitor
from app.utils.audit_logger import AuditLogger
from app import db
from sqlalchemy import func
import json

class HealthDashboard:
    """Manages system health dashboard and alerting"""
    
    def __init__(self):
        self.alert_thresholds = {
            'cpu_warning': 75,
            'cpu_critical': 90,
            'memory_warning': 80,
            'memory_critical': 90,
            'disk_warning': 85,
            'disk_critical': 95,
            'high_risk_sessions': 5,
            'failed_logins_per_hour': 50,
            'suspicious_activity_per_hour': 10
        }
    
    def get_dashboard_data(self):
        """Get comprehensive dashboard data"""
        try:
            dashboard_data = {
                'current_metrics': self._get_current_metrics(),
                'alerts': self._get_active_alerts(),
                'trends': self._get_trend_data(),
                'security_overview': self._get_security_overview(),
                'performance_summary': self._get_performance_summary(),
                'system_status': self._get_system_status(),
                'quick_stats': self._get_quick_stats(),
                'chart_data': self._get_chart_data(),
                'last_updated': datetime.now(timezone.utc).isoformat()
            }
            
            return dashboard_data
            
        except Exception as e:
            current_app.logger.error(f"Error getting dashboard data: {e}")
            return {
                'error': str(e),
                'current_metrics': {},
                'alerts': [],
                'system_status': 'unknown'
            }
    
    def _get_current_metrics(self):
        """Get current system metrics"""
        try:
            latest_metrics = SystemHealthMetric.get_latest_metrics()
            
            if not latest_metrics:
                return {
                    'status': 'no_data',
                    'message': 'No metrics available'
                }
            
            # Calculate health scores
            health_scores = self._calculate_health_scores(latest_metrics)
            
            return {
                'timestamp': latest_metrics.timestamp.isoformat(),
                'cpu': {
                    'percent': latest_metrics.cpu_percent,
                    'count': latest_metrics.cpu_count,
                    'load_avg_1m': latest_metrics.load_average_1m,
                    'health_score': health_scores.get('cpu', 100)
                },
                'memory': {
                    'total': latest_metrics.memory_total,
                    'used': latest_metrics.memory_used,
                    'available': latest_metrics.memory_available,
                    'percent': latest_metrics.memory_percent,
                    'cached': latest_metrics.memory_cached,
                    'health_score': health_scores.get('memory', 100)
                },
                'disk': {
                    'total': latest_metrics.disk_total,
                    'used': latest_metrics.disk_used,
                    'free': latest_metrics.disk_free,
                    'percent': latest_metrics.disk_percent,
                    'health_score': health_scores.get('disk', 100)
                },
                'database': {
                    'size': latest_metrics.database_size,
                    'connections': latest_metrics.database_connections
                },
                'application': {
                    'active_sessions': latest_metrics.active_sessions,
                    'total_users': latest_metrics.total_users,
                    'total_files': latest_metrics.total_files,
                    'total_storage': latest_metrics.total_storage_used
                },
                'network': {
                    'bytes_sent': latest_metrics.network_bytes_sent,
                    'bytes_recv': latest_metrics.network_bytes_recv,
                    'packets_sent': latest_metrics.network_packets_sent,
                    'packets_recv': latest_metrics.network_packets_recv
                },
                'overall_health': health_scores.get('overall', 100),
                'status': latest_metrics.status,
                'alerts': latest_metrics.get_alerts()
            }
            
        except Exception as e:
            current_app.logger.error(f"Error getting current metrics: {e}")
            return {'error': str(e)}
    
    def _calculate_health_scores(self, metrics):
        """Calculate health scores for different system components"""
        scores = {}
        
        # CPU health score
        if metrics.cpu_percent is not None:
            if metrics.cpu_percent >= self.alert_thresholds['cpu_critical']:
                scores['cpu'] = 25
            elif metrics.cpu_percent >= self.alert_thresholds['cpu_warning']:
                scores['cpu'] = 50
            elif metrics.cpu_percent >= 50:
                scores['cpu'] = 75
            else:
                scores['cpu'] = 100
        else:
            scores['cpu'] = 100
        
        # Memory health score
        if metrics.memory_percent is not None:
            if metrics.memory_percent >= self.alert_thresholds['memory_critical']:
                scores['memory'] = 25
            elif metrics.memory_percent >= self.alert_thresholds['memory_warning']:
                scores['memory'] = 50
            elif metrics.memory_percent >= 60:
                scores['memory'] = 75
            else:
                scores['memory'] = 100
        else:
            scores['memory'] = 100
        
        # Disk health score
        if metrics.disk_percent is not None:
            if metrics.disk_percent >= self.alert_thresholds['disk_critical']:
                scores['disk'] = 25
            elif metrics.disk_percent >= self.alert_thresholds['disk_warning']:
                scores['disk'] = 50
            elif metrics.disk_percent >= 70:
                scores['disk'] = 75
            else:
                scores['disk'] = 100
        else:
            scores['disk'] = 100
        
        # Overall health score (weighted average)
        scores['overall'] = int((scores['cpu'] * 0.3 + scores['memory'] * 0.4 + scores['disk'] * 0.3))
        
        return scores
    
    def _get_active_alerts(self):
        """Get active system alerts"""
        try:
            active_alerts = SystemAlert.get_active_alerts()
            
            alerts_data = []
            for alert in active_alerts:
                alert_data = alert.to_dict()
                alert_data['severity_class'] = self._get_severity_class(alert.severity)
                alert_data['age_minutes'] = int((datetime.now(timezone.utc) - alert.timestamp).total_seconds() / 60)
                alerts_data.append(alert_data)
            
            return alerts_data
            
        except Exception as e:
            current_app.logger.error(f"Error getting active alerts: {e}")
            return []
    
    def _get_severity_class(self, severity):
        """Get CSS class for alert severity"""
        severity_classes = {
            'info': 'alert-info',
            'warning': 'alert-warning',
            'critical': 'alert-danger'
        }
        return severity_classes.get(severity, 'alert-secondary')
    
    def _get_trend_data(self, hours=24):
        """Get trend data for the last N hours"""
        try:
            start_time = datetime.now(timezone.utc) - timedelta(hours=hours)
            
            metrics_history = SystemHealthMetric.get_metrics_history(hours=hours, limit=144)  # ~10 minute intervals
            
            if not metrics_history:
                return {
                    'cpu_trend': [],
                    'memory_trend': [],
                    'disk_trend': [],
                    'sessions_trend': [],
                    'message': 'No historical data available'
                }
            
            trends = {
                'cpu_trend': [],
                'memory_trend': [],
                'disk_trend': [],
                'sessions_trend': [],
                'storage_trend': []
            }
            
            for metric in reversed(metrics_history):  # Chronological order
                timestamp = metric.timestamp.isoformat()
                
                trends['cpu_trend'].append({
                    'timestamp': timestamp,
                    'value': metric.cpu_percent or 0
                })
                
                trends['memory_trend'].append({
                    'timestamp': timestamp,
                    'value': metric.memory_percent or 0
                })
                
                trends['disk_trend'].append({
                    'timestamp': timestamp,
                    'value': metric.disk_percent or 0
                })
                
                trends['sessions_trend'].append({
                    'timestamp': timestamp,
                    'value': metric.active_sessions or 0
                })
                
                trends['storage_trend'].append({
                    'timestamp': timestamp,
                    'value': (metric.total_storage_used or 0) / (1024**3)  # Convert to GB
                })
            
            return trends
            
        except Exception as e:
            current_app.logger.error(f"Error getting trend data: {e}")
            return {}
    
    def _get_security_overview(self):
        """Get security overview metrics"""
        try:
            now = datetime.now(timezone.utc)
            last_hour = now - timedelta(hours=1)
            last_24h = now - timedelta(hours=24)
            
            security_data = {
                'suspicious_sessions': UserSession.query.filter_by(
                    is_active=True, 
                    is_suspicious=True
                ).count(),
                'high_risk_sessions': UserSession.query.filter(
                    UserSession.is_active == True,
                    UserSession.risk_score > 70
                ).count(),
                'failed_logins_1h': AuditLog.query.filter(
                    AuditLog.action == 'security_login_failed',
                    AuditLog.timestamp >= last_hour
                ).count(),
                'failed_logins_24h': AuditLog.query.filter(
                    AuditLog.action == 'security_login_failed',
                    AuditLog.timestamp >= last_24h
                ).count(),
                'security_events_1h': AuditLog.query.filter(
                    AuditLog.category == 'security',
                    AuditLog.timestamp >= last_hour
                ).count(),
                'blocked_ips': 0,  # Would need IP blocklist model
                'locked_accounts': User.query.filter(User.failed_login_attempts >= 3).count()
            }
            
            # Calculate security score
            security_score = 100
            
            if security_data['suspicious_sessions'] > self.alert_thresholds['high_risk_sessions']:
                security_score -= 20
            
            if security_data['failed_logins_1h'] > self.alert_thresholds['failed_logins_per_hour']:
                security_score -= 30
            
            if security_data['security_events_1h'] > self.alert_thresholds['suspicious_activity_per_hour']:
                security_score -= 25
            
            security_data['security_score'] = max(security_score, 0)
            security_data['security_status'] = self._get_security_status(security_score)
            
            return security_data
            
        except Exception as e:
            current_app.logger.error(f"Error getting security overview: {e}")
            return {}
    
    def _get_security_status(self, score):
        """Get security status based on score"""
        if score >= 90:
            return {'status': 'excellent', 'class': 'success'}
        elif score >= 70:
            return {'status': 'good', 'class': 'info'}
        elif score >= 50:
            return {'status': 'warning', 'class': 'warning'}
        else:
            return {'status': 'critical', 'class': 'danger'}
    
    def _get_performance_summary(self):
        """Get performance summary metrics"""
        try:
            # Get average metrics for the last 24 hours
            avg_metrics = SystemHealthMetric.get_average_metrics(hours=24)
            
            if not avg_metrics:
                return {
                    'message': 'No performance data available'
                }
            
            performance_data = {
                'avg_cpu': avg_metrics['avg_cpu'],
                'avg_memory': avg_metrics['avg_memory'],
                'avg_disk': avg_metrics['avg_disk'],
                'max_cpu': avg_metrics['max_cpu'],
                'max_memory': avg_metrics['max_memory'],
                'max_disk': avg_metrics['max_disk'],
                'sample_count': avg_metrics['sample_count']
            }
            
            # Calculate performance grade
            avg_usage = (avg_metrics['avg_cpu'] + avg_metrics['avg_memory'] + avg_metrics['avg_disk']) / 3
            
            if avg_usage <= 30:
                performance_data['grade'] = 'A'
                performance_data['grade_class'] = 'success'
            elif avg_usage <= 50:
                performance_data['grade'] = 'B'
                performance_data['grade_class'] = 'info'
            elif avg_usage <= 70:
                performance_data['grade'] = 'C'
                performance_data['grade_class'] = 'warning'
            else:
                performance_data['grade'] = 'D'
                performance_data['grade_class'] = 'danger'
            
            return performance_data
            
        except Exception as e:
            current_app.logger.error(f"Error getting performance summary: {e}")
            return {}
    
    def _get_system_status(self):
        """Get overall system status"""
        try:
            latest_metrics = SystemHealthMetric.get_latest_metrics()
            active_alerts = SystemAlert.get_active_alerts()
            
            if not latest_metrics:
                return {
                    'status': 'unknown',
                    'message': 'No system data available',
                    'class': 'secondary'
                }
            
            # Check for critical alerts
            critical_alerts = [a for a in active_alerts if a.severity == 'critical']
            warning_alerts = [a for a in active_alerts if a.severity == 'warning']
            
            if critical_alerts:
                return {
                    'status': 'critical',
                    'message': f'{len(critical_alerts)} critical issue(s) require attention',
                    'class': 'danger'
                }
            elif warning_alerts:
                return {
                    'status': 'warning',
                    'message': f'{len(warning_alerts)} warning(s) detected',
                    'class': 'warning'
                }
            elif latest_metrics.status == 'healthy':
                return {
                    'status': 'healthy',
                    'message': 'All systems operational',
                    'class': 'success'
                }
            else:
                return {
                    'status': latest_metrics.status,
                    'message': f'System status: {latest_metrics.status}',
                    'class': 'info'
                }
            
        except Exception as e:
            current_app.logger.error(f"Error getting system status: {e}")
            return {
                'status': 'error',
                'message': 'Error determining system status',
                'class': 'danger'
            }
    
    def _get_quick_stats(self):
        """Get quick statistics for dashboard widgets"""
        try:
            now = datetime.now(timezone.utc)
            today = now.replace(hour=0, minute=0, second=0, microsecond=0)
            
            stats = {
                'users_online': UserSession.query.filter_by(is_active=True).count(),
                'new_users_today': User.query.filter(User.created_at >= today).count(),
                'files_uploaded_today': File.query.filter(File.uploaded_at >= today).count(),
                'security_events_today': AuditLog.query.filter(
                    AuditLog.category == 'security',
                    AuditLog.timestamp >= today
                ).count(),
                'system_uptime': self._calculate_uptime()
            }
            
            return stats
            
        except Exception as e:
            current_app.logger.error(f"Error getting quick stats: {e}")
            return {}
    
    def _calculate_uptime(self):
        """Calculate system uptime based on metrics collection"""
        try:
            # Get the oldest metric from today
            today = datetime.now(timezone.utc).replace(hour=0, minute=0, second=0, microsecond=0)
            oldest_metric = SystemHealthMetric.query.filter(
                SystemHealthMetric.timestamp >= today
            ).order_by(SystemHealthMetric.timestamp.asc()).first()
            
            if oldest_metric:
                uptime_seconds = (datetime.now(timezone.utc) - oldest_metric.timestamp).total_seconds()
                
                if uptime_seconds >= 86400:  # More than 24 hours
                    return f"{int(uptime_seconds / 86400)}d {int((uptime_seconds % 86400) / 3600)}h"
                elif uptime_seconds >= 3600:  # More than 1 hour
                    return f"{int(uptime_seconds / 3600)}h {int((uptime_seconds % 3600) / 60)}m"
                else:
                    return f"{int(uptime_seconds / 60)}m"
            
            return "Unknown"
            
        except Exception as e:
            return "Unknown"
    
    def _get_chart_data(self):
        """Get data formatted for charts"""
        try:
            # Get last 24 hours of data
            trends = self._get_trend_data(hours=24)
            
            chart_data = {
                'system_resources': {
                    'labels': [point['timestamp'] for point in trends.get('cpu_trend', [])],
                    'datasets': [
                        {
                            'label': 'CPU %',
                            'data': [point['value'] for point in trends.get('cpu_trend', [])],
                            'borderColor': 'rgb(255, 99, 132)',
                            'backgroundColor': 'rgba(255, 99, 132, 0.2)'
                        },
                        {
                            'label': 'Memory %',
                            'data': [point['value'] for point in trends.get('memory_trend', [])],
                            'borderColor': 'rgb(54, 162, 235)',
                            'backgroundColor': 'rgba(54, 162, 235, 0.2)'
                        },
                        {
                            'label': 'Disk %',
                            'data': [point['value'] for point in trends.get('disk_trend', [])],
                            'borderColor': 'rgb(255, 205, 86)',
                            'backgroundColor': 'rgba(255, 205, 86, 0.2)'
                        }
                    ]
                },
                'user_activity': {
                    'labels': [point['timestamp'] for point in trends.get('sessions_trend', [])],
                    'datasets': [
                        {
                            'label': 'Active Sessions',
                            'data': [point['value'] for point in trends.get('sessions_trend', [])],
                            'borderColor': 'rgb(75, 192, 192)',
                            'backgroundColor': 'rgba(75, 192, 192, 0.2)'
                        }
                    ]
                }
            }
            
            return chart_data
            
        except Exception as e:
            current_app.logger.error(f"Error getting chart data: {e}")
            return {}
    
    def check_and_create_alerts(self):
        """Check system metrics and create alerts if thresholds are exceeded"""
        try:
            latest_metrics = SystemHealthMetric.get_latest_metrics()
            
            if not latest_metrics:
                return
            
            alerts_created = 0
            
            # Check CPU alerts
            if latest_metrics.cpu_percent is not None:
                if latest_metrics.cpu_percent >= self.alert_thresholds['cpu_critical']:
                    if not self._alert_exists('cpu_critical'):
                        SystemAlert.create_alert(
                            'cpu_critical',
                            'Critical CPU Usage',
                            f'CPU usage is at {latest_metrics.cpu_percent:.1f}% (critical threshold: {self.alert_thresholds["cpu_critical"]}%)',
                            'critical',
                            cpu_usage=latest_metrics.cpu_percent
                        )
                        alerts_created += 1
                        
                elif latest_metrics.cpu_percent >= self.alert_thresholds['cpu_warning']:
                    if not self._alert_exists('cpu_warning'):
                        SystemAlert.create_alert(
                            'cpu_warning',
                            'High CPU Usage',
                            f'CPU usage is at {latest_metrics.cpu_percent:.1f}% (warning threshold: {self.alert_thresholds["cpu_warning"]}%)',
                            'warning',
                            cpu_usage=latest_metrics.cpu_percent
                        )
                        alerts_created += 1
            
            # Check Memory alerts
            if latest_metrics.memory_percent is not None:
                if latest_metrics.memory_percent >= self.alert_thresholds['memory_critical']:
                    if not self._alert_exists('memory_critical'):
                        SystemAlert.create_alert(
                            'memory_critical',
                            'Critical Memory Usage',
                            f'Memory usage is at {latest_metrics.memory_percent:.1f}% (critical threshold: {self.alert_thresholds["memory_critical"]}%)',
                            'critical',
                            memory_usage=latest_metrics.memory_percent
                        )
                        alerts_created += 1
                        
                elif latest_metrics.memory_percent >= self.alert_thresholds['memory_warning']:
                    if not self._alert_exists('memory_warning'):
                        SystemAlert.create_alert(
                            'memory_warning',
                            'High Memory Usage',
                            f'Memory usage is at {latest_metrics.memory_percent:.1f}% (warning threshold: {self.alert_thresholds["memory_warning"]}%)',
                            'warning',
                            memory_usage=latest_metrics.memory_percent
                        )
                        alerts_created += 1
            
            # Check Disk alerts
            if latest_metrics.disk_percent is not None:
                if latest_metrics.disk_percent >= self.alert_thresholds['disk_critical']:
                    if not self._alert_exists('disk_critical'):
                        SystemAlert.create_alert(
                            'disk_critical',
                            'Critical Disk Usage',
                            f'Disk usage is at {latest_metrics.disk_percent:.1f}% (critical threshold: {self.alert_thresholds["disk_critical"]}%)',
                            'critical',
                            disk_usage=latest_metrics.disk_percent
                        )
                        alerts_created += 1
                        
                elif latest_metrics.disk_percent >= self.alert_thresholds['disk_warning']:
                    if not self._alert_exists('disk_warning'):
                        SystemAlert.create_alert(
                            'disk_warning',
                            'High Disk Usage',
                            f'Disk usage is at {latest_metrics.disk_percent:.1f}% (warning threshold: {self.alert_thresholds["disk_warning"]}%)',
                            'warning',
                            disk_usage=latest_metrics.disk_percent
                        )
                        alerts_created += 1
            
            # Check security alerts
            self._check_security_alerts()
            
            if alerts_created > 0:
                current_app.logger.info(f"Created {alerts_created} new system alerts")
            
        except Exception as e:
            current_app.logger.error(f"Error checking and creating alerts: {e}")
    
    def _alert_exists(self, alert_type):
        """Check if an alert of this type already exists and is active"""
        return SystemAlert.query.filter_by(
            alert_type=alert_type,
            is_active=True
        ).first() is not None
    
    def _check_security_alerts(self):
        """Check for security-related alerts"""
        try:
            now = datetime.now(timezone.utc)
            last_hour = now - timedelta(hours=1)
            
            # Check high-risk sessions
            high_risk_sessions = UserSession.query.filter(
                UserSession.is_active == True,
                UserSession.risk_score > 70
            ).count()
            
            if high_risk_sessions > self.alert_thresholds['high_risk_sessions']:
                if not self._alert_exists('high_risk_sessions'):
                    SystemAlert.create_alert(
                        'high_risk_sessions',
                        'Multiple High-Risk Sessions',
                        f'{high_risk_sessions} high-risk sessions detected (threshold: {self.alert_thresholds["high_risk_sessions"]})',
                        'warning',
                        session_count=high_risk_sessions
                    )
            
            # Check failed logins
            failed_logins = AuditLog.query.filter(
                AuditLog.action == 'security_login_failed',
                AuditLog.timestamp >= last_hour
            ).count()
            
            if failed_logins > self.alert_thresholds['failed_logins_per_hour']:
                if not self._alert_exists('excessive_failed_logins'):
                    SystemAlert.create_alert(
                        'excessive_failed_logins',
                        'Excessive Failed Login Attempts',
                        f'{failed_logins} failed login attempts in the last hour (threshold: {self.alert_thresholds["failed_logins_per_hour"]})',
                        'warning',
                        failed_count=failed_logins
                    )
            
        except Exception as e:
            current_app.logger.error(f"Error checking security alerts: {e}")
    
    def resolve_alerts_by_threshold(self):
        """Automatically resolve alerts when conditions improve"""
        try:
            latest_metrics = SystemHealthMetric.get_latest_metrics()
            
            if not latest_metrics:
                return
            
            resolved_count = 0
            
            # Resolve CPU alerts if usage has dropped
            if latest_metrics.cpu_percent is not None:
                if latest_metrics.cpu_percent < self.alert_thresholds['cpu_warning']:
                    cpu_alerts = SystemAlert.query.filter_by(
                        alert_type='cpu_warning',
                        is_active=True
                    ).all()
                    for alert in cpu_alerts:
                        alert.resolve()
                        resolved_count += 1
                
                if latest_metrics.cpu_percent < self.alert_thresholds['cpu_critical']:
                    cpu_alerts = SystemAlert.query.filter_by(
                        alert_type='cpu_critical',
                        is_active=True
                    ).all()
                    for alert in cpu_alerts:
                        alert.resolve()
                        resolved_count += 1
            
            # Similar logic for memory and disk alerts...
            # (Implementation would be similar to CPU alerts)
            
            if resolved_count > 0:
                current_app.logger.info(f"Auto-resolved {resolved_count} system alerts")
            
        except Exception as e:
            current_app.logger.error(f"Error resolving alerts: {e}")


# Global health dashboard instance
health_dashboard = HealthDashboard()