"""
Audit Trail Viewer for SafeVault
Provides comprehensive audit log viewing, filtering, and analysis capabilities
"""

from datetime import datetime, timezone, timedelta
from flask import current_app
from app.models.audit_log import AuditLog
from app.models.activity_log import ActivityLog
from app.models.user import User
from app import db
from sqlalchemy import func, desc, asc, and_, or_
import json
import csv
import io

class AuditViewer:
    """Handles audit trail viewing and analysis operations"""
    
    def __init__(self):
        self.valid_sort_fields = [
            'timestamp', 'action', 'category', 'level', 'status', 'user_id', 
            'username', 'ip_address', 'risk_level', 'is_suspicious'
        ]
        self.valid_sort_orders = ['asc', 'desc']
    
    def search_audit_logs(self, **filters):
        """
        Search audit logs with advanced filtering and pagination
        
        Args:
            **filters: Dictionary of filter criteria
            
        Returns:
            dict: Search results with pagination info
        """
        try:
            # Start with base query
            query = AuditLog.query
            
            # Apply filters
            query = self._apply_audit_filters(query, filters)
            
            # Get total count before pagination
            total_count = query.count()
            
            # Apply sorting
            query = self._apply_sorting(query, filters)
            
            # Apply pagination
            page = filters.get('page', 1)
            per_page = min(filters.get('per_page', 50), 200)  # Max 200 per page for audit logs
            
            paginated = query.paginate(
                page=page,
                per_page=per_page,
                error_out=False
            )
            
            # Format audit log data
            logs_data = []
            include_details = filters.get('include_details', False)
            
            for log in paginated.items:
                log_data = self._format_audit_log(log, include_details)
                logs_data.append(log_data)
            
            return {
                'logs': logs_data,
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
                'filters_applied': self._get_applied_filters(filters),
                'total_count': total_count,
                'search_time': datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            current_app.logger.error(f"Audit search failed: {e}")
            return {
                'error': f'Audit search failed: {str(e)}',
                'logs': [],
                'pagination': {},
                'total_count': 0
            }
    
    def _apply_audit_filters(self, query, filters):
        """Apply various filters to the audit log query"""
        
        # Text search across multiple fields
        search_text = filters.get('search', '').strip()
        if search_text:
            search_pattern = f'%{search_text}%'
            query = query.filter(
                or_(
                    AuditLog.action.ilike(search_pattern),
                    AuditLog.description.ilike(search_pattern),
                    AuditLog.username.ilike(search_pattern),
                    AuditLog.target_name.ilike(search_pattern),
                    AuditLog.ip_address.ilike(search_pattern)
                )
            )
        
        # Action filter
        if 'action' in filters:
            if isinstance(filters['action'], list):
                query = query.filter(AuditLog.action.in_(filters['action']))
            else:
                query = query.filter(AuditLog.action == filters['action'])
        
        # Category filter
        if 'category' in filters:
            if isinstance(filters['category'], list):
                query = query.filter(AuditLog.category.in_(filters['category']))
            else:
                query = query.filter(AuditLog.category == filters['category'])
        
        # Level filter
        if 'level' in filters:
            if isinstance(filters['level'], list):
                query = query.filter(AuditLog.level.in_(filters['level']))
            else:
                query = query.filter(AuditLog.level == filters['level'])
        
        # Status filter
        if 'status' in filters:
            if isinstance(filters['status'], list):
                query = query.filter(AuditLog.status.in_(filters['status']))
            else:
                query = query.filter(AuditLog.status == filters['status'])
        
        # User filter
        if 'user_id' in filters:
            query = query.filter(AuditLog.user_id == filters['user_id'])
        
        if 'username' in filters:
            query = query.filter(AuditLog.username.ilike(f"%{filters['username']}%"))
        
        # IP address filter
        if 'ip_address' in filters:
            query = query.filter(AuditLog.ip_address.ilike(f"%{filters['ip_address']}%"))
        
        # Target type filter
        if 'target_type' in filters:
            query = query.filter(AuditLog.target_type == filters['target_type'])
        
        # Suspicious filter
        if 'is_suspicious' in filters:
            is_suspicious = filters['is_suspicious'] in ['true', '1', True]
            query = query.filter(AuditLog.is_suspicious == is_suspicious)
        
        # Risk level filter
        if 'min_risk_level' in filters:
            try:
                min_risk = int(filters['min_risk_level'])
                query = query.filter(AuditLog.risk_level >= min_risk)
            except (ValueError, TypeError):
                pass
        
        if 'max_risk_level' in filters:
            try:
                max_risk = int(filters['max_risk_level'])
                query = query.filter(AuditLog.risk_level <= max_risk)
            except (ValueError, TypeError):
                pass
        
        # Date range filters
        if 'start_date' in filters:
            try:
                start_date = datetime.fromisoformat(filters['start_date'].replace('Z', '+00:00'))
                query = query.filter(AuditLog.timestamp >= start_date)
            except (ValueError, AttributeError):
                pass
        
        if 'end_date' in filters:
            try:
                end_date = datetime.fromisoformat(filters['end_date'].replace('Z', '+00:00'))
                query = query.filter(AuditLog.timestamp <= end_date)
            except (ValueError, AttributeError):
                pass
        
        # Endpoint filter
        if 'endpoint' in filters:
            query = query.filter(AuditLog.endpoint.ilike(f"%{filters['endpoint']}%"))
        
        # HTTP method filter
        if 'method' in filters:
            query = query.filter(AuditLog.method == filters['method'])
        
        # Duration filter (for performance analysis)
        if 'min_duration' in filters:
            try:
                min_duration = int(filters['min_duration'])
                query = query.filter(AuditLog.duration_ms >= min_duration)
            except (ValueError, TypeError):
                pass
        
        return query
    
    def _apply_sorting(self, query, filters):
        """Apply sorting to the audit log query"""
        sort_by = filters.get('sort_by', 'timestamp')
        sort_order = filters.get('sort_order', 'desc')
        
        # Validate sort parameters
        if sort_by not in self.valid_sort_fields:
            sort_by = 'timestamp'
        
        if sort_order not in self.valid_sort_orders:
            sort_order = 'desc'
        
        # Apply sorting
        if hasattr(AuditLog, sort_by):
            sort_column = getattr(AuditLog, sort_by)
            if sort_order == 'desc':
                query = query.order_by(desc(sort_column))
            else:
                query = query.order_by(asc(sort_column))
        
        # Secondary sort by timestamp for consistency
        if sort_by != 'timestamp':
            query = query.order_by(desc(AuditLog.timestamp))
        
        return query
    
    def _format_audit_log(self, log, include_details=False):
        """Format audit log data for display"""
        try:
            log_data = {
                'id': log.id,
                'timestamp': log.timestamp.isoformat(),
                'action': log.action,
                'category': log.category,
                'level': log.level,
                'status': log.status,
                'user_id': log.user_id,
                'username': log.username or 'System',
                'session_id': log.session_id,
                'ip_address': log.ip_address,
                'user_agent': log.user_agent,
                'endpoint': log.endpoint,
                'method': log.method,
                'target_type': log.target_type,
                'target_id': log.target_id,
                'target_name': log.target_name,
                'description': log.description,
                'risk_level': log.risk_level,
                'is_suspicious': log.is_suspicious,
                'duration_ms': log.duration_ms,
                'result_code': log.result_code,
                'formatted_timestamp': log.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC'),
                'level_badge_class': self._get_level_badge_class(log.level),
                'status_badge_class': self._get_status_badge_class(log.status),
                'risk_badge_class': self._get_risk_badge_class(log.risk_level)
            }
            
            if include_details:
                log_data['details'] = log.get_details()
            
            return log_data
            
        except Exception as e:
            current_app.logger.error(f"Error formatting audit log {log.id}: {e}")
            return {
                'id': log.id,
                'error': 'Error formatting log data'
            }
    
    def _get_level_badge_class(self, level):
        """Get CSS class for log level badge"""
        level_classes = {
            'debug': 'bg-secondary',
            'info': 'bg-primary',
            'warning': 'bg-warning',
            'error': 'bg-danger',
            'critical': 'bg-danger'
        }
        return level_classes.get(level, 'bg-secondary')
    
    def _get_status_badge_class(self, status):
        """Get CSS class for status badge"""
        status_classes = {
            'success': 'bg-success',
            'failed': 'bg-danger',
            'error': 'bg-danger',
            'pending': 'bg-warning',
            'cancelled': 'bg-secondary'
        }
        return status_classes.get(status, 'bg-secondary')
    
    def _get_risk_badge_class(self, risk_level):
        """Get CSS class for risk level badge"""
        if risk_level >= 80:
            return 'bg-danger'
        elif risk_level >= 50:
            return 'bg-warning'
        elif risk_level >= 20:
            return 'bg-info'
        else:
            return 'bg-success'
    
    def _get_applied_filters(self, filters):
        """Get summary of applied filters for display"""
        applied = []
        
        if filters.get('search'):
            applied.append(f"Search: '{filters['search']}'")
        
        if 'action' in filters:
            if isinstance(filters['action'], list):
                applied.append(f"Actions: {', '.join(filters['action'])}")
            else:
                applied.append(f"Action: {filters['action']}")
        
        if 'category' in filters:
            if isinstance(filters['category'], list):
                applied.append(f"Categories: {', '.join(filters['category'])}")
            else:
                applied.append(f"Category: {filters['category']}")
        
        if 'level' in filters:
            if isinstance(filters['level'], list):
                applied.append(f"Levels: {', '.join(filters['level'])}")
            else:
                applied.append(f"Level: {filters['level']}")
        
        if 'status' in filters:
            applied.append(f"Status: {filters['status']}")
        
        if 'username' in filters:
            applied.append(f"User: {filters['username']}")
        
        if 'ip_address' in filters:
            applied.append(f"IP: {filters['ip_address']}")
        
        if 'start_date' in filters:
            applied.append(f"From: {filters['start_date']}")
        
        if 'end_date' in filters:
            applied.append(f"To: {filters['end_date']}")
        
        if 'is_suspicious' in filters:
            suspicious = 'Yes' if filters['is_suspicious'] in ['true', '1', True] else 'No'
            applied.append(f"Suspicious: {suspicious}")
        
        return applied
    
    def get_audit_statistics(self, start_date=None, end_date=None):
        """Get audit log statistics for dashboard"""
        try:
            # Use AuditLog method if available, otherwise calculate here
            if hasattr(AuditLog, 'get_stats'):
                return AuditLog.get_stats(start_date, end_date)
            
            # Fallback calculation
            query = AuditLog.query
            
            if start_date:
                query = query.filter(AuditLog.timestamp >= start_date)
            if end_date:
                query = query.filter(AuditLog.timestamp <= end_date)
            
            stats = {
                'total_events': query.count(),
                'by_category': dict(query.with_entities(AuditLog.category, func.count(AuditLog.id)).group_by(AuditLog.category).all()),
                'by_level': dict(query.with_entities(AuditLog.level, func.count(AuditLog.id)).group_by(AuditLog.level).all()),
                'by_status': dict(query.with_entities(AuditLog.status, func.count(AuditLog.id)).group_by(AuditLog.status).all()),
                'failed_events': query.filter(AuditLog.status != 'success').count(),
                'suspicious_events': query.filter(AuditLog.is_suspicious == True).count(),
                'high_risk_events': query.filter(AuditLog.risk_level >= 70).count()
            }
            
            return stats
            
        except Exception as e:
            current_app.logger.error(f"Error getting audit statistics: {e}")
            return {}
    
    def get_quick_filters(self):
        """Get quick filter options for common searches"""
        try:
            # Get available values for filters
            categories = db.session.query(AuditLog.category).distinct().all()
            categories = [c[0] for c in categories if c[0]]
            
            # Get all actions (not limited) and organize by category
            actions = db.session.query(AuditLog.action).distinct().all()
            actions = [a[0] for a in actions if a[0]]
            
            # Organize actions by category for better UX
            admin_actions = [a for a in actions if a.startswith('admin_')]
            auth_actions = [a for a in actions if a.startswith('auth_')]
            security_actions = [a for a in actions if a.startswith('security_')]
            file_actions = [a for a in actions if a.startswith('file_')]
            system_actions = [a for a in actions if a.startswith('system_')]
            
            levels = ['debug', 'info', 'warning', 'error', 'critical']
            statuses = ['success', 'failed', 'error', 'pending']
            
            return {
                'categories': sorted(categories),
                'actions': sorted(actions),
                'actions_by_category': {
                    'Admin Operations': sorted(admin_actions),
                    'Authentication': sorted(auth_actions),
                    'Security Events': sorted(security_actions),
                    'File Operations': sorted(file_actions),
                    'System Events': sorted(system_actions)
                },
                'levels': levels,
                'statuses': statuses,
                'quick_searches': [
                    {'name': 'Failed Logins', 'filters': {'action': 'security_login_failed'}},
                    {'name': 'Admin Actions', 'filters': {'category': 'administration'}},
                    {'name': 'Security Events', 'filters': {'category': 'security'}},
                    {'name': 'File Operations', 'filters': {'category': 'file'}},
                    {'name': 'Suspicious Activity', 'filters': {'is_suspicious': 'true'}},
                    {'name': 'High Risk Events', 'filters': {'min_risk_level': '70'}},
                    {'name': 'System Events', 'filters': {'category': 'system'}},
                    {'name': 'Authentication Events', 'filters': {'category': 'authentication'}},
                    {'name': 'Failed Operations', 'filters': {'status': 'failed'}},
                    {'name': 'Recent Critical', 'filters': {'level': 'critical', 'start_date': (datetime.now(timezone.utc) - timedelta(hours=24)).isoformat()}},
                    # Add specific admin action filters for evidence tracking
                    {'name': 'User Management', 'filters': {'action': ['admin_user_create', 'admin_user_delete', 'admin_user_disable', 'admin_user_enable']}},
                    {'name': 'Quota Changes', 'filters': {'action': ['admin_quota_change', 'admin_bulk_quota_change']}},
                    {'name': 'IP Blocks', 'filters': {'action': ['admin_ip_block', 'admin_ip_unblock', 'admin_ip_cleanup']}},
                    {'name': 'Session Management', 'filters': {'action': ['admin_session_terminate', 'admin_bulk_operation']}},
                    {'name': 'Backup Operations', 'filters': {'action': ['admin_backup_create', 'admin_backup_delete', 'admin_backup_cleanup']}},
                    {'name': 'Export Operations', 'filters': {'action': ['admin_export_create', 'admin_export_delete', 'admin_export_download']}}
                ]
            }
            
        except Exception as e:
            current_app.logger.error(f"Error getting quick filters: {e}")
            return {}
    
    def export_audit_logs(self, filters=None, format='csv', include_legacy=True):
        """Export audit logs with applied filters"""
        try:
            # Remove pagination for export
            export_filters = filters.copy() if filters else {}
            export_filters.pop('page', None)
            export_filters.pop('per_page', None)
            export_filters['include_details'] = True
            
            # Get all matching logs
            results = self.search_audit_logs(**export_filters)
            
            if format == 'csv':
                return self._export_audit_csv(results, include_legacy)
            elif format == 'json':
                return self._export_audit_json(results, include_legacy)
            else:
                raise ValueError(f"Unsupported export format: {format}")
                
        except Exception as e:
            raise Exception(f"Audit export failed: {str(e)}")
    
    def _export_audit_csv(self, results, include_legacy):
        """Export audit logs to CSV format"""
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'Timestamp', 'Action', 'Category', 'Level', 'Status', 'User ID', 'Username',
            'IP Address', 'Endpoint', 'Method', 'Target Type', 'Target ID', 'Target Name',
            'Description', 'Risk Level', 'Is Suspicious', 'Duration (ms)', 'Session ID',
            'User Agent', 'Result Code'
        ])
        
        # Write audit log data
        for log in results.get('logs', []):
            writer.writerow([
                log['timestamp'],
                log['action'],
                log['category'],
                log['level'],
                log['status'],
                log['user_id'] or '',
                log['username'] or '',
                log['ip_address'] or '',
                log['endpoint'] or '',
                log['method'] or '',
                log['target_type'] or '',
                log['target_id'] or '',
                log['target_name'] or '',
                log['description'] or '',
                log['risk_level'],
                log['is_suspicious'],
                log['duration_ms'] or '',
                log['session_id'] or '',
                log['user_agent'] or '',
                log['result_code'] or ''
            ])
        
        # Include legacy activity logs if requested
        if include_legacy:
            self._append_legacy_logs_csv(writer, results.get('filters_applied', {}))
        
        csv_content = output.getvalue()
        output.close()
        
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        filename = f'audit_trail_export_{timestamp}.csv'
        
        return csv_content, filename
    
    def _export_audit_json(self, results, include_legacy):
        """Export audit logs to JSON format"""
        export_data = {
            'export_info': {
                'exported_at': datetime.now(timezone.utc).isoformat(),
                'total_records': results.get('total_count', 0),
                'filters_applied': results.get('filters_applied', []),
                'includes_legacy': include_legacy,
                'export_type': 'audit_trail'
            },
            'audit_logs': results.get('logs', [])
        }
        
        # Include legacy logs if requested
        if include_legacy:
            legacy_logs = self._get_legacy_logs_for_export()
            export_data['legacy_activity_logs'] = legacy_logs
            export_data['export_info']['legacy_records'] = len(legacy_logs)
        
        json_content = json.dumps(export_data, indent=2, default=str)
        
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        filename = f'audit_trail_export_{timestamp}.json'
        
        return json_content, filename
    
    def _append_legacy_logs_csv(self, writer, filters):
        """Append legacy activity logs to CSV export"""
        try:
            # Get legacy logs with basic filtering
            query = ActivityLog.query
            
            # Apply basic date filters if present
            if 'start_date' in filters:
                try:
                    start_date = datetime.fromisoformat(filters['start_date'].replace('Z', '+00:00'))
                    query = query.filter(ActivityLog.timestamp >= start_date)
                except:
                    pass
            
            if 'end_date' in filters:
                try:
                    end_date = datetime.fromisoformat(filters['end_date'].replace('Z', '+00:00'))
                    query = query.filter(ActivityLog.timestamp <= end_date)
                except:
                    pass
            
            legacy_logs = query.order_by(desc(ActivityLog.timestamp)).limit(1000).all()
            
            for log in legacy_logs:
                writer.writerow([
                    log.timestamp.isoformat(),
                    log.action,
                    'legacy',  # category
                    'info',    # level
                    log.status,
                    log.user_id or '',
                    log.user.username if log.user else '',
                    log.ip_address or '',
                    '',  # endpoint
                    '',  # method
                    '',  # target_type
                    '',  # target_id
                    '',  # target_name
                    log.detail or '',
                    0,   # risk_level
                    False,  # is_suspicious
                    '',  # duration_ms
                    '',  # session_id
                    '',  # user_agent
                    ''   # result_code
                ])
                
        except Exception as e:
            current_app.logger.error(f"Error appending legacy logs: {e}")
    
    def _get_legacy_logs_for_export(self):
        """Get legacy activity logs for JSON export"""
        try:
            legacy_logs = ActivityLog.query.order_by(
                desc(ActivityLog.timestamp)
            ).limit(1000).all()
            
            return [
                {
                    'timestamp': log.timestamp.isoformat(),
                    'action': log.action,
                    'status': log.status,
                    'user_id': log.user_id,
                    'username': log.user.username if log.user else None,
                    'detail': log.detail,
                    'ip_address': log.ip_address,
                    'type': 'legacy_activity_log'
                }
                for log in legacy_logs
            ]
            
        except Exception as e:
            current_app.logger.error(f"Error getting legacy logs: {e}")
            return []


# Global audit viewer instance
audit_viewer = AuditViewer()