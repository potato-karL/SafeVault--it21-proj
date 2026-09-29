"""
Audit Log Export Utility for SafeVault
Provides comprehensive audit trail export capabilities
"""

import csv
import json
import io
from datetime import datetime, timezone, timedelta
from flask import current_app, make_response
from app.models.audit_log import AuditLog
from app.models.activity_log import ActivityLog
from app.models.user import User
from app.utils.audit_logger import AuditLogger
import zipfile
import tempfile
import os

class AuditExporter:
    """Handles audit log export operations"""
    
    @staticmethod
    def export_to_csv(filters=None, include_legacy=True):
        """
        Export audit logs to CSV format
        
        Args:
            filters: Dictionary of filters to apply
            include_legacy: Whether to include legacy ActivityLog entries
            
        Returns:
            tuple: (csv_content, filename)
        """
        try:
            # Get audit logs based on filters
            audit_logs = AuditExporter._get_filtered_logs(filters or {})
            
            # Create CSV content
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write header
            headers = [
                'Timestamp', 'Action', 'Category', 'Level', 'Status', 'User ID', 'Username',
                'IP Address', 'User Agent', 'Endpoint', 'Method', 'Target Type', 'Target ID',
                'Target Name', 'Description', 'Risk Level', 'Is Suspicious', 'Duration (ms)',
                'Session ID', 'Details'
            ]
            writer.writerow(headers)
            
            # Write audit log data
            for log in audit_logs:
                writer.writerow([
                    log.timestamp.isoformat(),
                    log.action,
                    log.category,
                    log.level,
                    log.status,
                    log.user_id or '',
                    log.username or '',
                    log.ip_address or '',
                    log.user_agent or '',
                    log.endpoint or '',
                    log.method or '',
                    log.target_type or '',
                    log.target_id or '',
                    log.target_name or '',
                    log.description or '',
                    log.risk_level or 0,
                    log.is_suspicious,
                    log.duration_ms or '',
                    log.session_id or '',
                    log.details or ''
                ])
            
            # Include legacy activity logs if requested
            if include_legacy:
                AuditExporter._append_legacy_logs_to_csv(writer, filters)
            
            csv_content = output.getvalue()
            output.close()
            
            # Generate filename with timestamp
            timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
            filename = f'safevault_audit_export_{timestamp}.csv'
            
            # Log the export action
            AuditLogger.log_admin_action(
                'admin_audit_export',
                description=f"Audit logs exported to CSV ({len(audit_logs)} entries)"
            )
            
            return csv_content, filename
            
        except Exception as e:
            current_app.logger.error(f"Error exporting audit logs to CSV: {e}")
            raise
    
    @staticmethod
    def export_to_json(filters=None, include_legacy=True, pretty=True):
        """
        Export audit logs to JSON format
        
        Args:
            filters: Dictionary of filters to apply
            include_legacy: Whether to include legacy ActivityLog entries
            pretty: Whether to format JSON for readability
            
        Returns:
            tuple: (json_content, filename)
        """
        try:
            # Get audit logs
            audit_logs = AuditExporter._get_filtered_logs(filters or {})
            
            # Convert to dictionaries
            export_data = {
                'export_info': {
                    'exported_at': datetime.now(timezone.utc).isoformat(),
                    'total_records': len(audit_logs),
                    'filters_applied': filters or {},
                    'includes_legacy': include_legacy,
                    'safevault_version': '1.0'
                },
                'audit_logs': [log.to_dict() for log in audit_logs]
            }
            
            # Include legacy logs if requested
            if include_legacy:
                legacy_logs = AuditExporter._get_legacy_logs(filters)
                export_data['legacy_activity_logs'] = [
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
                export_data['export_info']['legacy_records'] = len(legacy_logs)
                export_data['export_info']['total_records'] += len(legacy_logs)
            
            # Convert to JSON
            if pretty:
                json_content = json.dumps(export_data, indent=2, default=str)
            else:
                json_content = json.dumps(export_data, default=str)
            
            # Generate filename
            timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
            filename = f'safevault_audit_export_{timestamp}.json'
            
            # Log the export action
            AuditLogger.log_admin_action(
                'admin_audit_export',
                description=f"Audit logs exported to JSON ({len(audit_logs)} entries)"
            )
            
            return json_content, filename
            
        except Exception as e:
            current_app.logger.error(f"Error exporting audit logs to JSON: {e}")
            raise
    
    @staticmethod
    def export_comprehensive_archive(filters=None):
        """
        Export comprehensive audit archive with multiple formats and metadata
        
        Returns:
            tuple: (zip_content, filename)
        """
        try:
            # Create temporary directory
            with tempfile.TemporaryDirectory() as temp_dir:
                
                # Export CSV
                csv_content, csv_filename = AuditExporter.export_to_csv(filters, include_legacy=True)
                csv_path = os.path.join(temp_dir, csv_filename)
                with open(csv_path, 'w', encoding='utf-8') as f:
                    f.write(csv_content)
                
                # Export JSON
                json_content, json_filename = AuditExporter.export_to_json(filters, include_legacy=True)
                json_path = os.path.join(temp_dir, json_filename)
                with open(json_path, 'w', encoding='utf-8') as f:
                    f.write(json_content)
                
                # Create metadata file
                metadata = AuditExporter._generate_export_metadata(filters)
                metadata_path = os.path.join(temp_dir, 'export_metadata.json')
                with open(metadata_path, 'w', encoding='utf-8') as f:
                    json.dump(metadata, f, indent=2, default=str)
                
                # Create README file
                readme_content = AuditExporter._generate_readme()
                readme_path = os.path.join(temp_dir, 'README.md')
                with open(readme_path, 'w', encoding='utf-8') as f:
                    f.write(readme_content)
                
                # Create ZIP archive
                zip_buffer = io.BytesIO()
                with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zip_file:
                    zip_file.write(csv_path, csv_filename)
                    zip_file.write(json_path, json_filename)
                    zip_file.write(metadata_path, 'export_metadata.json')
                    zip_file.write(readme_path, 'README.md')
                
                zip_content = zip_buffer.getvalue()
                zip_buffer.close()
                
                # Generate filename
                timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
                filename = f'safevault_comprehensive_audit_export_{timestamp}.zip'
                
                # Log the export action
                AuditLogger.log_admin_action(
                    'admin_comprehensive_export',
                    description="Comprehensive audit archive exported"
                )
                
                return zip_content, filename
                
        except Exception as e:
            current_app.logger.error(f"Error creating comprehensive audit archive: {e}")
            raise
    
    @staticmethod
    def _get_filtered_logs(filters):
        """Get audit logs with applied filters"""
        query = AuditLog.query
        
        # Apply filters
        if 'start_date' in filters:
            query = query.filter(AuditLog.timestamp >= filters['start_date'])
        
        if 'end_date' in filters:
            query = query.filter(AuditLog.timestamp <= filters['end_date'])
        
        if 'user_id' in filters:
            query = query.filter(AuditLog.user_id == filters['user_id'])
        
        if 'action' in filters:
            if isinstance(filters['action'], list):
                query = query.filter(AuditLog.action.in_(filters['action']))
            else:
                query = query.filter(AuditLog.action == filters['action'])
        
        if 'category' in filters:
            query = query.filter(AuditLog.category == filters['category'])
        
        if 'level' in filters:
            query = query.filter(AuditLog.level == filters['level'])
        
        if 'status' in filters:
            query = query.filter(AuditLog.status == filters['status'])
        
        if 'ip_address' in filters:
            query = query.filter(AuditLog.ip_address == filters['ip_address'])
        
        if 'is_suspicious' in filters:
            query = query.filter(AuditLog.is_suspicious == filters['is_suspicious'])
        
        if 'min_risk_level' in filters:
            query = query.filter(AuditLog.risk_level >= filters['min_risk_level'])
        
        # Order by timestamp
        query = query.order_by(AuditLog.timestamp.desc())
        
        # Apply limit
        limit = filters.get('limit', 10000)  # Default limit of 10k records
        return query.limit(limit).all()
    
    @staticmethod
    def _get_legacy_logs(filters):
        """Get legacy activity logs with applied filters"""
        query = ActivityLog.query
        
        # Apply similar filters to legacy logs
        if 'start_date' in filters:
            query = query.filter(ActivityLog.timestamp >= filters['start_date'])
        
        if 'end_date' in filters:
            query = query.filter(ActivityLog.timestamp <= filters['end_date'])
        
        if 'user_id' in filters:
            query = query.filter(ActivityLog.user_id == filters['user_id'])
        
        if 'action' in filters:
            if isinstance(filters['action'], list):
                query = query.filter(ActivityLog.action.in_(filters['action']))
            else:
                query = query.filter(ActivityLog.action == filters['action'])
        
        # Order by timestamp
        query = query.order_by(ActivityLog.timestamp.desc())
        
        # Apply limit
        limit = filters.get('limit', 5000)  # Smaller limit for legacy logs
        return query.limit(limit).all()
    
    @staticmethod
    def _append_legacy_logs_to_csv(writer, filters):
        """Append legacy activity logs to CSV"""
        legacy_logs = AuditExporter._get_legacy_logs(filters)
        
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
                '',  # user_agent
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
                ''   # details
            ])
    
    @staticmethod
    def _generate_export_metadata(filters):
        """Generate export metadata"""
        stats = AuditLog.get_stats()
        
        return {
            'export_timestamp': datetime.now(timezone.utc).isoformat(),
            'filters_applied': filters,
            'database_stats': stats,
            'system_info': {
                'safevault_version': '1.0',
                'export_format_version': '1.0'
            },
            'export_types': ['csv', 'json'],
            'includes_legacy_logs': True
        }
    
    @staticmethod
    def _generate_readme():
        """Generate README content for export archive"""
        return """# SafeVault Audit Log Export

This archive contains a comprehensive export of SafeVault audit logs.

## Contents

- `safevault_audit_export_*.csv` - Audit logs in CSV format
- `safevault_audit_export_*.json` - Audit logs in JSON format  
- `export_metadata.json` - Export metadata and statistics
- `README.md` - This file

## CSV Format

The CSV file contains the following columns:
- Timestamp: When the event occurred (ISO format)
- Action: The action that was performed
- Category: Event category (authentication, file, admin, etc.)
- Level: Log level (info, warning, error, critical)
- Status: Operation status (success, failed)
- User ID: ID of the user who performed the action
- Username: Username of the user
- IP Address: Source IP address
- User Agent: Browser/client user agent
- Endpoint: Application endpoint accessed
- Method: HTTP method used
- Target Type: Type of target object (user, file, system)
- Target ID: ID of the target object
- Target Name: Name/description of target
- Description: Human-readable description
- Risk Level: Calculated risk score (0-100)
- Is Suspicious: Whether flagged as suspicious
- Duration (ms): Operation duration in milliseconds
- Session ID: User session identifier
- Details: Additional JSON-encoded details

## JSON Format

The JSON file contains structured audit log data with:
- Export metadata and statistics
- Detailed audit log entries
- Legacy activity log entries (if included)

## Data Integrity

This export was generated from SafeVault's audit logging system and represents
a point-in-time snapshot of audit events. The data should be treated as
read-only for compliance and analysis purposes.

## Questions

If you have questions about this export, contact your SafeVault administrator.
"""

    @staticmethod
    def create_scheduled_export(filters, export_format='json', schedule_type='daily'):
        """
        Create a scheduled export configuration (placeholder for future implementation)
        """
        # This would be implemented with a task queue like Celery
        pass