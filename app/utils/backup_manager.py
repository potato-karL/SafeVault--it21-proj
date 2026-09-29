"""
Backup Management utilities for SafeVault.
Handles database backups, file backups, and system configuration backups.
"""
import os
import shutil
import sqlite3
import json
import hashlib
import zipfile
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from flask import current_app
from app import db
from app.models import BackupLog, User, File, AuditLog, ActivityLog
from app.utils.audit_logger import AuditLogger

class BackupManager:
    """Manages backup operations for SafeVault."""
    
    def __init__(self):
        self.backup_dir = Path(current_app.config.get('BACKUP_DIRECTORY', 'backups'))
        self.backup_dir.mkdir(exist_ok=True)
        
    def create_full_backup(self, user_id, include_files=True):
        """Create a full system backup."""
        backup_log = BackupLog(
            backup_type='full',
            status='in_progress',
            initiated_by=user_id
        )
        db.session.add(backup_log)
        db.session.commit()
        
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_filename = f"safevault_full_backup_{timestamp}.zip"
            backup_path = self.backup_dir / backup_filename
            
            with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                # Backup database
                db_backup_path = self._backup_database(zipf)
                
                # Backup configuration files
                self._backup_configuration(zipf)
                
                # Backup user files if requested
                items_count = 0
                if include_files:
                    items_count = self._backup_user_files(zipf)
                
                # Add backup metadata
                metadata = {
                    'backup_type': 'full',
                    'timestamp': timestamp,
                    'safevault_version': current_app.config.get('VERSION', 'unknown'),
                    'include_files': include_files,
                    'database_backup': db_backup_path,
                    'items_count': items_count
                }
                
                zipf.writestr('backup_metadata.json', json.dumps(metadata, indent=2))
            
            # Calculate file size and checksum
            file_size = backup_path.stat().st_size
            checksum = self._calculate_checksum(backup_path)
            
            # Update backup log
            backup_log.mark_completed(str(backup_path), file_size, checksum, items_count)
            backup_log.set_metadata(metadata)
            db.session.commit()
            
            # Log the action
            AuditLogger.log_admin_action(
                action='backup_created',
                description=f'Full backup created: {backup_filename}',
                target_type='system'
            )
            
            return backup_log
            
        except Exception as e:
            backup_log.mark_failed(str(e))
            db.session.commit()
            raise
    
    def create_database_backup(self, user_id):
        """Create a database-only backup."""
        backup_log = BackupLog(
            backup_type='database_only',
            status='in_progress',
            initiated_by=user_id
        )
        db.session.add(backup_log)
        db.session.commit()
        
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_filename = f"safevault_db_backup_{timestamp}.sqlite"
            backup_path = self.backup_dir / backup_filename
            
            # Get database path
            db_path = current_app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')
            
            # Create database backup
            shutil.copy2(db_path, backup_path)
            
            # Calculate file size and checksum
            file_size = backup_path.stat().st_size
            checksum = self._calculate_checksum(backup_path)
            
            # Count records
            items_count = self._count_database_records()
            
            metadata = {
                'backup_type': 'database_only',
                'timestamp': timestamp,
                'records_count': items_count
            }
            
            backup_log.mark_completed(str(backup_path), file_size, checksum, items_count)
            backup_log.set_metadata(metadata)
            db.session.commit()
            
            AuditLogger.log_admin_action(
                action='database_backup_created',
                description=f'Database backup created: {backup_filename}',
                target_type='system'
            )
            
            return backup_log
            
        except Exception as e:
            backup_log.mark_failed(str(e))
            db.session.commit()
            raise
    
    def create_incremental_backup(self, user_id, since_date=None):
        """Create an incremental backup with changes since the specified date."""
        if not since_date:
            # Get the last successful backup date
            last_backup = BackupLog.query.filter_by(
                status='completed'
            ).order_by(BackupLog.completed_at.desc()).first()
            
            if last_backup:
                since_date = last_backup.completed_at
            else:
                # No previous backup, create full backup instead
                return self.create_full_backup(user_id)
        
        backup_log = BackupLog(
            backup_type='incremental',
            status='in_progress',
            initiated_by=user_id
        )
        db.session.add(backup_log)
        db.session.commit()
        
        try:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_filename = f"safevault_incremental_backup_{timestamp}.zip"
            backup_path = self.backup_dir / backup_filename
            
            with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                # Backup changed files
                changed_files = File.query.filter(
                    File.uploaded_at > since_date
                ).all()
                
                items_count = 0
                for file_record in changed_files:
                    try:
                        file_path = Path(file_record.file_path)
                        if file_path.exists():
                            arcname = f"files/{file_record.user_id}/{file_record.encrypted_filename}"
                            zipf.write(file_path, arcname)
                            items_count += 1
                    except Exception:
                        continue  # Skip files that can't be backed up
                
                # Export changed database records
                self._backup_incremental_data(zipf, since_date)
                
                # Add backup metadata
                metadata = {
                    'backup_type': 'incremental',
                    'timestamp': timestamp,
                    'since_date': since_date.isoformat(),
                    'changed_files': items_count
                }
                
                zipf.writestr('backup_metadata.json', json.dumps(metadata, indent=2))
            
            file_size = backup_path.stat().st_size
            checksum = self._calculate_checksum(backup_path)
            
            backup_log.mark_completed(str(backup_path), file_size, checksum, items_count)
            backup_log.set_metadata(metadata)
            db.session.commit()
            
            AuditLogger.log_admin_action(
                action='incremental_backup_created',
                description=f'Incremental backup created: {backup_filename}',
                target_type='system'
            )
            
            return backup_log
            
        except Exception as e:
            backup_log.mark_failed(str(e))
            db.session.commit()
            raise
    
    def restore_backup(self, backup_id, user_id, restore_files=True):
        """Restore from a backup."""
        backup_log = BackupLog.query.get_or_404(backup_id)
        
        if not backup_log.file_path or not Path(backup_log.file_path).exists():
            raise ValueError("Backup file not found")
        
        # Verify backup integrity
        if not self._verify_backup_integrity(backup_log):
            raise ValueError("Backup integrity check failed")
        
        try:
            if backup_log.backup_type == 'database_only':
                self._restore_database_backup(backup_log, user_id)
            else:
                self._restore_full_backup(backup_log, user_id, restore_files)
            
            AuditLogger.log_admin_action(
                action='backup_restored',
                description=f'Backup restored: {backup_log.file_path}',
                target_type='system'
            )
            
        except Exception as e:
            AuditLogger.log_admin_action(
                action='backup_restore_failed',
                description=f'Backup restore failed: {str(e)}',
                target_type='system'
            )
            raise
    
    def cleanup_old_backups(self, retention_days=30):
        """Clean up old backup files."""
        cutoff_date = datetime.now(timezone.utc) - timedelta(days=retention_days)
        
        old_backups = BackupLog.query.filter(
            BackupLog.started_at < cutoff_date,
            BackupLog.status == 'completed'
        ).all()
        
        cleaned_count = 0
        freed_space = 0
        
        for backup in old_backups:
            if backup.file_path and Path(backup.file_path).exists():
                file_size = Path(backup.file_path).stat().st_size
                os.remove(backup.file_path)
                freed_space += file_size
                cleaned_count += 1
            
            # Remove the backup log entry
            db.session.delete(backup)
        
        db.session.commit()
        
        return {
            'cleaned_count': cleaned_count,
            'freed_space': freed_space
        }
    
    def _backup_database(self, zipf):
        """Backup the database to the zip file using SQLite's safe backup API."""
        db_path = current_app.config['SQLALCHEMY_DATABASE_URI'].replace('sqlite:///', '')

        # Create temp file path without keeping it open (Windows fix: close handle first)
        tmp_fd, tmp_path = tempfile.mkstemp(suffix='.sqlite')
        os.close(tmp_fd)  # Close the OS-level file descriptor immediately

        try:
            # Use SQLite's built-in backup API — safely copies a live/locked DB
            src_conn = sqlite3.connect(db_path)
            dst_conn = sqlite3.connect(tmp_path)
            try:
                src_conn.backup(dst_conn)
            finally:
                dst_conn.close()
                src_conn.close()

            zipf.write(tmp_path, 'database/safevault.db')
        finally:
            # Always clean up the temp file
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

        return 'database/safevault.db'
    
    def _backup_configuration(self, zipf):
        """Backup configuration files."""
        config_files = ['config.py', '.env']
        
        for config_file in config_files:
            config_path = Path(config_file)
            if config_path.exists():
                zipf.write(config_path, f'config/{config_file}')
    
    def _backup_user_files(self, zipf):
        """Backup all user files."""
        files = File.query.all()
        items_count = 0
        
        for file_record in files:
            try:
                file_path = Path(file_record.file_path)
                if file_path.exists():
                    # Create a structured path in the backup
                    arcname = f"files/{file_record.user_id}/{file_record.encrypted_filename}"
                    zipf.write(file_path, arcname)
                    items_count += 1
            except Exception:
                continue  # Skip files that can't be backed up
        
        return items_count
    
    def _backup_incremental_data(self, zipf, since_date):
        """Backup database records changed since the specified date."""
        # Export audit logs
        audit_logs = AuditLog.query.filter(AuditLog.timestamp > since_date).all()
        audit_data = []
        for log in audit_logs:
            audit_data.append({
                'id': log.id,
                'user_id': log.user_id,
                'action': log.action,
                'details': log.details,
                'timestamp': log.timestamp.isoformat(),
                'ip_address': log.ip_address,
                'user_agent': log.user_agent
            })
        
        zipf.writestr('incremental_data/audit_logs.json', json.dumps(audit_data, indent=2))
        
        # Export activity logs
        activity_logs = ActivityLog.query.filter(ActivityLog.timestamp > since_date).all()
        activity_data = []
        for log in activity_logs:
            activity_data.append({
                'id': log.id,
                'user_id': log.user_id,
                'action': log.action,
                'details': log.details,
                'timestamp': log.timestamp.isoformat(),
                'ip_address': log.ip_address
            })
        
        zipf.writestr('incremental_data/activity_logs.json', json.dumps(activity_data, indent=2))
    
    def _count_database_records(self):
        """Count total records in key database tables."""
        try:
            user_count = User.query.count()
            file_count = File.query.count()
            audit_count = AuditLog.query.count()
            activity_count = ActivityLog.query.count()
            
            return user_count + file_count + audit_count + activity_count
        except Exception:
            return 0
    
    def _calculate_checksum(self, file_path):
        """Calculate SHA-256 checksum of a file."""
        hash_sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_sha256.update(chunk)
        return hash_sha256.hexdigest()
    
    def _verify_backup_integrity(self, backup_log):
        """Verify backup file integrity using checksum."""
        if not backup_log.checksum:
            return True  # No checksum to verify
        
        current_checksum = self._calculate_checksum(backup_log.file_path)
        return current_checksum == backup_log.checksum
    
    def _restore_database_backup(self, backup_log, user_id):
        """Restore from a database-only backup."""
        # This is a dangerous operation - implement with extreme caution
        # In a production environment, this should require additional confirmation
        raise NotImplementedError("Database restore requires manual intervention for safety")
    
    def _restore_full_backup(self, backup_log, user_id, restore_files):
        """Restore from a full backup."""
        # This is a dangerous operation - implement with extreme caution
        # In a production environment, this should require additional confirmation
        raise NotImplementedError("Full restore requires manual intervention for safety")
    
    def get_backup_statistics(self):
        """Get backup statistics and metrics."""
        total_backups = BackupLog.query.count()
        successful_backups = BackupLog.query.filter_by(status='completed').count()
        failed_backups = BackupLog.query.filter_by(status='failed').count()
        
        # Calculate total backup size
        completed_backups = BackupLog.query.filter_by(status='completed').all()
        total_size = sum(backup.file_size or 0 for backup in completed_backups)
        
        # Get latest backup
        latest_backup = BackupLog.query.filter_by(
            status='completed'
        ).order_by(BackupLog.completed_at.desc()).first()
        
        return {
            'total_backups': total_backups,
            'successful_backups': successful_backups,
            'failed_backups': failed_backups,
            'success_rate': (successful_backups / total_backups * 100) if total_backups > 0 else 0,
            'total_size': total_size,
            'latest_backup': latest_backup.completed_at if latest_backup else None,
            'backup_directory_size': self._get_directory_size(self.backup_dir)
        }
    
    def _get_directory_size(self, directory):
        """Calculate total size of files in a directory."""
        total_size = 0
        try:
            for dirpath, dirnames, filenames in os.walk(directory):
                for filename in filenames:
                    filepath = os.path.join(dirpath, filename)
                    try:
                        total_size += os.path.getsize(filepath)
                    except (OSError, FileNotFoundError):
                        continue
        except Exception:
            pass
        return total_size