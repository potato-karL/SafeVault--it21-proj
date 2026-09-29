"""
Disk Integrity Scanner for SafeVault
Scans and verifies file integrity, detects corruption, and maintains file health
"""

import os
import hashlib
import time
from datetime import datetime, timezone, timedelta
from flask import current_app
from app.models.file import File
from app.models.audit_log import AuditLog
from app.utils.audit_logger import AuditLogger
from app import db
import threading
import json

class IntegrityScanner:
    """Handles file integrity scanning and verification"""
    
    def __init__(self):
        self.scan_active = False
        self.scan_thread = None
        self.scan_results = {}
        
    def start_full_scan(self, background=True):
        """
        Start a full integrity scan of all files
        
        Args:
            background: Whether to run in background thread
            
        Returns:
            dict: Scan results if not background, scan ID if background
        """
        if self.scan_active:
            return {'error': 'Scan already in progress'}
        
        scan_id = f"scan_{int(time.time())}"
        
        if background:
            self.scan_active = True
            self.scan_thread = threading.Thread(
                target=self._run_full_scan,
                args=(scan_id,),
                daemon=True,
                name='IntegrityScanner'
            )
            self.scan_thread.start()
            
            AuditLogger.log_system_event(
                'system_integrity_scan_started',
                description="Full integrity scan started in background"
            )
            
            return {'scan_id': scan_id, 'status': 'started', 'background': True}
        else:
            return self._run_full_scan(scan_id)
    
    def _run_full_scan(self, scan_id):
        """Run the actual full scan"""
        try:
            start_time = time.time()
            results = {
                'scan_id': scan_id,
                'started_at': datetime.now(timezone.utc).isoformat(),
                'status': 'running',
                'files_scanned': 0,
                'files_healthy': 0,
                'files_corrupted': 0,
                'files_missing': 0,
                'files_orphaned': 0,
                'corrupted_files': [],
                'missing_files': [],
                'orphaned_files': [],
                'errors': []
            }
            
            self.scan_results[scan_id] = results
            
            # Get all files from database
            files = File.query.all()
            total_files = len(files)
            
            current_app.logger.info(f"Starting integrity scan of {total_files} files")
            
            for i, file_record in enumerate(files):
                if not self.scan_active:  # Check if scan was cancelled
                    break
                    
                try:
                    # Update progress
                    results['files_scanned'] = i + 1
                    results['progress'] = ((i + 1) / total_files) * 100 if total_files > 0 else 0
                    
                    # Check file integrity
                    integrity_result = self._check_file_integrity(file_record)
                    
                    if integrity_result['status'] == 'healthy':
                        results['files_healthy'] += 1
                    elif integrity_result['status'] == 'corrupted':
                        results['files_corrupted'] += 1
                        results['corrupted_files'].append({
                            'id': file_record.id,
                            'filename': file_record.filename,
                            'path': file_record.get_file_path(),
                            'expected_hash': file_record.hash_value,
                            'actual_hash': integrity_result.get('actual_hash'),
                            'details': integrity_result.get('details')
                        })
                        
                        # Log corrupted file
                        AuditLogger.log_security_event(
                            'security_file_corruption_detected',
                            description=f"File corruption detected: {file_record.filename}",
                            is_suspicious=True,
                            level='critical'
                        )
                        
                    elif integrity_result['status'] == 'missing':
                        results['files_missing'] += 1
                        results['missing_files'].append({
                            'id': file_record.id,
                            'filename': file_record.filename,
                            'path': file_record.get_file_path(),
                            'details': integrity_result.get('details')
                        })
                        
                        # Log missing file
                        AuditLogger.log_security_event(
                            'security_file_missing',
                            description=f"File missing from disk: {file_record.filename}",
                            is_suspicious=True,
                            level='warning'
                        )
                
                except Exception as e:
                    error_msg = f"Error scanning file {file_record.id} ({file_record.filename}): {str(e)}"
                    results['errors'].append(error_msg)
                    current_app.logger.error(error_msg)
            
            # Scan for orphaned files (files on disk not in database)
            orphaned_files = self._find_orphaned_files()
            results['files_orphaned'] = len(orphaned_files)
            results['orphaned_files'] = orphaned_files
            
            # Complete scan
            end_time = time.time()
            results['completed_at'] = datetime.now(timezone.utc).isoformat()
            results['duration_seconds'] = int(end_time - start_time)
            results['status'] = 'completed'
            results['summary'] = self._generate_scan_summary(results)
            
            # Log scan completion
            AuditLogger.log_system_event(
                'system_integrity_scan_completed',
                description=f"Integrity scan completed: {results['files_scanned']} files scanned, "
                          f"{results['files_corrupted']} corrupted, {results['files_missing']} missing"
            )
            
            current_app.logger.info(f"Integrity scan completed: {results['summary']}")
            
            self.scan_active = False
            return results
            
        except Exception as e:
            error_msg = f"Integrity scan failed: {str(e)}"
            current_app.logger.error(error_msg)
            
            results['status'] = 'failed'
            results['error'] = error_msg
            results['completed_at'] = datetime.now(timezone.utc).isoformat()
            
            AuditLogger.log_system_event(
                'system_integrity_scan_failed',
                description=error_msg,
                level='error'
            )
            
            self.scan_active = False
            return results
    
    def _check_file_integrity(self, file_record):
        """
        Check integrity of a single file
        
        Args:
            file_record: File database record
            
        Returns:
            dict: Integrity check result
        """
        try:
            file_path = file_record.get_file_path()
            
            # Check if file exists
            if not os.path.exists(file_path):
                return {
                    'status': 'missing',
                    'details': f'File not found at path: {file_path}'
                }
            
            # Check file size
            actual_size = os.path.getsize(file_path)
            if actual_size != file_record.size:
                return {
                    'status': 'corrupted',
                    'details': f'File size mismatch. Expected: {file_record.size}, Actual: {actual_size}'
                }
            
            # Check file hash
            if file_record.hash_value:
                actual_hash = self._calculate_file_hash(file_path)
                if actual_hash != file_record.hash_value:
                    return {
                        'status': 'corrupted',
                        'actual_hash': actual_hash,
                        'details': f'Hash mismatch. Expected: {file_record.hash_value}, Actual: {actual_hash}'
                    }
            
            # Check file permissions and accessibility
            if not os.access(file_path, os.R_OK):
                return {
                    'status': 'corrupted',
                    'details': 'File is not readable'
                }
            
            return {
                'status': 'healthy',
                'details': 'File integrity verified'
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'details': f'Error checking file integrity: {str(e)}'
            }
    
    def _calculate_file_hash(self, file_path, algorithm='sha256', chunk_size=8192):
        """Calculate hash of a file"""
        hash_obj = hashlib.new(algorithm)
        
        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(chunk_size):
                    hash_obj.update(chunk)
            return hash_obj.hexdigest()
        except Exception as e:
            raise Exception(f"Error calculating file hash: {str(e)}")
    
    def _find_orphaned_files(self):
        """Find files on disk that are not in the database"""
        orphaned_files = []
        
        try:
            upload_folder = current_app.config.get('UPLOAD_FOLDER', 'uploads')
            
            if not os.path.exists(upload_folder):
                return orphaned_files
            
            # Get all files from database
            db_files = set()
            for file_record in File.query.all():
                # Add both absolute and relative paths
                file_path = file_record.get_file_path()
                db_files.add(file_path)
                db_files.add(os.path.basename(file_path))
                if hasattr(file_record, 'filename'):
                    db_files.add(file_record.filename)
            
            # Scan upload directory
            for root, dirs, files in os.walk(upload_folder):
                for filename in files:
                    full_path = os.path.join(root, filename)
                    
                    # Skip hidden files and directories
                    if filename.startswith('.'):
                        continue
                    
                    # Check if file is in database
                    if (full_path not in db_files and 
                        filename not in db_files and 
                        os.path.basename(full_path) not in db_files):
                        
                        file_info = {
                            'path': full_path,
                            'filename': filename,
                            'size': os.path.getsize(full_path),
                            'modified': datetime.fromtimestamp(
                                os.path.getmtime(full_path), 
                                tz=timezone.utc
                            ).isoformat()
                        }
                        orphaned_files.append(file_info)
            
        except Exception as e:
            current_app.logger.error(f"Error finding orphaned files: {e}")
        
        return orphaned_files
    
    def _generate_scan_summary(self, results):
        """Generate a human-readable scan summary"""
        total_files = results['files_scanned']
        healthy = results['files_healthy']
        corrupted = results['files_corrupted']
        missing = results['files_missing']
        orphaned = results['files_orphaned']
        
        if total_files == 0:
            return "No files to scan"
        
        health_percentage = (healthy / total_files) * 100 if total_files > 0 else 0
        
        summary = f"{total_files} files scanned, {health_percentage:.1f}% healthy"
        
        issues = []
        if corrupted > 0:
            issues.append(f"{corrupted} corrupted")
        if missing > 0:
            issues.append(f"{missing} missing")
        if orphaned > 0:
            issues.append(f"{orphaned} orphaned")
        
        if issues:
            summary += f" - Issues: {', '.join(issues)}"
        
        return summary
    
    def get_scan_status(self, scan_id):
        """Get status of a specific scan"""
        return self.scan_results.get(scan_id, {'error': 'Scan not found'})
    
    def cancel_scan(self):
        """Cancel active scan"""
        if self.scan_active:
            self.scan_active = False
            if self.scan_thread:
                self.scan_thread.join(timeout=10)
            
            AuditLogger.log_system_event(
                'system_integrity_scan_cancelled',
                description="Integrity scan cancelled by administrator"
            )
            
            return True
        return False
    
    def quick_check_file(self, file_id):
        """Perform quick integrity check on a single file"""
        try:
            file_record = File.query.get(file_id)
            if not file_record:
                return {'error': 'File not found in database'}
            
            result = self._check_file_integrity(file_record)
            
            # Log the check
            AuditLogger.log_file_event(
                'file_integrity_check',
                file_id=file_id,
                filename=file_record.filename,
                status='success' if result['status'] == 'healthy' else 'failed'
            )
            
            return {
                'file_id': file_id,
                'filename': file_record.filename,
                'integrity_result': result,
                'checked_at': datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            error_msg = f"Error checking file {file_id}: {str(e)}"
            current_app.logger.error(error_msg)
            return {'error': error_msg}
    
    def repair_file_record(self, file_id, action='recalculate_hash'):
        """
        Attempt to repair a file record
        
        Args:
            file_id: File ID to repair
            action: Repair action ('recalculate_hash', 'update_size', etc.)
        """
        try:
            file_record = File.query.get(file_id)
            if not file_record:
                return {'error': 'File not found'}
            
            file_path = file_record.get_file_path()
            if not os.path.exists(file_path):
                return {'error': 'File not found on disk'}
            
            if action == 'recalculate_hash':
                # Recalculate and update hash
                new_hash = self._calculate_file_hash(file_path)
                old_hash = file_record.hash_value
                
                file_record.hash_value = new_hash
                db.session.commit()
                
                AuditLogger.log_admin_event(
                    'admin_file_repair',
                    target_user_id=file_record.user_id,
                    description=f"File hash recalculated for {file_record.filename}. "
                              f"Old: {old_hash}, New: {new_hash}"
                )
                
                return {
                    'success': True,
                    'action': 'recalculate_hash',
                    'old_hash': old_hash,
                    'new_hash': new_hash
                }
            
            elif action == 'update_size':
                # Update file size
                new_size = os.path.getsize(file_path)
                old_size = file_record.size
                
                file_record.size = new_size
                db.session.commit()
                
                AuditLogger.log_admin_event(
                    'admin_file_repair',
                    target_user_id=file_record.user_id,
                    description=f"File size updated for {file_record.filename}. "
                              f"Old: {old_size}, New: {new_size}"
                )
                
                return {
                    'success': True,
                    'action': 'update_size',
                    'old_size': old_size,
                    'new_size': new_size
                }
            
            else:
                return {'error': f'Unknown repair action: {action}'}
                
        except Exception as e:
            error_msg = f"Error repairing file {file_id}: {str(e)}"
            current_app.logger.error(error_msg)
            return {'error': error_msg}
    
    def cleanup_orphaned_files(self, confirm=False):
        """
        Clean up orphaned files (files on disk not in database)
        
        Args:
            confirm: Must be True to actually delete files
        """
        if not confirm:
            return {'error': 'Must confirm deletion of orphaned files'}
        
        try:
            orphaned_files = self._find_orphaned_files()
            deleted_count = 0
            errors = []
            
            for file_info in orphaned_files:
                try:
                    os.remove(file_info['path'])
                    deleted_count += 1
                except Exception as e:
                    errors.append(f"Failed to delete {file_info['path']}: {str(e)}")
            
            # Log cleanup
            AuditLogger.log_admin_event(
                'admin_cleanup_orphaned_files',
                description=f"Cleaned up {deleted_count} orphaned files. {len(errors)} errors."
            )
            
            return {
                'success': True,
                'deleted_count': deleted_count,
                'total_orphaned': len(orphaned_files),
                'errors': errors
            }
            
        except Exception as e:
            error_msg = f"Error cleaning up orphaned files: {str(e)}"
            current_app.logger.error(error_msg)
            return {'error': error_msg}


# Global scanner instance
integrity_scanner = IntegrityScanner()