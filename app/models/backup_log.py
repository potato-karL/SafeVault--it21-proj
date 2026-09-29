"""
Backup Log Model for tracking backup operations and status.
"""
from datetime import datetime, timezone
from app import db
import json

class BackupLog(db.Model):
    """Track backup operations and their status."""
    __tablename__ = 'backup_logs'
    
    id = db.Column(db.Integer, primary_key=True)
    backup_type = db.Column(db.String(50), nullable=False)  # 'full', 'incremental', 'files_only', 'database_only'
    status = db.Column(db.String(20), nullable=False)  # 'in_progress', 'completed', 'failed'
    started_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    completed_at = db.Column(db.DateTime)
    file_path = db.Column(db.String(500))
    file_size = db.Column(db.BigInteger)  # Size in bytes
    checksum = db.Column(db.String(128))  # SHA-256 checksum
    error_message = db.Column(db.Text)
    
    # Backup details
    items_count = db.Column(db.Integer, default=0)
    compressed_size = db.Column(db.BigInteger)
    compression_ratio = db.Column(db.Float)
    
    # Metadata
    initiated_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    backup_metadata = db.Column(db.Text)  # JSON string with additional details
    
    # Relationships
    user = db.relationship('User', backref='initiated_backups')
    
    def __repr__(self):
        return f'<BackupLog {self.id}: {self.backup_type} - {self.status}>'
    
    @property
    def duration(self):
        """Calculate backup duration."""
        if self.completed_at and self.started_at:
            return self.completed_at - self.started_at
        elif self.started_at:
            # Use naive datetime to match SQLite storage (no timezone info)
            now = datetime.utcnow()
            started = self.started_at.replace(tzinfo=None) if self.started_at.tzinfo else self.started_at
            return now - started
        return None
    
    @property
    def metadata_dict(self):
        """Parse backup metadata as dictionary."""
        if self.backup_metadata:
            try:
                return json.loads(self.backup_metadata)
            except json.JSONDecodeError:
                return {}
        return {}
    
    def set_metadata(self, metadata_dict):
        """Set backup metadata from dictionary."""
        self.backup_metadata = json.dumps(metadata_dict)
    
    def mark_completed(self, file_path, file_size, checksum, items_count=0):
        """Mark backup as completed with details."""
        self.status = 'completed'
        self.completed_at = datetime.now(timezone.utc)
        self.file_path = file_path
        self.file_size = file_size
        self.checksum = checksum
        self.items_count = items_count
        
        # Calculate compression ratio if compressed size is available
        if self.compressed_size and file_size > 0:
            self.compression_ratio = (file_size - self.compressed_size) / file_size * 100
    
    def mark_failed(self, error_message):
        """Mark backup as failed with error message."""
        self.status = 'failed'
        self.completed_at = datetime.now(timezone.utc)
        self.error_message = error_message

class DataExportRequest(db.Model):
    """Track data export requests and their status."""
    __tablename__ = 'data_export_requests'
    
    id = db.Column(db.Integer, primary_key=True)
    export_type = db.Column(db.String(50), nullable=False)  # 'user_data', 'audit_logs', 'system_logs', 'custom'
    format_type = db.Column(db.String(20), nullable=False)  # 'json', 'csv', 'xlsx', 'xml'
    status = db.Column(db.String(20), nullable=False, default='pending')  # 'pending', 'processing', 'completed', 'failed'
    
    # Request details
    requested_at = db.Column(db.DateTime, nullable=False, default=lambda: datetime.now(timezone.utc))
    processed_at = db.Column(db.DateTime)
    expires_at = db.Column(db.DateTime)  # When the export file expires
    
    # Filters and parameters
    date_from = db.Column(db.DateTime)
    date_to = db.Column(db.DateTime)
    user_filter = db.Column(db.String(200))  # Username or user ID filter
    additional_filters = db.Column(db.Text)  # JSON string with additional filters
    
    # Results
    file_path = db.Column(db.String(500))
    file_size = db.Column(db.BigInteger)
    records_count = db.Column(db.Integer, default=0)
    error_message = db.Column(db.Text)
    
    # Request metadata
    requested_by = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    download_count = db.Column(db.Integer, default=0)
    
    # Relationships
    user = db.relationship('User', backref='export_requests')
    
    def __repr__(self):
        return f'<DataExportRequest {self.id}: {self.export_type} - {self.status}>'
    
    @property
    def is_expired(self):
        """Check if export has expired."""
        if not self.expires_at:
            return False
        # Use naive datetime to match SQLite storage (no timezone info)
        now = datetime.utcnow()
        expires = self.expires_at.replace(tzinfo=None) if self.expires_at.tzinfo else self.expires_at
        return now > expires
    
    @property
    def filters_dict(self):
        """Parse additional filters as dictionary."""
        if self.additional_filters:
            try:
                return json.loads(self.additional_filters)
            except json.JSONDecodeError:
                return {}
        return {}
    
    def set_filters(self, filters_dict):
        """Set additional filters from dictionary."""
        self.additional_filters = json.dumps(filters_dict)