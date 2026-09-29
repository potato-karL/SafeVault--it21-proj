"""
Data Export utilities for SafeVault.
Exports admin datasets as PDF reports.
"""
import io
import json
from datetime import datetime, timezone, timedelta
from pathlib import Path

from flask import current_app
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import cm
from reportlab.platypus import (
    SimpleDocTemplate, Table, TableStyle, Paragraph,
    Spacer, HRFlowable
)
from reportlab.lib.enums import TA_CENTER, TA_LEFT

from app import db
from app.models.backup_log import DataExportRequest
from app.utils.audit_logger import AuditLogger


class DataExporter:
    """Handles PDF export operations for SafeVault admin panel."""

    def __init__(self):
        self.export_dir = Path(current_app.config.get('EXPORT_DIRECTORY', 'exports'))
        self.export_dir.mkdir(exist_ok=True)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def create_export(self, export_type, format_type, user_id, filters=None):
        """Create and process a new export request synchronously."""
        # Always PDF — ignore any format_type value passed in
        format_type = 'pdf'

        expires_at = datetime.now(timezone.utc) + timedelta(days=7)
        export_request = DataExportRequest(
            export_type=export_type,
            format_type=format_type,
            status='pending',
            requested_by=user_id,
            expires_at=expires_at,
        )
        if filters:
            if 'date_from' in filters:
                export_request.date_from = filters['date_from']
            if 'date_to' in filters:
                export_request.date_to = filters['date_to']
            if 'user_filter' in filters:
                export_request.user_filter = filters['user_filter']
            if 'additional_filters' in filters:
                export_request.set_filters(filters['additional_filters'])

        db.session.add(export_request)
        db.session.commit()

        try:
            self._process_export(export_request)
            AuditLogger.log_admin_action(
                action='admin_export_create',
                description=f'Data export created: {export_type} (PDF)',
            )
            return export_request

        except Exception as e:
            export_request.status = 'failed'
            export_request.error_message = str(e)
            export_request.processed_at = datetime.now(timezone.utc)
            db.session.commit()
            raise

    def cleanup_expired_exports(self):
        """Remove files and mark expired export records."""
        expired = DataExportRequest.query.filter(
            DataExportRequest.expires_at < datetime.now(timezone.utc),
            DataExportRequest.status == 'completed',
        ).all()

        cleaned, freed = 0, 0
        for exp in expired:
            if exp.file_path:
                p = Path(exp.file_path)
                if p.exists():
                    freed += p.stat().st_size
                    p.unlink()
                    cleaned += 1
            exp.status = 'expired'

        db.session.commit()
        return {'cleaned_count': cleaned, 'freed_space': freed}

    def get_export_statistics(self):
        """Return a simple dict of export stats for the dashboard."""
        total = DataExportRequest.query.count()
        completed = DataExportRequest.query.filter_by(status='completed').count()
        failed = DataExportRequest.query.filter_by(status='failed').count()
        size = db.session.query(
            db.func.coalesce(db.func.sum(DataExportRequest.file_size), 0)
        ).filter_by(status='completed').scalar() or 0

        return {
            'total_exports': total,
            'completed_exports': completed,
            'failed_exports': failed,
            'success_rate': (completed / total * 100) if total else 0,
            'total_size': size,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _process_export(self, export_request):
        export_request.status = 'processing'
        db.session.commit()

        rows, headers, title = self._get_export_data(export_request)

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{export_request.export_type}_{timestamp}.pdf"
        filepath = self.export_dir / filename

        self._render_pdf(filepath, title, headers, rows, export_request)

        export_request.status = 'completed'
        export_request.processed_at = datetime.now(timezone.utc)
        export_request.file_path = str(filepath)
        export_request.file_size = filepath.stat().st_size
        export_request.records_count = len(rows)
        db.session.commit()

    def _get_export_data(self, export_request):
        """Return (rows, column_headers, report_title)."""
        t = export_request.export_type
        if t == 'user_data':
            return self._users(export_request)
        elif t == 'audit_logs':
            return self._audit_logs(export_request)
        elif t == 'activity_logs':
            return self._activity_logs(export_request)
        elif t == 'user_sessions':
            return self._user_sessions(export_request)
        elif t == 'file_metadata':
            return self._file_metadata(export_request)
        elif t == 'system_summary':
            return self._system_summary(export_request)
        else:
            raise ValueError(f"Unknown export type: {t}")

    # -- data collectors -----------------------------------------------

    def _users(self, req):
        from app.models import User, File
        q = User.query
        if req.user_filter:
            q = q.filter(
                db.or_(
                    User.username.ilike(f'%{req.user_filter}%'),
                    User.email.ilike(f'%{req.user_filter}%'),
                )
            )
        if req.date_from:
            q = q.filter(User.created_at >= req.date_from)
        if req.date_to:
            q = q.filter(User.created_at <= req.date_to)

        users = q.order_by(User.created_at.desc()).all()
        headers = ['ID', 'Username', 'Email', 'Role', 'Active', '2FA',
                   'Storage Used', 'Quota (MB)', 'Files', 'Created']
        rows = []
        for u in users:
            files = File.query.filter_by(user_id=u.id).count()
            quota_mb = f"{u.storage_quota_bytes/(1024*1024):.1f}" if u.storage_quota_bytes else 'Unlimited'
            used_mb = f"{(u.current_storage_bytes or 0)/(1024*1024):.2f} MB"
            rows.append([
                str(u.id), u.username, u.email,
                u.role, '✓' if u.is_active_account else '✗',
                '✓' if u.totp_enabled else '✗',
                used_mb, quota_mb, str(files),
                u.created_at.strftime('%Y-%m-%d') if u.created_at else '—',
            ])
        return rows, headers, 'User Data Export'

    def _audit_logs(self, req):
        from app.models import AuditLog, User
        q = AuditLog.query
        if req.date_from:
            q = q.filter(AuditLog.timestamp >= req.date_from)
        if req.date_to:
            q = q.filter(AuditLog.timestamp <= req.date_to)
        if req.user_filter:
            sub = db.session.query(User.id).filter(
                db.or_(
                    User.username.ilike(f'%{req.user_filter}%'),
                    User.email.ilike(f'%{req.user_filter}%'),
                )
            ).subquery()
            q = q.filter(AuditLog.user_id.in_(sub))
        logs = q.order_by(AuditLog.timestamp.desc()).limit(2000).all()
        headers = ['Timestamp', 'User', 'Action', 'Category', 'Level', 'Status', 'IP', 'Description']
        rows = [
            [
                l.timestamp.strftime('%Y-%m-%d %H:%M'),
                l.username or '—',
                l.action, l.category, l.level, l.status,
                l.ip_address or '—',
                (l.description or '')[:80],
            ]
            for l in logs
        ]
        return rows, headers, 'Audit Log Export'

    def _activity_logs(self, req):
        from app.models import ActivityLog, User
        q = ActivityLog.query
        if req.date_from:
            q = q.filter(ActivityLog.timestamp >= req.date_from)
        if req.date_to:
            q = q.filter(ActivityLog.timestamp <= req.date_to)
        if req.user_filter:
            sub = db.session.query(User.id).filter(
                db.or_(
                    User.username.ilike(f'%{req.user_filter}%'),
                    User.email.ilike(f'%{req.user_filter}%'),
                )
            ).subquery()
            q = q.filter(ActivityLog.user_id.in_(sub))
        logs = q.order_by(ActivityLog.timestamp.desc()).limit(2000).all()
        headers = ['Timestamp', 'User', 'Action', 'Status', 'IP', 'Detail']
        rows = [
            [
                l.timestamp.strftime('%Y-%m-%d %H:%M'),
                l.user.username if l.user else '—',
                l.action, l.status or '—',
                l.ip_address or '—',
                (l.detail or '')[:80],
            ]
            for l in logs
        ]
        return rows, headers, 'Activity Log Export'

    def _user_sessions(self, req):
        from app.models import UserSession
        q = UserSession.query
        if req.date_from:
            q = q.filter(UserSession.created_at >= req.date_from)
        if req.date_to:
            q = q.filter(UserSession.created_at <= req.date_to)
        sessions = q.order_by(UserSession.created_at.desc()).limit(2000).all()
        headers = ['User', 'Created', 'Last Activity', 'Expires', 'Active', 'IP', 'Device']
        rows = [
            [
                s.user.username if s.user else '—',
                s.created_at.strftime('%Y-%m-%d %H:%M'),
                s.last_activity.strftime('%Y-%m-%d %H:%M') if s.last_activity else '—',
                s.expires_at.strftime('%Y-%m-%d %H:%M') if s.expires_at else '—',
                '✓' if s.is_active else '✗',
                s.ip_address or '—',
                (s.user_agent or '—')[:50],
            ]
            for s in sessions
        ]
        return rows, headers, 'User Sessions Export'

    def _file_metadata(self, req):
        from app.models import File, User
        q = File.query
        if req.date_from:
            q = q.filter(File.uploaded_at >= req.date_from)
        if req.date_to:
            q = q.filter(File.uploaded_at <= req.date_to)
        if req.user_filter:
            sub = db.session.query(User.id).filter(
                db.or_(
                    User.username.ilike(f'%{req.user_filter}%'),
                    User.email.ilike(f'%{req.user_filter}%'),
                )
            ).subquery()
            q = q.filter(File.user_id.in_(sub))
        files = q.order_by(File.uploaded_at.desc()).limit(2000).all()
        headers = ['Owner', 'Filename', 'Size', 'MIME Type', 'Uploaded', 'Verified']
        rows = [
            [
                f.owner.username if f.owner else '—',
                f.original_filename or f.stored_filename,
                f'{(f.file_size_bytes or 0)/1024:.1f} KB',
                getattr(f, 'mime_type', '—') or '—',
                f.uploaded_at.strftime('%Y-%m-%d %H:%M') if f.uploaded_at else '—',
                '✓' if getattr(f, 'is_verified', False) else '—',
            ]
            for f in files
        ]
        return rows, headers, 'File Metadata Export'

    def _system_summary(self, req):
        from app.models import User, File, ActivityLog, AuditLog
        rows = [
            ['Total Users', str(User.query.count())],
            ['Active Users', str(User.query.filter_by(is_active_account=True).count())],
            ['Admin Users', str(User.query.filter(User.role == 'admin').count())],
            ['Users with 2FA', str(User.query.filter_by(totp_enabled=True).count())],
            ['Total Files', str(File.query.count())],
            ['Total Storage', f"{(db.session.query(db.func.coalesce(db.func.sum(File.file_size_bytes),0)).scalar() or 0)/(1024*1024):.2f} MB"],
            ['Audit Log Entries', str(AuditLog.query.count())],
            ['Activity Log Entries', str(ActivityLog.query.count())],
            ['Report Generated', datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')],
        ]
        headers = ['Metric', 'Value']
        return rows, headers, 'System Summary Report'

    # -- PDF renderer --------------------------------------------------

    def _render_pdf(self, filepath, title, headers, rows, export_request):
        """Generate a styled A4 PDF report."""
        # Landscape for wide tables
        wide_types = {'audit_logs', 'activity_logs', 'user_sessions', 'user_data', 'file_metadata'}
        pagesize = landscape(A4) if export_request.export_type in wide_types else A4

        doc = SimpleDocTemplate(
            str(filepath),
            pagesize=pagesize,
            leftMargin=1.5*cm, rightMargin=1.5*cm,
            topMargin=2*cm, bottomMargin=2*cm,
        )

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle(
            'ReportTitle',
            parent=styles['Heading1'],
            fontSize=16, alignment=TA_CENTER,
            spaceAfter=4,
            textColor=colors.HexColor('#1a202c'),
        )
        sub_style = ParagraphStyle(
            'ReportSub',
            parent=styles['Normal'],
            fontSize=9, alignment=TA_CENTER,
            textColor=colors.HexColor('#718096'),
            spaceAfter=12,
        )
        cell_style = ParagraphStyle(
            'Cell',
            parent=styles['Normal'],
            fontSize=7.5, leading=10,
            wordWrap='LTR',
        )

        story = []

        # Header block
        story.append(Paragraph('SafeVault', ParagraphStyle(
            'Brand', parent=styles['Normal'],
            fontSize=10, textColor=colors.HexColor('#667eea'),
            alignment=TA_CENTER,
        )))
        story.append(Paragraph(title, title_style))
        filters_desc = []
        if export_request.date_from:
            filters_desc.append(f"From: {export_request.date_from.strftime('%Y-%m-%d')}")
        if export_request.date_to:
            filters_desc.append(f"To: {export_request.date_to.strftime('%Y-%m-%d')}")
        if export_request.user_filter:
            filters_desc.append(f"User filter: {export_request.user_filter}")
        filters_desc.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M UTC')}")
        story.append(Paragraph(' · '.join(filters_desc), sub_style))
        story.append(HRFlowable(width='100%', thickness=1, color=colors.HexColor('#e2e8f0')))
        story.append(Spacer(1, 0.4*cm))

        if not rows:
            story.append(Paragraph('No records found for the selected filters.', styles['Normal']))
        else:
            # Wrap header cells
            header_cells = [Paragraph(f'<b>{h}</b>', cell_style) for h in headers]

            # Wrap data cells
            data_cells = []
            for row in rows:
                data_cells.append([
                    Paragraph(str(cell) if cell is not None else '—', cell_style)
                    for cell in row
                ])

            table_data = [header_cells] + data_cells

            # Distribute column widths evenly
            avail_w = pagesize[0] - 3*cm   # total minus margins
            col_w = avail_w / len(headers)
            col_widths = [col_w] * len(headers)

            tbl = Table(table_data, colWidths=col_widths, repeatRows=1)
            tbl.setStyle(TableStyle([
                # Header row
                ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#667eea')),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.white),
                ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                ('FONTSIZE', (0, 0), (-1, 0), 8),
                ('BOTTOMPADDING', (0, 0), (-1, 0), 6),
                ('TOPPADDING', (0, 0), (-1, 0), 6),
                # Alternating rows
                ('ROWBACKGROUNDS', (0, 1), (-1, -1), [colors.white, colors.HexColor('#f7fafc')]),
                # Grid
                ('GRID', (0, 0), (-1, -1), 0.4, colors.HexColor('#e2e8f0')),
                # Alignment
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('ALIGN', (0, 0), (-1, 0), 'CENTER'),
                # Padding
                ('TOPPADDING', (0, 1), (-1, -1), 3),
                ('BOTTOMPADDING', (0, 1), (-1, -1), 3),
                ('LEFTPADDING', (0, 0), (-1, -1), 4),
                ('RIGHTPADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(tbl)

        story.append(Spacer(1, 0.5*cm))
        story.append(HRFlowable(width='100%', thickness=0.5, color=colors.HexColor('#e2e8f0')))
        story.append(Paragraph(
            f'SafeVault Admin — {export_request.export_type.replace("_"," ").title()} — '
            f'{len(rows)} record(s) — Confidential',
            ParagraphStyle('Footer', parent=styles['Normal'],
                           fontSize=7, textColor=colors.HexColor('#a0aec0'),
                           alignment=TA_CENTER, spaceBefore=4),
        ))

        doc.build(story)
