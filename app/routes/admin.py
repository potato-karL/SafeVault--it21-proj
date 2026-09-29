from flask import Blueprint, render_template, redirect, url_for, flash, request, abort, current_app, jsonify, make_response
from flask_login import login_required, current_user
from sqlalchemy import func
from datetime import datetime, timedelta, timezone
from pathlib import Path

from app import db
from app.utils.decorators import admin_required
from app.models.user import User
from app.models.file import File
from app.models.activity_log import ActivityLog
from app.models.ip_blocklist import IPBlocklist
from app.utils.audit_logger import AuditLogger
from app.utils.audit_export import AuditExporter
from app.utils.integrity_scanner import integrity_scanner
from app.models.system_health import SystemHealthMetric, SystemAlert
from app.utils.backup_manager import BackupManager
from app.utils.data_exporter import DataExporter
from app.models.backup_log import BackupLog, DataExportRequest

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


@admin_bp.route("/")
@login_required
@admin_required
def dashboard():
    from datetime import datetime, timedelta
    from sqlalchemy import func
    
    total_users = User.query.count()
    active_users = User.query.filter_by(is_active_account=True).count()
    total_files = File.query.count()
    failed_logins = ActivityLog.query.filter_by(action="login", status="fail").count()
    total_downloads = ActivityLog.query.filter_by(action="download", status="success").count()
    total_storage = db.session.query(db.func.sum(File.file_size_bytes)).scalar() or 0

    # New security metrics
    blocked_ips_count = IPBlocklist.query.count()
    
    # Get activity data for the last 7 days
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    last_24h = datetime.utcnow() - timedelta(hours=24)
    
    # Security events in last 24h
    recent_ip_bans = IPBlocklist.query.filter(IPBlocklist.blocked_at >= last_24h).count()
    blocked_attempts_24h = ActivityLog.query.filter(
        ActivityLog.action == "access_blocked",
        ActivityLog.timestamp >= last_24h
    ).count()
    
    # Storage quota metrics
    users_with_quota = User.query.filter(User.storage_quota_bytes.isnot(None)).count()
    users_near_quota = 0
    users_over_quota = 0
    
    if users_with_quota > 0:
        # Users near quota (>80%)
        users_near_quota = User.query.filter(
            User.storage_quota_bytes.isnot(None),
            User.storage_quota_bytes > 0,
            User.current_storage_bytes > User.storage_quota_bytes * 0.8
        ).count()
        
        # Users over quota
        users_over_quota = User.query.filter(
            User.storage_quota_bytes.isnot(None),
            User.storage_quota_bytes > 0,
            User.current_storage_bytes > User.storage_quota_bytes
        ).count()

    stats = {
        "total_users": total_users,
        "active_users": active_users,
        "deactivated_users": total_users - active_users,
        "total_files": total_files,
        "failed_logins": failed_logins,
        "total_downloads": total_downloads,
        "total_storage": total_storage,
        # Security metrics
        "blocked_ips_count": blocked_ips_count,
        "recent_ip_bans": recent_ip_bans,
        "blocked_attempts_24h": blocked_attempts_24h,
        # Storage metrics
        "users_with_quota": users_with_quota,
        "users_near_quota": users_near_quota,
        "users_over_quota": users_over_quota,
    }

    # Get activity data for the last 7 days
    seven_days_ago = datetime.utcnow() - timedelta(days=7)
    
    # Activity by day for the last 7 days
    daily_activity = db.session.query(
        func.date(ActivityLog.timestamp).label('date'),
        func.count(ActivityLog.id).label('count')
    ).filter(
        ActivityLog.timestamp >= seven_days_ago
    ).group_by(
        func.date(ActivityLog.timestamp)
    ).order_by('date').all()
    
    # Activity by action type
    activity_by_action = db.session.query(
        ActivityLog.action,
        func.count(ActivityLog.id).label('count')
    ).group_by(ActivityLog.action).all()
    
    # Success vs Fail ratio
    success_fail = db.session.query(
        ActivityLog.status,
        func.count(ActivityLog.id).label('count')
    ).group_by(ActivityLog.status).all()
    
    # Recent activity (last 5 for quick view)
    recent_activity = (
        ActivityLog.query.order_by(ActivityLog.timestamp.desc()).limit(5).all()
    )

    # Suspicious IPs - IPs with most failed login attempts
    suspicious_ips = db.session.query(
        ActivityLog.ip_address,
        func.count(ActivityLog.id).label('fail_count')
    ).filter(
        ActivityLog.action == "login",
        ActivityLog.status == "fail",
        ActivityLog.ip_address.isnot(None)
    ).group_by(ActivityLog.ip_address).order_by(func.count(ActivityLog.id).desc()).limit(5).all()

    # Prepare chart data
    # Fill in missing days with 0 counts
    chart_dates = []
    chart_counts = []
    for i in range(7):
        date = (datetime.utcnow() - timedelta(days=6-i)).date()
        chart_dates.append(date.strftime("%m/%d"))
        # Find count for this date
        count = 0
        for activity_date, activity_count in daily_activity:
            if activity_date == date:
                count = activity_count
                break
        chart_counts.append(count)
    
    # Action distribution
    action_labels = []
    action_counts = []
    for action, count in activity_by_action:
        action_labels.append(action.capitalize())
        action_counts.append(count)
    
    # Success/Fail distribution
    success_count = 0
    fail_count = 0
    for status, count in success_fail:
        if status == "success":
            success_count = count
        else:
            fail_count = count

    chart_data = {
        "daily_dates": chart_dates,
        "daily_counts": chart_counts,
        "action_labels": action_labels,
        "action_counts": action_counts,
        "success_count": success_count,
        "fail_count": fail_count
    }

    return render_template(
        "admin/dashboard.html", 
        stats=stats, 
        recent_activity=recent_activity, 
        chart_data=chart_data,
        suspicious_ips=suspicious_ips
    )



@admin_bp.route("/users")
@login_required
@admin_required
def users():
    all_users = User.query.order_by(User.created_at.desc()).all()
    # Precompute file counts so the template doesn't run N+1 queries.
    file_counts = dict(
        db.session.query(File.user_id, db.func.count(File.id))
        .group_by(File.user_id)
        .all()
    )
    return render_template("admin/users.html", users=all_users, file_counts=file_counts)


@admin_bp.route("/users/<int:user_id>/toggle-active", methods=["POST"])
@login_required
@admin_required
def toggle_active(user_id):
    user = User.query.get(user_id)
    if user is None:
        abort(404)

    # Prevent an admin from locking themselves out — a common real-world
    # footgun in admin panels.
    if user.id == current_user.id:
        flash("You can't deactivate your own account.", "warning")
        return redirect(url_for("admin.users"))

    user.is_active_account = not user.is_active_account
    db.session.commit()

    status = "reactivated" if user.is_active_account else "deactivated"

    # Audit log
    AuditLogger.log_admin_action(
        action='admin_user_enable' if user.is_active_account else 'admin_user_disable',
        target_user_id=user.id,
        target_username=user.username,
        description=f'Admin {current_user.username} {status} account "{user.username}"',
        level='warning',
    )

    flash(f'Account "{user.username}" was {status}.', "info")
    return redirect(url_for("admin.users"))


@admin_bp.route("/users/<int:user_id>/unlock", methods=["POST"])
@login_required
@admin_required
def unlock_user(user_id):
    user = User.query.get(user_id)
    if user is None:
        abort(404)

    user.reset_failed_logins()
    db.session.commit()

    AuditLogger.log_admin_action(
        action='admin_user_unlock',
        target_user_id=user.id,
        target_username=user.username,
        description=f'Admin {current_user.username} unlocked account "{user.username}"',
    )

    flash(f'Account "{user.username}" was unlocked successfully.', "success")
    return redirect(url_for("admin.users"))



@admin_bp.route("/users/<int:user_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete_user(user_id):
    import os
    from flask import current_app

    user = User.query.get(user_id)
    if user is None:
        abort(404)

    if user.id == current_user.id:
        flash("You can't delete your own account.", "warning")
        return redirect(url_for("admin.users"))

    if user.is_admin:
        flash("Admin accounts can't be deleted from here. Demote the account first.", "warning")
        return redirect(url_for("admin.users"))

    # Remove the user's encrypted files from disk before the DB cascade
    # deletes their File rows (cascade="all, delete-orphan" on User.files
    # handles the DB rows, but it doesn't know about files on disk).
    for file_row in user.files:
        upload_dir = current_app.config["UPLOAD_FOLDER"]
        disk_path = os.path.join(upload_dir, file_row.stored_filename)
        if os.path.exists(disk_path):
            os.remove(disk_path)

    username = user.username
    db.session.delete(user)  # cascades to files + activity_logs
    db.session.commit()

    AuditLogger.log_admin_action(
        action='admin_user_delete',
        description=f'Admin {current_user.username} permanently deleted account "{username}"',
        level='warning',
    )

    flash(f'Account "{username}" and all associated files were permanently deleted.', "info")
    return redirect(url_for("admin.users"))


@admin_bp.route("/logs")
@login_required
@admin_required
def logs():
    page = request.args.get("page", 1, type=int)
    action_filter = request.args.get("action", "")
    status_filter = request.args.get("status", "")

    query = ActivityLog.query
    if action_filter:
        query = query.filter_by(action=action_filter)
    if status_filter:
        query = query.filter_by(status=status_filter)

    pagination = query.order_by(ActivityLog.timestamp.desc()).paginate(
        page=page, per_page=10, error_out=False
    )

    return render_template(
        "admin/logs.html",
        pagination=pagination,
        action_filter=action_filter,
        status_filter=status_filter,
    )


@admin_bp.route("/security")
@login_required
@admin_required
def security_center():
    """Security Center dashboard showing IP blocks and security metrics."""
    # Get blocked IPs
    blocked_ips = IPBlocklist.get_blocked_ips(include_expired=False)
    total_blocked = len(blocked_ips)
    
    # Get recent security events
    from datetime import datetime, timezone, timedelta
    last_24h = datetime.now(timezone.utc) - timedelta(hours=24)
    
    recent_bans = IPBlocklist.query.filter(
        IPBlocklist.blocked_at >= last_24h
    ).count()
    
    failed_logins_24h = ActivityLog.query.filter(
        ActivityLog.action == "login",
        ActivityLog.status == "fail",
        ActivityLog.timestamp >= last_24h
    ).count()
    
    blocked_attempts_24h = ActivityLog.query.filter(
        ActivityLog.action == "access_blocked",
        ActivityLog.timestamp >= last_24h
    ).count()
    
    # Top suspicious IPs (most failed attempts)
    suspicious_ips = db.session.query(
        ActivityLog.ip_address,
        func.count(ActivityLog.id).label('fail_count')
    ).filter(
        ActivityLog.action == "login",
        ActivityLog.status == "fail",
        ActivityLog.ip_address.isnot(None),
        ActivityLog.timestamp >= last_24h
    ).group_by(ActivityLog.ip_address).order_by(func.count(ActivityLog.id).desc()).limit(10).all()
    
    stats = {
        'total_blocked': total_blocked,
        'recent_bans': recent_bans,
        'failed_logins_24h': failed_logins_24h,
        'blocked_attempts_24h': blocked_attempts_24h
    }
    
    return render_template(
        "admin/security.html",
        stats=stats,
        blocked_ips=blocked_ips,
        suspicious_ips=suspicious_ips
    )


@admin_bp.route("/security/ip-blocklist")
@login_required
@admin_required
def ip_blocklist():
    """View and manage IP blocklist."""
    page = request.args.get("page", 1, type=int)
    show_expired = request.args.get("show_expired", False, type=bool)
    
    # Get blocked IPs with pagination
    if show_expired:
        query = IPBlocklist.query
    else:
        from datetime import datetime, timezone
        now = datetime.now(timezone.utc)
        query = IPBlocklist.query.filter(
            db.or_(
                IPBlocklist.blocked_until.is_(None),  # Permanent bans
                IPBlocklist.blocked_until > now       # Active temporary bans
            )
        )
    
    pagination = query.order_by(IPBlocklist.blocked_at.desc()).paginate(
        page=page, per_page=20, error_out=False
    )
    
    return render_template(
        "admin/ip_blocklist.html",
        pagination=pagination,
        show_expired=show_expired
    )


@admin_bp.route("/security/block-ip", methods=["POST"])
@login_required
@admin_required
def block_ip():
    """Manually block an IP address."""
    ip_address = request.form.get("ip_address", "").strip()
    reason = request.form.get("reason", "Manually blocked by admin").strip()
    duration_hours = request.form.get("duration_hours", type=int)
    
    if not ip_address:
        flash("IP address is required.", "error")
        return redirect(url_for("admin.ip_blocklist"))
    
    # Validate IP format (basic check)
    import re
    ipv4_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
    ipv6_pattern = r'^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
    
    if not (re.match(ipv4_pattern, ip_address) or re.match(ipv6_pattern, ip_address)):
        flash("Invalid IP address format.", "error")
        return redirect(url_for("admin.ip_blocklist"))
    
    # Check if already blocked
    if IPBlocklist.is_ip_blocked(ip_address):
        flash(f"IP address {ip_address} is already blocked.", "warning")
        return redirect(url_for("admin.ip_blocklist"))
    
    # Convert hours to minutes for consistency with auto-ban logic
    duration_minutes = duration_hours * 60 if duration_hours else None
    
    try:
        IPBlocklist.block_ip(
            ip_address=ip_address,
            reason=reason,
            is_automatic=False,
            duration_minutes=duration_minutes,
            blocked_by_user_id=current_user.id
        )
        
        # Log the manual ban
        ActivityLog.record(
            user_id=current_user.id,
            action="ip_manual_ban",
            status="success",
            detail=f"Manually banned {ip_address}: {reason}",
            ip_address=request.remote_addr
        )
        AuditLogger.log_security_event(
            action='admin_ip_block',
            description=f'Admin {current_user.username} blocked IP {ip_address}: {reason}',
            level='warning',
        )
        
        duration_str = f"for {duration_hours} hours" if duration_hours else "permanently"
        flash(f"IP address {ip_address} has been blocked {duration_str}.", "success")
        
    except Exception as e:
        flash(f"Failed to block IP address: {str(e)}", "error")
    
    return redirect(url_for("admin.ip_blocklist"))


@admin_bp.route("/security/unblock-ip/<int:block_id>", methods=["POST"])
@login_required
@admin_required
def unblock_ip(block_id):
    """Unblock an IP address."""
    blocked_ip = IPBlocklist.query.get_or_404(block_id)
    ip_address = blocked_ip.ip_address
    
    try:
        if IPBlocklist.unblock_ip(ip_address, unblocked_by_user_id=current_user.id):
            # Log the unblock action
            ActivityLog.record(
                user_id=current_user.id,
                action="ip_unblock",
                status="success",
                detail=f"Manually unblocked {ip_address}",
                ip_address=request.remote_addr
            )
            AuditLogger.log_security_event(
                action='admin_ip_unblock',
                description=f'Admin {current_user.username} unblocked IP {ip_address}',
                level='warning',
            )
            flash(f"IP address {ip_address} has been unblocked.", "success")
        else:
            flash(f"IP address {ip_address} was not found in the blocklist.", "warning")
            
    except Exception as e:
        flash(f"Failed to unblock IP address: {str(e)}", "error")
    
    return redirect(url_for("admin.ip_blocklist"))


@admin_bp.route("/security/cleanup-expired", methods=["POST"])
@login_required
@admin_required
def cleanup_expired_blocks():
    """Clean up expired IP blocks."""
    try:
        count = IPBlocklist.cleanup_expired_blocks()
        
        ActivityLog.record(
            user_id=current_user.id,
            action="ip_cleanup",
            status="success",
            detail=f"Cleaned up {count} expired IP blocks",
            ip_address=request.remote_addr
        )
        
        if count > 0:
            flash(f"Cleaned up {count} expired IP blocks.", "success")
        else:
            flash("No expired IP blocks found to clean up.", "info")
            
    except Exception as e:
        flash(f"Failed to clean up expired blocks: {str(e)}", "error")
    
    return redirect(url_for("admin.ip_blocklist"))


@admin_bp.route("/storage")
@login_required
@admin_required
def storage_management():
    """Storage quota management dashboard."""
    # Get storage statistics
    total_users = User.query.count()
    users_with_quota = User.query.filter(User.storage_quota_bytes.isnot(None)).count()
    
    # Calculate total storage usage
    total_storage_used = db.session.query(
        func.coalesce(func.sum(User.current_storage_bytes), 0)
    ).scalar()
    
    # Users approaching quota limits (>80%)
    users_near_limit = []
    if users_with_quota > 0:
        users_near_limit = User.query.filter(
            User.storage_quota_bytes.isnot(None),
            User.storage_quota_bytes > 0,
            User.current_storage_bytes > User.storage_quota_bytes * 0.8
        ).all()
    
    # Users over quota (shouldn't happen with proper enforcement, but good to check)
    users_over_quota = []
    if users_with_quota > 0:
        users_over_quota = User.query.filter(
            User.storage_quota_bytes.isnot(None),
            User.storage_quota_bytes > 0,
            User.current_storage_bytes > User.storage_quota_bytes
        ).all()
    
    # Recent quota changes
    from datetime import datetime, timezone, timedelta
    last_24h = datetime.now(timezone.utc) - timedelta(hours=24)
    recent_quota_changes = ActivityLog.query.filter(
        ActivityLog.action == "quota_update",
        ActivityLog.timestamp >= last_24h
    ).order_by(ActivityLog.timestamp.desc()).limit(10).all()
    
    stats = {
        'total_users': total_users,
        'users_with_quota': users_with_quota,
        'users_without_quota': total_users - users_with_quota,
        'total_storage_used_mb': total_storage_used / (1024 * 1024),
        'users_near_limit_count': len(users_near_limit),
        'users_over_quota_count': len(users_over_quota)
    }
    
    return render_template(
        "admin/storage.html",
        stats=stats,
        users_near_limit=users_near_limit,
        users_over_quota=users_over_quota,
        recent_quota_changes=recent_quota_changes
    )


@admin_bp.route("/storage/users")
@login_required
@admin_required
def storage_users():
    """View users with storage quota details."""
    page = request.args.get("page", 1, type=int)
    sort_by = request.args.get("sort", "usage_percent")  # usage_percent, quota, used, username
    
    # Base query
    query = User.query
    
    # Apply sorting
    if sort_by == "quota":
        query = query.order_by(User.storage_quota_bytes.desc().nullslast())
    elif sort_by == "used":
        query = query.order_by(User.current_storage_bytes.desc())
    elif sort_by == "username":
        query = query.order_by(User.username.asc())
    else:  # usage_percent - need to calculate in Python due to SQLite limitations
        users_list = query.all()
        users_list.sort(key=lambda u: u.get_storage_usage_percent() or 0, reverse=True)
        
        # Manual pagination for sorted list
        per_page = 20
        total = len(users_list)
        start = (page - 1) * per_page
        end = start + per_page
        users_page = users_list[start:end]
        
        # Create a simple pagination-like object
        class SimplePagination:
            def __init__(self, items, page, per_page, total):
                self.items = items
                self.page = page
                self.per_page = per_page
                self.total = total
                self.pages = (total + per_page - 1) // per_page
                self.has_prev = page > 1
                self.has_next = page < self.pages
                self.prev_num = page - 1 if self.has_prev else None
                self.next_num = page + 1 if self.has_next else None
        
        pagination = SimplePagination(users_page, page, per_page, total)
        
        return render_template(
            "admin/storage_users.html",
            pagination=pagination,
            sort_by=sort_by
        )
    
    # Standard SQLAlchemy pagination for other sorts
    pagination = query.paginate(page=page, per_page=20, error_out=False)
    
    return render_template(
        "admin/storage_users.html",
        pagination=pagination,
        sort_by=sort_by
    )


@admin_bp.route("/storage/set-quota/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def set_user_quota(user_id):
    """Set storage quota for a user."""
    user = User.query.get_or_404(user_id)
    quota_mb = request.form.get("quota_mb", type=float)
    
    if quota_mb is not None and quota_mb < 0:
        flash("Quota cannot be negative.", "error")
        return redirect(request.referrer or url_for("admin.storage_users"))
    
    try:
        old_quota = user.get_storage_quota_mb()
        user.set_storage_quota(quota_mb, updated_by_admin_id=current_user.id)
        db.session.commit()
        
        if quota_mb is None:
            quota_str = "unlimited"
        else:
            quota_str = f"{quota_mb}MB"
        
        old_quota_str = f"{old_quota}MB" if old_quota else "unlimited"

        AuditLogger.log_admin_action(
            action='admin_quota_change',
            target_user_id=user.id,
            target_username=user.username,
            description=(
                f'Admin {current_user.username} changed quota for "{user.username}" '
                f'from {old_quota_str} to {quota_str}'
            ),
        )

        flash(
            f"Storage quota for {user.username} updated from {old_quota_str} to {quota_str}.",
            "success"
        )
        
    except Exception as e:
        flash(f"Failed to update quota: {str(e)}", "error")
    
    return redirect(request.referrer or url_for("admin.storage_users"))


@admin_bp.route("/storage/recalculate/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def recalculate_user_storage(user_id):
    """Recalculate storage usage for a user."""
    user = User.query.get_or_404(user_id)
    
    try:
        old_usage = user.current_storage_bytes
        user.update_storage_usage()
        new_usage = user.current_storage_bytes
        
        ActivityLog.record(
            user_id=current_user.id,
            action="storage_recalculate",
            status="success",
            detail=f"Recalculated storage for {user.username}: {old_usage} -> {new_usage} bytes",
            ip_address=request.remote_addr
        )
        
        old_mb = old_usage / (1024 * 1024)
        new_mb = new_usage / (1024 * 1024)
        
        flash(
            f"Storage recalculated for {user.username}: {old_mb:.1f}MB → {new_mb:.1f}MB",
            "success"
        )
        
    except Exception as e:
        flash(f"Failed to recalculate storage: {str(e)}", "error")
    
    return redirect(request.referrer or url_for("admin.storage_users"))


@admin_bp.route("/storage/bulk-quota", methods=["POST"])
@login_required
@admin_required  
def set_bulk_quota():
    """Set quota for multiple users or all users without quota."""
    quota_mb = request.form.get("quota_mb", type=float)
    apply_to = request.form.get("apply_to", "no_quota")  # "no_quota", "all", "selected"
    
    if quota_mb is not None and quota_mb < 0:
        flash("Quota cannot be negative.", "error")
        return redirect(url_for("admin.storage_management"))
    
    try:
        count = 0
        
        if apply_to == "no_quota":
            # Apply to users without quota
            users = User.query.filter(User.storage_quota_bytes.is_(None)).all()
        elif apply_to == "all":
            # Apply to all users
            users = User.query.all()
        else:
            flash("Invalid bulk operation type.", "error")
            return redirect(url_for("admin.storage_management"))
        
        for user in users:
            user.set_storage_quota(quota_mb, updated_by_admin_id=current_user.id)
            count += 1
        
        db.session.commit()
        
        quota_str = f"{quota_mb}MB" if quota_mb is not None else "unlimited"
        flash(f"Set quota to {quota_str} for {count} users.", "success")

        AuditLogger.log_admin_action(
            action='admin_bulk_quota_change',
            description=(
                f'Admin {current_user.username} bulk-set quota to {quota_str} '
                f'for {count} users (scope: {apply_to})'
            ),
        )
        
    except Exception as e:
        db.session.rollback()
        flash(f"Failed to set bulk quota: {str(e)}", "error")
    
    return redirect(url_for("admin.storage_management"))


# =============================================================================
# Phase 2 Operational Features
# =============================================================================

@admin_bp.route("/audit-export")
@login_required
@admin_required
def audit_export():
    """Audit log export interface"""
    return render_template("admin/audit_export.html")

@admin_bp.route("/audit-export/csv", methods=["POST"])
@login_required
@admin_required
def export_audit_csv():
    """Export audit logs to CSV"""
    try:
        # Get filters from form
        filters = {}
        
        if request.form.get('start_date'):
            filters['start_date'] = datetime.strptime(request.form['start_date'], '%Y-%m-%d')
        
        if request.form.get('end_date'):
            filters['end_date'] = datetime.strptime(request.form['end_date'], '%Y-%m-%d')
        
        if request.form.get('user_id'):
            filters['user_id'] = int(request.form['user_id'])
        
        if request.form.get('action'):
            filters['action'] = request.form['action']
        
        if request.form.get('category'):
            filters['category'] = request.form['category']
        
        if request.form.get('level'):
            filters['level'] = request.form['level']
        
        include_legacy = request.form.get('include_legacy') == 'on'
        
        # Export to CSV
        csv_content, filename = AuditExporter.export_to_csv(filters, include_legacy)
        
        # Create response
        response = make_response(csv_content)
        response.headers['Content-Type'] = 'text/csv'
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        return response
        
    except Exception as e:
        current_app.logger.error(f"Error exporting audit CSV: {e}")
        flash("Error exporting audit logs to CSV.", "danger")
        return redirect(url_for("admin.audit_export"))

@admin_bp.route("/audit-export/json", methods=["POST"])
@login_required
@admin_required
def export_audit_json():
    """Export audit logs to JSON"""
    try:
        # Get filters from form (same as CSV)
        filters = {}
        
        if request.form.get('start_date'):
            filters['start_date'] = datetime.strptime(request.form['start_date'], '%Y-%m-%d')
        
        if request.form.get('end_date'):
            filters['end_date'] = datetime.strptime(request.form['end_date'], '%Y-%m-%d')
        
        if request.form.get('user_id'):
            filters['user_id'] = int(request.form['user_id'])
        
        if request.form.get('action'):
            filters['action'] = request.form['action']
        
        if request.form.get('category'):
            filters['category'] = request.form['category']
        
        if request.form.get('level'):
            filters['level'] = request.form['level']
        
        include_legacy = request.form.get('include_legacy') == 'on'
        
        # Export to JSON
        json_content, filename = AuditExporter.export_to_json(filters, include_legacy)
        
        # Create response
        response = make_response(json_content)
        response.headers['Content-Type'] = 'application/json'
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        return response
        
    except Exception as e:
        current_app.logger.error(f"Error exporting audit JSON: {e}")
        flash("Error exporting audit logs to JSON.", "danger")
        return redirect(url_for("admin.audit_export"))

@admin_bp.route("/audit-export/comprehensive", methods=["POST"])
@login_required
@admin_required
def export_audit_comprehensive():
    """Export comprehensive audit archive"""
    try:
        # Get filters from form
        filters = {}
        
        if request.form.get('start_date'):
            filters['start_date'] = datetime.strptime(request.form['start_date'], '%Y-%m-%d')
        
        if request.form.get('end_date'):
            filters['end_date'] = datetime.strptime(request.form['end_date'], '%Y-%m-%d')
        
        if request.form.get('user_id'):
            filters['user_id'] = int(request.form['user_id'])
        
        # Export comprehensive archive
        zip_content, filename = AuditExporter.export_comprehensive_archive(filters)
        
        # Create response
        response = make_response(zip_content)
        response.headers['Content-Type'] = 'application/zip'
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        return response
        
    except Exception as e:
        current_app.logger.error(f"Error exporting comprehensive audit archive: {e}")
        flash("Error exporting comprehensive audit archive.", "danger")
        return redirect(url_for("admin.audit_export"))

@admin_bp.route("/integrity-scanner")
@login_required
@admin_required
def integrity_scanner_interface():
    """Disk integrity scanner interface"""
    # Get latest scan results if any
    latest_results = None
    if hasattr(integrity_scanner, 'scan_results') and integrity_scanner.scan_results:
        # Get most recent scan
        scan_ids = list(integrity_scanner.scan_results.keys())
        if scan_ids:
            latest_scan_id = max(scan_ids)  # Most recent by ID
            latest_results = integrity_scanner.scan_results[latest_scan_id]
    
    return render_template("admin/integrity_scanner.html", 
                         scan_active=integrity_scanner.scan_active,
                         latest_results=latest_results)

@admin_bp.route("/integrity-scanner/start", methods=["POST"])
@login_required
@admin_required
def start_integrity_scan():
    """Start a full integrity scan"""
    try:
        if integrity_scanner.scan_active:
            flash("Integrity scan is already running.", "warning")
            return redirect(url_for("admin.integrity_scanner_interface"))
        
        # Start scan in background
        result = integrity_scanner.start_full_scan(background=True)
        
        if 'error' in result:
            flash(f"Failed to start integrity scan: {result['error']}", "danger")
        else:
            flash("Integrity scan started successfully. Check back for results.", "success")
        
        return redirect(url_for("admin.integrity_scanner_interface"))
        
    except Exception as e:
        current_app.logger.error(f"Error starting integrity scan: {e}")
        flash("Error starting integrity scan.", "danger")
        return redirect(url_for("admin.integrity_scanner_interface"))

@admin_bp.route("/integrity-scanner/cancel", methods=["POST"])
@login_required
@admin_required
def cancel_integrity_scan():
    """Cancel active integrity scan"""
    try:
        if integrity_scanner.cancel_scan():
            flash("Integrity scan cancelled successfully.", "success")
        else:
            flash("No active scan to cancel.", "warning")
        
        return redirect(url_for("admin.integrity_scanner_interface"))
        
    except Exception as e:
        current_app.logger.error(f"Error cancelling integrity scan: {e}")
        flash("Error cancelling integrity scan.", "danger")
        return redirect(url_for("admin.integrity_scanner_interface"))

@admin_bp.route("/integrity-scanner/status/<scan_id>")
@login_required
@admin_required
def get_scan_status(scan_id):
    """Get scan status as JSON"""
    try:
        status = integrity_scanner.get_scan_status(scan_id)
        return jsonify(status)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@admin_bp.route("/integrity-scanner/check-file/<int:file_id>", methods=["POST"])
@login_required
@admin_required
def check_single_file(file_id):
    """Check integrity of a single file"""
    try:
        result = integrity_scanner.quick_check_file(file_id)
        
        if 'error' in result:
            flash(f"Error checking file: {result['error']}", "danger")
        else:
            status = result['integrity_result']['status']
            if status == 'healthy':
                flash(f"File integrity verified: {result['filename']}", "success")
            else:
                flash(f"File integrity issue detected: {result['filename']} - {status}", "warning")
        
        return redirect(url_for("admin.integrity_scanner_interface"))
        
    except Exception as e:
        current_app.logger.error(f"Error checking file {file_id}: {e}")
        flash("Error checking file integrity.", "danger")
        return redirect(url_for("admin.integrity_scanner_interface"))

@admin_bp.route("/integrity-scanner/repair/<int:file_id>", methods=["POST"])
@login_required
@admin_required
def repair_file(file_id):
    """Repair a file record"""
    try:
        action = request.form.get('action', 'recalculate_hash')
        result = integrity_scanner.repair_file_record(file_id, action)
        
        if 'error' in result:
            flash(f"Error repairing file: {result['error']}", "danger")
        else:
            flash(f"File repaired successfully: {action}", "success")
        
        return redirect(url_for("admin.integrity_scanner_interface"))
        
    except Exception as e:
        current_app.logger.error(f"Error repairing file {file_id}: {e}")
        flash("Error repairing file.", "danger")
        return redirect(url_for("admin.integrity_scanner_interface"))

@admin_bp.route("/integrity-scanner/cleanup-orphaned", methods=["POST"])
@login_required
@admin_required
def cleanup_orphaned_files():
    """Clean up orphaned files"""
    try:
        confirm = request.form.get('confirm') == 'yes'
        
        if not confirm:
            flash("Must confirm deletion of orphaned files.", "warning")
            return redirect(url_for("admin.integrity_scanner_interface"))
        
        result = integrity_scanner.cleanup_orphaned_files(confirm=True)
        
        if 'error' in result:
            flash(f"Error cleaning up orphaned files: {result['error']}", "danger")
        else:
            flash(f"Cleaned up {result['deleted_count']} orphaned files.", "success")
            if result['errors']:
                flash(f"Encountered {len(result['errors'])} errors during cleanup.", "warning")
        
        return redirect(url_for("admin.integrity_scanner_interface"))
        
    except Exception as e:
        current_app.logger.error(f"Error cleaning up orphaned files: {e}")
        flash("Error cleaning up orphaned files.", "danger")
        return redirect(url_for("admin.integrity_scanner_interface"))

@admin_bp.route("/system-health")
@login_required
@admin_required
def system_health():
    """System health monitoring dashboard"""
    from app.utils.health_dashboard import health_dashboard
    
    try:
        # Get comprehensive dashboard data
        dashboard_data = health_dashboard.get_dashboard_data()
        
        return render_template("admin/system_health_dashboard.html",
                             dashboard_data=dashboard_data)
        
    except Exception as e:
        current_app.logger.error(f"Error loading system health dashboard: {e}")
        flash("Error loading system health dashboard.", "danger")
        return redirect(url_for("admin.dashboard"))

@admin_bp.route("/system-health/api")
@login_required
@admin_required
def system_health_api():
    """API endpoint for real-time system health data"""
    from app.utils.health_dashboard import health_dashboard
    
    try:
        dashboard_data = health_dashboard.get_dashboard_data()
        return jsonify(dashboard_data)
        
    except Exception as e:
        current_app.logger.error(f"System health API error: {e}")
        return jsonify({'error': str(e)}), 500

@admin_bp.route("/system-health/metrics")
@login_required
@admin_required
def system_health_metrics():
    """Get current system metrics only"""
    from app.utils.health_dashboard import health_dashboard
    
    try:
        current_metrics = health_dashboard._get_current_metrics()
        return jsonify(current_metrics)
        
    except Exception as e:
        current_app.logger.error(f"Error getting system metrics: {e}")
        return jsonify({'error': str(e)}), 500

@admin_bp.route("/system-health/collect", methods=["POST"])
@login_required
@admin_required
def collect_system_metrics():
    """Manually collect system metrics"""
    try:
        metrics = SystemHealthMetric.collect_and_store()
        
        if metrics:
            flash("System metrics collected successfully.", "success")
        else:
            flash("Error collecting system metrics.", "danger")
        
        return redirect(url_for("admin.system_health"))
        
    except Exception as e:
        current_app.logger.error(f"Error collecting system metrics: {e}")
        flash("Error collecting system metrics.", "danger")
        return redirect(url_for("admin.system_health"))

@admin_bp.route("/system-health/acknowledge-alert/<alert_id>", methods=["POST"])
@login_required
@admin_required
def acknowledge_alert(alert_id):
    """Acknowledge a system alert"""
    try:
        alert = SystemAlert.query.get(alert_id)
        if not alert:
            flash("Alert not found.", "danger")
            return redirect(url_for("admin.system_health"))
        
        alert.acknowledge(current_user.id)
        flash("Alert acknowledged successfully.", "success")
        
        return redirect(url_for("admin.system_health"))
        
    except Exception as e:
        current_app.logger.error(f"Error acknowledging alert {alert_id}: {e}")
        flash("Error acknowledging alert.", "danger")
        return redirect(url_for("admin.system_health"))

# =============================================================================
# Bulk User Management Operations
# =============================================================================

@admin_bp.route("/bulk-operations")
@login_required
@admin_required
def bulk_operations():
    """Bulk user management operations interface"""
    from app.utils.bulk_operations import BulkUserOperations
    
    try:
        # Get user statistics
        stats = BulkUserOperations.get_user_statistics()
        
        # Get recent users for selection
        recent_users = User.query.order_by(User.created_at.desc()).limit(50).all()
        
        return render_template("admin/bulk_operations.html", 
                             stats=stats,
                             recent_users=recent_users)
        
    except Exception as e:
        current_app.logger.error(f"Error loading bulk operations: {e}")
        flash("Error loading bulk operations interface.", "danger")
        return redirect(url_for("admin.dashboard"))

@admin_bp.route("/bulk-operations/validate", methods=["POST"])
@login_required
@admin_required
def validate_bulk_operation():
    """Validate bulk operation before execution"""
    from app.utils.bulk_operations import BulkUserOperations
    
    try:
        user_ids = request.json.get('user_ids', [])
        operation_type = request.json.get('operation_type', '')
        
        validation = BulkUserOperations.validate_bulk_operation(user_ids, operation_type)
        return jsonify(validation)
        
    except Exception as e:
        return jsonify({
            'valid': False,
            'errors': [f'Validation error: {str(e)}']
        }), 500

@admin_bp.route("/bulk-operations/disable", methods=["POST"])
@login_required
@admin_required
def bulk_disable_users():
    """Bulk disable users"""
    from app.utils.bulk_operations import BulkUserOperations
    
    try:
        user_ids = request.form.getlist('user_ids')
        reason = request.form.get('reason', 'Administrative action')
        
        if not user_ids:
            flash("No users selected for bulk disable operation.", "warning")
            return redirect(url_for("admin.bulk_operations"))
        
        # Convert to integers
        user_ids = [int(uid) for uid in user_ids if uid.isdigit()]
        
        result = BulkUserOperations.bulk_disable_users(user_ids, reason)
        
        if 'error' in result:
            flash(f"Bulk disable operation failed: {result['error']}", "danger")
        else:
            flash(f"Bulk disable completed: {result['disabled']} users disabled, "
                 f"{result['already_disabled']} already disabled, {len(result['errors'])} errors.", "success")
            
            if result['errors']:
                for error in result['errors'][:5]:  # Show first 5 errors
                    flash(f"Error: {error}", "warning")
        
        return redirect(url_for("admin.bulk_operations"))
        
    except Exception as e:
        current_app.logger.error(f"Bulk disable operation error: {e}")
        flash("Error performing bulk disable operation.", "danger")
        return redirect(url_for("admin.bulk_operations"))

@admin_bp.route("/bulk-operations/enable", methods=["POST"])
@login_required
@admin_required
def bulk_enable_users():
    """Bulk enable users"""
    from app.utils.bulk_operations import BulkUserOperations
    
    try:
        user_ids = request.form.getlist('user_ids')
        reason = request.form.get('reason', 'Administrative action')
        
        if not user_ids:
            flash("No users selected for bulk enable operation.", "warning")
            return redirect(url_for("admin.bulk_operations"))
        
        # Convert to integers
        user_ids = [int(uid) for uid in user_ids if uid.isdigit()]
        
        result = BulkUserOperations.bulk_enable_users(user_ids, reason)
        
        if 'error' in result:
            flash(f"Bulk enable operation failed: {result['error']}", "danger")
        else:
            flash(f"Bulk enable completed: {result['enabled']} users enabled, "
                 f"{result['already_enabled']} already enabled, {len(result['errors'])} errors.", "success")
            
            if result['errors']:
                for error in result['errors'][:5]:  # Show first 5 errors
                    flash(f"Error: {error}", "warning")
        
        return redirect(url_for("admin.bulk_operations"))
        
    except Exception as e:
        current_app.logger.error(f"Bulk enable operation error: {e}")
        flash("Error performing bulk enable operation.", "danger")
        return redirect(url_for("admin.bulk_operations"))

@admin_bp.route("/bulk-operations/reset-passwords", methods=["POST"])
@login_required
@admin_required
def bulk_reset_passwords():
    """Bulk reset passwords"""
    from app.utils.bulk_operations import BulkUserOperations
    
    try:
        user_ids = request.form.getlist('user_ids')
        password_length = int(request.form.get('password_length', 12))
        
        if not user_ids:
            flash("No users selected for bulk password reset.", "warning")
            return redirect(url_for("admin.bulk_operations"))
        
        # Convert to integers
        user_ids = [int(uid) for uid in user_ids if uid.isdigit()]
        
        result = BulkUserOperations.bulk_reset_passwords(user_ids, password_length)
        
        if 'error' in result:
            flash(f"Bulk password reset failed: {result['error']}", "danger")
        else:
            flash(f"Bulk password reset completed: {result['reset']} passwords reset, {len(result['errors'])} errors.", "success")
            
            if result['errors']:
                for error in result['errors'][:5]:  # Show first 5 errors
                    flash(f"Error: {error}", "warning")
            
            # Create downloadable password list
            if result['password_list']:
                password_content = '\n'.join(result['password_list'])
                timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
                
                response = make_response(password_content)
                response.headers['Content-Type'] = 'text/plain'
                response.headers['Content-Disposition'] = f'attachment; filename="reset_passwords_{timestamp}.txt"'
                
                flash("New passwords have been downloaded. Distribute securely to users.", "info")
                return response
        
        return redirect(url_for("admin.bulk_operations"))
        
    except Exception as e:
        current_app.logger.error(f"Bulk password reset error: {e}")
        flash("Error performing bulk password reset.", "danger")
        return redirect(url_for("admin.bulk_operations"))

@admin_bp.route("/bulk-operations/clear-sessions", methods=["POST"])
@login_required
@admin_required
def bulk_clear_sessions():
    """Bulk clear user sessions"""
    from app.utils.bulk_operations import BulkUserOperations
    
    try:
        user_ids = request.form.getlist('user_ids')
        reason = request.form.get('reason', 'Administrative action')
        
        if not user_ids:
            flash("No users selected for bulk session clear.", "warning")
            return redirect(url_for("admin.bulk_operations"))
        
        # Convert to integers
        user_ids = [int(uid) for uid in user_ids if uid.isdigit()]
        
        result = BulkUserOperations.bulk_clear_sessions(user_ids, reason)
        
        if 'error' in result:
            flash(f"Bulk session clear failed: {result['error']}", "danger")
        else:
            flash(f"Bulk session clear completed: {result['total_sessions']} sessions cleared "
                 f"for {result['sessions_cleared']} users, {len(result['errors'])} errors.", "success")
            
            if result['errors']:
                for error in result['errors'][:5]:  # Show first 5 errors
                    flash(f"Error: {error}", "warning")
        
        return redirect(url_for("admin.bulk_operations"))
        
    except Exception as e:
        current_app.logger.error(f"Bulk session clear error: {e}")
        flash("Error performing bulk session clear.", "danger")
        return redirect(url_for("admin.bulk_operations"))

@admin_bp.route("/bulk-operations/delete", methods=["POST"])
@login_required
@admin_required
def bulk_delete_users():
    """Bulk delete users (DESTRUCTIVE)"""
    from app.utils.bulk_operations import BulkUserOperations
    
    try:
        user_ids = request.form.getlist('user_ids')
        confirm = request.form.get('confirm_delete') == 'DELETE'
        delete_files = request.form.get('delete_files') == 'on'
        
        if not user_ids:
            flash("No users selected for bulk delete operation.", "warning")
            return redirect(url_for("admin.bulk_operations"))
        
        if not confirm:
            flash("You must type 'DELETE' to confirm this destructive operation.", "danger")
            return redirect(url_for("admin.bulk_operations"))
        
        # Convert to integers
        user_ids = [int(uid) for uid in user_ids if uid.isdigit()]
        
        result = BulkUserOperations.bulk_delete_users(user_ids, confirm_deletion=True, delete_files=delete_files)
        
        if 'error' in result:
            flash(f"Bulk delete operation failed: {result['error']}", "danger")
        else:
            flash(f"Bulk delete completed: {result['deleted']} users deleted, "
                 f"{result['files_deleted']} files deleted, {len(result['errors'])} errors.", "success")
            
            if result['errors']:
                for error in result['errors'][:5]:  # Show first 5 errors
                    flash(f"Error: {error}", "warning")
        
        return redirect(url_for("admin.bulk_operations"))
        
    except Exception as e:
        current_app.logger.error(f"Bulk delete operation error: {e}")
        flash("Error performing bulk delete operation.", "danger")
        return redirect(url_for("admin.bulk_operations"))

@admin_bp.route("/bulk-operations/export-users", methods=["POST"])
@login_required
@admin_required
def export_users():
    """Export user data"""
    from app.utils.bulk_operations import BulkUserOperations
    
    try:
        export_format = request.form.get('format', 'csv')
        include_files = request.form.get('include_files') == 'on'
        user_ids = request.form.getlist('user_ids')
        
        # Convert user_ids to integers if provided
        if user_ids:
            user_ids = [int(uid) for uid in user_ids if uid.isdigit()]
        else:
            user_ids = None  # Export all users
        
        content, filename = BulkUserOperations.export_user_data(
            user_ids=user_ids,
            format=export_format,
            include_files=include_files
        )
        
        # Create response
        response = make_response(content)
        
        if export_format == 'csv':
            response.headers['Content-Type'] = 'text/csv'
        else:
            response.headers['Content-Type'] = 'application/json'
        
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        return response
        
    except Exception as e:
        current_app.logger.error(f"User export error: {e}")
        flash("Error exporting user data.", "danger")
        return redirect(url_for("admin.bulk_operations"))
# =============================================================================
# Advanced User Search and Filtering
# =============================================================================

@admin_bp.route("/user-search")
@login_required
@admin_required
def user_search():
    """Advanced user search and filtering interface"""
    from app.utils.user_search import user_search_filter
    
    try:
        # Get filter suggestions for the UI
        suggestions = user_search_filter.get_filter_suggestions()
        
        # Get initial user list (recent users)
        initial_filters = {
            'page': 1,
            'per_page': 20,
            'sort_by': 'created_at',
            'sort_order': 'desc'
        }
        
        results = user_search_filter.search_users(**initial_filters)
        
        return render_template("admin/user_search.html", 
                             results=results,
                             suggestions=suggestions,
                             filters=initial_filters)
        
    except Exception as e:
        current_app.logger.error(f"Error loading user search: {e}")
        flash("Error loading user search interface.", "danger")
        return redirect(url_for("admin.dashboard"))

@admin_bp.route("/user-search/api", methods=["GET", "POST"])
@login_required
@admin_required
def user_search_api():
    """API endpoint for user search"""
    from app.utils.user_search import user_search_filter
    
    try:
        # Get filters from request
        if request.method == 'POST':
            filters = request.get_json() or {}
        else:
            filters = request.args.to_dict()
        
        # Convert string parameters to appropriate types
        for key, value in filters.items():
            if key in ['page', 'per_page', 'storage_min', 'storage_max', 'failed_logins_min', 'file_count_min', 'file_count_max']:
                try:
                    filters[key] = int(value) if value else None
                except (ValueError, TypeError):
                    pass
            elif key in ['include_stats']:
                filters[key] = value in ['true', '1', 'on', True]
        
        # Perform search
        results = user_search_filter.search_users(**filters)
        
        return jsonify(results)
        
    except Exception as e:
        current_app.logger.error(f"User search API error: {e}")
        return jsonify({
            'error': str(e),
            'users': [],
            'pagination': {},
            'total_count': 0
        }), 500

@admin_bp.route("/user-search/export", methods=["POST"])
@login_required
@admin_required
def export_user_search():
    """Export user search results"""
    from app.utils.user_search import user_search_filter
    
    try:
        # Get search filters and export format
        filters = request.get_json() or {}
        export_format = filters.pop('export_format', 'csv')
        
        # Remove pagination for export (get all results)
        filters.pop('page', None)
        filters.pop('per_page', None)
        filters['include_stats'] = True  # Include detailed stats in export
        
        # Perform search
        results = user_search_filter.search_users(**filters)
        
        # Export results
        content, filename = user_search_filter.export_search_results(results, export_format)
        
        # Create response
        response = make_response(content)
        
        if export_format == 'csv':
            response.headers['Content-Type'] = 'text/csv'
        else:
            response.headers['Content-Type'] = 'application/json'
        
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        # Log export
        from app.utils.audit_logger import AuditLogger
        AuditLogger.log_admin_action(
            'admin_user_search_export',
            description=f"User search results exported ({results['total_count']} users, format: {export_format})"
        )
        
        return response
        
    except Exception as e:
        current_app.logger.error(f"User search export error: {e}")
        return jsonify({'error': str(e)}), 500

@admin_bp.route("/user-search/suggestions")
@login_required
@admin_required
def user_search_suggestions():
    """Get filter suggestions for user search"""
    from app.utils.user_search import user_search_filter
    
    try:
        suggestions = user_search_filter.get_filter_suggestions()
        return jsonify(suggestions)
        
    except Exception as e:
        current_app.logger.error(f"Error getting search suggestions: {e}")
        return jsonify({'error': str(e)}), 500

@admin_bp.route("/user-search/quick-filter/<filter_type>")
@login_required
@admin_required
def user_search_quick_filter(filter_type):
    """Quick filter presets for common searches"""
    from app.utils.user_search import user_search_filter
    
    try:
        # Define quick filter presets
        quick_filters = {
            'admin_users': {
                'is_admin': 'true',
                'sort_by': 'username',
                'sort_order': 'asc'
            },
            'inactive_accounts': {
                'is_active': 'false',
                'sort_by': 'created_at',
                'sort_order': 'desc'
            },
            'no_2fa': {
                'has_2fa': 'false',
                'is_active': 'true',
                'sort_by': 'last_login',
                'sort_order': 'desc'
            },
            'locked_accounts': {
                'is_locked': 'true',
                'sort_by': 'failed_login_attempts',
                'sort_order': 'desc'
            },
            'never_logged_in': {
                'never_logged_in': 'true',
                'sort_by': 'created_at',
                'sort_order': 'desc'
            },
            'high_storage': {
                'storage_min': '100',  # 100MB+
                'sort_by': 'current_storage_bytes',
                'sort_order': 'desc'
            },
            'no_files': {
                'has_files': 'false',
                'is_active': 'true',
                'sort_by': 'created_at',
                'sort_order': 'desc'
            },
            'recent_users': {
                'created_after': (datetime.now(timezone.utc) - timedelta(days=30)).isoformat(),
                'sort_by': 'created_at',
                'sort_order': 'desc'
            },
            'active_sessions': {
                'has_active_sessions': 'true',
                'sort_by': 'last_login',
                'sort_order': 'desc'
            }
        }
        
        if filter_type not in quick_filters:
            return jsonify({'error': 'Unknown quick filter type'}), 400
        
        # Apply the quick filter
        filters = quick_filters[filter_type]
        filters['page'] = 1
        filters['per_page'] = 20
        filters['include_stats'] = True
        
        results = user_search_filter.search_users(**filters)
        
        return jsonify({
            'filter_type': filter_type,
            'filters_applied': filters,
            'results': results
        })
        
    except Exception as e:
        current_app.logger.error(f"Quick filter error: {e}")
        return jsonify({'error': str(e)}), 500

@admin_bp.route("/user-search/save", methods=["POST"])
@login_required
@admin_required
def save_user_search():
    """Save a user search configuration"""
    from app.utils.user_search import SavedSearch
    
    try:
        data = request.get_json()
        search_name = data.get('name', '').strip()
        filters = data.get('filters', {})
        
        if not search_name:
            return jsonify({'error': 'Search name is required'}), 400
        
        result = SavedSearch.save_search(search_name, filters, current_user.id)
        
        # Log the action
        from app.utils.audit_logger import AuditLogger
        AuditLogger.log_admin_action(
            'admin_search_saved',
            description=f"User search configuration saved: {search_name}"
        )
        
        return jsonify(result)
        
    except Exception as e:
        current_app.logger.error(f"Error saving search: {e}")
        return jsonify({'error': str(e)}), 500

@admin_bp.route("/user-search/saved")
@login_required
@admin_required
def list_saved_searches():
    """List saved search configurations"""
    from app.utils.user_search import SavedSearch
    
    try:
        saved_searches = SavedSearch.list_saved_searches(current_user.id)
        return jsonify({'saved_searches': saved_searches})
        
    except Exception as e:
        current_app.logger.error(f"Error listing saved searches: {e}")
        return jsonify({'error': str(e)}), 500

@admin_bp.route("/user-details/<int:user_id>")
@login_required
@admin_required
def user_details_modal(user_id):
    """Get detailed user information for modal display"""
    from app.utils.user_search import user_search_filter
    
    try:
        user = User.query.get_or_404(user_id)
        
        # Get detailed user data
        user_data = user_search_filter._format_user_data(user, include_stats=True)
        
        # Get recent sessions
        recent_sessions = UserSession.get_active_sessions_for_user(user_id)
        sessions_data = []
        
        for session in recent_sessions[:10]:  # Last 10 sessions
            sessions_data.append({
                'id': session.id,
                'created_at': session.created_at.isoformat(),
                'last_activity': session.last_activity.isoformat(),
                'ip_address': session.ip_address,
                'device_summary': session.get_device_summary(),
                'location_summary': session.get_location_summary(),
                'is_suspicious': session.is_suspicious,
                'risk_score': session.risk_score
            })
        
        # Get recent files
        recent_files = File.query.filter_by(user_id=user_id).order_by(
            File.uploaded_at.desc()
        ).limit(10).all()
        
        files_data = []
        for file_record in recent_files:
            files_data.append({
                'id': file_record.id,
                'filename': file_record.filename,
                'size': file_record.size,
                'size_formatted': file_record.get_size_formatted(),
                'uploaded_at': file_record.uploaded_at.isoformat() if file_record.uploaded_at else None,
                'mime_type': file_record.mime_type
            })
        
        return jsonify({
            'user': user_data,
            'recent_sessions': sessions_data,
            'recent_files': files_data,
            'total_sessions': UserSession.query.filter_by(user_id=user_id).count(),
            'total_files': File.query.filter_by(user_id=user_id).count()
        })
        
    except Exception as e:
        current_app.logger.error(f"Error getting user details: {e}")
        return jsonify({'error': str(e)}), 500
# =============================================================================
# Session Management Features
# =============================================================================

@admin_bp.route("/session-management")
@login_required
@admin_required
def session_management_dashboard():
    """Session management dashboard"""
    from app.utils.session_management import SessionManagement
    
    try:
        # Get session statistics
        stats = SessionManagement.get_session_statistics()
        
        # Get recent sessions (first page)
        initial_filters = {
            'page': 1,
            'per_page': 20,
            'sort_by': 'last_activity',
            'sort_order': 'desc'
        }
        
        sessions_data = SessionManagement.get_all_active_sessions(initial_filters)
        
        return render_template("admin/session_management.html",
                             stats=stats,
                             sessions_data=sessions_data,
                             filters=initial_filters)
        
    except Exception as e:
        current_app.logger.error(f"Error loading session management: {e}")
        flash("Error loading session management dashboard.", "danger")
        return redirect(url_for("admin.dashboard"))

@admin_bp.route("/session-management/api", methods=["GET", "POST"])
@login_required
@admin_required
def session_management_api():
    """API endpoint for session management"""
    from app.utils.session_management import SessionManagement
    
    try:
        # Get filters from request
        if request.method == 'POST':
            filters = request.get_json() or {}
        else:
            filters = request.args.to_dict()
        
        # Convert string parameters to appropriate types
        for key, value in filters.items():
            if key in ['page', 'per_page', 'user_id', 'min_risk_level', 'idle_minutes']:
                try:
                    filters[key] = int(value) if value else None
                except (ValueError, TypeError):
                    pass
            elif key in ['is_suspicious']:
                filters[key] = value in ['true', '1', 'on', True]
        
        # Get session data
        sessions_data = SessionManagement.get_all_active_sessions(filters)
        
        return jsonify(sessions_data)
        
    except Exception as e:
        current_app.logger.error(f"Session management API error: {e}")
        return jsonify({
            'error': str(e),
            'sessions': [],
            'pagination': {},
            'total_count': 0
        }), 500

@admin_bp.route("/session-management/terminate/<session_id>", methods=["POST"])
@login_required
@admin_required
def terminate_session(session_id):
    """Terminate a specific session"""
    from app.utils.session_management import SessionManagement
    
    try:
        reason = request.form.get('reason', 'Administrative termination')
        
        result = SessionManagement.terminate_session(session_id, reason)
        
        if 'error' in result:
            flash(f"Error terminating session: {result['error']}", "danger")
        else:
            flash(f"Session terminated successfully for user {result['username']}", "success")
        
        return redirect(url_for("admin.session_management_dashboard"))
        
    except Exception as e:
        current_app.logger.error(f"Error terminating session {session_id}: {e}")
        flash("Error terminating session.", "danger")
        return redirect(url_for("admin.session_management_dashboard"))

@admin_bp.route("/session-management/terminate-user/<int:user_id>", methods=["POST"])
@login_required
@admin_required
def terminate_user_sessions(user_id):
    """Terminate all sessions for a specific user"""
    from app.utils.session_management import SessionManagement
    
    try:
        reason = request.form.get('reason', 'Administrative termination')
        exclude_current = request.form.get('exclude_current', 'on') == 'on'
        
        result = SessionManagement.terminate_user_sessions(user_id, exclude_current, reason)
        
        if 'error' in result:
            flash(f"Error terminating user sessions: {result['error']}", "danger")
        else:
            flash(f"Terminated {result['terminated_count']} sessions for user {result['username']}", "success")
        
        return redirect(url_for("admin.session_management_dashboard"))
        
    except Exception as e:
        current_app.logger.error(f"Error terminating user sessions for {user_id}: {e}")
        flash("Error terminating user sessions.", "danger")
        return redirect(url_for("admin.session_management_dashboard"))

@admin_bp.route("/session-management/bulk-terminate", methods=["POST"])
@login_required
@admin_required
def bulk_terminate_sessions():
    """Bulk terminate multiple sessions"""
    from app.utils.session_management import SessionManagement
    
    try:
        session_ids = request.form.getlist('session_ids')
        reason = request.form.get('reason', 'Bulk administrative termination')
        
        if not session_ids:
            flash("No sessions selected for termination.", "warning")
            return redirect(url_for("admin.session_management_dashboard"))
        
        result = SessionManagement.bulk_terminate_sessions(session_ids, reason)
        
        if 'error' in result:
            flash(f"Bulk termination failed: {result['error']}", "danger")
        else:
            flash(f"Bulk termination completed: {result['terminated']} sessions terminated, {len(result['errors'])} errors.", "success")
            
            if result['errors']:
                for error in result['errors'][:5]:  # Show first 5 errors
                    flash(f"Error: {error}", "warning")
        
        return redirect(url_for("admin.session_management_dashboard"))
        
    except Exception as e:
        current_app.logger.error(f"Bulk session termination error: {e}")
        flash("Error performing bulk session termination.", "danger")
        return redirect(url_for("admin.session_management_dashboard"))

@admin_bp.route("/session-management/flag-suspicious/<session_id>", methods=["POST"])
@login_required
@admin_required
def flag_session_suspicious(session_id):
    """Flag a session as suspicious"""
    from app.utils.session_management import SessionManagement
    
    try:
        reason = request.form.get('reason', 'Administrative review')
        
        result = SessionManagement.flag_session_suspicious(session_id, reason)
        
        if 'error' in result:
            flash(f"Error flagging session: {result['error']}", "danger")
        else:
            flash("Session flagged as suspicious successfully.", "success")
        
        return redirect(url_for("admin.session_management_dashboard"))
        
    except Exception as e:
        current_app.logger.error(f"Error flagging session {session_id}: {e}")
        flash("Error flagging session as suspicious.", "danger")
        return redirect(url_for("admin.session_management_dashboard"))

@admin_bp.route("/session-management/export", methods=["POST"])
@login_required
@admin_required
def export_session_data():
    """Export session data"""
    from app.utils.session_management import SessionManagement
    
    try:
        # Get filters and export format
        filters = request.get_json() or {}
        export_format = filters.pop('export_format', 'csv')
        
        # Export session data
        content, filename = SessionManagement.export_session_data(filters, export_format)
        
        # Create response
        response = make_response(content)
        
        if export_format == 'csv':
            response.headers['Content-Type'] = 'text/csv'
        else:
            response.headers['Content-Type'] = 'application/json'
        
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        # Log export
        from app.utils.audit_logger import AuditLogger
        AuditLogger.log_admin_action(
            'admin_session_data_export',
            description=f"Session data exported (format: {export_format})"
        )
        
        return response
        
    except Exception as e:
        current_app.logger.error(f"Session export error: {e}")
        return jsonify({'error': str(e)}), 500

@admin_bp.route("/session-management/cleanup-idle", methods=["POST"])
@login_required
@admin_required
def cleanup_idle_sessions():
    """Clean up idle sessions"""
    from app.utils.session_management import SessionManagement
    
    try:
        idle_minutes = int(request.form.get('idle_minutes', 60))
        
        result = SessionManagement.cleanup_idle_sessions(idle_minutes)
        
        if 'error' in result:
            flash(f"Error cleaning up idle sessions: {result['error']}", "danger")
        else:
            flash(f"Cleaned up {result['cleaned_count']} idle sessions (idle > {idle_minutes} minutes).", "success")
        
        return redirect(url_for("admin.session_management_dashboard"))
        
    except Exception as e:
        current_app.logger.error(f"Error cleaning up idle sessions: {e}")
        flash("Error cleaning up idle sessions.", "danger")
        return redirect(url_for("admin.session_management_dashboard"))

@admin_bp.route("/session-management/statistics")
@login_required
@admin_required
def session_statistics_api():
    """Get session statistics as JSON"""
    from app.utils.session_management import SessionManagement
    
    try:
        stats = SessionManagement.get_session_statistics()
        return jsonify(stats)
        
    except Exception as e:
        current_app.logger.error(f"Error getting session statistics: {e}")
        return jsonify({'error': str(e)}), 500

@admin_bp.route("/session-management/user/<int:user_id>/sessions")
@login_required
@admin_required
def user_session_details(user_id):
    """Get detailed session information for a specific user"""
    from app.utils.session_management import SessionManagement
    from app.models.user_session import UserSession
    
    try:
        user = User.query.get_or_404(user_id)
        
        # Get user's active sessions
        active_sessions = UserSession.get_active_sessions_for_user(user_id)
        
        # Format session data
        sessions_data = []
        for session in active_sessions:
            session_data = SessionManagement._format_session_data(session)
            sessions_data.append(session_data)
        
        # Get session history (last 10 inactive sessions)
        inactive_sessions = UserSession.query.filter_by(
            user_id=user_id, 
            is_active=False
        ).order_by(UserSession.last_activity.desc()).limit(10).all()
        
        history_data = []
        for session in inactive_sessions:
            session_data = SessionManagement._format_session_data(session)
            history_data.append(session_data)
        
        return jsonify({
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email,
                'is_active': user.is_active_account
            },
            'active_sessions': sessions_data,
            'session_history': history_data,
            'total_active': len(sessions_data),
            'total_history': len(inactive_sessions)
        })
        
    except Exception as e:
        current_app.logger.error(f"Error getting user session details: {e}")
        return jsonify({'error': str(e)}), 500
# =============================================================================
# Audit Trail Viewer with Advanced Filtering
# =============================================================================

@admin_bp.route("/audit-trail")
@login_required
@admin_required
def audit_trail_viewer():
    """Advanced audit trail viewer interface"""
    from app.utils.audit_viewer import audit_viewer
    
    try:
        # Get quick filters and statistics
        quick_filters = audit_viewer.get_quick_filters()
        
        # Get audit statistics for the last 30 days
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=30)
        stats = audit_viewer.get_audit_statistics(start_date, end_date)
        
        # Get initial audit logs (recent entries)
        initial_filters = {
            'page': 1,
            'per_page': 50,
            'sort_by': 'timestamp',
            'sort_order': 'desc'
        }
        
        results = audit_viewer.search_audit_logs(**initial_filters)
        
        return render_template("admin/audit_trail.html",
                             results=results,
                             quick_filters=quick_filters,
                             stats=stats,
                             filters=initial_filters)
        
    except Exception as e:
        current_app.logger.error(f"Error loading audit trail viewer: {e}")
        flash("Error loading audit trail viewer.", "danger")
        return redirect(url_for("admin.dashboard"))

@admin_bp.route("/audit-trail/api", methods=["GET", "POST"])
@login_required
@admin_required
def audit_trail_api():
    """API endpoint for audit trail search"""
    from app.utils.audit_viewer import audit_viewer
    
    try:
        # Get filters from request
        if request.method == 'POST':
            filters = request.get_json() or {}
        else:
            filters = request.args.to_dict()
        
        # Convert string parameters to appropriate types
        for key, value in filters.items():
            if key in ['page', 'per_page', 'user_id', 'min_risk_level', 'max_risk_level', 'min_duration']:
                try:
                    filters[key] = int(value) if value else None
                except (ValueError, TypeError):
                    pass
            elif key in ['include_details', 'is_suspicious']:
                filters[key] = value in ['true', '1', 'on', True]
            elif key in ['action', 'category', 'level', 'status'] and ',' in str(value):
                # Handle comma-separated lists
                filters[key] = [item.strip() for item in str(value).split(',') if item.strip()]
        
        # Perform search
        results = audit_viewer.search_audit_logs(**filters)
        
        return jsonify(results)
        
    except Exception as e:
        current_app.logger.error(f"Audit trail API error: {e}")
        return jsonify({
            'error': str(e),
            'logs': [],
            'pagination': {},
            'total_count': 0
        }), 500

@admin_bp.route("/audit-trail/export", methods=["POST"])
@login_required
@admin_required
def export_audit_trail():
    """Export audit trail search results"""
    from app.utils.audit_viewer import audit_viewer
    
    try:
        # Get search filters and export format
        data = request.get_json() or {}
        filters = data.get('filters', {})
        export_format = data.get('format', 'csv')
        include_legacy = data.get('include_legacy', True)
        
        # Export audit logs
        content, filename = audit_viewer.export_audit_logs(filters, export_format, include_legacy)
        
        # Create response
        response = make_response(content)
        
        if export_format == 'csv':
            response.headers['Content-Type'] = 'text/csv'
        else:
            response.headers['Content-Type'] = 'application/json'
        
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        # Log export
        from app.utils.audit_logger import AuditLogger
        AuditLogger.log_admin_action(
            'admin_audit_trail_export',
            description=f"Audit trail exported (format: {export_format}, include_legacy: {include_legacy})"
        )
        
        return response
        
    except Exception as e:
        current_app.logger.error(f"Audit trail export error: {e}")
        return jsonify({'error': str(e)}), 500

@admin_bp.route("/audit-trail/quick-filter/<filter_name>")
@login_required
@admin_required
def audit_trail_quick_filter(filter_name):
    """Apply predefined quick filters"""
    from app.utils.audit_viewer import audit_viewer
    
    try:
        # Get quick filters
        quick_filters_data = audit_viewer.get_quick_filters()
        
        # Find the requested quick filter
        quick_filter = None
        for qf in quick_filters_data.get('quick_searches', []):
            if qf['name'].lower().replace(' ', '_') == filter_name.lower():
                quick_filter = qf
                break
        
        if not quick_filter:
            return jsonify({'error': 'Quick filter not found'}), 404
        
        # Apply the quick filter
        filters = quick_filter['filters'].copy()
        filters.update({
            'page': 1,
            'per_page': 50,
            'sort_by': 'timestamp',
            'sort_order': 'desc',
            'include_details': True
        })
        
        results = audit_viewer.search_audit_logs(**filters)
        
        return jsonify({
            'filter_name': quick_filter['name'],
            'filters_applied': filters,
            'results': results
        })
        
    except Exception as e:
        current_app.logger.error(f"Quick filter error: {e}")
        return jsonify({'error': str(e)}), 500

@admin_bp.route("/audit-trail/log/<log_id>")
@login_required
@admin_required
def audit_log_details(log_id):
    """Get detailed information for a specific audit log"""
    from app.models.audit_log import AuditLog
    from app.utils.audit_viewer import audit_viewer
    
    try:
        audit_log = AuditLog.query.get_or_404(log_id)
        
        # Format the log with full details
        log_data = audit_viewer._format_audit_log(audit_log, include_details=True)
        
        # Get related logs (same user, similar time)
        related_query = AuditLog.query.filter(
            AuditLog.id != log_id,
            AuditLog.timestamp >= audit_log.timestamp - timedelta(minutes=5),
            AuditLog.timestamp <= audit_log.timestamp + timedelta(minutes=5)
        )
        
        if audit_log.user_id:
            related_query = related_query.filter(AuditLog.user_id == audit_log.user_id)
        elif audit_log.ip_address:
            related_query = related_query.filter(AuditLog.ip_address == audit_log.ip_address)
        
        related_logs = related_query.order_by(AuditLog.timestamp).limit(10).all()
        related_data = [audit_viewer._format_audit_log(log) for log in related_logs]
        
        return jsonify({
            'log': log_data,
            'related_logs': related_data,
            'total_related': len(related_data)
        })
        
    except Exception as e:
        current_app.logger.error(f"Error getting audit log details: {e}")
        return jsonify({'error': str(e)}), 500

@admin_bp.route("/audit-trail/statistics")
@login_required
@admin_required
def audit_trail_statistics():
    """Get audit trail statistics"""
    from app.utils.audit_viewer import audit_viewer
    
    try:
        # Get date range from request
        days = int(request.args.get('days', 30))
        end_date = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=days)
        
        stats = audit_viewer.get_audit_statistics(start_date, end_date)
        
        # Add time range info
        stats['time_range'] = {
            'start_date': start_date.isoformat(),
            'end_date': end_date.isoformat(),
            'days': days
        }
        
        return jsonify(stats)
        
    except Exception as e:
        current_app.logger.error(f"Error getting audit statistics: {e}")
        return jsonify({'error': str(e)}), 500

@admin_bp.route("/audit-trail/user-activity/<int:user_id>")
@login_required
@admin_required
def user_audit_activity(user_id):
    """Get audit activity for a specific user"""
    from app.utils.audit_viewer import audit_viewer
    
    try:
        user = User.query.get_or_404(user_id)
        
        # Get user's audit activity (last 30 days)
        filters = {
            'user_id': user_id,
            'start_date': (datetime.now(timezone.utc) - timedelta(days=30)).isoformat(),
            'sort_by': 'timestamp',
            'sort_order': 'desc',
            'per_page': 100,
            'include_details': True
        }
        
        results = audit_viewer.search_audit_logs(**filters)
        
        # Calculate user-specific statistics
        user_stats = {
            'total_actions': results['total_count'],
            'failed_actions': len([log for log in results['logs'] if log['status'] != 'success']),
            'suspicious_actions': len([log for log in results['logs'] if log['is_suspicious']]),
            'categories': {}
        }
        
        # Count actions by category
        for log in results['logs']:
            category = log['category']
            user_stats['categories'][category] = user_stats['categories'].get(category, 0) + 1
        
        return jsonify({
            'user': {
                'id': user.id,
                'username': user.username,
                'email': user.email
            },
            'activity': results['logs'],
            'statistics': user_stats,
            'pagination': results['pagination']
        })
        
    except Exception as e:
        current_app.logger.error(f"Error getting user audit activity: {e}")
        return jsonify({'error': str(e)}), 500

@admin_bp.route("/audit-trail/search-suggestions")
@login_required
@admin_required
def audit_search_suggestions():
    """Get search suggestions for audit trail"""
    from app.utils.audit_viewer import audit_viewer
    
    try:
        suggestions = audit_viewer.get_quick_filters()
        return jsonify(suggestions)
        
    except Exception as e:
        current_app.logger.error(f"Error getting search suggestions: {e}")
        return jsonify({'error': str(e)}), 500
# Additional System Health Dashboard Routes

@admin_bp.route("/system-health/alerts")
@login_required
@admin_required
def system_health_alerts():
    """Get system alerts"""
    from app.utils.health_dashboard import health_dashboard
    
    try:
        alerts = health_dashboard._get_active_alerts()
        return jsonify({'alerts': alerts})
        
    except Exception as e:
        current_app.logger.error(f"Error getting system alerts: {e}")
        return jsonify({'error': str(e)}), 500

@admin_bp.route("/system-health/trends/<int:hours>")
@login_required
@admin_required
def system_health_trends(hours):
    """Get system trends for specified hours"""
    from app.utils.health_dashboard import health_dashboard
    
    try:
        # Limit hours to prevent excessive data
        hours = min(hours, 168)  # Max 1 week
        trends = health_dashboard._get_trend_data(hours=hours)
        return jsonify(trends)
        
    except Exception as e:
        current_app.logger.error(f"Error getting system trends: {e}")
        return jsonify({'error': str(e)}), 500

@admin_bp.route("/system-health/check-alerts", methods=["POST"])
@login_required
@admin_required
def check_system_alerts():
    """Manually trigger alert checking"""
    from app.utils.health_dashboard import health_dashboard
    
    try:
        health_dashboard.check_and_create_alerts()
        health_dashboard.resolve_alerts_by_threshold()
        
        flash("Alert check completed successfully.", "success")
        return redirect(url_for("admin.system_health"))
        
    except Exception as e:
        current_app.logger.error(f"Error checking alerts: {e}")
        flash("Error checking system alerts.", "danger")
        return redirect(url_for("admin.system_health"))

@admin_bp.route("/system-health/export", methods=["POST"])
@login_required
@admin_required  
def export_system_health():
    """Export system health data"""
    from app.utils.health_dashboard import health_dashboard
    
    try:
        export_format = request.form.get('format', 'json')
        hours = int(request.form.get('hours', 24))
        
        # Get dashboard data
        dashboard_data = health_dashboard.get_dashboard_data()
        
        # Get additional trend data
        trends = health_dashboard._get_trend_data(hours=hours)
        dashboard_data['trends'] = trends
        
        if export_format == 'json':
            content = json.dumps(dashboard_data, indent=2, default=str)
            filename = f'system_health_export_{datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")}.json'
            content_type = 'application/json'
        else:
            # CSV format for metrics
            import csv
            import io
            
            output = io.StringIO()
            writer = csv.writer(output)
            
            # Write metrics data
            writer.writerow(['Metric', 'Value', 'Timestamp'])
            
            current_metrics = dashboard_data.get('current_metrics', {})
            timestamp = current_metrics.get('timestamp', '')
            
            if 'cpu' in current_metrics:
                writer.writerow(['CPU Percent', current_metrics['cpu'].get('percent'), timestamp])
                writer.writerow(['CPU Health Score', current_metrics['cpu'].get('health_score'), timestamp])
            
            if 'memory' in current_metrics:
                writer.writerow(['Memory Percent', current_metrics['memory'].get('percent'), timestamp])
                writer.writerow(['Memory Health Score', current_metrics['memory'].get('health_score'), timestamp])
            
            if 'disk' in current_metrics:
                writer.writerow(['Disk Percent', current_metrics['disk'].get('percent'), timestamp])
                writer.writerow(['Disk Health Score', current_metrics['disk'].get('health_score'), timestamp])
            
            writer.writerow(['Overall Health Score', current_metrics.get('overall_health'), timestamp])
            
            content = output.getvalue()
            output.close()
            
            filename = f'system_health_export_{datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")}.csv'
            content_type = 'text/csv'
        
        # Create response
        response = make_response(content)
        response.headers['Content-Type'] = content_type
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        # Log export
        from app.utils.audit_logger import AuditLogger
        AuditLogger.log_admin_action(
            'admin_system_health_export',
            description=f"System health data exported (format: {export_format}, hours: {hours})"
        )
        
        return response
        
    except Exception as e:
        current_app.logger.error(f"System health export error: {e}")
        flash("Error exporting system health data.", "danger")
        return redirect(url_for("admin.system_health"))

# =============================================================================
# Data Export and Backup Management - Task #7
# =============================================================================

@admin_bp.route("/backups")
@login_required
@admin_required
def backup_management():
    """Backup management dashboard."""
    backup_manager = BackupManager()
    
    # Get backup statistics
    stats = backup_manager.get_backup_statistics()
    
    # Get recent backups
    page = request.args.get("page", 1, type=int)
    recent_backups = BackupLog.query.order_by(
        BackupLog.started_at.desc()
    ).paginate(page=page, per_page=20, error_out=False)
    
    # Get backup status counts
    status_counts = db.session.query(
        BackupLog.status,
        func.count(BackupLog.id).label('count')
    ).group_by(BackupLog.status).all()
    
    return render_template(
        "admin/backups.html",
        stats=stats,
        recent_backups=recent_backups,
        status_counts=dict(status_counts)
    )


@admin_bp.route("/backups/create", methods=["POST"])
@login_required
@admin_required
def create_backup():
    """Create a new backup."""
    backup_type = request.form.get("backup_type", "full")
    include_files = request.form.get("include_files") == "on"
    
    backup_manager = BackupManager()
    
    try:
        if backup_type == "full":
            backup_log = backup_manager.create_full_backup(
                user_id=current_user.id,
                include_files=include_files
            )
            flash(f"Full backup created successfully. Backup ID: {backup_log.id}", "success")
        
        elif backup_type == "database_only":
            backup_log = backup_manager.create_database_backup(user_id=current_user.id)
            flash(f"Database backup created successfully. Backup ID: {backup_log.id}", "success")
        
        elif backup_type == "incremental":
            since_date = None
            if request.form.get("since_date"):
                since_date = datetime.strptime(request.form["since_date"], '%Y-%m-%d')
            
            backup_log = backup_manager.create_incremental_backup(
                user_id=current_user.id,
                since_date=since_date
            )
            flash(f"Incremental backup created successfully. Backup ID: {backup_log.id}", "success")
        
        else:
            flash("Invalid backup type.", "error")
            return redirect(url_for("admin.backup_management"))
    
    except Exception as e:
        flash(f"Backup creation failed: {str(e)}", "error")
    
    return redirect(url_for("admin.backup_management"))


@admin_bp.route("/backups/<int:backup_id>/download")
@login_required
@admin_required
def download_backup(backup_id):
    """Download a backup file."""
    backup_log = BackupLog.query.get_or_404(backup_id)
    
    if not backup_log.file_path or not Path(backup_log.file_path).exists():
        flash("Backup file not found.", "error")
        return redirect(url_for("admin.backup_management"))
    
    try:
        from flask import send_file
        filename = f"safevault_backup_{backup_id}_{backup_log.backup_type}.zip"
        return send_file(
            backup_log.file_path,
            as_attachment=True,
            download_name=filename
        )
    except Exception as e:
        flash(f"Download failed: {str(e)}", "error")
        return redirect(url_for("admin.backup_management"))


@admin_bp.route("/backups/<int:backup_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete_backup(backup_id):
    """Delete a backup file."""
    backup_log = BackupLog.query.get_or_404(backup_id)
    
    try:
        # Remove file from disk
        if backup_log.file_path and Path(backup_log.file_path).exists():
            Path(backup_log.file_path).unlink()
        
        # Remove database record
        db.session.delete(backup_log)
        db.session.commit()
        
        AuditLogger.log_admin_action(
            action='admin_backup_delete',
            description=f'Backup deleted: {backup_log.backup_type} (ID: {backup_id})',
            target_type='system'
        )
        
        flash("Backup deleted successfully.", "success")
    
    except Exception as e:
        flash(f"Failed to delete backup: {str(e)}", "error")
    
    return redirect(url_for("admin.backup_management"))


@admin_bp.route("/backups/cleanup", methods=["POST"])
@login_required
@admin_required
def cleanup_old_backups():
    """Clean up old backup files."""
    retention_days = request.form.get("retention_days", 30, type=int)
    
    if retention_days < 1:
        flash("Retention period must be at least 1 day.", "error")
        return redirect(url_for("admin.backup_management"))
    
    backup_manager = BackupManager()
    
    try:
        result = backup_manager.cleanup_old_backups(retention_days)
        
        freed_mb = result['freed_space'] / (1024 * 1024)
        flash(
            f"Cleaned up {result['cleaned_count']} old backups, "
            f"freed {freed_mb:.1f}MB of space.",
            "success"
        )
        
        AuditLogger.log_admin_action(
            action='admin_backup_cleanup',
            description=f"Cleaned up {result['cleaned_count']} backups older than {retention_days} days",
            target_type='system'
        )
    
    except Exception as e:
        flash(f"Cleanup failed: {str(e)}", "error")
    
    return redirect(url_for("admin.backup_management"))


@admin_bp.route("/exports")
@login_required
@admin_required
def data_exports():
    """Data export management dashboard."""
    data_exporter = DataExporter()
    
    # Get export statistics
    stats = data_exporter.get_export_statistics()
    
    # Get recent exports
    page = request.args.get("page", 1, type=int)
    recent_exports = DataExportRequest.query.order_by(
        DataExportRequest.requested_at.desc()
    ).paginate(page=page, per_page=10, error_out=False)
    
    # Get available export types
    export_types = [
        ('user_data', 'User Data'),
        ('audit_logs', 'Audit Logs'),
        ('activity_logs', 'Activity Logs'),
        ('user_sessions', 'User Sessions'),
        ('file_metadata', 'File Metadata'),
        ('system_summary', 'System Summary')
    ]
    
    format_types = [
        ('json', 'JSON'),
        ('csv', 'CSV'),
        ('xlsx', 'Excel'),
        ('xml', 'XML')
    ]
    
    return render_template(
        "admin/data_exports.html",
        stats=stats,
        recent_exports=recent_exports,
        export_types=export_types,
        format_types=format_types
    )


@admin_bp.route("/exports/create", methods=["POST"])
@login_required
@admin_required
def create_data_export():
    """Create a new data export (PDF)."""
    export_type = request.form.get("export_type")

    if not export_type:
        flash("Export type is required.", "error")
        return redirect(url_for("admin.data_exports"))

    # Collect filters
    filters = {}
    if request.form.get("date_from"):
        try:
            filters['date_from'] = datetime.strptime(request.form["date_from"], '%Y-%m-%d')
        except ValueError:
            flash("Invalid 'from' date format.", "error")
            return redirect(url_for("admin.data_exports"))
    if request.form.get("date_to"):
        try:
            filters['date_to'] = datetime.strptime(request.form["date_to"], '%Y-%m-%d')
        except ValueError:
            flash("Invalid 'to' date format.", "error")
            return redirect(url_for("admin.data_exports"))
    if request.form.get("user_filter"):
        filters['user_filter'] = request.form["user_filter"].strip()

    data_exporter = DataExporter()
    try:
        export_request = data_exporter.create_export(
            export_type=export_type,
            format_type='pdf',          # always PDF
            user_id=current_user.id,
            filters=filters,
        )
        flash(
            f"PDF export created — {export_request.records_count} record(s). "
            "Click Download to save the file.",
            "success",
        )
    except Exception as e:
        current_app.logger.error(f"Export creation failed: {e}", exc_info=True)
        flash(f"Export failed: {e}", "error")

    return redirect(url_for("admin.data_exports"))


@admin_bp.route("/exports/<int:export_id>/download")
@login_required
@admin_required
def download_export(export_id):
    """Download an export PDF file."""
    from flask import send_file

    export_request = DataExportRequest.query.get_or_404(export_id)

    if export_request.status != 'completed':
        flash("Export is not ready for download.", "error")
        return redirect(url_for("admin.data_exports"))

    if export_request.is_expired:
        flash("Export has expired and the file has been removed.", "error")
        return redirect(url_for("admin.data_exports"))

    if not export_request.file_path:
        flash("No file path recorded for this export.", "error")
        return redirect(url_for("admin.data_exports"))

    filepath = Path(export_request.file_path)
    if not filepath.exists():
        flash("Export file not found on disk — it may have been cleaned up.", "error")
        return redirect(url_for("admin.data_exports"))

    try:
        export_request.download_count = (export_request.download_count or 0) + 1
        db.session.commit()

        AuditLogger.log_admin_action(
            action='admin_export_download',
            description=f'Export downloaded: {export_request.export_type} (ID {export_id})',
            target_type='system',
        )

        download_name = f"safevault_{export_request.export_type}_{export_request.requested_at.strftime('%Y%m%d')}.pdf"
        return send_file(
            str(filepath),
            mimetype='application/pdf',
            as_attachment=True,
            download_name=download_name,
        )

    except Exception as e:
        current_app.logger.error(f"Export download failed: {e}", exc_info=True)
        flash(f"Download failed: {e}", "error")
        return redirect(url_for("admin.data_exports"))


@admin_bp.route("/exports/<int:export_id>/delete", methods=["POST"])
@login_required
@admin_required
def delete_export(export_id):
    """Delete an export file."""
    export_request = DataExportRequest.query.get_or_404(export_id)
    
    try:
        # Remove file from disk
        if export_request.file_path and Path(export_request.file_path).exists():
            Path(export_request.file_path).unlink()
        
        # Remove database record
        db.session.delete(export_request)
        db.session.commit()
        
        AuditLogger.log_admin_action(
            action='admin_export_delete',
            description=f'Export deleted: {export_request.export_type} (ID: {export_id})',
            target_type='system'
        )
        
        flash("Export deleted successfully.", "success")
    
    except Exception as e:
        flash(f"Failed to delete export: {str(e)}", "error")
    
    return redirect(url_for("admin.data_exports"))


@admin_bp.route("/exports/cleanup", methods=["POST"])
@login_required
@admin_required
def cleanup_expired_exports():
    """Clean up expired export files."""
    data_exporter = DataExporter()
    
    try:
        result = data_exporter.cleanup_expired_exports()
        
        freed_mb = result['freed_space'] / (1024 * 1024)
        flash(
            f"Cleaned up {result['cleaned_count']} expired exports, "
            f"freed {freed_mb:.1f}MB of space.",
            "success"
        )
        
        AuditLogger.log_admin_action(
            action='admin_export_cleanup',
            description=f"Cleaned up {result['cleaned_count']} expired exports",
            target_type='system'
        )
    
    except Exception as e:
        flash(f"Cleanup failed: {str(e)}", "error")
    
    return redirect(url_for("admin.data_exports"))


@admin_bp.route("/backup-restore")
@login_required
@admin_required
def backup_restore():
    """Backup restoration interface (read-only for safety)."""
    # Get available backups
    available_backups = BackupLog.query.filter_by(
        status='completed'
    ).order_by(BackupLog.completed_at.desc()).limit(50).all()
    
    return render_template(
        "admin/backup_restore.html",
        available_backups=available_backups
    )


@admin_bp.route("/backup-restore/<int:backup_id>/verify", methods=["POST"])
@login_required
@admin_required
def verify_backup_integrity(backup_id):
    """Verify backup file integrity."""
    backup_log = BackupLog.query.get_or_404(backup_id)
    backup_manager = BackupManager()
    
    try:
        is_valid = backup_manager._verify_backup_integrity(backup_log)
        
        if is_valid:
            flash(f"Backup integrity verified successfully.", "success")
        else:
            flash(f"Backup integrity check failed! File may be corrupted.", "error")
    
    except Exception as e:
        flash(f"Integrity check failed: {str(e)}", "error")
    
    return redirect(url_for("admin.backup_restore"))


# Scheduled maintenance endpoints for automated backup/cleanup
@admin_bp.route("/api/maintenance/backup", methods=["POST"])
@login_required
@admin_required
def api_scheduled_backup():
    """API endpoint for scheduled backups."""
    backup_manager = BackupManager()
    
    try:
        # Create incremental backup by default for scheduled runs
        backup_log = backup_manager.create_incremental_backup(
            user_id=current_user.id
        )
        
        return jsonify({
            'status': 'success',
            'backup_id': backup_log.id,
            'backup_type': backup_log.backup_type,
            'file_size': backup_log.file_size,
            'items_count': backup_log.items_count
        })
    
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500


@admin_bp.route("/api/maintenance/cleanup", methods=["POST"])
@login_required
@admin_required
def api_scheduled_cleanup():
    """API endpoint for scheduled cleanup operations."""
    backup_manager = BackupManager()
    data_exporter = DataExporter()
    
    try:
        # Clean up old backups (30 days default)
        backup_result = backup_manager.cleanup_old_backups(retention_days=30)
        
        # Clean up expired exports
        export_result = data_exporter.cleanup_expired_exports()
        
        total_freed = backup_result['freed_space'] + export_result['freed_space']
        total_cleaned = backup_result['cleaned_count'] + export_result['cleaned_count']
        
        return jsonify({
            'status': 'success',
            'backups_cleaned': backup_result['cleaned_count'],
            'exports_cleaned': export_result['cleaned_count'],
            'total_cleaned': total_cleaned,
            'total_freed_bytes': total_freed
        })
    
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500