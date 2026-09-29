"""Verify audit_trail.html renders without errors."""
import traceback
from app import create_app
from app.models.user import User

app = create_app()
app.config['TESTING'] = True
app.config['WTF_CSRF_ENABLED'] = False

with app.app_context():
    admin = User.query.filter_by(role='admin').first()
    print(f"Admin: {admin.username}")

    try:
        from datetime import datetime, timedelta, timezone
        from app.utils.audit_viewer import audit_viewer
        from flask import render_template

        quick_filters = audit_viewer.get_quick_filters()
        end_date   = datetime.now(timezone.utc)
        start_date = end_date - timedelta(days=30)
        stats      = audit_viewer.get_audit_statistics(start_date, end_date)
        results    = audit_viewer.search_audit_logs(page=1, per_page=50, sort_by='timestamp', sort_order='desc')

        with app.test_request_context('/admin/audit-trail'):
            html = render_template(
                "admin/audit_trail.html",
                results=results,
                quick_filters=quick_filters,
                stats=stats,
                filters={'page': 1, 'per_page': 50}
            )
        print(f"✅ Rendered OK — {len(html):,} bytes")

        # Spot-check key elements
        checks = [
            ("stats cards",       'Audit Records'      in html),
            ("filter bar",        'filterAction'       in html),
            ("category filter",   'filterCategory'     in html),
            ("status filter",     'filterStatus'       in html),
            ("table header",      'auditTableBody'     in html),
            ("action grouped",    'optgroup'           in html),
            ("detail modal",      'auditDetailModal'   in html),
            ("pagination",        'paginationControls' in html),
        ]
        all_ok = True
        for name, ok in checks:
            icon = "✅" if ok else "❌"
            print(f"  {icon} {name}")
            if not ok:
                all_ok = False

        print("\n✅ All checks passed!" if all_ok else "\n❌ Some checks failed.")

    except Exception as e:
        print(f"❌ Render failed: {e}")
        traceback.print_exc()
