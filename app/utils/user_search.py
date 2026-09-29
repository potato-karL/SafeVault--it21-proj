"""
Advanced User Search and Filtering for SafeVault
Provides comprehensive user search, filtering, and pagination capabilities
"""

from datetime import datetime, timezone, timedelta
from flask import request
from app.models.user import User
from app.models.file import File
from app.models.user_session import UserSession
from app import db
from sqlalchemy import func, and_, or_, desc, asc
import json

class UserSearchFilter:
    """Handles advanced user search and filtering operations"""
    
    def __init__(self):
        self.valid_sort_fields = [
            'id', 'username', 'email', 'created_at', 'last_login', 
            'storage_used', 'storage_quota', 'failed_logins', 'is_active_account'
        ]
        self.valid_sort_orders = ['asc', 'desc']
    
    def search_users(self, **filters):
        """
        Search users with advanced filtering and pagination
        
        Args:
            **filters: Dictionary of filter criteria
            
        Returns:
            dict: Search results with pagination info
        """
        try:
            # Start with base query
            query = User.query
            
            # Apply filters
            query = self._apply_filters(query, filters)
            
            # Get total count before pagination
            total_count = query.count()
            
            # Apply sorting
            query = self._apply_sorting(query, filters)
            
            # Apply pagination
            page = filters.get('page', 1)
            per_page = min(filters.get('per_page', 20), 100)  # Max 100 per page
            
            paginated = query.paginate(
                page=page,
                per_page=per_page,
                error_out=False
            )
            
            # Enhance users with additional data if requested
            users_data = []
            include_stats = filters.get('include_stats', False)
            
            for user in paginated.items:
                user_data = self._format_user_data(user, include_stats)
                users_data.append(user_data)
            
            return {
                'users': users_data,
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
            return {
                'error': f'Search failed: {str(e)}',
                'users': [],
                'pagination': {},
                'total_count': 0
            }
    
    def _apply_filters(self, query, filters):
        """Apply various filters to the user query"""
        
        # Text search (username, email)
        search_text = filters.get('search', '').strip()
        if search_text:
            search_pattern = f'%{search_text}%'
            query = query.filter(
                or_(
                    User.username.ilike(search_pattern),
                    User.email.ilike(search_pattern)
                )
            )
        
        # Account status filter
        if 'is_active' in filters:
            is_active = filters['is_active']
            if is_active in ['true', '1', True]:
                query = query.filter(User.is_active_account == True)
            elif is_active in ['false', '0', False]:
                query = query.filter(User.is_active_account == False)
        
        # Admin status filter
        if 'is_admin' in filters:
            is_admin = filters['is_admin']
            if is_admin in ['true', '1', True]:
                query = query.filter(User.is_admin == True)
            elif is_admin in ['false', '0', False]:
                query = query.filter(User.is_admin == False)
        
        # 2FA status filter
        if 'has_2fa' in filters:
            has_2fa = filters['has_2fa']
            if has_2fa in ['true', '1', True]:
                query = query.filter(User.totp_enabled == True)
            elif has_2fa in ['false', '0', False]:
                query = query.filter(User.totp_enabled == False)
        
        # Registration date range
        if 'created_after' in filters:
            try:
                created_after = datetime.fromisoformat(filters['created_after'].replace('Z', '+00:00'))
                query = query.filter(User.created_at >= created_after)
            except (ValueError, AttributeError):
                pass
        
        if 'created_before' in filters:
            try:
                created_before = datetime.fromisoformat(filters['created_before'].replace('Z', '+00:00'))
                query = query.filter(User.created_at <= created_before)
            except (ValueError, AttributeError):
                pass
        
        # Last login date range
        if 'last_login_after' in filters:
            try:
                last_login_after = datetime.fromisoformat(filters['last_login_after'].replace('Z', '+00:00'))
                query = query.filter(User.last_login >= last_login_after)
            except (ValueError, AttributeError):
                pass
        
        if 'last_login_before' in filters:
            try:
                last_login_before = datetime.fromisoformat(filters['last_login_before'].replace('Z', '+00:00'))
                query = query.filter(User.last_login <= last_login_before)
            except (ValueError, AttributeError):
                pass
        
        # Never logged in filter
        if 'never_logged_in' in filters and filters['never_logged_in'] in ['true', '1', True]:
            query = query.filter(User.last_login.is_(None))
        
        # Storage usage filters
        if 'storage_min' in filters:
            try:
                storage_min = int(filters['storage_min']) * 1024 * 1024  # Convert MB to bytes
                query = query.filter(User.current_storage_bytes >= storage_min)
            except (ValueError, TypeError):
                pass
        
        if 'storage_max' in filters:
            try:
                storage_max = int(filters['storage_max']) * 1024 * 1024  # Convert MB to bytes
                query = query.filter(User.current_storage_bytes <= storage_max)
            except (ValueError, TypeError):
                pass
        
        # Storage quota filters
        if 'has_quota' in filters:
            has_quota = filters['has_quota']
            if has_quota in ['true', '1', True]:
                query = query.filter(User.storage_quota_bytes.isnot(None))
            elif has_quota in ['false', '0', False]:
                query = query.filter(User.storage_quota_bytes.is_(None))
        
        # Failed login attempts
        if 'failed_logins_min' in filters:
            try:
                failed_min = int(filters['failed_logins_min'])
                query = query.filter(User.failed_login_attempts >= failed_min)
            except (ValueError, TypeError):
                pass
        
        # Locked out users
        if 'is_locked' in filters and filters['is_locked'] in ['true', '1', True]:
            query = query.filter(User.failed_login_attempts >= 3)  # Assuming 3 is lockout threshold
        
        # Users with files
        if 'has_files' in filters:
            has_files = filters['has_files']
            if has_files in ['true', '1', True]:
                query = query.filter(User.id.in_(
                    db.session.query(File.user_id).distinct()
                ))
            elif has_files in ['false', '0', False]:
                query = query.filter(~User.id.in_(
                    db.session.query(File.user_id).distinct()
                ))
        
        # File count filters
        if 'file_count_min' in filters or 'file_count_max' in filters:
            # Subquery to count files per user
            file_count_subquery = db.session.query(
                File.user_id,
                func.count(File.id).label('file_count')
            ).group_by(File.user_id).subquery()
            
            query = query.outerjoin(file_count_subquery, User.id == file_count_subquery.c.user_id)
            
            if 'file_count_min' in filters:
                try:
                    file_count_min = int(filters['file_count_min'])
                    query = query.filter(
                        func.coalesce(file_count_subquery.c.file_count, 0) >= file_count_min
                    )
                except (ValueError, TypeError):
                    pass
            
            if 'file_count_max' in filters:
                try:
                    file_count_max = int(filters['file_count_max'])
                    query = query.filter(
                        func.coalesce(file_count_subquery.c.file_count, 0) <= file_count_max
                    )
                except (ValueError, TypeError):
                    pass
        
        # IP address filter
        if 'ip_address' in filters:
            ip_pattern = f'%{filters["ip_address"]}%'
            query = query.filter(User.last_login_ip.ilike(ip_pattern))
        
        # Active sessions filter
        if 'has_active_sessions' in filters:
            has_sessions = filters['has_active_sessions']
            active_session_user_ids = db.session.query(UserSession.user_id).filter(
                UserSession.is_active == True
            ).distinct().subquery()
            
            if has_sessions in ['true', '1', True]:
                query = query.filter(User.id.in_(active_session_user_ids))
            elif has_sessions in ['false', '0', False]:
                query = query.filter(~User.id.in_(active_session_user_ids))
        
        return query
    
    def _apply_sorting(self, query, filters):
        """Apply sorting to the query"""
        sort_by = filters.get('sort_by', 'created_at')
        sort_order = filters.get('sort_order', 'desc')
        
        # Validate sort parameters
        if sort_by not in self.valid_sort_fields:
            sort_by = 'created_at'
        
        if sort_order not in self.valid_sort_orders:
            sort_order = 'desc'
        
        # Apply sorting
        if hasattr(User, sort_by):
            sort_column = getattr(User, sort_by)
            if sort_order == 'desc':
                query = query.order_by(desc(sort_column))
            else:
                query = query.order_by(asc(sort_column))
        
        # Secondary sort by ID for consistency
        query = query.order_by(User.id)
        
        return query
    
    def _format_user_data(self, user, include_stats=False):
        """Format user data for response"""
        user_data = {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'is_active_account': user.is_active_account,
            'is_admin': user.is_admin,
            'totp_enabled': user.totp_enabled,
            'created_at': user.created_at.isoformat() if user.created_at else None,
            'last_login': user.last_login.isoformat() if user.last_login else None,
            'last_login_ip': user.last_login_ip,
            'failed_login_attempts': user.failed_login_attempts or 0,
            'current_storage_bytes': user.current_storage_bytes or 0,
            'storage_quota_bytes': user.storage_quota_bytes,
            'is_locked_out': user.is_locked_out(),
            'storage_used_mb': round((user.current_storage_bytes or 0) / (1024 * 1024), 2),
            'storage_quota_mb': round((user.storage_quota_bytes or 0) / (1024 * 1024), 2) if user.storage_quota_bytes else None
        }
        
        if include_stats:
            # Add additional statistics
            user_data.update(self._get_user_statistics(user))
        
        return user_data
    
    def _get_user_statistics(self, user):
        """Get additional statistics for a user"""
        try:
            # File statistics
            file_count = File.query.filter_by(user_id=user.id).count()
            total_file_size = db.session.query(func.sum(File.size)).filter_by(user_id=user.id).scalar() or 0
            
            # Session statistics
            active_sessions = UserSession.get_active_sessions_for_user(user.id)
            total_sessions = UserSession.query.filter_by(user_id=user.id).count()
            
            # Recent activity
            recent_login = user.last_login and user.last_login > (datetime.now(timezone.utc) - timedelta(days=30))
            
            return {
                'file_count': file_count,
                'total_file_size': total_file_size,
                'active_sessions_count': len(active_sessions),
                'total_sessions_count': total_sessions,
                'recent_activity': recent_login,
                'days_since_created': (datetime.now(timezone.utc) - user.created_at).days if user.created_at else None,
                'days_since_last_login': (datetime.now(timezone.utc) - user.last_login).days if user.last_login else None
            }
            
        except Exception as e:
            return {
                'file_count': 0,
                'total_file_size': 0,
                'active_sessions_count': 0,
                'total_sessions_count': 0,
                'recent_activity': False,
                'days_since_created': None,
                'days_since_last_login': None,
                'stats_error': str(e)
            }
    
    def _get_applied_filters(self, filters):
        """Get summary of applied filters for display"""
        applied = []
        
        if filters.get('search'):
            applied.append(f"Text search: '{filters['search']}'")
        
        if 'is_active' in filters:
            status = 'Active' if filters['is_active'] in ['true', '1', True] else 'Inactive'
            applied.append(f"Status: {status}")
        
        if 'is_admin' in filters:
            admin_status = 'Admin' if filters['is_admin'] in ['true', '1', True] else 'Regular user'
            applied.append(f"Role: {admin_status}")
        
        if 'has_2fa' in filters:
            tfa_status = 'Enabled' if filters['has_2fa'] in ['true', '1', True] else 'Disabled'
            applied.append(f"2FA: {tfa_status}")
        
        if filters.get('created_after'):
            applied.append(f"Created after: {filters['created_after']}")
        
        if filters.get('created_before'):
            applied.append(f"Created before: {filters['created_before']}")
        
        if filters.get('storage_min'):
            applied.append(f"Storage >= {filters['storage_min']} MB")
        
        if filters.get('storage_max'):
            applied.append(f"Storage <= {filters['storage_max']} MB")
        
        if filters.get('has_quota') in ['true', '1', True]:
            applied.append("Has storage quota")
        elif filters.get('has_quota') in ['false', '0', False]:
            applied.append("No storage quota")
        
        if filters.get('is_locked') in ['true', '1', True]:
            applied.append("Account locked")
        
        if filters.get('never_logged_in') in ['true', '1', True]:
            applied.append("Never logged in")
        
        return applied
    
    def get_filter_suggestions(self):
        """Get suggestions for filter values"""
        try:
            suggestions = {
                'storage_ranges': [
                    {'label': '0-10 MB', 'min': 0, 'max': 10},
                    {'label': '10-100 MB', 'min': 10, 'max': 100},
                    {'label': '100MB-1GB', 'min': 100, 'max': 1024},
                    {'label': '1GB+', 'min': 1024, 'max': None}
                ],
                'date_ranges': [
                    {'label': 'Last 7 days', 'days': 7},
                    {'label': 'Last 30 days', 'days': 30},
                    {'label': 'Last 90 days', 'days': 90},
                    {'label': 'Last year', 'days': 365}
                ],
                'common_searches': [
                    'Admin users',
                    'Inactive accounts',
                    'Users without 2FA',
                    'Locked accounts',
                    'Users with no files',
                    'High storage usage'
                ]
            }
            
            return suggestions
            
        except Exception as e:
            return {'error': str(e)}
    
    def export_search_results(self, search_results, format='csv'):
        """Export search results to CSV or JSON"""
        try:
            if format == 'csv':
                return self._export_to_csv(search_results)
            elif format == 'json':
                return self._export_to_json(search_results)
            else:
                raise ValueError(f"Unsupported export format: {format}")
                
        except Exception as e:
            raise Exception(f"Export failed: {str(e)}")
    
    def _export_to_csv(self, search_results):
        """Export search results to CSV"""
        import csv
        import io
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            'ID', 'Username', 'Email', 'Active', 'Admin', '2FA Enabled',
            'Created At', 'Last Login', 'Storage Used (MB)', 'Storage Quota (MB)',
            'Failed Logins', 'Is Locked', 'File Count', 'Active Sessions'
        ])
        
        # Write data
        for user in search_results.get('users', []):
            writer.writerow([
                user['id'],
                user['username'],
                user['email'],
                user['is_active_account'],
                user['is_admin'],
                user['totp_enabled'],
                user['created_at'],
                user['last_login'],
                user['storage_used_mb'],
                user['storage_quota_mb'],
                user['failed_login_attempts'],
                user['is_locked_out'],
                user.get('file_count', ''),
                user.get('active_sessions_count', '')
            ])
        
        csv_content = output.getvalue()
        output.close()
        
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        filename = f'user_search_results_{timestamp}.csv'
        
        return csv_content, filename
    
    def _export_to_json(self, search_results):
        """Export search results to JSON"""
        export_data = {
            'export_info': {
                'exported_at': datetime.now(timezone.utc).isoformat(),
                'total_results': search_results.get('total_count', 0),
                'filters_applied': search_results.get('filters_applied', []),
                'search_time': search_results.get('search_time')
            },
            'results': search_results
        }
        
        json_content = json.dumps(export_data, indent=2, default=str)
        
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')
        filename = f'user_search_results_{timestamp}.json'
        
        return json_content, filename


class SavedSearch:
    """Manages saved search configurations"""
    
    @staticmethod
    def save_search(name, filters, user_id):
        """Save a search configuration (placeholder for future implementation)"""
        # This would typically save to database
        # For now, we'll return a simple response
        return {
            'saved': True,
            'search_id': f"search_{int(datetime.now().timestamp())}",
            'name': name,
            'filters': filters
        }
    
    @staticmethod
    def load_search(search_id, user_id):
        """Load a saved search configuration"""
        # Placeholder implementation
        return {'error': 'Saved searches not yet implemented'}
    
    @staticmethod
    def list_saved_searches(user_id):
        """List saved searches for a user"""
        # Placeholder implementation
        return []


# Global search filter instance
user_search_filter = UserSearchFilter()