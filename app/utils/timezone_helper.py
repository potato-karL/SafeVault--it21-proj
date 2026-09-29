"""
Timezone handling utilities for SafeVault.
"""
from datetime import datetime
import pytz
from flask import current_app


def get_local_timezone():
    """Get the configured local timezone."""
    try:
        timezone_name = current_app.config.get('TIMEZONE', 'Asia/Manila')
        return pytz.timezone(timezone_name)
    except (AttributeError, pytz.exceptions.UnknownTimeZoneError):
        return pytz.UTC


def utc_to_local(utc_dt):
    """
    Convert a UTC datetime to local timezone.
    
    Args:
        utc_dt: datetime object (assumed to be in UTC)
        
    Returns:
        datetime object converted to local timezone
    """
    if utc_dt is None:
        return None
        
    # If datetime is naive, assume it's UTC
    if utc_dt.tzinfo is None:
        utc_dt = pytz.UTC.localize(utc_dt)
    
    # Convert to local timezone
    local_tz = get_local_timezone()
    local_dt = utc_dt.astimezone(local_tz)
    
    return local_dt


def local_to_utc(local_dt):
    """
    Convert a local datetime to UTC.
    
    Args:
        local_dt: datetime object (assumed to be in local timezone)
        
    Returns:
        datetime object converted to UTC
    """
    if local_dt is None:
        return None
        
    local_tz = get_local_timezone()
    
    # If datetime is naive, assume it's local time
    if local_dt.tzinfo is None:
        local_dt = local_tz.localize(local_dt)
    
    # Convert to UTC
    utc_dt = local_dt.astimezone(pytz.UTC)
    
    return utc_dt


def now_local():
    """Get current datetime in local timezone."""
    utc_now = datetime.utcnow()
    return utc_to_local(utc_now)


def format_local_time(utc_dt, format_str="%Y-%m-%d %H:%M:%S"):
    """
    Format a UTC datetime as local time string.
    
    Args:
        utc_dt: datetime object in UTC
        format_str: strftime format string
        
    Returns:
        Formatted datetime string in local timezone
    """
    if utc_dt is None:
        return ""
        
    local_dt = utc_to_local(utc_dt)
    return local_dt.strftime(format_str)