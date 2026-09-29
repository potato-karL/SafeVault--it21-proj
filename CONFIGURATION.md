# SafeVault Configuration Guide

This document describes the environment variables available to configure SafeVault's security and storage features.

## Environment Variables

### Basic Security
- `SAFEVAULT_SECRET_KEY`: Flask secret key (required in production)
- `SAFEVAULT_FORCE_HTTPS`: Set to "true" to enforce HTTPS (`false` by default)

### IP Auto-Ban System
- `SAFEVAULT_IP_AUTO_BAN_ATTEMPTS`: Number of failed login attempts before IP auto-ban (default: `10`)
- `SAFEVAULT_IP_AUTO_BAN_DURATION`: Auto-ban duration in minutes (default: `60`)
- `SAFEVAULT_IP_WINDOW_MINUTES`: Time window for counting failed attempts in minutes (default: `30`)

### Storage Quotas
- `SAFEVAULT_DEFAULT_QUOTA_MB`: Default storage quota for new users in MB (default: unlimited)
- `SAFEVAULT_QUOTA_WARNING_PERCENT`: Percentage at which to show quota warnings (default: `80`)
- `SAFEVAULT_QUOTA_CRITICAL_PERCENT`: Percentage at which quota usage becomes critical (default: `90`)

### Global Storage Monitoring
- `SAFEVAULT_GLOBAL_WARNING_GB`: Global storage warning threshold in GB (default: `10`)
- `SAFEVAULT_GLOBAL_CRITICAL_GB`: Global storage critical threshold in GB (default: `20`)

## Example Configuration

### Development Environment (.env file)
```bash
# Basic settings
SAFEVAULT_SECRET_KEY=your-secret-key-here
SAFEVAULT_FORCE_HTTPS=false

# Moderate security settings for development
SAFEVAULT_IP_AUTO_BAN_ATTEMPTS=5
SAFEVAULT_IP_AUTO_BAN_DURATION=30
SAFEVAULT_IP_WINDOW_MINUTES=15

# User quotas
SAFEVAULT_DEFAULT_QUOTA_MB=100
SAFEVAULT_QUOTA_WARNING_PERCENT=75
SAFEVAULT_QUOTA_CRITICAL_PERCENT=85
```

### Production Environment
```bash
# Production security
SAFEVAULT_SECRET_KEY=long-random-production-key
SAFEVAULT_FORCE_HTTPS=true

# Strict security settings
SAFEVAULT_IP_AUTO_BAN_ATTEMPTS=3
SAFEVAULT_IP_AUTO_BAN_DURATION=120
SAFEVAULT_IP_WINDOW_MINUTES=10

# Storage management
SAFEVAULT_DEFAULT_QUOTA_MB=50
SAFEVAULT_QUOTA_WARNING_PERCENT=80
SAFEVAULT_QUOTA_CRITICAL_PERCENT=90

# Global monitoring
SAFEVAULT_GLOBAL_WARNING_GB=50
SAFEVAULT_GLOBAL_CRITICAL_GB=100
```

## Security Recommendations

### IP Auto-Ban Settings
- **Development**: Use lenient settings (5+ attempts, shorter bans) to avoid locking yourself out
- **Production**: Use strict settings (3 attempts, longer bans) for better security
- **High-Security**: Consider permanent bans or very long durations for critical environments

### Storage Quotas
- **Individual Users**: Start with 50-100MB quotas and adjust based on usage patterns
- **Organizations**: Set quotas based on user roles (e.g., 100MB for regular users, 500MB for managers)
- **Warning Thresholds**: 80% provides good advance warning, 90% indicates urgent action needed

## Admin Access

Admins can override these settings through the web interface:
- **Security Center** (`/admin/security`): Manage IP blocks and security metrics
- **Storage Management** (`/admin/storage`): Set individual and bulk storage quotas
- **User Management** (`/admin/storage/users`): Monitor individual user storage usage

## Default Values

If no environment variables are set, SafeVault uses these safe defaults:
- IP auto-ban after 10 failed attempts in 30 minutes
- 60-minute auto-ban duration
- No default storage quotas (unlimited)
- Warning at 80% quota usage, critical at 90%

## Notes

1. **IP Auto-Ban**: Only affects failed login attempts. Successful logins reset the counter.
2. **Storage Quotas**: Existing users are not affected by `SAFEVAULT_DEFAULT_QUOTA_MB` changes.
3. **Global Thresholds**: Currently informational only; automatic cleanup not implemented.
4. **Configuration Changes**: Most settings require application restart to take effect.