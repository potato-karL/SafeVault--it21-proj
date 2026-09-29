#!/usr/bin/env python3
"""
Migration script to add backup and export management tables.
This adds the BackupLog and DataExportRequest models for Task #7.
"""
import os
import sys
import sqlite3
from datetime import datetime, timezone

def create_backup_logs_table(cursor):
    """Create the backup_logs table."""
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS backup_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            backup_type VARCHAR(50) NOT NULL,
            status VARCHAR(20) NOT NULL,
            started_at DATETIME NOT NULL,
            completed_at DATETIME,
            file_path VARCHAR(500),
            file_size BIGINT,
            checksum VARCHAR(128),
            error_message TEXT,
            items_count INTEGER DEFAULT 0,
            compressed_size BIGINT,
            compression_ratio FLOAT,
            initiated_by INTEGER NOT NULL,
            backup_metadata TEXT,
            FOREIGN KEY (initiated_by) REFERENCES users(id)
        )
    """)
    print("✓ Created backup_logs table")

def create_data_export_requests_table(cursor):
    """Create the data_export_requests table."""
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS data_export_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            export_type VARCHAR(50) NOT NULL,
            format_type VARCHAR(20) NOT NULL,
            status VARCHAR(20) NOT NULL DEFAULT 'pending',
            requested_at DATETIME NOT NULL,
            processed_at DATETIME,
            expires_at DATETIME,
            date_from DATETIME,
            date_to DATETIME,
            user_filter VARCHAR(200),
            additional_filters TEXT,
            file_path VARCHAR(500),
            file_size BIGINT,
            records_count INTEGER DEFAULT 0,
            error_message TEXT,
            requested_by INTEGER NOT NULL,
            download_count INTEGER DEFAULT 0,
            FOREIGN KEY (requested_by) REFERENCES users(id)
        )
    """)
    print("✓ Created data_export_requests table")

def create_indexes(cursor):
    """Create indexes for better performance."""
    indexes = [
        ("idx_backup_logs_status", "backup_logs", "status"),
        ("idx_backup_logs_started_at", "backup_logs", "started_at"),
        ("idx_backup_logs_backup_type", "backup_logs", "backup_type"),
        ("idx_backup_logs_initiated_by", "backup_logs", "initiated_by"),
        ("idx_data_export_requests_status", "data_export_requests", "status"),
        ("idx_data_export_requests_requested_at", "data_export_requests", "requested_at"),
        ("idx_data_export_requests_export_type", "data_export_requests", "export_type"),
        ("idx_data_export_requests_requested_by", "data_export_requests", "requested_by"),
        ("idx_data_export_requests_expires_at", "data_export_requests", "expires_at"),
    ]
    
    for index_name, table_name, column_name in indexes:
        try:
            cursor.execute(f"CREATE INDEX IF NOT EXISTS {index_name} ON {table_name}({column_name})")
            print(f"✓ Created index {index_name}")
        except sqlite3.Error as e:
            print(f"⚠ Warning: Could not create index {index_name}: {e}")

def check_existing_tables(cursor):
    """Check if tables already exist."""
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name IN ('backup_logs', 'data_export_requests')")
    existing_tables = [row[0] for row in cursor.fetchall()]
    return existing_tables

def main():
    # Determine database path
    if os.path.exists('instance/safevault.db'):
        db_path = 'instance/safevault.db'
    elif os.path.exists('safevault.db'):
        db_path = 'safevault.db'
    else:
        print("❌ Error: Could not find database file (safevault.db or instance/safevault.db)")
        sys.exit(1)
    
    print(f"🔧 Migrating database: {db_path}")
    print(f"📅 Migration started at: {datetime.now(timezone.utc)}")
    
    try:
        # Create backup of database
        import shutil
        backup_path = f"{db_path}.backup.{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        shutil.copy2(db_path, backup_path)
        print(f"✓ Created database backup: {backup_path}")
        
        # Connect to database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check existing tables
        existing_tables = check_existing_tables(cursor)
        if existing_tables:
            print(f"ℹ Found existing tables: {', '.join(existing_tables)}")
            response = input("Continue with migration? Some tables may already exist. (y/N): ").strip().lower()
            if response != 'y':
                print("❌ Migration cancelled by user")
                sys.exit(0)
        
        # Begin transaction
        cursor.execute("BEGIN TRANSACTION")
        
        # Create tables
        create_backup_logs_table(cursor)
        create_data_export_requests_table(cursor)
        
        # Create indexes
        create_indexes(cursor)
        
        # Commit transaction
        conn.commit()
        
        print("✅ Migration completed successfully!")
        print("\n📊 New tables added:")
        print("   • backup_logs - For tracking backup operations")
        print("   • data_export_requests - For tracking data export requests")
        print("\n🔧 Next steps:")
        print("   1. Restart SafeVault application")
        print("   2. Access Admin Panel > Backup Management")
        print("   3. Access Admin Panel > Data Export Management")
        
    except sqlite3.Error as e:
        print(f"❌ Database error: {e}")
        try:
            conn.rollback()
            print("🔄 Transaction rolled back")
        except:
            pass
        sys.exit(1)
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        try:
            conn.rollback()
            print("🔄 Transaction rolled back")
        except:
            pass
        sys.exit(1)
    finally:
        if 'conn' in locals():
            conn.close()

if __name__ == "__main__":
    print("=" * 60)
    print("SafeVault Backup & Export Management Migration")
    print("Adding backup_logs and data_export_requests tables")
    print("=" * 60)
    main()