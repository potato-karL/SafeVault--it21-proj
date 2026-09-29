#!/usr/bin/env python3
"""
Migration script to add storage quota columns to existing SafeVault database.
Run this script if you have existing data and want to preserve it.

Usage: python scripts/migrate_add_storage_quotas.py
"""

import os
import sys
import sqlite3
from pathlib import Path

def add_storage_quota_columns():
    """Add storage quota columns to the users table."""
    
    # Get the database path
    db_path = Path(__file__).parent.parent / "instance" / "safevault.db"
    
    if not db_path.exists():
        print("Database not found. Please run the application first to create the initial database.")
        return False
    
    print(f"Adding storage quota columns to database: {db_path}")
    
    try:
        # Connect to database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if columns already exist
        cursor.execute("PRAGMA table_info(users)")
        columns = [row[1] for row in cursor.fetchall()]
        
        if 'storage_quota_bytes' in columns:
            print("Storage quota columns already exist. Migration not needed.")
            conn.close()
            return True
        
        # Add new columns
        print("Adding storage_quota_bytes column...")
        cursor.execute("ALTER TABLE users ADD COLUMN storage_quota_bytes BIGINT")
        
        print("Adding current_storage_bytes column...")
        cursor.execute("ALTER TABLE users ADD COLUMN current_storage_bytes BIGINT NOT NULL DEFAULT 0")
        
        print("Adding quota_updated_at column...")
        cursor.execute("ALTER TABLE users ADD COLUMN quota_updated_at DATETIME")
        
        # Calculate current storage usage for existing users
        print("Calculating current storage usage for existing users...")
        cursor.execute("""
            UPDATE users 
            SET current_storage_bytes = (
                SELECT COALESCE(SUM(file_size_bytes), 0) 
                FROM files 
                WHERE files.user_id = users.id
            )
        """)
        
        # Commit changes
        conn.commit()
        conn.close()
        
        print("✅ Migration completed successfully!")
        print("\nNew columns added:")
        print("- storage_quota_bytes: Storage limit in bytes (NULL = unlimited)")
        print("- current_storage_bytes: Current usage in bytes")
        print("- quota_updated_at: Timestamp of last quota change")
        
        return True
        
    except sqlite3.Error as e:
        print(f"❌ Database error: {e}")
        if 'conn' in locals():
            conn.rollback()
            conn.close()
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

def add_ip_blocklist_table():
    """Add IP blocklist table if it doesn't exist."""
    
    db_path = Path(__file__).parent.parent / "instance" / "safevault.db"
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if table exists
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ip_blocklist'")
        if cursor.fetchone():
            print("IP blocklist table already exists.")
            conn.close()
            return True
        
        print("Creating IP blocklist table...")
        cursor.execute("""
            CREATE TABLE ip_blocklist (
                id INTEGER NOT NULL PRIMARY KEY,
                ip_address VARCHAR(45) NOT NULL UNIQUE,
                blocked_at DATETIME NOT NULL,
                blocked_until DATETIME,
                reason VARCHAR(255) NOT NULL,
                is_automatic BOOLEAN NOT NULL DEFAULT 1,
                failed_attempts INTEGER NOT NULL DEFAULT 0,
                blocked_by_user_id INTEGER,
                unblocked_by_user_id INTEGER,
                unblocked_at DATETIME,
                FOREIGN KEY(blocked_by_user_id) REFERENCES users (id),
                FOREIGN KEY(unblocked_by_user_id) REFERENCES users (id)
            )
        """)
        
        # Create index on ip_address for faster lookups
        cursor.execute("CREATE INDEX ix_ip_blocklist_ip_address ON ip_blocklist (ip_address)")
        
        conn.commit()
        conn.close()
        
        print("✅ IP blocklist table created successfully!")
        return True
        
    except sqlite3.Error as e:
        print(f"❌ Database error creating IP blocklist table: {e}")
        if 'conn' in locals():
            conn.rollback()
            conn.close()
        return False

def main():
    """Run the migration."""
    print("SafeVault Storage Quota Migration")
    print("=" * 40)
    
    # Add storage quota columns
    if not add_storage_quota_columns():
        sys.exit(1)
    
    print()
    
    # Add IP blocklist table
    if not add_ip_blocklist_table():
        sys.exit(1)
    
    print("\n🎉 All migrations completed successfully!")
    print("\nYou can now:")
    print("1. Start the SafeVault application")
    print("2. Access the admin panel to manage storage quotas")
    print("3. Configure IP auto-ban settings in the Security Center")

if __name__ == "__main__":
    main()