#!/usr/bin/env python3
"""
Fix database by adding missing columns if they don't exist.
This is safe to run multiple times.
"""

import sqlite3
import os
from datetime import datetime

def fix_database():
    """Add missing columns to the database."""
    db_path = "instance/safevault.db"
    
    if not os.path.exists(db_path):
        print("Database doesn't exist. It will be created when you start the app.")
        return True
    
    print(f"Checking database: {db_path}")
    
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check current table structure
        cursor.execute("PRAGMA table_info(users)")
        existing_columns = [row[1] for row in cursor.fetchall()]
        print(f"Existing columns in users table: {existing_columns}")
        
        columns_to_add = []
        
        # Check which columns need to be added
        if 'storage_quota_bytes' not in existing_columns:
            columns_to_add.append(('storage_quota_bytes', 'BIGINT'))
        
        if 'current_storage_bytes' not in existing_columns:
            columns_to_add.append(('current_storage_bytes', 'BIGINT NOT NULL DEFAULT 0'))
        
        if 'quota_updated_at' not in existing_columns:
            columns_to_add.append(('quota_updated_at', 'DATETIME'))
        
        # Add missing columns
        for column_name, column_type in columns_to_add:
            print(f"Adding column: {column_name} ({column_type})")
            cursor.execute(f"ALTER TABLE users ADD COLUMN {column_name} {column_type}")
        
        # If we added current_storage_bytes, calculate it for existing users
        if any(col[0] == 'current_storage_bytes' for col in columns_to_add):
            print("Calculating current storage usage for existing users...")
            cursor.execute("""
                UPDATE users 
                SET current_storage_bytes = (
                    SELECT COALESCE(SUM(file_size_bytes), 0) 
                    FROM files 
                    WHERE files.user_id = users.id
                )
            """)
        
        # Check if ip_blocklist table exists, create if not
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='ip_blocklist'")
        if not cursor.fetchone():
            print("Creating ip_blocklist table...")
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
            cursor.execute("CREATE INDEX ix_ip_blocklist_ip_address ON ip_blocklist (ip_address)")
        
        conn.commit()
        conn.close()
        
        if columns_to_add:
            print(f"✅ Successfully added {len(columns_to_add)} missing columns!")
        else:
            print("✅ All columns already exist, database is up to date!")
        
        return True
        
    except Exception as e:
        print(f"❌ Error fixing database: {e}")
        if 'conn' in locals():
            conn.rollback()
            conn.close()
        return False

if __name__ == "__main__":
    print("SafeVault Database Fix")
    print("=" * 30)
    if fix_database():
        print("\n🎉 Database fix completed!")
        print("You can now start the application with: python run.py")
    else:
        print("\n❌ Database fix failed!")
        print("You may need to delete instance/safevault.db and let the app recreate it.")