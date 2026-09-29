"""
Migration script to add user_sessions table to SafeVault database
Run this script to add session tracking capabilities
"""

import os
import sys
import sqlite3
from datetime import datetime, timezone

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def add_user_sessions_table():
    """Add user_sessions table to the database"""
    
    # Database path
    db_path = os.path.join('instance', 'safevault.db')
    
    if not os.path.exists(db_path):
        print(f"Error: Database file not found at {db_path}")
        print("Make sure you're running this script from the project root directory")
        return False
    
    print(f"Adding user_sessions table to database: {db_path}")
    
    try:
        # Connect to database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if table already exists
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name='user_sessions'
        """)
        
        if cursor.fetchone():
            print("user_sessions table already exists!")
            conn.close()
            return True
        
        # Create user_sessions table
        cursor.execute("""
            CREATE TABLE user_sessions (
                id VARCHAR(36) PRIMARY KEY,
                user_id INTEGER NOT NULL,
                created_at DATETIME NOT NULL,
                last_activity DATETIME NOT NULL,
                expires_at DATETIME,
                is_active BOOLEAN NOT NULL DEFAULT 1,
                ip_address VARCHAR(45) NOT NULL,
                user_agent TEXT,
                device_type VARCHAR(50),
                device_brand VARCHAR(50),
                device_model VARCHAR(100),
                browser_family VARCHAR(50),
                browser_version VARCHAR(50),
                os_family VARCHAR(50),
                os_version VARCHAR(50),
                country VARCHAR(2),
                region VARCHAR(100),
                city VARCHAR(100),
                login_method VARCHAR(20) DEFAULT 'password',
                is_suspicious BOOLEAN NOT NULL DEFAULT 0,
                risk_score INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users (id)
            )
        """)
        
        # Create indexes for better performance
        cursor.execute("""
            CREATE INDEX idx_user_sessions_user_id ON user_sessions (user_id)
        """)
        
        cursor.execute("""
            CREATE INDEX idx_user_sessions_active ON user_sessions (is_active)
        """)
        
        cursor.execute("""
            CREATE INDEX idx_user_sessions_last_activity ON user_sessions (last_activity)
        """)
        
        cursor.execute("""
            CREATE INDEX idx_user_sessions_ip_address ON user_sessions (ip_address)
        """)
        
        # Commit changes
        conn.commit()
        print("✓ Created user_sessions table")
        print("✓ Created database indexes")
        
        # Verify table creation
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='user_sessions'")
        if cursor.fetchone():
            print("✓ user_sessions table verified successfully")
        else:
            print("✗ Error: Table creation verification failed")
            return False
        
        conn.close()
        print("\n✓ Database migration completed successfully!")
        print("\nNext steps:")
        print("1. Install new dependencies: pip install user-agents geoip2")
        print("2. Restart your application")
        print("3. Session tracking will be automatically enabled")
        
        return True
        
    except sqlite3.Error as e:
        print(f"✗ Database error: {e}")
        if 'conn' in locals():
            conn.rollback()
            conn.close()
        return False
    
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        if 'conn' in locals():
            conn.close()
        return False

def main():
    print("SafeVault User Sessions Migration")
    print("=" * 35)
    
    if add_user_sessions_table():
        print("\nMigration completed successfully! 🎉")
    else:
        print("\nMigration failed! ❌")
        sys.exit(1)

if __name__ == "__main__":
    main()