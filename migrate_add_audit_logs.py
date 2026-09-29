"""
Migration script to add audit_logs table to SafeVault database
Run this script to add comprehensive audit trail capabilities
"""

import os
import sys
import sqlite3
from datetime import datetime, timezone

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def add_audit_logs_table():
    """Add audit_logs table to the database"""
    
    # Database path
    db_path = os.path.join('instance', 'safevault.db')
    
    if not os.path.exists(db_path):
        print(f"Error: Database file not found at {db_path}")
        print("Make sure you're running this script from the project root directory")
        return False
    
    print(f"Adding audit_logs table to database: {db_path}")
    
    try:
        # Connect to database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if table already exists
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name='audit_logs'
        """)
        
        if cursor.fetchone():
            print("audit_logs table already exists!")
            conn.close()
            return True
        
        # Create audit_logs table
        cursor.execute("""
            CREATE TABLE audit_logs (
                id VARCHAR(36) PRIMARY KEY,
                timestamp DATETIME NOT NULL,
                action VARCHAR(50) NOT NULL,
                category VARCHAR(20) NOT NULL,
                level VARCHAR(10) NOT NULL DEFAULT 'info',
                status VARCHAR(20) NOT NULL DEFAULT 'success',
                user_id INTEGER,
                username VARCHAR(80),
                session_id VARCHAR(36),
                ip_address VARCHAR(45),
                user_agent TEXT,
                endpoint VARCHAR(100),
                method VARCHAR(10),
                target_type VARCHAR(50),
                target_id VARCHAR(100),
                target_name VARCHAR(255),
                description TEXT,
                details TEXT,
                risk_level INTEGER NOT NULL DEFAULT 0,
                is_suspicious BOOLEAN NOT NULL DEFAULT 0,
                duration_ms INTEGER,
                result_code VARCHAR(20),
                FOREIGN KEY (user_id) REFERENCES users (id),
                FOREIGN KEY (session_id) REFERENCES user_sessions (id)
            )
        """)
        
        # Create indexes for better performance
        indexes = [
            "CREATE INDEX idx_audit_logs_timestamp ON audit_logs (timestamp)",
            "CREATE INDEX idx_audit_logs_user_id ON audit_logs (user_id)",
            "CREATE INDEX idx_audit_logs_action ON audit_logs (action)",
            "CREATE INDEX idx_audit_logs_category ON audit_logs (category)",
            "CREATE INDEX idx_audit_logs_level ON audit_logs (level)",
            "CREATE INDEX idx_audit_logs_ip_address ON audit_logs (ip_address)",
            "CREATE INDEX idx_audit_logs_status ON audit_logs (status)",
            "CREATE INDEX idx_audit_logs_is_suspicious ON audit_logs (is_suspicious)",
            "CREATE INDEX idx_audit_logs_risk_level ON audit_logs (risk_level)",
            "CREATE INDEX idx_audit_logs_target_type ON audit_logs (target_type)",
            "CREATE INDEX idx_audit_logs_session_id ON audit_logs (session_id)"
        ]
        
        for index_sql in indexes:
            cursor.execute(index_sql)
        
        # Commit changes
        conn.commit()
        print("✓ Created audit_logs table")
        print("✓ Created database indexes")
        
        # Verify table creation
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='audit_logs'")
        if cursor.fetchone():
            print("✓ audit_logs table verified successfully")
        else:
            print("✗ Error: Table creation verification failed")
            return False
        
        # Create a test audit log entry
        cursor.execute("""
            INSERT INTO audit_logs (
                id, timestamp, action, category, level, status, description,
                target_type, risk_level
            ) VALUES (
                'test-migration-entry',
                datetime('now'),
                'system_migration',
                'system',
                'info',
                'success',
                'Audit logs table migration completed successfully',
                'system',
                0
            )
        """)
        
        conn.commit()
        print("✓ Created test audit log entry")
        
        conn.close()
        print("\n✓ Database migration completed successfully!")
        print("\nAudit Logging Features Added:")
        print("- Comprehensive audit trail tracking")
        print("- Risk level calculation")
        print("- Suspicious activity detection") 
        print("- Performance monitoring (duration tracking)")
        print("- Detailed context capture")
        print("- Advanced search and filtering")
        print("\nNext steps:")
        print("1. Restart your application")
        print("2. Enhanced audit logging will be automatically enabled")
        print("3. Check admin dashboard for audit trail features")
        
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
    print("SafeVault Audit Logs Migration")
    print("=" * 32)
    
    if add_audit_logs_table():
        print("\nMigration completed successfully! 🎉")
    else:
        print("\nMigration failed! ❌")
        sys.exit(1)

if __name__ == "__main__":
    main()