"""
Migration script to add system health monitoring tables to SafeVault database
Run this script to add system monitoring capabilities
"""

import os
import sys
import sqlite3
from datetime import datetime, timezone

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def add_system_health_tables():
    """Add system health monitoring tables to the database"""
    
    # Database path
    db_path = os.path.join('instance', 'safevault.db')
    
    if not os.path.exists(db_path):
        print(f"Error: Database file not found at {db_path}")
        print("Make sure you're running this script from the project root directory")
        return False
    
    print(f"Adding system health monitoring tables to database: {db_path}")
    
    try:
        # Connect to database
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        
        # Check if tables already exist
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name IN ('system_health_metrics', 'system_alerts')
        """)
        
        existing_tables = [row[0] for row in cursor.fetchall()]
        
        if 'system_health_metrics' in existing_tables and 'system_alerts' in existing_tables:
            print("System health tables already exist!")
            conn.close()
            return True
        
        # Create system_health_metrics table
        if 'system_health_metrics' not in existing_tables:
            cursor.execute("""
                CREATE TABLE system_health_metrics (
                    id VARCHAR(36) PRIMARY KEY,
                    timestamp DATETIME NOT NULL,
                    cpu_percent REAL,
                    cpu_count INTEGER,
                    load_average_1m REAL,
                    load_average_5m REAL,
                    load_average_15m REAL,
                    memory_total BIGINT,
                    memory_available BIGINT,
                    memory_used BIGINT,
                    memory_percent REAL,
                    memory_cached BIGINT,
                    disk_total BIGINT,
                    disk_used BIGINT,
                    disk_free BIGINT,
                    disk_percent REAL,
                    database_size BIGINT,
                    database_connections INTEGER,
                    network_bytes_sent BIGINT,
                    network_bytes_recv BIGINT,
                    network_packets_sent BIGINT,
                    network_packets_recv BIGINT,
                    active_sessions INTEGER,
                    total_users INTEGER,
                    total_files INTEGER,
                    total_storage_used BIGINT,
                    response_time_avg REAL,
                    error_rate REAL,
                    uptime_seconds BIGINT,
                    process_count INTEGER,
                    thread_count INTEGER,
                    status VARCHAR(20) NOT NULL DEFAULT 'healthy',
                    alerts TEXT
                )
            """)
            print("✓ Created system_health_metrics table")
        
        # Create system_alerts table
        if 'system_alerts' not in existing_tables:
            cursor.execute("""
                CREATE TABLE system_alerts (
                    id VARCHAR(36) PRIMARY KEY,
                    timestamp DATETIME NOT NULL,
                    alert_type VARCHAR(50) NOT NULL,
                    severity VARCHAR(20) NOT NULL DEFAULT 'warning',
                    title VARCHAR(255) NOT NULL,
                    message TEXT NOT NULL,
                    is_active BOOLEAN NOT NULL DEFAULT 1,
                    acknowledged BOOLEAN NOT NULL DEFAULT 0,
                    acknowledged_by INTEGER,
                    acknowledged_at DATETIME,
                    resolved BOOLEAN NOT NULL DEFAULT 0,
                    resolved_at DATETIME,
                    metadata TEXT,
                    FOREIGN KEY (acknowledged_by) REFERENCES users (id)
                )
            """)
            print("✓ Created system_alerts table")
        
        # Create indexes for better performance
        indexes = [
            "CREATE INDEX idx_system_health_timestamp ON system_health_metrics (timestamp)",
            "CREATE INDEX idx_system_health_status ON system_health_metrics (status)",
            "CREATE INDEX idx_system_alerts_timestamp ON system_alerts (timestamp)",
            "CREATE INDEX idx_system_alerts_type ON system_alerts (alert_type)",
            "CREATE INDEX idx_system_alerts_severity ON system_alerts (severity)",
            "CREATE INDEX idx_system_alerts_is_active ON system_alerts (is_active)",
            "CREATE INDEX idx_system_alerts_acknowledged ON system_alerts (acknowledged)"
        ]
        
        for index_sql in indexes:
            try:
                cursor.execute(index_sql)
            except sqlite3.OperationalError as e:
                if "already exists" not in str(e):
                    raise
        
        # Commit changes
        conn.commit()
        print("✓ Created database indexes")
        
        # Verify table creation
        cursor.execute("""
            SELECT name FROM sqlite_master 
            WHERE type='table' AND name IN ('system_health_metrics', 'system_alerts')
        """)
        
        created_tables = [row[0] for row in cursor.fetchall()]
        
        if 'system_health_metrics' in created_tables and 'system_alerts' in created_tables:
            print("✓ System health tables verified successfully")
        else:
            print("✗ Error: Table creation verification failed")
            return False
        
        # Create initial system health entry
        cursor.execute("""
            INSERT INTO system_health_metrics (
                id, timestamp, status, cpu_percent, memory_percent, disk_percent,
                active_sessions, total_users, total_files
            ) VALUES (
                'initial-system-health',
                datetime('now'),
                'healthy',
                0.0,
                0.0,
                0.0,
                0,
                0,
                0
            )
        """)
        
        conn.commit()
        print("✓ Created initial system health entry")
        
        conn.close()
        print("\n✓ Database migration completed successfully!")
        print("\nSystem Health Features Added:")
        print("- Comprehensive system metrics collection")
        print("- CPU, memory, disk, and network monitoring")
        print("- Application-specific metrics tracking")
        print("- Automated alert generation")
        print("- Performance trend analysis")
        print("\nNext steps:")
        print("1. Restart your application")
        print("2. System monitoring will be automatically available")
        print("3. Check admin dashboard for system health metrics")
        
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
    print("SafeVault System Health Migration")
    print("=" * 34)
    
    if add_system_health_tables():
        print("\nMigration completed successfully! 🎉")
    else:
        print("\nMigration failed! ❌")
        sys.exit(1)

if __name__ == "__main__":
    main()