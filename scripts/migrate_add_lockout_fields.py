"""
One-off migration: adds the brute-force lockout columns to an existing
users table, without touching any existing rows/files.

db.create_all() only creates *missing tables* — it will never ALTER an
existing table, so anyone upgrading from a pre-lockout copy of SafeVault
needs to run this once.

Usage (from the project root, with the venv active):
    python scripts/migrate_add_lockout_fields.py
"""
import sqlite3
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import Config


def column_exists(cursor, table, column) -> bool:
    cursor.execute(f"PRAGMA table_info({table})")
    return any(row[1] == column for row in cursor.fetchall())


def main():
    db_path = Config.SQLALCHEMY_DATABASE_URI.replace("sqlite:///", "")
    if not os.path.exists(db_path):
        print(f"No existing database at {db_path} — nothing to migrate. "
              f"It will be created fresh with the new schema on next app start.")
        return

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    added = []
    if not column_exists(cur, "users", "failed_login_attempts"):
        cur.execute("ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER NOT NULL DEFAULT 0")
        added.append("failed_login_attempts")

    if not column_exists(cur, "users", "locked_until"):
        cur.execute("ALTER TABLE users ADD COLUMN locked_until DATETIME")
        added.append("locked_until")

    if not column_exists(cur, "users", "totp_secret"):
        cur.execute("ALTER TABLE users ADD COLUMN totp_secret VARCHAR(32)")
        added.append("totp_secret")

    if not column_exists(cur, "users", "totp_enabled"):
        cur.execute("ALTER TABLE users ADD COLUMN totp_enabled BOOLEAN NOT NULL DEFAULT 0")
        added.append("totp_enabled")

    conn.commit()
    conn.close()

    if added:
        print(f"Migration complete. Added columns: {', '.join(added)}")
    else:
        print("Database already up to date — no changes made.")


if __name__ == "__main__":
    main()
