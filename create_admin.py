#!/usr/bin/env python3
"""
Create an admin user for SafeVault.

Interactive usage (local):
    python create_admin.py

Non-interactive usage (Railway one-off command / CI):
    ADMIN_USERNAME=admin ADMIN_EMAIL=admin@example.com ADMIN_PASSWORD=secret python create_admin.py
"""

import os
from app import create_app, db
from app.models.user import User


def create_admin_user():
    app = create_app()

    with app.app_context():
        # Prefer env vars so this works in non-interactive environments (Railway, CI).
        username = os.environ.get("ADMIN_USERNAME") or input("Enter admin username: ").strip()
        email    = os.environ.get("ADMIN_EMAIL")    or input("Enter admin email: ").strip()
        password = os.environ.get("ADMIN_PASSWORD") or input("Enter admin password: ").strip()

        if not username or not email or not password:
            print("❌ All fields are required!")
            return False

        existing = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()

        if existing:
            print("❌ Username or email already exists!")
            return False

        admin = User(username=username, email=email, role="admin")
        admin.set_password(password)

        if app.config.get("DEFAULT_USER_STORAGE_QUOTA_MB"):
            admin.set_storage_quota(app.config["DEFAULT_USER_STORAGE_QUOTA_MB"])

        db.session.add(admin)
        db.session.commit()

        print(f"✅ Admin user '{username}' created successfully!")
        print(f"📧 Email: {email}")
        print(f"🔑 Role: admin")
        print("\nYou can now log in to the admin panel!")
        return True


if __name__ == "__main__":
    print("SafeVault Admin User Creation")
    print("=" * 35)
    create_admin_user()
