"""
Promote an existing user to admin.

Deliberately NOT exposed as a web route or self-service option — registration
always creates role='user' (see app/routes/auth.py). Admin promotion has to
go through this script (i.e. requires server/shell access), so a bug or bypass
in the web app can never let someone grant themselves admin rights.

Usage:
    python scripts/make_admin.py <username>
"""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import create_app, db
from app.models.user import User


def main():
    if len(sys.argv) != 2:
        print("Usage: python scripts/make_admin.py <username>")
        sys.exit(1)

    username = sys.argv[1]
    app = create_app()

    with app.app_context():
        user = User.query.filter_by(username=username).first()
        if user is None:
            print(f"No user found with username '{username}'.")
            sys.exit(1)

        if user.is_admin:
            print(f"'{username}' is already an admin.")
            return

        user.role = "admin"
        db.session.commit()
        print(f"'{username}' is now an admin.")


if __name__ == "__main__":
    main()
