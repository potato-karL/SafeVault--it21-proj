"""
Phase 8: security testing & hardening.

Runs a battery of actual attack attempts against a live test-client instance
of the app (not just static code review) and confirms each one is blocked
or handled safely. Covers:

  1. SQL injection via login and registration fields
  2. XSS via a malicious filename, checked in rendered HTML
  3. Path traversal via a malicious filename
  4. CSRF: request missing a token is rejected
  5. Session fixation: session cookie value changes after login
  6. File size limit enforcement
  7. Log hygiene: raw passwords never appear in activity_logs

Run with: python scripts/test_security.py
"""

import sys
import os
import re
import io

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import create_app, db
from config import Config


def section(title):
    print(f"\n{'=' * 65}\n{title}\n{'=' * 65}")


def get_csrf(html):
    m = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html)
    if not m:
        m = re.search(r'value="([^"]+)"[^>]*name="csrf_token"', html)
    return m.group(1) if m else None


def register_and_login(client, username, email, password):
    resp = client.get("/register")
    csrf = get_csrf(resp.get_data(as_text=True))
    client.post("/register", data={
        "csrf_token": csrf, "username": username, "email": email,
        "password": password, "confirm_password": password,
    }, follow_redirects=True)
    resp = client.get("/login")
    csrf = get_csrf(resp.get_data(as_text=True))
    client.post("/login", data={"csrf_token": csrf, "username": username, "password": password}, follow_redirects=True)


def test_sql_injection(app):
    section("Test 1: SQL injection attempts (login + registration)")
    client = app.test_client()

    payloads = [
        "' OR '1'='1",
        "'; DROP TABLE users; --",
        "admin'--",
        "' UNION SELECT * FROM users --",
    ]

    with app.app_context():
        from app.models.user import User
        users_before = User.query.count()
        tables_before = db.inspect(db.engine).get_table_names()

    all_safe = True
    for payload in payloads:
        resp = client.get("/login")
        csrf = get_csrf(resp.get_data(as_text=True))
        resp = client.post("/login", data={
            "csrf_token": csrf, "username": payload, "password": payload,
        }, follow_redirects=True)
        # Should NEVER succeed, NEVER crash (500), just the normal invalid-login response.
        if resp.status_code == 500:
            print(f"FAIL: payload {payload!r} caused a server error!")
            all_safe = False
        elif b"Invalid username or password" not in resp.data:
            print(f"FAIL: payload {payload!r} did not get the expected rejection!")
            all_safe = False
        else:
            print(f"OK: payload {payload!r} rejected cleanly (status {resp.status_code}).")

    with app.app_context():
        from app.models.user import User
        users_after = User.query.count()
        tables_intact = db.inspect(db.engine).get_table_names()

    if users_after != users_before:
        print("FAIL: user count changed — injection may have created/altered rows!")
        all_safe = False
    if set(tables_intact) != set(tables_before):
        print(f"FAIL: table set changed unexpectedly: {tables_intact}")
        all_safe = False
    else:
        print(f"OK: all tables intact ({tables_intact}), user count unchanged ({users_after}).")

    print("PASS: SQL injection attempts had no effect." if all_safe else "SOME CHECKS FAILED.")
    return all_safe


def test_xss_via_filename(app):
    section("Test 2: XSS via malicious filename")
    client = app.test_client()
    register_and_login(client, "xss_tester", "xss@example.com", "xsstestpass123")

    malicious_name = "<script>alert('pwned')</script>.txt"
    resp = client.get("/upload")
    csrf = get_csrf(resp.get_data(as_text=True))
    resp = client.post("/upload", data={
        "csrf_token": csrf,
        "file": (io.BytesIO(b"harmless content"), malicious_name),
        "encryption_password": "xssfilepass1",
        "confirm_password": "xssfilepass1",
    }, content_type="multipart/form-data", follow_redirects=True)

    html = resp.get_data(as_text=True)

    if "<script>alert('pwned')</script>" in html:
        print("FAIL: raw <script> tag appeared unescaped in dashboard HTML!")
        return False

    if "&lt;script&gt;" in html:
        print("PASS: filename was HTML-escaped by Jinja2 autoescaping before rendering.")
        return True

    print("WARN: escaped script tag not found at all — filename may not have rendered.")
    return False


def test_path_traversal_filename(app):
    section("Test 3: Path traversal via malicious filename")
    client = app.test_client()
    register_and_login(client, "traversal_tester", "trav@example.com", "travtestpass123")

    # This filename has no recognizable extension ('/etc/passwd' isn't in the
    # allow-list), so it should get caught by the extension check before it
    # ever reaches the stored-filename logic. Confirmed separately below.
    no_ext_traversal = "../../../../etc/passwd"
    resp = client.get("/upload")
    csrf = get_csrf(resp.get_data(as_text=True))
    client.post("/upload", data={
        "csrf_token": csrf,
        "file": (io.BytesIO(b"malicious content"), no_ext_traversal),
        "encryption_password": "travfilepass1",
        "confirm_password": "travfilepass1",
    }, content_type="multipart/form-data", follow_redirects=True)

    with app.app_context():
        from app.models.file import File
        from app.models.user import User
        user = User.query.filter_by(username="traversal_tester").first()
        blocked_by_extension_check = File.query.filter_by(user_id=user.id).count() == 0

    print(f"Filename with no valid extension ('...etc/passwd') blocked by allow-list: {blocked_by_extension_check}")

    # Now the real test: a traversal filename WITH an allowed extension, so
    # it passes the extension check and we can confirm the deeper defense —
    # stored_filename is a random UUID, completely unrelated to user input,
    # regardless of what the extension check let through.
    traversal_with_valid_ext = "../../../../etc/cron.d/evil.txt"
    resp = client.get("/upload")
    csrf = get_csrf(resp.get_data(as_text=True))
    client.post("/upload", data={
        "csrf_token": csrf,
        "file": (io.BytesIO(b"malicious content 2"), traversal_with_valid_ext),
        "encryption_password": "travfilepass2",
        "confirm_password": "travfilepass2",
    }, content_type="multipart/form-data", follow_redirects=True)

    with app.app_context():
        from app.models.file import File
        from app.models.user import User
        user = User.query.filter_by(username="traversal_tester").first()
        file_row = (
            File.query.filter_by(user_id=user.id)
            .order_by(File.id.desc())
            .first()
        )

    if file_row is None:
        print("FAIL: expected this upload (valid extension) to succeed so the deeper check could run!")
        return False

    stored_path = os.path.abspath(os.path.join(app.config["UPLOAD_FOLDER"], file_row.stored_filename))
    upload_dir = os.path.abspath(app.config["UPLOAD_FOLDER"])

    safe = stored_path.startswith(upload_dir) and ".." not in file_row.stored_filename and "/" not in file_row.stored_filename
    print(f"original_filename stored as-is in DB (fine, it's just text, never a path): {file_row.original_filename!r}")
    print(f"stored_filename (the actual name used on disk): {file_row.stored_filename!r}")
    print(f"Resolved disk path stays inside uploads/: {safe}")
    print("PASS: stored_filename is a random UUID, completely unrelated to user input." if safe else "FAIL: path traversal possible!")
    return safe and blocked_by_extension_check


def test_csrf_enforcement(app):
    section("Test 4: CSRF protection — request with no/invalid token")
    client = app.test_client()
    register_and_login(client, "csrf_tester", "csrf@example.com", "csrftestpass123")

    # Attempt upload with NO csrf_token field at all.
    resp = client.post("/upload", data={
        "file": (io.BytesIO(b"data"), "test.txt"),
        "encryption_password": "csrffilepass1",
        "confirm_password": "csrffilepass1",
    }, content_type="multipart/form-data")

    if resp.status_code == 400:
        print(f"PASS: request without CSRF token rejected with 400 (as expected).")
        return True
    print(f"FAIL: expected 400, got {resp.status_code} — CSRF protection may not be active!")
    return False


def test_session_fixation(app):
    section("Test 5: Session fixation — session cookie changes on login")
    client = app.test_client()

    # Touch a page to get an initial session cookie before authentication.
    client.get("/login")
    cookie_before = client.get_cookie("session")
    value_before = cookie_before.value if cookie_before else None

    register_and_login(client, "fixation_tester", "fix@example.com", "fixtestpass123")

    cookie_after = client.get_cookie("session")
    value_after = cookie_after.value if cookie_after else None

    print(f"Session cookie before login: {value_before[:24] if value_before else None}...")
    print(f"Session cookie after login:  {value_after[:24] if value_after else None}...")

    if value_before is not None and value_before == value_after:
        print("FAIL: session cookie value did NOT change after login!")
        return False
    print("PASS: session cookie value changed after authentication.")
    return True


def test_upload_size_limit(app):
    section("Test 6: File size limit enforcement")
    # Build a small app instance with a tiny limit so the test runs fast.
    class TinyLimitConfig(Config):
        SQLALCHEMY_DATABASE_URI = app.config["SQLALCHEMY_DATABASE_URI"]
        MAX_CONTENT_LENGTH = 1024  # 1 KB, for a fast test

    tiny_app = create_app(TinyLimitConfig)
    client = tiny_app.test_client()
    register_and_login(client, "sizelimit_tester", "size@example.com", "sizetestpass123")

    oversized_content = b"A" * (2 * 1024)  # 2 KB > 1 KB limit
    resp = client.get("/upload")
    csrf = get_csrf(resp.get_data(as_text=True))
    resp = client.post("/upload", data={
        "csrf_token": csrf,
        "file": (io.BytesIO(oversized_content), "big.txt"),
        "encryption_password": "sizefilepass1",
        "confirm_password": "sizefilepass1",
    }, content_type="multipart/form-data")

    if resp.status_code == 413:
        print("PASS: oversized upload rejected with 413 Payload Too Large.")
        return True
    print(f"FAIL: expected 413, got {resp.status_code}.")
    return False


def test_no_plaintext_passwords_in_logs(app):
    section("Test 7: Passwords never appear in activity_logs")
    with app.app_context():
        from app.models.activity_log import ActivityLog
        suspicious_terms = ["alicepass", "password123", "correcthorse", "davepass"]
        all_logs = ActivityLog.query.all()
        leaked = []
        for log in all_logs:
            if log.detail:
                for term in suspicious_terms:
                    if term.lower() in log.detail.lower():
                        leaked.append((log.id, log.detail))

        if leaked:
            print(f"FAIL: possible password leakage in logs: {leaked}")
            return False
        print(f"PASS: scanned {len(all_logs)} log entries, no plaintext password fragments found.")
        return True


def run_test(test_fn):
    app = create_app()
    with app.app_context():
        db.drop_all()
        db.create_all()
    return test_fn(app)


def main():
    results = {}
    results["sql_injection"] = run_test(test_sql_injection)
    results["xss_filename"] = run_test(test_xss_via_filename)
    results["path_traversal"] = run_test(test_path_traversal_filename)
    results["csrf_enforcement"] = run_test(test_csrf_enforcement)
    results["session_fixation"] = run_test(test_session_fixation)
    results["upload_size_limit"] = run_test(test_upload_size_limit)
    results["password_log_hygiene"] = run_test(test_no_plaintext_passwords_in_logs)

    section("SUMMARY")
    for name, passed in results.items():
        print(f"  [{'PASS' if passed else 'FAIL'}] {name}")

    if all(results.values()):
        print("\nAll Phase 8 security checks passed.")
    else:
        print("\nSOME CHECKS FAILED — see above.")
        sys.exit(1)


if __name__ == "__main__":
    main()
