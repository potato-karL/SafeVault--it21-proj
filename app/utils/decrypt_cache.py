"""
Temporary, one-time-use storage for decrypted file bytes.

Why this exists: /decrypt/<file_id> verifies the password and performs the
actual decryption, but /download/<file_id> is what streams the file to the
browser. Rather than writing decrypted plaintext to disk (which would leave
a lingering unencrypted copy — exactly what this whole project is trying to
avoid) or re-deriving the key from a password re-submitted on every request,
we hold the decrypted bytes in memory very briefly, behind a random one-time
token, and destroy them immediately after they're either downloaded or they
expire.

LIMITATION (worth noting in your report): this is an in-process dict, so it
only works with a single-process dev server (`flask run` / `python run.py`).
A production deployment running multiple worker processes would need a
shared store with TTL support (e.g. Redis) instead. For a course project
running the Flask dev server, this is fine and keeps the dependency list
small.
"""

import secrets
import threading
import time

_LOCK = threading.Lock()
_STORE: dict[str, dict] = {}

TTL_SECONDS = 60  # how long a decrypted payload may sit in memory unclaimed


def _purge_expired():
    now = time.time()
    expired = [token for token, entry in _STORE.items() if entry["expires_at"] < now]
    for token in expired:
        _STORE.pop(token, None)


def put(user_id: int, file_id: int, filename: str, data: bytes) -> str:
    """Store decrypted bytes and return a one-time token to retrieve them."""
    with _LOCK:
        _purge_expired()
        token = secrets.token_urlsafe(32)
        _STORE[token] = {
            "user_id": user_id,
            "file_id": file_id,
            "filename": filename,
            "data": data,
            "expires_at": time.time() + TTL_SECONDS,
        }
        return token


def pop(token: str, user_id: int, file_id: int):
    """Retrieve and IMMEDIATELY DELETE a decrypted payload. Returns None if
    the token doesn't exist, has expired, or doesn't belong to this exact
    user + file (defense-in-depth against a leaked/guessed token being used
    for a different file).
    """
    with _LOCK:
        _purge_expired()
        entry = _STORE.pop(token, None)

    if entry is None:
        return None
    if entry["user_id"] != user_id or entry["file_id"] != file_id:
        return None
    if entry["expires_at"] < time.time():
        return None

    return entry["filename"], entry["data"]
