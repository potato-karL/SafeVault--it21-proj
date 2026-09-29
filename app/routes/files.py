import os

from flask import (
    Blueprint, render_template, redirect, url_for, flash, request,
    send_file, abort, current_app, jsonify
)
from flask_login import login_required, current_user
import io
import base64

from app import db
from app.forms import UploadForm, DecryptForm
from app.models.file import File
from app.models.activity_log import ActivityLog
from app.crypto_engine import encrypt_bytes, decrypt_bytes, DecryptionError
from app.integrity import verify_file_at_rest
from app.utils.security import allowed_file, content_matches_extension, generate_stored_filename, upload_path_for
from app.utils.decorators import storage_quota_check
from app.utils import decrypt_cache

files_bp = Blueprint("files", __name__)


def _get_owned_file_or_404(file_id: int, action: str) -> File:
    """Fetch a file and enforce ownership in one place, used by every route
    below. Returns 404 (not 403) for files that exist but belong to someone
    else — this avoids confirming to an attacker that a given file_id exists
    at all, which is exactly the 'guessing URLs/IDs' attack the Phase 8 test
    plan calls out.

    Logs a failed attempt under whichever action the caller was trying to
    perform (decrypt/download/delete) BEFORE aborting — an unauthorized
    access attempt is itself a security-relevant event, and without this the
    activity log would show nothing at all when someone probes another
    user's file IDs. `action` must be one of the values in VALID_ACTIONS.
    """
    file_row = File.query.get(file_id)
    if file_row is None or file_row.user_id != current_user.id:
        ActivityLog.record(
            user_id=current_user.id, action=action, status="fail",
            detail=f"unauthorized access attempt on file_id={file_id}",
            ip_address=request.remote_addr,
        )
        abort(404)
    return file_row


@files_bp.route("/")
@files_bp.route("/landing")
def index():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for("admin.dashboard"))
        return redirect(url_for("files.dashboard"))
    return render_template("landing.html")



@files_bp.route("/dashboard")
@login_required
def dashboard():
    user_files = (
        File.query.filter_by(user_id=current_user.id)
        .order_by(File.uploaded_at.desc())
        .all()
    )
    
    # Get storage quota information
    storage_info = {
        'has_quota': current_user.has_storage_quota(),
        'quota_mb': current_user.get_storage_quota_mb(),
        'used_mb': current_user.get_current_storage_mb(),
        'usage_percent': current_user.get_storage_usage_percent(),
        'available_bytes': current_user.get_available_storage_bytes()
    }
    
    return render_template("dashboard.html", files=user_files, storage_info=storage_info)


@files_bp.route("/upload", methods=["GET", "POST"])
@login_required
@storage_quota_check
def upload():
    form = UploadForm()
    if form.validate_on_submit():
        uploaded = form.file.data
        original_filename = uploaded.filename

        if not original_filename or not allowed_file(original_filename):
            ActivityLog.record(
                user_id=current_user.id, action="upload", status="fail",
                detail=f"disallowed file type: {original_filename}", ip_address=request.remote_addr,
            )
            allowed_list = ", ".join(sorted(current_app.config["ALLOWED_EXTENSIONS"])).upper()
            flash(f"File type not permitted. SafeVault only accepts: {allowed_list}", "danger")
            return render_template("upload.html", form=form)

        plaintext = uploaded.read()
        if not plaintext:
            ActivityLog.record(
                user_id=current_user.id, action="upload", status="fail",
                detail="empty file", ip_address=request.remote_addr,
            )
            flash("That file appears to be empty.", "danger")
            return render_template("upload.html", form=form)

        # Content-sniff with libmagic: catches a disallowed file type
        # (e.g. an executable) that's simply been renamed to match an
        # allowed extension. The extension check above is necessary but
        # not sufficient on its own.
        if not content_matches_extension(plaintext, original_filename):
            ActivityLog.record(
                user_id=current_user.id, action="upload", status="fail",
                detail=f"content/extension mismatch: {original_filename}",
                ip_address=request.remote_addr,
            )
            flash("That file's content doesn't match its extension.", "danger")
            return render_template("upload.html", form=form)

        # Encrypt BEFORE anything touches disk — plaintext only ever exists
        # in memory for this request.
        try:
            result = encrypt_bytes(plaintext, form.encryption_password.data)
        except Exception:
            ActivityLog.record(
                user_id=current_user.id, action="encrypt", status="fail",
                detail=original_filename, ip_address=request.remote_addr,
            )
            flash("Something went wrong while encrypting that file. Please try again.", "danger")
            return render_template("upload.html", form=form)

        stored_filename = generate_stored_filename(original_filename)
        disk_path = upload_path_for(stored_filename)
        with open(disk_path, "wb") as f:
            f.write(result["ciphertext"])

        file_row = File(
            user_id=current_user.id,
            original_filename=original_filename,
            stored_filename=stored_filename,
            salt=result["salt"].hex(),
            iv=result["nonce"].hex(),
            file_hash=result["file_hash"],
            encrypted_hash=result["encrypted_hash"],
            file_size_bytes=len(result["ciphertext"]),
        )
        db.session.add(file_row)
        
        # Update user's storage usage
        current_user.add_file_to_storage(len(result["ciphertext"]))
        db.session.commit()

        ActivityLog.record(
            user_id=current_user.id, action="upload", status="success",
            detail=original_filename, ip_address=request.remote_addr,
        )
        ActivityLog.record(
            user_id=current_user.id, action="encrypt", status="success",
            detail=original_filename, ip_address=request.remote_addr,
        )

        flash(f'"{original_filename}" was encrypted and uploaded.', "success")
        return redirect(url_for("files.dashboard"))

    return render_template("upload.html", form=form)


@files_bp.route("/decrypt/<int:file_id>", methods=["GET", "POST"])
@login_required
def decrypt(file_id):
    file_row = _get_owned_file_or_404(file_id, action="decrypt")
    form = DecryptForm()

    if form.validate_on_submit():
        disk_path = upload_path_for(file_row.stored_filename)

        if not os.path.exists(disk_path):
            ActivityLog.record(
                user_id=current_user.id, action="decrypt", status="fail",
                detail=f"missing file on disk: {file_row.original_filename}",
                ip_address=request.remote_addr,
            )
            flash("This file's data could not be found on the server.", "danger")
            return redirect(url_for("files.dashboard"))

        # At-rest integrity check FIRST, before even attempting decryption —
        # this catches disk corruption/tampering independent of the password,
        # and gives a clear log entry distinguishing it from a wrong password
        # at the infrastructure level (the user still sees the same generic
        # message, per the crypto engine's design).
        integrity = verify_file_at_rest(disk_path, file_row.encrypted_hash)
        if not integrity.ok:
            ActivityLog.record(
                user_id=current_user.id, action="decrypt", status="fail",
                detail=f"at-rest integrity check failed: {file_row.original_filename}",
                ip_address=request.remote_addr,
            )
            flash("This file failed an integrity check and cannot be decrypted safely.", "danger")
            return redirect(url_for("files.dashboard"))

        with open(disk_path, "rb") as f:
            ciphertext = f.read()

        try:
            plaintext = decrypt_bytes(
                ciphertext,
                form.encryption_password.data,
                bytes.fromhex(file_row.salt),
                bytes.fromhex(file_row.iv),
                expected_file_hash=file_row.file_hash,
            )
        except DecryptionError:
            ActivityLog.record(
                user_id=current_user.id, action="decrypt", status="fail",
                detail=file_row.original_filename, ip_address=request.remote_addr,
            )
            flash("Incorrect password or the file could not be verified.", "danger")
            return render_template("decrypt.html", form=form, file=file_row)

        ActivityLog.record(
            user_id=current_user.id, action="decrypt", status="success",
            detail=file_row.original_filename, ip_address=request.remote_addr,
        )

        token = decrypt_cache.put(
            user_id=current_user.id,
            file_id=file_row.id,
            filename=file_row.original_filename,
            data=plaintext,
        )
        return redirect(url_for("files.download", file_id=file_row.id, token=token))

    return render_template("decrypt.html", form=form, file=file_row)


@files_bp.route("/download/<int:file_id>")
@login_required
def download(file_id):
    file_row = _get_owned_file_or_404(file_id, action="download")
    token = request.args.get("token", "")

    result = decrypt_cache.pop(token, user_id=current_user.id, file_id=file_row.id)
    if result is None:
        ActivityLog.record(
            user_id=current_user.id, action="download", status="fail",
            detail=f"expired or reused token: {file_row.original_filename}",
            ip_address=request.remote_addr,
        )
        flash("That download link has expired or already been used. Please decrypt again.", "warning")
        return redirect(url_for("files.decrypt", file_id=file_row.id))

    filename, data = result

    ActivityLog.record(
        user_id=current_user.id, action="download", status="success",
        detail=filename, ip_address=request.remote_addr,
    )

    return send_file(
        io.BytesIO(data),
        download_name=filename,
        as_attachment=True,
        mimetype="application/octet-stream",
    )


@files_bp.route("/delete/<int:file_id>", methods=["POST"])
@login_required
def delete(file_id):
    file_row = _get_owned_file_or_404(file_id, action="delete")
    disk_path = upload_path_for(file_row.stored_filename)

    if os.path.exists(disk_path):
        os.remove(disk_path)

    filename = file_row.original_filename
    file_size = file_row.file_size_bytes
    
    # Update user's storage usage before deleting the record
    current_user.remove_file_from_storage(file_size)
    
    db.session.delete(file_row)
    db.session.commit()

    ActivityLog.record(
        user_id=current_user.id, action="delete", status="success",
        detail=filename, ip_address=request.remote_addr,
    )

    flash(f'"{filename}" was deleted.', "info")
    return redirect(url_for("files.dashboard"))


def format_hex_dump(data: bytes, bytes_per_line: int = 16):
    lines = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i + bytes_per_line]
        offset = f"{i:08x}"
        hex_bytes = " ".join(f"{b:02x}" for b in chunk)
        hex_bytes_padded = hex_bytes.ljust(bytes_per_line * 3 - 1)
        ascii_bytes = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append({
            "offset": offset,
            "hex": hex_bytes_padded,
            "ascii": ascii_bytes
        })
    return lines


@files_bp.route("/preview/<int:file_id>")
@login_required
def preview(file_id):
    file_row = _get_owned_file_or_404(file_id, action="preview")
    disk_path = upload_path_for(file_row.stored_filename)

    if not os.path.exists(disk_path):
        ActivityLog.record(
            user_id=current_user.id, action="preview", status="fail",
            detail=f"missing file on disk: {file_row.original_filename}",
            ip_address=request.remote_addr,
        )
        flash("This file's ciphertext payload could not be found on disk.", "danger")
        return redirect(url_for("files.dashboard"))

    with open(disk_path, "rb") as f:
        ciphertext = f.read()

    # Create hex dump for first 1024 bytes
    preview_bytes = ciphertext[:1024]
    hex_dump = format_hex_dump(preview_bytes)
    base64_snippet = base64.b64encode(preview_bytes[:256]).decode("utf-8")

    ActivityLog.record(
        user_id=current_user.id, action="preview", status="success",
        detail=file_row.original_filename, ip_address=request.remote_addr,
    )

    return render_template(
        "preview.html",
        file=file_row,
        hex_dump=hex_dump,
        base64_snippet=base64_snippet,
        total_ciphertext_size=len(ciphertext),
    )

