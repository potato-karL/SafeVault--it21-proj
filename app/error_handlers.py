"""
Custom error pages, registered once in the app factory.

Deliberately generic wording on every page — none of these reveal *why*
something failed (e.g. 404 doesn't distinguish "no such file" from "that
file belongs to someone else"), consistent with the access-control design
in app/routes/files.py.
"""

from flask import render_template


def register_error_handlers(app):

    @app.errorhandler(403)
    def forbidden(e):
        return render_template(
            "errors/error.html", code=403, title="Access denied",
            message="You don't have permission to view this page.",
        ), 403

    @app.errorhandler(404)
    def not_found(e):
        return render_template(
            "errors/error.html", code=404, title="Page not found",
            message="That page or file doesn't exist, or isn't available to you.",
        ), 404

    @app.errorhandler(413)
    def payload_too_large(e):
        max_mb = app.config["MAX_CONTENT_LENGTH"] // (1024 * 1024)
        return render_template(
            "errors/error.html", code=413, title="File too large",
            message=f"That file is larger than the {max_mb} MB upload limit.",
        ), 413

    @app.errorhandler(500)
    def internal_error(e):
        # Never leak stack traces or internal details to the browser — this
        # is what the user sees regardless of what actually broke server-side.
        return render_template(
            "errors/error.html", code=500, title="Something went wrong",
            message="An unexpected error occurred. Please try again.",
        ), 500
