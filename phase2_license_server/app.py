"""
Flask application factory for the Phase 2 license server.

Run it with:
    python app.py
    # or
    flask --app app run
"""
from __future__ import annotations

import logging
import os
from typing import Optional

from flask import Flask, jsonify, send_from_directory
from sqlalchemy import text

from config import REPO_ROOT, Config
from errors import APIError
from extensions import db
from keys import KeyConfigError, ensure_keys
from routes import api

logger = logging.getLogger(__name__)

# The UI screens live with the rest of the Stitch design suite so the visual
# language stays in one place; the server just serves the licensed screen.
UI_ROOT = REPO_ROOT / "stitch_pam_suite_dashboard_ui"
LICENSE_SCREEN = UI_ROOT / "license_entitlement_center" / "code.html"


def _register_error_handlers(app: Flask) -> None:
    @app.errorhandler(APIError)
    def handle_api_error(error: APIError):
        return jsonify(error.to_dict()), error.status_code

    @app.errorhandler(KeyConfigError)
    def handle_key_error(error: KeyConfigError):
        return jsonify({"error": str(error)}), 500

    @app.errorhandler(404)
    def handle_not_found(_error):
        return jsonify({"error": "Not found"}), 404

    @app.errorhandler(405)
    def handle_method_not_allowed(_error):
        return jsonify({"error": "Method not allowed"}), 405

    @app.errorhandler(Exception)
    def handle_unexpected(error: Exception):
        logger.exception("Unhandled error while serving %s", error)
        return jsonify({"error": "Internal server error"}), 500


def create_app(config: Optional[Config] = None) -> Flask:
    """Build the Flask app: config -> DB -> routes -> startup checks."""
    config = config or Config.from_env()

    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=config.secret_key,
        SQLALCHEMY_DATABASE_URI=config.database_uri,
        SQLALCHEMY_TRACK_MODIFICATIONS=False,
        LICENSE_CONFIG=config,
    )

    db.init_app(app)
    app.register_blueprint(api)
    _register_error_handlers(app)

    @app.after_request
    def add_auth_mode_header(response):
        response.headers["X-Auth-Mode"] = "token" if config.admin_token else "open"
        return response

    @app.get("/health")
    def health():
        try:
            db.session.execute(text("SELECT 1"))
            database = "ok"
        except Exception:  # pragma: no cover - only when the DB is down
            logger.exception("Database connectivity check failed")
            database = "error"
        payload = {
            "status": "ok" if database == "ok" else "degraded",
            "database": database,
            "auth": "token" if config.admin_token else "open",
            "private_key": str(config.private_key_path),
        }
        return jsonify(payload), (200 if database == "ok" else 503)

    @app.get("/")
    @app.get("/license")
    def license_screen():
        """Serve the License & Entitlement screen from the design suite."""
        if not LICENSE_SCREEN.is_file():
            return jsonify({"error": f"License screen not found at {LICENSE_SCREEN}"}), 404
        return send_from_directory(str(LICENSE_SCREEN.parent), LICENSE_SCREEN.name)

    # Fail fast on unusable signing keys, then create missing tables.
    ensure_keys(config)
    with app.app_context():
        db.create_all()

    return app


def main() -> None:
    logging.basicConfig(
        level=logging.DEBUG if os.getenv("LICENSE_SERVER_DEBUG") else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    application = create_app()
    application.run(
        host=os.getenv("LICENSE_SERVER_HOST", "127.0.0.1"),
        port=int(os.getenv("LICENSE_SERVER_PORT", "5000")),
        debug=bool(os.getenv("LICENSE_SERVER_DEBUG")),
    )


if __name__ == "__main__":
    main()
