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

from flask import Flask, abort, jsonify, send_from_directory
from sqlalchemy import text

from config import REPO_ROOT, Config
from errors import APIError
from extensions import db
from keys import KeyConfigError, ensure_keys
from licensing_bridge import sig
from models import ensure_schema
from routes import api
from rotation_scheduler import start as start_rotation_scheduler
from service import ensure_command_rules

logger = logging.getLogger(__name__)

# The product frontend (copied from the frozen design reference in
# stitch_pam_suite_dashboard_ui/): the server serves the launcher, the two
# live screens and every sidebar-linked screen from here.
UI_ROOT = REPO_ROOT / "frontend"
LICENSE_SCREEN = UI_ROOT / "screens" / "license_entitlement_center" / "code.html"
SETTINGS_SCREEN = UI_ROOT / "screens" / "platform_settings_center" / "code.html"


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
            "algorithms": list(sig.SUPPORTED_ALGORITHMS),
            "formats": list(sig.SUPPORTED_FORMATS),
            "ed25519_key": config.ed25519_private_key_path.exists(),
        }
        return jsonify(payload), (200 if database == "ok" else 503)

    @app.get("/")
    @app.get("/license")
    def license_screen():
        """Serve the License & Entitlement screen from the design suite."""
        if not LICENSE_SCREEN.is_file():
            return jsonify({"error": f"License screen not found at {LICENSE_SCREEN}"}), 404
        return send_from_directory(str(LICENSE_SCREEN.parent), LICENSE_SCREEN.name)

    @app.get("/settings")
    def settings_screen():
        """Serve the live Platform Settings screen from the design suite."""
        if not SETTINGS_SCREEN.is_file():
            return jsonify({"error": f"Settings screen not found at {SETTINGS_SCREEN}"}), 404
        return send_from_directory(str(SETTINGS_SCREEN.parent), SETTINGS_SCREEN.name)

    @app.get("/<path:suite_path>")
    def suite_files(suite_path: str):
        """Serve the rest of the frontend (sidebars link to it).

        Registered last and least specific: /health, /, /license, /settings and
        every /api/v1 route still win. The API and health namespaces are
        refused outright so a missing API path keeps returning JSON 404s
        instead of a file lookup.
        """
        if suite_path == "health" or suite_path == "api" or suite_path.startswith("api/"):
            abort(404)
        root = UI_ROOT.resolve()
        try:
            target = (UI_ROOT / suite_path).resolve()
            target.relative_to(root)
        except (OSError, ValueError):
            abort(404)
        if not target.is_file():
            abort(404)
        return send_from_directory(str(target.parent), target.name)

    # Fail fast on unusable signing keys, then create missing tables and append
    # any columns introduced by later spec revisions. The vault starts empty:
    # credentials only ever enter it through the onboarding API (no fake data).
    ensure_keys(config)
    with app.app_context():
        db.create_all()
        added = ensure_schema(db.engine)
        if added:
            logger.info("Schema migrated, added columns: %s", ", ".join(added))
        # command control (module 9): the shipped section-9 policy, seeded
        # once into an empty rules table (deletions an admin made stay made)
        seeded = ensure_command_rules()
        if seeded:
            logger.info("Command control: seeded %d default policy rules", seeded)

    # Optional real-clock rotation scheduler (ROTATION_SCHEDULER=1); off in
    # tests and dev unless explicitly enabled, never fabricated when quiet.
    if config.rotation_scheduler:
        start_rotation_scheduler(app, config.rotation_scheduler_interval)

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
