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

from flask import Flask, abort, jsonify, redirect, send_from_directory
from sqlalchemy import text

from config import REPO_ROOT, Config
from errors import APIError, ServiceUnavailable
from extensions import db
from keys import KeyConfigError, ensure_keys
from licensing_bridge import sig
from models import ensure_schema
from routes import api
from rotation_scheduler import start as start_rotation_scheduler
from cluster_monitor import start as start_cluster_monitor
from service import (
    cluster_self_role,
    ensure_cluster_self,
    ensure_command_rules,
    ensure_rbac_seed,
)
from audit import ensure_audit_chain

logger = logging.getLogger(__name__)

# The product frontend: the React console (built bundle under
# frontend/app/dist, served at /app/ per docs/frontend/ADR-0012) plus the
# legacy static suite it strangles - the server serves the launcher, the
# live license screen and every sidebar-linked screen from here. The
# settings screen is the first strangler flip (ADR-0015 11.5): /settings
# redirects to the React page and the legacy settings page is deleted.
UI_ROOT = REPO_ROOT / "frontend"
LICENSE_SCREEN = UI_ROOT / "screens" / "license_entitlement_center" / "code.html"
CONSOLE_DIST = UI_ROOT / "app" / "dist"


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

    # phase 7: CSRF double-submit for cookie-authenticated mutations. A
    # request that presents no bearer/header credential but carries the
    # session cookie must send the X-CSRF-Token minted at login; header
    # (machine) clients skip this because a bearer token is never an
    # ambient credential.
    @app.before_request
    def enforce_cookie_csrf():
        from flask import g, request

        if request.method in ("GET", "HEAD", "OPTIONS"):
            return None
        if request.headers.get("Authorization") or request.headers.get("X-Admin-Token"):
            return None
        cookie = request.cookies.get("vypam_session")
        if not cookie:
            return None
        import identity as identity_module

        user, session = identity_module.verify_console_session(cookie)
        g.console_session = session
        g.console_user = user
        g.auth_via = "cookie"
        presented = request.headers.get("X-CSRF-Token", "")
        if not identity_module.csrf_ok(session, presented):
            from errors import Forbidden

            raise Forbidden(
                "CSRF token missing or invalid for a cookie-authenticated "
                "mutation (send the csrf_token from login in X-CSRF-Token)",
                {"reason": "csrf"},
            )
        return None

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
        # HA / DC / DR (section 18): this node's deployment identity, so a
        # peer's real probe and an operator's `curl` both see which node
        # answered. The role comes from this node's own registry row; when
        # the database is down the row cannot be read, so it says `unknown`
        # rather than guessing a default.
        role = "unknown"
        if database == "ok":
            try:
                role = cluster_self_role()
            except Exception:  # pragma: no cover - defensive, still honest
                logger.exception("Cluster role read failed")
        payload = {
            "status": "ok" if database == "ok" else "degraded",
            "database": database,
            "auth": "token" if config.admin_token else "open",
            "node": config.node_name,
            "site": config.node_site,
            "role": role,
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
        """Strangle flip (ADR-0015, 11.5): the old URL keeps working and
        lands on the React Platform Settings page under /app/."""
        return redirect("/app/settings")

    @app.get("/app")
    @app.get("/app/")
    def console_shell():
        """Serve the built React console shell - same-origin under /app/
        exactly as ADR-0012 prescribes for the migration. Until the
        bundle is built the answer is an honest 404, never a stub."""
        if not (CONSOLE_DIST / "index.html").is_file():
            return jsonify(
                {"error": f"console build not found at {CONSOLE_DIST} - run pnpm build"}
            ), 404
        return send_from_directory(str(CONSOLE_DIST), "index.html")

    @app.get("/app/<path:console_path>")
    def console_files(console_path: str):
        """Built console files, with the app shell as the SPA fallback so
        client routes like /app/settings deep-link (basename /app)."""
        root = CONSOLE_DIST.resolve()
        try:
            target = (CONSOLE_DIST / console_path).resolve()
            target.relative_to(root)
        except (OSError, ValueError):
            abort(404)
        if target.is_file():
            return send_from_directory(str(target.parent), target.name)
        if (CONSOLE_DIST / "index.html").is_file():
            return send_from_directory(str(CONSOLE_DIST), "index.html")
        return jsonify(
            {"error": f"console build not found at {CONSOLE_DIST} - run pnpm build"}
        ), 404

    @app.get("/<folder>/<path:screen_path>")
    def screen_root_mirror(folder: str, screen_path: str):
        """P0 fix (ADR-0020): the entry screen served at / carries relative
        `../<folder>/code.html` hrefs, which the browser clamps to
        `/<folder>/code.html` at the root - mirror those onto the screens
        tree so the canonical sidebar works from both serving contexts.
        Shared assets (`/vendor/...`) fall back to the plain UI-root
        lookup, and the API/health namespaces are refused exactly as in
        suite_files, which stays the catch-all below."""
        if folder in ("api", "health") or folder.startswith("api/"):
            abort(404)
        root = UI_ROOT.resolve()
        if folder == "screens":
            candidates = (UI_ROOT / "screens" / screen_path,)
        else:
            # the screens mirror first, then the plain UI-root lookup so
            # two-segment assets like /vendor/... keep answering as before
            candidates = (
                UI_ROOT / "screens" / folder / screen_path,
                UI_ROOT / folder / screen_path,
            )
        for candidate in candidates:
            try:
                target = candidate.resolve()
                target.relative_to(root)
            except (OSError, ValueError):
                continue
            if target.is_file():
                return send_from_directory(str(target.parent), target.name)
        abort(404)

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
        # immutable audit ledger (section 19): append-only triggers plus a
        # backfill that chains any pre-existing history before serving
        backfilled = ensure_audit_chain()
        if backfilled:
            logger.info("Audit ledger: backfilled %d historical events", backfilled)
        # HA / DC / DR (section 18): this node's own registry row, seeded
        # once from PAM_NODE_NAME / PAM_SITE. A restart never resets the
        # role - a promoted node stays promoted until an operator demotes.
        registered = ensure_cluster_self()
        if registered:
            logger.info("Cluster: registered this node as '%s'", registered)
        # RBAC / ABAC (section 10): the five built-in roles, seeded once -
        # bindings are created by an admin, never fabricated at startup.
        roles_seeded = ensure_rbac_seed()
        if roles_seeded:
            logger.info("RBAC: seeded %d built-in roles", roles_seeded)
        # phase 7 (Addendum C): the sealed emergency admin, seeded once -
        # its password is random + sealed and grants nothing until a
        # dual-approved grant opens a window.
        import identity as identity_module

        try:
            if identity_module.ensure_emergency_admin() is not None:
                logger.info(
                    "Identity: seeded the sealed emergency admin ('%s')",
                    identity_module.EMERGENCY_USERNAME,
                )
        except ServiceUnavailable as exc:
            # fail-closed for the seal, fail-open for the boot: sealing
            # needs the vault key, and a node without one must still
            # start (it refuses vault operations with an honest 503
            # instead). The seed happens on the next boot, once the key
            # exists.
            logger.warning(
                "Identity: emergency admin not seeded this boot - %s", exc
            )
        # first-run setup (ADR-0018): the two bootstrap officers are created
        # only on an instance that has never completed setup and has no
        # console identity yet (the sealed emergency admin above grants
        # nothing and does not count) - their generated passwords print
        # once, right above this line, in this boot log.
        import setup as setup_module

        try:
            if setup_module.ensure_bootstrap_officers() is not None:
                logger.info(
                    "Setup: bootstrap officers created - password pair above, "
                    "shown once"
                )
        except Exception:
            # fail-open for the boot, exactly like the /health DB guards
            # above: a transient DB error (or a duplicate-key when two
            # gunicorn workers race a virgin database) must not abort
            # create_app - neither raises ServiceUnavailable, which is why
            # this guard is broad. The officers seed on the next boot.
            logger.exception("Setup: bootstrap officers not seeded this boot")

    # Optional real-clock rotation scheduler (ROTATION_SCHEDULER=1); off in
    # tests and dev unless explicitly enabled, never fabricated when quiet.
    if config.rotation_scheduler:
        start_rotation_scheduler(app, config.rotation_scheduler_interval)

    # Optional automatic-failover monitor (CLUSTER_MONITOR=1): while this
    # node is passive it probes the registered active peers on a real
    # clock and promotes with the failures as the reason.
    if config.cluster_monitor:
        start_cluster_monitor(app, config.cluster_monitor_interval)

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
