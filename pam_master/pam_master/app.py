"""Flask application factory for VY-PAM MASTER."""
from __future__ import annotations

from typing import Optional

from flask import Flask

from pam_master.config import Config
from pam_master.routes import master_bp


def create_app(config: Optional[Config] = None) -> Flask:
    """Build the vendor-tool app with an explicit config.

    Tests always pass their own isolated config (temp keys, temp database);
    ``None`` resolves ``MASTER_*`` from the environment.
    """
    app = Flask("vy_pam_master")
    app.config["MASTER_CONFIG"] = config or Config.from_env()
    app.register_blueprint(master_bp)
    return app
