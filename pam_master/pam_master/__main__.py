"""Run the vendor tool: ``python -m pam_master`` (binds to 127.0.0.1:5400).

Docker is a development convenience only (``pam_master/docker-compose.yml``);
the shipped product story — installs directly, no container runtime — is
documented in ``pam_master/README.md``.
"""
from __future__ import annotations

from pam_master.app import create_app
from pam_master.config import Config


def main() -> None:
    config = Config.from_env()
    app = create_app(config)
    app.run(host=config.host, port=config.port)


if __name__ == "__main__":
    main()
