"""VY-PAM MASTER — the vendor license authority (internal tool, never shipped).

This package is deliberately self-contained: it imports the shared crypto
engine (``backend/ipam_licensing``) but never the PAM runtime, and it is the
only place in the repository that holds license *private* keys. See
``pam_master/README.md`` for the custody rules and run instructions.
"""
from __future__ import annotations

from pam_master.app import create_app
from pam_master.config import Config, ConfigError

__all__ = ["Config", "ConfigError", "create_app"]
