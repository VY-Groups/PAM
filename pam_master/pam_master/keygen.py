"""Create VY-PAM MASTER keys — the only way keys ever come to exist.

Usage (run from ``pam_master/`` or with the package importable)::

    python -m pam_master.keygen                 # RSA + Ed25519 + registry PII
    python -m pam_master.keygen --rsa-only
    python -m pam_master.keygen --ed25519-only
    python -m pam_master.keygen --registry-only

Paths come from ``MASTER_RSA_PRIVATE_KEY_PATH`` / ``MASTER_ED25519_PRIVATE_KEY_PATH``
/ ``MASTER_CUSTOMER_KEY_PATH`` (defaults: repo-root custody files and
``pam_master/customer_registry.key``, all git-ignored). Existing keys are
**kept** — this command never overwrites.
"""
from __future__ import annotations

import argparse
import sys
from typing import List, Optional

from pam_master.config import Config, ConfigError
from pam_master.keys import (
    KeyCustodyError,
    generate_ed25519_key,
    generate_registry_key,
    generate_rsa_key,
    key_presence,
)


def run(
    config: Config,
    rsa: bool = True,
    ed25519: bool = True,
    registry: bool = True,
) -> List[str]:
    """Generate the selected keys; returns human-readable result lines."""
    lines: List[str] = []
    jobs = []
    if rsa:
        jobs.append(
            ("RSA-PSS-SHA256", config.rsa_private_key_path,
             generate_rsa_key, True)
        )
    if ed25519:
        jobs.append(
            ("Ed25519", config.ed25519_private_key_path,
             generate_ed25519_key, True)
        )
    if registry:
        jobs.append(
            ("registry-PII", config.customer_key_path,
             generate_registry_key, False)
        )
    for algorithm, path, generator, has_public in jobs:
        if key_presence(path) == "present":
            lines.append(f"kept    {algorithm}: {path} (exists)")
            continue
        generator(path)
        lines.append(f"created {algorithm}: {path}")
        if has_public:
            public_path = path.with_name(
                path.stem.replace("private", "public") + path.suffix
            )
            lines.append(f"public  {algorithm}: {public_path}")
    return lines


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m pam_master.keygen",
        description="Create VY-PAM MASTER keys (never overwrites).",
    )
    parser.add_argument("--rsa-only", action="store_true",
                        help="generate only the RSA private key")
    parser.add_argument("--ed25519-only", action="store_true",
                        help="generate only the Ed25519 private key")
    parser.add_argument("--registry-only", action="store_true",
                        help="generate only the customer-registry PII key")
    args = parser.parse_args(argv)
    selected = [args.rsa_only, args.ed25519_only, args.registry_only]
    if sum(selected) > 1:
        parser.error(
            "choose at most one of --rsa-only / --ed25519-only "
            "/ --registry-only"
        )

    try:
        config = Config.from_env()
        for line in run(
            config,
            rsa=not (args.ed25519_only or args.registry_only),
            ed25519=not (args.rsa_only or args.registry_only),
            registry=not (args.rsa_only or args.ed25519_only),
        ):
            print(line)
    except (ConfigError, KeyCustodyError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
