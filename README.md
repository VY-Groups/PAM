# IPAM Licensing

Cryptographic licensing for the IPAM tool: a signing/validation library
(Phase 1) and an issuing/revocation server (Phase 2).

```
PAM/
├── license_private_key.pem      # RSA-2048 signing key  (KEEP SECRET, never commit)
├── license_public_key.pem       # verification key      (ships to clients)
├── license_<UUID>.json          # licenses issued so far
├── ipam_licensing/              # Phase 1: library + CLIs
│   ├── license.py               #   data model (License, LicenseType, LicenseStatus)
│   ├── license_tool.py          #   LicenseGenerator (sign) + issuing CLI
│   ├── license_validator.py     #   LicenseValidator (verify) + validating CLI
│   ├── test_licensing.py        #   sandboxed demo script
│   └── test_license_core.py     #   pytest suite (47 tests)
├── stitch_pam_suite_dashboard_ui/  # Stitch design suite (AegisPAM)
│   ├── zero_trust_sentinel/DESIGN.md   # design tokens + system spec
│   ├── pam_command_center_threat_dashboard/ ...  # 8 static screens
│   └── license_entitlement_center/code.html      # live screen (served by Phase 2)
└── phase2_license_server/       # Phase 2: Flask API (see its README.md)
    ├── app.py / routes.py / service.py / models.py
    ├── tests/test_api.py        #   pytest suite (27 tests)
    └── README.md                #   full API reference
```

## Quick start

```bash
pip install -r ipam_licensing/requirements.txt -r phase2_license_server/requirements.txt

# Phase 1: generate a license from the CLI, then verify it
python ipam_licensing/license_tool.py --type subscription --issued-to "Acme Ltd" --output-dir .
python ipam_licensing/license_validator.py license_<UUID>.json --public-key license_public_key.pem

# Phase 2: run the issuing/revocation server
cd phase2_license_server && python app.py     # http://127.0.0.1:5000

# Tests (both phases)
python -m pytest -q                           # 74 tests
```

## How it fits together

- Licenses are JSON (`{license_data, signature, algorithm, version}`) signed
  with **RSA-PSS-SHA256** over canonical JSON (sorted keys, no whitespace).
- Phase 1 verifies a license **offline**: signature → structure → expiry.
- Phase 2 adds the things that cannot be known offline — **revocation**, an
  issuing **audit trail**, and a central place to look up who holds what.
  It imports Phase 1's signer/verifier directly (`licensing_bridge.py`), so the
  two can never drift apart: a license issued by the server validates with the
  Phase 1 CLI and vice versa.

## Key management

- `license_private_key.pem` **never leaves the server** and must never be
  committed or attached to a support ticket; it is excluded via `.gitignore`.
- `license_public_key.pem` is what clients embed for offline validation.
- Rotating the private key invalidates every license signed by the old one —
  keep the old public key around if previously issued licenses must still
  verify.
- Server startup fails fast if the public/private pair does not match
  (`phase2_license_server/keys.py`).
