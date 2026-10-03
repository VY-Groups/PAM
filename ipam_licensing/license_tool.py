"""
License generation tool for IPAM Tool.
Generates secure licenses with cryptographic signatures.

Supports two signature algorithms (RSA-PSS-SHA256 and Ed25519) and two wire
formats (the original JSON envelope and compact JWS/JWT tokens for air-gapped
``.lic`` / ``.jwt`` ingestion). All of the cryptography lives in ``signature``
so the validator never has to guess.
"""
import base64
import json
import os
import secrets
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, Optional, Union

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from license import (
    DEFAULT_CLASSIFICATIONS,
    DEFAULT_ISSUER,
    DEFAULT_PLANS,
    DEFAULT_TIERS,
    License,
    LicenseType,
    default_modules,
    default_quotas,
)
import signature as sig

KeyLike = Union[rsa.RSAPrivateKey, ed25519.Ed25519PrivateKey]


class LicenseGenerator:
    """Generates and signs licenses for the IPAM tool."""

    def __init__(
        self,
        private_key_path: str = "license_private_key.pem",
        ed25519_private_key_path: Optional[str] = None,
    ):
        """
        Initialize license generator.

        Args:
            private_key_path: Path to RSA private key file for signing
            ed25519_private_key_path: Path to the Ed25519 private key. Defaults
                to ``license_ed25519_private.pem`` next to the RSA key; it is
                created on first use.
        """
        self.private_key_path = private_key_path
        rsa_path = Path(private_key_path)
        self.ed25519_private_key_path = str(
            Path(ed25519_private_key_path)
            if ed25519_private_key_path
            # Default sits beside the RSA key with matching naming, which is
            # where LicenseValidator looks for the public counterpart.
            else rsa_path.with_name("license_ed25519_private.pem")
        )
        # The RSA key stays eagerly loaded: startup checks and existing callers
        # depend on a missing/corrupt key failing immediately.
        self.private_key = self._load_or_create_private_key(
            self.private_key_path, sig.ALGORITHM_RSA
        )
        self._ed25519_private_key: Optional[KeyLike] = None

    # ------------------------------------------------------------------ keys
    @staticmethod
    def _load_or_create_private_key(path: str, algorithm: str) -> KeyLike:
        """Load existing private key or generate a new one."""
        if os.path.exists(path):
            with open(path, "rb") as key_file:
                return serialization.load_pem_private_key(
                    key_file.read(),
                    password=None
                )

        if algorithm == sig.ALGORITHM_ED25519:
            private_key: KeyLike = ed25519.Ed25519PrivateKey.generate()
        else:
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )

        pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        with open(path, "wb") as key_file:
            key_file.write(pem)
        print(f"Generated new {algorithm} private key at {path}")

        # Keep the matching public key on disk for validators/offline clients.
        public_path = str(Path(path).with_name(Path(path).stem.replace(
            "private", "public"
        ) + ".pem"))
        if public_path != path and not os.path.exists(public_path):
            with open(public_path, "wb") as public_file:
                public_file.write(
                    private_key.public_key().public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo,
                    )
                )
            print(f"Generated new {algorithm} public key at {public_path}")
        return private_key

    def private_key_for(self, algorithm: str = sig.DEFAULT_ALGORITHM) -> KeyLike:
        """Return (creating on demand) the private key for an algorithm."""
        if algorithm == sig.ALGORITHM_RSA:
            return self.private_key
        if algorithm == sig.ALGORITHM_ED25519:
            if self._ed25519_private_key is None:
                self._ed25519_private_key = self._load_or_create_private_key(
                    self.ed25519_private_key_path, sig.ALGORITHM_ED25519
                )
            return self._ed25519_private_key
        raise sig.UnsupportedAlgorithm(f"Unsupported algorithm '{algorithm}'")

    def get_public_key_pem(self, algorithm: str = sig.DEFAULT_ALGORITHM) -> bytes:
        """Get public key in PEM format for distribution."""
        return self.private_key_for(algorithm).public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def generate_license_key(self) -> str:
        """Generate a unique license key."""
        # Use UUID4 for uniqueness, format as XXXX-XXXX-XXXX-XXXX
        raw_uuid = str(uuid.uuid4())
        # Format as license key: 8-4-4-4-12 (standard UUID format with hyphens)
        return raw_uuid.upper()

    @staticmethod
    def generate_license_id(environment: str = "PROD") -> str:
        """Generate a human-readable license id (LIC-9942-AEGIS-SEC-PROD)."""
        sequence = secrets.randbelow(9000) + 1000
        env = "".join(ch for ch in environment.upper() if ch.isalnum() or ch == "-") or "PROD"
        return f"LIC-{sequence}-AEGIS-SEC-{env}"

    # -------------------------------------------------------------- signing
    def sign_license(
        self,
        license_data: Dict[str, Any],
        algorithm: str = sig.DEFAULT_ALGORITHM,
    ) -> str:
        """
        Sign license data with private key.

        Args:
            license_data: Dictionary representation of license
            algorithm: Signature algorithm to sign with

        Returns:
            Base64-encoded signature
        """
        return sig.sign_claims(self.private_key_for(algorithm), license_data, algorithm)

    def sign_license_bytes(
        self,
        license_data: Dict[str, Any],
        algorithm: str = sig.DEFAULT_ALGORITHM,
    ) -> bytes:
        """Sign and return the raw signature bytes (used for fingerprints)."""
        return base64.b64decode(self.sign_license(license_data, algorithm))

    # ----------------------------------------------------------- generation
    def generate_license(
        self,
        license_type: LicenseType,
        issued_to: str,
        trial_days: int = 30,
        features: Optional[list] = None,
        usage_limits: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        tier: Optional[str] = None,
        plan: Optional[str] = None,
        license_id: Optional[str] = None,
        subject_entity: Optional[str] = None,
        classification: Optional[str] = None,
        issuer: Optional[str] = None,
        enclave_binding: Optional[str] = None,
        quotas: Optional[Dict[str, Any]] = None,
        modules: Optional[list] = None,
        account: Optional[Dict[str, Any]] = None,
        environment: str = "PROD",
    ) -> License:
        """
        Generate a new license.

        Args:
            license_type: Type of license to generate
            issued_to: Customer/entity receiving the license
            trial_days: Number of days for trial licenses (ignored for non-trial)
            features: List of enabled features
            usage_limits: Usage constraints (users/subnets/devices)
            metadata: Additional information
            tier / plan / classification: Commercial display fields
            license_id: Human readable id (generated when omitted)
            subject_entity: Legal entity (defaults to issued_to)
            issuer: Issuing authority (defaults to the air-gap root)
            enclave_binding: Optional TPM/PCR binding
            quotas: Node/session/tunnel ceilings + node pool breakdown
            modules: Entitlement modules (defaults to the tier's set)
            account: Account & SLA block
            environment: Environment segment used in a generated license id

        Returns:
            Generated License object
        """
        # Generate license key
        license_key = self.generate_license_key()

        # Set issue date
        issued_date = datetime.now()

        # Set expiration date based on license type
        expires_on = None
        if license_type == LicenseType.TRIAL:
            expires_on = issued_date + timedelta(days=trial_days)
        elif license_type == LicenseType.SUBSCRIPTION:
            # For Phase 1, assume annual subscription
            expires_on = issued_date + timedelta(days=365)
        # PERPETUAL and ENTERPRISE don't expire by default (can be customized in metadata)

        # Set default features based on license type
        if features is None:
            features = self._get_default_features(license_type)

        # Set default usage limits
        if usage_limits is None:
            usage_limits = self._get_default_usage_limits(license_type)

        # Create license object
        license_obj = License(
            license_key=license_key,
            license_type=license_type,
            issued_to=issued_to,
            issued_date=issued_date,
            expires_on=expires_on,
            features=features,
            usage_limits=usage_limits,
            metadata=metadata or {},
            tier=tier or DEFAULT_TIERS[license_type],
            plan=plan or DEFAULT_PLANS[license_type],
            license_id=license_id or self.generate_license_id(environment),
            subject_entity=subject_entity or issued_to,
            classification=classification or DEFAULT_CLASSIFICATIONS[license_type],
            issuer=issuer or DEFAULT_ISSUER,
            enclave_binding=enclave_binding,
            quotas=quotas if quotas is not None else default_quotas(license_type),
            modules=modules if modules is not None else default_modules(license_type),
            account=account or {},
        )

        return license_obj

    def _get_default_features(self, license_type: LicenseType) -> list:
        """Get default features for license type."""
        base_features = ["ip_discovery", "subnet_management", "basic_reporting"]

        if license_type == LicenseType.TRIAL:
            return base_features
        elif license_type == LicenseType.SUBSCRIPTION:
            return base_features + ["advanced_reporting", "api_access", "email_alerts"]
        elif license_type == LicenseType.PERPETUAL:
            return base_features + ["advanced_reporting"]
        elif license_type == LicenseType.ENTERPRISE:
            return base_features + ["advanced_reporting", "api_access", "email_alerts", 
                                  "ldap_integration", "custom_dashboards", "multi_tenant"]
        else:
            return base_features

    def _get_default_usage_limits(self, license_type: LicenseType) -> Dict[str, Any]:
        """Get default usage limits for license type."""
        if license_type == LicenseType.TRIAL:
            return {"max_users": 5, "max_subnets": 100, "max_devices": 1000}
        elif license_type == LicenseType.SUBSCRIPTION:
            return {"max_users": 50, "max_subnets": 1000, "max_devices": 10000}
        elif license_type == LicenseType.PERPETUAL:
            return {"max_users": 20, "max_subnets": 500, "max_devices": 5000}
        elif license_type == LicenseType.ENTERPRISE:
            return {"max_users": 1000, "max_subnets": 10000, "max_devices": 100000}
        else:
            return {"max_users": 5, "max_subnets": 100, "max_devices": 1000}

    # ------------------------------------------------------------ serialising
    def build_license_file(
        self,
        license_obj: License,
        algorithm: str = sig.DEFAULT_ALGORITHM,
        file_format: str = sig.FORMAT_JSON,
    ) -> Dict[str, Any]:
        """
        Sign a license and return its wire envelope.

        For ``json`` this is the original Phase 1 envelope. For ``jwt`` the
        envelope holds the compact token as well, so callers can serve either
        representation without re-signing.
        """
        license_data = license_obj.to_dict()
        if file_format == sig.FORMAT_JWT:
            token, _signing_input = sig.encode_token(
                self.private_key_for(algorithm), license_data, algorithm
            )
            envelope = sig.decode_token(token)  # keeps header + signing input
            envelope["token"] = token
            envelope["fingerprint"] = sig.fingerprint(
                base64.b64decode(envelope["signature"])
            )
            return envelope

        if file_format != sig.FORMAT_JSON:
            raise sig.UnsupportedAlgorithm(f"Unsupported license format '{file_format}'")

        signature_b64 = self.sign_license(license_data, algorithm)
        return {
            "license_data": license_data,
            "signature": signature_b64,
            "algorithm": algorithm,
            "format": sig.FORMAT_JSON,
            "version": sig.ENVIRONMENT_VERSION,
            "fingerprint": sig.fingerprint(base64.b64decode(signature_b64)),
        }

    def save_license_file(
        self,
        license_obj: License,
        output_path: str,
        algorithm: str = sig.DEFAULT_ALGORITHM,
        file_format: str = sig.FORMAT_JSON,
    ) -> str:
        """
        Save license to file with signature.

        Args:
            license_obj: License to save
            output_path: Path to save license file
            algorithm: Signature algorithm
            file_format: 'json' (envelope) or 'jwt' (compact token)

        Returns:
            Path to saved license file
        """
        envelope = self.build_license_file(license_obj, algorithm, file_format)

        if file_format == sig.FORMAT_JWT:
            with open(output_path, 'w') as f:
                f.write(envelope["token"])
        else:
            payload = {
                key: value
                for key, value in envelope.items()
                if key not in ("token", "signing_input")
            }
            with open(output_path, 'w') as f:
                json.dump(payload, f, indent=2)

        print(f"License saved to {output_path}")
        return output_path

    def generate_and_save_license(
        self,
        license_type: LicenseType,
        issued_to: str,
        output_dir: str = ".",
        trial_days: int = 30,
        algorithm: str = sig.DEFAULT_ALGORITHM,
        file_format: str = sig.FORMAT_JSON,
        **kwargs
    ) -> str:
        """
        Generate license and save to file.

        Args:
            license_type: Type of license
            issued_to: Recipient
            output_dir: Directory to save license file
            trial_days: Number of days for trial license
            algorithm: Signature algorithm
            file_format: 'json' or 'jwt'
            **kwargs: Additional license parameters

        Returns:
            Path to generated license file
        """
        # Generate license
        license_obj = self.generate_license(
            license_type=license_type,
            issued_to=issued_to,
            trial_days=trial_days,
            **kwargs
        )

        # Create filename
        extension = "jwt" if file_format == sig.FORMAT_JWT else "json"
        filename = f"license_{license_obj.license_key}.{extension}"
        output_path = os.path.join(output_dir, filename)

        # Save license
        return self.save_license_file(license_obj, output_path, algorithm, file_format)


def main():
    """Command-line interface for license generation."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate licenses for IPAM Tool")
    parser.add_argument(
        "--type", 
        choices=[t.value for t in LicenseType],
        required=True,
        help="Type of license to generate"
    )
    parser.add_argument(
        "--issued-to",
        required=True,
        help="Customer/entity to issue license to"
    )
    parser.add_argument(
        "--output-dir",
        default=".",
        help="Directory to save license file (default: current directory)"
    )
    parser.add_argument(
        "--trial-days",
        type=int,
        default=30,
        help="Number of days for trial license (default: 30)"
    )
    parser.add_argument(
        "--features",
        nargs="+",
        help="List of features to enable (overrides defaults)"
    )
    parser.add_argument(
        "--max-users",
        type=int,
        help="Maximum number of users (overrides defaults)"
    )
    parser.add_argument(
        "--max-subnets",
        type=int,
        help="Maximum number of subnets (overrides defaults)"
    )
    parser.add_argument(
        "--max-devices",
        type=int,
        help="Maximum number of devices (overrides defaults)"
    )
    parser.add_argument(
        "--algorithm",
        choices=list(sig.SUPPORTED_ALGORITHMS),
        default=sig.DEFAULT_ALGORITHM,
        help="Signature algorithm (default: RSA-PSS-SHA256)"
    )
    parser.add_argument(
        "--format",
        choices=list(sig.SUPPORTED_FORMATS),
        default=sig.FORMAT_JSON,
        dest="file_format",
        help="License file format: json envelope or compact jwt for .lic/.jwt"
    )
    parser.add_argument(
        "--tier",
        help="Override the commercial tier display name"
    )
    parser.add_argument(
        "--plan",
        help="Override the commercial plan display name"
    )
    parser.add_argument(
        "--enclave-binding",
        help="Hardware enclave binding (e.g. 'TPM 2.0 PCR Registers 0 & 7')"
    )
    
    args = parser.parse_args()
    
    # Create generator
    generator = LicenseGenerator()
    
    # Prepare optional arguments
    kwargs = {}
    if args.features:
        kwargs["features"] = args.features
    if args.tier:
        kwargs["tier"] = args.tier
    if args.plan:
        kwargs["plan"] = args.plan
    if args.enclave_binding:
        kwargs["enclave_binding"] = args.enclave_binding
    
    usage_limits = {}
    if args.max_users is not None:
        usage_limits["max_users"] = args.max_users
    if args.max_subnets is not None:
        usage_limits["max_subnets"] = args.max_subnets
    if args.max_devices is not None:
        usage_limits["max_devices"] = args.max_devices
    if usage_limits:
        kwargs["usage_limits"] = usage_limits
    
    # Generate and save license
    try:
        license_type = LicenseType(args.type)
        output_path = generator.generate_and_save_license(
            license_type=license_type,
            issued_to=args.issued_to,
            output_dir=args.output_dir,
            trial_days=args.trial_days,
            algorithm=args.algorithm,
            file_format=args.file_format,
            **kwargs
        )
        print(f"Successfully generated license: {output_path}")
        
        # Also save public keys for verification. The RSA key is always written
        # (validators require it as their base key); an Ed25519 run additionally
        # refreshes the Ed25519 public key it signs with.
        public_key_path = os.path.join(args.output_dir, "license_public_key.pem")
        with open(public_key_path, "wb") as f:
            f.write(generator.get_public_key_pem(sig.ALGORITHM_RSA))
        print(f"Public key saved to: {public_key_path}")
        if args.algorithm != sig.ALGORITHM_RSA:
            ed_public_path = os.path.join(args.output_dir, "license_ed25519_public.pem")
            with open(ed_public_path, "wb") as f:
                f.write(generator.get_public_key_pem(args.algorithm))
            print(f"Public key saved to: {ed_public_path}")
        
    except Exception as e:
        print(f"Error generating license: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())
