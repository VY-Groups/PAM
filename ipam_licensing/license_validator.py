"""
License validation tool for IPAM Tool.
Validates licenses cryptographically and checks status.

Understands both wire formats (the original JSON envelope and compact
``.lic`` / ``.jwt`` JWS tokens) and both signature algorithms
(RSA-PSS-SHA256 and Ed25519); the rules live in ``signature``.
"""
import json
import os
from pathlib import Path
from typing import Optional, Dict, Any, Tuple
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from license import License, LicenseType, LicenseStatus, MODULE_CATALOG
import signature as sig


class LicenseValidator:
    """Validates licenses for the IPAM tool."""

    def __init__(
        self,
        public_key_path: str = "license_public_key.pem",
        ed25519_public_key_path: Optional[str] = None,
    ):
        """
        Initialize license validator.

        Args:
            public_key_path: Path to RSA public key file for verification
            ed25519_public_key_path: Optional Ed25519 public key. Defaults to
                ``license_ed25519_public.pem`` next to the RSA key; loaded only
                when present, so RSA-only deployments keep working.
        """
        self.public_key_path = public_key_path
        self.public_key = self._load_public_key()
        rsa_path = Path(public_key_path)
        self.ed25519_public_key_path = str(
            Path(ed25519_public_key_path)
            if ed25519_public_key_path
            else rsa_path.with_name("license_ed25519_public.pem")
        )
        self._ed25519_public_key: Optional[ed25519.Ed25519PublicKey] = None
        self._ed25519_loaded = False

    # ------------------------------------------------------------------ keys
    def _load_public_key(self):
        """Load public key from file."""
        if not os.path.exists(self.public_key_path):
            raise FileNotFoundError(f"Public key not found at {self.public_key_path}")
        
        with open(self.public_key_path, "rb") as key_file:
            return serialization.load_pem_public_key(key_file.read())

    def public_key_for(self, algorithm: str):
        """Return the verifying key for an algorithm, or None when absent."""
        if algorithm == sig.ALGORITHM_RSA:
            return self.public_key
        if algorithm == sig.ALGORITHM_ED25519:
            if not self._ed25519_loaded:
                self._ed25519_loaded = True
                if os.path.exists(self.ed25519_public_key_path):
                    with open(self.ed25519_public_key_path, "rb") as key_file:
                        key = serialization.load_pem_public_key(key_file.read())
                    if isinstance(key, ed25519.Ed25519PublicKey):
                        self._ed25519_public_key = key
            return self._ed25519_public_key
        return None

    # -------------------------------------------------------------- envelopes
    def load_license_envelope(self, license_path: str) -> Optional[Dict[str, Any]]:
        """
        Load a license file in either supported format.

        Returns a signature envelope (``license_data`` + ``signature`` +
        ``algorithm`` + ``format``), or None when the file cannot be parsed.
        """
        try:
            with open(license_path, "r", encoding="utf-8") as handle:
                raw = handle.read()
        except (FileNotFoundError, OSError, UnicodeDecodeError):
            return None

        stripped = raw.strip()
        if not stripped:
            return None

        if stripped.startswith("{"):
            try:
                document = json.loads(stripped)
            except json.JSONDecodeError:
                return None
            # A JSON object that is not a license envelope may still wrap one.
            return sig.parse_envelope(document)

        # Anything else is treated as a compact .lic / .jwt token.
        return sig.parse_envelope(stripped)

    def load_license_file(self, license_path: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """
        Load and parse license file.
        
        Args:
            license_path: Path to license file
            
        Returns:
            Tuple of (license_data_dict, signature) or (None, None) if invalid
        """
        envelope = self.load_license_envelope(license_path)
        if envelope is None:
            return None, None
        return envelope.get("license_data"), envelope.get("signature")

    def verify_envelope(self, envelope: Optional[Dict[str, Any]]) -> bool:
        """Verify an envelope in either format against the right public key."""
        if not isinstance(envelope, dict):
            return False
        algorithm = str(envelope.get("algorithm") or sig.DEFAULT_ALGORITHM)
        key = self.public_key_for(algorithm)
        if key is None:
            return False
        return sig.verify_envelope(key, envelope)

    def verify_signature(
        self,
        license_data: Dict[str, Any],
        signature_b64: str,
        algorithm: str = sig.DEFAULT_ALGORITHM,
    ) -> bool:
        """
        Verify license signature.
        
        Args:
            license_data: License data dictionary
            signature_b64: Base64-encoded signature
            algorithm: Signature algorithm used to produce the signature
            
        Returns:
            True if signature is valid, False otherwise
        """
        key = self.public_key_for(algorithm)
        if key is None:
            return False
        return sig.verify_claims(key, license_data, signature_b64, algorithm)

    def validate_license_file(self, license_path: str) -> Tuple[LicenseStatus, Optional[License]]:
        """
        Validate a license file (JSON envelope or compact token).
        
        Args:
            license_path: Path to license file
            
        Returns:
            Tuple of (status, license_object) where license_object is None if invalid
        """
        envelope = self.load_license_envelope(license_path)
        if envelope is None:
            return LicenseStatus.MALFORMED, None

        # Verify signature
        if not self.verify_envelope(envelope):
            return LicenseStatus.SIGNATURE_INVALID, None

        try:
            # Create license object
            license_obj = License.from_dict(envelope["license_data"])

            # Check if expired
            if license_obj.is_expired():
                return LicenseStatus.EXPIRED, license_obj

            # License is valid
            return LicenseStatus.VALID, license_obj
        except (KeyError, ValueError, TypeError):
            return LicenseStatus.MALFORMED, None

    def validate_license_key_format(self, license_key: str) -> bool:
        """
        Validate that a string looks like a license key.
        
        Args:
            license_key: String to validate
            
        Returns:
            True if format matches expected license key pattern
        """
        # Expected format: XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX (UUID format)
        import re
        pattern = r'^[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}$'
        return bool(re.match(pattern, license_key.upper()))

    def check_feature_access(self, license: License, feature: str) -> bool:
        """
        Check if license grants access to a specific feature.
        
        Args:
            license: License object
            feature: Feature name to check
            
        Returns:
            True if feature is enabled, False otherwise
        """
        return feature in license.features

    def check_module_access(self, license: License, module_id: str) -> bool:
        """
        Check if a zero-trust entitlement module is granted.

        Args:
            license: License object
            module_id: Module id from the entitlement catalog
        """
        return module_id in license.entitled_module_ids

    def check_usage_limit(self, license: License, limit_type: str, current_usage: int) -> bool:
        """
        Check if current usage exceeds license limit.
        
        Args:
            license: License object
            limit_type: Type of limit (e.g., 'max_users', 'max_subnets')
            current_usage: Current usage count
            
        Returns:
            True if within limits, False if exceeded
        """
        limit = license.usage_limits.get(limit_type)
        if limit is None:
            limit = license.quotas.get(limit_type) if license.quotas else None
        if limit is None:
            return True  # No limit set
        
        return current_usage <= limit

    def get_license_info(self, license: License) -> Dict[str, Any]:
        """
        Get formatted license information for display.
        
        Args:
            license: License object
            
        Returns:
            Dictionary with license information
        """
        info = {
            "license_key": license.license_key,
            "type": license.license_type.value,
            "issued_to": license.issued_to,
            "issued_date": license.issued_date.strftime("%Y-%m-%d"),
            "status": "VALID" if not license.is_expired() else "EXPIRED",
            "features": license.features,
            "usage_limits": license.usage_limits
        }

        # Enterprise licensing spec fields (present only when set on the license)
        for field in ("tier", "plan", "license_id", "subject_entity",
                      "classification", "issuer", "enclave_binding"):
            value = getattr(license, field, None)
            if value:
                info[field] = value
        if license.quotas:
            info["quotas"] = license.quotas
        if license.modules:
            info["modules"] = license.modules
            info["entitled_modules"] = license.entitled_module_ids
        if license.account:
            info["account"] = license.account
        if license.license_id or license.tier:
            info["module_catalog_size"] = len(MODULE_CATALOG)

        if license.expires_on:
            info["expires_on"] = license.expires_on.strftime("%Y-%m-%d")
            info["days_until_expiry"] = license.days_until_expiry()
        else:
            info["expires_on"] = "PERPETUAL"
            info["days_until_expiry"] = None
            
        return info


def validate_license(license_path: str, public_key_path: str = "license_public_key.pem") -> None:
    """
    Simple function to validate a license and print results.
    
    Args:
        license_path: Path to license file
        public_key_path: Path to public key file
    """
    try:
        validator = LicenseValidator(public_key_path)
        status, license_obj = validator.validate_license_file(license_path)
        
        print(f"License validation result: {status.value}")
        
        if license_obj:
            info = validator.get_license_info(license_obj)
            print("\nLicense Information:")
            for key, value in info.items():
                print(f"  {key}: {value}")
        else:
            print("Invalid license file.")
            
    except Exception as e:
        print(f"Error validating license: {e}")


def main():
    """Command-line interface for license validation."""
    import argparse
    
    parser = argparse.ArgumentParser(description="Validate licenses for IPAM Tool")
    parser.add_argument(
        "license_file",
        help="Path to license file to validate"
    )
    parser.add_argument(
        "--public-key",
        default="license_public_key.pem",
        help="Path to public key file (default: license_public_key.pem)"
    )
    
    args = parser.parse_args()
    
    validate_license(args.license_file, args.public_key)


if __name__ == "__main__":
    main()
