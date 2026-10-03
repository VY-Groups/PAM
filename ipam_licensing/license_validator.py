"""
License validation tool for IPAM Tool.
Validates licenses cryptographically and checks status.
"""
import json
import base64
import os
from datetime import datetime
from typing import Tuple, Optional, Dict, Any
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature

from license import License, LicenseType, LicenseStatus


class LicenseValidator:
    """Validates licenses for the IPAM tool."""
    
    def __init__(self, public_key_path: str = "license_public_key.pem"):
        """
        Initialize license validator.
        
        Args:
            public_key_path: Path to RSA public key file for verification
        """
        self.public_key_path = public_key_path
        self.public_key = self._load_public_key()
    
    def _load_public_key(self):
        """Load public key from file."""
        if not os.path.exists(self.public_key_path):
            raise FileNotFoundError(f"Public key not found at {self.public_key_path}")
        
        with open(self.public_key_path, "rb") as key_file:
            return serialization.load_pem_public_key(key_file.read())
    
    def load_license_file(self, license_path: str) -> Tuple[Optional[Dict[str, Any]], Optional[str]]:
        """
        Load and parse license file.
        
        Args:
            license_path: Path to license file
            
        Returns:
            Tuple of (license_data_dict, signature) or (None, None) if invalid
        """
        try:
            with open(license_path, 'r') as f:
                license_file = json.load(f)
            
            # Anything that is not a JSON object (arrays, strings, numbers)
            # cannot hold a license; treat it as malformed rather than crash.
            if not isinstance(license_file, dict):
                return None, None
            
            license_data = license_file.get("license_data")
            signature = license_file.get("signature")
            
            if license_data is None or signature is None:
                return None, None
                
            return license_data, signature
        except (json.JSONDecodeError, FileNotFoundError, KeyError, TypeError):
            return None, None
    
    def verify_signature(self, license_data: Dict[str, Any], signature_b64: str) -> bool:
        """
        Verify license signature.
        
        Args:
            license_data: License data dictionary
            signature_b64: Base64-encoded signature
            
        Returns:
            True if signature is valid, False otherwise
        """
        try:
            # Convert license data to JSON with same sorting as during signing
            license_json = json.dumps(license_data, sort_keys=True, separators=(',', ':'))
            
            # Decode signature
            signature = base64.b64decode(signature_b64)
            
            # Verify signature
            self.public_key.verify(
                signature,
                license_json.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
        except Exception:
            return False
    
    def validate_license_file(self, license_path: str) -> Tuple[LicenseStatus, Optional[License]]:
        """
        Validate a license file.
        
        Args:
            license_path: Path to license file
            
        Returns:
            Tuple of (status, license_object) where license_object is None if invalid
        """
        # Load license file
        license_data, signature = self.load_license_file(license_path)
        if license_data is None or signature is None:
            return LicenseStatus.MALFORMED, None
        
        # Verify signature
        if not self.verify_signature(license_data, signature):
            return LicenseStatus.SIGNATURE_INVALID, None
        
        try:
            # Create license object
            license_obj = License.from_dict(license_data)
            
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