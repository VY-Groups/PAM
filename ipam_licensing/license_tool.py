"""
License generation tool for IPAM Tool.
Generates secure licenses with cryptographic signatures.
"""
import uuid
import json
import base64
from datetime import datetime, timedelta
from typing import Optional, Dict, Any
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.exceptions import InvalidSignature
import os

from license import License, LicenseType


class LicenseGenerator:
    """Generates and signs licenses for the IPAM tool."""
    
    def __init__(self, private_key_path: str = "license_private_key.pem"):
        """
        Initialize license generator.
        
        Args:
            private_key_path: Path to RSA private key file for signing
        """
        self.private_key_path = private_key_path
        self.private_key = self._load_or_create_private_key()
    
    def _load_or_create_private_key(self):
        """Load existing private key or generate a new one."""
        if os.path.exists(self.private_key_path):
            with open(self.private_key_path, "rb") as key_file:
                return serialization.load_pem_private_key(
                    key_file.read(),
                    password=None
                )
        else:
            # Generate new RSA private key
            private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
            )
            # Save private key
            pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            )
            with open(self.private_key_path, "wb") as key_file:
                key_file.write(pem)
            print(f"Generated new private key at {self.private_key_path}")
            return private_key
    
    def get_public_key_pem(self) -> bytes:
        """Get public key in PEM format for distribution."""
        public_key = self.private_key.public_key()
        return public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def generate_license_key(self) -> str:
        """Generate a unique license key."""
        # Use UUID4 for uniqueness, format as XXXX-XXXX-XXXX-XXXX
        raw_uuid = str(uuid.uuid4())
        # Format as license key: 8-4-4-4-12 (standard UUID format with hyphens)
        return raw_uuid.upper()
    
    def sign_license(self, license_data: Dict[str, Any]) -> str:
        """
        Sign license data with private key.
        
        Args:
            license_data: Dictionary representation of license
            
        Returns:
            Base64-encoded signature
        """
        # Convert to JSON string with sorted keys for consistent signing
        license_json = json.dumps(license_data, sort_keys=True, separators=(',', ':'))
        
        # Sign the data
        signature = self.private_key.sign(
            license_json.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return base64.b64encode(signature).decode('utf-8')
    
    def generate_license(
        self,
        license_type: LicenseType,
        issued_to: str,
        trial_days: int = 30,
        features: Optional[list] = None,
        usage_limits: Optional[Dict[str, Any]] = None,
        metadata: Optional[Dict[str, Any]] = None
    ) -> License:
        """
        Generate a new license.
        
        Args:
            license_type: Type of license to generate
            issued_to: Customer/entity receiving the license
            trial_days: Number of days for trial licenses (ignored for non-trial)
            features: List of enabled features
            usage_limits: Usage constraints
            metadata: Additional information
            
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
            metadata=metadata or {}
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
    
    def save_license_file(self, license_obj: License, output_path: str) -> str:
        """
        Save license to file with signature.
        
        Args:
            license_obj: License to save
            output_path: Path to save license file
            
        Returns:
            Path to saved license file
        """
        # Prepare license data for signing
        license_data = license_obj.to_dict()
        
        # Generate signature
        signature = self.sign_license(license_data)
        
        # Create license file content
        license_file = {
            "license_data": license_data,
            "signature": signature,
            "algorithm": "RSA-PSS-SHA256",
            "version": "1.0"
        }
        
        # Write to file
        with open(output_path, 'w') as f:
            json.dump(license_file, f, indent=2)
        
        print(f"License saved to {output_path}")
        return output_path
    
    def generate_and_save_license(
        self,
        license_type: LicenseType,
        issued_to: str,
        output_dir: str = ".",
        trial_days: int = 30,
        **kwargs
    ) -> str:
        """
        Generate license and save to file.
        
        Args:
            license_type: Type of license
            issued_to: Recipient
            output_dir: Directory to save license file
            trial_days: Days for trial license
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
        filename = f"license_{license_obj.license_key}.json"
        output_path = os.path.join(output_dir, filename)
        
        # Save license
        return self.save_license_file(license_obj, output_path)


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
    
    args = parser.parse_args()
    
    # Create generator
    generator = LicenseGenerator()
    
    # Prepare optional arguments
    kwargs = {}
    if args.features:
        kwargs["features"] = args.features
    
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
            **kwargs
        )
        print(f"Successfully generated license: {output_path}")
        
        # Also save public key for verification
        public_key_path = os.path.join(args.output_dir, "license_public_key.pem")
        with open(public_key_path, "wb") as f:
            f.write(generator.get_public_key_pem())
        print(f"Public key saved to: {public_key_path}")
        
    except Exception as e:
        print(f"Error generating license: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())