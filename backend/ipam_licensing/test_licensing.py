"""
Test script demonstrating license generation and validation.

Runs entirely inside a temporary directory so it can never touch the real
signing keys or issued licenses kept at the repository root.
"""
import os
import tempfile

from license_tool import LicenseGenerator, LicenseType
from license_validator import LicenseValidator


def test_license_generation_and_validation():
    """Test generating and validating licenses."""
    print("=== IPAM Tool License System Test ===\n")

    with tempfile.TemporaryDirectory(prefix="ipam_license_demo_") as workdir:
        private_key_path = os.path.join(workdir, "license_private_key.pem")
        public_key_path = os.path.join(workdir, "license_public_key.pem")

        # 1. Generate a trial license
        print("1. Generating trial license...")
        generator = LicenseGenerator(private_key_path=private_key_path)
        # Save public key for validation
        with open(public_key_path, "wb") as f:
            f.write(generator.get_public_key_pem())
        trial_license_path = generator.generate_and_save_license(
            license_type=LicenseType.TRIAL,
            issued_to="Test Customer Inc.",
            output_dir=workdir,
            trial_days=30
        )

        # 2. Generate a subscription license
        print("\n2. Generating subscription license...")
        sub_license_path = generator.generate_and_save_license(
            license_type=LicenseType.SUBSCRIPTION,
            issued_to="Enterprise Corp.",
            output_dir=workdir,
            trial_days=365  # Annual subscription
        )

        # 3. Validate the trial license
        print("\n3. Validating trial license...")
        validator = LicenseValidator(public_key_path=public_key_path)
        status, license_obj = validator.validate_license_file(trial_license_path)

        print(f"   Status: {status.value}")
        if license_obj:
            info = validator.get_license_info(license_obj)
            print("   License Info:")
            for key, value in info.items():
                print(f"     {key}: {value}")

        # 4. Validate the subscription license
        print("\n4. Validating subscription license...")
        status, license_obj = validator.validate_license_file(sub_license_path)

        print(f"   Status: {status.value}")
        if license_obj:
            info = validator.get_license_info(license_obj)
            print("   License Info:")
            for key, value in info.items():
                print(f"     {key}: {value}")

        # 5. Test feature checking
        print("\n5. Testing feature access...")
        if license_obj:
            features_to_check = ["ip_discovery", "advanced_reporting", "api_access", "ldap_integration"]
            for feature in features_to_check:
                has_access = validator.check_feature_access(license_obj, feature)
                print(f"   {feature}: {'PASS' if has_access else 'FAIL'}")

        # 6. Test usage limit checking
        print("\n6. Testing usage limits...")
        if license_obj:
            limits_to_check = [
                ("max_users", 25),
                ("max_subnets", 500),
                ("max_devices", 5000)
            ]
            for limit_type, current_usage in limits_to_check:
                within_limit = validator.check_usage_limit(license_obj, limit_type, current_usage)
                limit_value = license_obj.usage_limits.get(limit_type, "No limit")
                result = "OK" if within_limit else "EXCEEDED"
                print(f"   {limit_type}: {current_usage}/{limit_value} -> {result}")

    print("\n=== Test Complete ===")
    print("(temporary license files and keys were removed automatically)")


if __name__ == "__main__":
    test_license_generation_and_validation()
