"""HTTP-mapped errors shared by the VY-PAM MASTER endpoints.

One base class keeps every route's failure shape identical:

    {"error": {"type": <error_type>, "message": <message>}}

with the class's ``status``. ``registry`` re-exports these names so the
existing registry imports keep working.
"""
from __future__ import annotations


class RegistryApiError(Exception):
    """Base for API failures the HTTP layer maps to a status code."""

    status = 500
    error_type = "internal_error"

    def __init__(self, message: str) -> None:
        super().__init__(message)
        self.message = message


class ValidationError(RegistryApiError):
    status = 400
    error_type = "validation_error"


class CustomerNotFound(RegistryApiError):
    status = 404
    error_type = "customer_not_found"


class LicenseNotFound(RegistryApiError):
    status = 404
    error_type = "license_not_found"


class LicenseConflict(RegistryApiError):
    """Operation is not legal for the license's current state (e.g. renewing
    an already-superseded license)."""

    status = 409
    error_type = "license_not_active"


class RegistryUnavailable(RegistryApiError):
    status = 503
    error_type = "registry_unavailable"


class SigningUnavailable(RegistryApiError):
    status = 503
    error_type = "signing_unavailable"


class DataIntegrityError(RegistryApiError):
    status = 500
    error_type = "registry_data_corrupt"
