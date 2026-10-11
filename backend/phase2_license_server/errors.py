"""API error type surfaced as JSON by the app-level error handlers."""
from __future__ import annotations

from typing import Any, Dict, Optional


class APIError(Exception):
    """Raised anywhere in the service/route layer; rendered as JSON."""

    def __init__(self, status_code: int, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(message)
        self.status_code = status_code
        self.message = message
        self.details = details or {}

    def to_dict(self) -> Dict[str, Any]:
        payload: Dict[str, Any] = {"error": self.message}
        if self.details:
            payload["details"] = self.details
        return payload


class NotFound(APIError):
    def __init__(self, message: str):
        super().__init__(404, message)


class ValidationFailed(APIError):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(400, message, details)


class Unauthorized(APIError):
    def __init__(
        self,
        message: str = "Admin authentication required",
        details: Optional[Dict[str, Any]] = None,
    ):
        super().__init__(401, message, details)


class Forbidden(APIError):
    """Authenticated, but this credential's role or scope may not do this."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(403, message, details)


class Conflict(APIError):
    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(409, message, details)


class ServiceUnavailable(APIError):
    """A required local dependency (e.g. the vault encryption key) is missing."""

    def __init__(self, message: str, details: Optional[Dict[str, Any]] = None):
        super().__init__(503, message, details)
