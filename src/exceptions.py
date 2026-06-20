"""Custom exceptions for Knowledge-Fortress."""


class KnowledgeFortressError(Exception):
    """Base exception for all Knowledge-Fortress errors."""


class ValidationError(KnowledgeFortressError):
    """Raised when a validation operation fails or produces a blocking result."""


class AccessDeniedError(KnowledgeFortressError):
    """Raised when a user attempts to access a resource above their clearance level."""


class ComplianceViolationError(KnowledgeFortressError):
    """Raised when an operation would violate a regulatory compliance requirement."""


class FactNotFoundError(KnowledgeFortressError):
    """Raised when a requested fact_id does not exist in the vault."""


class DuplicateFactError(KnowledgeFortressError):
    """Raised when attempting to add a fact that already exists with identical content."""


class ImmutabilityViolationError(KnowledgeFortressError):
    """Raised when code attempts to modify an immutable audit entry."""


class PIIDetectedError(ComplianceViolationError):
    """Raised when personally identifiable information is detected in an operation."""
