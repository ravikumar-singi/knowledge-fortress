"""
Knowledge-Fortress
==================
Production-grade knowledge management and validation for regulated industries.
"""

from .exceptions import (
    AccessDeniedError,
    ComplianceViolationError,
    DuplicateFactError,
    FactNotFoundError,
    ImmutabilityViolationError,
    KnowledgeFortressError,
    PIIDetectedError,
    ValidationError,
)
from .fortress import (
    AccessLevel,
    AuditAction,
    AuditEntry,
    AuditResult,
    ComplianceEngine,
    FactMetadata,
    KnowledgeVault,
    UserRole,
    ValidationEngine,
    ValidationRecommendation,
    ValidationResult,
    validate_access,
)

__all__ = [
    # Core classes
    "KnowledgeVault",
    "ValidationEngine",
    "ComplianceEngine",
    # Data structures
    "FactMetadata",
    "ValidationResult",
    "AuditEntry",
    # Enums
    "AccessLevel",
    "UserRole",
    "AuditAction",
    "AuditResult",
    "ValidationRecommendation",
    # Access control
    "validate_access",
    # Exceptions
    "KnowledgeFortressError",
    "ValidationError",
    "AccessDeniedError",
    "ComplianceViolationError",
    "FactNotFoundError",
    "DuplicateFactError",
    "ImmutabilityViolationError",
    "PIIDetectedError",
]
