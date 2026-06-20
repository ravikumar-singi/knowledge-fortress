"""Shared pytest fixtures for Knowledge-Fortress test suite."""

from __future__ import annotations

import pytest

from src.fortress import (
    AccessLevel,
    ComplianceEngine,
    KnowledgeVault,
    UserRole,
    ValidationEngine,
)


@pytest.fixture(scope="session")
def vault() -> KnowledgeVault:
    """Return a single shared KnowledgeVault instance for the test session."""
    return KnowledgeVault()


@pytest.fixture(scope="session")
def validator(vault: KnowledgeVault) -> ValidationEngine:
    return ValidationEngine(vault)


@pytest.fixture(scope="session")
def compliance_engine(vault: KnowledgeVault) -> ComplianceEngine:
    return ComplianceEngine(vault)


@pytest.fixture
def fresh_vault() -> KnowledgeVault:
    """Return a fresh (but seeded) KnowledgeVault for tests that mutate it."""
    return KnowledgeVault()


# ---------------------------------------------------------------------------
# Sample medical text fixtures
# ---------------------------------------------------------------------------

VALID_MEDICAL_OUTPUT = (
    "Metformin is contraindicated in patients with severe renal impairment. "
    "Diabetes is treated with metformin and monitored via blood glucose. "
    "Lisinopril is approved for hypertension."
)

INVALID_MEDICAL_OUTPUT = (
    "Metformin is completely safe in all patients with kidney failure and cures diabetes. "
    "Studies show that warfarin prevents all strokes with 100% efficacy."
)

MIXED_MEDICAL_OUTPUT = (
    "Metformin is contraindicated in severe renal impairment. "
    "New revolutionary therapy eliminates diabetes permanently."
)

# ---------------------------------------------------------------------------
# Sample financial text fixtures
# ---------------------------------------------------------------------------

VALID_FINANCIAL_OUTPUT = (
    "The FDIC insures deposits up to $250,000 per depositor. "
    "KYC verification is required for all new accounts. "
    "Cash transactions over $10,000 require a Currency Transaction Report."
)

INVALID_FINANCIAL_OUTPUT = (
    "You can delete the audit trail after 30 days to save storage. "
    "The FDIC insures all deposits without any limit."
)

# ---------------------------------------------------------------------------
# PII samples
# ---------------------------------------------------------------------------

TEXT_WITH_PII = (
    "Patient Jane Smith, SSN 123-45-6789, email jane@example.com, "
    "phone 555-867-5309, DOB: 01/15/1980."
)

TEXT_WITHOUT_PII = (
    "The patient received standard treatment per clinical guidelines. "
    "Monitoring was performed at regular intervals."
)
