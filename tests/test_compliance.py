"""Unit tests for ComplianceEngine."""

from __future__ import annotations

import pytest

from src.fortress import AccessLevel, ComplianceEngine, KnowledgeVault
from tests.conftest import TEXT_WITH_PII, TEXT_WITHOUT_PII


class TestPIIDetection:
    def test_pii_detected_in_sensitive_text(
        self, compliance_engine: ComplianceEngine
    ) -> None:
        pii_found, categories = compliance_engine.check_pii_exposure(TEXT_WITH_PII)
        assert pii_found is True
        assert len(categories) > 0

    def test_ssn_detected(self, compliance_engine: ComplianceEngine) -> None:
        _, categories = compliance_engine.check_pii_exposure(
            "The patient SSN is 123-45-6789."
        )
        assert "SSN" in categories

    def test_email_detected(self, compliance_engine: ComplianceEngine) -> None:
        _, categories = compliance_engine.check_pii_exposure(
            "Contact us at admin@company.com for details."
        )
        assert "Email" in categories

    def test_phone_detected(self, compliance_engine: ComplianceEngine) -> None:
        _, categories = compliance_engine.check_pii_exposure(
            "Call us at 555-867-5309."
        )
        assert "Phone" in categories

    def test_credit_card_detected(self, compliance_engine: ComplianceEngine) -> None:
        _, categories = compliance_engine.check_pii_exposure(
            "Card number: 4111111111111111"
        )
        assert "Credit_Card" in categories

    def test_no_pii_in_clean_text(self, compliance_engine: ComplianceEngine) -> None:
        pii_found, categories = compliance_engine.check_pii_exposure(TEXT_WITHOUT_PII)
        assert pii_found is False
        assert categories == []

    def test_pii_categories_returns_descriptions(
        self, compliance_engine: ComplianceEngine
    ) -> None:
        categories = compliance_engine.check_pii_categories()
        assert isinstance(categories, dict)
        assert "SSN" in categories
        assert "Email" in categories
        assert "Phone" in categories


class TestRegulatoryCompliance:
    def test_hipaa_clean_text_compliant(
        self, compliance_engine: ComplianceEngine
    ) -> None:
        is_compliant, _ = compliance_engine.check_regulatory_compliance(
            "The patient received standard care per protocol.", regulation="HIPAA"
        )
        assert is_compliant is True

    def test_hipaa_pii_exposure_non_compliant(
        self, compliance_engine: ComplianceEngine
    ) -> None:
        is_compliant, explanation = compliance_engine.check_regulatory_compliance(
            "Patient SSN 123-45-6789 was stored in the public database.",
            regulation="HIPAA",
        )
        assert is_compliant is False
        assert "HIPAA" in explanation

    def test_gdpr_pii_exposure_non_compliant(
        self, compliance_engine: ComplianceEngine
    ) -> None:
        is_compliant, _ = compliance_engine.check_regulatory_compliance(
            "We store email john@example.com indefinitely.", regulation="GDPR"
        )
        assert is_compliant is False

    def test_gdpr_clean_text_compliant(
        self, compliance_engine: ComplianceEngine
    ) -> None:
        is_compliant, _ = compliance_engine.check_regulatory_compliance(
            "Data is retained for 90 days and then securely deleted.",
            regulation="GDPR",
        )
        assert is_compliant is True

    def test_sox_audit_deletion_non_compliant(
        self, compliance_engine: ComplianceEngine
    ) -> None:
        is_compliant, explanation = compliance_engine.check_regulatory_compliance(
            "We will delete the audit log after 30 days to save storage.",
            regulation="SOX",
        )
        assert is_compliant is False
        assert "SOX" in explanation

    def test_sox_clean_claim_compliant(
        self, compliance_engine: ComplianceEngine
    ) -> None:
        is_compliant, _ = compliance_engine.check_regulatory_compliance(
            "Financial records are retained for 7 years in an immutable audit trail.",
            regulation="SOX",
        )
        assert is_compliant is True

    def test_fda_absolute_language_non_compliant(
        self, compliance_engine: ComplianceEngine
    ) -> None:
        is_compliant, explanation = compliance_engine.check_regulatory_compliance(
            "This medication is a guaranteed cure for all patients.",
            regulation="FDA",
        )
        assert is_compliant is False
        assert "FDA" in explanation

    def test_unsupported_regulation_raises(
        self, compliance_engine: ComplianceEngine
    ) -> None:
        with pytest.raises(ValueError, match="Unsupported regulation"):
            compliance_engine.check_regulatory_compliance(
                "Some claim.", regulation="ISO27001"
            )


class TestDataClassification:
    def test_text_with_pii_classified_restricted(
        self, compliance_engine: ComplianceEngine
    ) -> None:
        level = compliance_engine.check_data_classification(TEXT_WITH_PII)
        assert level == AccessLevel.RESTRICTED

    def test_text_with_patient_keyword_restricted(
        self, compliance_engine: ComplianceEngine
    ) -> None:
        level = compliance_engine.check_data_classification(
            "The patient diagnosis is confidential."
        )
        assert level == AccessLevel.RESTRICTED

    def test_public_text_classified_public(
        self, compliance_engine: ComplianceEngine
    ) -> None:
        level = compliance_engine.check_data_classification(
            "The weather today is sunny."
        )
        assert level == AccessLevel.PUBLIC

    def test_confidential_text_classified_confidential(
        self, compliance_engine: ComplianceEngine
    ) -> None:
        level = compliance_engine.check_data_classification(
            "This document contains proprietary algorithm and trade secret details."
        )
        assert level == AccessLevel.CONFIDENTIAL

    def test_internal_text_classified_internal(
        self, compliance_engine: ComplianceEngine
    ) -> None:
        level = compliance_engine.check_data_classification(
            "Internal policy document for staff use only."
        )
        assert level == AccessLevel.INTERNAL


class TestComplianceReport:
    def test_report_contains_expected_keys(
        self, compliance_engine: ComplianceEngine
    ) -> None:
        report = compliance_engine.generate_compliance_report(days=30)
        required_keys = {
            "period_days",
            "generated_at",
            "total_events",
            "blocked_events",
            "pii_incidents",
            "block_rate_percent",
            "risk_level",
        }
        assert required_keys.issubset(report.keys())

    def test_report_risk_level_is_valid(
        self, compliance_engine: ComplianceEngine
    ) -> None:
        report = compliance_engine.generate_compliance_report(days=30)
        assert report["risk_level"] in {"LOW", "MEDIUM", "HIGH"}

    def test_report_counts_are_non_negative(
        self, compliance_engine: ComplianceEngine
    ) -> None:
        report = compliance_engine.generate_compliance_report(days=30)
        assert report["total_events"] >= 0
        assert report["blocked_events"] >= 0
        assert report["pii_incidents"] >= 0


class TestAuditReportForRegulators:
    def test_hipaa_report_generated(
        self, compliance_engine: ComplianceEngine
    ) -> None:
        report = compliance_engine.generate_audit_report_for_regulators("HIPAA")
        assert report["regulation"] == "HIPAA"
        assert "compliance_summary" in report
        assert "audit_log_integrity" in report

    def test_gdpr_report_generated(
        self, compliance_engine: ComplianceEngine
    ) -> None:
        report = compliance_engine.generate_audit_report_for_regulators("GDPR")
        assert report["regulation"] == "GDPR"

    def test_sox_report_integrity_checked(
        self, compliance_engine: ComplianceEngine
    ) -> None:
        report = compliance_engine.generate_audit_report_for_regulators("SOX")
        assert report["audit_log_integrity"]["integrity_status"] == "PASS"

    def test_unsupported_regulation_raises(
        self, compliance_engine: ComplianceEngine
    ) -> None:
        with pytest.raises(ValueError):
            compliance_engine.generate_audit_report_for_regulators("CCPA")
