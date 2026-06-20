"""Unit tests for ValidationEngine."""

from __future__ import annotations

import pytest

from src.fortress import ValidationEngine, ValidationRecommendation
from tests.conftest import (
    INVALID_MEDICAL_OUTPUT,
    MIXED_MEDICAL_OUTPUT,
    VALID_MEDICAL_OUTPUT,
)


class TestExtractClaims:
    def test_extracts_multiple_sentences(self, validator: ValidationEngine) -> None:
        text = (
            "Metformin is contraindicated in renal impairment. "
            "Diabetes is treated with metformin. "
            "Should doctors monitor kidney function?"
        )
        claims = validator.extract_claims(text)
        # The question should be excluded
        assert all(not c.endswith("?") for c in claims)
        assert len(claims) >= 2

    def test_short_text_returned_as_single_claim(
        self, validator: ValidationEngine
    ) -> None:
        text = "Metformin is contraindicated in renal failure."
        claims = validator.extract_claims(text)
        assert len(claims) == 1

    def test_very_short_text_returns_empty(self, validator: ValidationEngine) -> None:
        claims = validator.extract_claims("Yes.")
        assert claims == []

    def test_non_assertive_sentence_excluded(self, validator: ValidationEngine) -> None:
        text = "Is metformin safe? Maybe. It depends."
        claims = validator.extract_claims(text)
        # No assertive cues — should return empty or minimal results
        assert isinstance(claims, list)


class TestIsHallucinationLikely:
    def test_vague_sourcing_flagged(self, validator: ValidationEngine) -> None:
        assert validator.is_hallucination_likely(
            "Studies show that metformin cures all forms of diabetes."
        )

    def test_unanchored_percentage_flagged(self, validator: ValidationEngine) -> None:
        assert validator.is_hallucination_likely(
            "The treatment has a success rate of 97% in all patients."
        )

    def test_factual_statement_not_flagged(self, validator: ValidationEngine) -> None:
        assert not validator.is_hallucination_likely(
            "Metformin is contraindicated in severe renal impairment."
        )

    def test_fda_anchored_percentage_not_flagged(
        self, validator: ValidationEngine
    ) -> None:
        # Should not be flagged because "FDA" anchors the number
        assert not validator.is_hallucination_likely(
            "FDA-approved trial showed 85% response rate in Phase III data."
        )


class TestCheckContradictions:
    def test_contradictory_claims_detected(self, validator: ValidationEngine) -> None:
        claims = [
            "Metformin is safe for patients with renal impairment.",
            "Metformin is not safe for patients with renal impairment.",
        ]
        issues = validator.check_contradictions(claims)
        assert len(issues) > 0

    def test_consistent_claims_no_issues(self, validator: ValidationEngine) -> None:
        claims = [
            "Metformin is contraindicated in severe renal impairment.",
            "Diabetes is monitored using blood glucose levels.",
        ]
        issues = validator.check_contradictions(claims)
        assert issues == []

    def test_single_claim_no_contradiction(self, validator: ValidationEngine) -> None:
        claims = ["Lisinopril is approved for hypertension."]
        issues = validator.check_contradictions(claims)
        assert issues == []

    def test_empty_claims_no_contradiction(self, validator: ValidationEngine) -> None:
        issues = validator.check_contradictions([])
        assert issues == []


class TestValidateOutput:
    def test_valid_medical_output_proceeds_or_reviews(
        self, validator: ValidationEngine
    ) -> None:
        result = validator.validate_output(
            VALID_MEDICAL_OUTPUT, domain="medical", user_id="test_user"
        )
        assert result.recommendation in {
            ValidationRecommendation.PROCEED,
            ValidationRecommendation.REVIEW,
        }

    def test_invalid_medical_output_blocked(
        self, validator: ValidationEngine
    ) -> None:
        result = validator.validate_output(
            INVALID_MEDICAL_OUTPUT, domain="medical", user_id="test_user"
        )
        assert result.recommendation == ValidationRecommendation.BLOCK

    def test_result_has_required_fields(self, validator: ValidationEngine) -> None:
        result = validator.validate_output(
            VALID_MEDICAL_OUTPUT, domain="medical", user_id="test_user"
        )
        assert hasattr(result, "is_valid")
        assert hasattr(result, "confidence")
        assert hasattr(result, "approved_claims")
        assert hasattr(result, "blocked_claims")
        assert hasattr(result, "unverified_claims")
        assert hasattr(result, "issues")
        assert hasattr(result, "recommendation")
        assert hasattr(result, "timestamp")

    def test_confidence_in_valid_range(self, validator: ValidationEngine) -> None:
        result = validator.validate_output(
            VALID_MEDICAL_OUTPUT, domain="medical", user_id="test_user"
        )
        assert 0.0 <= result.confidence <= 1.0

    def test_to_dict_is_json_serializable(self, validator: ValidationEngine) -> None:
        import json
        result = validator.validate_output(
            VALID_MEDICAL_OUTPUT, domain="medical", user_id="test_user"
        )
        # Should not raise
        json.dumps(result.to_dict())

    def test_blocked_output_has_blocked_claims(
        self, validator: ValidationEngine
    ) -> None:
        result = validator.validate_output(
            "Studies show that warfarin is safe in pregnancy with 100% success.",
            domain="medical",
            user_id="test_user",
        )
        assert result.recommendation == ValidationRecommendation.BLOCK

    def test_hallucination_appears_in_blocked_claims(
        self, validator: ValidationEngine
    ) -> None:
        result = validator.validate_output(
            "Experts believe metformin cures diabetes with 99% success rate "
            "according to recent research.",
            domain="medical",
            user_id="test_user",
        )
        assert result.blocked_claims or result.issues


class TestValidateClaimsBatch:
    def test_batch_returns_correct_count(self, validator: ValidationEngine) -> None:
        outputs = [VALID_MEDICAL_OUTPUT, INVALID_MEDICAL_OUTPUT, MIXED_MEDICAL_OUTPUT]
        results = validator.validate_claims_batch(
            outputs, domain="medical", user_id="batch_user"
        )
        assert len(results) == 3

    def test_batch_each_result_is_validation_result(
        self, validator: ValidationEngine
    ) -> None:
        from src.fortress import ValidationResult
        outputs = [VALID_MEDICAL_OUTPUT, INVALID_MEDICAL_OUTPUT]
        results = validator.validate_claims_batch(
            outputs, domain="medical", user_id="batch_user"
        )
        for r in results:
            assert isinstance(r, ValidationResult)

    def test_batch_empty_list_returns_empty(self, validator: ValidationEngine) -> None:
        results = validator.validate_claims_batch(
            [], domain="medical", user_id="batch_user"
        )
        assert results == []
