"""Unit tests for KnowledgeVault."""

from __future__ import annotations

import pytest

from src.exceptions import FactNotFoundError
from src.fortress import AccessLevel, AuditAction, KnowledgeVault


class TestVaultInitialisation:
    def test_vault_seeds_medical_facts(self, vault: KnowledgeVault) -> None:
        medical = vault.list_facts(domain="medical")
        assert len(medical) > 0, "Vault should contain seeded medical facts"

    def test_vault_seeds_financial_facts(self, vault: KnowledgeVault) -> None:
        financial = vault.list_facts(domain="financial")
        assert len(financial) > 0

    def test_vault_seeds_legal_facts(self, vault: KnowledgeVault) -> None:
        legal = vault.list_facts(domain="legal")
        assert len(legal) > 0

    def test_audit_log_populated_after_seed(self, vault: KnowledgeVault) -> None:
        log = vault.get_audit_log(limit=1000)
        assert len(log) > 0

    def test_seeded_fact_has_correct_domain(self, vault: KnowledgeVault) -> None:
        medical = vault.list_facts(domain="medical")
        for fact in medical:
            assert fact.domain == "medical"


class TestAddFact:
    def test_add_fact_returns_fact_metadata(self, fresh_vault: KnowledgeVault) -> None:
        fact = fresh_vault.add_fact(
            domain="medical",
            claim="Aspirin is used for pain relief.",
            source="FDA Drug Label",
            confidence=0.95,
        )
        assert fact.fact_id
        assert fact.domain == "medical"
        assert fact.version == 1

    def test_add_fact_invalid_confidence_raises(self, fresh_vault: KnowledgeVault) -> None:
        with pytest.raises(ValueError, match="Confidence"):
            fresh_vault.add_fact(
                domain="medical",
                claim="Some claim",
                source="Source",
                confidence=1.5,
            )

    def test_add_fact_invalid_domain_raises(self, fresh_vault: KnowledgeVault) -> None:
        with pytest.raises(ValueError, match="Domain"):
            fresh_vault.add_fact(
                domain="astronomy",
                claim="Stars exist.",
                source="NASA",
                confidence=0.99,
            )

    def test_add_fact_creates_audit_entry(self, fresh_vault: KnowledgeVault) -> None:
        before_count = len(fresh_vault._audit_log)
        fresh_vault.add_fact(
            domain="financial",
            claim="FDIC insures deposits up to $250,000.",
            source="FDIC",
            confidence=0.99,
        )
        assert len(fresh_vault._audit_log) > before_count

    def test_add_fact_stores_verified_by(self, fresh_vault: KnowledgeVault) -> None:
        fact = fresh_vault.add_fact(
            domain="medical",
            claim="Insulin is used for type 1 diabetes.",
            source="ADA Guidelines",
            confidence=0.99,
            verified_by="dr_expert",
        )
        assert fact.verified_by == "dr_expert"

    def test_add_fact_default_access_level_is_internal(
        self, fresh_vault: KnowledgeVault
    ) -> None:
        fact = fresh_vault.add_fact(
            domain="general",
            claim="Water boils at 100°C at sea level.",
            source="Physics textbook",
            confidence=1.0,
        )
        assert fact.access_level == AccessLevel.INTERNAL

    def test_add_fact_timestamps_are_iso8601(self, fresh_vault: KnowledgeVault) -> None:
        from datetime import datetime, timezone
        fact = fresh_vault.add_fact(
            domain="general",
            claim="The sky is blue.",
            source="Observation",
            confidence=0.99,
        )
        # Should not raise
        datetime.fromisoformat(fact.created_at)
        datetime.fromisoformat(fact.last_updated)


class TestVerifyClaim:
    def test_verify_known_claim_returns_true(self, vault: KnowledgeVault) -> None:
        verified, conf = vault.verify_claim(
            "Metformin is contraindicated in severe renal impairment",
            domain="medical",
        )
        assert verified is True
        assert conf > 0.9

    def test_verify_unknown_claim_returns_false(self, vault: KnowledgeVault) -> None:
        verified, conf = vault.verify_claim(
            "Unicorn dust cures all diseases",
            domain="medical",
        )
        assert verified is False
        assert conf == 0.0

    def test_verify_claim_without_domain_searches_all(
        self, vault: KnowledgeVault
    ) -> None:
        verified, conf = vault.verify_claim(
            "metformin contraindicated renal impairment"
        )
        assert verified is True

    def test_verify_claim_logs_audit(self, fresh_vault: KnowledgeVault) -> None:
        before = len(fresh_vault._audit_log)
        fresh_vault.verify_claim("some claim", domain="general")
        assert len(fresh_vault._audit_log) > before


class TestUpdateFact:
    def test_update_fact_increments_version(self, fresh_vault: KnowledgeVault) -> None:
        fact = fresh_vault.add_fact(
            domain="medical",
            claim="Original claim.",
            source="Source A",
            confidence=0.8,
        )
        updated = fresh_vault.update_fact(
            fact.fact_id, {"claim": "Updated claim.", "confidence": 0.95}
        )
        assert updated.version == 2
        assert updated.claim == "Updated claim."
        assert updated.confidence == 0.95

    def test_update_fact_preserves_created_at(self, fresh_vault: KnowledgeVault) -> None:
        fact = fresh_vault.add_fact(
            domain="general", claim="Claim", source="Src", confidence=0.5
        )
        updated = fresh_vault.update_fact(fact.fact_id, {"confidence": 0.6})
        assert updated.created_at == fact.created_at

    def test_update_fact_retains_history(self, fresh_vault: KnowledgeVault) -> None:
        fact = fresh_vault.add_fact(
            domain="general", claim="Original", source="Src", confidence=0.5
        )
        fresh_vault.update_fact(fact.fact_id, {"confidence": 0.6})
        fresh_vault.update_fact(fact.fact_id, {"confidence": 0.7})
        lineage = fresh_vault.get_fact_lineage(fact.fact_id)
        assert lineage["version_count"] == 3

    def test_update_fact_immutable_field_raises(
        self, fresh_vault: KnowledgeVault
    ) -> None:
        fact = fresh_vault.add_fact(
            domain="general", claim="Claim", source="Src", confidence=0.5
        )
        with pytest.raises(ValueError, match="immutable"):
            fresh_vault.update_fact(fact.fact_id, {"fact_id": "other-id"})

    def test_update_nonexistent_fact_raises(self, fresh_vault: KnowledgeVault) -> None:
        with pytest.raises(FactNotFoundError):
            fresh_vault.update_fact("nonexistent-id", {"confidence": 0.9})


class TestGetFactLineage:
    def test_lineage_contains_current_and_history(
        self, fresh_vault: KnowledgeVault
    ) -> None:
        fact = fresh_vault.add_fact(
            domain="general", claim="Claim", source="Src", confidence=0.5
        )
        lineage = fresh_vault.get_fact_lineage(fact.fact_id)
        assert "current" in lineage
        assert "history" in lineage
        assert lineage["version_count"] == 1

    def test_lineage_nonexistent_raises(self, fresh_vault: KnowledgeVault) -> None:
        with pytest.raises(FactNotFoundError):
            fresh_vault.get_fact_lineage("no-such-id")


class TestAuditLog:
    def test_audit_log_returns_dicts(self, vault: KnowledgeVault) -> None:
        log = vault.get_audit_log(limit=5)
        assert isinstance(log, list)
        for entry in log:
            assert "hash" in entry
            assert "timestamp" in entry
            assert "action" in entry

    def test_audit_log_respects_limit(self, vault: KnowledgeVault) -> None:
        log = vault.get_audit_log(limit=3)
        assert len(log) <= 3

    def test_audit_log_action_filter(self, vault: KnowledgeVault) -> None:
        log = vault.get_audit_log(limit=100, action_filter=AuditAction.FACT_CREATED)
        for entry in log:
            assert entry["action"] == AuditAction.FACT_CREATED.value
