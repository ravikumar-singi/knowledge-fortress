"""Unit tests for access control and AuditEntry immutability."""

from __future__ import annotations

import pytest

from src.exceptions import ImmutabilityViolationError
from src.fortress import (
    AccessLevel,
    AuditAction,
    AuditEntry,
    AuditResult,
    KnowledgeVault,
    UserRole,
    validate_access,
)


class TestValidateAccess:
    """Tests for role-based access control."""

    def _make_fact(self, vault: KnowledgeVault, access_level: AccessLevel):
        return vault.add_fact(
            domain="general",
            claim="Test fact.",
            source="Test",
            confidence=0.9,
            access_level=access_level,
        )

    def test_user_can_access_public(self, fresh_vault: KnowledgeVault) -> None:
        fact = self._make_fact(fresh_vault, AccessLevel.PUBLIC)
        assert validate_access(UserRole.USER.value, fact) is True

    def test_user_cannot_access_internal(self, fresh_vault: KnowledgeVault) -> None:
        fact = self._make_fact(fresh_vault, AccessLevel.INTERNAL)
        assert validate_access(UserRole.USER.value, fact) is False

    def test_user_cannot_access_restricted(self, fresh_vault: KnowledgeVault) -> None:
        fact = self._make_fact(fresh_vault, AccessLevel.RESTRICTED)
        assert validate_access(UserRole.USER.value, fact) is False

    def test_user_cannot_access_confidential(
        self, fresh_vault: KnowledgeVault
    ) -> None:
        fact = self._make_fact(fresh_vault, AccessLevel.CONFIDENTIAL)
        assert validate_access(UserRole.USER.value, fact) is False

    def test_reviewer_can_access_internal(self, fresh_vault: KnowledgeVault) -> None:
        fact = self._make_fact(fresh_vault, AccessLevel.INTERNAL)
        assert validate_access(UserRole.REVIEWER.value, fact) is True

    def test_reviewer_cannot_access_restricted(
        self, fresh_vault: KnowledgeVault
    ) -> None:
        fact = self._make_fact(fresh_vault, AccessLevel.RESTRICTED)
        assert validate_access(UserRole.REVIEWER.value, fact) is False

    def test_expert_can_access_restricted(self, fresh_vault: KnowledgeVault) -> None:
        fact = self._make_fact(fresh_vault, AccessLevel.RESTRICTED)
        assert validate_access(UserRole.EXPERT.value, fact) is True

    def test_expert_cannot_access_confidential(
        self, fresh_vault: KnowledgeVault
    ) -> None:
        fact = self._make_fact(fresh_vault, AccessLevel.CONFIDENTIAL)
        assert validate_access(UserRole.EXPERT.value, fact) is False

    def test_admin_can_access_confidential(self, fresh_vault: KnowledgeVault) -> None:
        fact = self._make_fact(fresh_vault, AccessLevel.CONFIDENTIAL)
        assert validate_access(UserRole.ADMIN.value, fact) is True

    def test_admin_can_access_all_levels(self, fresh_vault: KnowledgeVault) -> None:
        for level in AccessLevel:
            fact = self._make_fact(fresh_vault, level)
            assert validate_access(UserRole.ADMIN.value, fact) is True

    def test_invalid_role_raises_value_error(
        self, fresh_vault: KnowledgeVault
    ) -> None:
        fact = self._make_fact(fresh_vault, AccessLevel.PUBLIC)
        with pytest.raises(ValueError, match="Unknown role"):
            validate_access("SUPERUSER", fact)

    def test_case_insensitive_role(self, fresh_vault: KnowledgeVault) -> None:
        fact = self._make_fact(fresh_vault, AccessLevel.PUBLIC)
        # Should not raise — role comparison is case-insensitive
        assert validate_access("admin", fact) is True


class TestListFactsAccessFiltering:
    """list_facts should filter by role clearance."""

    def test_user_role_only_sees_public_facts(
        self, fresh_vault: KnowledgeVault
    ) -> None:
        fresh_vault.add_fact(
            domain="general",
            claim="Public fact.",
            source="S",
            confidence=0.9,
            access_level=AccessLevel.PUBLIC,
        )
        fresh_vault.add_fact(
            domain="general",
            claim="Internal fact.",
            source="S",
            confidence=0.9,
            access_level=AccessLevel.INTERNAL,
        )
        results = fresh_vault.list_facts(
            domain="general",
            user_role=UserRole.USER.value,
        )
        for fact in results:
            assert fact.access_level == AccessLevel.PUBLIC

    def test_admin_role_sees_all_levels(self, fresh_vault: KnowledgeVault) -> None:
        levels = [
            AccessLevel.PUBLIC,
            AccessLevel.INTERNAL,
            AccessLevel.RESTRICTED,
            AccessLevel.CONFIDENTIAL,
        ]
        for level in levels:
            fresh_vault.add_fact(
                domain="general",
                claim=f"{level.value} level fact.",
                source="S",
                confidence=0.9,
                access_level=level,
            )
        results = fresh_vault.list_facts(
            domain="general", user_role=UserRole.ADMIN.value
        )
        returned_levels = {f.access_level for f in results}
        assert AccessLevel.CONFIDENTIAL in returned_levels


class TestAuditEntryImmutability:
    """AuditEntry must resist post-creation mutation."""

    def _make_entry(self) -> AuditEntry:
        return AuditEntry(
            timestamp="2026-06-20T10:00:00+00:00",
            user_id="test_user",
            action=AuditAction.VALIDATION,
            resource="test_resource",
            details={"key": "value"},
            result=AuditResult.SUCCESS,
        )

    def test_audit_entry_has_hash_on_creation(self) -> None:
        entry = self._make_entry()
        assert entry.hash
        assert len(entry.hash) == 64  # SHA-256 hex

    def test_audit_entry_hash_is_deterministic(self) -> None:
        entry_a = self._make_entry()
        entry_b = self._make_entry()
        assert entry_a.hash == entry_b.hash

    def test_audit_entry_mutation_raises(self) -> None:
        entry = self._make_entry()
        with pytest.raises(ImmutabilityViolationError):
            entry.hash = "tampered"

    def test_audit_entry_to_dict_includes_hash(self) -> None:
        entry = self._make_entry()
        d = entry.to_dict()
        assert "hash" in d
        assert d["hash"] == entry.hash

    def test_audit_entry_hash_changes_with_different_content(self) -> None:
        entry_a = AuditEntry(
            timestamp="2026-06-20T10:00:00+00:00",
            user_id="user_a",
            action=AuditAction.VALIDATION,
            resource="res",
            details={},
            result=AuditResult.SUCCESS,
        )
        entry_b = AuditEntry(
            timestamp="2026-06-20T10:00:00+00:00",
            user_id="user_b",
            action=AuditAction.VALIDATION,
            resource="res",
            details={},
            result=AuditResult.SUCCESS,
        )
        assert entry_a.hash != entry_b.hash

    def test_audit_log_only_appends(self, fresh_vault: KnowledgeVault) -> None:
        initial_count = len(fresh_vault._audit_log)
        fresh_vault._log_audit(
            user_id="test",
            action=AuditAction.ACCESS,
            resource="test",
            details={},
            result=AuditResult.SUCCESS,
        )
        assert len(fresh_vault._audit_log) == initial_count + 1
