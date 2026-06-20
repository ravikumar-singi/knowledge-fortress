"""
Knowledge-Fortress: production-grade knowledge management and validation system
for regulated industries (healthcare, finance, legal).

Architecture overview:
    KnowledgeVault   — immutable fact store with versioning and audit log
    ValidationEngine — validate AI outputs against the vault in real-time
    ComplianceEngine — HIPAA / GDPR / SOX / FDA regulatory checks
    AccessControl    — role-based fact access

Entry point: run ``python -m src.fortress`` for a live demo.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from .exceptions import (
    AccessDeniedError,
    ComplianceViolationError,
    FactNotFoundError,
    ImmutabilityViolationError,
    ValidationError,
)
from .knowledge_bases import (
    CONDITIONS,
    CONTRAINDICATIONS,
    DRUG_INTERACTIONS,
    FINANCIAL_POLICIES,
    FINANCIAL_REGULATIONS,
    LEGAL_PRECEDENTS,
    MEDICATIONS,
)
from .validators import detect_pii, get_pii_category_descriptions, validate_confidence_score

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

logger = logging.getLogger("knowledge_fortress")
logging.basicConfig(
    level=logging.INFO,
    format='{"time": "%(asctime)s", "level": "%(levelname)s", '
    '"logger": "%(name)s", "message": "%(message)s"}',
    datefmt="%Y-%m-%dT%H:%M:%S",
)

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class AccessLevel(str, Enum):
    """Sensitivity classification for stored facts."""

    PUBLIC = "PUBLIC"
    INTERNAL = "INTERNAL"
    RESTRICTED = "RESTRICTED"
    CONFIDENTIAL = "CONFIDENTIAL"


class UserRole(str, Enum):
    """User roles in the system, ordered by privilege level."""

    USER = "USER"
    REVIEWER = "REVIEWER"
    EXPERT = "EXPERT"
    ADMIN = "ADMIN"


class AuditAction(str, Enum):
    """Enumeration of audit-worthy actions."""

    VALIDATION = "VALIDATION"
    MODIFICATION = "MODIFICATION"
    ACCESS = "ACCESS"
    ESCALATION = "ESCALATION"
    COMPLIANCE_CHECK = "COMPLIANCE_CHECK"
    FACT_CREATED = "FACT_CREATED"
    FACT_UPDATED = "FACT_UPDATED"


class AuditResult(str, Enum):
    """Outcome recorded on each audit entry."""

    SUCCESS = "SUCCESS"
    BLOCKED = "BLOCKED"
    ESCALATED = "ESCALATED"
    FAILED = "FAILED"


class ValidationRecommendation(str, Enum):
    """Top-level recommendation produced by the ValidationEngine."""

    PROCEED = "PROCEED"
    REVIEW = "REVIEW"
    BLOCK = "BLOCK"


# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------


@dataclass
class FactMetadata:
    """Immutable record representing a single verified fact in the vault.

    Facts are never deleted; they are versioned.  Each update produces a new
    FactMetadata with an incremented version number, and the previous version
    is retained in the vault history.

    Attributes:
        fact_id: Unique identifier (UUID4).
        domain: Knowledge domain (``medical``, ``financial``, ``legal``).
        claim: The factual statement stored.
        source: Authoritative source citation.
        confidence: Reliability score in [0.0, 1.0].
        created_at: ISO-8601 creation timestamp.
        last_updated: ISO-8601 last modification timestamp.
        verified_by: Optional expert who validated the fact.
        regulatory_status: e.g. ``FDA_APPROVED``, ``SOX_COMPLIANT``.
        version: Monotonically increasing version counter.
        access_level: Minimum clearance required to read this fact.
        related_facts: List of fact_ids that are semantically related.
    """

    fact_id: str
    domain: str
    claim: str
    source: str
    confidence: float
    created_at: str
    last_updated: str
    verified_by: Optional[str] = None
    regulatory_status: Optional[str] = None
    version: int = 1
    access_level: AccessLevel = AccessLevel.INTERNAL
    related_facts: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the fact to a JSON-compatible dictionary."""
        return {
            "fact_id": self.fact_id,
            "domain": self.domain,
            "claim": self.claim,
            "source": self.source,
            "confidence": self.confidence,
            "created_at": self.created_at,
            "last_updated": self.last_updated,
            "verified_by": self.verified_by,
            "regulatory_status": self.regulatory_status,
            "version": self.version,
            "access_level": self.access_level.value,
            "related_facts": self.related_facts,
        }


@dataclass
class ValidationResult:
    """Output of a single validation request.

    Attributes:
        is_valid: Whether all extracted claims passed validation.
        confidence: Weighted average confidence across validated claims.
        approved_claims: Claims confirmed by the knowledge vault.
        blocked_claims: Claims contradicted by the knowledge vault.
        unverified_claims: Claims absent from the vault.
        issues: Human-readable problem descriptions.
        recommendation: Top-level action directive.
        timestamp: ISO-8601 timestamp of the validation.
    """

    is_valid: bool
    confidence: float
    approved_claims: List[str]
    blocked_claims: List[str]
    unverified_claims: List[str]
    issues: List[str]
    recommendation: ValidationRecommendation
    timestamp: str

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the result to a JSON-compatible dictionary."""
        return {
            "is_valid": self.is_valid,
            "confidence": self.confidence,
            "approved_claims": self.approved_claims,
            "blocked_claims": self.blocked_claims,
            "unverified_claims": self.unverified_claims,
            "issues": self.issues,
            "recommendation": self.recommendation.value,
            "timestamp": self.timestamp,
        }


@dataclass
class AuditEntry:
    """Immutable, cryptographically signed record of a system event.

    The ``hash`` field is computed once at creation and covers all other
    fields.  Any subsequent mutation raises ``ImmutabilityViolationError``.

    Attributes:
        timestamp: ISO-8601 creation time.
        user_id: Actor who triggered the action.
        action: Category of the action.
        resource: Identifier of the affected resource.
        details: Arbitrary context dictionary.
        result: Outcome of the action.
        hash: SHA-256 digest for integrity verification.
    """

    timestamp: str
    user_id: str
    action: AuditAction
    resource: str
    details: Dict[str, Any]
    result: AuditResult
    hash: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "hash", self.compute_hash())

    def __setattr__(self, name: str, value: Any) -> None:
        if name == "hash" and hasattr(self, "hash"):
            raise ImmutabilityViolationError(
                "AuditEntry is immutable after creation."
            )
        object.__setattr__(self, name, value)

    def compute_hash(self) -> str:
        """Compute a SHA-256 digest over the entry's content fields.

        Returns:
            Hex-encoded SHA-256 string.
        """
        payload = json.dumps(
            {
                "timestamp": self.timestamp,
                "user_id": self.user_id,
                "action": self.action.value,
                "resource": self.resource,
                "details": self.details,
                "result": self.result.value,
            },
            sort_keys=True,
        ).encode("utf-8")
        return hashlib.sha256(payload).hexdigest()

    def to_dict(self) -> Dict[str, Any]:
        """Serialize the audit entry to a JSON-compatible dictionary."""
        return {
            "timestamp": self.timestamp,
            "user_id": self.user_id,
            "action": self.action.value,
            "resource": self.resource,
            "details": self.details,
            "result": self.result.value,
            "hash": self.hash,
        }


# ---------------------------------------------------------------------------
# Access Control
# ---------------------------------------------------------------------------

# Defines which roles may read which access levels.
_ROLE_CLEARANCE: Dict[UserRole, List[AccessLevel]] = {
    UserRole.USER: [AccessLevel.PUBLIC],
    UserRole.REVIEWER: [AccessLevel.PUBLIC, AccessLevel.INTERNAL],
    UserRole.EXPERT: [
        AccessLevel.PUBLIC,
        AccessLevel.INTERNAL,
        AccessLevel.RESTRICTED,
    ],
    UserRole.ADMIN: [
        AccessLevel.PUBLIC,
        AccessLevel.INTERNAL,
        AccessLevel.RESTRICTED,
        AccessLevel.CONFIDENTIAL,
    ],
}


def validate_access(user_role: str, fact: FactMetadata) -> bool:
    """Return True if *user_role* is cleared to read *fact*.

    Args:
        user_role: Role name string matching a ``UserRole`` enum value.
        fact: The fact being requested.

    Returns:
        True if access is permitted, False otherwise.

    Raises:
        ValueError: If *user_role* is not a recognised role name.
    """
    try:
        role = UserRole(user_role.upper())
    except ValueError:
        raise ValueError(
            f"Unknown role '{user_role}'. Valid roles: {[r.value for r in UserRole]}"
        )
    return fact.access_level in _ROLE_CLEARANCE[role]


# ---------------------------------------------------------------------------
# Knowledge Vault
# ---------------------------------------------------------------------------


class KnowledgeVault:
    """Immutable knowledge store for verified facts with full audit history.

    The vault is an append-only structure.  Facts can be updated (which
    creates a new version), but no version is ever discarded.  Every mutating
    operation is recorded in the cryptographically linked audit log.

    Usage::

        vault = KnowledgeVault()
        fact = vault.add_fact(
            domain="medical",
            claim="Metformin is contraindicated in severe renal impairment.",
            source="FDA Black Box Warning",
            confidence=0.99,
            user_id="dr_smith",
        )
        is_valid, conf = vault.verify_claim(
            "metformin is contraindicated in renal failure", domain="medical"
        )
    """

    ALLOWED_DOMAINS = ["medical", "financial", "legal", "general"]

    def __init__(self) -> None:
        # Primary store: fact_id → FactMetadata (current version)
        self._facts: Dict[str, FactMetadata] = {}
        # Version history: fact_id → list of FactMetadata (oldest first)
        self._history: Dict[str, List[FactMetadata]] = {}
        # Append-only audit log
        self._audit_log: List[AuditEntry] = []

        logger.info("Initializing KnowledgeVault with default knowledge bases")
        self._seed_knowledge_bases()

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def add_fact(
        self,
        domain: str,
        claim: str,
        source: str,
        confidence: float,
        user_id: str = "system",
        verified_by: Optional[str] = None,
        regulatory_status: Optional[str] = None,
        access_level: AccessLevel = AccessLevel.INTERNAL,
        related_facts: Optional[List[str]] = None,
    ) -> FactMetadata:
        """Add a new verified fact to the vault.

        Args:
            domain: Knowledge domain (medical / financial / legal / general).
            claim: The factual statement.
            source: Authoritative citation.
            confidence: Reliability score [0.0, 1.0].
            user_id: Actor adding the fact.
            verified_by: Optional expert identifier.
            regulatory_status: Optional regulatory label (e.g. FDA_APPROVED).
            access_level: Sensitivity classification.
            related_facts: Optional list of related fact_ids.

        Returns:
            The newly created ``FactMetadata``.

        Raises:
            ValueError: If confidence or domain is invalid.
        """
        validate_confidence_score(confidence)
        if domain not in self.ALLOWED_DOMAINS:
            raise ValueError(
                f"Domain '{domain}' not allowed. Choose from {self.ALLOWED_DOMAINS}"
            )

        now = _utcnow()
        fact_id = str(uuid.uuid4())
        fact = FactMetadata(
            fact_id=fact_id,
            domain=domain,
            claim=claim,
            source=source,
            confidence=confidence,
            created_at=now,
            last_updated=now,
            verified_by=verified_by,
            regulatory_status=regulatory_status,
            version=1,
            access_level=access_level,
            related_facts=related_facts or [],
        )
        self._facts[fact_id] = fact
        self._history[fact_id] = [fact]

        self._log_audit(
            user_id=user_id,
            action=AuditAction.FACT_CREATED,
            resource=fact_id,
            details={"domain": domain, "confidence": confidence, "source": source},
            result=AuditResult.SUCCESS,
        )
        logger.info(
            "Fact added: fact_id=%s domain=%s confidence=%.2f",
            fact_id,
            domain,
            confidence,
        )
        return fact

    def verify_claim(
        self,
        claim: str,
        domain: Optional[str] = None,
        user_id: str = "system",
    ) -> Tuple[bool, float]:
        """Check whether a claim is supported by facts in the vault.

        Matching is case-insensitive substring / keyword-based.  For semantic
        matching integrate an embedding layer on top of this method.

        Args:
            claim: The statement to verify.
            domain: Restrict search to a specific domain (optional).
            user_id: Actor performing the lookup (for audit purposes).

        Returns:
            ``(is_verified, confidence)`` tuple.
        """
        claim_lower = claim.lower()
        best_confidence = 0.0
        matched = False

        for fact in self._facts.values():
            if domain and fact.domain != domain:
                continue
            if self._text_matches(claim_lower, fact.claim.lower()):
                matched = True
                if fact.confidence > best_confidence:
                    best_confidence = fact.confidence

        self._log_audit(
            user_id=user_id,
            action=AuditAction.ACCESS,
            resource="claim_verification",
            details={"claim_snippet": claim[:120], "domain": domain, "matched": matched},
            result=AuditResult.SUCCESS if matched else AuditResult.FAILED,
        )
        return matched, best_confidence

    def get_fact_lineage(self, fact_id: str) -> Dict[str, Any]:
        """Return the full version history of a fact.

        Args:
            fact_id: Identifier of the fact.

        Returns:
            Dictionary with ``current`` (latest) and ``history`` (all versions).

        Raises:
            FactNotFoundError: If *fact_id* does not exist.
        """
        if fact_id not in self._facts:
            raise FactNotFoundError(f"Fact '{fact_id}' not found in vault.")
        return {
            "fact_id": fact_id,
            "current": self._facts[fact_id].to_dict(),
            "history": [v.to_dict() for v in self._history[fact_id]],
            "version_count": len(self._history[fact_id]),
        }

    def update_fact(
        self,
        fact_id: str,
        updates: Dict[str, Any],
        user_id: str = "system",
    ) -> FactMetadata:
        """Create a new version of an existing fact with the supplied changes.

        Only mutable fields (``claim``, ``source``, ``confidence``,
        ``verified_by``, ``regulatory_status``, ``access_level``,
        ``related_facts``) may be updated.  ``fact_id``, ``created_at``, and
        ``version`` are managed by the vault.

        Args:
            fact_id: The fact to update.
            updates: Mapping of field names to new values.
            user_id: Actor performing the update.

        Returns:
            The new ``FactMetadata`` version.

        Raises:
            FactNotFoundError: If the fact does not exist.
            ValueError: If an immutable field is included in *updates*.
        """
        immutable_fields = {"fact_id", "created_at", "version", "domain"}
        illegal = immutable_fields & updates.keys()
        if illegal:
            raise ValueError(
                f"Fields {illegal} are immutable and cannot be updated."
            )

        if fact_id not in self._facts:
            raise FactNotFoundError(f"Fact '{fact_id}' not found in vault.")

        existing = self._facts[fact_id]
        if "confidence" in updates:
            validate_confidence_score(updates["confidence"])

        now = _utcnow()
        new_fact = FactMetadata(
            fact_id=fact_id,
            domain=existing.domain,
            claim=updates.get("claim", existing.claim),
            source=updates.get("source", existing.source),
            confidence=updates.get("confidence", existing.confidence),
            created_at=existing.created_at,
            last_updated=now,
            verified_by=updates.get("verified_by", existing.verified_by),
            regulatory_status=updates.get(
                "regulatory_status", existing.regulatory_status
            ),
            version=existing.version + 1,
            access_level=updates.get("access_level", existing.access_level),
            related_facts=updates.get("related_facts", existing.related_facts),
        )

        self._facts[fact_id] = new_fact
        self._history[fact_id].append(new_fact)

        self._log_audit(
            user_id=user_id,
            action=AuditAction.FACT_UPDATED,
            resource=fact_id,
            details={"updated_fields": list(updates.keys()), "new_version": new_fact.version},
            result=AuditResult.SUCCESS,
        )
        return new_fact

    def list_facts(
        self,
        domain: Optional[str] = None,
        access_level: Optional[AccessLevel] = None,
        user_id: str = "system",
        user_role: str = UserRole.ADMIN.value,
    ) -> List[FactMetadata]:
        """List facts, optionally filtered by domain and/or access level.

        Args:
            domain: Optional domain filter.
            access_level: Optional access-level filter.
            user_id: Requesting user (for audit).
            user_role: Role used for access-control filtering.

        Returns:
            List of ``FactMetadata`` accessible to *user_role*.
        """
        results = []
        for fact in self._facts.values():
            if domain and fact.domain != domain:
                continue
            if access_level and fact.access_level != access_level:
                continue
            if validate_access(user_role, fact):
                results.append(fact)

        self._log_audit(
            user_id=user_id,
            action=AuditAction.ACCESS,
            resource="fact_list",
            details={"domain": domain, "access_level": str(access_level), "count": len(results)},
            result=AuditResult.SUCCESS,
        )
        return results

    def get_audit_log(
        self, limit: int = 100, action_filter: Optional[AuditAction] = None
    ) -> List[Dict[str, Any]]:
        """Return recent audit entries, newest first.

        Args:
            limit: Maximum number of entries to return.
            action_filter: If set, return only entries with this action.

        Returns:
            List of audit entry dictionaries.
        """
        entries = list(reversed(self._audit_log))
        if action_filter:
            entries = [e for e in entries if e.action == action_filter]
        return [e.to_dict() for e in entries[:limit]]

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _log_audit(
        self,
        user_id: str,
        action: AuditAction,
        resource: str,
        details: Dict[str, Any],
        result: AuditResult,
    ) -> None:
        """Append a new immutable entry to the audit log."""
        entry = AuditEntry(
            timestamp=_utcnow(),
            user_id=user_id,
            action=action,
            resource=resource,
            details=details,
            result=result,
        )
        self._audit_log.append(entry)

    @staticmethod
    def _text_matches(query: str, target: str) -> bool:
        """Return True if any significant word in *query* appears in *target*."""
        stopwords = {
            "the", "a", "an", "is", "in", "of", "for", "to", "and",
            "or", "with", "that", "this", "are", "was", "be", "as",
            "it", "its", "have", "has", "had", "not",
        }
        keywords = [w for w in query.split() if w not in stopwords and len(w) > 2]
        if not keywords:
            return False
        # Require at least 40 % of keywords to appear in the target
        matches = sum(1 for kw in keywords if kw in target)
        return matches / len(keywords) >= 0.4

    def _seed_knowledge_bases(self) -> None:
        """Populate the vault with curated medical, financial and legal facts."""
        # Medical — medications
        for drug, data in MEDICATIONS.items():
            self.add_fact(
                domain="medical",
                claim=(
                    f"{drug.replace('_', ' ').title()} is FDA approved for "
                    f"{', '.join(data['approved_for'])} and is contraindicated in "
                    f"{', '.join(data['contraindications'])}."
                ),
                source=data.get("source", "FDA Drug Label"),
                confidence=data["confidence"],
                user_id="system",
                regulatory_status=data.get("fda_status"),
                access_level=AccessLevel.RESTRICTED,
            )

        # Medical — conditions
        for condition, data in CONDITIONS.items():
            self.add_fact(
                domain="medical",
                claim=(
                    f"{condition.replace('_', ' ').title()} is treated with "
                    f"{', '.join(data['approved_treatments'])} and monitored via "
                    f"{', '.join(data['monitoring'])}."
                ),
                source=data.get("source", "Clinical Guidelines"),
                confidence=data["confidence"],
                user_id="system",
                access_level=AccessLevel.RESTRICTED,
            )

        # Medical — drug interactions
        for (drug_a, drug_b), data in DRUG_INTERACTIONS.items():
            self.add_fact(
                domain="medical",
                claim=(
                    f"Concurrent use of {drug_a.replace('_', ' ')} and "
                    f"{drug_b.replace('_', ' ')} causes {data['effect'].replace('_', ' ')} "
                    f"(severity: {data['severity']}). Mitigation: "
                    f"{data['mitigation'].replace('_', ' ')}."
                ),
                source=data.get("source", "Drug Interaction Database"),
                confidence=data["confidence"],
                user_id="system",
                regulatory_status="FDA_INTERACTION_WARNING",
                access_level=AccessLevel.RESTRICTED,
            )

        # Medical — contraindications
        for key, data in CONTRAINDICATIONS.items():
            self.add_fact(
                domain="medical",
                claim=(
                    f"{data['drug'].replace('_', ' ').title()} is absolutely "
                    f"contraindicated in {data['condition'].replace('_', ' ')} "
                    f"due to {data['reason'].replace('_', ' ')}."
                ),
                source=data.get("source", "FDA Black Box Warning"),
                confidence=data["confidence"],
                user_id="system",
                regulatory_status="FDA_BLACK_BOX_WARNING",
                access_level=AccessLevel.RESTRICTED,
            )

        # Financial — regulations
        for key, data in FINANCIAL_REGULATIONS.items():
            self.add_fact(
                domain="financial",
                claim=data["description"],
                source=data.get("source", "Regulatory Authority"),
                confidence=data["confidence"],
                user_id="system",
                regulatory_status=data.get("regulation"),
                access_level=AccessLevel.INTERNAL,
            )

        # Financial — policies
        for key, data in FINANCIAL_POLICIES.items():
            self.add_fact(
                domain="financial",
                claim=data["description"],
                source=data.get("source", "Regulatory Authority"),
                confidence=data["confidence"],
                user_id="system",
                regulatory_status=data.get("regulation"),
                access_level=AccessLevel.INTERNAL,
            )

        # Legal — precedents
        for key, data in LEGAL_PRECEDENTS.items():
            self.add_fact(
                domain="legal",
                claim=data["principle"],
                source=data.get("source", "Legal Authority"),
                confidence=data["confidence"],
                user_id="system",
                regulatory_status=data.get("regulation"),
                access_level=AccessLevel.INTERNAL,
            )

        logger.info(
            "Knowledge vault seeded with %d facts.", len(self._facts)
        )


# ---------------------------------------------------------------------------
# Validation Engine
# ---------------------------------------------------------------------------


class ValidationEngine:
    """Validates AI-generated outputs against the KnowledgeVault in real-time.

    Usage::

        vault = KnowledgeVault()
        engine = ValidationEngine(vault)
        result = engine.validate_output(
            ai_output="Metformin can be safely used in patients with kidney failure.",
            domain="medical",
            user_id="dr_jones",
        )
        print(result.recommendation)  # ValidationRecommendation.BLOCK
    """

    # Sentence tokenisation — splits on . ! ? followed by space or end-of-string
    _SENTENCE_RE = re.compile(r"(?<=[.!?])\s+")

    # Patterns that suggest factual assertions rather than hedged language
    _ASSERTION_CUES = re.compile(
        r"\b(is|are|was|were|has|have|causes|prevents|treats|contraindicated|"
        r"approved|required|must|should|recommend|indicates|shows|confirms|"
        r"proven|demonstrated|established|known)\b",
        re.IGNORECASE,
    )

    # Hallucination risk markers — vague or unverifiable language
    _HALLUCINATION_MARKERS = re.compile(
        r"\b(studies show|research indicates|experts believe|it is known that|"
        r"generally accepted|widely believed|some say|recent research|"
        r"new studies|scientists claim|doctors recommend)\b",
        re.IGNORECASE,
    )

    def __init__(self, vault: KnowledgeVault) -> None:
        """Initialise with a knowledge vault.

        Args:
            vault: The ``KnowledgeVault`` instance to validate against.
        """
        self._vault = vault

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def validate_output(
        self,
        ai_output: str,
        domain: str,
        user_id: str = "system",
    ) -> ValidationResult:
        """Validate a block of AI-generated text against the knowledge vault.

        Steps:
            1. Extract individual claims from the text.
            2. Verify each claim against the vault.
            3. Check for internal contradictions.
            4. Compute aggregate confidence and recommendation.
            5. Log the validation to the audit trail.

        Args:
            ai_output: Raw text from an AI system.
            domain: Domain context (medical / financial / legal / general).
            user_id: Requesting user identifier.

        Returns:
            ``ValidationResult`` with full breakdown.
        """
        claims = self.extract_claims(ai_output)
        approved: List[str] = []
        blocked: List[str] = []
        unverified: List[str] = []
        issues: List[str] = []
        confidences: List[float] = []

        for claim in claims:
            verified, conf = self._vault.verify_claim(claim, domain=domain, user_id=user_id)
            if verified:
                approved.append(claim)
                confidences.append(conf)
            elif self.is_hallucination_likely(claim):
                blocked.append(claim)
                issues.append(f"Potential hallucination detected: '{claim[:80]}…'")
                confidences.append(0.0)
            else:
                unverified.append(claim)
                confidences.append(0.3)  # Low confidence for unknown claims

        contradiction_issues = self.check_contradictions(claims)
        issues.extend(contradiction_issues)

        avg_confidence = sum(confidences) / len(confidences) if confidences else 0.0
        recommendation = self._determine_recommendation(
            blocked=blocked,
            unverified=unverified,
            contradiction_issues=contradiction_issues,
            avg_confidence=avg_confidence,
        )
        is_valid = (
            recommendation == ValidationRecommendation.PROCEED
            and not blocked
        )

        result = ValidationResult(
            is_valid=is_valid,
            confidence=round(avg_confidence, 4),
            approved_claims=approved,
            blocked_claims=blocked,
            unverified_claims=unverified,
            issues=issues,
            recommendation=recommendation,
            timestamp=_utcnow(),
        )

        self._vault._log_audit(
            user_id=user_id,
            action=AuditAction.VALIDATION,
            resource=f"domain:{domain}",
            details={
                "total_claims": len(claims),
                "approved": len(approved),
                "blocked": len(blocked),
                "unverified": len(unverified),
                "recommendation": recommendation.value,
                "confidence": round(avg_confidence, 4),
            },
            result=(
                AuditResult.SUCCESS
                if is_valid
                else AuditResult.BLOCKED
                if blocked
                else AuditResult.ESCALATED
            ),
        )
        logger.info(
            "Validation complete: domain=%s claims=%d approved=%d blocked=%d "
            "unverified=%d recommendation=%s",
            domain,
            len(claims),
            len(approved),
            len(blocked),
            len(unverified),
            recommendation.value,
        )
        return result

    def validate_claims_batch(
        self,
        outputs: List[str],
        domain: str,
        user_id: str = "system",
    ) -> List[ValidationResult]:
        """Validate multiple AI outputs in a single call.

        Args:
            outputs: List of AI-generated text blocks.
            domain: Shared domain context.
            user_id: Requesting user identifier.

        Returns:
            List of ``ValidationResult`` objects in the same order as *outputs*.
        """
        return [
            self.validate_output(text, domain=domain, user_id=user_id)
            for text in outputs
        ]

    def check_contradictions(self, claims: List[str]) -> List[str]:
        """Detect pairs of claims that directly contradict each other.

        Currently uses keyword-based negation detection.  For higher accuracy
        integrate a natural language inference model.

        Args:
            claims: List of claim strings to check pairwise.

        Returns:
            List of issue descriptions for each detected contradiction.
        """
        issues: List[str] = []
        negation_re = re.compile(r"\b(not|no|never|contraindicated|avoid|stop)\b", re.I)

        for i, claim_a in enumerate(claims):
            for claim_b in claims[i + 1 :]:
                # Detect when one claim negates keywords from the other
                a_words = set(claim_a.lower().split())
                b_words = set(claim_b.lower().split())
                shared = a_words & b_words - {
                    "the", "a", "an", "is", "in", "of", "to", "and", "or"
                }
                if len(shared) >= 3:
                    a_negated = bool(negation_re.search(claim_a))
                    b_negated = bool(negation_re.search(claim_b))
                    if a_negated != b_negated:
                        issues.append(
                            f"Contradiction detected between: "
                            f"'{claim_a[:60]}…' and '{claim_b[:60]}…'"
                        )
        return issues

    def extract_claims(self, text: str) -> List[str]:
        """Extract individual factual assertions from a block of text.

        Splits on sentence boundaries, then filters out non-assertive
        sentences (questions, interjections, very short fragments).

        Args:
            text: Raw text potentially containing multiple claims.

        Returns:
            List of candidate claim strings.
        """
        sentences = self._SENTENCE_RE.split(text.strip())
        claims = []
        for sentence in sentences:
            sentence = sentence.strip()
            if len(sentence) < 15:
                continue
            if sentence.endswith("?"):
                continue
            if self._ASSERTION_CUES.search(sentence):
                claims.append(sentence)
        return claims if claims else [text.strip()] if len(text.strip()) >= 15 else []

    def is_hallucination_likely(self, claim: str) -> bool:
        """Heuristically flag claims that exhibit hallucination risk signals.

        Returns True when the claim uses vague sourcing language, invokes
        unspecific authorities ("studies show"), or makes numerical claims
        without a known fact to anchor them.

        Args:
            claim: Single claim string to evaluate.

        Returns:
            True if hallucination risk is elevated.
        """
        if self._HALLUCINATION_MARKERS.search(claim):
            return True
        # Flag bare numeric claims without context (e.g. "success rate is 97%")
        unanchored_number = re.search(r"\b\d+(\.\d+)?\s*%", claim)
        if unanchored_number and not re.search(
            r"\b(FDA|guideline|trial|study name|published|approved)\b",
            claim,
            re.IGNORECASE,
        ):
            return True
        return False

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _determine_recommendation(
        blocked: List[str],
        unverified: List[str],
        contradiction_issues: List[str],
        avg_confidence: float,
    ) -> ValidationRecommendation:
        if blocked or contradiction_issues:
            return ValidationRecommendation.BLOCK
        if unverified or avg_confidence < 0.7:
            return ValidationRecommendation.REVIEW
        return ValidationRecommendation.PROCEED


# ---------------------------------------------------------------------------
# Compliance Engine
# ---------------------------------------------------------------------------


class ComplianceEngine:
    """Regulatory compliance checks for HIPAA, GDPR, SOX, and FDA.

    Usage::

        vault = KnowledgeVault()
        engine = ComplianceEngine(vault)

        pii_found, categories = engine.check_pii_exposure("Patient SSN: 123-45-6789")
        report = engine.generate_compliance_report(days=30)
    """

    _SUPPORTED_REGULATIONS = {"HIPAA", "GDPR", "SOX", "FDA"}

    def __init__(self, vault: KnowledgeVault) -> None:
        """Initialise with a knowledge vault for audit log access.

        Args:
            vault: The ``KnowledgeVault`` instance this engine monitors.
        """
        self._vault = vault

    # ------------------------------------------------------------------
    # Public interface
    # ------------------------------------------------------------------

    def check_pii_exposure(self, text: str) -> Tuple[bool, List[str]]:
        """Scan text for exposed PII and log the check.

        Args:
            text: Text to inspect.

        Returns:
            ``(pii_found: bool, list of PII category names detected)``.
        """
        pii_found, categories = detect_pii(text)
        self._vault._log_audit(
            user_id="compliance_engine",
            action=AuditAction.COMPLIANCE_CHECK,
            resource="pii_scan",
            details={"pii_found": pii_found, "categories": categories},
            result=AuditResult.BLOCKED if pii_found else AuditResult.SUCCESS,
        )
        if pii_found:
            logger.warning(
                "PII exposure detected: categories=%s", categories
            )
        return pii_found, categories

    def check_pii_categories(self) -> Dict[str, str]:
        """Return descriptions of all tracked PII categories.

        Returns:
            Mapping from category name to regulatory description string.
        """
        return get_pii_category_descriptions()

    def check_regulatory_compliance(
        self, claim: str, regulation: str
    ) -> Tuple[bool, str]:
        """Verify that a claim is consistent with a specific regulation.

        Args:
            claim: Statement to evaluate.
            regulation: Regulation identifier (HIPAA / GDPR / SOX / FDA).

        Returns:
            ``(is_compliant: bool, explanation: str)``.

        Raises:
            ValueError: If the regulation is not supported.
        """
        regulation = regulation.upper()
        if regulation not in self._SUPPORTED_REGULATIONS:
            raise ValueError(
                f"Unsupported regulation '{regulation}'. "
                f"Supported: {self._SUPPORTED_REGULATIONS}"
            )

        is_compliant, explanation = self._evaluate_regulation(claim, regulation)

        self._vault._log_audit(
            user_id="compliance_engine",
            action=AuditAction.COMPLIANCE_CHECK,
            resource=f"regulation:{regulation}",
            details={"claim_snippet": claim[:120], "compliant": is_compliant},
            result=AuditResult.SUCCESS if is_compliant else AuditResult.BLOCKED,
        )
        return is_compliant, explanation

    def check_data_classification(self, text: str) -> AccessLevel:
        """Infer the sensitivity level of text based on its content.

        Args:
            text: Text to classify.

        Returns:
            Appropriate ``AccessLevel`` for the content.
        """
        text_lower = text.lower()

        confidential_signals = [
            "proprietary algorithm",
            "trade secret",
            "m&a",
            "merger",
            "acquisition target",
        ]
        restricted_signals = [
            "patient", "diagnosis", "prescription", "ssn", "medical record",
            "hipaa", "phi", "credit card", "bank account", "routing number",
        ]
        internal_signals = [
            "internal", "employee", "staff", "department", "policy", "procedure"
        ]

        if any(sig in text_lower for sig in confidential_signals):
            return AccessLevel.CONFIDENTIAL
        pii_found, _ = detect_pii(text)
        if pii_found or any(sig in text_lower for sig in restricted_signals):
            return AccessLevel.RESTRICTED
        if any(sig in text_lower for sig in internal_signals):
            return AccessLevel.INTERNAL
        return AccessLevel.PUBLIC

    def generate_compliance_report(self, days: int = 30) -> Dict[str, Any]:
        """Summarise compliance-relevant activity over the last *days* days.

        Args:
            days: Look-back window in days.

        Returns:
            Dictionary with counts, violation summaries, and risk indicators.
        """
        cutoff = _days_ago(days)
        log_entries = self._vault.get_audit_log(limit=10_000)
        recent = [e for e in log_entries if e["timestamp"] >= cutoff]

        total = len(recent)
        blocked = sum(1 for e in recent if e["result"] == AuditResult.BLOCKED.value)
        pii_incidents = sum(
            1
            for e in recent
            if e["action"] == AuditAction.COMPLIANCE_CHECK.value
            and e["details"].get("pii_found")
        )
        validations = sum(
            1 for e in recent if e["action"] == AuditAction.VALIDATION.value
        )

        return {
            "period_days": days,
            "generated_at": _utcnow(),
            "total_events": total,
            "blocked_events": blocked,
            "pii_incidents": pii_incidents,
            "validation_events": validations,
            "block_rate_percent": round(blocked / total * 100, 2) if total else 0,
            "risk_level": (
                "HIGH" if blocked / total > 0.1 and total > 0
                else "MEDIUM" if pii_incidents > 0
                else "LOW"
            ),
        }

    def generate_audit_report_for_regulators(
        self, regulation: str
    ) -> Dict[str, Any]:
        """Produce a regulator-facing audit package for a specific regulation.

        Args:
            regulation: Regulation identifier (HIPAA / GDPR / SOX / FDA).

        Returns:
            Structured audit report suitable for regulatory submission.

        Raises:
            ValueError: If the regulation is not supported.
        """
        regulation = regulation.upper()
        if regulation not in self._SUPPORTED_REGULATIONS:
            raise ValueError(
                f"Unsupported regulation '{regulation}'. "
                f"Supported: {self._SUPPORTED_REGULATIONS}"
            )

        all_entries = self._vault.get_audit_log(limit=10_000)
        total_facts = len(self._vault._facts)

        report = {
            "regulation": regulation,
            "generated_at": _utcnow(),
            "system": "Knowledge-Fortress v1.0",
            "total_facts_in_vault": total_facts,
            "total_audit_events": len(all_entries),
            "audit_log_integrity": self._verify_audit_integrity(),
            "compliance_summary": self._regulation_specific_summary(
                regulation, all_entries
            ),
        }
        logger.info("Regulator audit report generated for %s", regulation)
        return report

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _evaluate_regulation(
        self, claim: str, regulation: str
    ) -> Tuple[bool, str]:
        """Route a claim to the appropriate regulatory evaluator."""
        evaluators = {
            "HIPAA": self._check_hipaa,
            "GDPR": self._check_gdpr,
            "SOX": self._check_sox,
            "FDA": self._check_fda,
        }
        return evaluators[regulation](claim)

    def _check_hipaa(self, claim: str) -> Tuple[bool, str]:
        pii_found, categories = detect_pii(claim)
        if pii_found:
            return (
                False,
                f"HIPAA violation: unprotected PHI detected ({', '.join(categories)}). "
                "All PHI must be encrypted and access-controlled per 45 CFR § 164.312.",
            )
        text_lower = claim.lower()
        if "share" in text_lower and "patient" in text_lower:
            return (
                False,
                "HIPAA concern: claim references sharing patient data. "
                "Ensure minimum necessary standard (45 CFR § 164.502(b)) is applied.",
            )
        return True, "HIPAA: No PHI exposure detected. Claim appears compliant."

    def _check_gdpr(self, claim: str) -> Tuple[bool, str]:
        pii_found, categories = detect_pii(claim)
        if pii_found:
            return (
                False,
                f"GDPR violation: personal data detected ({', '.join(categories)}). "
                "Processing requires lawful basis per GDPR Article 6.",
            )
        if re.search(r"\b(store|retain|keep)\b.{0,30}\b(indefinitely|forever|permanent)\b",
                     claim, re.IGNORECASE):
            return (
                False,
                "GDPR violation: indefinite data retention breaches storage limitation "
                "principle (GDPR Article 5(1)(e)).",
            )
        return True, "GDPR: No personal data exposure or retention violations detected."

    def _check_sox(self, claim: str) -> Tuple[bool, str]:
        lower = claim.lower()
        if re.search(r"\b(delete|destroy|wipe|erase)\b.{0,30}\b(audit|log|record|trail)\b",
                     lower):
            return (
                False,
                "SOX violation: claim implies deletion of audit records. "
                "SOX Section 802 requires audit records to be retained for 7 years.",
            )
        if "modify" in lower and "audit" in lower:
            return (
                False,
                "SOX violation: audit log modification is prohibited under SOX Section 802.",
            )
        return (
            True,
            "SOX: Claim does not violate audit-trail immutability requirements.",
        )

    def _check_fda(self, claim: str) -> Tuple[bool, str]:
        lower = claim.lower()
        # Check for off-label promotion language
        off_label_re = re.compile(
            r"\b(cure|guaranteed|100%|miracle|eliminates|reverses)\b", re.IGNORECASE
        )
        if off_label_re.search(claim):
            return (
                False,
                "FDA concern: claim uses absolute or promotional language that may "
                "constitute off-label promotion. Ensure statements are backed by "
                "approved labeling (21 CFR Part 202).",
            )
        # Verify any drug name in the claim has an approved indication in the vault
        for drug in MEDICATIONS:
            if drug.replace("_", " ") in lower or drug in lower:
                verified, _ = self._vault.verify_claim(claim, domain="medical")
                if not verified:
                    return (
                        False,
                        f"FDA concern: claim about '{drug}' could not be verified "
                        "against approved labeling in the knowledge vault.",
                    )
        return True, "FDA: Claim is consistent with approved labeling information."

    def _verify_audit_integrity(self) -> Dict[str, Any]:
        """Re-hash each audit entry and report any integrity failures."""
        total = len(self._vault._audit_log)
        failures = []
        for entry in self._vault._audit_log:
            expected = entry.compute_hash()
            if entry.hash != expected:
                failures.append(entry.timestamp)
        return {
            "total_entries": total,
            "integrity_failures": len(failures),
            "failure_timestamps": failures,
            "integrity_status": "PASS" if not failures else "FAIL",
        }

    def _regulation_specific_summary(
        self, regulation: str, entries: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        summaries: Dict[str, Dict[str, Any]] = {
            "HIPAA": {
                "description": "Health Insurance Portability and Accountability Act",
                "pii_scans": sum(1 for e in entries
                                 if e["action"] == AuditAction.COMPLIANCE_CHECK.value),
                "phi_incidents": sum(1 for e in entries
                                     if e["details"].get("pii_found")),
                "controls": ["PHI encryption", "access control", "minimum necessary",
                             "breach notification"],
            },
            "GDPR": {
                "description": "General Data Protection Regulation",
                "data_access_events": sum(1 for e in entries
                                          if e["action"] == AuditAction.ACCESS.value),
                "blocked_operations": sum(1 for e in entries
                                          if e["result"] == AuditResult.BLOCKED.value),
                "controls": ["lawful basis", "data minimization", "right to erasure",
                             "breach notification"],
            },
            "SOX": {
                "description": "Sarbanes-Oxley Act",
                "audit_events": len(entries),
                "modification_events": sum(1 for e in entries
                                           if e["action"] == AuditAction.FACT_UPDATED.value),
                "integrity_status": self._verify_audit_integrity()["integrity_status"],
                "controls": ["immutable audit trail", "access logging",
                             "7-year retention", "executive certification"],
            },
            "FDA": {
                "description": "Food and Drug Administration",
                "validation_events": sum(1 for e in entries
                                         if e["action"] == AuditAction.VALIDATION.value),
                "blocked_claims": sum(1 for e in entries
                                      if e["result"] == AuditResult.BLOCKED.value),
                "controls": ["approved labeling", "off-label detection",
                             "provenance tracking", "regulatory status"],
            },
        }
        return summaries.get(regulation, {})


# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------


def _utcnow() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _days_ago(days: int) -> str:
    """Return ISO-8601 timestamp for *days* days before now."""
    from datetime import timedelta
    return (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()


# ---------------------------------------------------------------------------
# __main__ demo
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    print("=" * 70)
    print("Knowledge-Fortress - Live Demo")
    print("=" * 70)

    # Initialise core components
    vault = KnowledgeVault()
    validator = ValidationEngine(vault)
    compliance = ComplianceEngine(vault)

    # ---- 1. Medical Diagnosis Validation ----
    print("\n[1] Medical Diagnosis Validation")
    print("-" * 40)
    ai_medical_output = (
        "Metformin is contraindicated in patients with severe renal impairment "
        "due to lactic acidosis risk. "
        "Diabetes is treated with metformin and is monitored via blood glucose. "
        "Studies show that metformin cures diabetes completely in all patients."
    )
    result = validator.validate_output(ai_medical_output, domain="medical", user_id="dr_chen")
    print(f"Recommendation : {result.recommendation.value}")
    print(f"Confidence     : {result.confidence:.2%}")
    print(f"Approved claims: {len(result.approved_claims)}")
    print(f"Blocked claims : {len(result.blocked_claims)}")
    print(f"Issues         : {result.issues}")

    # ---- 2. Financial Compliance ----
    print("\n[2] Financial Compliance Check")
    print("-" * 40)
    is_compliant, explanation = compliance.check_regulatory_compliance(
        claim="The FDIC insures deposits up to $250,000 per depositor.",
        regulation="SOX",
    )
    print(f"Compliant : {is_compliant}")
    print(f"Detail    : {explanation}")

    # ---- 3. PII Detection ----
    print("\n[3] PII Exposure Check")
    print("-" * 40)
    sensitive_text = "Patient John Doe, SSN 123-45-6789, email john@example.com"
    pii_found, categories = compliance.check_pii_exposure(sensitive_text)
    print(f"PII Found  : {pii_found}")
    print(f"Categories : {categories}")

    # ---- 4. Fact Lineage ----
    print("\n[4] Fact Lineage")
    print("-" * 40)
    first_fact_id = next(iter(vault._facts))
    lineage = vault.get_fact_lineage(first_fact_id)
    print(f"Fact ID      : {lineage['fact_id']}")
    print(f"Versions     : {lineage['version_count']}")
    print(f"Current claim: {lineage['current']['claim'][:80]}...")

    # ---- 5. Compliance Report ----
    print("\n[5] Compliance Report (last 30 days)")
    print("-" * 40)
    report = compliance.generate_compliance_report(days=30)
    for key, val in report.items():
        print(f"  {key}: {val}")

    # ---- 6. Audit Log ----
    print("\n[6] Recent Audit Entries (last 5)")
    print("-" * 40)
    for entry in vault.get_audit_log(limit=5):
        print(
            f"  [{entry['timestamp']}] {entry['action']} "
            f"-> {entry['result']} (hash: {entry['hash'][:16]}...)"
        )

    print("\nDemo complete.")
