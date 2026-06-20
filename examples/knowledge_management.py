"""
Example: Knowledge Management Workflows
=========================================
Demonstrates adding custom facts, fact versioning, lineage tracking,
role-based access control, and audit log inspection.

Run from the project root::

    python examples/knowledge_management.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.fortress import (
    AccessLevel,
    AuditAction,
    ComplianceEngine,
    KnowledgeVault,
    UserRole,
    ValidationEngine,
    validate_access,
)


def main() -> None:
    vault = KnowledgeVault()

    print("=" * 65)
    print("Knowledge-Fortress: Knowledge Management Example")
    print("=" * 65)

    # ----------------------------------------------------------------
    # 1. Add a custom domain fact
    # ----------------------------------------------------------------
    print("\n[1] Adding Custom Facts to the Vault")
    print("-" * 40)

    fact_a = vault.add_fact(
        domain="medical",
        claim=(
            "Semaglutide (Ozempic/Wegovy) is FDA-approved for type 2 diabetes "
            "management and chronic weight management."
        ),
        source="FDA Drug Label 2023",
        confidence=0.99,
        user_id="dr_patel",
        verified_by="dr_patel",
        regulatory_status="FDA_APPROVED",
        access_level=AccessLevel.RESTRICTED,
    )
    print(f"  Created fact : {fact_a.fact_id}")
    print(f"  Domain       : {fact_a.domain}")
    print(f"  Version      : {fact_a.version}")
    print(f"  Access level : {fact_a.access_level.value}")
    print(f"  Confidence   : {fact_a.confidence:.2f}")

    # ----------------------------------------------------------------
    # 2. Update the fact (creates a new version)
    # ----------------------------------------------------------------
    print("\n[2] Updating a Fact (Versioning)")
    print("-" * 40)

    updated = vault.update_fact(
        fact_id=fact_a.fact_id,
        updates={
            "claim": (
                "Semaglutide (Ozempic/Wegovy/Rybelsus) is FDA-approved for type 2 diabetes "
                "management, chronic weight management, and cardiovascular risk reduction."
            ),
            "source": "FDA Drug Label 2024 — Updated with CV indication",
            "confidence": 0.995,
        },
        user_id="dr_patel",
    )
    print(f"  New version  : {updated.version}")
    print(f"  Updated claim: {updated.claim[:80]}…")

    # ----------------------------------------------------------------
    # 3. Inspect fact lineage
    # ----------------------------------------------------------------
    print("\n[3] Fact Lineage (Full Version History)")
    print("-" * 40)

    lineage = vault.get_fact_lineage(fact_a.fact_id)
    print(f"  Fact ID     : {lineage['fact_id']}")
    print(f"  Total vers. : {lineage['version_count']}")
    for version_dict in lineage["history"]:
        print(
            f"    v{version_dict['version']} [{version_dict['last_updated'][:19]}] "
            f"conf={version_dict['confidence']:.3f}"
        )

    # ----------------------------------------------------------------
    # 4. Role-based access control demonstration
    # ----------------------------------------------------------------
    print("\n[4] Role-Based Access Control")
    print("-" * 40)

    # Add facts at different sensitivity levels
    public_fact = vault.add_fact(
        domain="general",
        claim="Hand hygiene is the most effective infection control measure.",
        source="WHO Guidelines",
        confidence=0.99,
        access_level=AccessLevel.PUBLIC,
    )
    confidential_fact = vault.add_fact(
        domain="medical",
        claim="Clinical trial protocol XR-2025 details: primary endpoint is HbA1c reduction.",
        source="Internal Research Protocol",
        confidence=0.95,
        access_level=AccessLevel.CONFIDENTIAL,
    )

    role_tests = [
        (UserRole.USER, public_fact, "PUBLIC fact"),
        (UserRole.USER, confidential_fact, "CONFIDENTIAL fact"),
        (UserRole.REVIEWER, confidential_fact, "CONFIDENTIAL fact"),
        (UserRole.EXPERT, updated, "RESTRICTED fact"),
        (UserRole.EXPERT, confidential_fact, "CONFIDENTIAL fact"),
        (UserRole.ADMIN, confidential_fact, "CONFIDENTIAL fact"),
    ]

    for role, fact, label in role_tests:
        has_access = validate_access(role.value, fact)
        symbol = "✓" if has_access else "✗"
        print(
            f"  {symbol} {role.value:10s} → {label:22s} "
            f"[{fact.access_level.value}]"
        )

    # ----------------------------------------------------------------
    # 5. List facts with domain and role filtering
    # ----------------------------------------------------------------
    print("\n[5] Listing Facts with Role-Based Filtering")
    print("-" * 40)

    for role in [UserRole.USER, UserRole.EXPERT, UserRole.ADMIN]:
        facts = vault.list_facts(domain="medical", user_role=role.value)
        print(f"  {role.value:10s}: {len(facts):3d} medical facts visible")

    # ----------------------------------------------------------------
    # 6. Claim verification
    # ----------------------------------------------------------------
    print("\n[6] Claim Verification Lookups")
    print("-" * 40)

    test_claims = [
        ("Metformin is contraindicated in severe renal impairment", "medical"),
        ("Warfarin requires INR monitoring", "medical"),
        ("Cash transactions over $10,000 require a Currency Transaction Report", "financial"),
        ("Unicorn dust cures all diseases instantly", "medical"),
    ]

    for claim, domain in test_claims:
        verified, confidence = vault.verify_claim(claim, domain=domain)
        status = "VERIFIED" if verified else "NOT FOUND"
        print(f"  [{status}] conf={confidence:.2f}  {claim[:60]}")

    # ----------------------------------------------------------------
    # 7. Audit log inspection
    # ----------------------------------------------------------------
    print("\n[7] Recent Audit Log Entries")
    print("-" * 40)

    entries = vault.get_audit_log(limit=8)
    print(f"  Showing last {len(entries)} entries (newest first):")
    for entry in entries:
        print(
            f"  {entry['timestamp'][:19]}  {entry['action']:18s}  "
            f"{entry['result']:10s}  hash:{entry['hash'][:12]}…"
        )

    # Verify audit integrity by filtering for FACT_CREATED events
    created_events = vault.get_audit_log(
        limit=100, action_filter=AuditAction.FACT_CREATED
    )
    print(f"\n  Total FACT_CREATED audit events : {len(created_events)}")
    print(f"  Total facts in vault            : {len(vault._facts)}")

    # ----------------------------------------------------------------
    # 8. Serialise a fact to JSON
    # ----------------------------------------------------------------
    print("\n[8] Fact Serialisation (JSON)")
    print("-" * 40)
    print(json.dumps(updated.to_dict(), indent=2))


if __name__ == "__main__":
    main()
