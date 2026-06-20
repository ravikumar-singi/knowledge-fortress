"""
Example: Compliance Audit Workflows
=====================================
Demonstrates HIPAA, GDPR, SOX, and FDA compliance checks, PII scanning,
data classification, and regulator-facing audit report generation.

Run from the project root::

    python examples/compliance_audit.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from src.fortress import ComplianceEngine, KnowledgeVault


def main() -> None:
    vault = KnowledgeVault()
    engine = ComplianceEngine(vault)

    print("=" * 65)
    print("Knowledge-Fortress: Compliance Audit Example")
    print("=" * 65)

    # ----------------------------------------------------------------
    # 1. PII exposure scanning
    # ----------------------------------------------------------------
    print("\n[1] PII Exposure Scanning")
    print("-" * 40)

    samples = [
        ("Clean clinical note", "Patient received 500mg amoxicillin twice daily."),
        ("Note with SSN", "Patient Jane Doe, SSN 123-45-6789 was admitted."),
        ("Note with email+phone", "Contact dr.smith@hospital.org or 555-867-5309."),
        ("Note with credit card", "Billing card: 4111111111111111 on file."),
    ]

    for label, text in samples:
        pii_found, categories = engine.check_pii_exposure(text)
        status = "BLOCKED" if pii_found else "CLEAN"
        cats = ", ".join(categories) if categories else "none"
        print(f"  [{status}] {label:30s} → {cats}")

    # ----------------------------------------------------------------
    # 2. Regulation-specific compliance checks
    # ----------------------------------------------------------------
    print("\n[2] Regulation-Specific Compliance Checks")
    print("-" * 40)

    checks = [
        ("HIPAA", "Patient SSN 123-45-6789 was stored unencrypted in the public portal."),
        ("HIPAA", "The patient received treatment per standard guidelines."),
        ("GDPR", "We retain all user emails indefinitely for marketing purposes."),
        ("GDPR", "Personal data is deleted after 30 days per our retention policy."),
        ("SOX", "The finance team will delete the audit log to free up disk space."),
        ("SOX", "Audit trails are retained for 7 years in an immutable ledger."),
        ("FDA", "Our drug is a guaranteed miracle cure with 100% success."),
        ("FDA", "Metformin is contraindicated in severe renal impairment."),
    ]

    for regulation, claim in checks:
        is_compliant, explanation = engine.check_regulatory_compliance(
            claim=claim, regulation=regulation
        )
        status = "PASS" if is_compliant else "FAIL"
        print(f"  [{regulation}][{status}] {claim[:60]}…")
        if not is_compliant:
            print(f"          ↳ {explanation[:90]}")

    # ----------------------------------------------------------------
    # 3. Data classification
    # ----------------------------------------------------------------
    print("\n[3] Automatic Data Classification")
    print("-" * 40)

    texts = [
        "The quarterly earnings report is attached.",
        "Internal staff meeting notes for Q3 planning.",
        "Patient diagnosis: type 2 diabetes. HbA1c: 8.2%.",
        "M&A target company proprietary algorithm details enclosed.",
    ]

    for text in texts:
        level = engine.check_data_classification(text)
        print(f"  [{level.value:12s}] {text[:60]}")

    # ----------------------------------------------------------------
    # 4. Compliance summary report
    # ----------------------------------------------------------------
    print("\n[4] 30-Day Compliance Summary Report")
    print("-" * 40)

    report = engine.generate_compliance_report(days=30)
    for key, value in report.items():
        print(f"  {key:30s}: {value}")

    # ----------------------------------------------------------------
    # 5. Regulator-facing audit packages
    # ----------------------------------------------------------------
    print("\n[5] Regulator Audit Package (SOX)")
    print("-" * 40)

    sox_report = engine.generate_audit_report_for_regulators("SOX")
    print(f"  Regulation        : {sox_report['regulation']}")
    print(f"  Total facts       : {sox_report['total_facts_in_vault']}")
    print(f"  Total audit events: {sox_report['total_audit_events']}")
    integrity = sox_report["audit_log_integrity"]
    print(f"  Integrity status  : {integrity['integrity_status']}")
    print(f"  Integrity failures: {integrity['integrity_failures']}")

    print("\n  Full SOX compliance summary:")
    for key, value in sox_report["compliance_summary"].items():
        print(f"    {key}: {value}")

    # ----------------------------------------------------------------
    # 6. PII category reference guide
    # ----------------------------------------------------------------
    print("\n[6] Tracked PII Category Descriptions")
    print("-" * 40)
    categories = engine.check_pii_categories()
    for cat, desc in list(categories.items())[:5]:
        print(f"  {cat:25s}: {desc[:60]}")
    print(f"  … and {len(categories) - 5} more categories tracked.")


if __name__ == "__main__":
    main()
