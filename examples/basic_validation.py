"""
Example: Basic AI Output Validation
====================================
Demonstrates how to validate a block of AI-generated medical text against
the Knowledge-Fortress vault and act on the recommendation.

Run from the project root::

    python examples/basic_validation.py
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Allow running from the examples/ directory or from the project root
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.fortress import KnowledgeVault, ValidationEngine, ValidationRecommendation


def main() -> None:
    # Initialise the vault and engine (vault is pre-seeded with medical facts)
    vault = KnowledgeVault()
    engine = ValidationEngine(vault)

    print("=" * 65)
    print("Knowledge-Fortress: Basic Validation Example")
    print("=" * 65)

    # ----------------------------------------------------------------
    # Scenario 1: AI output that contains a dangerous hallucination
    # ----------------------------------------------------------------
    dangerous_output = (
        "Metformin is safe to use in patients with severe renal impairment. "
        "Studies show it causes no side effects in kidney disease patients. "
        "Doctors recommend metformin even when eGFR is below 15."
    )

    print("\n[Scenario 1] Validating dangerous AI output …")
    result = engine.validate_output(
        ai_output=dangerous_output,
        domain="medical",
        user_id="clinical_ai_system",
    )
    _print_result(result)

    # Act on recommendation
    if result.recommendation == ValidationRecommendation.BLOCK:
        print("ACTION: Output BLOCKED — do not present to clinician.")
        print(f"REASON: {result.issues}")
    elif result.recommendation == ValidationRecommendation.REVIEW:
        print("ACTION: Output flagged for EXPERT REVIEW before use.")
    else:
        print("ACTION: Output approved for presentation.")

    # ----------------------------------------------------------------
    # Scenario 2: AI output that is factually accurate
    # ----------------------------------------------------------------
    safe_output = (
        "Metformin is contraindicated in patients with severe renal impairment "
        "due to the risk of lactic acidosis. "
        "Patients with diabetes are monitored using blood glucose and HbA1c."
    )

    print("\n[Scenario 2] Validating accurate AI output …")
    result = engine.validate_output(
        ai_output=safe_output,
        domain="medical",
        user_id="clinical_ai_system",
    )
    _print_result(result)

    # ----------------------------------------------------------------
    # Scenario 3: Batch validation of multiple outputs
    # ----------------------------------------------------------------
    outputs = [
        "Lisinopril is approved for hypertension and heart failure.",
        "Warfarin is safe to use during pregnancy without any risk.",
        "Atorvastatin is used to treat hyperlipidemia.",
    ]

    print("\n[Scenario 3] Batch validation of 3 outputs …")
    results = engine.validate_claims_batch(
        outputs=outputs,
        domain="medical",
        user_id="batch_processor",
    )
    for i, (text, res) in enumerate(zip(outputs, results), start=1):
        print(f"  [{i}] {res.recommendation.value:8s}  conf={res.confidence:.2f}  "
              f"'{text[:55]}…'")

    # ----------------------------------------------------------------
    # Scenario 4: Serialise a result to JSON for downstream systems
    # ----------------------------------------------------------------
    print("\n[Scenario 4] JSON serialisation of a validation result:")
    sample = engine.validate_output(
        ai_output="Warfarin is contraindicated in pregnancy.",
        domain="medical",
        user_id="api_caller",
    )
    print(json.dumps(sample.to_dict(), indent=2))


def _print_result(result) -> None:
    print(f"  Recommendation : {result.recommendation.value}")
    print(f"  Confidence     : {result.confidence:.2%}")
    print(f"  Approved       : {len(result.approved_claims)} claims")
    print(f"  Blocked        : {len(result.blocked_claims)} claims")
    print(f"  Unverified     : {len(result.unverified_claims)} claims")
    if result.issues:
        print(f"  Issues         : {result.issues[0][:80]}")


if __name__ == "__main__":
    main()
