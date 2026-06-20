"""
Standalone compliance utilities re-exported for external use.

All substantive logic lives in ``fortress.ComplianceEngine``.  This module
provides convenience imports so callers can do::

    from src.compliance import run_full_compliance_audit
"""

from __future__ import annotations

from typing import Any, Dict

from .fortress import ComplianceEngine, KnowledgeVault


def run_full_compliance_audit(vault: KnowledgeVault) -> Dict[str, Any]:
    """Run compliance audit reports for all supported regulations.

    Args:
        vault: Initialised ``KnowledgeVault`` instance.

    Returns:
        Dictionary keyed by regulation name, each value is the regulator report.
    """
    engine = ComplianceEngine(vault)
    regulations = ["HIPAA", "GDPR", "SOX", "FDA"]
    return {reg: engine.generate_audit_report_for_regulators(reg) for reg in regulations}


__all__ = ["ComplianceEngine", "run_full_compliance_audit"]
