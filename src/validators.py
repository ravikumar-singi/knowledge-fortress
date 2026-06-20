"""PII detection and regex validation patterns for Knowledge-Fortress."""

import re
from typing import Dict, List, Tuple


# ---------------------------------------------------------------------------
# PII regex patterns
# ---------------------------------------------------------------------------

PII_PATTERNS: Dict[str, re.Pattern] = {
    "SSN": re.compile(
        r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0{4})\d{4}\b"
    ),
    "Email": re.compile(
        r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
    ),
    "Phone": re.compile(
        r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]\d{3}[-.\s]\d{4}\b"
    ),
    "Credit_Card": re.compile(
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|"
        r"3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"
    ),
    "Date_of_Birth": re.compile(
        r"\b(?:DOB|Date of Birth|born on|birth date)[:\s]*"
        r"\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}\b",
        re.IGNORECASE,
    ),
    "Medical_Record_Number": re.compile(
        r"\b(?:MRN|Medical Record(?:\s+No\.?|Number)?)[:\s]*[A-Z0-9\-]{5,20}\b",
        re.IGNORECASE,
    ),
    "IP_Address": re.compile(
        r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
    ),
    "Passport": re.compile(
        r"\b[A-Z]{1,2}[0-9]{6,9}\b"
    ),
}

# HIPAA-specific identifiers beyond standard PII
HIPAA_IDENTIFIERS: Dict[str, re.Pattern] = {
    "Patient_Name": re.compile(
        r"\b(?:patient|pt\.?)[:\s]+[A-Z][a-z]+ [A-Z][a-z]+\b"
    ),
    "Account_Number": re.compile(
        r"\b(?:account|acct\.?)[:\s]*[A-Z0-9\-]{6,20}\b",
        re.IGNORECASE,
    ),
    "Health_Plan_Number": re.compile(
        r"\b(?:policy|plan|member)[:\s]*(?:no\.?|number|#)[:\s]*[A-Z0-9\-]{5,20}\b",
        re.IGNORECASE,
    ),
}

# Financial-specific sensitive patterns
FINANCIAL_PATTERNS: Dict[str, re.Pattern] = {
    "Routing_Number": re.compile(r"\b[0-9]{9}\b"),
    "IBAN": re.compile(
        r"\b[A-Z]{2}[0-9]{2}[A-Z0-9]{4}[0-9]{7}(?:[A-Z0-9]{0,16})?\b"
    ),
    "Tax_ID": re.compile(r"\b[0-9]{2}-[0-9]{7}\b"),
}


def detect_pii(text: str) -> Tuple[bool, List[str]]:
    """Scan text for PII using compiled regex patterns.

    Args:
        text: Raw text to inspect.

    Returns:
        Tuple of (pii_found: bool, list of matched PII category names).
    """
    found_categories: List[str] = []

    all_patterns = {**PII_PATTERNS, **HIPAA_IDENTIFIERS, **FINANCIAL_PATTERNS}
    for category, pattern in all_patterns.items():
        if pattern.search(text):
            found_categories.append(category)

    return bool(found_categories), found_categories


def get_pii_category_descriptions() -> Dict[str, str]:
    """Return human-readable descriptions for all tracked PII categories.

    Returns:
        Mapping from category name to regulatory description.
    """
    return {
        "SSN": "Social Security Number — federal US identifier, HIPAA PHI",
        "Email": "Email address — GDPR personal data, HIPAA PHI",
        "Phone": "Phone number — GDPR personal data, HIPAA PHI",
        "Credit_Card": "Payment card number — PCI-DSS regulated",
        "Date_of_Birth": "Date of birth — HIPAA PHI, GDPR special category",
        "Medical_Record_Number": "Medical record number — HIPAA PHI identifier",
        "IP_Address": "IP address — GDPR personal data under EU precedent",
        "Passport": "Passport number — government-issued ID, highly sensitive",
        "Patient_Name": "Patient name — HIPAA PHI direct identifier",
        "Account_Number": "Financial/health account number — regulated identifier",
        "Health_Plan_Number": "Health insurance plan/member number — HIPAA PHI",
        "Routing_Number": "Bank routing number — financial sensitive data",
        "IBAN": "International Bank Account Number — financial sensitive data",
        "Tax_ID": "Employer Identification Number / Tax ID — IRS regulated",
    }


def sanitize_text(text: str) -> str:
    """Replace detected PII in text with redaction markers.

    Args:
        text: Text potentially containing PII.

    Returns:
        Text with PII replaced by [REDACTED:<category>] tokens.
    """
    result = text
    all_patterns = {**PII_PATTERNS, **HIPAA_IDENTIFIERS, **FINANCIAL_PATTERNS}
    for category, pattern in all_patterns.items():
        result = pattern.sub(f"[REDACTED:{category}]", result)
    return result


def validate_confidence_score(confidence: float) -> None:
    """Raise ValueError when confidence is outside [0.0, 1.0].

    Args:
        confidence: Score to validate.
    """
    if not (0.0 <= confidence <= 1.0):
        raise ValueError(
            f"Confidence must be between 0.0 and 1.0, got {confidence}"
        )


def validate_domain(domain: str, allowed_domains: List[str]) -> None:
    """Raise ValueError when domain is not in the allowed set.

    Args:
        domain: Domain string to check.
        allowed_domains: Permitted domain identifiers.
    """
    if domain not in allowed_domains:
        raise ValueError(
            f"Unknown domain '{domain}'. Allowed: {allowed_domains}"
        )
