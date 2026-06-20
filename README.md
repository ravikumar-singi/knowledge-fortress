# Knowledge-Fortress

Production-grade knowledge management and AI output validation for regulated industries (healthcare, finance, legal).

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Knowledge-Fortress                          │
│                                                                 │
│  ┌──────────────┐    ┌──────────────────┐    ┌─────────────┐   │
│  │  Knowledge   │◄──►│   Validation     │    │ Compliance  │   │
│  │    Vault     │    │    Engine        │    │   Engine    │   │
│  │              │    │                  │    │             │   │
│  │ • Facts      │    │ • Extract claims │    │ • HIPAA     │   │
│  │ • Versioning │    │ • Verify vs vault│    │ • GDPR      │   │
│  │ • Lineage    │    │ • Check contrad. │    │ • SOX       │   │
│  │ • Audit log  │    │ • Score/recommend│    │ • FDA       │   │
│  └──────┬───────┘    └──────────────────┘    └──────┬──────┘   │
│         │                                           │           │
│         ▼                                           ▼           │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                     Audit Logger                         │   │
│  │   • Append-only  • SHA-256 hashed  • Tamper-evident      │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                 │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                   Access Control                         │   │
│  │    USER → PUBLIC   REVIEWER → INTERNAL                   │   │
│  │    EXPERT → RESTRICTED   ADMIN → CONFIDENTIAL            │   │
│  └──────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

---

## Quick Start

```python
from src.fortress import KnowledgeVault, ValidationEngine, ComplianceEngine

# 1. Initialise (auto-seeds medical, financial, legal knowledge bases)
vault = KnowledgeVault()
engine = ValidationEngine(vault)
compliance = ComplianceEngine(vault)

# 2. Validate AI output
result = engine.validate_output(
    ai_output="Metformin is safe in all patients, including those with kidney failure.",
    domain="medical",
    user_id="ai_system",
)
print(result.recommendation)   # ValidationRecommendation.BLOCK
print(result.issues)           # ["Potential hallucination detected: …"]

# 3. Check PII exposure
pii_found, categories = compliance.check_pii_exposure("Patient SSN: 123-45-6789")
# pii_found=True, categories=["SSN"]

# 4. Regulatory compliance
is_compliant, msg = compliance.check_regulatory_compliance(
    "Delete the audit log after 30 days.", regulation="SOX"
)
# is_compliant=False, msg="SOX violation: …"
```

---

## File Structure

```
knowledge-fortress/
├── src/
│   ├── __init__.py          — Public API surface
│   ├── fortress.py          — Core implementation (~900 lines)
│   ├── exceptions.py        — Custom exception hierarchy
│   ├── validators.py        — PII regex patterns + input validation
│   ├── compliance.py        — Compliance utilities / re-exports
│   └── knowledge_bases.py   — Curated medical, financial, legal data
├── tests/
│   ├── conftest.py          — Shared fixtures
│   ├── test_vault.py        — KnowledgeVault unit tests
│   ├── test_validation.py   — ValidationEngine unit tests
│   ├── test_compliance.py   — ComplianceEngine unit tests
│   └── test_access_control.py — RBAC + AuditEntry immutability
├── examples/
│   ├── basic_validation.py  — Medical AI output validation walkthrough
│   ├── compliance_audit.py  — HIPAA/GDPR/SOX/FDA audit workflows
│   └── knowledge_management.py — Versioning, lineage, RBAC demo
├── requirements.txt
└── README.md
```

---

## Core Classes

### KnowledgeVault

Append-only store for verified facts. Every write is versioned; no fact is ever deleted.

| Method | Description |
|--------|-------------|
| `add_fact(...)` | Add a new versioned fact |
| `verify_claim(claim, domain)` | Check if a claim is supported → `(bool, confidence)` |
| `update_fact(fact_id, updates)` | Create a new version of a fact |
| `get_fact_lineage(fact_id)` | Full version history of a fact |
| `list_facts(domain, access_level)` | Filtered, role-checked fact listing |
| `get_audit_log(limit, action_filter)` | Recent audit entries, newest first |

### ValidationEngine

Validates AI-generated text blocks against the vault in real-time.

| Method | Description |
|--------|-------------|
| `validate_output(text, domain, user_id)` | Full validation with recommendation |
| `validate_claims_batch(outputs, domain)` | Validate multiple outputs at once |
| `extract_claims(text)` | Sentence-level claim extraction |
| `check_contradictions(claims)` | Detect pairwise contradictions |
| `is_hallucination_likely(claim)` | Heuristic hallucination flag |

**Recommendation values:** `PROCEED` · `REVIEW` · `BLOCK`

### ComplianceEngine

Regulatory checks for HIPAA, GDPR, SOX, and FDA.

| Method | Description |
|--------|-------------|
| `check_pii_exposure(text)` | Scan for PII → `(bool, [categories])` |
| `check_pii_categories()` | Descriptions of all tracked PII types |
| `check_regulatory_compliance(claim, regulation)` | Per-regulation check |
| `check_data_classification(text)` | Infer `AccessLevel` from content |
| `generate_compliance_report(days)` | 30-day activity summary |
| `generate_audit_report_for_regulators(regulation)` | Regulator package |

---

## Data Structures

### FactMetadata

```python
@dataclass
class FactMetadata:
    fact_id: str              # UUID4
    domain: str               # medical / financial / legal / general
    claim: str                # The factual statement
    source: str               # Authoritative citation
    confidence: float         # [0.0, 1.0]
    created_at: str           # ISO-8601
    last_updated: str         # ISO-8601
    verified_by: Optional[str]
    regulatory_status: Optional[str]   # e.g. "FDA_APPROVED"
    version: int              # Increments on each update
    access_level: AccessLevel # PUBLIC / INTERNAL / RESTRICTED / CONFIDENTIAL
    related_facts: List[str]  # Related fact_ids
```

### ValidationResult

```python
@dataclass
class ValidationResult:
    is_valid: bool
    confidence: float
    approved_claims: List[str]
    blocked_claims: List[str]
    unverified_claims: List[str]
    issues: List[str]
    recommendation: ValidationRecommendation   # PROCEED / REVIEW / BLOCK
    timestamp: str
```

### AuditEntry (immutable)

```python
@dataclass
class AuditEntry:
    timestamp: str
    user_id: str
    action: AuditAction       # VALIDATION / MODIFICATION / ACCESS / …
    resource: str
    details: Dict[str, Any]
    result: AuditResult       # SUCCESS / BLOCKED / ESCALATED / FAILED
    hash: str                 # SHA-256; computed at creation, immutable
```

---

## Access Control

| Role | PUBLIC | INTERNAL | RESTRICTED | CONFIDENTIAL |
|------|--------|----------|------------|--------------|
| USER | ✓ | ✗ | ✗ | ✗ |
| REVIEWER | ✓ | ✓ | ✗ | ✗ |
| EXPERT | ✓ | ✓ | ✓ | ✗ |
| ADMIN | ✓ | ✓ | ✓ | ✓ |

---

## Compliance Features

### HIPAA
- PHI detection via 8 regex patterns (SSN, email, phone, MRN, DOB, …)
- Minimum necessary standard enforcement
- 60-day breach notification tracking
- Audit trail for all PHI access events

### GDPR
- Personal data detection across 14 categories
- Storage limitation principle validation
- Right to erasure policy checks
- Data minimization guidance

### SOX
- Append-only audit log — mutations raise `ImmutabilityViolationError`
- SHA-256 integrity hashing on every audit entry
- 7-year retention policy validation
- Prohibition on audit log deletion

### FDA
- Off-label promotion detection (absolute/promotional language)
- Drug-claim verification against approved labeling
- `FDA_APPROVED` / `FDA_BLACK_BOX_WARNING` regulatory status tagging
- Drug interaction and contraindication knowledge base

---

## Pre-Seeded Knowledge Bases

**Medical**
- 6 medications with indications, contraindications, interactions, monitoring
- 5 conditions with approved treatments and monitoring protocols
- 6 critical drug interaction pairs with severity and mitigation
- 4 absolute contraindications with FDA black-box warnings

**Financial**
- 6 US financial regulations (FDIC, FCBA, EFTA, BSA, IRS, FINRA)
- 5 compliance policies (KYC, AML, SOX, GDPR, HIPAA)

**Legal**
- 4 regulatory precedents (GDPR erasure, HIPAA breach notification, SOX 302, HIPAA minimum necessary)

---

## Running Tests

```bash
# Install dev dependencies
pip install pytest pytest-cov

# Run all tests
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=src --cov-report=term-missing

# Run a specific test file
pytest tests/test_vault.py -v
```

---

## Running Examples

```bash
# From the project root
python examples/basic_validation.py
python examples/compliance_audit.py
python examples/knowledge_management.py

# Live demo (same as __main__ in fortress.py)
python -m src.fortress
```

---

## Exception Hierarchy

```
KnowledgeFortressError
├── ValidationError             — validation operation failure
├── AccessDeniedError           — insufficient clearance
├── ComplianceViolationError    — regulatory breach
│   └── PIIDetectedError        — PII exposure detected
├── FactNotFoundError           — fact_id does not exist
├── DuplicateFactError          — identical fact already in vault
└── ImmutabilityViolationError  — attempt to mutate audit entry
```

---

## Performance Targets

| Operation | Target |
|-----------|--------|
| Single claim verification | < 100 ms |
| 100-claim batch validation | < 500 ms |
| Exact fact lookup | O(1) |
| Audit log query (10 K entries) | < 1 000 ms |
| Memory for 100 K facts | < 500 MB |

---

## Security Design

- **No secrets in code** — no API keys, passwords, or tokens
- **Immutable audit trail** — `AuditEntry.__setattr__` blocks post-creation writes
- **Cryptographic integrity** — SHA-256 hash computed and stored on every entry
- **PII detection** — 14 categories of PII/PHI caught before storage or display
- **Role-based access** — every `list_facts` call is filtered by role clearance
- **Structured logging** — JSON-format logs include timestamps and user context

---

## Real-World Use Cases

### 1. Clinical Decision Support
```python
# AI suggests a treatment plan — validate before showing to a clinician
result = engine.validate_output(
    ai_output=clinical_ai_response,
    domain="medical",
    user_id=clinician_id,
)
if result.recommendation == ValidationRecommendation.BLOCK:
    raise SafetyError("AI output contains contraindicated recommendations.")
```

### 2. Financial Transaction Compliance
```python
# Check whether a transaction description violates AML/BSA rules
is_compliant, detail = compliance.check_regulatory_compliance(
    claim=transaction_description, regulation="HIPAA"
)
```

### 3. Automated Regulatory Reporting
```python
# Generate a SOX-ready audit package for external auditors
report = compliance.generate_audit_report_for_regulators("SOX")
# report["audit_log_integrity"]["integrity_status"] == "PASS"
```

---

## License

MIT — see LICENSE file.
