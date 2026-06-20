"""Pre-seeded knowledge bases for medical and financial domains."""

from typing import Any, Dict, Tuple


# ---------------------------------------------------------------------------
# Medical domain
# ---------------------------------------------------------------------------

MEDICATIONS: Dict[str, Dict[str, Any]] = {
    "metformin": {
        "approved_for": ["diabetes", "prediabetes", "polycystic_ovary_syndrome"],
        "contraindications": [
            "severe_renal_impairment",
            "metabolic_acidosis",
            "diabetic_ketoacidosis",
        ],
        "interactions": ["contrast_dye", "alcohol", "topiramate"],
        "requires_monitoring": ["kidney_function", "vitamin_b12"],
        "fda_status": "FDA_APPROVED",
        "confidence": 0.99,
        "source": "FDA Drug Label / Clinical Pharmacology",
    },
    "lisinopril": {
        "approved_for": ["hypertension", "heart_failure", "post_mi"],
        "contraindications": [
            "pregnancy",
            "history_of_angioedema",
            "concurrent_aliskiren_in_diabetes",
        ],
        "interactions": ["potassium_supplements", "nsaids", "lithium"],
        "requires_monitoring": ["blood_pressure", "serum_potassium", "renal_function"],
        "fda_status": "FDA_APPROVED",
        "confidence": 0.99,
        "source": "FDA Drug Label",
    },
    "warfarin": {
        "approved_for": [
            "atrial_fibrillation",
            "dvt_treatment",
            "pe_treatment",
            "mechanical_heart_valves",
        ],
        "contraindications": [
            "pregnancy",
            "active_major_bleeding",
            "hemorrhagic_stroke",
        ],
        "interactions": [
            "aspirin",
            "ibuprofen",
            "amiodarone",
            "fluconazole",
            "rifampin",
            "vitamin_k_rich_foods",
        ],
        "requires_monitoring": ["inr", "bleeding_signs"],
        "fda_status": "FDA_APPROVED",
        "confidence": 0.99,
        "source": "FDA Drug Label / ACCP Guidelines",
    },
    "atorvastatin": {
        "approved_for": [
            "hyperlipidemia",
            "mixed_dyslipidemia",
            "primary_prevention_cvd",
        ],
        "contraindications": ["active_liver_disease", "pregnancy", "nursing_mothers"],
        "interactions": ["cyclosporine", "clarithromycin", "itraconazole", "niacin"],
        "requires_monitoring": ["liver_enzymes", "muscle_pain_symptoms"],
        "fda_status": "FDA_APPROVED",
        "confidence": 0.99,
        "source": "FDA Drug Label",
    },
    "insulin_glargine": {
        "approved_for": ["type1_diabetes", "type2_diabetes"],
        "contraindications": ["hypoglycemia"],
        "interactions": ["beta_blockers", "alcohol", "pioglitazone"],
        "requires_monitoring": [
            "blood_glucose",
            "HbA1c",
            "injection_site_reactions",
        ],
        "fda_status": "FDA_APPROVED",
        "confidence": 0.99,
        "source": "FDA Drug Label",
    },
    "amoxicillin": {
        "approved_for": [
            "bacterial_infections",
            "strep_throat",
            "otitis_media",
            "sinusitis",
            "pneumonia",
            "h_pylori_eradication",
        ],
        "contraindications": ["penicillin_allergy"],
        "interactions": ["warfarin", "methotrexate", "oral_contraceptives"],
        "requires_monitoring": ["renal_function_in_high_dose"],
        "fda_status": "FDA_APPROVED",
        "confidence": 0.99,
        "source": "FDA Drug Label",
    },
}

CONDITIONS: Dict[str, Dict[str, Any]] = {
    "diabetes": {
        "type": "chronic",
        "approved_treatments": [
            "metformin",
            "insulin_glargine",
            "glipizide",
            "sitagliptin",
            "empagliflozin",
        ],
        "monitoring": ["blood_glucose", "HbA1c", "kidney_function", "eye_exams"],
        "icd10_code": "E11",
        "confidence": 0.99,
        "source": "ADA Standards of Medical Care",
    },
    "hypertension": {
        "type": "chronic",
        "approved_treatments": [
            "lisinopril",
            "amlodipine",
            "hydrochlorothiazide",
            "losartan",
        ],
        "monitoring": ["blood_pressure", "serum_potassium", "renal_function"],
        "icd10_code": "I10",
        "confidence": 0.99,
        "source": "JNC8 / ACC/AHA Guidelines",
    },
    "hyperlipidemia": {
        "type": "chronic",
        "approved_treatments": ["atorvastatin", "rosuvastatin", "ezetimibe"],
        "monitoring": ["lipid_panel", "liver_enzymes"],
        "icd10_code": "E78",
        "confidence": 0.99,
        "source": "ACC/AHA Cholesterol Guidelines",
    },
    "atrial_fibrillation": {
        "type": "chronic",
        "approved_treatments": [
            "warfarin",
            "apixaban",
            "rivaroxaban",
            "metoprolol",
            "amiodarone",
        ],
        "monitoring": ["inr_if_warfarin", "heart_rate", "stroke_risk"],
        "icd10_code": "I48",
        "confidence": 0.99,
        "source": "AHA/ACC/HRS Guideline",
    },
    "bacterial_infection": {
        "type": "acute",
        "approved_treatments": [
            "amoxicillin",
            "azithromycin",
            "doxycycline",
            "cephalexin",
        ],
        "monitoring": ["symptoms", "culture_sensitivity"],
        "icd10_code": "A49",
        "confidence": 0.95,
        "source": "IDSA Guidelines",
    },
}

# Keys are ordered tuples (drug_a, drug_b) — always sort alphabetically
DRUG_INTERACTIONS: Dict[Tuple[str, str], Dict[str, Any]] = {
    ("contrast_dye", "metformin"): {
        "severity": "HIGH",
        "effect": "lactic_acidosis_risk",
        "mitigation": "hold_metformin_48h_before_contrast_procedure",
        "confidence": 0.99,
        "source": "ACR Manual on Contrast Media",
    },
    ("amiodarone", "warfarin"): {
        "severity": "HIGH",
        "effect": "potentiated_anticoagulation_bleeding_risk",
        "mitigation": "reduce_warfarin_dose_monitor_inr_closely",
        "confidence": 0.99,
        "source": "FDA Drug Interaction Database",
    },
    ("aspirin", "warfarin"): {
        "severity": "MODERATE",
        "effect": "increased_bleeding_risk",
        "mitigation": "use_lowest_effective_aspirin_dose_monitor_inr",
        "confidence": 0.97,
        "source": "Clinical Pharmacology Database",
    },
    ("clarithromycin", "atorvastatin"): {
        "severity": "HIGH",
        "effect": "myopathy_rhabdomyolysis_risk",
        "mitigation": "suspend_atorvastatin_during_clarithromycin_course",
        "confidence": 0.99,
        "source": "FDA Drug Label / Drug Interaction Database",
    },
    ("alcohol", "metformin"): {
        "severity": "MODERATE",
        "effect": "lactic_acidosis_risk_potentiated",
        "mitigation": "counsel_patient_to_avoid_excessive_alcohol",
        "confidence": 0.95,
        "source": "FDA Drug Label",
    },
    ("beta_blockers", "insulin_glargine"): {
        "severity": "MODERATE",
        "effect": "hypoglycemia_symptom_masking",
        "mitigation": "monitor_blood_glucose_closely_educate_patient",
        "confidence": 0.97,
        "source": "Clinical Pharmacology Database",
    },
}

CONTRAINDICATIONS: Dict[str, Dict[str, Any]] = {
    "metformin_in_severe_renal_impairment": {
        "drug": "metformin",
        "condition": "severe_renal_impairment",
        "egfr_threshold": 30,
        "reason": "lactic_acidosis_risk_due_to_drug_accumulation",
        "severity": "ABSOLUTE",
        "confidence": 0.99,
        "source": "FDA Black Box Warning",
    },
    "warfarin_in_pregnancy": {
        "drug": "warfarin",
        "condition": "pregnancy",
        "reason": "fetal_warfarin_syndrome_and_hemorrhage",
        "severity": "ABSOLUTE",
        "confidence": 0.99,
        "source": "FDA Black Box Warning",
    },
    "lisinopril_in_pregnancy": {
        "drug": "lisinopril",
        "condition": "pregnancy",
        "reason": "fetal_renal_toxicity_and_death",
        "severity": "ABSOLUTE",
        "confidence": 0.99,
        "source": "FDA Black Box Warning",
    },
    "atorvastatin_in_pregnancy": {
        "drug": "atorvastatin",
        "condition": "pregnancy",
        "reason": "fetal_harm_cholesterol_required_for_fetal_development",
        "severity": "ABSOLUTE",
        "confidence": 0.99,
        "source": "FDA Drug Label",
    },
}


# ---------------------------------------------------------------------------
# Financial domain
# ---------------------------------------------------------------------------

FINANCIAL_REGULATIONS: Dict[str, Dict[str, Any]] = {
    "credit_card_fraud_liability_limit": {
        "amount": 50,
        "description": (
            "Maximum consumer liability for unauthorized credit card charges "
            "under the Fair Credit Billing Act (FCBA) when reported within 60 days"
        ),
        "jurisdiction": "US",
        "regulation": "Fair Credit Billing Act 15 U.S.C. § 1643",
        "confidence": 0.99,
        "source": "CFPB / FTC Official Guidance",
    },
    "debit_card_fraud_liability_limit_reported_within_2_days": {
        "amount": 50,
        "description": (
            "Maximum consumer liability when unauthorized debit card use "
            "is reported within 2 business days under EFTA"
        ),
        "jurisdiction": "US",
        "regulation": "Electronic Funds Transfer Act 15 U.S.C. § 1693g",
        "confidence": 0.99,
        "source": "CFPB Official Guidance",
    },
    "fdic_insurance_limit": {
        "amount": 250000,
        "description": "Per-depositor, per-institution, per-ownership-category FDIC coverage",
        "jurisdiction": "US",
        "regulation": "Federal Deposit Insurance Act",
        "confidence": 0.99,
        "source": "FDIC Official Site",
    },
    "irs_gift_tax_annual_exclusion_2024": {
        "amount": 18000,
        "description": "Annual gift tax exclusion per recipient for 2024",
        "jurisdiction": "US",
        "regulation": "IRC § 2503(b)",
        "confidence": 0.99,
        "source": "IRS Rev. Proc. 2023-34",
    },
    "finra_pattern_day_trader_minimum_equity": {
        "amount": 25000,
        "description": (
            "Minimum equity a pattern day trader must maintain in a "
            "margin account before day trading"
        ),
        "jurisdiction": "US",
        "regulation": "FINRA Rule 4210",
        "confidence": 0.99,
        "source": "FINRA Official Rules",
    },
    "bsa_cash_transaction_reporting_threshold": {
        "amount": 10000,
        "description": "Cash transactions ≥ $10,000 require a Currency Transaction Report (CTR)",
        "jurisdiction": "US",
        "regulation": "Bank Secrecy Act 31 U.S.C. § 5313",
        "confidence": 0.99,
        "source": "FinCEN Official Guidance",
    },
}

FINANCIAL_POLICIES: Dict[str, Dict[str, Any]] = {
    "kyc_required_for_new_accounts": {
        "description": "Know Your Customer (KYC) verification mandatory for all new accounts",
        "regulation": "BSA / FinCEN Customer Due Diligence Rule",
        "mandatory": True,
        "confidence": 0.99,
        "source": "FinCEN CDD Final Rule",
    },
    "aml_monitoring_required": {
        "description": "Anti-Money Laundering transaction monitoring required for financial institutions",
        "regulation": "Bank Secrecy Act",
        "mandatory": True,
        "confidence": 0.99,
        "source": "FinCEN / FFIEC BSA/AML Examination Manual",
    },
    "sox_audit_trail_retention": {
        "description": "SOX requires audit trails be retained for minimum 7 years",
        "regulation": "Sarbanes-Oxley Act Section 802",
        "retention_years": 7,
        "mandatory": True,
        "confidence": 0.99,
        "source": "SEC / PCAOB Official Rules",
    },
    "gdpr_data_retention_limits": {
        "description": "Personal data must not be kept longer than necessary for its purpose",
        "regulation": "GDPR Article 5(1)(e)",
        "mandatory": True,
        "confidence": 0.99,
        "source": "EU GDPR Official Text",
    },
    "hipaa_minimum_necessary_standard": {
        "description": "Access to PHI must be limited to the minimum necessary for the purpose",
        "regulation": "HIPAA Privacy Rule 45 CFR § 164.502(b)",
        "mandatory": True,
        "confidence": 0.99,
        "source": "HHS HIPAA Official Guidance",
    },
}

# ---------------------------------------------------------------------------
# Legal domain
# ---------------------------------------------------------------------------

LEGAL_PRECEDENTS: Dict[str, Dict[str, Any]] = {
    "gdpr_right_to_erasure": {
        "principle": "Data subjects have the right to request deletion of their personal data",
        "regulation": "GDPR Article 17",
        "jurisdiction": "EU",
        "exceptions": [
            "legal_obligation",
            "public_interest",
            "legal_claims",
            "freedom_of_expression",
        ],
        "confidence": 0.99,
        "source": "EU GDPR Official Text",
    },
    "hipaa_breach_notification": {
        "principle": (
            "Covered entities must notify affected individuals within 60 days of "
            "discovering a PHI breach affecting 500+ individuals"
        ),
        "regulation": "HIPAA Breach Notification Rule 45 CFR §§ 164.400-414",
        "jurisdiction": "US",
        "deadline_days": 60,
        "confidence": 0.99,
        "source": "HHS Official Rule",
    },
    "sox_302_certification": {
        "principle": (
            "Principal executive and financial officers must certify the accuracy "
            "of financial reports"
        ),
        "regulation": "Sarbanes-Oxley Act Section 302",
        "jurisdiction": "US",
        "confidence": 0.99,
        "source": "SEC Official Rules",
    },
    "hipaa_minimum_necessary": {
        "principle": "PHI disclosures must be limited to the minimum necessary",
        "regulation": "HIPAA Privacy Rule 45 CFR § 164.502(b)",
        "jurisdiction": "US",
        "confidence": 0.99,
        "source": "HHS HIPAA Official Guidance",
    },
}
