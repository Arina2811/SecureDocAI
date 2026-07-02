"""
Rule-based compliance analysis engine.

Maps detected entity types to potential violations across major
compliance frameworks: GDPR, HIPAA, PCI DSS, ISO 27001, SOC 2,
and DPDP Act (India).
"""

from __future__ import annotations

import logging
from typing import Optional

from models.schemas import ComplianceViolation, DetectedEntity, Severity

logger = logging.getLogger("securedoc.compliance")


# ─── Compliance Rule Definitions ──────────────────────────────────────────────

# Each rule maps a set of entity types to a framework violation.
# ``trigger_types`` — if **any** of these types appear, the rule fires.

_COMPLIANCE_RULES: list[dict] = [
    # ── GDPR ──────────────────────────────────────────────────────────────
    {
        "framework": "GDPR",
        "trigger_types": {
            "Person Name", "Email Address", "Phone Number", "Physical Address",
            "Aadhaar Number", "PAN Number", "Passport Number",
            "Driving License Number",
        },
        "violation": "Processing of personal data without adequate protection",
        "description": (
            "GDPR Article 5 & 32 require appropriate technical and "
            "organisational measures to protect personal data. The document "
            "contains unprotected PII."
        ),
        "severity": Severity.HIGH,
        "recommendation": (
            "Encrypt or pseudonymise personal data. Implement access controls "
            "and audit logging. Conduct a Data Protection Impact Assessment."
        ),
    },
    {
        "framework": "GDPR",
        "trigger_types": {"Salary Information", "Monetary Value"},
        "violation": "Exposure of special-category financial data",
        "description": (
            "GDPR requires explicit consent for processing financial data "
            "that can identify individuals."
        ),
        "severity": Severity.MEDIUM,
        "recommendation": "Redact salary and financial details. Restrict access.",
    },

    # ── HIPAA ─────────────────────────────────────────────────────────────
    {
        "framework": "HIPAA",
        "trigger_types": {
            "Person Name", "Email Address", "Phone Number", "Physical Address",
            "SSN", "Date",
        },
        "violation": "Potential exposure of Protected Health Information (PHI)",
        "description": (
            "HIPAA Privacy Rule requires safeguards for individually "
            "identifiable health information. Document contains identifiers "
            "that may constitute PHI if associated with health data."
        ),
        "severity": Severity.HIGH,
        "recommendation": (
            "Apply HIPAA-compliant encryption. Implement minimum necessary "
            "access. Train staff on PHI handling."
        ),
    },

    # ── PCI DSS ───────────────────────────────────────────────────────────
    {
        "framework": "PCI DSS",
        "trigger_types": {
            "Credit/Debit Card Number", "Bank Account Number", "IFSC Code",
            "UPI ID",
        },
        "violation": "Storage of payment card and financial data in plaintext",
        "description": (
            "PCI DSS Requirement 3 prohibits storing sensitive "
            "authentication data after authorisation. Card numbers must be "
            "masked or tokenised."
        ),
        "severity": Severity.CRITICAL,
        "recommendation": (
            "Immediately remove or mask card numbers. Implement PCI-compliant "
            "tokenisation. Never store CVV or full magnetic stripe data."
        ),
    },

    # ── ISO 27001 ─────────────────────────────────────────────────────────
    {
        "framework": "ISO 27001",
        "trigger_types": {
            "Password", "API Key", "OAuth/Bearer Token", "JWT Token",
            "SSH/Private Key", "AWS Access Key", "Azure Key",
            "Google Cloud Credential", "Secret Key",
        },
        "violation": "Inadequate information security controls for credentials",
        "description": (
            "ISO 27001 Annex A.9 requires access control policies. "
            "Credentials stored in documents violate secure handling practices."
        ),
        "severity": Severity.CRITICAL,
        "recommendation": (
            "Rotate all exposed credentials immediately. Store secrets in a "
            "vault (HashiCorp Vault, AWS Secrets Manager). Revoke compromised keys."
        ),
    },

    # ── SOC 2 ─────────────────────────────────────────────────────────────
    {
        "framework": "SOC 2",
        "trigger_types": {
            "Person Name", "Email Address", "Customer ID", "Employee ID",
            "Confidentiality Marker",
        },
        "violation": "Failure to meet Trust Services Criteria for confidentiality",
        "description": (
            "SOC 2 CC6.1 & C1.1 require controls to protect confidential "
            "information. The document contains identifiable data without "
            "documented controls."
        ),
        "severity": Severity.MEDIUM,
        "recommendation": (
            "Classify documents by sensitivity level. Apply DLP policies. "
            "Implement access reviews and monitoring."
        ),
    },

    # ── DPDP Act (India) ──────────────────────────────────────────────────
    {
        "framework": "DPDP Act (India)",
        "trigger_types": {
            "Aadhaar Number", "PAN Number", "Passport Number",
            "Driving License Number", "Phone Number", "Email Address",
            "Person Name",
        },
        "violation": "Processing digital personal data without valid consent",
        "description": (
            "The Digital Personal Data Protection Act, 2023 (India) requires "
            "lawful purpose and explicit consent for processing personal data "
            "of Indian data principals."
        ),
        "severity": Severity.HIGH,
        "recommendation": (
            "Obtain explicit consent. Implement data localisation where "
            "required. Appoint a Data Protection Officer. Enable data "
            "erasure mechanisms."
        ),
    },
    {
        "framework": "DPDP Act (India)",
        "trigger_types": {"Aadhaar Number"},
        "violation": "Exposure of Aadhaar data in violation of Aadhaar Act provisions",
        "description": (
            "Section 29 of the Aadhaar Act prohibits unauthorized disclosure "
            "of identity information including Aadhaar numbers."
        ),
        "severity": Severity.CRITICAL,
        "recommendation": (
            "Mask Aadhaar numbers (show only last 4 digits). Implement "
            "Virtual ID where possible. Restrict access to Aadhaar data."
        ),
    },
]


# ─── Public API ────────────────────────────────────────────────────────────────


def check_compliance(
    entities: list[DetectedEntity],
) -> list[ComplianceViolation]:
    """Evaluate detected entities against all compliance rules.

    Parameters
    ----------
    entities : list[DetectedEntity]
        Entities detected in the document.

    Returns
    -------
    list[ComplianceViolation]
        All triggered violations, sorted by severity.
    """
    entity_types_present = {e.entity_type for e in entities}
    violations: list[ComplianceViolation] = []

    for rule in _COMPLIANCE_RULES:
        triggered = entity_types_present & rule["trigger_types"]
        if triggered:
            violations.append(
                ComplianceViolation(
                    framework=rule["framework"],
                    violation=rule["violation"],
                    description=rule["description"],
                    severity=rule["severity"],
                    affected_entities=sorted(triggered),
                    recommendation=rule["recommendation"],
                )
            )

    # Sort: critical first
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    violations.sort(
        key=lambda v: (severity_order.get(v.severity, 5), v.framework)
    )

    logger.info(
        "Compliance check: %d violations across %d frameworks",
        len(violations),
        len({v.framework for v in violations}),
    )

    return violations
