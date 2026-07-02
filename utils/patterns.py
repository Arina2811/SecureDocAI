"""
Regex patterns for sensitive data detection.

Each pattern is a dict with:
  - pattern:    compiled regex
  - entity_type: human-readable label
  - category:   EntityCategory value
  - severity:   Severity value
  - confidence: base confidence for a regex match
"""

from __future__ import annotations

import re
from models.schemas import EntityCategory, Severity

# ─── Helper ────────────────────────────────────────────────────────────────────

def _compile(pattern: str, flags: int = 0) -> re.Pattern:
    """Compile a regex pattern with optional flags."""
    return re.compile(pattern, flags)


# ─── Pattern Definitions ──────────────────────────────────────────────────────

SENSITIVE_PATTERNS: list[dict] = [
    # ── PII / Government Identifiers ──────────────────────────────────────
    {
        "pattern": _compile(r"\b[2-9]\d{3}\s?\d{4}\s?\d{4}\b"),
        "entity_type": "Aadhaar Number",
        "category": EntityCategory.PII,
        "severity": Severity.HIGH,
        "confidence": 0.90,
    },
    {
        "pattern": _compile(r"\b[A-Z]{5}\d{4}[A-Z]\b"),
        "entity_type": "PAN Number",
        "category": EntityCategory.PII,
        "severity": Severity.HIGH,
        "confidence": 0.95,
    },
    {
        "pattern": _compile(r"\b[A-Z][1-9]\d{6}[A-Z]?\b"),
        "entity_type": "Passport Number",
        "category": EntityCategory.PII,
        "severity": Severity.HIGH,
        "confidence": 0.85,
    },
    {
        "pattern": _compile(
            r"\b(?:DL|dl)[- ]?\d{2}[- ]?\d{2}[- ]?\d{4}[- ]?\d{7}\b"
        ),
        "entity_type": "Driving License Number",
        "category": EntityCategory.PII,
        "severity": Severity.HIGH,
        "confidence": 0.85,
    },
    {
        "pattern": _compile(r"(?i)\b(?:EMP|EMPLOYEE|EMP\s*ID)[-_\s]?\d{4,8}\b"),
        "entity_type": "Employee ID",
        "category": EntityCategory.PII,
        "severity": Severity.MEDIUM,
        "confidence": 0.85,
    },
    {
        "pattern": _compile(r"(?i)\b(?:CUST|CUSTOMER|CUS)[-_\s]?\d{4,10}\b"),
        "entity_type": "Customer ID",
        "category": EntityCategory.PII,
        "severity": Severity.MEDIUM,
        "confidence": 0.80,
    },
    {
        "pattern": _compile(
            r"\b\d{3}[- ]?\d{2}[- ]?\d{4}\b"
        ),
        "entity_type": "SSN",
        "category": EntityCategory.PII,
        "severity": Severity.CRITICAL,
        "confidence": 0.80,
    },

    # ── Contact Information ───────────────────────────────────────────────
    {
        "pattern": _compile(
            r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b"
        ),
        "entity_type": "Email Address",
        "category": EntityCategory.CONTACT,
        "severity": Severity.MEDIUM,
        "confidence": 0.95,
    },
    {
        "pattern": _compile(
            r"(?:\+91[\s\-]?)?(?:\(?\d{2,5}\)?[\s\-]?)?\d{5,10}\b"
        ),
        "entity_type": "Phone Number",
        "category": EntityCategory.CONTACT,
        "severity": Severity.MEDIUM,
        "confidence": 0.70,
    },
    {
        "pattern": _compile(
            r"\b\d{1,5}\s[\w\s]{2,30}(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Drive|Dr|Lane|Ln|Court|Ct|Way|Place|Pl)\b",
            re.IGNORECASE,
        ),
        "entity_type": "Physical Address",
        "category": EntityCategory.CONTACT,
        "severity": Severity.MEDIUM,
        "confidence": 0.75,
    },

    # ── Financial Information ─────────────────────────────────────────────
    {
        "pattern": _compile(r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b"),
        "entity_type": "Credit/Debit Card Number",
        "category": EntityCategory.FINANCIAL,
        "severity": Severity.CRITICAL,
        "confidence": 0.92,
    },
    {
        "pattern": _compile(r"(?i)\b(?:account\s*no|a/c|acct|account\s*number)[\s\.:-]*\d{9,18}\b"),
        "entity_type": "Bank Account Number",
        "category": EntityCategory.FINANCIAL,
        "severity": Severity.HIGH,
        "confidence": 0.90,
    },
    {
        "pattern": _compile(r"\b\d{9,18}\b"),
        "entity_type": "Bank Account Number",
        "category": EntityCategory.FINANCIAL,
        "severity": Severity.HIGH,
        "confidence": 0.55,  # low confidence — needs context
    },
    {
        "pattern": _compile(r"\b[A-Z]{4}0[A-Z0-9]{6}\b"),
        "entity_type": "IFSC Code",
        "category": EntityCategory.FINANCIAL,
        "severity": Severity.MEDIUM,
        "confidence": 0.93,
    },
    {
        "pattern": _compile(
            r"\b[\w.\-]+@(?:ybl|okhdfcbank|okicici|oksbi|paytm|upi|apl|axisbank|ibl|sbi|hdfcbank|icici)\b",
            re.IGNORECASE,
        ),
        "entity_type": "UPI ID",
        "category": EntityCategory.FINANCIAL,
        "severity": Severity.HIGH,
        "confidence": 0.92,
    },

    # ── Authentication Secrets ────────────────────────────────────────────
    {
        "pattern": _compile(
            r"(?i)(?:password|passwd|pwd)\s*[:=]\s*\S+",
        ),
        "entity_type": "Password",
        "category": EntityCategory.AUTH_SECRETS,
        "severity": Severity.CRITICAL,
        "confidence": 0.90,
    },
    {
        "pattern": _compile(
            r"(?i)(?:api[_\-]?key|apikey)\s*[:=]\s*[A-Za-z0-9_\-]{16,}",
        ),
        "entity_type": "API Key",
        "category": EntityCategory.AUTH_SECRETS,
        "severity": Severity.CRITICAL,
        "confidence": 0.92,
    },
    {
        "pattern": _compile(
            r"(?i)(?:bearer|token)\s+[A-Za-z0-9_\-\.]{20,}",
        ),
        "entity_type": "OAuth/Bearer Token",
        "category": EntityCategory.AUTH_SECRETS,
        "severity": Severity.CRITICAL,
        "confidence": 0.90,
    },
    {
        "pattern": _compile(
            r"\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b",
        ),
        "entity_type": "JWT Token",
        "category": EntityCategory.AUTH_SECRETS,
        "severity": Severity.CRITICAL,
        "confidence": 0.97,
    },
    {
        "pattern": _compile(
            r"-----BEGIN (?:RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----",
        ),
        "entity_type": "SSH/Private Key",
        "category": EntityCategory.AUTH_SECRETS,
        "severity": Severity.CRITICAL,
        "confidence": 0.99,
    },
    {
        "pattern": _compile(
            r"(?i)AKIA[0-9A-Z]{16}",
        ),
        "entity_type": "AWS Access Key",
        "category": EntityCategory.AUTH_SECRETS,
        "severity": Severity.CRITICAL,
        "confidence": 0.97,
    },
    {
        "pattern": _compile(
            r"(?i)(?:azure[_\-]?(?:client|tenant|subscription)[_\-]?(?:id|secret|key))\s*[:=]\s*[A-Za-z0-9_\-]{8,}",
        ),
        "entity_type": "Azure Key",
        "category": EntityCategory.AUTH_SECRETS,
        "severity": Severity.CRITICAL,
        "confidence": 0.90,
    },
    {
        "pattern": _compile(
            r'(?i)(?:google[_\-]?(?:cloud|api)[_\-]?(?:key|credentials|secret))\s*[:=]\s*["\']?[A-Za-z0-9_\-]{20,}',
        ),
        "entity_type": "Google Cloud Credential",
        "category": EntityCategory.AUTH_SECRETS,
        "severity": Severity.CRITICAL,
        "confidence": 0.90,
    },
    {
        "pattern": _compile(
            r"(?i)(?:secret[_\-]?key|client[_\-]?secret|private[_\-]?key)\s*[:=]\s*[A-Za-z0-9_\-]{16,}",
        ),
        "entity_type": "Secret Key",
        "category": EntityCategory.AUTH_SECRETS,
        "severity": Severity.CRITICAL,
        "confidence": 0.88,
    },

    # ── Business Confidential ─────────────────────────────────────────────
    {
        "pattern": _compile(
            r"(?i)\b(?:confidential|internal\s+only|proprietary|trade\s+secret|classified|restricted|do\s+not\s+distribute)\b",
        ),
        "entity_type": "Confidentiality Marker",
        "category": EntityCategory.BUSINESS,
        "severity": Severity.HIGH,
        "confidence": 0.85,
    },
    {
        "pattern": _compile(
            r"(?i)(?:salary|compensation|ctc|pay\s*(?:roll|scale|grade))\s*[:=]?\s*(?:(?:INR|USD|Rs\.?|\$|₹)\s*)?\d[\d,\.]+",
        ),
        "entity_type": "Salary Information",
        "category": EntityCategory.BUSINESS,
        "severity": Severity.HIGH,
        "confidence": 0.88,
    },
    {
        "pattern": _compile(
            r"(?i)(?:contract|agreement|nda|non[- ]disclosure)\s*(?:#|number|no\.?)\s*[:=]?\s*\w+",
        ),
        "entity_type": "Contract Reference",
        "category": EntityCategory.BUSINESS,
        "severity": Severity.MEDIUM,
        "confidence": 0.80,
    },
]

# ─── Quick-access entity types ────────────────────────────────────────────────

ALL_ENTITY_TYPES: list[str] = sorted(
    {p["entity_type"] for p in SENSITIVE_PATTERNS}
)
