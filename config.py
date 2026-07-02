"""
Configuration module for the DLP & Compliance Analysis Platform.

Manages environment variables, model settings, file constraints,
risk thresholds, and application-wide constants.
"""

import os
# pyrefly: ignore [missing-import]
from dotenv import load_dotenv

# Load environment variables from .env file (override=True ensures .env takes priority)
load_dotenv(override=True)


def _get_config(key: str, default: str = "") -> str:
    """Retrieve config from environment variable or fallback to streamlit secrets."""
    val = os.getenv(key)
    if val is not None and val.strip() != "":
        return val
    try:
        import streamlit as st
        if key in st.secrets:
            val = str(st.secrets[key])
            if val.strip() != "":
                return val
    except Exception:
        pass
    return default


# ─── AI / LLM Configuration ────────────────────────────────────────────────────

GEMINI_API_KEY: str = _get_config("GEMINI_API_KEY", "")
GEMINI_MODEL: str = _get_config("GEMINI_MODEL", "gemini-2.0-flash")
GEMINI_TEMPERATURE: float = float(_get_config("GEMINI_TEMPERATURE", "0.3"))
GEMINI_MAX_TOKENS: int = int(_get_config("GEMINI_MAX_TOKENS", "4096"))

# OpenAI fallback for Q&A
OPENAI_API_KEY: str = _get_config("OPENAI_API_KEY", "")
OPENAI_MODEL: str = _get_config("OPENAI_MODEL", "gpt-4o-mini")

# ─── File Upload Constraints ───────────────────────────────────────────────────

MAX_FILE_SIZE_MB: int = int(_get_config("MAX_FILE_SIZE_MB", "50"))
MAX_FILE_SIZE_BYTES: int = MAX_FILE_SIZE_MB * 1024 * 1024
SUPPORTED_EXTENSIONS: list[str] = [".pdf", ".txt", ".csv"]

# ─── Sensitive Data Detection ──────────────────────────────────────────────────

# Confidence thresholds for detection methods
REGEX_CONFIDENCE: float = 0.95
NER_CONFIDENCE: float = 0.80
LLM_CONFIDENCE: float = 0.75

# ─── Risk Assessment Thresholds ────────────────────────────────────────────────

RISK_THRESHOLDS: dict[str, int] = {
    "low": 20,       # Security score >= 80
    "medium": 40,    # Security score >= 60
    "high": 60,      # Security score >= 40
    "critical": 80,  # Security score < 40
}

# Severity weights for risk scoring
SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 10.0,
    "high": 6.0,
    "medium": 3.0,
    "low": 1.0,
    "info": 0.5,
}

# Category risk multipliers
CATEGORY_MULTIPLIERS: dict[str, float] = {
    "authentication_secrets": 3.0,
    "financial_information": 2.5,
    "government_identifiers": 2.0,
    "personally_identifiable_information": 1.5,
    "contact_information": 1.0,
    "business_confidential": 2.0,
}

# ─── RAG Configuration ────────────────────────────────────────────────────────

CHUNK_SIZE: int = int(_get_config("CHUNK_SIZE", "512"))
CHUNK_OVERLAP: int = int(_get_config("CHUNK_OVERLAP", "64"))
TOP_K_RESULTS: int = int(_get_config("TOP_K_RESULTS", "5"))
EMBEDDING_MODEL: str = _get_config("EMBEDDING_MODEL", "all-MiniLM-L6-v2")

# ─── Compliance Frameworks ────────────────────────────────────────────────────

COMPLIANCE_FRAMEWORKS: list[str] = [
    "GDPR",
    "HIPAA",
    "PCI DSS",
    "ISO 27001",
    "SOC 2",
    "DPDP Act (India)",
]

# ─── Application Settings ─────────────────────────────────────────────────────

APP_TITLE: str = "SecureDoc AI — DLP & Compliance Platform"
APP_ICON: str = "🛡️"
APP_VERSION: str = "1.0.0"
LOG_LEVEL: str = _get_config("LOG_LEVEL", "INFO")
