"""
Data models and schemas for the DLP & Compliance Analysis Platform.

Defines Pydantic models for detected entities, risk assessments,
compliance reports, and document analysis results using strict typing.
"""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Optional

from pydantic import BaseModel, Field


# ─── Enumerations ──────────────────────────────────────────────────────────────


class RiskLevel(str, enum.Enum):
    """Overall document risk classification."""
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class Severity(str, enum.Enum):
    """Severity of a detected sensitive entity."""
    INFO = "Info"
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"


class EntityCategory(str, enum.Enum):
    """Top-level category for sensitive entities."""
    PII = "Personally Identifiable Information"
    CONTACT = "Contact Information"
    FINANCIAL = "Financial Information"
    AUTH_SECRETS = "Authentication Secrets"
    BUSINESS = "Business Confidential Information"


class DetectionMethod(str, enum.Enum):
    """How the entity was detected."""
    REGEX = "Regex"
    NER = "NER"
    LLM = "LLM"
    HYBRID = "Hybrid"


# ─── Detected Entity ──────────────────────────────────────────────────────────


class DetectedEntity(BaseModel):
    """A single piece of sensitive information found in a document."""
    entity_type: str = Field(..., description="Specific type, e.g. 'Aadhaar Number'")
    category: EntityCategory
    value: str = Field(..., description="The extracted sensitive value")
    confidence: float = Field(..., ge=0.0, le=1.0)
    detection_method: DetectionMethod
    position: Optional[str] = Field(None, description="Location in document, e.g. 'Line 42'")
    severity: Severity
    context: Optional[str] = Field(None, description="Surrounding text snippet for context")

    class Config:
        use_enum_values = True


# ─── Risk Assessment ──────────────────────────────────────────────────────────


class RiskAssessment(BaseModel):
    """Overall risk classification for the analysed document."""
    risk_level: RiskLevel
    security_score: int = Field(..., ge=0, le=100)
    total_entities: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    info_count: int = 0
    risk_factors: list[str] = Field(default_factory=list)
    summary: str = ""

    class Config:
        use_enum_values = True


# ─── Compliance Violation ─────────────────────────────────────────────────────


class ComplianceViolation(BaseModel):
    """A single compliance-framework violation."""
    framework: str = Field(..., description="e.g. GDPR, HIPAA")
    violation: str
    description: str
    severity: Severity
    affected_entities: list[str] = Field(default_factory=list)
    recommendation: str = ""

    class Config:
        use_enum_values = True


# ─── Compliance Report ────────────────────────────────────────────────────────


class ComplianceReport(BaseModel):
    """Full AI-generated compliance and security report."""
    executive_summary: str = ""
    compliance_violations: list[ComplianceViolation] = Field(default_factory=list)
    security_risks: list[str] = Field(default_factory=list)
    business_impact: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    generated_at: datetime = Field(default_factory=datetime.utcnow)


# ─── Document Analysis (top-level result) ─────────────────────────────────────


class DocumentAnalysis(BaseModel):
    """Complete analysis result for a single uploaded document."""
    filename: str
    file_type: str
    file_size_bytes: int = 0
    text_length: int = 0
    extracted_text: str = ""
    entities: list[DetectedEntity] = Field(default_factory=list)
    risk_assessment: Optional[RiskAssessment] = None
    compliance_report: Optional[ComplianceReport] = None
    analysed_at: datetime = Field(default_factory=datetime.utcnow)

    class Config:
        use_enum_values = True


# ─── Chat / Q&A Models ────────────────────────────────────────────────────────


class ChatMessage(BaseModel):
    """A single message in the Q&A conversation."""
    role: str = Field(..., description="'user' or 'assistant'")
    content: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
