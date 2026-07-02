"""
AI-powered Compliance & Security Report Generator.

Uses Google Gemini to produce a professional compliance report, with
a rule-based fallback when the API is unavailable.
"""

from __future__ import annotations

import logging
import re
from datetime import datetime

import google.genai as genai

import config
from models.schemas import (
    ComplianceReport,
    ComplianceViolation,
    DetectedEntity,
    RiskAssessment,
)
from prompts.templates import COMPLIANCE_REPORT_PROMPT, EXECUTIVE_SUMMARY_PROMPT
from services.compliance import check_compliance
from services.detector import get_entities_summary

logger = logging.getLogger("securedoc.summarizer")


# ─── Public API ────────────────────────────────────────────────────────────────


def generate_report(
    text: str,
    entities: list[DetectedEntity],
    risk: RiskAssessment,
) -> ComplianceReport:
    """Generate a full compliance and security report.

    Attempts an AI-generated report via Gemini; falls back to a
    rule-based report on failure.

    Parameters
    ----------
    text : str
        Extracted document text.
    entities : list[DetectedEntity]
        Detected sensitive entities.
    risk : RiskAssessment
        Computed risk assessment.

    Returns
    -------
    ComplianceReport
    """
    # Rule-based compliance violations (always generated)
    violations = check_compliance(entities)

    # Try AI-generated report
    if config.GEMINI_API_KEY:
        try:
            report = _generate_ai_report(text, entities, risk, violations)
            logger.info("AI-generated compliance report created successfully")
            return report
        except Exception as exc:
            logger.warning("AI report generation failed, using fallback: %s", exc)

    # Fallback
    return _generate_fallback_report(entities, risk, violations)


# ─── AI Report ────────────────────────────────────────────────────────────────


def _generate_ai_report(
    text: str,
    entities: list[DetectedEntity],
    risk: RiskAssessment,
    violations: list[ComplianceViolation],
) -> ComplianceReport:
    """Call Gemini to produce a structured compliance report."""
    client = genai.Client(api_key=config.GEMINI_API_KEY)

    entities_summary = get_entities_summary(entities)

    prompt = COMPLIANCE_REPORT_PROMPT.format(
        document_text=text[:6_000],
        entities_summary=entities_summary,
        risk_level=risk.risk_level,
        security_score=risk.security_score,
        total_entities=risk.total_entities,
    )

    response = client.models.generate_content(
        model=config.GEMINI_MODEL,
        contents=prompt,
        config=genai.types.GenerateContentConfig(
            temperature=config.GEMINI_TEMPERATURE,
            max_output_tokens=config.GEMINI_MAX_TOKENS,
        ),
    )

    raw = response.text.strip()

    # Parse sections from the AI markdown response
    executive_summary = _extract_section(raw, "Executive Summary")
    security_risks_text = _extract_section(raw, "Security Risks")
    business_impact_text = _extract_section(raw, "Business Impact")
    recommendations_text = _extract_section(raw, "Recommended Remediation")

    return ComplianceReport(
        executive_summary=executive_summary or _fallback_summary(entities, risk),
        compliance_violations=violations,
        security_risks=_text_to_list(security_risks_text),
        business_impact=_text_to_list(business_impact_text),
        recommendations=_text_to_list(recommendations_text),
        generated_at=datetime.utcnow(),
    )


# ─── Fallback Report ─────────────────────────────────────────────────────────


def _generate_fallback_report(
    entities: list[DetectedEntity],
    risk: RiskAssessment,
    violations: list[ComplianceViolation],
) -> ComplianceReport:
    """Build a report from rules alone (no AI)."""
    summary = _fallback_summary(entities, risk)

    security_risks: list[str] = []
    if any(e.category == "Authentication Secrets" for e in entities):
        security_risks.append(
            "Exposed credentials detected — these could allow unauthorized access "
            "to systems, APIs, or cloud infrastructure."
        )
    if any(e.category == "Personally Identifiable Information" for e in entities):
        security_risks.append(
            "PII leakage risk — personally identifiable information found in the "
            "document could be used for identity theft or social engineering."
        )
    if any(e.category == "Financial Information" for e in entities):
        security_risks.append(
            "Financial data exposure — credit card numbers, bank accounts, or UPI "
            "IDs could lead to fraudulent transactions."
        )
    if any(e.category == "Business Confidential Information" for e in entities):
        security_risks.append(
            "Business-confidential material — salary data, contracts, or proprietary "
            "information could harm competitive advantage if disclosed."
        )

    business_impact: list[str] = [
        "Legal liability from data protection regulation violations.",
        "Financial penalties under applicable compliance frameworks.",
        "Reputation damage if sensitive data is disclosed publicly.",
    ]

    recommendations: list[str] = [
        "Redact all sensitive PII before sharing or storing the document.",
        "Encrypt documents containing financial or authentication data.",
        "Rotate any exposed API keys, passwords, or access tokens immediately.",
        "Apply role-based access control to restrict document visibility.",
        "Enable audit logging for document access and modifications.",
        "Conduct a full data protection impact assessment.",
    ]

    return ComplianceReport(
        executive_summary=summary,
        compliance_violations=violations,
        security_risks=security_risks,
        business_impact=business_impact,
        recommendations=recommendations,
        generated_at=datetime.utcnow(),
    )


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _fallback_summary(entities: list[DetectedEntity], risk: RiskAssessment) -> str:
    """Generate a brief executive summary without AI."""
    categories = {e.category for e in entities}
    return (
        f"This document contains {len(entities)} sensitive data elements "
        f"spanning {len(categories)} categories. "
        f"The overall risk is classified as **{risk.risk_level}** with a "
        f"security score of **{risk.security_score}/100**. "
        f"Immediate remediation is {'strongly recommended' if risk.security_score < 60 else 'advisable'}."
    )


def _extract_section(markdown: str, heading: str) -> str:
    """Extract content under a Markdown heading (##)."""
    pattern = rf"##\s*{re.escape(heading)}\s*\n(.*?)(?=\n##\s|\Z)"
    match = re.search(pattern, markdown, re.DOTALL)
    return match.group(1).strip() if match else ""


def _text_to_list(text: str) -> list[str]:
    """Convert markdown bullet-point text into a Python list of strings."""
    if not text:
        return []
    lines = text.split("\n")
    items: list[str] = []
    for line in lines:
        cleaned = re.sub(r"^[\s\-\*•]+", "", line).strip()
        if cleaned:
            items.append(cleaned)
    return items
