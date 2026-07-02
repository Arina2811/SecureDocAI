"""
Risk Assessment Engine.

Analyses detected entities and classifies the overall document risk as
Low / Medium / High / Critical with a numeric security score (0–100).
"""

from __future__ import annotations

import logging
from collections import Counter

import config
from models.schemas import DetectedEntity, RiskAssessment, RiskLevel

logger = logging.getLogger("securedoc.classifier")


# ─── Public API ────────────────────────────────────────────────────────────────


def assess_risk(entities: list[DetectedEntity]) -> RiskAssessment:
    """Compute a risk assessment for the given set of detected entities.

    The algorithm uses a **weighted penalty model**:
      1. Each entity contributes a penalty based on its severity weight.
      2. Category multipliers amplify penalties for high-impact categories
         (e.g., exposed credentials are weighted 3×).
      3. Density bonus: more unique entity *types* increase the penalty.
      4. The raw penalty is converted to a 0–100 security score
         (100 = perfectly safe, 0 = maximum risk).
      5. The security score maps to a risk level.

    Parameters
    ----------
    entities : list[DetectedEntity]
        Entities detected in the document.

    Returns
    -------
    RiskAssessment
        Complete risk assessment with score, level, and factors.
    """
    if not entities:
        return RiskAssessment(
            risk_level=RiskLevel.LOW,
            security_score=100,
            total_entities=0,
            summary="No sensitive entities detected. Document appears safe.",
        )

    # ── Count by severity ─────────────────────────────────────────────────
    sev_counter: Counter = Counter()
    for e in entities:
        sev_counter[e.severity] += 1

    critical_count = sev_counter.get("Critical", 0)
    high_count = sev_counter.get("High", 0)
    medium_count = sev_counter.get("Medium", 0)
    low_count = sev_counter.get("Low", 0)
    info_count = sev_counter.get("Info", 0)

    # ── Weighted penalty ──────────────────────────────────────────────────
    raw_penalty = 0.0
    for e in entities:
        sev_weight = config.SEVERITY_WEIGHTS.get(e.severity.lower() if isinstance(e.severity, str) else e.severity, 1.0)

        # Map category string to config key
        cat_key = _category_key(e.category)
        cat_mult = config.CATEGORY_MULTIPLIERS.get(cat_key, 1.0)

        raw_penalty += sev_weight * cat_mult

    # Density bonus: unique entity types present
    unique_types = len({e.entity_type for e in entities})
    raw_penalty += unique_types * 1.5

    # ── Security score ────────────────────────────────────────────────────
    # Logistic-like mapping: penalty → score
    max_penalty = 300.0  # approximate ceiling for normalization
    normalized = min(raw_penalty / max_penalty, 1.0)
    security_score = max(0, int(100 * (1 - normalized)))

    # ── Risk level ────────────────────────────────────────────────────────
    risk_level = _score_to_risk_level(security_score)

    # ── Risk factors ──────────────────────────────────────────────────────
    risk_factors = _build_risk_factors(entities, critical_count, high_count)

    # ── Summary ───────────────────────────────────────────────────────────
    summary = (
        f"Detected {len(entities)} sensitive entities "
        f"({critical_count} critical, {high_count} high, {medium_count} medium). "
        f"Security score: {security_score}/100. "
        f"Risk level: {risk_level}."
    )

    return RiskAssessment(
        risk_level=risk_level,
        security_score=security_score,
        total_entities=len(entities),
        critical_count=critical_count,
        high_count=high_count,
        medium_count=medium_count,
        low_count=low_count,
        info_count=info_count,
        risk_factors=risk_factors,
        summary=summary,
    )


# ─── Helpers ──────────────────────────────────────────────────────────────────


def _category_key(category: str) -> str:
    """Convert a display-friendly category name to a config key."""
    mapping = {
        "Personally Identifiable Information": "personally_identifiable_information",
        "Contact Information": "contact_information",
        "Financial Information": "financial_information",
        "Authentication Secrets": "authentication_secrets",
        "Business Confidential Information": "business_confidential",
    }
    return mapping.get(category, "contact_information")


def _score_to_risk_level(score: int) -> RiskLevel:
    """Map a 0–100 security score to a risk level."""
    if score >= 80:
        return RiskLevel.LOW
    elif score >= 60:
        return RiskLevel.MEDIUM
    elif score >= 40:
        return RiskLevel.HIGH
    else:
        return RiskLevel.CRITICAL


def _build_risk_factors(
    entities: list[DetectedEntity],
    critical_count: int,
    high_count: int,
) -> list[str]:
    """Generate a list of human-readable risk factors."""
    factors: list[str] = []

    categories_present = {e.category for e in entities}
    types_present = {e.entity_type for e in entities}

    if critical_count > 0:
        factors.append(
            f"{critical_count} critical-severity entities detected"
        )

    if "Authentication Secrets" in categories_present:
        factors.append("Exposed authentication secrets or credentials")

    if any(t in types_present for t in ("Credit/Debit Card Number", "Bank Account Number", "UPI ID")):
        factors.append("Financial account information detected")

    if any(t in types_present for t in ("Aadhaar Number", "PAN Number", "Passport Number", "SSN")):
        factors.append("Government-issued identifiers found")

    if "Personally Identifiable Information" in categories_present:
        factors.append("Personally identifiable information (PII) present")

    if any(t in types_present for t in ("Salary Information", "Confidentiality Marker", "Contract Reference")):
        factors.append("Business-confidential information detected")

    if high_count > 5:
        factors.append(f"High density of sensitive data ({high_count} high-severity items)")

    if len(types_present) > 10:
        factors.append(f"Wide variety of sensitive data types ({len(types_present)} distinct types)")

    return factors
