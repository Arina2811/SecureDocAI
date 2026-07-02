"""
Unit tests for the risk assessment engine.
"""

import pytest
from models.schemas import DetectedEntity, EntityCategory, DetectionMethod, Severity
from services.classifier import assess_risk


def _make_entity(
    entity_type: str = "Email Address",
    category: str = "Contact Information",
    severity: str = "Medium",
    value: str = "test@example.com",
) -> DetectedEntity:
    """Helper to create a DetectedEntity for testing."""
    return DetectedEntity(
        entity_type=entity_type,
        category=category,
        value=value,
        confidence=0.9,
        detection_method="Regex",
        severity=severity,
    )


class TestRiskAssessment:
    """Tests for the assess_risk() function."""

    def test_no_entities_low_risk(self):
        """An empty entity list returns Low risk and score 100."""
        result = assess_risk([])
        assert result.risk_level == "Low"
        assert result.security_score == 100

    def test_single_low_entity(self):
        """A single low-severity entity keeps risk low."""
        entities = [_make_entity(severity="Low")]
        result = assess_risk(entities)
        assert result.security_score >= 80
        assert result.risk_level == "Low"

    def test_critical_entities_high_risk(self):
        """Multiple critical entities produce High or Critical risk."""
        entities = [
            _make_entity("Password", "Authentication Secrets", "Critical", "pass123"),
            _make_entity("API Key", "Authentication Secrets", "Critical", "sk_key123456789012"),
            _make_entity("AWS Access Key", "Authentication Secrets", "Critical", "AKIA1234567890"),
            _make_entity("JWT Token", "Authentication Secrets", "Critical", "eyJabc.eyJdef.ghi"),
        ]
        result = assess_risk(entities)
        assert result.security_score < 60
        assert result.risk_level in ("High", "Critical")

    def test_mixed_severity(self):
        """Mixed-severity entities produce a moderate risk."""
        entities = [
            _make_entity("Email Address", "Contact Information", "Medium"),
            _make_entity("Person Name", "Personally Identifiable Information", "Medium"),
            _make_entity("Password", "Authentication Secrets", "Critical", "pass"),
        ]
        result = assess_risk(entities)
        assert 0 <= result.security_score <= 100
        assert result.total_entities == 3

    def test_risk_factors_generated(self):
        """Risk factors are generated for critical entities."""
        entities = [
            _make_entity("Password", "Authentication Secrets", "Critical", "pass"),
        ]
        result = assess_risk(entities)
        assert len(result.risk_factors) > 0

    def test_severity_counts(self):
        """Severity counts are tallied correctly."""
        entities = [
            _make_entity(severity="Critical"),
            _make_entity(severity="Critical", value="a"),
            _make_entity(severity="High", value="b"),
            _make_entity(severity="Medium", value="c"),
            _make_entity(severity="Low", value="d"),
        ]
        result = assess_risk(entities)
        assert result.critical_count == 2
        assert result.high_count == 1
        assert result.medium_count == 1
        assert result.low_count == 1
