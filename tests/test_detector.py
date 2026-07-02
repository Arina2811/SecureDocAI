"""
Unit tests for the sensitive data detection engine.
"""

import pytest
from services.detector import detect_sensitive_data


class TestRegexDetection:
    """Tests for regex-based entity detection."""

    def test_detect_email(self):
        """Email addresses are detected."""
        text = "Contact us at john.doe@example.com for details."
        entities = detect_sensitive_data(text, use_ner=False, use_llm=False)
        emails = [e for e in entities if e.entity_type == "Email Address"]
        assert len(emails) >= 1
        assert "john.doe@example.com" in emails[0].value

    def test_detect_pan(self):
        """Indian PAN numbers are detected."""
        text = "PAN: ABCDE1234F is registered."
        entities = detect_sensitive_data(text, use_ner=False, use_llm=False)
        pans = [e for e in entities if e.entity_type == "PAN Number"]
        assert len(pans) >= 1

    def test_detect_aadhaar(self):
        """Aadhaar numbers are detected."""
        text = "Aadhaar: 2345 6789 0123"
        entities = detect_sensitive_data(text, use_ner=False, use_llm=False)
        aadhaar = [e for e in entities if e.entity_type == "Aadhaar Number"]
        assert len(aadhaar) >= 1

    def test_detect_api_key(self):
        """API keys are detected."""
        text = "api_key = sk_test_abcdefghij1234567890"
        entities = detect_sensitive_data(text, use_ner=False, use_llm=False)
        keys = [e for e in entities if e.entity_type == "API Key"]
        assert len(keys) >= 1

    def test_detect_password(self):
        """Password patterns are detected."""
        text = "password: SuperSecret123!"
        entities = detect_sensitive_data(text, use_ner=False, use_llm=False)
        passwords = [e for e in entities if e.entity_type == "Password"]
        assert len(passwords) >= 1

    def test_detect_jwt(self):
        """JWT tokens are detected."""
        text = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc123def456"
        entities = detect_sensitive_data(text, use_ner=False, use_llm=False)
        jwts = [e for e in entities if e.entity_type == "JWT Token"]
        assert len(jwts) >= 1

    def test_detect_aws_key(self):
        """AWS access keys are detected."""
        text = "AKIAIOSFODNN7EXAMPLE"
        entities = detect_sensitive_data(text, use_ner=False, use_llm=False)
        aws = [e for e in entities if e.entity_type == "AWS Access Key"]
        assert len(aws) >= 1

    def test_detect_ifsc(self):
        """IFSC codes are detected."""
        text = "IFSC: SBIN0001234"
        entities = detect_sensitive_data(text, use_ner=False, use_llm=False)
        ifsc = [e for e in entities if e.entity_type == "IFSC Code"]
        assert len(ifsc) >= 1

    def test_detect_confidentiality_marker(self):
        """Confidentiality markers are detected."""
        text = "This document is CONFIDENTIAL and should not be shared."
        entities = detect_sensitive_data(text, use_ner=False, use_llm=False)
        markers = [e for e in entities if e.entity_type == "Confidentiality Marker"]
        assert len(markers) >= 1

    def test_detect_salary(self):
        """Salary information is detected."""
        text = "Annual salary: INR 12,00,000"
        entities = detect_sensitive_data(text, use_ner=False, use_llm=False)
        salary = [e for e in entities if e.entity_type == "Salary Information"]
        assert len(salary) >= 1

    def test_no_false_positives_clean_text(self):
        """Clean text without sensitive data produces few/no critical entities."""
        text = "The weather today is sunny with clear skies."
        entities = detect_sensitive_data(text, use_ner=False, use_llm=False)
        critical = [e for e in entities if e.severity == "Critical"]
        assert len(critical) == 0

    def test_deduplication(self):
        """Duplicate entities are removed."""
        text = "Email: test@example.com\nAlso contact test@example.com"
        entities = detect_sensitive_data(text, use_ner=False, use_llm=False)
        emails = [e for e in entities if e.entity_type == "Email Address"]
        assert len(emails) == 1
