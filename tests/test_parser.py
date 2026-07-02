"""
Unit tests for the document parsing service.
"""

import pytest
from services.parser import parse_document


class TestParseDocument:
    """Tests for the parse_document() dispatcher."""

    def test_parse_txt_basic(self):
        """Plain UTF-8 text is extracted correctly."""
        content = b"Hello, world!\nLine two."
        text, ftype = parse_document(content, "sample.txt")
        assert ftype == "txt"
        assert "Hello, world!" in text
        assert "Line two" in text

    def test_parse_txt_utf8_bom(self):
        """UTF-8 BOM is handled."""
        content = b"\xef\xbb\xbfBOM text"
        text, ftype = parse_document(content, "bom.txt")
        assert "BOM text" in text

    def test_parse_csv_basic(self):
        """CSV files are parsed into readable text."""
        csv_bytes = b"Name,Email,Phone\nAlice,alice@test.com,9876543210\n"
        text, ftype = parse_document(csv_bytes, "data.csv")
        assert ftype == "csv"
        assert "alice@test.com" in text
        assert "Name" in text

    def test_unsupported_extension(self):
        """Unsupported file extensions raise ValueError."""
        with pytest.raises(ValueError, match="Unsupported"):
            parse_document(b"data", "file.docx")

    def test_empty_txt(self):
        """Empty text files produce empty string."""
        text, ftype = parse_document(b"", "empty.txt")
        assert ftype == "txt"
        assert text == ""

    def test_csv_with_semicolons(self):
        """CSV with semicolon separator is handled."""
        csv_bytes = b"A;B;C\n1;2;3\n"
        text, ftype = parse_document(csv_bytes, "semi.csv")
        assert ftype == "csv"


class TestFileSizeValidation:
    """Tests for file size limits."""

    def test_large_file_rejected(self):
        """Files exceeding MAX_FILE_SIZE_BYTES are rejected."""
        import config
        huge = b"x" * (config.MAX_FILE_SIZE_BYTES + 1)
        with pytest.raises(ValueError, match="too large"):
            parse_document(huge, "big.txt")
