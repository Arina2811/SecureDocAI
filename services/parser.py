"""
Document parsing service.

Extracts text from uploaded files (PDF, TXT, CSV) with robust error
handling, encoding detection, and structure preservation.
"""

from __future__ import annotations

import io
import logging
from typing import Tuple

import pandas as pd

from utils.helpers import clean_text, validate_file_extension, validate_file_size

logger = logging.getLogger("securedoc.parser")


# ─── Public API ────────────────────────────────────────────────────────────────


def parse_document(
    file_bytes: bytes,
    filename: str,
) -> Tuple[str, str]:
    """Parse uploaded file bytes and return ``(extracted_text, file_type)``.

    Parameters
    ----------
    file_bytes : bytes
        Raw bytes of the uploaded file.
    filename : str
        Original filename (used for extension detection).

    Returns
    -------
    tuple[str, str]
        ``(text, file_type)`` where *file_type* is one of
        ``"pdf"``, ``"txt"``, ``"csv"``.

    Raises
    ------
    ValueError
        If the file is unsupported, too large, or corrupted.
    """
    # Validate extension
    if not validate_file_extension(filename):
        raise ValueError(
            f"Unsupported file format: '{filename}'. "
            f"Supported formats: PDF, TXT, CSV."
        )

    # Validate size
    if not validate_file_size(len(file_bytes)):
        raise ValueError(
            f"File too large ({len(file_bytes) / (1024*1024):.1f} MB). "
            f"Maximum allowed size is configured in settings."
        )

    ext = filename.rsplit(".", 1)[-1].lower()

    try:
        if ext == "pdf":
            text = _parse_pdf(file_bytes)
            return clean_text(text), "pdf"
        elif ext == "txt":
            text = _parse_txt(file_bytes)
            return clean_text(text), "txt"
        elif ext == "csv":
            text = _parse_csv(file_bytes)
            return clean_text(text), "csv"
        else:
            raise ValueError(f"Unsupported extension: .{ext}")
    except ValueError:
        raise
    except Exception as exc:
        logger.exception("Failed to parse '%s'", filename)
        raise ValueError(
            f"Could not parse '{filename}'. The file may be corrupted or "
            f"contain unsupported content. Error: {exc}"
        ) from exc


# ─── Internal Parsers ─────────────────────────────────────────────────────────


def _parse_pdf(file_bytes: bytes) -> str:
    """Extract text from a PDF using pdfplumber, with PyMuPDF and OCR fallbacks."""
    text = ""

    # Primary: pdfplumber (better table/layout handling)
    try:
        import pdfplumber

        with pdfplumber.open(io.BytesIO(file_bytes)) as pdf:
            for page in pdf.pages:
                page_text = page.extract_text()
                if page_text:
                    text += page_text + "\n\n"
        if len(text.strip()) > 50:
            logger.info("PDF parsed successfully via pdfplumber (%d chars)", len(text))
            return text
    except Exception as exc:
        logger.warning("pdfplumber failed, falling back to PyMuPDF: %s", exc)

    # Fallback: PyMuPDF (fitz)
    if len(text.strip()) <= 50:
        try:
            import fitz  # PyMuPDF
            text = "" # reset text
            doc = fitz.open(stream=file_bytes, filetype="pdf")
            for page in doc:
                text += page.get_text() + "\n\n"
            doc.close()
            if len(text.strip()) > 50:
                logger.info("PDF parsed successfully via PyMuPDF (%d chars)", len(text))
                return text
        except Exception as exc:
            logger.warning("PyMuPDF also failed: %s", exc)

    # OCR Fallback for scanned documents
    if len(text.strip()) <= 50:
        logger.info("Minimal text extracted natively, attempting OCR fallback...")
        try:
            import pdf2image
            import pytesseract
            
            images = pdf2image.convert_from_bytes(file_bytes)
            ocr_text = ""
            for img in images:
                ocr_text += pytesseract.image_to_string(img) + "\n\n"
                
            if len(ocr_text.strip()) > len(text.strip()):
                logger.info("OCR successfully extracted %d chars", len(ocr_text))
                return ocr_text
        except ImportError:
            logger.warning("pytesseract or pdf2image not installed, skipping OCR.")
        except Exception as exc:
            logger.warning("OCR failed: %s", exc)

    if not text.strip():
        raise ValueError(
            "Could not extract text from the PDF. "
            "The file may be image-based (scanned) or corrupted."
        )

    return text


def _parse_txt(file_bytes: bytes) -> str:
    """Decode a plain-text file with encoding detection fallback."""
    # Try common encodings
    for encoding in ("utf-8", "utf-8-sig", "latin-1", "cp1252"):
        try:
            return file_bytes.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            continue

    # Last resort: replace errors
    return file_bytes.decode("utf-8", errors="replace")


def _parse_csv(file_bytes: bytes) -> str:
    """Parse a CSV into a readable text representation.

    Preserves column headers and renders each row as a labelled record
    for downstream NLP processing.
    """
    try:
        df = pd.read_csv(io.BytesIO(file_bytes))
    except Exception:
        # Retry with different separator
        try:
            df = pd.read_csv(io.BytesIO(file_bytes), sep=";")
        except Exception as exc:
            raise ValueError(f"Failed to parse CSV: {exc}") from exc

    if df.empty:
        return "(Empty CSV file)"

    lines: list[str] = []
    lines.append(f"CSV File — {len(df)} rows × {len(df.columns)} columns")
    lines.append(f"Columns: {', '.join(df.columns.tolist())}")
    lines.append("")

    # Render rows as readable records (limit to first 500 for performance)
    for idx, row in df.head(500).iterrows():
        record_parts = [f"{col}: {val}" for col, val in row.items()]
        lines.append(f"Row {idx + 1}: {' | '.join(record_parts)}")

    if len(df) > 500:
        lines.append(f"\n... and {len(df) - 500} more rows (truncated).")

    return "\n".join(lines)
