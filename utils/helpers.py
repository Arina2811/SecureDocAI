"""
Utility helpers for the DLP & Compliance Analysis Platform.

Provides common functions for text processing, masking, file validation,
and audit logging used across multiple services.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import re
from datetime import datetime
from typing import Any

import config

# ─── Logging Setup ─────────────────────────────────────────────────────────────

logging.basicConfig(
    level=getattr(logging, config.LOG_LEVEL, logging.INFO),
    format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger("securedoc")


# ─── Text Helpers ──────────────────────────────────────────────────────────────


def truncate(text: str, max_chars: int = 200) -> str:
    """Return a truncated version of *text* for display/logging."""
    if len(text) <= max_chars:
        return text
    return text[:max_chars] + "…"


def mask_value(value: str, entity_type: str = "") -> str:
    """Mask a sensitive value based on its entity type or format."""
    val_len = len(value)
    if val_len <= 4:
        return "*" * val_len

    type_lower = entity_type.lower()
    
    if "email" in type_lower or "@" in value:
        parts = value.split("@")
        if len(parts) == 2:
            name, domain = parts
            masked_name = name[:2] + "*" * max(len(name)-2, 2)
            return f"{masked_name}@{domain}"
    
    if "phone" in type_lower or "contact" in type_lower:
        # e.g. 9876543210 -> 98******10
        digits = re.sub(r"\D", "", value)
        if len(digits) >= 10:
            return value[:2] + "*" * (len(value)-4) + value[-2:]

    if "pan" in type_lower:
        return value[:2] + "*" * (len(value)-6) + value[-4:]
        
    if "password" in type_lower:
        return value[0] + "*" * (len(value) - 1)
        
    if "api key" in type_lower or "token" in type_lower or "secret" in type_lower:
        # e.g. sk_test_************************
        if value.startswith(("sk_", "pk_", "AKIA")):
            prefix = value[:min(8, val_len//3)]
            return prefix + "*" * (val_len - len(prefix))
        return value[:4] + "*" * (val_len - 4)

    # Default fallback (Aadhaar, Credit Card, etc.)
    # e.g. 234567891234 -> 2345****1234
    # e.g. 4111111111111111 -> 4111********1111
    return value[:4] + "*" * max(val_len - 8, 4) + value[-4:]


def clean_text(text: str) -> str:
    """Normalise whitespace in extracted document text."""
    text = re.sub(r"\r\n", "\n", text)
    text = re.sub(r"[ \t]+", " ", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    return text.strip()


# ─── File Helpers ──────────────────────────────────────────────────────────────


def validate_file_size(file_size_bytes: int) -> bool:
    """Return True if the file size is within the configured limit."""
    return file_size_bytes <= config.MAX_FILE_SIZE_BYTES


def validate_file_extension(filename: str) -> bool:
    """Return True if the file extension is supported."""
    _, ext = os.path.splitext(filename.lower())
    return ext in config.SUPPORTED_EXTENSIONS


def file_hash(content: bytes) -> str:
    """Return the SHA-256 hex digest for file content."""
    return hashlib.sha256(content).hexdigest()


# ─── Chunk Helpers (for RAG) ──────────────────────────────────────────────────


def chunk_text(
    text: str,
    chunk_size: int = config.CHUNK_SIZE,
    overlap: int = config.CHUNK_OVERLAP,
) -> list[str]:
    """Split *text* into overlapping word-based chunks for embedding.

    Parameters
    ----------
    text : str
        Full document text.
    chunk_size : int
        Approximate number of words per chunk.
    overlap : int
        Number of overlapping words between consecutive chunks.

    Returns
    -------
    list[str]
        List of text chunks.
    """
    words = text.split()
    if not words:
        return []

    chunks: list[str] = []
    start = 0
    while start < len(words):
        end = start + chunk_size
        chunks.append(" ".join(words[start:end]))
        start += chunk_size - overlap
    return chunks


# ─── Audit Logger ──────────────────────────────────────────────────────────────


def audit_log(event: str, details: dict[str, Any] | None = None) -> None:
    """Append an audit entry to the structured audit log.

    Parameters
    ----------
    event : str
        Short event name, e.g. ``"file_uploaded"``.
    details : dict, optional
        Additional key-value pairs for the entry.
    """
    entry = {
        "timestamp": datetime.utcnow().isoformat(),
        "event": event,
        **(details or {}),
    }
    logger.info("AUDIT | %s", json.dumps(entry, default=str))


# ─── Formatting Helpers ───────────────────────────────────────────────────────


def severity_emoji(severity: str) -> str:
    """Return a coloured emoji for a severity level."""
    return {
        "Critical": "🔴",
        "High": "🟠",
        "Medium": "🟡",
        "Low": "🟢",
        "Info": "🔵",
    }.get(severity, "⚪")


def risk_color(risk_level: str) -> str:
    """Return a hex colour for a risk level."""
    return {
        "Critical": "#e74c3c",
        "High": "#e67e22",
        "Medium": "#f39c12",
        "Low": "#27ae60",
    }.get(risk_level, "#95a5a6")


def format_file_size(size_bytes: int) -> str:
    """Return a human-readable file size string."""
    for unit in ("B", "KB", "MB", "GB"):
        if size_bytes < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024  # type: ignore[assignment]
    return f"{size_bytes:.1f} TB"
