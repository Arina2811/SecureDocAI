"""
Sensitive Data Detection Engine.

Implements a hybrid detection pipeline that combines:
  1. Regex pattern matching  (high-speed, high-precision for known formats)
  2. spaCy NER              (general named-entity extraction)
  3. LLM reasoning          (contextual / business-confidential detection)

Each detector returns a list of ``DetectedEntity`` objects.
"""

from __future__ import annotations

import json
import logging
import re
from collections import Counter
from typing import Optional

import google.genai as genai

import config
from models.schemas import (
    DetectedEntity,
    DetectionMethod,
    EntityCategory,
    Severity,
)
from prompts.templates import LLM_DETECTION_PROMPT
from utils.helpers import mask_value, truncate
from utils.patterns import SENSITIVE_PATTERNS

logger = logging.getLogger("securedoc.detector")


# ─── Public API ─────────────────────────────────────────────────────────────

def detect_sensitive_data(
    text: str,
    use_ner: bool = True,
    use_llm: bool = True,
) -> list[DetectedEntity]:
    """Run the full detection pipeline on *text* and return all findings.

    Parameters
    ----------
    text : str
        Extracted document text.
    use_ner : bool
        Whether to run spaCy NER (may be slow on large docs).
    use_llm : bool
        Whether to call the LLM for contextual detection.

    Returns
    -------
    list[DetectedEntity]
        Deduplicated, sorted list of detected entities.
    """
    entities: list[DetectedEntity] = []

    # 1. Regex detection
    regex_results = _detect_regex(text)
    entities.extend(regex_results)
    logger.info("Regex detection found %d entities", len(regex_results))

    # 2. spaCy NER detection
    if use_ner:
        try:
            ner_results = _detect_ner(text)
            entities.extend(ner_results)
            logger.info("NER detection found %d entities", len(ner_results))
        except Exception as exc:
            logger.warning("NER detection failed: %s", exc)

    # 3. LLM-assisted detection
    if use_llm and config.GEMINI_API_KEY:
        try:
            llm_results = _detect_llm(text)
            entities.extend(llm_results)
            logger.info("LLM detection found %d entities", len(llm_results))
        except Exception as exc:
            logger.warning("LLM detection failed: %s", exc)

    # Deduplicate
    entities = _deduplicate(entities)
    logger.info("Total unique entities after dedup: %d", len(entities))

    return entities


def get_entities_summary(entities: list[DetectedEntity]) -> str:
    """Build a human-readable summary of detected entities for prompts."""
    if not entities:
        return "No sensitive entities detected."

    counter: Counter = Counter()
    for e in entities:
        counter[e.entity_type] += 1

    lines = [f"- {etype}: {count}" for etype, count in counter.most_common()]
    return "\n".join(lines)


# ─── Regex Detector ────────────────────────────────────────────────────────

def _detect_regex(text: str) -> list[DetectedEntity]:
    """Apply all regex patterns from ``utils.patterns``."""
    results: list[DetectedEntity] = []
    lines = text.split("\n")

    for pat_def in SENSITIVE_PATTERNS:
        pattern: re.Pattern = pat_def["pattern"]
        entity_type: str = pat_def["entity_type"]
        category: EntityCategory = pat_def["category"]
        severity: Severity = pat_def["severity"]
        base_confidence: float = pat_def["confidence"]

        # Skip overly noisy patterns on large docs
        if entity_type == "Bank Account Number" and len(text) > 50_000:
            continue

        for line_num, line in enumerate(lines, start=1):
            for match in pattern.finditer(line):
                value = match.group().strip()

                # Skip very short matches that are likely false positives
                if len(value) < 3:
                    continue

                # Skip phone number false positives (pure short numbers)
                if entity_type == "Phone Number" and len(re.sub(r"\D", "", value)) < 7:
                    continue

                results.append(
                    DetectedEntity(
                        entity_type=entity_type,
                        category=category,
                        value=value,
                        confidence=base_confidence,
                        detection_method=DetectionMethod.REGEX,
                        position=f"Line {line_num}",
                        severity=severity,
                        context=truncate(line, 120),
                    )
                )

    return results


# ─── NER Detector (spaCy) ─────────────────────────────────────────────────────

import streamlit as st

@st.cache_resource
def _get_nlp():
    """Lazy-load the spaCy model with caching. No runtime downloads."""
    try:
        import spacy
        
        try:
            return spacy.load("en_core_web_sm")
        except OSError:
            # Model not available - don't try to download in Streamlit Cloud
            # (read-only environment, permission denied)
            logger.warning(
                "spaCy model 'en_core_web_sm' not found. "
                "Install locally: python -m spacy download en_core_web_sm"
            )
            raise
    except ImportError:
        logger.warning("spaCy not installed — NER detection unavailable")
        raise


# Mapping of spaCy entity labels to our schema
_NER_LABEL_MAP: dict[str, dict] = {
    "PERSON": {
        "entity_type": "Person Name",
        "category": EntityCategory.PII,
        "severity": Severity.MEDIUM,
    },
    "ORG": {
        "entity_type": "Organisation Name",
        "category": EntityCategory.BUSINESS,
        "severity": Severity.LOW,
    },
    "GPE": {
        "entity_type": "Location (GPE)",
        "category": EntityCategory.CONTACT,
        "severity": Severity.LOW,
    },
    "DATE": {
        "entity_type": "Date",
        "category": EntityCategory.PII,
        "severity": Severity.INFO,
    },
    "MONEY": {
        "entity_type": "Monetary Value",
        "category": EntityCategory.FINANCIAL,
        "severity": Severity.MEDIUM,
    },
    "CARDINAL": {
        "entity_type": "Numeric Value",
        "category": EntityCategory.PII,
        "severity": Severity.INFO,
    },
}


def _detect_ner(text: str) -> list[DetectedEntity]:
    """Run spaCy NER and map recognized entities."""
    nlp = _get_nlp()

    # Process in chunks to avoid memory issues with large docs
    max_chars = 100_000
    doc_text = text[:max_chars]
    doc = nlp(doc_text)

    results: list[DetectedEntity] = []
    for ent in doc.ents:
        mapping = _NER_LABEL_MAP.get(ent.label_)
        if mapping is None:
            continue

        value = ent.text.strip()
        if len(value) < 2:
            continue

        # Skip very generic single-word entities
        if ent.label_ in ("CARDINAL", "DATE") and len(value) < 4:
            continue

        results.append(
            DetectedEntity(
                entity_type=mapping["entity_type"],
                category=mapping["category"],
                value=value,
                confidence=config.NER_CONFIDENCE,
                detection_method=DetectionMethod.NER,
                position=f"Char {ent.start_char}–{ent.end_char}",
                severity=mapping["severity"],
                context=truncate(text[max(0, ent.start_char - 30):ent.end_char + 30], 120),
            )
        )

    return results


# ─── LLM Detector (Gemini) ───────────────────────────────────────────────────

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def _detect_llm(text: str) -> list[DetectedEntity]:
    """Use Gemini to find contextual / business-confidential entities."""
    genai.configure(api_key=config.GEMINI_API_KEY)
    model = genai.Client().models.generate_content_stream

    # Truncate for the prompt (Gemini has token limits)
    truncated = text[:8_000]
    prompt = LLM_DETECTION_PROMPT.format(document_text=truncated)

    try:
        # Use the new google-genai SDK
        client = genai.Client(api_key=config.GEMINI_API_KEY)
        response = client.models.generate_content(
            model=config.GEMINI_MODEL,
            contents=prompt,
            config=genai.types.GenerateContentConfig(
                temperature=0.2,
                max_output_tokens=2048,
            ),
        )
        raw = response.text.strip()

        # Strip markdown code fences if present
        if raw.startswith("```"):
            raw = re.sub(r"^```(?:json)?\s*", "", raw)
            raw = re.sub(r"\s*```$", "", raw)

        items = json.loads(raw)
        if not isinstance(items, list):
            return []

    except Exception as exc:
        logger.warning("LLM detection response parsing failed: %s", exc)
        return []

    results: list[DetectedEntity] = []
    for item in items:
        try:
            sev_str = str(item.get("severity", "Medium")).lower()
            results.append(
                DetectedEntity(
                    entity_type=str(item.get("entity_type", "Unknown")),
                    category=EntityCategory.BUSINESS,
                    value=str(item.get("value", "")),
                    confidence=float(item.get("confidence", config.LLM_CONFIDENCE)),
                    detection_method=DetectionMethod.LLM,
                    position=None,
                    severity=_SEVERITY_MAP.get(sev_str, Severity.MEDIUM),
                    context=str(item.get("reason", "")),
                )
            )
        except Exception:
            continue

    return results


# ─── Deduplication ────────────────────────────────────────────────────────

def _deduplicate(entities: list[DetectedEntity]) -> list[DetectedEntity]:
    """Remove duplicate entities (same type + same value)."""
    seen: set[tuple[str, str]] = set()
    unique: list[DetectedEntity] = []

    for e in entities:
        key = (e.entity_type, e.value)
        if key not in seen:
            seen.add(key)
            unique.append(e)

    # Sort: critical first, then by type
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
    unique.sort(key=lambda x: (severity_order.get(x.severity, 5), x.entity_type))

    return unique
