"""
Retrieval-Augmented Generation (RAG) service.

Chunks the document, builds an in-memory FAISS vector index,
retrieves relevant passages for a user query, and calls Gemini
for a context-augmented answer.
"""

from __future__ import annotations

import logging
from typing import Optional

import numpy as np
import google.genai as genai

import config
from models.schemas import DetectedEntity, RiskAssessment
from prompts.templates import GENERAL_QA_PROMPT, RAG_QA_PROMPT
from services.detector import get_entities_summary
from utils.helpers import chunk_text

logger = logging.getLogger("securedoc.rag")


# ─── Vector Store ─────────────────────────────────────────────────────────────


class DocumentVectorStore:
    """Lightweight in-memory vector store backed by FAISS.

    Stores document chunks and their embeddings for similarity search.
    Falls back to keyword-based retrieval if FAISS/sentence-transformers
    are unavailable.
    """

    def __init__(self) -> None:
        self.chunks: list[str] = []
        self.embeddings: Optional[np.ndarray] = None
        self._index = None
        self._embed_model = None
        self._ready = False

    def build_index(self, text: str) -> None:
        """Chunk the text and build a FAISS index.

        Parameters
        ----------
        text : str
            Full document text.
        """
        self.chunks = chunk_text(text)
        if not self.chunks:
            logger.warning("No chunks produced — document may be empty")
            return

        try:
            self._init_embedding_model()
            self._compute_embeddings()
            self._build_faiss_index()
            self._ready = True
            logger.info(
                "FAISS index built: %d chunks, dimension %d",
                len(self.chunks),
                self.embeddings.shape[1] if self.embeddings is not None else 0,
            )
        except Exception as exc:
            logger.warning(
                "Failed to build FAISS index (will use keyword fallback): %s",
                exc,
            )
            self._ready = False

    def search(self, query: str, top_k: int = config.TOP_K_RESULTS) -> list[str]:
        """Return the top-k most relevant chunks for *query*.

        Falls back to simple keyword overlap if the FAISS index is
        unavailable.
        """
        if self._ready and self._embed_model is not None:
            return self._faiss_search(query, top_k)
        return self._keyword_search(query, top_k)

    # ── Internal ──────────────────────────────────────────────────────────

    def _init_embedding_model(self) -> None:
        self._embed_model = get_embedding_model()

import streamlit as st

@st.cache_resource
def get_embedding_model():
    """Cache the embedding model to avoid reloading it on every document."""
    from sentence_transformers import SentenceTransformer
    return SentenceTransformer(config.EMBEDDING_MODEL)

    def _compute_embeddings(self) -> None:
        assert self._embed_model is not None
        self.embeddings = self._embed_model.encode(
            self.chunks, show_progress_bar=False, convert_to_numpy=True
        )

    def _build_faiss_index(self) -> None:
        import faiss  # type: ignore[import]

        assert self.embeddings is not None
        dim = self.embeddings.shape[1]
        self._index = faiss.IndexFlatL2(dim)
        self._index.add(self.embeddings.astype(np.float32))

    def _faiss_search(self, query: str, top_k: int) -> list[str]:
        assert self._embed_model is not None and self._index is not None
        q_vec = self._embed_model.encode([query], convert_to_numpy=True).astype(
            np.float32
        )
        distances, indices = self._index.search(q_vec, min(top_k, len(self.chunks)))
        return [self.chunks[i] for i in indices[0] if i < len(self.chunks)]

    def _keyword_search(self, query: str, top_k: int) -> list[str]:
        """Simple keyword-overlap fallback."""
        query_words = set(query.lower().split())
        scored = []
        for chunk in self.chunks:
            chunk_words = set(chunk.lower().split())
            overlap = len(query_words & chunk_words)
            scored.append((overlap, chunk))
        scored.sort(key=lambda x: x[0], reverse=True)
        return [chunk for _, chunk in scored[:top_k]]


# ─── Public API ────────────────────────────────────────────────────────────────


def answer_question(
    question: str,
    text: str,
    entities: list[DetectedEntity],
    risk: RiskAssessment,
    vector_store: Optional[DocumentVectorStore] = None,
) -> str:
    """Answer a user question about the analysed document.

    Uses RAG (vector retrieval + Gemini) when possible, falls back
    to a simpler prompt if FAISS/embeddings are unavailable.

    Parameters
    ----------
    question : str
        User's natural language question.
    text : str
        Full extracted document text.
    entities : list[DetectedEntity]
        Detected sensitive entities.
    risk : RiskAssessment
        Computed risk assessment.
    vector_store : DocumentVectorStore, optional
        Pre-built vector store (avoids re-indexing for each question).

    Returns
    -------
    str
        AI-generated answer.
    """
    if not config.GEMINI_API_KEY:
        return (
            "⚠️ Gemini API key is not configured. Please add your API key "
            "to the `.env` file to enable AI-powered question answering."
        )

    client = genai.Client(api_key=config.GEMINI_API_KEY)

    entities_summary = get_entities_summary(entities)

    # Try RAG with context retrieval
    context = ""
    if vector_store is not None:
        try:
            relevant_chunks = vector_store.search(question)
            context = "\n\n---\n\n".join(relevant_chunks)
        except Exception as exc:
            logger.warning("Vector search failed: %s", exc)

    if context:
        prompt = RAG_QA_PROMPT.format(
            context=context,
            entities_summary=entities_summary,
            risk_level=risk.risk_level,
            security_score=risk.security_score,
            question=question,
        )
    else:
        prompt = GENERAL_QA_PROMPT.format(
            filename="(uploaded document)",
            risk_level=risk.risk_level,
            security_score=risk.security_score,
            total_entities=risk.total_entities,
            entities_summary=entities_summary,
            question=question,
        )

    import time

    # ── Attempt 1: Gemini with retry ─────────────────────────────────────
    max_retries = 2
    gemini_failed = False
    for attempt in range(max_retries):
        try:
            response = client.models.generate_content(
                model=config.GEMINI_MODEL,
                contents=prompt,
                config=genai.types.GenerateContentConfig(
                    temperature=config.GEMINI_TEMPERATURE,
                    max_output_tokens=config.GEMINI_MAX_TOKENS,
                ),
            )
            return response.text.strip()
        except Exception as exc:
            err_str = str(exc).lower()
            is_rate_limit = "429" in err_str or "quota" in err_str or "exhausted" in err_str or "rate" in err_str

            if is_rate_limit and attempt < max_retries - 1:
                wait_time = (attempt + 1) * 3
                logger.warning(
                    "Gemini rate limit hit (attempt %d/%d), waiting %ds…",
                    attempt + 1, max_retries, wait_time,
                )
                time.sleep(wait_time)
                continue

            logger.warning("Gemini Q&A failed, will try OpenAI fallback: %s", exc)
            gemini_failed = True
            break

    # ── Attempt 2: OpenAI fallback ────────────────────────────────────────
    if gemini_failed and config.OPENAI_API_KEY:
        try:
            from openai import OpenAI

            client = OpenAI(api_key=config.OPENAI_API_KEY)
            logger.info("Falling back to OpenAI (%s) for Q&A", config.OPENAI_MODEL)

            oai_response = client.chat.completions.create(
                model=config.OPENAI_MODEL,
                messages=[
                    {"role": "system", "content": "You are an AI assistant specialised in document security analysis. Answer concisely and accurately."},
                    {"role": "user", "content": prompt},
                ],
                temperature=config.GEMINI_TEMPERATURE,
                max_tokens=config.GEMINI_MAX_TOKENS,
            )
            return oai_response.choices[0].message.content.strip()
        except Exception as oai_exc:
            logger.error("OpenAI fallback also failed: %s", oai_exc)
            return "⚠️ Both Gemini and OpenAI APIs failed. Please check your API keys and try again."

    if gemini_failed:
        return "⚠️ Gemini API rate limit exceeded and no OpenAI fallback key is configured. Please wait and try again."

    return "⚠️ Could not generate an answer. Please try again."

