"""Core logic for aumai-confidentialrag."""

from __future__ import annotations

import re
import uuid
from collections import Counter
from typing import Any

from cryptography.fernet import Fernet, InvalidToken

from .models import ConfidentialDocument, QueryResult

__all__ = [
    "DocumentEncryptor",
    "ConfidentialIndex",
    "AccessController",
]

_SNIPPET_LENGTH = 200


class DocumentEncryptor:
    """
    Encrypts and decrypts document content using Fernet symmetric encryption.

    Fernet guarantees authenticated encryption (AES-128-CBC + HMAC-SHA256).
    """

    @staticmethod
    def generate_key() -> bytes:
        """Generate a new Fernet key."""
        return Fernet.generate_key()

    def encrypt(self, content: str, key: bytes) -> str:
        """
        Encrypt *content* with *key*.

        Returns a URL-safe base64-encoded ciphertext string.
        """
        f = Fernet(key)
        return f.encrypt(content.encode("utf-8")).decode("ascii")

    def decrypt(self, ciphertext: str, key: bytes) -> str:
        """
        Decrypt *ciphertext* with *key*.

        Raises ``InvalidToken`` if the key is wrong or the token is corrupted.
        """
        f = Fernet(key)
        return f.decrypt(ciphertext.encode("ascii")).decode("utf-8")


class AccessController:
    """
    Enforces attribute-based access policies on document retrieval.

    Policy is a dict of required key-value pairs.  A requester context
    must contain ALL required values to be granted access.

    Example::

        policy = {"clearance": "secret", "department": "research"}
        context = {"clearance": "secret", "department": "research", "role": "analyst"}
        AccessController().check(policy, context)  # True
    """

    def check(
        self,
        policy: dict[str, Any],
        requester_context: dict[str, Any],
    ) -> bool:
        """
        Return ``True`` if *requester_context* satisfies *policy*.

        An empty policy grants access to everyone.
        """
        if not policy:
            return True
        for required_key, required_value in policy.items():
            if requester_context.get(required_key) != required_value:
                return False
        return True


class ConfidentialIndex:
    """
    An encrypted document index supporting add/search operations.

    Documents are stored in encrypted form.  Searching decrypts each
    document in-memory, scores it against the query using TF-IDF-like
    term frequency, and re-encrypts before storage.

    This simulates the confidential compute pattern where decryption
    occurs only within the trusted execution boundary.
    """

    def __init__(self, access_controller: AccessController | None = None) -> None:
        self._documents: dict[str, ConfidentialDocument] = {}
        self._access_controller = access_controller or AccessController()

    def add_document(
        self,
        doc: ConfidentialDocument,
    ) -> None:
        """Add an encrypted document to the index."""
        self._documents[doc.doc_id] = doc

    def remove_document(self, doc_id: str) -> None:
        """Remove a document from the index."""
        self._documents.pop(doc_id, None)

    def search(
        self,
        query: str,
        key: bytes,
        top_k: int = 5,
        requester_context: dict[str, Any] | None = None,
    ) -> list[QueryResult]:
        """
        Search the index for documents relevant to *query*.

        Decrypts each document using *key*, scores it, then returns the
        top-k results with a decrypted snippet.  Access policy is enforced
        per document via *requester_context*.

        Args:
            query: Plain-text search query.
            key: Fernet key for decryption.
            top_k: Maximum number of results to return.
            requester_context: Attributes used to evaluate access policies.

        Returns:
            List of ``QueryResult`` sorted by relevance descending.
        """
        encryptor = DocumentEncryptor()
        context = requester_context or {}
        query_terms = _tokenize(query)
        scored: list[tuple[str, float, str]] = []

        for doc_id, doc in self._documents.items():
            # Access control check
            if not self._access_controller.check(doc.access_policy, context):
                continue
            # Decrypt
            try:
                plaintext = encryptor.decrypt(doc.encrypted_content, key)
            except InvalidToken:
                continue

            score = _tfidf_score(query_terms, plaintext)
            if score > 0:
                scored.append((doc_id, score, plaintext))

        # Sort descending by score
        scored.sort(key=lambda x: x[1], reverse=True)
        results: list[QueryResult] = []
        for doc_id, score, plaintext in scored[:top_k]:
            snippet = _extract_snippet(plaintext, query_terms, _SNIPPET_LENGTH)
            results.append(
                QueryResult(
                    doc_id=doc_id,
                    relevance_score=min(1.0, score),
                    decrypted_snippet=snippet,
                )
            )
        return results

    def document_count(self) -> int:
        """Return the number of documents in the index."""
        return len(self._documents)

    def get_document(self, doc_id: str) -> ConfidentialDocument:
        """Retrieve a document by ID."""
        doc = self._documents.get(doc_id)
        if doc is None:
            raise KeyError(f"No document with id {doc_id!r}.")
        return doc

    def all_doc_ids(self) -> list[str]:
        """Return all document IDs in the index."""
        return list(self._documents.keys())


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _tokenize(text: str) -> list[str]:
    """Lowercase, remove punctuation, split into words."""
    return re.findall(r"[a-z0-9]+", text.lower())


def _tfidf_score(query_terms: list[str], document: str) -> float:
    """
    Compute a simple TF-based relevance score.

    For each query term, TF = count(term, doc) / len(doc_terms).
    Score = sum of TF values across query terms, normalized to [0, 1]
    by dividing by the maximum possible score.
    """
    if not query_terms:
        return 0.0
    doc_terms = _tokenize(document)
    if not doc_terms:
        return 0.0
    term_counts = Counter(doc_terms)
    doc_len = len(doc_terms)
    total_tf = sum(
        term_counts.get(term, 0) / doc_len for term in query_terms
    )
    # Normalize: max possible tf per term is 1.0, so max total = len(query_terms)
    return total_tf / len(query_terms)


def _extract_snippet(
    text: str, query_terms: list[str], max_len: int
) -> str:
    """
    Extract a snippet from *text* centered around the first query term hit.

    Returns a substring of at most *max_len* characters.
    """
    lower = text.lower()
    best_pos = len(text)
    for term in query_terms:
        pos = lower.find(term)
        if pos != -1 and pos < best_pos:
            best_pos = pos
    if best_pos == len(text):
        return text[:max_len]
    start = max(0, best_pos - max_len // 4)
    end = min(len(text), start + max_len)
    snippet = text[start:end]
    if start > 0:
        snippet = "..." + snippet
    if end < len(text):
        snippet = snippet + "..."
    return snippet
