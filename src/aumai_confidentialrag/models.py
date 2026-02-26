"""Pydantic models for aumai-confidentialrag."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

__all__ = [
    "EncryptionConfig",
    "ConfidentialDocument",
    "QueryResult",
]


class EncryptionConfig(BaseModel):
    """Configuration for symmetric encryption of documents."""

    algorithm: str = "fernet"
    key_id: str


class ConfidentialDocument(BaseModel):
    """An encrypted document with access policy metadata."""

    doc_id: str
    encrypted_content: str   # Base64-encoded Fernet ciphertext
    metadata: dict[str, Any] = Field(default_factory=dict)
    access_policy: dict[str, Any] = Field(default_factory=dict)


class QueryResult(BaseModel):
    """A single result from a confidential document search."""

    doc_id: str
    relevance_score: float = Field(ge=0.0, le=1.0)
    decrypted_snippet: str | None = None
