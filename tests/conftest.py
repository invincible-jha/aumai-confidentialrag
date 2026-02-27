"""Shared test fixtures for aumai-confidentialrag."""

from __future__ import annotations

import uuid
from typing import Any

import pytest

from aumai_confidentialrag.core import (
    AccessController,
    ConfidentialIndex,
    DocumentEncryptor,
)
from aumai_confidentialrag.models import ConfidentialDocument


# ---------------------------------------------------------------------------
# Encryption
# ---------------------------------------------------------------------------


@pytest.fixture()
def encryptor() -> DocumentEncryptor:
    return DocumentEncryptor()


@pytest.fixture()
def fernet_key() -> bytes:
    return DocumentEncryptor.generate_key()


@pytest.fixture()
def alternate_key() -> bytes:
    return DocumentEncryptor.generate_key()


# ---------------------------------------------------------------------------
# Documents
# ---------------------------------------------------------------------------


SAMPLE_TEXTS: list[str] = [
    "The transformer architecture uses self-attention mechanisms for sequence modeling.",
    "Reinforcement learning trains agents through reward and punishment signals.",
    "Convolutional neural networks excel at image recognition tasks.",
    "Natural language processing enables computers to understand human text.",
    "Large language models are trained on massive text corpora.",
]


@pytest.fixture()
def sample_texts() -> list[str]:
    return list(SAMPLE_TEXTS)


def _make_document(
    content: str,
    key: bytes,
    access_policy: dict[str, Any] | None = None,
) -> ConfidentialDocument:
    encryptor = DocumentEncryptor()
    ciphertext = encryptor.encrypt(content, key)
    return ConfidentialDocument(
        doc_id=str(uuid.uuid4()),
        encrypted_content=ciphertext,
        metadata={"source": "test"},
        access_policy=access_policy or {},
    )


@pytest.fixture()
def sample_documents(
    fernet_key: bytes,
    sample_texts: list[str],
) -> list[ConfidentialDocument]:
    return [_make_document(text, fernet_key) for text in sample_texts]


# ---------------------------------------------------------------------------
# Index
# ---------------------------------------------------------------------------


@pytest.fixture()
def access_controller() -> AccessController:
    return AccessController()


@pytest.fixture()
def index() -> ConfidentialIndex:
    return ConfidentialIndex()


@pytest.fixture()
def populated_index(
    index: ConfidentialIndex,
    sample_documents: list[ConfidentialDocument],
) -> ConfidentialIndex:
    for doc in sample_documents:
        index.add_document(doc)
    return index
