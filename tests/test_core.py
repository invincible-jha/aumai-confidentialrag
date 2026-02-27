"""Tests for aumai_confidentialrag.core."""

from __future__ import annotations

import uuid
from typing import Any

import pytest
from cryptography.fernet import InvalidToken

from aumai_confidentialrag.core import (
    AccessController,
    ConfidentialIndex,
    DocumentEncryptor,
    _extract_snippet,
    _tfidf_score,
    _tokenize,
)
from aumai_confidentialrag.models import ConfidentialDocument, QueryResult


# ---------------------------------------------------------------------------
# _tokenize
# ---------------------------------------------------------------------------


class TestTokenize:
    def test_basic_split(self) -> None:
        assert _tokenize("hello world") == ["hello", "world"]

    def test_lowercases(self) -> None:
        assert _tokenize("Hello WORLD") == ["hello", "world"]

    def test_strips_punctuation(self) -> None:
        tokens = _tokenize("foo, bar. baz!")
        assert "foo" in tokens
        assert "bar" in tokens
        assert "baz" in tokens
        assert "," not in tokens

    def test_handles_digits(self) -> None:
        assert "123" in _tokenize("value 123")

    def test_empty_string(self) -> None:
        assert _tokenize("") == []

    def test_only_punctuation(self) -> None:
        assert _tokenize("!@#$%") == []


# ---------------------------------------------------------------------------
# _tfidf_score
# ---------------------------------------------------------------------------


class TestTfidfScore:
    def test_exact_match_returns_nonzero(self) -> None:
        score = _tfidf_score(["transformer"], "the transformer model")
        assert score > 0

    def test_no_match_returns_zero(self) -> None:
        assert _tfidf_score(["xyz"], "hello world foo bar") == 0.0

    def test_empty_query_returns_zero(self) -> None:
        assert _tfidf_score([], "some document text") == 0.0

    def test_empty_document_returns_zero(self) -> None:
        assert _tfidf_score(["term"], "") == 0.0

    def test_score_in_zero_one_range(self) -> None:
        score = _tfidf_score(
            ["the", "transformer"],
            "the transformer architecture uses the attention mechanism the the",
        )
        assert 0.0 <= score <= 1.0

    def test_more_occurrences_means_higher_score(self) -> None:
        low = _tfidf_score(
            ["attention"], "the transformer architecture uses mechanisms"
        )
        high = _tfidf_score(
            ["attention"],
            "attention attention attention mechanisms attention",
        )
        assert high > low

    def test_multiple_query_terms(self) -> None:
        score = _tfidf_score(
            ["neural", "network"],
            "neural network architecture for neural processing",
        )
        assert score > 0


# ---------------------------------------------------------------------------
# _extract_snippet
# ---------------------------------------------------------------------------


class TestExtractSnippet:
    def test_snippet_within_max_len(self) -> None:
        text = "hello world foo bar baz"
        snippet = _extract_snippet(text, ["foo"], 200)
        assert len(snippet) <= 210  # allow for ellipsis padding

    def test_snippet_contains_term(self) -> None:
        text = "a" * 50 + " transformer " + "b" * 50
        snippet = _extract_snippet(text, ["transformer"], 40)
        assert "transformer" in snippet

    def test_short_text_returned_intact(self) -> None:
        text = "short text"
        snippet = _extract_snippet(text, ["short"], 200)
        assert "short" in snippet

    def test_term_not_found_returns_start_of_text(self) -> None:
        text = "hello world"
        snippet = _extract_snippet(text, ["xyz"], 5)
        assert snippet == "hello"

    def test_empty_query_terms_returns_start(self) -> None:
        text = "the quick brown fox"
        snippet = _extract_snippet(text, [], 10)
        assert len(snippet) <= 10


# ---------------------------------------------------------------------------
# DocumentEncryptor
# ---------------------------------------------------------------------------


class TestDocumentEncryptor:
    def test_generate_key_returns_bytes(self, fernet_key: bytes) -> None:
        assert isinstance(fernet_key, bytes)

    def test_key_length(self, fernet_key: bytes) -> None:
        # Fernet keys are 44-byte URL-safe base64 strings
        assert len(fernet_key) == 44

    def test_keys_are_unique(
        self, fernet_key: bytes, alternate_key: bytes
    ) -> None:
        assert fernet_key != alternate_key

    def test_encrypt_returns_string(
        self, encryptor: DocumentEncryptor, fernet_key: bytes
    ) -> None:
        ct = encryptor.encrypt("hello", fernet_key)
        assert isinstance(ct, str)

    def test_encrypt_is_non_deterministic(
        self, encryptor: DocumentEncryptor, fernet_key: bytes
    ) -> None:
        # Fernet uses a random IV so two encryptions of the same plaintext differ
        ct1 = encryptor.encrypt("hello", fernet_key)
        ct2 = encryptor.encrypt("hello", fernet_key)
        assert ct1 != ct2

    def test_decrypt_recovers_plaintext(
        self, encryptor: DocumentEncryptor, fernet_key: bytes
    ) -> None:
        original = "The quick brown fox jumps over the lazy dog."
        ct = encryptor.encrypt(original, fernet_key)
        assert encryptor.decrypt(ct, fernet_key) == original

    def test_decrypt_wrong_key_raises_invalid_token(
        self,
        encryptor: DocumentEncryptor,
        fernet_key: bytes,
        alternate_key: bytes,
    ) -> None:
        ct = encryptor.encrypt("secret", fernet_key)
        with pytest.raises(InvalidToken):
            encryptor.decrypt(ct, alternate_key)

    def test_encrypt_unicode_content(
        self, encryptor: DocumentEncryptor, fernet_key: bytes
    ) -> None:
        text = "El ni\u00f1o aprendi\u00f3 matem\u00e1ticas. \U0001f600"
        ct = encryptor.encrypt(text, fernet_key)
        assert encryptor.decrypt(ct, fernet_key) == text

    def test_encrypt_empty_string(
        self, encryptor: DocumentEncryptor, fernet_key: bytes
    ) -> None:
        ct = encryptor.encrypt("", fernet_key)
        assert encryptor.decrypt(ct, fernet_key) == ""

    def test_encrypt_large_content(
        self, encryptor: DocumentEncryptor, fernet_key: bytes
    ) -> None:
        large_text = "word " * 10000
        ct = encryptor.encrypt(large_text, fernet_key)
        assert encryptor.decrypt(ct, fernet_key) == large_text


# ---------------------------------------------------------------------------
# AccessController
# ---------------------------------------------------------------------------


class TestAccessController:
    def test_empty_policy_grants_access(
        self, access_controller: AccessController
    ) -> None:
        assert access_controller.check({}, {"role": "analyst"}) is True

    def test_matching_policy_grants_access(
        self, access_controller: AccessController
    ) -> None:
        policy = {"clearance": "secret", "dept": "research"}
        context = {"clearance": "secret", "dept": "research", "role": "analyst"}
        assert access_controller.check(policy, context) is True

    def test_missing_key_denies_access(
        self, access_controller: AccessController
    ) -> None:
        policy = {"clearance": "secret"}
        context = {"dept": "research"}
        assert access_controller.check(policy, context) is False

    def test_wrong_value_denies_access(
        self, access_controller: AccessController
    ) -> None:
        policy = {"clearance": "topsecret"}
        context = {"clearance": "secret"}
        assert access_controller.check(policy, context) is False

    def test_empty_context_with_non_empty_policy_denies(
        self, access_controller: AccessController
    ) -> None:
        assert access_controller.check({"key": "val"}, {}) is False

    def test_extra_context_keys_are_ignored(
        self, access_controller: AccessController
    ) -> None:
        policy = {"role": "admin"}
        context = {"role": "admin", "extra": "value", "other": 123}
        assert access_controller.check(policy, context) is True

    def test_all_policy_keys_must_match(
        self, access_controller: AccessController
    ) -> None:
        policy = {"a": 1, "b": 2}
        assert access_controller.check(policy, {"a": 1}) is False
        assert access_controller.check(policy, {"b": 2}) is False
        assert access_controller.check(policy, {"a": 1, "b": 2}) is True


# ---------------------------------------------------------------------------
# ConfidentialIndex
# ---------------------------------------------------------------------------


class TestConfidentialIndex:
    def test_add_and_count(
        self,
        index: ConfidentialIndex,
        sample_documents: list[ConfidentialDocument],
    ) -> None:
        for doc in sample_documents:
            index.add_document(doc)
        assert index.document_count() == len(sample_documents)

    def test_get_document_by_id(
        self,
        populated_index: ConfidentialIndex,
        sample_documents: list[ConfidentialDocument],
    ) -> None:
        doc_id = sample_documents[0].doc_id
        retrieved = populated_index.get_document(doc_id)
        assert retrieved.doc_id == doc_id

    def test_get_nonexistent_raises_key_error(
        self, index: ConfidentialIndex
    ) -> None:
        with pytest.raises(KeyError, match="no-such-id"):
            index.get_document("no-such-id")

    def test_remove_document(
        self,
        populated_index: ConfidentialIndex,
        sample_documents: list[ConfidentialDocument],
    ) -> None:
        doc_id = sample_documents[0].doc_id
        populated_index.remove_document(doc_id)
        assert populated_index.document_count() == len(sample_documents) - 1
        with pytest.raises(KeyError):
            populated_index.get_document(doc_id)

    def test_remove_nonexistent_is_no_op(
        self, index: ConfidentialIndex
    ) -> None:
        index.remove_document("ghost")  # must not raise

    def test_all_doc_ids_returns_all(
        self,
        populated_index: ConfidentialIndex,
        sample_documents: list[ConfidentialDocument],
    ) -> None:
        ids = populated_index.all_doc_ids()
        assert set(ids) == {d.doc_id for d in sample_documents}

    def test_search_returns_query_results(
        self,
        populated_index: ConfidentialIndex,
        fernet_key: bytes,
    ) -> None:
        results = populated_index.search(
            query="transformer attention", key=fernet_key, top_k=3
        )
        assert isinstance(results, list)
        assert all(isinstance(r, QueryResult) for r in results)

    def test_search_respects_top_k(
        self,
        populated_index: ConfidentialIndex,
        fernet_key: bytes,
    ) -> None:
        results = populated_index.search(
            query="neural network model", key=fernet_key, top_k=2
        )
        assert len(results) <= 2

    def test_search_scores_in_valid_range(
        self,
        populated_index: ConfidentialIndex,
        fernet_key: bytes,
    ) -> None:
        results = populated_index.search(
            query="learning", key=fernet_key, top_k=5
        )
        for r in results:
            assert 0.0 <= r.relevance_score <= 1.0

    def test_search_no_match_returns_empty(
        self,
        populated_index: ConfidentialIndex,
        fernet_key: bytes,
    ) -> None:
        results = populated_index.search(
            query="xylophone quantum frobnicator", key=fernet_key
        )
        assert results == []

    def test_search_wrong_key_returns_empty(
        self,
        populated_index: ConfidentialIndex,
        alternate_key: bytes,
    ) -> None:
        results = populated_index.search(
            query="transformer", key=alternate_key
        )
        assert results == []

    def test_search_results_sorted_by_score_descending(
        self,
        populated_index: ConfidentialIndex,
        fernet_key: bytes,
    ) -> None:
        results = populated_index.search(
            query="neural network language", key=fernet_key, top_k=5
        )
        scores = [r.relevance_score for r in results]
        assert scores == sorted(scores, reverse=True)

    def test_search_enforces_access_policy(
        self, fernet_key: bytes
    ) -> None:
        encryptor = DocumentEncryptor()
        restricted = ConfidentialDocument(
            doc_id=str(uuid.uuid4()),
            encrypted_content=encryptor.encrypt(
                "classified transformer research", fernet_key
            ),
            access_policy={"clearance": "topsecret"},
        )
        public_doc = ConfidentialDocument(
            doc_id=str(uuid.uuid4()),
            encrypted_content=encryptor.encrypt(
                "public transformer documentation", fernet_key
            ),
            access_policy={},
        )
        idx = ConfidentialIndex()
        idx.add_document(restricted)
        idx.add_document(public_doc)

        # Without clearance: only public doc returned
        results_low = idx.search(
            query="transformer", key=fernet_key, requester_context={}
        )
        low_ids = {r.doc_id for r in results_low}
        assert public_doc.doc_id in low_ids
        assert restricted.doc_id not in low_ids

        # With clearance: both docs returned
        results_high = idx.search(
            query="transformer",
            key=fernet_key,
            requester_context={"clearance": "topsecret"},
        )
        high_ids = {r.doc_id for r in results_high}
        assert restricted.doc_id in high_ids
        assert public_doc.doc_id in high_ids

    def test_search_snippet_present_for_matches(
        self,
        populated_index: ConfidentialIndex,
        fernet_key: bytes,
    ) -> None:
        results = populated_index.search(
            query="transformer", key=fernet_key, top_k=3
        )
        for r in results:
            assert r.decrypted_snippet is not None

    def test_search_empty_index_returns_empty(
        self, index: ConfidentialIndex, fernet_key: bytes
    ) -> None:
        results = index.search(query="anything", key=fernet_key)
        assert results == []

    def test_add_duplicate_doc_id_overwrites(
        self, index: ConfidentialIndex, fernet_key: bytes
    ) -> None:
        encryptor = DocumentEncryptor()
        doc_id = str(uuid.uuid4())
        doc1 = ConfidentialDocument(
            doc_id=doc_id,
            encrypted_content=encryptor.encrypt("original", fernet_key),
        )
        doc2 = ConfidentialDocument(
            doc_id=doc_id,
            encrypted_content=encryptor.encrypt("replaced", fernet_key),
        )
        index.add_document(doc1)
        index.add_document(doc2)
        assert index.document_count() == 1
        stored = index.get_document(doc_id)
        assert stored.encrypted_content == doc2.encrypted_content

    def test_index_with_custom_access_controller(
        self, fernet_key: bytes
    ) -> None:
        controller = AccessController()
        idx = ConfidentialIndex(access_controller=controller)
        encryptor = DocumentEncryptor()
        doc = ConfidentialDocument(
            doc_id=str(uuid.uuid4()),
            encrypted_content=encryptor.encrypt(
                "neural network training data", fernet_key
            ),
        )
        idx.add_document(doc)
        results = idx.search(query="neural", key=fernet_key)
        assert len(results) == 1
