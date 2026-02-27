"""Tests for aumai_confidentialrag CLI."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from click.testing import CliRunner

from aumai_confidentialrag.cli import main
from aumai_confidentialrag.core import DocumentEncryptor
from aumai_confidentialrag.models import ConfidentialDocument


# ---------------------------------------------------------------------------
# Version
# ---------------------------------------------------------------------------


class TestVersionFlag:
    def test_version_exits_zero(self) -> None:
        runner = CliRunner()
        result = runner.invoke(main, ["--version"])
        assert result.exit_code == 0
        assert "0.1.0" in result.output


# ---------------------------------------------------------------------------
# keygen command
# ---------------------------------------------------------------------------


class TestKeygenCommand:
    def test_keygen_creates_key_file(self, tmp_path: Path) -> None:
        key_path = str(tmp_path / "my.key")
        runner = CliRunner()
        result = runner.invoke(main, ["keygen", "--output", key_path])
        assert result.exit_code == 0, result.output
        assert Path(key_path).exists()

    def test_keygen_key_is_valid_fernet_key(self, tmp_path: Path) -> None:
        key_path = str(tmp_path / "my.key")
        runner = CliRunner()
        runner.invoke(main, ["keygen", "--output", key_path])
        key = Path(key_path).read_bytes()
        # Should be 44 bytes (URL-safe base64 of 32 raw bytes)
        assert len(key) == 44

    def test_keygen_output_mentions_path(self, tmp_path: Path) -> None:
        key_path = str(tmp_path / "secret.key")
        runner = CliRunner()
        result = runner.invoke(main, ["keygen", "--output", key_path])
        assert key_path in result.output

    def test_keygen_two_keys_are_different(self, tmp_path: Path) -> None:
        k1_path = str(tmp_path / "k1.key")
        k2_path = str(tmp_path / "k2.key")
        runner = CliRunner()
        runner.invoke(main, ["keygen", "--output", k1_path])
        runner.invoke(main, ["keygen", "--output", k2_path])
        assert Path(k1_path).read_bytes() != Path(k2_path).read_bytes()

    def test_keygen_default_filename(self, tmp_path: Path) -> None:
        runner = CliRunner()
        with runner.isolated_filesystem(temp_dir=str(tmp_path)):
            result = runner.invoke(main, ["keygen"])
        assert result.exit_code == 0


# ---------------------------------------------------------------------------
# encrypt command
# ---------------------------------------------------------------------------


class TestEncryptCommand:
    def _setup_key_and_docs(
        self, tmp_path: Path
    ) -> tuple[Path, Path, Path]:
        key_path = tmp_path / "test.key"
        key = DocumentEncryptor.generate_key()
        key_path.write_bytes(key)

        input_dir = tmp_path / "docs"
        input_dir.mkdir()
        (input_dir / "doc1.txt").write_text("Hello transformer world", encoding="utf-8")
        (input_dir / "doc2.txt").write_text("Neural network training", encoding="utf-8")

        output_dir = tmp_path / "encrypted"
        return key_path, input_dir, output_dir

    def test_encrypt_creates_output_directory(
        self, tmp_path: Path
    ) -> None:
        key_path, input_dir, output_dir = self._setup_key_and_docs(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "encrypt",
                "--input", str(input_dir),
                "--output", str(output_dir),
                "--key", str(key_path),
            ],
        )
        assert result.exit_code == 0, result.output
        assert output_dir.exists()

    def test_encrypt_creates_json_files(self, tmp_path: Path) -> None:
        key_path, input_dir, output_dir = self._setup_key_and_docs(tmp_path)
        runner = CliRunner()
        runner.invoke(
            main,
            [
                "encrypt",
                "--input", str(input_dir),
                "--output", str(output_dir),
                "--key", str(key_path),
            ],
        )
        json_files = list(output_dir.glob("*.json"))
        assert len(json_files) == 2

    def test_encrypt_json_is_valid_document(self, tmp_path: Path) -> None:
        key_path, input_dir, output_dir = self._setup_key_and_docs(tmp_path)
        runner = CliRunner()
        runner.invoke(
            main,
            [
                "encrypt",
                "--input", str(input_dir),
                "--output", str(output_dir),
                "--key", str(key_path),
            ],
        )
        for json_file in output_dir.glob("*.json"):
            doc = ConfidentialDocument.model_validate(
                json.loads(json_file.read_text())
            )
            assert doc.doc_id
            assert doc.encrypted_content

    def test_encrypt_counts_output(self, tmp_path: Path) -> None:
        key_path, input_dir, output_dir = self._setup_key_and_docs(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "encrypt",
                "--input", str(input_dir),
                "--output", str(output_dir),
                "--key", str(key_path),
            ],
        )
        assert "2" in result.output

    def test_encrypt_missing_key_fails(self, tmp_path: Path) -> None:
        _, input_dir, output_dir = self._setup_key_and_docs(tmp_path)
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "encrypt",
                "--input", str(input_dir),
                "--output", str(output_dir),
                "--key", str(tmp_path / "nonexistent.key"),
            ],
        )
        assert result.exit_code != 0


# ---------------------------------------------------------------------------
# search command
# ---------------------------------------------------------------------------


class TestSearchCommand:
    def _setup_encrypted_index(
        self, tmp_path: Path, docs: list[str]
    ) -> tuple[Path, Path]:
        key = DocumentEncryptor.generate_key()
        key_path = tmp_path / "search.key"
        key_path.write_bytes(key)

        index_dir = tmp_path / "index"
        index_dir.mkdir()

        encryptor = DocumentEncryptor()
        for i, text in enumerate(docs):
            import uuid

            doc = ConfidentialDocument(
                doc_id=str(uuid.uuid4()),
                encrypted_content=encryptor.encrypt(text, key),
            )
            (index_dir / f"{doc.doc_id}.json").write_text(
                doc.model_dump_json(), encoding="utf-8"
            )
        return key_path, index_dir

    def test_search_finds_relevant_docs(self, tmp_path: Path) -> None:
        docs = [
            "The transformer uses attention mechanisms for NLP tasks.",
            "Convolutional networks excel at image classification.",
            "Reinforcement learning trains agents with reward signals.",
        ]
        key_path, index_dir = self._setup_encrypted_index(tmp_path, docs)
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "search",
                "--query", "transformer attention",
                "--index", str(index_dir),
                "--key", str(key_path),
            ],
        )
        assert result.exit_code == 0, result.output
        assert "result" in result.output.lower()

    def test_search_empty_query_no_match(self, tmp_path: Path) -> None:
        docs = ["neural network model training"]
        key_path, index_dir = self._setup_encrypted_index(tmp_path, docs)
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "search",
                "--query", "xylophoneQQQ999",
                "--index", str(index_dir),
                "--key", str(key_path),
            ],
        )
        assert result.exit_code == 0
        assert "No results" in result.output

    def test_search_with_top_k(self, tmp_path: Path) -> None:
        docs = [
            "neural network architecture one",
            "neural network training two",
            "neural network optimization three",
            "neural network deployment four",
        ]
        key_path, index_dir = self._setup_encrypted_index(tmp_path, docs)
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "search",
                "--query", "neural network",
                "--index", str(index_dir),
                "--key", str(key_path),
                "--top-k", "2",
            ],
        )
        assert result.exit_code == 0

    def test_search_empty_index_fails(self, tmp_path: Path) -> None:
        key = DocumentEncryptor.generate_key()
        key_path = tmp_path / "k.key"
        key_path.write_bytes(key)
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "search",
                "--query", "anything",
                "--index", str(empty_dir),
                "--key", str(key_path),
            ],
        )
        assert result.exit_code != 0

    def test_search_invalid_context_json_fails(
        self, tmp_path: Path
    ) -> None:
        docs = ["some text"]
        key_path, index_dir = self._setup_encrypted_index(tmp_path, docs)
        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "search",
                "--query", "text",
                "--index", str(index_dir),
                "--key", str(key_path),
                "--context", "not-valid-json",
            ],
        )
        assert result.exit_code != 0

    def test_search_wrong_key_returns_no_results(
        self, tmp_path: Path
    ) -> None:
        docs = ["transformer attention mechanism"]
        key_path, index_dir = self._setup_encrypted_index(tmp_path, docs)

        # Create a different key
        wrong_key = DocumentEncryptor.generate_key()
        wrong_key_path = tmp_path / "wrong.key"
        wrong_key_path.write_bytes(wrong_key)

        runner = CliRunner()
        result = runner.invoke(
            main,
            [
                "search",
                "--query", "transformer",
                "--index", str(index_dir),
                "--key", str(wrong_key_path),
            ],
        )
        assert result.exit_code == 0
        assert "No results" in result.output
