"""CLI entry point for aumai-confidentialrag."""

from __future__ import annotations

import base64
import json
import os
import sys
import uuid
from pathlib import Path

import click

from .core import AccessController, ConfidentialIndex, DocumentEncryptor
from .models import ConfidentialDocument, EncryptionConfig


@click.group()
@click.version_option()
def main() -> None:
    """AumAI ConfidentialRAG — privacy-preserving encrypted document retrieval."""


@main.command("keygen")
@click.option(
    "--output",
    "key_path",
    default="confidential.key",
    show_default=True,
    help="Path to write the generated Fernet key.",
)
def keygen_command(key_path: str) -> None:
    """Generate a new Fernet encryption key."""
    key = DocumentEncryptor.generate_key()
    Path(key_path).write_bytes(key)
    click.echo(f"Key written to {key_path}")
    click.echo("IMPORTANT: Keep this key secret and backed up.")


@main.command("encrypt")
@click.option(
    "--input",
    "input_dir",
    required=True,
    type=click.Path(exists=True, file_okay=False),
    help="Directory of plain-text documents to encrypt.",
)
@click.option(
    "--output",
    "output_dir",
    required=True,
    type=click.Path(file_okay=False),
    help="Directory to write encrypted document JSONs.",
)
@click.option(
    "--key",
    "key_path",
    default="confidential.key",
    show_default=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to the Fernet key file.",
)
@click.option(
    "--key-id",
    "key_id",
    default="default",
    show_default=True,
    help="Logical key identifier stored in config.",
)
def encrypt_command(
    input_dir: str, output_dir: str, key_path: str, key_id: str
) -> None:
    """Encrypt all text files in a directory."""
    key = Path(key_path).read_bytes()
    encryptor = DocumentEncryptor()
    out_path = Path(output_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    config = EncryptionConfig(algorithm="fernet", key_id=key_id)
    count = 0

    for txt_file in sorted(Path(input_dir).rglob("*")):
        if not txt_file.is_file():
            continue
        content = txt_file.read_text(encoding="utf-8", errors="replace")
        doc_id = str(uuid.uuid4())
        ciphertext = encryptor.encrypt(content, key)
        doc = ConfidentialDocument(
            doc_id=doc_id,
            encrypted_content=ciphertext,
            metadata={
                "original_filename": txt_file.name,
                "key_id": config.key_id,
                "algorithm": config.algorithm,
            },
        )
        out_file = out_path / f"{doc_id}.json"
        out_file.write_text(doc.model_dump_json(indent=2), encoding="utf-8")
        count += 1

    click.echo(f"Encrypted {count} document(s) to {output_dir}/")


@main.command("search")
@click.option("--query", required=True, help="Search query text.")
@click.option(
    "--index",
    "index_dir",
    required=True,
    type=click.Path(exists=True, file_okay=False),
    help="Directory of encrypted document JSON files.",
)
@click.option(
    "--key",
    "key_path",
    default="confidential.key",
    show_default=True,
    type=click.Path(exists=True, dir_okay=False),
    help="Path to the Fernet key file.",
)
@click.option("--top-k", default=5, show_default=True, type=int)
@click.option(
    "--context",
    "context_json",
    default="{}",
    help="Requester context JSON for access policy evaluation.",
)
def search_command(
    query: str,
    index_dir: str,
    key_path: str,
    top_k: int,
    context_json: str,
) -> None:
    """Search an encrypted document index."""
    key = Path(key_path).read_bytes()
    try:
        requester_context = json.loads(context_json)
    except json.JSONDecodeError as exc:
        click.echo(f"Error: invalid JSON for --context: {exc}", err=True)
        sys.exit(1)

    index = ConfidentialIndex()

    doc_files = list(Path(index_dir).glob("*.json"))
    if not doc_files:
        click.echo("No encrypted documents found.", err=True)
        sys.exit(1)

    for doc_file in doc_files:
        doc = ConfidentialDocument.model_validate(
            json.loads(doc_file.read_text())
        )
        index.add_document(doc)

    click.echo(f"Loaded {index.document_count()} document(s).", err=True)

    results = index.search(
        query=query,
        key=key,
        top_k=top_k,
        requester_context=requester_context,
    )

    if not results:
        click.echo("No results found.")
        return

    click.echo(f"Top {len(results)} result(s) for query: {query!r}\n")
    for rank, result in enumerate(results, start=1):
        click.echo(
            f"[{rank}] doc_id={result.doc_id}  score={result.relevance_score:.4f}"
        )
        if result.decrypted_snippet:
            click.echo(f"    {result.decrypted_snippet!r}")
        click.echo()


if __name__ == "__main__":
    main()
