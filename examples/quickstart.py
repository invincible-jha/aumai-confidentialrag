"""
aumai-confidentialrag quickstart — working demo of encryption, access control, and search.

Run directly:

    python examples/quickstart.py

All demos are self-contained and require no external files.
"""

from __future__ import annotations

import json
import pathlib
import tempfile
import uuid


# ---------------------------------------------------------------------------
# Demo 1: Generate a key, encrypt a document, and decrypt it
# ---------------------------------------------------------------------------

def demo_encrypt_decrypt() -> bytes:
    """Demonstrate Fernet key generation, encryption, and decryption."""
    print("\n=== Demo 1: Key generation, encrypt, decrypt ===")

    from aumai_confidentialrag.core import DocumentEncryptor

    # Generate a fresh encryption key
    key = DocumentEncryptor.generate_key()
    print(f"  Key (first 20 bytes): {key[:20]}...")
    print(f"  Key length          : {len(key)} bytes")

    encryptor = DocumentEncryptor()

    # Encrypt some sensitive text
    plaintext = (
        "Q1 2025 revenue exceeded projections by 12%. "
        "Operating margin improved to 18.4%. "
        "This document is confidential — finance department only."
    )
    ciphertext = encryptor.encrypt(plaintext, key)
    print(f"\n  Plaintext length    : {len(plaintext)} chars")
    print(f"  Ciphertext (first 40): {ciphertext[:40]}...")

    # Decrypt
    recovered = encryptor.decrypt(ciphertext, key)
    assert recovered == plaintext, "Decryption mismatch!"
    print(f"\n  Decrypted (first 60): {recovered[:60]}...")
    print("  Decrypt OK: plaintext matches original")

    # Demonstrate wrong-key behavior
    wrong_key = DocumentEncryptor.generate_key()
    from cryptography.fernet import InvalidToken
    try:
        encryptor.decrypt(ciphertext, wrong_key)
        print("  ERROR: should have raised InvalidToken!")
    except InvalidToken:
        print("  Wrong key correctly raises InvalidToken")

    return key


# ---------------------------------------------------------------------------
# Demo 2: Attribute-based access control
# ---------------------------------------------------------------------------

def demo_access_control() -> None:
    """Demonstrate AccessController with various policy and context combinations."""
    print("\n=== Demo 2: Attribute-based access control ===")

    from aumai_confidentialrag.core import AccessController

    controller = AccessController()

    cases = [
        # (policy, context, expected, label)
        ({}, {}, True, "Empty policy — always grant"),
        ({}, {"role": "guest"}, True, "Empty policy with context — grant"),
        (
            {"clearance": "secret"},
            {"clearance": "secret", "department": "research"},
            True,
            "Single required attr — match",
        ),
        (
            {"clearance": "secret"},
            {"clearance": "public"},
            False,
            "Single required attr — mismatch",
        ),
        (
            {"clearance": "secret", "department": "research"},
            {"clearance": "secret", "department": "research", "role": "analyst"},
            True,
            "Multi-attr policy — all match",
        ),
        (
            {"clearance": "secret", "department": "research"},
            {"clearance": "secret"},
            False,
            "Multi-attr policy — partial match",
        ),
    ]

    for policy, context, expected, label in cases:
        result = controller.check(policy, context)
        status = "PASS" if result == expected else "FAIL"
        print(f"  [{status}] {label}: check={result}")


# ---------------------------------------------------------------------------
# Demo 3: Build a ConfidentialIndex and search it
# ---------------------------------------------------------------------------

def demo_confidential_index() -> None:
    """Add encrypted documents to an index and run a search."""
    print("\n=== Demo 3: ConfidentialIndex search ===")

    from aumai_confidentialrag.core import DocumentEncryptor, ConfidentialIndex
    from aumai_confidentialrag.models import ConfidentialDocument

    key = DocumentEncryptor.generate_key()
    encryptor = DocumentEncryptor()
    index = ConfidentialIndex()

    # Add several documents with varied content
    documents = [
        (
            "doc-policy-retention",
            "The data retention policy requires all customer records older than seven "
            "years to be purged from primary storage. Active legal holds are exempt.",
            {},
        ),
        (
            "doc-policy-access",
            "Access to production databases is restricted to engineers with internal "
            "clearance. All access must be logged and reviewed monthly.",
            {},
        ),
        (
            "doc-finance-q1",
            "Q1 revenue grew 12% year-over-year. Operating costs decreased 3%. "
            "The finance committee approved the new capital expenditure plan.",
            {"clearance": "confidential", "department": "finance"},
        ),
        (
            "doc-incident-response",
            "The incident response team must be notified within one hour of any "
            "suspected data breach. Triage includes containment and legal notification.",
            {},
        ),
    ]

    for doc_id, content, policy in documents:
        doc = ConfidentialDocument(
            doc_id=doc_id,
            encrypted_content=encryptor.encrypt(content, key),
            metadata={"title": doc_id},
            access_policy=policy,
        )
        index.add_document(doc)

    print(f"  Documents in index: {index.document_count()}")

    # Search as a general requester — finance doc is not accessible
    print("\n  Search: 'data retention policy' (as general user)")
    results = index.search(
        "data retention policy",
        key,
        top_k=3,
        requester_context={"role": "employee"},
    )
    print(f"  Results: {len(results)}")
    for rank, r in enumerate(results, 1):
        print(f"    [{rank}] {r.doc_id}  score={r.relevance_score:.4f}")
        if r.decrypted_snippet:
            print(f"         {r.decrypted_snippet[:80]}...")

    # Search as a finance staff member — sees finance doc too
    print("\n  Search: 'revenue finance' (as finance staff)")
    results = index.search(
        "revenue finance",
        key,
        top_k=3,
        requester_context={"clearance": "confidential", "department": "finance"},
    )
    print(f"  Results: {len(results)}")
    for rank, r in enumerate(results, 1):
        print(f"    [{rank}] {r.doc_id}  score={r.relevance_score:.4f}")


# ---------------------------------------------------------------------------
# Demo 4: Persist documents to disk and reload
# ---------------------------------------------------------------------------

def demo_persist_and_reload() -> None:
    """Serialize encrypted documents to JSON files and reload them into a new index."""
    print("\n=== Demo 4: Persist encrypted index to disk and reload ===")

    from aumai_confidentialrag.core import DocumentEncryptor, ConfidentialIndex
    from aumai_confidentialrag.models import ConfidentialDocument

    key = DocumentEncryptor.generate_key()
    encryptor = DocumentEncryptor()

    with tempfile.TemporaryDirectory() as index_dir:
        index_path = pathlib.Path(index_dir)

        # Create and persist 3 documents
        texts = [
            "Machine learning operations require automated pipelines for reproducibility.",
            "Continuous integration ensures model quality gates are enforced on every commit.",
            "Monitoring model drift is essential for maintaining production accuracy.",
        ]
        doc_ids = []
        for text in texts:
            doc_id = str(uuid.uuid4())
            doc_ids.append(doc_id)
            doc = ConfidentialDocument(
                doc_id=doc_id,
                encrypted_content=encryptor.encrypt(text, key),
                metadata={"length": len(text)},
                access_policy={},
            )
            (index_path / f"{doc_id}.json").write_text(
                doc.model_dump_json(indent=2), encoding="utf-8"
            )

        print(f"  Persisted {len(doc_ids)} encrypted documents to {index_path}")
        print(f"  Files: {[f.name[:8] + '...' for f in index_path.glob('*.json')]}")

        # Reload into a fresh index
        new_index = ConfidentialIndex()
        for json_file in index_path.glob("*.json"):
            doc = ConfidentialDocument.model_validate(
                json.loads(json_file.read_text())
            )
            new_index.add_document(doc)

        print(f"\n  Reloaded index document count: {new_index.document_count()}")

        results = new_index.search("model pipelines monitoring", key, top_k=2)
        print(f"\n  Search results for 'model pipelines monitoring': {len(results)}")
        for r in results:
            print(f"    score={r.relevance_score:.4f}  {(r.decrypted_snippet or '')[:70]}...")


# ---------------------------------------------------------------------------
# Demo 5: Key rotation
# ---------------------------------------------------------------------------

def demo_key_rotation() -> None:
    """Re-encrypt a document with a new key."""
    print("\n=== Demo 5: Key rotation ===")

    from aumai_confidentialrag.core import DocumentEncryptor
    from aumai_confidentialrag.models import ConfidentialDocument

    encryptor = DocumentEncryptor()
    old_key = DocumentEncryptor.generate_key()
    new_key = DocumentEncryptor.generate_key()

    original_text = "This document must survive a key rotation."
    doc = ConfidentialDocument(
        doc_id="rotation-test",
        encrypted_content=encryptor.encrypt(original_text, old_key),
        access_policy={},
    )

    # Rotate: decrypt with old key, re-encrypt with new key
    plaintext = encryptor.decrypt(doc.encrypted_content, old_key)
    rotated_doc = doc.model_copy(
        update={"encrypted_content": encryptor.encrypt(plaintext, new_key)}
    )

    recovered = encryptor.decrypt(rotated_doc.encrypted_content, new_key)
    assert recovered == original_text, "Key rotation failed!"
    print(f"  Original text  : {original_text}")
    print(f"  Rotated doc_id : {rotated_doc.doc_id}")
    print("  Decryption with new key OK")

    # Old key no longer works on rotated document
    from cryptography.fernet import InvalidToken
    try:
        encryptor.decrypt(rotated_doc.encrypted_content, old_key)
        print("  ERROR: old key should not decrypt rotated document!")
    except InvalidToken:
        print("  Old key correctly rejected after rotation")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print("aumai-confidentialrag quickstart demo")
    print("=" * 40)

    demo_encrypt_decrypt()
    demo_access_control()
    demo_confidential_index()
    demo_persist_and_reload()
    demo_key_rotation()

    print("\n" + "=" * 40)
    print("All demos completed successfully.")


if __name__ == "__main__":
    main()
