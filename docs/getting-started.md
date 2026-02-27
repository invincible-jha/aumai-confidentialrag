# Getting Started with aumai-confidentialrag

This guide walks you from a plaintext document corpus to a searchable encrypted index in about
ten minutes, using both the CLI and the Python API.

---

## Prerequisites

- Python 3.11 or later
- `pip` (or any PEP-517-compatible installer)
- A directory of plain-text documents you want to keep confidential

---

## Installation

### From PyPI

```bash
pip install aumai-confidentialrag
```

### From source

```bash
git clone https://github.com/aumai/aumai-confidentialrag.git
cd aumai-confidentialrag
pip install -e ".[dev]"
```

### Verify the installation

```bash
aumai-confidentialrag --version
python -c "import aumai_confidentialrag; print(aumai_confidentialrag.__version__)"
```

---

## Step-by-Step Tutorial

### Step 1 — Create a sample corpus

```python
# create_corpus.py
import pathlib

corpus = pathlib.Path("./plaintext-docs")
corpus.mkdir(exist_ok=True)

docs = {
    "policy-data-retention.txt": (
        "The data retention policy requires all customer records older than seven years "
        "to be purged from primary storage. Records under active legal hold are exempt. "
        "Compliance audits occur quarterly."
    ),
    "policy-access-control.txt": (
        "Access to production databases is restricted to engineers with security clearance "
        "level 'internal' or higher. All access must be logged and reviewed monthly. "
        "Third-party contractors require explicit written approval."
    ),
    "policy-incident-response.txt": (
        "The incident response team must be notified within one hour of any suspected "
        "data breach. Initial triage includes scope assessment, containment, and "
        "notification of the legal department."
    ),
}

for filename, content in docs.items():
    (corpus / filename).write_text(content)

print(f"Created {len(docs)} documents in {corpus}")
```

```bash
python create_corpus.py
```

### Step 2 — Generate an encryption key

```bash
aumai-confidentialrag keygen --output my.key
```

```
Key written to my.key
IMPORTANT: Keep this key secret and backed up.
```

The key file is 44 bytes of URL-safe base64-encoded random data. Store it securely — in a
secrets manager, not in your repository.

### Step 3 — Encrypt the corpus

```bash
aumai-confidentialrag encrypt \
  --input ./plaintext-docs \
  --output ./encrypted-index \
  --key my.key \
  --key-id tutorial-2025
```

```
Encrypted 3 document(s) to encrypted-index/
```

The `encrypted-index/` directory now contains three JSON files, each named with a UUID:

```json
{
  "doc_id": "a3f2b1c4-...",
  "encrypted_content": "gAAAAAB...",
  "metadata": {
    "original_filename": "policy-data-retention.txt",
    "key_id": "tutorial-2025",
    "algorithm": "fernet"
  },
  "access_policy": {}
}
```

### Step 4 — Search the encrypted index

```bash
aumai-confidentialrag search \
  --query "data retention policy" \
  --index ./encrypted-index \
  --key my.key \
  --top-k 3
```

```
Loaded 3 document(s).
Top 3 result(s) for query: 'data retention policy'

[1] doc_id=a3f2b1c4-...  score=0.0833
    '...data retention policy requires all customer records older than seven years...'

[2] doc_id=7e4abc12-...  score=0.0167
    '...incident response team must be notified within one hour of any suspected...'
```

The raw ciphertext never leaves the search function. Decryption happens in-memory only, and
only for documents whose access policy the requester satisfies.

### Step 5 — Add access policies and test ABAC

Documents encrypted via the CLI currently get empty access policies (unrestricted). To
use attribute-based access control, add documents programmatically:

```python
from aumai_confidentialrag.core import DocumentEncryptor, ConfidentialIndex
from aumai_confidentialrag.models import ConfidentialDocument

key = open("my.key", "rb").read()
encryptor = DocumentEncryptor()
index = ConfidentialIndex()

# Public document — no policy
public_doc = ConfidentialDocument(
    doc_id="pub-001",
    encrypted_content=encryptor.encrypt("General company information.", key),
    access_policy={},
)

# Restricted document — requires legal clearance
legal_doc = ConfidentialDocument(
    doc_id="legal-001",
    encrypted_content=encryptor.encrypt("Settlement terms for case #4471.", key),
    access_policy={"clearance": "confidential", "department": "legal"},
)

index.add_document(public_doc)
index.add_document(legal_doc)

# Query as a general user — only sees public document
general_results = index.search(
    "company settlement", key, requester_context={"role": "employee"}
)
print([r.doc_id for r in general_results])  # ['pub-001']

# Query as legal staff — sees both
legal_results = index.search(
    "company settlement", key,
    requester_context={"clearance": "confidential", "department": "legal"},
)
print([r.doc_id for r in legal_results])  # ['legal-001', 'pub-001']
```

---

## Common Patterns and Recipes

### Pattern 1 — Batch encrypt with per-document policies

```python
import uuid
from pathlib import Path
from aumai_confidentialrag.core import DocumentEncryptor
from aumai_confidentialrag.models import ConfidentialDocument

key = Path("my.key").read_bytes()
encryptor = DocumentEncryptor()

# Policy registry: map filename prefix to access policy
POLICY_MAP = {
    "legal-": {"clearance": "confidential", "department": "legal"},
    "hr-":    {"clearance": "internal", "department": "hr"},
    "public-": {},
}

def policy_for(filename: str) -> dict:
    for prefix, policy in POLICY_MAP.items():
        if filename.startswith(prefix):
            return policy
    return {"clearance": "internal"}  # default: internal only

docs = []
for txt_file in sorted(Path("./plaintext-docs").rglob("*.txt")):
    content = txt_file.read_text()
    doc = ConfidentialDocument(
        doc_id=str(uuid.uuid4()),
        encrypted_content=encryptor.encrypt(content, key),
        metadata={"source": txt_file.name},
        access_policy=policy_for(txt_file.name),
    )
    docs.append(doc)

print(f"Prepared {len(docs)} encrypted documents")
```

### Pattern 2 — Persisting and loading the index

`ConfidentialIndex` is in-memory only. Persist documents as JSON files and reload on each
search. This is exactly what the CLI `search` command does:

```python
import json
from pathlib import Path
from aumai_confidentialrag.core import ConfidentialIndex
from aumai_confidentialrag.models import ConfidentialDocument

INDEX_DIR = Path("./encrypted-index")

def load_index() -> ConfidentialIndex:
    index = ConfidentialIndex()
    for json_file in INDEX_DIR.glob("*.json"):
        doc = ConfidentialDocument.model_validate(
            json.loads(json_file.read_text())
        )
        index.add_document(doc)
    return index

index = load_index()
print(f"Loaded {index.document_count()} documents")
```

### Pattern 3 — Rotating keys

When rotating encryption keys, re-encrypt all documents with the new key:

```python
from aumai_confidentialrag.core import DocumentEncryptor

old_key = open("old.key", "rb").read()
new_key = open("new.key", "rb").read()
encryptor = DocumentEncryptor()

def rotate_document(doc: ConfidentialDocument) -> ConfidentialDocument:
    plaintext = encryptor.decrypt(doc.encrypted_content, old_key)
    new_ciphertext = encryptor.encrypt(plaintext, new_key)
    return doc.model_copy(update={"encrypted_content": new_ciphertext})
```

### Pattern 4 — Handling missing or wrong keys gracefully

`ConfidentialIndex.search` silently skips documents it cannot decrypt (wrong key or corrupted
ciphertext). If you need to detect those failures explicitly, use `DocumentEncryptor.decrypt`
directly and catch `cryptography.fernet.InvalidToken`:

```python
from cryptography.fernet import InvalidToken
from aumai_confidentialrag.core import DocumentEncryptor

encryptor = DocumentEncryptor()
key = open("my.key", "rb").read()

try:
    plaintext = encryptor.decrypt(doc.encrypted_content, key)
except InvalidToken:
    print(f"Cannot decrypt doc {doc.doc_id} — wrong key or corrupted content")
```

### Pattern 5 — Integrating with a real LLM (RAG pipeline)

```python
from aumai_confidentialrag.core import ConfidentialIndex

def rag_query(index: ConfidentialIndex, key: bytes, user_context: dict, query: str) -> str:
    results = index.search(query, key, top_k=3, requester_context=user_context)
    if not results:
        context_str = "No relevant documents found."
    else:
        snippets = [r.decrypted_snippet or "" for r in results if r.decrypted_snippet]
        context_str = "\n\n".join(snippets)

    # Pass context_str to your LLM of choice
    prompt = f"Context:\n{context_str}\n\nQuestion: {query}"
    # response = llm_client.complete(prompt)
    return prompt  # replace with actual LLM call
```

---

## Troubleshooting FAQ

**Q: `aumai-confidentialrag search` returns zero results even though the documents exist.**

The most likely cause is a mismatched encryption key. The search loop silently skips documents
where `InvalidToken` is raised during decryption. Verify the key file path matches the one
used during `encrypt`. Run `python -c "from cryptography.fernet import Fernet; Fernet(open('my.key','rb').read())"` to confirm the key is valid Fernet format.

---

**Q: I encrypted with `key-id=prod-key` but search shows no results.**

The `key_id` field is a label stored in metadata — it does not affect which key is used for
decryption. The actual decryption key is the raw bytes in the key file. `key_id` is only for
audit and rotation tracking.

---

**Q: Can I use asymmetric encryption (RSA, ECDH) instead of Fernet?**

Not with the current public API (SR-6 scope boundary). `DocumentEncryptor` exclusively uses
Fernet symmetric encryption. Asymmetric key exchange for key distribution is part of the
enterprise TEE integration layer.

---

**Q: `search` returns results but `decrypted_snippet` is `None` for some.**

`decrypted_snippet` is populated only when the TF scoring finds at least one query term in
the document. A score > 0 but an empty snippet should not occur, but if the snippet window is
very short it may appear truncated. Increase the search query specificity.

---

**Q: What happens if I call `index.get_document` with an ID that does not exist?**

It raises `KeyError: "No document with id '...'."`. Use `index.all_doc_ids()` to enumerate
valid IDs first.

---

**Q: How do I delete a document from the index?**

Call `index.remove_document(doc_id)`. This removes the in-memory entry. If you are persisting
documents as JSON files, also delete the corresponding `.json` file from the index directory.

---

**Q: Are the document metadata fields (`metadata` dict) also encrypted?**

No. The `metadata` field is stored in plaintext inside the `ConfidentialDocument` JSON. Only
`encrypted_content` is encrypted. Do not store sensitive data in `metadata`.
