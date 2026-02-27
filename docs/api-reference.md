# API Reference — aumai-confidentialrag

Complete reference for all public classes, methods, and Pydantic models exported by
`aumai-confidentialrag`.

---

## Module: `aumai_confidentialrag.core`

Public exports: `DocumentEncryptor`, `ConfidentialIndex`, `AccessController`

---

### class `DocumentEncryptor`

Encrypts and decrypts document content using Fernet symmetric authenticated encryption.

Fernet provides AES-128-CBC for confidentiality and HMAC-SHA256 for integrity. A Fernet
token is URL-safe base64-encoded and includes a timestamp, an IV, a ciphertext, and an HMAC.
The HMAC covers all preceding fields, so any modification to the token is detectable on
decryption.

---

#### `DocumentEncryptor.generate_key` (static)

```python
@staticmethod
def generate_key() -> bytes
```

Generate a new Fernet key.

Returns 32 cryptographically random bytes encoded as URL-safe base64 (44 ASCII characters).
This is the key that must be passed to `encrypt` and `decrypt`.

**Returns**

`bytes` — A valid Fernet key.

**Example**

```python
from aumai_confidentialrag.core import DocumentEncryptor

key = DocumentEncryptor.generate_key()
print(len(key))   # 44
print(type(key))  # <class 'bytes'>
```

---

#### `DocumentEncryptor.encrypt`

```python
def encrypt(self, content: str, key: bytes) -> str
```

Encrypt `content` with `key`.

Encodes `content` to UTF-8 bytes, encrypts with Fernet, and returns the token as an ASCII
string. The token is safe to embed in JSON.

**Parameters**

| Name | Type | Description |
|------|------|-------------|
| `content` | `str` | Plaintext document content |
| `key` | `bytes` | Fernet key (from `generate_key` or a stored 44-byte base64 key) |

**Returns**

`str` — URL-safe base64-encoded Fernet ciphertext token.

**Raises**

| Exception | Condition |
|-----------|-----------|
| `ValueError` (from Fernet) | `key` is not a valid 32-byte URL-safe base64 Fernet key |

**Example**

```python
from aumai_confidentialrag.core import DocumentEncryptor

key = DocumentEncryptor.generate_key()
encryptor = DocumentEncryptor()
ciphertext = encryptor.encrypt("Sensitive document text.", key)
print(ciphertext[:20], "...")  # gAAAAAB...
```

---

#### `DocumentEncryptor.decrypt`

```python
def decrypt(self, ciphertext: str, key: bytes) -> str
```

Decrypt `ciphertext` with `key`.

Decodes the Fernet token, verifies the HMAC, decrypts with AES-128-CBC, and decodes the
result as UTF-8.

**Parameters**

| Name | Type | Description |
|------|------|-------------|
| `ciphertext` | `str` | A Fernet token returned by `encrypt` |
| `key` | `bytes` | The Fernet key used during encryption |

**Returns**

`str` — Original plaintext content.

**Raises**

| Exception | Condition |
|-----------|-----------|
| `cryptography.fernet.InvalidToken` | Key is wrong, token is corrupted, or HMAC verification fails |

**Example**

```python
from aumai_confidentialrag.core import DocumentEncryptor
from cryptography.fernet import InvalidToken

encryptor = DocumentEncryptor()
key = DocumentEncryptor.generate_key()
ct = encryptor.encrypt("Hello, world!", key)

try:
    plaintext = encryptor.decrypt(ct, key)
    print(plaintext)  # Hello, world!
except InvalidToken:
    print("Decryption failed")
```

---

### class `AccessController`

Enforces attribute-based access policies on document retrieval.

A policy is a `dict` of required `key: value` pairs. A requester context is also a `dict`
of attributes. Access is granted if and only if the requester context contains every
required key with the required value.

An empty policy `{}` grants unrestricted access to all requesters.

---

#### `AccessController.check`

```python
def check(
    self,
    policy: dict[str, Any],
    requester_context: dict[str, Any],
) -> bool
```

Return `True` if `requester_context` satisfies every requirement in `policy`.

Iterates over every `(required_key, required_value)` pair in `policy`. If
`requester_context.get(required_key) != required_value` for any pair, returns `False`.
Returns `True` if all pairs pass. Empty policy always returns `True`.

**Parameters**

| Name | Type | Description |
|------|------|-------------|
| `policy` | `dict[str, Any]` | Required attribute key-value pairs for the document |
| `requester_context` | `dict[str, Any]` | Attributes asserted by the requester |

**Returns**

`bool` — `True` if access is granted, `False` if denied.

**Examples**

```python
from aumai_confidentialrag.core import AccessController

ac = AccessController()

# Empty policy — always granted
assert ac.check({}, {}) is True
assert ac.check({}, {"role": "guest"}) is True

# Single attribute
assert ac.check({"clearance": "secret"}, {"clearance": "secret"}) is True
assert ac.check({"clearance": "secret"}, {"clearance": "public"}) is False

# Multiple attributes — all must match
policy = {"clearance": "secret", "department": "research"}
assert ac.check(policy, {"clearance": "secret", "department": "research"}) is True
assert ac.check(policy, {"clearance": "secret"}) is False
```

---

### class `ConfidentialIndex`

An encrypted document index supporting add, remove, search, and retrieval operations.

Documents are stored as `ConfidentialDocument` objects with their content in ciphertext.
The `search` method decrypts each eligible document in-memory, scores it, and returns
snippets. Ciphertext is never stored in decrypted form.

---

#### `ConfidentialIndex.__init__`

```python
def __init__(self, access_controller: AccessController | None = None) -> None
```

**Parameters**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `access_controller` | `AccessController \| None` | `None` | Access controller instance; a default `AccessController()` is used if `None` |

---

#### `ConfidentialIndex.add_document`

```python
def add_document(self, doc: ConfidentialDocument) -> None
```

Add an encrypted document to the index. Overwrites any existing document with the same
`doc_id`.

**Parameters**

| Name | Type | Description |
|------|------|-------------|
| `doc` | `ConfidentialDocument` | Encrypted document to add |

---

#### `ConfidentialIndex.remove_document`

```python
def remove_document(self, doc_id: str) -> None
```

Remove a document from the index by ID. No-op if the ID does not exist.

**Parameters**

| Name | Type | Description |
|------|------|-------------|
| `doc_id` | `str` | Document identifier to remove |

---

#### `ConfidentialIndex.search`

```python
def search(
    self,
    query: str,
    key: bytes,
    top_k: int = 5,
    requester_context: dict[str, Any] | None = None,
) -> list[QueryResult]
```

Search the index for documents relevant to `query`.

For each document in the index:
1. Evaluates the document's `access_policy` against `requester_context`; skips if denied.
2. Decrypts using `key`; skips silently if decryption raises `InvalidToken`.
3. Computes a TF-based relevance score. Skips documents with score 0.
4. Collects `(doc_id, score, plaintext)`, sorts descending by score, returns top-k.

**Parameters**

| Name | Type | Default | Description |
|------|------|---------|-------------|
| `query` | `str` | — | Plaintext search query |
| `key` | `bytes` | — | Fernet key for decryption |
| `top_k` | `int` | `5` | Maximum number of results to return |
| `requester_context` | `dict[str, Any] \| None` | `None` | Requester attributes for ABAC evaluation; treated as `{}` if `None` |

**Returns**

`list[QueryResult]` — Sorted by `relevance_score` descending. Each result includes
`doc_id`, `relevance_score` (clamped to [0, 1]), and `decrypted_snippet`.

**Example**

```python
from aumai_confidentialrag.core import DocumentEncryptor, ConfidentialIndex
from aumai_confidentialrag.models import ConfidentialDocument

key = DocumentEncryptor.generate_key()
encryptor = DocumentEncryptor()
index = ConfidentialIndex()

index.add_document(ConfidentialDocument(
    doc_id="doc-1",
    encrypted_content=encryptor.encrypt("The quick brown fox jumps over the lazy dog.", key),
    access_policy={},
))

results = index.search("quick fox", key, top_k=1)
for r in results:
    print(r.doc_id, r.relevance_score, r.decrypted_snippet)
```

---

#### `ConfidentialIndex.document_count`

```python
def document_count(self) -> int
```

Return the number of documents currently in the index.

---

#### `ConfidentialIndex.get_document`

```python
def get_document(self, doc_id: str) -> ConfidentialDocument
```

Retrieve a document by ID without decryption.

**Raises**

| Exception | Condition |
|-----------|-----------|
| `KeyError` | No document with the given ID exists in the index |

---

#### `ConfidentialIndex.all_doc_ids`

```python
def all_doc_ids(self) -> list[str]
```

Return a list of all document IDs currently in the index.

---

## Module: `aumai_confidentialrag.models`

Public exports: `EncryptionConfig`, `ConfidentialDocument`, `QueryResult`

All models use Pydantic v2.

---

### class `EncryptionConfig`

Configuration for the symmetric encryption scheme applied to a batch of documents.
Stored in document metadata for audit and key rotation tracking.

```python
class EncryptionConfig(BaseModel):
    algorithm: str
    key_id: str
```

**Fields**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `algorithm` | `str` | `"fernet"` | Encryption algorithm label (informational) |
| `key_id` | `str` | required | Logical key identifier for audit trails and rotation |

**Example**

```python
from aumai_confidentialrag.models import EncryptionConfig

config = EncryptionConfig(algorithm="fernet", key_id="prod-2025-q1")
print(config.model_dump_json())
# {"algorithm":"fernet","key_id":"prod-2025-q1"}
```

---

### class `ConfidentialDocument`

An encrypted document with access policy metadata. This is the unit of storage in the
`ConfidentialIndex` and in on-disk JSON files.

```python
class ConfidentialDocument(BaseModel):
    doc_id: str
    encrypted_content: str
    metadata: dict[str, Any]
    access_policy: dict[str, Any]
```

**Fields**

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `doc_id` | `str` | required | Unique document identifier (UUID recommended) |
| `encrypted_content` | `str` | required | URL-safe base64 Fernet ciphertext token |
| `metadata` | `dict[str, Any]` | `{}` | Plaintext metadata (original filename, key_id, algorithm, etc.) — NOT encrypted |
| `access_policy` | `dict[str, Any]` | `{}` | Required attributes for access; empty means unrestricted |

**Important:** `metadata` is stored in plaintext. Never put sensitive information there.

**Example**

```python
from aumai_confidentialrag.models import ConfidentialDocument
from aumai_confidentialrag.core import DocumentEncryptor

key = DocumentEncryptor.generate_key()
enc = DocumentEncryptor()

doc = ConfidentialDocument(
    doc_id="policy-q1-2025",
    encrypted_content=enc.encrypt("Revenue grew 12% in Q1.", key),
    metadata={"source": "finance/q1.txt", "key_id": "prod-2025-q1"},
    access_policy={"clearance": "confidential", "department": "finance"},
)

# Persist to JSON
import json
with open(f"{doc.doc_id}.json", "w") as f:
    f.write(doc.model_dump_json(indent=2))
```

---

### class `QueryResult`

A single result from a `ConfidentialIndex.search` call.

```python
class QueryResult(BaseModel):
    doc_id: str
    relevance_score: float
    decrypted_snippet: str | None
```

**Fields**

| Field | Type | Constraints | Description |
|-------|------|-------------|-------------|
| `doc_id` | `str` | — | ID of the matching document |
| `relevance_score` | `float` | `[0.0, 1.0]` (Pydantic `ge=0.0, le=1.0`) | Normalized TF-based relevance score |
| `decrypted_snippet` | `str \| None` | — | Plaintext excerpt up to 200 characters centered on first query term match; `None` if not extracted |

**Example**

```python
from aumai_confidentialrag.models import QueryResult

result = QueryResult(
    doc_id="policy-q1-2025",
    relevance_score=0.0412,
    decrypted_snippet="...data retention policy requires all records older than seven years...",
)
print(result.relevance_score)
```

---

## Module: `aumai_confidentialrag`

```python
__version__: str  # e.g. "0.1.0"
```

---

## CLI Reference

The CLI is implemented in `aumai_confidentialrag.cli` using Click. Entry point: `aumai-confidentialrag`.

### `aumai-confidentialrag keygen`

```
Usage: aumai-confidentialrag keygen [OPTIONS]

  Generate a new Fernet encryption key.

Options:
  --output PATH    Path to write the generated key.  [default: confidential.key]
  --help           Show this message and exit.
```

### `aumai-confidentialrag encrypt`

```
Usage: aumai-confidentialrag encrypt [OPTIONS]

  Encrypt all text files in a directory.

Options:
  --input PATH     Directory of plain-text documents.  [required]
  --output PATH    Directory to write encrypted document JSONs.  [required]
  --key PATH       Path to the Fernet key file.  [default: confidential.key]
  --key-id TEXT    Logical key identifier stored in config.  [default: default]
  --help           Show this message and exit.
```

### `aumai-confidentialrag search`

```
Usage: aumai-confidentialrag search [OPTIONS]

  Search an encrypted document index.

Options:
  --query TEXT       Search query text.  [required]
  --index PATH       Directory of encrypted document JSON files.  [required]
  --key PATH         Path to the Fernet key file.  [default: confidential.key]
  --top-k INTEGER    Maximum results.  [default: 5]
  --context TEXT     Requester context JSON for ABAC evaluation.  [default: {}]
  --help             Show this message and exit.
```

---

## Internal Helpers (not public API)

| Symbol | Description |
|--------|-------------|
| `_tokenize(text)` | Lowercase, strip punctuation, split into word tokens using `[a-z0-9]+` |
| `_tfidf_score(query_terms, document)` | Sum of per-term TF values, normalized by query term count |
| `_extract_snippet(text, query_terms, max_len)` | Extract window of `max_len` chars centered on first query term hit |
| `_SNIPPET_LENGTH` | `200` — default snippet window in characters |
