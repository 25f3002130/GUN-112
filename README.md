# GUN-112 PDF Encryption Protocol

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.1.0-orange.svg)](pyproject.toml)

**GUN-112** is a production-ready Python library for encrypting PDF files with military-grade AES-256-GCM encryption, augmented by a nanosecond-precision time-based cryptographic challenge system. It protects your documents even when users choose weak passwords.

---

## Table of Contents

- [What is GUN-112?](#what-is-gun-112)
- [Security Architecture](#security-architecture)
- [Installation](#installation)
- [Quick Start](#quick-start)
  - [Password-Based Encryption (GUN-112)](#password-based-encryption)
  - [GUN-112-GKP (Ghost Key Protocol)](#gun-112-gkp-ghost-key-protocol)
- [CLI Usage](#cli-usage)
- [Python API Reference](#python-api-reference)
  - [PDFEncryptionHandler](#pdfencryptionhandler)
  - [IdentityManager](#identitymanager)
  - [CryptoEngine](#cryptoengine)
  - [KeyManager](#keymanager)
  - [SecurityLayer](#securitylayer)
- [Configuration](#configuration)
- [Examples](#examples)
- [Running Tests](#running-tests)
- [Security Considerations](#security-considerations)
- [Applying the GKP Rename — Files to Update](#applying-the-gkp-rename--files-to-update)
- [License](#license)

---

## What is GUN-112?

GUN-112 is a layered PDF encryption protocol built around a core insight: even if a password is stolen, the encrypted file should remain uncrackable. It does this by weaving nanosecond-precision timestamps into the encryption key itself.

**Two encryption modes are supported:**

| Mode | How it works | Best for |
|---|---|---|
| **GUN-112** (password-based) | User supplies a password; multi-layer key derivation hardens it | Personal files, shared secrets |
| **GUN-112-GKP** (Ghost Key Protocol) | A random AES key is sealed with the recipient's RSA-4096 public key | Targeted delivery; no password needed |

---

## Security Architecture

GUN-112 stacks five independent security layers. Breaking the encryption requires defeating all of them simultaneously.

### Layer 1 — Argon2 Password Hashing
The user's password is hashed with Argon2id — a memory-hard, GPU-resistant algorithm. This prevents rainbow table attacks and makes brute-force attempts extremely expensive.

### Layer 2 — Dual-Pass PBKDF2 Key Derivation
The raw password is stretched through two sequential PBKDF2 passes:
- **Pass 1**: PBKDF2-HMAC-SHA256 at 100,000 iterations
- **Pass 2**: PBKDF2-HMAC-SHA512 at 10,000 iterations

This ensures the encryption key is deterministic (same password + salt = same key, every time) while being computationally costly to brute-force.

### Layer 3 — GUN-112 Time-Based Challenge
At the moment of encryption, a challenge is created from the current time captured at nanosecond precision. This challenge is salted and hashed (SHA-256), then stored alongside the ciphertext. During decryption, the challenge is re-verified — any tampering with the file causes this check to fail.

The timestamp component is also mixed into the final AES key, meaning the key varies with each encryption even if the password is identical. Reverse-engineering this requires knowing the exact nanosecond of encryption, which is impossible after the fact.

### Layer 4 — AES-256-GCM Authenticated Encryption
Actual file content is encrypted with AES-256 in GCM mode. GCM provides both confidentiality (the content is hidden) and authenticity (any modification to the ciphertext is detected and rejected).

### Layer 5 — Rate Limiting
Decryption attempts are tracked per file (by SHA-256 fingerprint). After 5 failed attempts, the file is locked for 15 minutes. Lockout state persists to disk in `.security/lockout_log.json`.

---

## Installation

**From PyPI (recommended):**
```bash
pip install gun112
```

**From source:**
```bash
git clone https://github.com/25f3002130/GUN-112.git
cd GUN-112
pip install -e .
```

**Requirements:** Python 3.9+, `cryptography>=42.0.2`, `argon2-cffi>=23.1.0`

---

## Quick Start

### Password-Based Encryption

```python
from gun112 import PDFEncryptionHandler

handler = PDFEncryptionHandler()

# Read your PDF
with open("document.pdf", "rb") as f:
    pdf_data = f.read()

# Encrypt
encrypted = handler.encrypt_pdf(pdf_data, password="MySecurePassword!")

# Save encrypted file
with open("document.pdf.encrypted", "wb") as f:
    f.write(encrypted)

# Decrypt later
with open("document.pdf.encrypted", "rb") as f:
    encrypted_data = f.read()

decrypted_pdf, metadata = handler.decrypt_pdf(encrypted_data, password="MySecurePassword!")

with open("document_restored.pdf", "wb") as f:
    f.write(decrypted_pdf)
```

### GUN-112-GKP (Ghost Key Protocol)

GUN-112-GKP requires no shared password. The sender uses the recipient's public **GKP Identity Token**; only the recipient's physical device (which holds the matching private key) can decrypt the file.

**Step 1 — Recipient generates their GKP identity (one-time setup):**
```python
from gun112.identity import IdentityManager

manager = IdentityManager()
token = manager.generate_identity()   # optionally pass a passphrase
print("Share this token with senders:\n", token)
```

**Step 2 — Sender encrypts for the recipient:**
```python
from gun112 import PDFEncryptionHandler

handler = PDFEncryptionHandler()

with open("document.pdf", "rb") as f:
    pdf_data = f.read()

recipient_token = "..."   # GKP Identity Token provided by the recipient

encrypted = handler.encrypt_pdf_for_recipient(pdf_data, recipient_token)

with open("document.pdf.encrypted", "wb") as f:
    f.write(encrypted)
```

**Step 3 — Recipient decrypts on their device:**
```python
from gun112 import PDFEncryptionHandler

handler = PDFEncryptionHandler()

with open("document.pdf.encrypted", "rb") as f:
    encrypted_data = f.read()

decrypted_pdf, metadata = handler.decrypt_pdf_identity(encrypted_data)

with open("document_restored.pdf", "wb") as f:
    f.write(decrypted_pdf)
```

---

## CLI Usage

GUN-112 ships with a `gun112` command-line tool installed automatically with the package.

```
gun112 help                                           Show all commands
gun112 encrypt <file>                                 Encrypt a PDF with a password (GUN-112)
gun112 encrypt <file> --recipient <TOKEN>             Encrypt for a specific recipient (GUN-112-GKP)
gun112 decrypt <file>                                 Decrypt (auto-detects GUN-112 vs GKP)
gun112 generate-identity                              Generate your GKP Identity Token
gun112 show-identity                                  Display your GKP Identity Token
gun112 reset-identity                                 Delete your GKP identity (irreversible)
```

**Options:**

| Flag | Description |
|---|---|
| `-o`, `--output PATH` | Custom output file path |
| `--recipient TOKEN` | Recipient's GKP Identity Token (enables GUN-112-GKP mode) |

**Examples:**

```bash
# Password-based (GUN-112) — prompted to enter and confirm the password
gun112 encrypt report.pdf
gun112 decrypt report.pdf.encrypted

# GUN-112-GKP — no password needed
gun112 generate-identity
gun112 show-identity                          # copy the token and send it to the sender
gun112 encrypt report.pdf --recipient <GKP_TOKEN>
gun112 decrypt report.pdf.encrypted          # auto-detects GKP mode
```

---

## Python API Reference

### PDFEncryptionHandler

The main entry point for all encryption and decryption operations.

```python
from gun112 import PDFEncryptionHandler
handler = PDFEncryptionHandler()
```

#### `encrypt_pdf(pdf_data, password, metadata=None) → bytes`

Encrypts a PDF using password-based GUN-112. Raises `ValueError` on wrong password, challenge failure, tampering, or lockout.

| Parameter | Type | Description |
|---|---|---|
| `pdf_data` | `bytes` | Raw PDF file content |
| `password` | `str` | User password |
| `metadata` | `dict`, optional | Arbitrary key-value metadata to encrypt alongside the PDF |

Returns the encrypted container as `bytes`.

#### `decrypt_pdf(encrypted_package, password) → tuple[bytes, dict | None]`

Decrypts a password-locked GUN-112 PDF.

| Parameter | Type | Description |
|---|---|---|
| `encrypted_package` | `bytes` | Output of `encrypt_pdf` |
| `password` | `str` | User password |

Returns `(pdf_bytes, metadata_dict_or_None)`.

#### `encrypt_pdf_for_recipient(pdf_data, recipient_token, metadata=None) → bytes`

Encrypts a PDF using GUN-112-GKP for a specific recipient. No password required. A random AES-256 key is generated and sealed using the recipient's RSA-4096 GKP Identity Token.

| Parameter | Type | Description |
|---|---|---|
| `pdf_data` | `bytes` | Raw PDF file content |
| `recipient_token` | `str` | Recipient's GKP Identity Token |
| `metadata` | `dict`, optional | Arbitrary key-value metadata to encrypt alongside the PDF |

#### `decrypt_pdf_identity(encrypted_package, passphrase=None) → tuple[bytes, dict | None]`

Decrypts a GKP-locked PDF using this device's GKP private key.

| Parameter | Type | Description |
|---|---|---|
| `encrypted_package` | `bytes` | Output of `encrypt_pdf_for_recipient` |
| `passphrase` | `str`, optional | Passphrase if the GKP private key was protected at generation time |

---

### IdentityManager

Manages RSA-4096 keypairs and GKP Identity Tokens.

```python
from gun112.identity import IdentityManager
manager = IdentityManager()
```

| Method | Description |
|---|---|
| `generate_identity(passphrase=None) → str` | Generate a new GKP keypair; returns the public Identity Token |
| `get_identity_token() → str` | Retrieve the stored GKP Identity Token |
| `get_identity_fingerprint(token=None) → str` | Get a human-readable colon-separated fingerprint |
| `has_identity() → bool` | Check if a GKP identity exists on this device |
| `reset_identity()` | Delete the keypair from disk (irreversible) |
| `encrypt_symmetric_key(key, token) → bytes` | RSA-OAEP encrypt an AES key with a recipient's GKP token |
| `decrypt_symmetric_key(encrypted_key, passphrase=None) → bytes` | RSA-OAEP decrypt using local GKP private key |

GKP private keys are stored at `~/.gun112/private_key.pem` with `0o600` permissions (owner read/write only).

---

### CryptoEngine

Low-level AES-256-GCM encryption primitives.

```python
from gun112 import CryptoEngine
engine = CryptoEngine()
```

| Method | Description |
|---|---|
| `encrypt(data, key, aad=None) → (nonce, ciphertext, tag)` | Encrypt; returns separate components |
| `decrypt(nonce, ciphertext, tag, key, aad=None) → bytes` | Decrypt and verify |
| `encrypt_to_bytes(data, key, aad=None) → bytes` | Encrypt to single byte string (`nonce + ciphertext + tag`) |
| `decrypt_from_bytes(encrypted, key, aad=None) → bytes` | Decrypt from single byte string |

---

### KeyManager

Password hashing and key derivation.

```python
from gun112 import KeyManager
km = KeyManager()
```

| Method | Description |
|---|---|
| `derive_key_from_password(password, salt=None) → (key, salt)` | PBKDF2 dual-pass key derivation |
| `hash_password(password) → str` | Argon2 hash for storage |
| `verify_password(password, argon2_hash) → bool` | Verify a password against stored Argon2 hash |

---

### SecurityLayer

Rate-limiting and brute-force protection.

```python
from gun112 import SecurityLayer
layer = SecurityLayer(max_attempts=5)
```

| Method | Description |
|---|---|
| `record_attempt(identifier, success=False) → (allowed, message)` | Record a decryption attempt; returns whether allowed to proceed |
| `is_locked(identifier) → bool` | Check if an identifier is currently locked out |
| `get_status(identifier) → dict` | Get attempt count, lock status, and remaining attempts |
| `reset_attempts(identifier)` | Manually reset attempt counter |

---

## Configuration

Security parameters are centralized in `SecurityConfig` and available via the `security_config` singleton:

```python
from gun112 import security_config

print(security_config.ENCRYPTION_PROTOCOL)    # GUN-112
print(security_config.GKP_PROTOCOL)           # GUN-112-GKP
print(security_config.ENCRYPTION_ALGORITHM)   # AES-256-GCM
print(security_config.MAX_DECRYPTION_ATTEMPTS) # 5
print(security_config.LOCKOUT_DURATION)        # 15 minutes
```

| Parameter | Default | Description |
|---|---|---|
| `ENCRYPTION_PROTOCOL` | `"GUN-112"` | Outer protocol identifier (all containers) |
| `GKP_PROTOCOL` | `"GUN-112-GKP"` | GKP sub-protocol identifier |
| `GKP_LOCK_MODE` | `"GKP"` | Value stored in container's `lock_mode` field |
| `KEY_SIZE` | 32 bytes | AES key length (256 bits) |
| `ARGON2_TIME_COST` | 4 | Argon2 iteration count |
| `ARGON2_MEMORY_COST` | 128 MB | Argon2 memory requirement |
| `ARGON2_PARALLELISM` | 4 | Argon2 thread count |
| `KEY_STRETCH_ITERATIONS` | 100,000 | PBKDF2 iterations (first pass) |
| `MAX_DECRYPTION_ATTEMPTS` | 5 | Failed attempts before lockout |
| `LOCKOUT_DURATION` | 15 minutes | Lockout duration |
| `TIMESTAMP_TOLERANCE` | 300 seconds | Tolerance window for timestamp validation |

---

## Examples

The `examples/` directory contains ready-to-run scripts:

```bash
# Basic password-based encryption and decryption
python examples/basic_usage.py

# Advanced configuration and GUN-112-GKP (Ghost Key Protocol)
python examples/advanced_config.py
```

**Encrypt a real file in three lines:**
```python
from gun112 import PDFEncryptionHandler
handler = PDFEncryptionHandler()
open("out.encrypted","wb").write(handler.encrypt_pdf(open("doc.pdf","rb").read(), "password"))
```

**Attach metadata to an encrypted file:**
```python
metadata = {"author": "Alice", "classification": "CONFIDENTIAL"}
encrypted = handler.encrypt_pdf(pdf_data, "password", metadata=metadata)

pdf, meta = handler.decrypt_pdf(encrypted, "password")
print(meta)  # {'author': 'Alice', 'classification': 'CONFIDENTIAL'}
```

---

## Running Tests

```bash
pip install -e ".[dev]"
pytest
pytest --cov=gun112 --cov-report=term-missing   # with coverage
```

Tests cover encryption/decryption correctness, wrong-password rejection, rate limiting, GKP identity keypair operations, and GUN-112 challenge verification.

---

## Security Considerations

- **Lost password**: Password-locked files cannot be recovered without the original password. There is no back door.
- **Lost GKP identity**: If you delete your GKP identity (or lose the device), any GKP-encrypted files targeting that identity are permanently unrecoverable. Back up `~/.gun112/private_key.pem` before resetting.
- **GKP passphrase protection**: When generating a GKP identity, supply a passphrase to encrypt the private key at rest on disk.
- **Rate limiting persistence**: Lockout state is written to `.security/lockout_log.json` in the working directory. In server deployments, ensure this path is writable and persistent.
- **Timestamp validation**: GUN-112 verifies that the challenge timestamp in the encrypted metadata matches the one in the container. Any tampering with either field causes decryption to fail.

---

## Applying the GKP Rename — Files to Update

The GUN-112-GKP (Ghost Key Protocol) naming was introduced after the initial release. If you are applying this rename to an existing copy of the codebase, here are every file that needs to change and exactly what to update in each.

> **Note on backward compatibility**: The outer `"protocol"` field in all encrypted containers stays `"GUN-112"`. Only the `lock_mode` value changes from `"identity"` → `"GKP"`. This means **any files already encrypted with the old `lock_mode: "identity"` will fail to auto-detect correctly** until `pdf_handler.py` and `cli.py` are updated. Re-encrypt important files after the update if backward compatibility matters.

---

### `src/gun112/config.py`

Add two new constants to the `SecurityConfig` class:

```python
# GUN-112-GKP: Ghost Key Protocol (identity/asymmetric sub-protocol)
GKP_PROTOCOL = "GUN-112-GKP"
GKP_LOCK_MODE = "GKP"  # value stored in the container's lock_mode field
```

This is the single source of truth for both strings. Every other file reads from `security_config` rather than hardcoding them.

---

### `src/gun112/pdf_handler.py`

Three changes:

**1. Module docstring** — update the description of the identity-based mode to say "GUN-112-GKP (Ghost Key Protocol)".

**2. `encrypt_pdf_for_recipient`** — the container dict currently writes `"lock_mode": "identity"`. Replace with:

```python
"sub_protocol": security_config.GKP_PROTOCOL,  # "GUN-112-GKP"
"lock_mode": security_config.GKP_LOCK_MODE,     # "GKP"
```

Same change applies inside `encryption_metadata` (the dict that gets encrypted alongside the PDF).

**3. `decrypt_pdf` and `decrypt_pdf_identity`** — both methods check `lock_mode` to route or reject files. Update the string comparisons:

```python
# decrypt_pdf — reject GKP files
if lock_mode == security_config.GKP_LOCK_MODE:   # was: == "identity"
    raise ValueError("This file is GKP-locked (Ghost Key Protocol)...")

# decrypt_pdf_identity — require GKP files
if lock_mode != security_config.GKP_LOCK_MODE:   # was: != "identity"
    raise ValueError("This file is password-locked (GUN-112), not GKP-locked...")
```

---

### `src/gun112/identity.py`

No functional changes — this file only needs its **docstrings and comments** updated. Rename every occurrence of "Identity Manager" / "identity-based" / "identity-locked" to use "GKP" / "Ghost Key Protocol" language. The class name `IdentityManager` and all method names stay the same.

---

### `src/gun112/cli.py`

Two changes:

**1. Auto-detect block in `decrypt_command`** — currently compares `lock_mode == "identity"`. Update to:

```python
if lock_mode == security_config.GKP_LOCK_MODE:
```

**2. User-facing text** — update the banner, help strings, and info/success messages to say "GUN-112-GKP" and "Ghost Key Protocol" where they currently say "identity-based" or "Identity Token". No command names change (`generate-identity`, `show-identity`, `reset-identity` stay as-is for CLI backward compatibility).

---

### `src/gun112/__init__.py`

Add one new public constant:

```python
__gkp_protocol__ = "GUN-112-GKP"
```

Update the module docstring to mention both modes by name.

---

### `examples/basic_usage.py` and `examples/advanced_config.py`

Update comments and `print()` strings that refer to "identity-based encryption" to say "GUN-112-GKP (Ghost Key Protocol)". No functional code changes needed in the examples.

---

### Files that do **not** need changes

| File | Reason |
|---|---|
| `crypto_engine.py` | Pure AES-256-GCM logic; protocol-agnostic |
| `key_manager.py` | Pure key derivation; no protocol references |
| `security_layer.py` | Pure rate-limiting; no protocol references |
| `utils.py` | Pure utility functions; no protocol references |
| `gun112_challenge.py` | The challenge system is shared by both modes; no GKP-specific references |
| `pyproject.toml` | Package metadata; no protocol strings |
| `tests/` | Test logic uses method names, not protocol strings — no changes needed unless your tests assert on the `lock_mode` string value directly |

---

## License

MIT License — see [LICENSE](LICENSE) for full terms.