"""
GUN-112 PDF Encryption Protocol Suite

Two encryption modes:

  GUN-112 (password-based)
    AES-256-GCM with Argon2/PBKDF2 key derivation, time-based cryptographic
    challenge, and rate-limiting brute-force protection.

  GUN-112-GKP (Ghost Key Protocol — identity/asymmetric mode)
    RSA-4096 key wrapping via the recipient's public Identity Token.
    No shared password required. Only the recipient's physical device
    (holding the matching GKP private key) can decrypt the file.
"""

from .config import security_config
from .crypto_engine import CryptoEngine
from .key_manager import KeyManager
from .security_layer import SecurityLayer
from .pdf_handler import PDFEncryptionHandler
from .identity import IdentityManager
from .utils import (
    generate_salt,
    generate_nonce,
    get_current_timestamp,
    verify_password_hash,
    create_fingerprint
)

__version__ = "1.1.0"
__author__ = "Security Team"
__protocol__ = "GUN-112"
__gkp_protocol__ = "GUN-112-GKP"

__all__ = [
    "PDFEncryptionHandler",
    "IdentityManager",
    "CryptoEngine",
    "KeyManager",
    "SecurityLayer",
    "security_config",
    "generate_salt",
    "generate_nonce",
    "get_current_timestamp",
    "verify_password_hash",
    "create_fingerprint"
]