"""
PDF Encryption Layer Package
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

