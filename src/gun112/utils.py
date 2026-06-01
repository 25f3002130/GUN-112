"""
Utility functions for encryption layer
"""
import os
import hashlib
import hmac
from typing import Tuple
from datetime import datetime


def generate_salt(length: int = 16) -> bytes:
    """Generate cryptographically secure random salt"""
    return os.urandom(length)


def generate_nonce(length: int = 12) -> bytes:
    """Generate nonce for GCM mode"""
    return os.urandom(length)


def get_current_timestamp() -> str:
    """Get current timestamp in ISO format"""
    return datetime.utcnow().isoformat()


def hash_password_with_salt(password: str, salt: bytes) -> str:
    """
    Create a hash of password with salt for verification
    Uses PBKDF2 for additional security
    """
    import hashlib
    password_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt,
        100000
    )
    return password_hash.hex()


def verify_password_hash(password: str, salt: bytes, stored_hash: str) -> bool:
    """Verify password against stored hash"""
    computed_hash = hash_password_with_salt(password, salt)
    # Use constant-time comparison to prevent timing attacks
    return hmac.compare_digest(computed_hash, stored_hash)


def create_fingerprint(data: bytes) -> str:
    """Create fingerprint of data for integrity verification"""
    return hashlib.sha256(data).hexdigest()


def derive_key_component_from_timestamp() -> bytes:
    """
    Derive a key component from current timestamp
    This makes encrypted content time-specific and adds another layer
    """
    current_hour = datetime.utcnow().replace(minute=0, second=0, microsecond=0)
    timestamp_str = current_hour.isoformat()
    return hashlib.sha256(timestamp_str.encode()).digest()
