"""
Key management with Argon2 key derivation
Provides secure key generation from passwords
"""
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHash
import os
import hashlib
from typing import Tuple
from .config import security_config
from .utils import generate_salt


class KeyManager:
    """Manages secure key derivation and password hashing"""
    
    def __init__(self):
        self.hasher = PasswordHasher(
            time_cost=security_config.ARGON2_TIME_COST,
            memory_cost=security_config.ARGON2_MEMORY_COST,
            parallelism=security_config.ARGON2_PARALLELISM,
            salt_len=security_config.ARGON2_SALT_LENGTH,
        )
    
    def derive_key_from_password(
        self, 
        password: str, 
        salt: bytes = None
    ) -> Tuple[bytes, bytes]:
        """
        Derive encryption key from password using PBKDF2 with high security
        
        Args:
            password: User password
            salt: Optional salt (generates new if not provided)
            
        Returns:
            Tuple of (encryption_key, salt)
            
        Note: Uses PBKDF2 for deterministic key derivation (same input = same output)
              This is critical for decryption - same password + salt must produce same key
        """
        if salt is None:
            salt = generate_salt(security_config.ARGON2_SALT_LENGTH)
        
        # Use PBKDF2 for deterministic key derivation
        # PBKDF2 is deterministic: same password + salt = same key every time
        # This is essential for decryption to work
        password_bytes = password.encode('utf-8')
        
        # First level: PBKDF2 with SHA256 and high iterations
        key_material = hashlib.pbkdf2_hmac(
            'sha256',
            password_bytes,
            salt,
            security_config.KEY_STRETCH_ITERATIONS,
            dklen=security_config.KEY_SIZE
        )
        
        # Second level: Additional PBKDF2 with SHA512 for defense-in-depth
        encryption_key = hashlib.pbkdf2_hmac(
            'sha512',
            key_material,
            salt,
            security_config.KEY_STRETCH_ITERATIONS // 10,  # Fewer iterations for 2nd pass
            dklen=security_config.KEY_SIZE
        )
        
        return encryption_key, salt
    
    def verify_password(self, password: str, argon2_hash: str) -> bool:
        """
        Verify password against Argon2 hash
        
        Args:
            password: User password to verify
            argon2_hash: Stored Argon2 hash
            
        Returns:
            True if password matches, False otherwise
        """
        try:
            self.hasher.verify(argon2_hash, password)
            return True
        except (VerifyMismatchError, InvalidHash):
            return False
    
    def hash_password(self, password: str) -> str:
        """
        Create Argon2 hash of password for storage
        
        Args:
            password: Password to hash
            
        Returns:
            Argon2 hash string
        """
        return self.hasher.hash(password)
