"""
AES-256 GCM encryption engine
Provides secure encryption and decryption operations
"""
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import os
from typing import Tuple
from .config import security_config
from .utils import generate_nonce, generate_salt


class CryptoEngine:
    """AES-256-GCM encryption engine"""
    
    def __init__(self):
        self.key_size = security_config.KEY_SIZE
        self.nonce_length = security_config.NONCE_LENGTH
        self.tag_length = security_config.TAG_LENGTH
    
    def encrypt(
        self, 
        data: bytes, 
        encryption_key: bytes,
        associated_data: bytes = None
    ) -> Tuple[bytes, bytes, bytes]:
        """
        Encrypt data using AES-256-GCM
        
        Args:
            data: Data to encrypt
            encryption_key: 256-bit encryption key
            associated_data: Optional additional authenticated data (AAD)
            
        Returns:
            Tuple of (nonce, ciphertext, tag)
            Full encrypted data format: nonce + ciphertext + tag
        """
        if len(encryption_key) != self.key_size:
            raise ValueError(f"Key must be {self.key_size} bytes, got {len(encryption_key)}")
        
        # Generate random nonce
        nonce = generate_nonce(self.nonce_length)
        
        # Create cipher
        cipher = AESGCM(encryption_key)
        
        # Encrypt with authentication
        # GCM mode provides both confidentiality and authenticity
        ciphertext = cipher.encrypt(nonce, data, associated_data)
        
        # In GCM, the tag is appended to ciphertext by cryptography library
        # We need to separate it for flexibility
        actual_ciphertext = ciphertext[:-self.tag_length]
        tag = ciphertext[-self.tag_length:]
        
        return nonce, actual_ciphertext, tag
    
    def decrypt(
        self,
        nonce: bytes,
        ciphertext: bytes,
        tag: bytes,
        encryption_key: bytes,
        associated_data: bytes = None
    ) -> bytes:
        """
        Decrypt data using AES-256-GCM
        
        Args:
            nonce: Nonce used during encryption
            ciphertext: Encrypted data (without tag)
            tag: GCM authentication tag
            encryption_key: 256-bit encryption key
            associated_data: Optional additional authenticated data (AAD)
            
        Returns:
            Decrypted plaintext data
            
        Raises:
            cryptography.exceptions.InvalidTag: If authentication fails
        """
        if len(encryption_key) != self.key_size:
            raise ValueError(f"Key must be {self.key_size} bytes, got {len(encryption_key)}")
        
        cipher = AESGCM(encryption_key)
        
        # Reconstruct ciphertext with tag for decryption
        ciphertext_with_tag = ciphertext + tag
        
        try:
            plaintext = cipher.decrypt(nonce, ciphertext_with_tag, associated_data)
            return plaintext
        except Exception as e:
            raise ValueError(f"Decryption failed (possible tampering or wrong key): {str(e)}")
    
    def encrypt_to_bytes(
        self,
        data: bytes,
        encryption_key: bytes,
        associated_data: bytes = None
    ) -> bytes:
        """
        Encrypt data and return as single byte string
        Format: nonce (12 bytes) + ciphertext + tag (16 bytes)
        """
        nonce, ciphertext, tag = self.encrypt(data, encryption_key, associated_data)
        return nonce + ciphertext + tag
    
    def decrypt_from_bytes(
        self,
        encrypted_data: bytes,
        encryption_key: bytes,
        associated_data: bytes = None
    ) -> bytes:
        """
        Decrypt data from single byte string
        Expects format: nonce (12 bytes) + ciphertext + tag (16 bytes)
        """
        nonce_length = self.nonce_length
        tag_length = self.tag_length
        
        if len(encrypted_data) < nonce_length + tag_length:
            raise ValueError("Encrypted data too short")
        
        nonce = encrypted_data[:nonce_length]
        tag = encrypted_data[-tag_length:]
        ciphertext = encrypted_data[nonce_length:-tag_length]
        
        return self.decrypt(nonce, ciphertext, tag, encryption_key, associated_data)
