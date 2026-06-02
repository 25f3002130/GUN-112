"""
PDF Encryption and Decryption Handler with GUN-112 Protocol
Main interface for encrypting and decrypting PDFs with time-based cryptographic challenge
Supports both password-based and identity-based (asymmetric) encryption.
"""
import json
import os
import base64
from typing import Optional, Dict
from pathlib import Path
import hashlib

from .key_manager import KeyManager
from .crypto_engine import CryptoEngine
from .security_layer import SecurityLayer
from .gun112_challenge import GUN112Challenge
from .identity import IdentityManager
from .utils import get_current_timestamp, derive_key_component_from_timestamp
from .config import security_config


class PDFEncryptionHandler:
    """
    Handles PDF encryption and decryption with GUN-112 Protocol
    
    GUN-112 Security Features:
    - AES-256-GCM encryption
    - Time-based cryptographic challenge (nanosecond precision)
    - Salted challenge hash to prevent reverse engineering
    - Argon2 password hashing
    - Rate limiting on decryption attempts (5 max, 15-min lockout)
    - Key stretching against brute-force
    - Multi-layer defense: password verification + challenge verification required
    """
    
    def __init__(self):
        self.key_manager = KeyManager()
        self.crypto_engine = CryptoEngine()
        self.security_layer = SecurityLayer(
            max_attempts=security_config.MAX_DECRYPTION_ATTEMPTS,
            lockout_duration=security_config.LOCKOUT_DURATION
        )
        self.gun112_challenge = GUN112Challenge()
        self.identity_manager = IdentityManager()
    
    def encrypt_pdf(
        self,
        pdf_data: bytes,
        password: str,
        metadata: Optional[Dict] = None
    ) -> bytes:
        """
        Encrypt PDF with GUN-112 protocol and security layers
        
        Args:
            pdf_data: Raw PDF file content
            password: User password for encryption
            metadata: Optional metadata to include (encrypted)
            
        Returns:
            Encrypted package containing all necessary data with GUN-112 challenge
            Format: custom encrypted container with challenge hash
        """
        # Create GUN-112 cryptographic challenge
        challenge = self.gun112_challenge.create_challenge()
        
        # Derive encryption key from password
        encryption_key, salt = self.key_manager.derive_key_from_password(password)
        
        # Generate password hash for storage (for verification without storing password)
        password_hash = self.key_manager.hash_password(password)
        
        # Add timestamp-based key component for extra security
        # Use the challenge timestamp to derive a consistent component
        timestamp_component = self._derive_timestamp_component(challenge["datetime_iso"])
        
        # Combine keys for final encryption key
        # This ensures the encrypted content has multiple layers of protection
        combined_key = self._combine_keys(encryption_key, timestamp_component)
        
        # Create encryption metadata WITH GUN-112 challenge
        encryption_metadata = {
            "protocol": "GUN-112",
            "timestamp": challenge["datetime_iso"],
            "password_hash": password_hash,
            "salt": base64.b64encode(salt).decode('utf-8'),
            "algorithm": security_config.ENCRYPTION_ALGORITHM,
            "version": "1.0",
            # GUN-112 Challenge components
            "gun112_challenge": {
                "challenge_hash": challenge["challenge_hash"],
                "nanoseconds": challenge["nanoseconds"],
                "microseconds": challenge["microseconds"],
                "milliseconds": challenge["milliseconds"],
                "salt": challenge["salt"],
                "datetime_iso": challenge["datetime_iso"]
            }
        }
        
        if metadata:
            encryption_metadata["user_metadata"] = metadata
        
        # Serialize metadata
        metadata_json = json.dumps(encryption_metadata).encode('utf-8')
        
        # Encrypt PDF data
        encrypted_pdf = self.crypto_engine.encrypt_to_bytes(pdf_data, combined_key)
        
        # Encrypt metadata
        encrypted_metadata = self.crypto_engine.encrypt_to_bytes(metadata_json, encryption_key)
        
        # Create final container
        container = self._create_container(
            encrypted_pdf=encrypted_pdf,
            encrypted_metadata=encrypted_metadata,
            salt=salt,
            timestamp=challenge["datetime_iso"],
            protocol="GUN-112"
        )
        
        return container
    
    def decrypt_pdf(
        self,
        encrypted_package: bytes,
        password: str
    ) -> tuple[bytes, Optional[Dict]]:
        """
        Decrypt PDF with GUN-112 protocol verification
        
        Args:
            encrypted_package: Encrypted container from encrypt_pdf
            password: User password for decryption
            
        Returns:
            Tuple of (decrypted_pdf_data, metadata)
            
        Raises:
            ValueError: If password incorrect, challenge fails, tampering detected, or too many attempts
        """
        # Extract container contents
        try:
            container_data = json.loads(encrypted_package.decode('utf-8'))
        except:
            raise ValueError("Invalid encrypted package format")
        
        # Get resource identifier for rate limiting
        resource_id = hashlib.sha256(encrypted_package[:100]).hexdigest()
        
        # Check rate limiting
        allowed, message = self.security_layer.record_attempt(resource_id, success=False)
        if not allowed:
            raise ValueError(f"Decryption locked: {message}")
        
        # Extract components
        salt_b64 = container_data.get("salt")
        encrypted_pdf_b64 = container_data.get("encrypted_pdf")
        encrypted_metadata_b64 = container_data.get("encrypted_metadata")
        protocol = container_data.get("protocol", "Unknown")
        
        # Verify protocol
        if protocol != "GUN-112":
            raise ValueError(f"Unsupported encryption protocol: {protocol}. Expected GUN-112")
        
        # Reject identity-locked files early
        lock_mode = container_data.get("lock_mode", "password")
        if lock_mode == "identity":
            raise ValueError(
                "This file is identity-locked, not password-locked. "
                "Use decrypt_pdf_identity() or 'gun112 decrypt' (which auto-detects) instead."
            )
        
        # Decode from base64
        salt = base64.b64decode(salt_b64)
        encrypted_pdf = base64.b64decode(encrypted_pdf_b64)
        encrypted_metadata = base64.b64decode(encrypted_metadata_b64)
        
        # Derive encryption key from password
        try:
            encryption_key, _ = self.key_manager.derive_key_from_password(password, salt)
        except Exception as e:
            raise ValueError(f"Failed to derive key: {str(e)}")
        
        # Decrypt metadata first to verify password
        try:
            metadata_json = self.crypto_engine.decrypt_from_bytes(
                encrypted_metadata,
                encryption_key
            )
            metadata = json.loads(metadata_json.decode('utf-8'))
        except Exception as e:
            # Failed to decrypt metadata - likely wrong password
            raise ValueError("Decryption failed: Invalid password or corrupted data")
        
        # VERIFY GUN-112 CHALLENGE
        # This ensures the file wasn't tampered with and is legitimate
        gun112_challenge_data = metadata.get("gun112_challenge")
        if not gun112_challenge_data:
            raise ValueError("GUN-112 challenge data missing: File may be corrupted or tampered with")
        
        # Verify the challenge hash integrity
        is_challenge_valid = self.gun112_challenge.verify_challenge(gun112_challenge_data)
        if not is_challenge_valid:
            raise ValueError("GUN-112 challenge verification failed: File may be tampered with")
        
        # Validate timestamp if enabled
        if security_config.ENABLE_TIMESTAMP_VALIDATION:
            self._validate_timestamp(gun112_challenge_data.get("datetime_iso"), 
                                    metadata.get("timestamp"))
        
        # Recreate combined key using stored GUN-112 challenge timestamp
        # This ensures decryption uses the exact same key as encryption
        timestamp_component = self._derive_timestamp_component(gun112_challenge_data.get("datetime_iso"))
        combined_key = self._combine_keys(encryption_key, timestamp_component)
        
        # Decrypt PDF
        try:
            pdf_data = self.crypto_engine.decrypt_from_bytes(
                encrypted_pdf,
                combined_key
            )
        except Exception as e:
            raise ValueError(f"Failed to decrypt PDF: {str(e)}")
        
        # Record successful attempt
        self.security_layer.record_attempt(resource_id, success=True)
        
        # Return extracted metadata if present
        user_metadata = metadata.get("user_metadata")
        
        return pdf_data, user_metadata
    
    def _combine_keys(self, base_key: bytes, timestamp_component: bytes) -> bytes:
        """
        Combine base encryption key with timestamp component
        Creates an additional security layer
        """
        import hashlib
        combined = hashlib.sha256(base_key + timestamp_component).digest()
        return combined
    
    def _derive_timestamp_component(self, timestamp: str) -> bytes:
        """
        Derive timestamp component from a specific timestamp string
        Used during both encryption and decryption with the SAME timestamp
        """
        import hashlib
        return hashlib.sha256(timestamp.encode('utf-8')).digest()
    
    def _create_container(
        self,
        encrypted_pdf: bytes,
        encrypted_metadata: bytes,
        salt: bytes,
        timestamp: str,
        protocol: str = "GUN-112"
    ) -> bytes:
        """
        Create encrypted container with all components
        Format: JSON with base64-encoded binary data
        """
        container = {
            "protocol": protocol,
            "version": "1.0",
            "algorithm": security_config.ENCRYPTION_ALGORITHM,
            "salt": base64.b64encode(salt).decode('utf-8'),
            "encrypted_pdf": base64.b64encode(encrypted_pdf).decode('utf-8'),
            "encrypted_metadata": base64.b64encode(encrypted_metadata).decode('utf-8'),
            "timestamp": timestamp
        }
        
        return json.dumps(container).encode('utf-8')
    
    def _validate_timestamp(self, stored_timestamp: str, metadata_timestamp: str):
        """Validate that timestamps haven't been tampered with"""
        if stored_timestamp != metadata_timestamp:
            raise ValueError("Timestamp validation failed: Possible tampering detected")

    # =========================================================================
    # Identity-Based (Asymmetric) Encryption / Decryption
    # =========================================================================

    def encrypt_pdf_for_recipient(
        self,
        pdf_data: bytes,
        recipient_token: str,
        metadata: Optional[Dict] = None
    ) -> bytes:
        """
        Encrypt PDF targeted at a specific recipient's Identity Token.
        
        No password is needed. A random AES-256 key is generated and then
        encrypted with the recipient's RSA public key. Only the recipient's
        physical device (which holds the matching private key) can decrypt it.
        
        Args:
            pdf_data: Raw PDF file content.
            recipient_token: The recipient's public Identity Token string.
            metadata: Optional metadata to include (encrypted).
        
        Returns:
            Encrypted package (identity-locked).
        """
        # Create GUN-112 cryptographic challenge
        challenge = self.gun112_challenge.create_challenge()

        # Generate a random AES-256 symmetric key (no password needed)
        symmetric_key = os.urandom(security_config.KEY_SIZE)

        # Derive timestamp component and combine for final encryption key
        timestamp_component = self._derive_timestamp_component(challenge["datetime_iso"])
        combined_key = self._combine_keys(symmetric_key, timestamp_component)

        # Encrypt the symmetric key with the recipient's RSA public key
        encrypted_symmetric_key = self.identity_manager.encrypt_symmetric_key(
            symmetric_key, recipient_token
        )

        # Build metadata
        encryption_metadata = {
            "protocol": "GUN-112",
            "lock_mode": "identity",
            "timestamp": challenge["datetime_iso"],
            "algorithm": security_config.ENCRYPTION_ALGORITHM,
            "version": "1.0",
            "gun112_challenge": {
                "challenge_hash": challenge["challenge_hash"],
                "nanoseconds": challenge["nanoseconds"],
                "microseconds": challenge["microseconds"],
                "milliseconds": challenge["milliseconds"],
                "salt": challenge["salt"],
                "datetime_iso": challenge["datetime_iso"]
            }
        }
        if metadata:
            encryption_metadata["user_metadata"] = metadata

        metadata_json = json.dumps(encryption_metadata).encode("utf-8")

        # Encrypt PDF data with the combined key
        encrypted_pdf = self.crypto_engine.encrypt_to_bytes(pdf_data, combined_key)

        # Encrypt metadata with the raw symmetric key
        encrypted_metadata = self.crypto_engine.encrypt_to_bytes(metadata_json, symmetric_key)

        # Build the container (includes the RSA-encrypted symmetric key)
        container = {
            "protocol": "GUN-112",
            "lock_mode": "identity",
            "version": "1.0",
            "algorithm": security_config.ENCRYPTION_ALGORITHM,
            "encrypted_symmetric_key": base64.b64encode(encrypted_symmetric_key).decode("utf-8"),
            "encrypted_pdf": base64.b64encode(encrypted_pdf).decode("utf-8"),
            "encrypted_metadata": base64.b64encode(encrypted_metadata).decode("utf-8"),
            "timestamp": challenge["datetime_iso"]
        }

        return json.dumps(container).encode("utf-8")

    def decrypt_pdf_identity(
        self,
        encrypted_package: bytes,
        passphrase: Optional[str] = None
    ) -> tuple[bytes, Optional[Dict]]:
        """
        Decrypt an identity-locked PDF using this device's private key.
        
        Args:
            encrypted_package: Encrypted container from encrypt_pdf_for_recipient.
            passphrase: Optional passphrase if the private key was protected.
        
        Returns:
            Tuple of (decrypted_pdf_data, metadata).
        
        Raises:
            ValueError: If this device does not hold the correct private key.
        """
        try:
            container_data = json.loads(encrypted_package.decode("utf-8"))
        except Exception:
            raise ValueError("Invalid encrypted package format")

        protocol = container_data.get("protocol", "Unknown")
        if protocol != "GUN-112":
            raise ValueError(f"Unsupported encryption protocol: {protocol}. Expected GUN-112")

        lock_mode = container_data.get("lock_mode", "password")
        if lock_mode != "identity":
            raise ValueError(
                "This file is password-locked, not identity-locked. "
                "Use the standard decrypt_pdf() method with a password instead."
            )

        # Decode components
        encrypted_symmetric_key = base64.b64decode(container_data["encrypted_symmetric_key"])
        encrypted_pdf = base64.b64decode(container_data["encrypted_pdf"])
        encrypted_metadata = base64.b64decode(container_data["encrypted_metadata"])

        # Decrypt the symmetric key using this device's private key
        symmetric_key = self.identity_manager.decrypt_symmetric_key(
            encrypted_symmetric_key, passphrase
        )

        # Decrypt metadata
        try:
            metadata_json = self.crypto_engine.decrypt_from_bytes(
                encrypted_metadata, symmetric_key
            )
            metadata = json.loads(metadata_json.decode("utf-8"))
        except Exception:
            raise ValueError("Decryption failed: Could not decrypt metadata")

        # Verify GUN-112 challenge
        gun112_challenge_data = metadata.get("gun112_challenge")
        if not gun112_challenge_data:
            raise ValueError("GUN-112 challenge data missing: File may be corrupted")

        if not self.gun112_challenge.verify_challenge(gun112_challenge_data):
            raise ValueError("GUN-112 challenge verification failed: File may be tampered with")

        # Validate timestamps
        if security_config.ENABLE_TIMESTAMP_VALIDATION:
            self._validate_timestamp(
                gun112_challenge_data.get("datetime_iso"),
                metadata.get("timestamp")
            )

        # Recreate combined key
        timestamp_component = self._derive_timestamp_component(
            gun112_challenge_data.get("datetime_iso")
        )
        combined_key = self._combine_keys(symmetric_key, timestamp_component)

        # Decrypt PDF
        try:
            pdf_data = self.crypto_engine.decrypt_from_bytes(encrypted_pdf, combined_key)
        except Exception as e:
            raise ValueError(f"Failed to decrypt PDF: {str(e)}")

        user_metadata = metadata.get("user_metadata")
        return pdf_data, user_metadata
