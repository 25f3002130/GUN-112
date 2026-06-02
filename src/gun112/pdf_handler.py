"""
PDF Encryption and Decryption Handler — GUN-112 Protocol Suite

Supports two encryption modes:

  1. Password-based (GUN-112)
     Standard AES-256-GCM encryption with Argon2/PBKDF2 key derivation,
     a time-based GUN-112 cryptographic challenge, and rate limiting.

  2. Identity-based (GUN-112-GKP — Ghost Key Protocol)
     A random AES-256 key is sealed with the recipient's RSA-4096 public
     Identity Token. No shared password is needed. Only the recipient's
     physical device (holding the matching private key) can decrypt the file.

     GKP solves key-distribution: the sender never needs to transmit a
     password. The encrypted key travels with the file; the private key
     never leaves the recipient's device.

Container format: JSON with base64-encoded binary fields.
The "protocol" field is always "GUN-112". The "lock_mode" field
distinguishes password mode (absent / "password") from GKP mode ("GKP").
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
    Handles PDF encryption and decryption with the GUN-112 protocol suite.

    GUN-112 (password mode) security features:
    - AES-256-GCM authenticated encryption
    - Time-based cryptographic challenge (nanosecond precision)
    - Salted challenge hash to prevent reverse engineering
    - Argon2 password hashing
    - Dual-pass PBKDF2 key derivation (SHA-256 + SHA-512)
    - Rate limiting: 5 attempts max, 15-minute lockout
    - Multi-layer defence: password verification + challenge verification required

    GUN-112-GKP (Ghost Key Protocol) additional features:
    - RSA-4096 asymmetric key wrapping (RSA-OAEP / SHA-256)
    - No shared password required
    - Device-bound decryption: only the recipient's physical device can decrypt
    - GUN-112 challenge verification still applies (tamper detection)
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

    # =========================================================================
    # Password-Based Encryption / Decryption  (GUN-112)
    # =========================================================================

    def encrypt_pdf(
        self,
        pdf_data: bytes,
        password: str,
        metadata: Optional[Dict] = None
    ) -> bytes:
        """
        Encrypt a PDF using password-based GUN-112 encryption.

        Args:
            pdf_data: Raw PDF file content.
            password: User password for encryption.
            metadata: Optional metadata to include (encrypted alongside the PDF).

        Returns:
            Encrypted GUN-112 container (bytes).
            Format: JSON with base64-encoded binary fields + GUN-112 challenge.
        """
        # Create GUN-112 cryptographic challenge
        challenge = self.gun112_challenge.create_challenge()

        # Derive encryption key from password
        encryption_key, salt = self.key_manager.derive_key_from_password(password)

        # Generate Argon2 password hash for storage (verification without storing the password)
        password_hash = self.key_manager.hash_password(password)

        # Derive timestamp component from the challenge and mix into the final key
        timestamp_component = self._derive_timestamp_component(challenge["datetime_iso"])
        combined_key = self._combine_keys(encryption_key, timestamp_component)

        # Build encrypted metadata (includes challenge data)
        encryption_metadata = {
            "protocol": security_config.ENCRYPTION_PROTOCOL,
            "timestamp": challenge["datetime_iso"],
            "password_hash": password_hash,
            "salt": base64.b64encode(salt).decode('utf-8'),
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

        metadata_json = json.dumps(encryption_metadata).encode('utf-8')

        # Encrypt PDF with combined key; encrypt metadata with base key
        encrypted_pdf = self.crypto_engine.encrypt_to_bytes(pdf_data, combined_key)
        encrypted_metadata = self.crypto_engine.encrypt_to_bytes(metadata_json, encryption_key)

        return self._create_container(
            encrypted_pdf=encrypted_pdf,
            encrypted_metadata=encrypted_metadata,
            salt=salt,
            timestamp=challenge["datetime_iso"]
        )

    def decrypt_pdf(
        self,
        encrypted_package: bytes,
        password: str
    ) -> tuple[bytes, Optional[Dict]]:
        """
        Decrypt a password-locked GUN-112 PDF.

        Args:
            encrypted_package: Encrypted container from encrypt_pdf.
            password: User password for decryption.

        Returns:
            Tuple of (decrypted_pdf_data, metadata_or_None).

        Raises:
            ValueError: If the password is incorrect, the GUN-112 challenge fails,
                        tampering is detected, or the rate-limit lockout is active.
        """
        try:
            container_data = json.loads(encrypted_package.decode('utf-8'))
        except Exception:
            raise ValueError("Invalid encrypted package format")

        # Rate limiting — keyed by fingerprint of the first 100 bytes
        resource_id = hashlib.sha256(encrypted_package[:100]).hexdigest()
        allowed, message = self.security_layer.record_attempt(resource_id, success=False)
        if not allowed:
            raise ValueError(f"Decryption locked: {message}")

        # Verify outer protocol
        protocol = container_data.get("protocol", "Unknown")
        if protocol != security_config.ENCRYPTION_PROTOCOL:
            raise ValueError(
                f"Unsupported encryption protocol: {protocol}. "
                f"Expected {security_config.ENCRYPTION_PROTOCOL}"
            )

        # Reject GKP-locked files early with a helpful message
        lock_mode = container_data.get("lock_mode", "password")
        if lock_mode == security_config.GKP_LOCK_MODE:
            raise ValueError(
                "This file is GKP-locked (Ghost Key Protocol), not password-locked. "
                "Use decrypt_pdf_identity() or 'gun112 decrypt' (which auto-detects) instead."
            )

        salt = base64.b64decode(container_data["salt"])
        encrypted_pdf = base64.b64decode(container_data["encrypted_pdf"])
        encrypted_metadata = base64.b64decode(container_data["encrypted_metadata"])

        # Derive key from password + stored salt
        try:
            encryption_key, _ = self.key_manager.derive_key_from_password(password, salt)
        except Exception as e:
            raise ValueError(f"Failed to derive key: {str(e)}")

        # Decrypt metadata to verify password
        try:
            metadata_json = self.crypto_engine.decrypt_from_bytes(encrypted_metadata, encryption_key)
            metadata = json.loads(metadata_json.decode('utf-8'))
        except Exception:
            raise ValueError("Decryption failed: Invalid password or corrupted data")

        # Verify GUN-112 challenge integrity
        gun112_challenge_data = metadata.get("gun112_challenge")
        if not gun112_challenge_data:
            raise ValueError(
                "GUN-112 challenge data missing: File may be corrupted or tampered with"
            )

        if not self.gun112_challenge.verify_challenge(gun112_challenge_data):
            raise ValueError(
                "GUN-112 challenge verification failed: File may be tampered with"
            )

        if security_config.ENABLE_TIMESTAMP_VALIDATION:
            self._validate_timestamp(
                gun112_challenge_data.get("datetime_iso"),
                metadata.get("timestamp")
            )

        # Reconstruct the combined key using the stored challenge timestamp
        timestamp_component = self._derive_timestamp_component(
            gun112_challenge_data.get("datetime_iso")
        )
        combined_key = self._combine_keys(encryption_key, timestamp_component)

        # Decrypt PDF
        try:
            pdf_data = self.crypto_engine.decrypt_from_bytes(encrypted_pdf, combined_key)
        except Exception as e:
            raise ValueError(f"Failed to decrypt PDF: {str(e)}")

        self.security_layer.record_attempt(resource_id, success=True)
        return pdf_data, metadata.get("user_metadata")

    # =========================================================================
    # GUN-112-GKP (Ghost Key Protocol) — Identity-Based Encryption / Decryption
    # =========================================================================

    def encrypt_pdf_for_recipient(
        self,
        pdf_data: bytes,
        recipient_token: str,
        metadata: Optional[Dict] = None
    ) -> bytes:
        """
        Encrypt a PDF using GUN-112-GKP (Ghost Key Protocol) for a specific recipient.

        A random AES-256 key is generated and sealed using the recipient's RSA-4096
        public Identity Token (RSA-OAEP). No password is required. Only the recipient's
        physical device, which holds the matching GKP private key, can decrypt it.

        This solves the key-distribution problem: the sender only needs the recipient's
        public Identity Token — a string that can be shared over any channel.

        Args:
            pdf_data: Raw PDF file content.
            recipient_token: The recipient's public GKP Identity Token string.
            metadata: Optional metadata to include (encrypted).

        Returns:
            GKP-locked encrypted package (bytes).
        """
        # Create GUN-112 cryptographic challenge (applies to GKP too)
        challenge = self.gun112_challenge.create_challenge()

        # Generate a random AES-256 symmetric key (no password needed)
        symmetric_key = os.urandom(security_config.KEY_SIZE)

        # Mix in timestamp component for the final encryption key
        timestamp_component = self._derive_timestamp_component(challenge["datetime_iso"])
        combined_key = self._combine_keys(symmetric_key, timestamp_component)

        # Seal the symmetric key with the recipient's RSA public key (GKP core operation)
        encrypted_symmetric_key = self.identity_manager.encrypt_symmetric_key(
            symmetric_key, recipient_token
        )

        # Build metadata
        encryption_metadata = {
            "protocol": security_config.ENCRYPTION_PROTOCOL,
            "sub_protocol": security_config.GKP_PROTOCOL,  # "GUN-112-GKP"
            "lock_mode": security_config.GKP_LOCK_MODE,    # "GKP"
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

        # Encrypt PDF with combined key; encrypt metadata with raw symmetric key
        encrypted_pdf = self.crypto_engine.encrypt_to_bytes(pdf_data, combined_key)
        encrypted_metadata = self.crypto_engine.encrypt_to_bytes(metadata_json, symmetric_key)

        # Build GKP container
        container = {
            "protocol": security_config.ENCRYPTION_PROTOCOL,  # "GUN-112"
            "sub_protocol": security_config.GKP_PROTOCOL,     # "GUN-112-GKP"
            "lock_mode": security_config.GKP_LOCK_MODE,        # "GKP"
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
        Decrypt a GKP-locked PDF using this device's GKP private key.

        The device's private key is used to unseal the encrypted AES symmetric key,
        which is then used to decrypt the PDF. This device must be the one for which
        the file was originally encrypted.

        Args:
            encrypted_package: GKP-locked container from encrypt_pdf_for_recipient.
            passphrase: Optional passphrase if the private key was protected at generation.

        Returns:
            Tuple of (decrypted_pdf_data, metadata_or_None).

        Raises:
            ValueError: If this device does not hold the correct GKP private key,
                        or if the GUN-112 challenge verification fails.
        """
        try:
            container_data = json.loads(encrypted_package.decode("utf-8"))
        except Exception:
            raise ValueError("Invalid encrypted package format")

        protocol = container_data.get("protocol", "Unknown")
        if protocol != security_config.ENCRYPTION_PROTOCOL:
            raise ValueError(
                f"Unsupported encryption protocol: {protocol}. "
                f"Expected {security_config.ENCRYPTION_PROTOCOL}"
            )

        lock_mode = container_data.get("lock_mode", "password")
        if lock_mode != security_config.GKP_LOCK_MODE:
            raise ValueError(
                "This file is password-locked (GUN-112), not GKP-locked. "
                "Use the standard decrypt_pdf() method with a password instead."
            )

        # Decode components
        encrypted_symmetric_key = base64.b64decode(container_data["encrypted_symmetric_key"])
        encrypted_pdf = base64.b64decode(container_data["encrypted_pdf"])
        encrypted_metadata = base64.b64decode(container_data["encrypted_metadata"])

        # Unseal the symmetric key using this device's GKP private key
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
            raise ValueError("GKP decryption failed: Could not decrypt metadata")

        # Verify GUN-112 challenge (tamper detection applies to GKP too)
        gun112_challenge_data = metadata.get("gun112_challenge")
        if not gun112_challenge_data:
            raise ValueError(
                "GUN-112 challenge data missing: File may be corrupted"
            )

        if not self.gun112_challenge.verify_challenge(gun112_challenge_data):
            raise ValueError(
                "GUN-112 challenge verification failed: File may be tampered with"
            )

        if security_config.ENABLE_TIMESTAMP_VALIDATION:
            self._validate_timestamp(
                gun112_challenge_data.get("datetime_iso"),
                metadata.get("timestamp")
            )

        # Reconstruct the combined key
        timestamp_component = self._derive_timestamp_component(
            gun112_challenge_data.get("datetime_iso")
        )
        combined_key = self._combine_keys(symmetric_key, timestamp_component)

        # Decrypt PDF
        try:
            pdf_data = self.crypto_engine.decrypt_from_bytes(encrypted_pdf, combined_key)
        except Exception as e:
            raise ValueError(f"Failed to decrypt PDF: {str(e)}")

        return pdf_data, metadata.get("user_metadata")

    # =========================================================================
    # Private helpers
    # =========================================================================

    def _combine_keys(self, base_key: bytes, timestamp_component: bytes) -> bytes:
        """Combine base encryption key with timestamp component for an extra security layer."""
        combined = hashlib.sha256(base_key + timestamp_component).digest()
        return combined

    def _derive_timestamp_component(self, timestamp: str) -> bytes:
        """Derive a deterministic key component from a timestamp string."""
        return hashlib.sha256(timestamp.encode('utf-8')).digest()

    def _create_container(
        self,
        encrypted_pdf: bytes,
        encrypted_metadata: bytes,
        salt: bytes,
        timestamp: str,
    ) -> bytes:
        """
        Assemble a password-mode GUN-112 container.
        Format: JSON with base64-encoded binary data.
        """
        container = {
            "protocol": security_config.ENCRYPTION_PROTOCOL,
            "version": "1.0",
            "algorithm": security_config.ENCRYPTION_ALGORITHM,
            "salt": base64.b64encode(salt).decode('utf-8'),
            "encrypted_pdf": base64.b64encode(encrypted_pdf).decode('utf-8'),
            "encrypted_metadata": base64.b64encode(encrypted_metadata).decode('utf-8'),
            "timestamp": timestamp
        }
        return json.dumps(container).encode('utf-8')

    def _validate_timestamp(self, stored_timestamp: str, metadata_timestamp: str):
        """Verify that the challenge timestamp matches the container timestamp."""
        if stored_timestamp != metadata_timestamp:
            raise ValueError(
                "Timestamp validation failed: Possible tampering detected"
            )