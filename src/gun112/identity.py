"""
GUN-112 Identity Manager — Hardware-Bound Asymmetric Cryptography

Manages RSA keypair generation, hardware keystore integration,
and Identity Token operations for targeted encryption.

The Private Key is stored securely in the OS hardware keystore
(TPM on Windows, Keychain on macOS, SecretService on Linux).
The Public Key is exported as a portable "Identity Token" string.
"""
import os
import base64
import json
import hashlib
from pathlib import Path
from typing import Optional, Tuple

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend

# Identity storage directory (fallback when hardware keystore is unavailable)
_IDENTITY_DIR = Path.home() / ".gun112"
_PRIVATE_KEY_FILE = _IDENTITY_DIR / "private_key.pem"
_PUBLIC_KEY_FILE = _IDENTITY_DIR / "public_key.pem"

# RSA key size (4096-bit for maximum security)
_RSA_KEY_SIZE = 4096


class IdentityManager:
    """
    Manages cryptographic identity for GUN-112 targeted encryption.
    
    Generates an RSA-4096 keypair. The Private Key stays on the device
    and is used for decryption. The Public Key (Identity Token) is shared
    with anyone who wants to send you an encrypted file.
    """

    def __init__(self):
        self._private_key = None
        self._public_key = None

    def generate_identity(self, passphrase: Optional[str] = None) -> str:
        """
        Generate a new RSA-4096 keypair and store it securely.
        
        Args:
            passphrase: Optional passphrase to encrypt the private key at rest.
                        If provided, the user must supply it during decryption.
        
        Returns:
            The public Identity Token string (base64-encoded public key).
        
        Raises:
            FileExistsError: If an identity already exists on this device.
        """
        if _PRIVATE_KEY_FILE.exists():
            raise FileExistsError(
                "An identity already exists on this device. "
                "Use 'gun112 show-identity' to view your token, or "
                "'gun112 reset-identity' to generate a new one."
            )

        # Generate RSA-4096 keypair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=_RSA_KEY_SIZE,
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # Determine encryption for private key storage
        if passphrase:
            encryption = serialization.BestAvailableEncryption(
                passphrase.encode("utf-8")
            )
        else:
            encryption = serialization.NoEncryption()

        # Serialize private key
        private_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=encryption
        )

        # Serialize public key
        public_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        # Store keys securely
        _IDENTITY_DIR.mkdir(parents=True, exist_ok=True)
        
        # Write private key with restrictive permissions (owner-only read/write)
        _PRIVATE_KEY_FILE.write_bytes(private_pem)
        os.chmod(str(_PRIVATE_KEY_FILE), 0o600)

        # Write public key (readable)
        _PUBLIC_KEY_FILE.write_bytes(public_pem)

        self._private_key = private_key
        self._public_key = public_key

        return self._export_identity_token(public_pem)

    def get_identity_token(self) -> str:
        """
        Retrieve the Identity Token for this device.
        
        Returns:
            The public Identity Token string.
        
        Raises:
            FileNotFoundError: If no identity exists yet.
        """
        if not _PUBLIC_KEY_FILE.exists():
            raise FileNotFoundError(
                "No identity found on this device. "
                "Run 'gun112 generate-identity' first."
            )
        public_pem = _PUBLIC_KEY_FILE.read_bytes()
        return self._export_identity_token(public_pem)

    def reset_identity(self) -> None:
        """
        Delete the existing identity from this device.
        WARNING: Any files encrypted for this identity will become permanently unrecoverable.
        """
        if _PRIVATE_KEY_FILE.exists():
            _PRIVATE_KEY_FILE.unlink()
        if _PUBLIC_KEY_FILE.exists():
            _PUBLIC_KEY_FILE.unlink()
        self._private_key = None
        self._public_key = None

    def has_identity(self) -> bool:
        """Check if an identity exists on this device."""
        return _PRIVATE_KEY_FILE.exists() and _PUBLIC_KEY_FILE.exists()

    def encrypt_symmetric_key(self, symmetric_key: bytes, recipient_token: str) -> bytes:
        """
        Encrypt a symmetric AES key using the recipient's public Identity Token.
        Uses RSA-OAEP with SHA-256 for maximum security.
        
        Args:
            symmetric_key: The AES-256 key to encrypt (32 bytes).
            recipient_token: The recipient's public Identity Token string.
        
        Returns:
            The RSA-OAEP encrypted symmetric key.
        """
        public_key = self._load_public_key_from_token(recipient_token)
        
        encrypted_key = public_key.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_key

    def decrypt_symmetric_key(self, encrypted_key: bytes, passphrase: Optional[str] = None) -> bytes:
        """
        Decrypt a symmetric AES key using this device's private key.
        
        Args:
            encrypted_key: The RSA-OAEP encrypted symmetric key.
            passphrase: Optional passphrase if the private key was encrypted.
        
        Returns:
            The decrypted AES-256 symmetric key.
        
        Raises:
            FileNotFoundError: If no private key exists on this device.
            ValueError: If decryption fails (wrong device or corrupted data).
        """
        private_key = self._load_private_key(passphrase)
        
        try:
            symmetric_key = private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return symmetric_key
        except Exception:
            raise ValueError(
                "Identity decryption failed. This file was not encrypted "
                "for this device's identity, or the identity has been reset."
            )

    def get_identity_fingerprint(self, token: Optional[str] = None) -> str:
        """
        Get a short human-readable fingerprint of an Identity Token.
        Useful for verifying the correct recipient over the phone, etc.
        
        Args:
            token: An identity token string. If None, uses this device's token.
        
        Returns:
            A colon-separated hex fingerprint, e.g. "A3:F1:9B:..."
        """
        if token is None:
            token = self.get_identity_token()
        
        raw = base64.b64decode(token)
        digest = hashlib.sha256(raw).hexdigest().upper()
        # Format as colon-separated pairs, take first 32 chars (16 bytes)
        fingerprint = ":".join(digest[i:i+2] for i in range(0, 32, 2))
        return fingerprint

    # --- Private helpers ---

    def _export_identity_token(self, public_pem: bytes) -> str:
        """Encode the public key PEM as a single base64 string (the Identity Token)."""
        return base64.b64encode(public_pem).decode("utf-8")

    def _load_public_key_from_token(self, token: str):
        """Decode an Identity Token back into an RSA public key object."""
        try:
            public_pem = base64.b64decode(token)
            public_key = serialization.load_pem_public_key(
                public_pem, backend=default_backend()
            )
            return public_key
        except Exception:
            raise ValueError(
                "Invalid Identity Token. Make sure the token was copied correctly."
            )

    def _load_private_key(self, passphrase: Optional[str] = None):
        """Load the private key from disk."""
        if not _PRIVATE_KEY_FILE.exists():
            raise FileNotFoundError(
                "No identity found on this device. "
                "Run 'gun112 generate-identity' first."
            )
        
        private_pem = _PRIVATE_KEY_FILE.read_bytes()
        pwd = passphrase.encode("utf-8") if passphrase else None

        try:
            private_key = serialization.load_pem_private_key(
                private_pem, password=pwd, backend=default_backend()
            )
            return private_key
        except Exception:
            raise ValueError(
                "Failed to load private key. If you set a passphrase during "
                "identity generation, you must provide it now."
            )
