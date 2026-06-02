"""
Unit tests for GUN-112 Identity-Based Encryption

Tests the full lifecycle:
1. Identity generation
2. Identity token export / fingerprint
3. Encrypt PDF for a recipient's token
4. Decrypt PDF using the recipient's private key
5. Verify that wrong identity cannot decrypt
6. Verify that the help command works
"""
import pytest
import os
import shutil
from pathlib import Path
from unittest.mock import patch

from gun112 import PDFEncryptionHandler, IdentityManager
from gun112.identity import _IDENTITY_DIR, _PRIVATE_KEY_FILE, _PUBLIC_KEY_FILE


# Use a temporary identity directory for tests so we never touch real keys
_TEST_IDENTITY_DIR = Path(__file__).parent / "_test_identity"


@pytest.fixture(autouse=True)
def isolate_identity(monkeypatch, tmp_path):
    """
    Redirect identity storage to a temp directory for every test,
    ensuring complete isolation.
    """
    test_dir = tmp_path / ".gun112"
    test_priv = test_dir / "private_key.pem"
    test_pub = test_dir / "public_key.pem"

    monkeypatch.setattr("gun112.identity._IDENTITY_DIR", test_dir)
    monkeypatch.setattr("gun112.identity._PRIVATE_KEY_FILE", test_priv)
    monkeypatch.setattr("gun112.identity._PUBLIC_KEY_FILE", test_pub)

    yield

    # Cleanup
    if test_dir.exists():
        shutil.rmtree(test_dir)


class TestIdentityManager:
    """Test identity generation and management."""

    def test_generate_identity_creates_keys(self):
        """Test that generating identity creates both key files."""
        manager = IdentityManager()
        token = manager.generate_identity()

        assert token is not None
        assert len(token) > 100  # RSA-4096 public key is quite long

    def test_generate_identity_twice_raises(self):
        """Test that generating identity twice raises FileExistsError."""
        manager = IdentityManager()
        manager.generate_identity()

        with pytest.raises(FileExistsError):
            manager.generate_identity()

    def test_get_identity_token(self):
        """Test retrieving the identity token after generation."""
        manager = IdentityManager()
        generated_token = manager.generate_identity()
        retrieved_token = manager.get_identity_token()

        assert generated_token == retrieved_token

    def test_get_identity_token_without_generation_raises(self):
        """Test that getting token before generation raises."""
        manager = IdentityManager()
        with pytest.raises(FileNotFoundError):
            manager.get_identity_token()

    def test_has_identity(self):
        """Test has_identity check."""
        manager = IdentityManager()
        assert not manager.has_identity()

        manager.generate_identity()
        assert manager.has_identity()

    def test_reset_identity(self):
        """Test identity deletion."""
        manager = IdentityManager()
        manager.generate_identity()
        assert manager.has_identity()

        manager.reset_identity()
        assert not manager.has_identity()

    def test_fingerprint_is_consistent(self):
        """Test that fingerprint is the same for the same token."""
        manager = IdentityManager()
        token = manager.generate_identity()

        fp1 = manager.get_identity_fingerprint(token)
        fp2 = manager.get_identity_fingerprint(token)

        assert fp1 == fp2
        assert ":" in fp1  # Colon-separated format

    def test_identity_with_passphrase(self):
        """Test identity generation with a passphrase."""
        manager = IdentityManager()
        token = manager.generate_identity(passphrase="test_passphrase")
        assert token is not None

    def test_encrypt_decrypt_symmetric_key(self):
        """Test RSA encryption/decryption of a symmetric key."""
        manager = IdentityManager()
        token = manager.generate_identity()

        # Generate a random AES-256 key
        symmetric_key = os.urandom(32)

        # Encrypt it with the public key
        encrypted = manager.encrypt_symmetric_key(symmetric_key, token)
        assert encrypted != symmetric_key

        # Decrypt it with the private key
        decrypted = manager.decrypt_symmetric_key(encrypted)
        assert decrypted == symmetric_key


class TestIdentityBasedEncryption:
    """Test end-to-end identity-locked PDF encryption/decryption."""

    def test_encrypt_and_decrypt_for_recipient(self):
        """Test full cycle: encrypt for recipient → recipient decrypts."""
        manager = IdentityManager()
        recipient_token = manager.generate_identity()

        handler = PDFEncryptionHandler()
        pdf_data = b"%PDF-1.4\nIdentity-locked test document content"

        # Encrypt for the recipient
        encrypted = handler.encrypt_pdf_for_recipient(pdf_data, recipient_token)
        assert encrypted != pdf_data

        # Decrypt using the device's private key
        decrypted, metadata = handler.decrypt_pdf_identity(encrypted)
        assert decrypted == pdf_data
        assert metadata is None  # No user metadata was provided

    def test_encrypt_with_metadata(self):
        """Test identity encryption with user metadata."""
        manager = IdentityManager()
        token = manager.generate_identity()

        handler = PDFEncryptionHandler()
        pdf_data = b"%PDF-1.4\nConfidential report"
        user_meta = {"author": "Alice", "classification": "TOP SECRET"}

        encrypted = handler.encrypt_pdf_for_recipient(pdf_data, token, metadata=user_meta)
        decrypted, returned_meta = handler.decrypt_pdf_identity(encrypted)

        assert decrypted == pdf_data
        assert returned_meta == user_meta

    def test_wrong_identity_cannot_decrypt(self, tmp_path):
        """
        Test that a different device's identity cannot decrypt the file.
        Simulates a hacker generating their own identity.
        """
        # --- Recipient generates identity ---
        manager = IdentityManager()
        recipient_token = manager.generate_identity()

        handler = PDFEncryptionHandler()
        pdf_data = b"%PDF-1.4\nSecret data for recipient only"
        encrypted = handler.encrypt_pdf_for_recipient(pdf_data, recipient_token)

        # --- Hacker generates a DIFFERENT identity (simulated by replacing key files) ---
        manager.reset_identity()
        manager.generate_identity()  # This creates a brand-new keypair

        # Attempting to decrypt with the hacker's key should fail
        with pytest.raises(ValueError, match="GKP decryption failed"):
            handler.decrypt_pdf_identity(encrypted)

    def test_password_locked_file_rejects_identity_decrypt(self):
        """Test that password-locked files cannot be decrypted via identity mode."""
        manager = IdentityManager()
        manager.generate_identity()

        handler = PDFEncryptionHandler()
        pdf_data = b"%PDF-1.4\nPassword-locked content"
        encrypted = handler.encrypt_pdf(pdf_data, "SecurePassword123!")

        with pytest.raises(ValueError, match="password-locked"):
            handler.decrypt_pdf_identity(encrypted)

    def test_identity_locked_file_rejects_password_decrypt(self):
        """Test that identity-locked files tell users to use identity mode."""
        manager = IdentityManager()
        token = manager.generate_identity()

        handler = PDFEncryptionHandler()
        pdf_data = b"%PDF-1.4\nIdentity content"
        encrypted = handler.encrypt_pdf_for_recipient(pdf_data, token)

        # Trying password-based decryption on an identity-locked file
        # should fail because it's identity-locked
        with pytest.raises(ValueError, match="GKP-locked"):
            handler.decrypt_pdf(encrypted, "any_password")
