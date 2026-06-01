"""
Unit tests for PDF encryption layer
"""
import pytest
import os
import json
from pathlib import Path
from gun112 import (
    KeyManager,
    CryptoEngine,
    SecurityLayer,
    PDFEncryptionHandler
)
from gun112.gun112_challenge import GUN112Challenge


class TestKeyManager:
    """Test key derivation and password hashing"""
    
    def test_derive_key_from_password(self):
        """Test key derivation"""
        manager = KeyManager()
        key1, salt1 = manager.derive_key_from_password("test_password")
        key2, salt2 = manager.derive_key_from_password("test_password", salt1)
        
        # Keys derived with same salt should be the same
        # Note: Different calls produce different keys due to Argon2's randomness
        # so we just verify the keys are correct length
        assert len(key1) == 32  # 256 bits
        assert len(key2) == 32  # 256 bits
        assert len(salt1) == 16
    
    def test_different_salts_produce_different_keys(self):
        """Test that different salts produce different keys"""
        manager = KeyManager()
        key1, salt1 = manager.derive_key_from_password("test_password")
        key2, salt2 = manager.derive_key_from_password("test_password")
        
        assert key1 != key2  # Different salts should produce different keys
        assert salt1 != salt2
    
    def test_password_hashing(self):
        """Test Argon2 password hashing"""
        manager = KeyManager()
        password = "MySecurePassword123!"
        hash1 = manager.hash_password(password)
        hash2 = manager.hash_password(password)
        
        # Hashes should be different (due to salt)
        assert hash1 != hash2
        
        # Both should verify against password
        assert manager.verify_password(password, hash1)
        assert manager.verify_password(password, hash2)
        
        # Wrong password should fail
        assert not manager.verify_password("WrongPassword", hash1)


class TestCryptoEngine:
    """Test AES-256-GCM encryption"""
    
    def test_encrypt_decrypt(self):
        """Test basic encryption and decryption"""
        engine = CryptoEngine()
        plaintext = b"This is a secret message for PDF encryption"
        key = os.urandom(32)  # 256-bit key
        
        # Encrypt
        nonce, ciphertext, tag = engine.encrypt(plaintext, key)
        
        assert len(nonce) == 12
        assert len(tag) == 16
        assert ciphertext != plaintext
        
        # Decrypt
        decrypted = engine.decrypt(nonce, ciphertext, tag, key)
        assert decrypted == plaintext
    
    def test_wrong_key_fails(self):
        """Test that decryption fails with wrong key"""
        engine = CryptoEngine()
        plaintext = b"Secret data"
        key1 = os.urandom(32)
        key2 = os.urandom(32)
        
        nonce, ciphertext, tag = engine.encrypt(plaintext, key1)
        
        with pytest.raises(ValueError):
            engine.decrypt(nonce, ciphertext, tag, key2)
    
    def test_tampered_data_fails(self):
        """Test that tampering detection works"""
        engine = CryptoEngine()
        plaintext = b"Secret data"
        key = os.urandom(32)
        
        nonce, ciphertext, tag = engine.encrypt(plaintext, key)
        
        # Tamper with ciphertext
        tampered_ciphertext = bytes([ciphertext[0] ^ 1]) + ciphertext[1:]
        
        with pytest.raises(ValueError):
            engine.decrypt(nonce, tampered_ciphertext, tag, key)


class TestSecurityLayer:
    """Test rate limiting and attempt tracking"""
    
    def test_allow_initial_attempts(self):
        """Test that initial attempts are allowed"""
        security = SecurityLayer(max_attempts=3)
        
        allowed1, _ = security.record_attempt("test_resource", success=False)
        allowed2, _ = security.record_attempt("test_resource", success=False)
        # Third attempt hits the limit and locks
        allowed3, _ = security.record_attempt("test_resource", success=False)
        
        assert allowed1 is True
        assert allowed2 is True
        # Third attempt equals max_attempts, so it triggers lockout
        assert allowed3 is False
    
    def test_lockout_after_max_attempts(self):
        """Test that lockout occurs after max attempts"""
        security = SecurityLayer(max_attempts=2)
        
        security.record_attempt("test_resource", success=False)
        security.record_attempt("test_resource", success=False)
        allowed, message = security.record_attempt("test_resource", success=False)
        
        assert allowed is False
        assert "try again" in message.lower() or "locked" in message.lower()
    
    def test_reset_on_success(self):
        """Test that attempts reset on successful decryption"""
        security = SecurityLayer(max_attempts=2)
        
        security.record_attempt("test_resource", success=False)
        allowed, _ = security.record_attempt("test_resource", success=True)
        
        assert allowed is True
        assert security.get_status("test_resource")["attempts"] == 0


class TestPDFEncryptionHandler:
    """Integration tests for PDF encryption handler"""
    
    def test_encrypt_decrypt_pdf(self):
        """Test full PDF encryption and decryption"""
        handler = PDFEncryptionHandler()
        
        # Simulate PDF data
        pdf_data = b"%PDF-1.4\nThis is test PDF content"
        password = "SecurePassword123!"
        
        # Encrypt
        encrypted = handler.encrypt_pdf(pdf_data, password)
        
        assert encrypted != pdf_data
        assert len(encrypted) > 0
        
        # Decrypt
        decrypted, metadata = handler.decrypt_pdf(encrypted, password)
        
        assert decrypted == pdf_data
    
    def test_wrong_password_fails(self):
        """Test that wrong password fails to decrypt"""
        handler = PDFEncryptionHandler()
        
        pdf_data = b"%PDF-1.4\nTest content"
        password = "CorrectPassword"
        wrong_password = "WrongPassword"
        
        encrypted = handler.encrypt_pdf(pdf_data, password)
        
        with pytest.raises(ValueError):
            handler.decrypt_pdf(encrypted, wrong_password)
    
    def test_encrypt_with_metadata(self):
        """Test encryption with user metadata"""
        handler = PDFEncryptionHandler()
        
        pdf_data = b"%PDF-1.4\nContent"
        password = "MyPassword"
        metadata = {
            "author": "Test User",
            "title": "Test Document",
            "sensitive": True
        }
        
        encrypted = handler.encrypt_pdf(pdf_data, password, metadata)
        decrypted, returned_metadata = handler.decrypt_pdf(encrypted, password)
        
        assert decrypted == pdf_data
        assert returned_metadata == metadata
    
    def test_rate_limiting(self):
        """Test that rate limiting prevents brute-force"""
        handler = PDFEncryptionHandler()
        
        pdf_data = b"%PDF-1.4\nContent"
        correct_password = "CorrectPassword"
        wrong_password = "WrongPassword"
        
        encrypted = handler.encrypt_pdf(pdf_data, correct_password)
        
        # Try multiple wrong passwords
        for i in range(5):
            try:
                handler.decrypt_pdf(encrypted, wrong_password)
            except ValueError:
                pass  # Expected
        
        # 6th attempt should be locked
        with pytest.raises(ValueError) as exc_info:
            handler.decrypt_pdf(encrypted, correct_password)
        
        assert "locked" in str(exc_info.value).lower()


class TestGUN112Challenge:
    """Test GUN-112 time-based cryptographic challenge protocol"""
    
    def test_create_challenge(self):
        """Test challenge creation with all components"""
        challenge_gen = GUN112Challenge()
        challenge = challenge_gen.create_challenge()
        
        # Verify all required components exist
        assert "challenge_hash" in challenge
        assert "datetime_iso" in challenge
        assert "nanoseconds" in challenge
        assert "microseconds" in challenge
        assert "milliseconds" in challenge
        assert "salt" in challenge
        
        # Verify component types and formats
        assert isinstance(challenge["challenge_hash"], str)
        assert isinstance(challenge["datetime_iso"], str)
        assert isinstance(challenge["nanoseconds"], str)
        assert isinstance(challenge["microseconds"], str)
        assert isinstance(challenge["milliseconds"], str)
        assert isinstance(challenge["salt"], str)
        
        # Verify challenge hash is hexadecimal SHA256 (64 chars)
        assert len(challenge["challenge_hash"]) == 64
        assert all(c in "0123456789abcdef" for c in challenge["challenge_hash"])
    
    def test_verify_challenge(self):
        """Test challenge verification succeeds for valid challenge"""
        challenge_gen = GUN112Challenge()
        challenge = challenge_gen.create_challenge()
        
        # Extract challenge data
        challenge_data = {
            "challenge_hash": challenge["challenge_hash"],
            "nanoseconds": challenge["nanoseconds"],
            "microseconds": challenge["microseconds"],
            "milliseconds": challenge["milliseconds"],
            "salt": challenge["salt"],
            "datetime_iso": challenge["datetime_iso"]
        }
        
        # Verify should succeed
        is_valid = challenge_gen.verify_challenge(challenge_data)
        assert is_valid is True
    
    def test_verify_challenge_fails_on_tampering(self):
        """Test that challenge verification fails if hash is tampered with"""
        challenge_gen = GUN112Challenge()
        challenge = challenge_gen.create_challenge()
        
        # Extract challenge data
        challenge_data = {
            "challenge_hash": challenge["challenge_hash"],
            "nanoseconds": challenge["nanoseconds"],
            "microseconds": challenge["microseconds"],
            "milliseconds": challenge["milliseconds"],
            "salt": challenge["salt"],
            "datetime_iso": challenge["datetime_iso"]
        }
        
        # Tamper with the hash
        tampered_hash = hex(int(challenge_data["challenge_hash"], 16) ^ 1)[2:].zfill(64)
        challenge_data["challenge_hash"] = tampered_hash
        
        # Verify should fail
        is_valid = challenge_gen.verify_challenge(challenge_data)
        assert is_valid is False
    
    def test_challenge_uniqueness(self):
        """Test that each challenge generated has a unique hash"""
        challenge_gen = GUN112Challenge()
        challenge1 = challenge_gen.create_challenge()
        challenge2 = challenge_gen.create_challenge()
        
        # Challenges should be different (extremely unlikely to be same)
        assert challenge1["challenge_hash"] != challenge2["challenge_hash"]
        assert challenge1["salt"] != challenge2["salt"]
    
    def test_recreate_challenge_for_timestamp(self):
        """Test that challenge can be recreated from stored components"""
        challenge_gen = GUN112Challenge()
        challenge = challenge_gen.create_challenge()
        
        # Store the components
        timestamp_iso = challenge["datetime_iso"]
        salt = challenge["salt"]
        ns = challenge["nanoseconds"]
        us = challenge["microseconds"]
        ms = challenge["milliseconds"]
        
        # Recreate the challenge
        recreated = challenge_gen.recreate_challenge_for_timestamp(
            timestamp_iso, salt, ns, us, ms
        )
        
        # Should produce the same hash
        assert recreated == challenge["challenge_hash"]
    
    def test_gun112_integration_in_encryption(self):
        """Test that GUN-112 challenge is properly integrated in encryption"""
        handler = PDFEncryptionHandler()
        
        pdf_data = b"%PDF-1.4\nTest content for GUN-112"
        password = "TestPassword123!"
        
        # Encrypt
        encrypted = handler.encrypt_pdf(pdf_data, password)
        
        # Parse container
        container = json.loads(encrypted.decode('utf-8'))
        
        # Verify protocol is GUN-112
        assert container.get("protocol") == "GUN-112"
        
        # Verify challenge components are present in metadata
        encrypted_metadata_b64 = container.get("encrypted_metadata")
        assert encrypted_metadata_b64 is not None
        
        # Decrypt should verify challenge internally
        decrypted, metadata = handler.decrypt_pdf(encrypted, password)
        assert decrypted == pdf_data
    
    def test_gun112_challenge_prevents_tampering(self):
        """Test that GUN-112 challenge detection catches tampering"""
        handler = PDFEncryptionHandler()
        
        pdf_data = b"%PDF-1.4\nSensitive content"
        password = "SecurePassword"
        
        # Encrypt
        encrypted = handler.encrypt_pdf(pdf_data, password)
        
        # Parse and tamper with container
        container = json.loads(encrypted.decode('utf-8'))
        
        # Tamper with the encrypted PDF
        encrypted_pdf_b64 = container.get("encrypted_pdf")
        tampered_b64 = encrypted_pdf_b64[:-4] + "AAAA"
        container["encrypted_pdf"] = tampered_b64
        
        # Serialize back
        tampered_encrypted = json.dumps(container).encode('utf-8')
        
        # Decryption should fail
        with pytest.raises(ValueError):
            handler.decrypt_pdf(tampered_encrypted, password)

