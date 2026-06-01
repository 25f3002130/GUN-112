"""
Example: Basic PDF Encryption and Decryption
Demonstrates how to use the encryption layer
"""
import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from gun112 import PDFEncryptionHandler


def example_basic_encryption():
    """Example: Encrypt and decrypt a PDF"""
    print("=" * 60)
    print("Example 1: Basic PDF Encryption and Decryption")
    print("=" * 60)
    
    # Initialize handler
    handler = PDFEncryptionHandler()
    
    # Simulate PDF data (in real usage, read from a file)
    pdf_data = b"%PDF-1.4\n1 0 obj\n<<\n/Type /Catalog\n/Pages 2 0 R\n>>\nendobj\n"
    print(f"Original PDF size: {len(pdf_data)} bytes")
    
    # Encrypt with a password
    password = "MySecurePassword123!"
    print(f"\nEncrypting with password: {password}")
    encrypted_data = handler.encrypt_pdf(pdf_data, password)
    print(f"Encrypted data size: {len(encrypted_data)} bytes")
    print(f"Encrypted (truncated): {str(encrypted_data[:100])}")
    
    # Decrypt with correct password
    print(f"\nDecrypting with correct password...")
    try:
        decrypted_pdf, metadata = handler.decrypt_pdf(encrypted_data, password)
        print("✓ Decryption successful!")
        print(f"Decrypted PDF matches original: {decrypted_pdf == pdf_data}")
    except ValueError as e:
        print(f"✗ Decryption failed: {e}")
    
    # Try with wrong password
    print(f"\nTrying with wrong password...")
    try:
        handler.decrypt_pdf(encrypted_data, "WrongPassword")
        print("✗ Should have failed!")
    except ValueError as e:
        print(f"✓ Correctly rejected wrong password: {e}")


def example_with_metadata():
    """Example: Encryption with metadata"""
    print("\n" + "=" * 60)
    print("Example 2: Encryption with Metadata")
    print("=" * 60)
    
    handler = PDFEncryptionHandler()
    
    pdf_data = b"%PDF-1.4\nSample document content"
    password = "SecurePass456"
    
    # Add metadata
    metadata = {
        "author": "John Doe",
        "title": "Confidential Report",
        "classification": "SECRET",
        "created": "2026-06-02"
    }
    
    print(f"Original metadata: {metadata}")
    print(f"\nEncrypting PDF with metadata...")
    encrypted = handler.encrypt_pdf(pdf_data, password, metadata)
    
    print(f"Decrypting PDF...")
    decrypted_pdf, returned_metadata = handler.decrypt_pdf(encrypted, password)
    
    print(f"✓ Retrieved metadata: {returned_metadata}")
    print(f"Metadata matches: {returned_metadata == metadata}")


def example_brute_force_protection():
    """Example: Rate limiting against brute-force attacks"""
    print("\n" + "=" * 60)
    print("Example 3: Brute-Force Protection (Rate Limiting)")
    print("=" * 60)
    
    handler = PDFEncryptionHandler()
    
    pdf_data = b"%PDF-1.4\nSensitive data"
    correct_password = "CorrectPassword789"
    wrong_passwords = [
        "password",
        "123456",
        "admin",
        "letmein",
        "password123"
    ]
    
    encrypted = handler.encrypt_pdf(pdf_data, correct_password)
    
    print("Attempting 5 wrong passwords:")
    for i, wrong_pwd in enumerate(wrong_passwords, 1):
        try:
            handler.decrypt_pdf(encrypted, wrong_pwd)
            print(f"  Attempt {i}: Failed to reject password")
        except ValueError as e:
            print(f"  Attempt {i}: {str(e)[:50]}...")
    
    print("\nAttempting with CORRECT password (should be locked):")
    try:
        handler.decrypt_pdf(encrypted, correct_password)
        print("  ✗ Unexpected success!")
    except ValueError as e:
        print(f"  ✓ Account locked: {str(e)[:60]}...")


def example_security_features():
    """Example: Overview of security features"""
    print("\n" + "=" * 60)
    print("Example 4: Security Features Overview")
    print("=" * 60)
    
    print("""
Security Features Implemented:

1. AES-256-GCM Encryption
   - Military-grade 256-bit encryption
   - Galois/Counter Mode for authenticated encryption
   - Prevents both eavesdropping and tampering
   - Result: Even stolen encrypted files are useless

2. Argon2 Key Derivation
   - Modern password hashing algorithm
   - Resistant to GPU/ASIC brute-force attacks
   - Configurable time, memory, and parallelism costs
   - Result: Simple passwords become computationally expensive to crack
   
3. Key Stretching (PBKDF2)
   - 100,000+ iterations of SHA-256
   - Makes dictionary attacks exponentially slower
   - Combined with Argon2 for multiple layers
   - Result: Each password guess takes significant computation time

4. Timestamp-Based Anti-Tampering
   - Encryption tied to creation timestamp
   - Timestamp component included in key derivation
   - Detects if encrypted content is modified
   - Result: Tampering attempts are detected and rejected

5. Rate Limiting
   - Maximum 5 failed decryption attempts
   - 15-minute lockout after exceeding limit
   - Per-file attempt tracking
   - Result: Brute-force attacks are prevented

6. Security-in-Depth Approach
   - Multiple independent security layers
   - Each layer protects against different attack vectors
   - Failure of one layer doesn't compromise others
   - Result: Very high security even against determined attackers
    """)


def example_real_pdf_file():
    """Example: Encrypt a real PDF file (if available)"""
    print("\n" + "=" * 60)
    print("Example 5: Real PDF File Encryption")
    print("=" * 60)
    
    # Check if a test PDF exists
    test_pdf_path = Path("./test_document.pdf")
    
    if test_pdf_path.exists():
        handler = PDFEncryptionHandler()
        
        # Read PDF
        with open(test_pdf_path, 'rb') as f:
            pdf_data = f.read()
        print(f"Loaded PDF: {test_pdf_path.name} ({len(pdf_data)} bytes)")
        
        # Encrypt
        password = "MyTestPassword123"
        encrypted = handler.encrypt_pdf(pdf_data, password)
        print(f"Encrypted size: {len(encrypted)} bytes")
        
        # Save encrypted
        encrypted_path = Path("./test_document.encrypted")
        with open(encrypted_path, 'wb') as f:
            f.write(encrypted)
        print(f"Saved to: {encrypted_path.name}")
        
        # Decrypt and verify
        decrypted_pdf, _ = handler.decrypt_pdf(encrypted, password)
        print(f"✓ Successfully decrypted and verified!")
        print(f"Original == Decrypted: {decrypted_pdf == pdf_data}")
    else:
        print(f"To test with a real PDF, place a file at: {test_pdf_path}")
        print("Then run this example again.")


if __name__ == "__main__":
    print("\n")
    print("╔" + "=" * 58 + "╗")
    print("║" + " " * 58 + "║")
    print("║" + "  PDF Encryption Layer - Security Examples".center(58) + "║")
    print("║" + " " * 58 + "║")
    print("╚" + "=" * 58 + "╝")
    
    # Run examples
    example_basic_encryption()
    example_with_metadata()
    example_brute_force_protection()
    example_security_features()
    example_real_pdf_file()
    
    print("\n" + "=" * 60)
    print("All examples completed!")
    print("=" * 60 + "\n")
