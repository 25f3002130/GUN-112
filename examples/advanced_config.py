"""
Advanced Usage: Custom Security Configuration
Shows how to customize security parameters
"""
from datetime import timedelta
from pathlib import Path
import sys

# Add src to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from gun112.config import SecurityConfig, security_config
from gun112 import PDFEncryptionHandler


def example_custom_security_config():
    """Example: Customize security settings"""
    print("=" * 60)
    print("Advanced Example: Custom Security Configuration")
    print("=" * 60)
    
    print("\nCurrent Security Configuration:")
    print(f"  Encryption Algorithm: {security_config.ENCRYPTION_ALGORITHM}")
    print(f"  Key Size: {security_config.KEY_SIZE} bytes ({security_config.KEY_SIZE * 8} bits)")
    print(f"\n  Argon2 Parameters:")
    print(f"    Time Cost: {security_config.ARGON2_TIME_COST}")
    print(f"    Memory Cost: {security_config.ARGON2_MEMORY_COST} MB")
    print(f"    Parallelism: {security_config.ARGON2_PARALLELISM} threads")
    print(f"    Salt Length: {security_config.ARGON2_SALT_LENGTH} bytes")
    print(f"\n  Key Stretching:")
    print(f"    Iterations: {security_config.KEY_STRETCH_ITERATIONS}")
    print(f"\n  Rate Limiting:")
    print(f"    Max Attempts: {security_config.MAX_DECRYPTION_ATTEMPTS}")
    print(f"    Lockout Duration: {security_config.LOCKOUT_DURATION}")
    print(f"\n  Timestamp Validation:")
    print(f"    Enabled: {security_config.ENABLE_TIMESTAMP_VALIDATION}")
    print(f"    Tolerance: {security_config.TIMESTAMP_TOLERANCE} seconds")


def example_security_level_explanation():
    """Example: Explain different security levels"""
    print("\n" + "=" * 60)
    print("Security Levels Explanation")
    print("=" * 60)
    
    levels = {
        "Basic": {
            "description": "Good for normal users",
            "time_cost": 2,
            "memory_cost": 64,
            "key_stretch": 50000,
            "details": "Fast but still resistant to attacks"
        },
        "Standard": {
            "description": "Recommended for most applications",
            "time_cost": 4,
            "memory_cost": 128,
            "key_stretch": 100000,
            "details": "Good balance of security and performance"
        },
        "High": {
            "description": "For highly sensitive data",
            "time_cost": 8,
            "memory_cost": 256,
            "key_stretch": 200000,
            "details": "Very resistant to brute-force"
        },
        "Maximum": {
            "description": "For most critical systems",
            "time_cost": 16,
            "memory_cost": 512,
            "key_stretch": 500000,
            "details": "Nearly impenetrable (slower encryption)"
        }
    }
    
    for level_name, level_info in levels.items():
        print(f"\n{level_name} Security Level:")
        print(f"  {level_info['description']}")
        print(f"  Time Cost: {level_info['time_cost']}")
        print(f"  Memory Cost: {level_info['memory_cost']} MB")
        print(f"  Key Stretching: {level_info['key_stretch']} iterations")
        print(f"  → {level_info['details']}")


def example_attack_scenarios():
    """Example: Explain protection against different attacks"""
    print("\n" + "=" * 60)
    print("Attack Scenarios & Protection")
    print("=" * 60)
    
    scenarios = {
        "Brute-Force Attack": {
            "attack": "Attacker tries many passwords",
            "protection": "AES-256-GCM + Argon2 + Rate Limiting",
            "result": "Each attempt is computationally expensive; after 5 failures, 15-min lockout"
        },
        "Dictionary Attack": {
            "attack": "Attacker uses common password lists",
            "protection": "Key stretching (100,000 PBKDF2 iterations)",
            "result": "Each password from dictionary takes 100,000x more time"
        },
        "Stolen Encrypted File": {
            "attack": "Attacker obtains encrypted file",
            "protection": "AES-256-GCM authentication & Timestamp validation",
            "result": "File is useless without correct password; tampering detected"
        },
        "Password Interception": {
            "attack": "Attacker intercepts password",
            "protection": "Argon2 hash + salt (password never stored in plaintext)",
            "result": "Hash is useless; even with password, attacker needs correct salt"
        },
        "Replay Attack": {
            "attack": "Attacker replays old encrypted data",
            "protection": "Timestamp-based key derivation + Validation",
            "result": "Old encrypted data won't decrypt with current timestamp component"
        },
        "GPU Acceleration": {
            "attack": "Attacker uses GPU for faster hashing",
            "protection": "Argon2 (memory-hard) + Key stretching",
            "result": "GPU acceleration ineffective; memory requirements dominate"
        }
    }
    
    for scenario_name, scenario in scenarios.items():
        print(f"\n{scenario_name}:")
        print(f"  Attack: {scenario['attack']}")
        print(f"  Protection: {scenario['protection']}")
        print(f"  Result: {scenario['result']}")


def example_password_recommendations():
    """Example: Password recommendations"""
    print("\n" + "=" * 60)
    print("Password Recommendations")
    print("=" * 60)
    
    print("""
Best Practices for Passwords:

1. Length
   ✓ Use at least 12-16 characters
   ✗ Don't use short passwords (even 6-8 chars)
   → Impact: Longer passwords exponentially harder to crack

2. Complexity
   ✓ Mix uppercase, lowercase, numbers, and symbols
   ✗ Don't use only lowercase letters
   → Impact: Increases password space from 26 to 94+ characters

3. Randomness
   ✓ Use random generated passwords when possible
   ✗ Don't use predictable patterns or personal info
   → Impact: Dictionary attacks become ineffective

4. Uniqueness
   ✓ Use different passwords for different files
   ✗ Don't reuse passwords
   → Impact: If one password is compromised, others stay safe

5. Even with SIMPLE passwords
   ✓ This system protects you
   → Our Argon2 + key stretching makes even weak passwords strong
   → Rate limiting prevents brute-force attempts
   → GCM authentication detects tampering

Examples:
   Weak Password    →  "123456"     (but still protected here!)
   Medium Password  →  "MyPass2026"
   Strong Password  →  "M7p@2K26x$Qk9!"
   Very Strong      →  Randomly generated: "Xp2$kL9@m4Q7w&R3J!"
    """)


if __name__ == "__main__":
    print("\n")
    print("╔" + "=" * 58 + "╗")
    print("║" + " " * 58 + "║")
    print("║" + "  PDF Encryption - Advanced Configuration Examples".center(58) + "║")
    print("║" + " " * 58 + "║")
    print("╚" + "=" * 58 + "╝")
    
    example_custom_security_config()
    example_security_level_explanation()
    example_attack_scenarios()
    example_password_recommendations()
    
    print("\n" + "=" * 60)
    print("Advanced examples completed!")
    print("=" * 60 + "\n")
