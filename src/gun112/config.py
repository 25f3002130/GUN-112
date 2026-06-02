"""
Configuration and security constants for PDF encryption layer
"""
from datetime import timedelta


class SecurityConfig:
    """Security configuration for PDF encryption"""
    
    # GUN-112 Protocol: Time-Based Cryptographic Challenge (umbrella protocol)
    ENCRYPTION_PROTOCOL = "GUN-112"
    ENCRYPTION_ALGORITHM = "AES-256-GCM"
    KEY_SIZE = 32  # 256 bits

    # GUN-112-GKP: Ghost Key Protocol (identity/asymmetric sub-protocol)
    GKP_PROTOCOL = "GUN-112-GKP"
    GKP_LOCK_MODE = "GKP"  # value stored in container's lock_mode field

    # Argon2 key derivation parameters
    ARGON2_TIME_COST = 4  # iterations
    ARGON2_MEMORY_COST = 128  # MB
    ARGON2_PARALLELISM = 4  # threads
    ARGON2_SALT_LENGTH = 16  # bytes
    
    # Additional security layers
    NONCE_LENGTH = 12  # bytes for GCM mode
    TAG_LENGTH = 16  # bytes for GCM authentication tag
    
    # Rate limiting
    MAX_DECRYPTION_ATTEMPTS = 5
    LOCKOUT_DURATION = timedelta(minutes=15)
    ATTEMPT_RESET_DURATION = timedelta(hours=1)
    
    # Timestamp-based security
    ENABLE_TIMESTAMP_VALIDATION = True
    TIMESTAMP_TOLERANCE = 300  # seconds (5 minutes)
    
    # Key stretching iterations
    KEY_STRETCH_ITERATIONS = 100000


# Load configuration
security_config = SecurityConfig()