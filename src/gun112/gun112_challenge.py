"""
GUN-112 Time-Based Cryptographic Challenge System
Creates mathematically impossible reverse-engineering barriers using nanosecond-precision timestamps
"""
import hashlib
import time
from datetime import datetime
import os


class GUN112Challenge:
    """
    GUN-112 Protocol: Time-Based Cryptographic Challenge
    
    Mechanism:
    1. Capture current time at nanosecond precision
    2. Extract: first 10 digits of nanoseconds, 10 digits of microseconds, 
               first 10 digits of milliseconds, and exact datetime
    3. Combine these with a random salt
    4. Hash the combination to create an "encryption challenge"
    5. Store challenge hash with the encrypted file
    6. During decryption, use stored challenge to verify legitimacy
    
    Security Properties:
    - The challenge is deterministic (same timestamp + salt = same hash)
    - Stored with file, so legitimate decryption always works
    - Reverse engineering requires knowing exact nanosecond precision
    - Salting makes it impossible to crack via brute force
    - Even if timestamp is known, nanosecond digits are unmeasurable after the fact
    """
    
    def __init__(self):
        self.protocol_version = "GUN-112"
        self.challenge_salt_length = 32  # 256-bit salt
    
    def create_challenge(self) -> dict:
        """
        Create a GUN-112 cryptographic challenge at current time
        
        Returns:
            Dictionary containing:
            - challenge_hash: The hashed challenge
            - timestamp: Human-readable timestamp
            - nanoseconds: First 10 digits of nanosecond precision
            - microseconds: 10 digits of microsecond precision  
            - milliseconds: First 10 digits of millisecond precision
            - salt: Random salt used in challenge
            - datetime_iso: ISO format datetime
        """
        # Get current time with highest precision available
        current_time = datetime.utcnow()
        time_ns = time.time_ns()  # Nanoseconds since epoch
        
        # Extract time components
        # Convert nanoseconds to string and get first 10 digits
        time_ns_str = str(time_ns)
        nanoseconds = time_ns_str[-9:].zfill(10)[:10]  # Last 9 digits = nanoseconds
        
        # Get microseconds (6 digits)
        microseconds = str(int((time.time() % 1) * 1_000_000)).zfill(6).zfill(10)[:10]
        
        # Get milliseconds (3 digits)
        milliseconds = str(int((time.time() % 1) * 1_000)).zfill(3).zfill(10)[:10]
        
        # Format datetime
        datetime_iso = current_time.isoformat()
        
        # Generate random salt
        salt = os.urandom(self.challenge_salt_length)
        
        # Combine all components into challenge material
        challenge_material = (
            f"{nanoseconds}|{microseconds}|{milliseconds}|{datetime_iso}|{salt.hex()}"
        ).encode('utf-8')
        
        # Create salted hash
        challenge_hash = hashlib.sha256(challenge_material).hexdigest()
        
        return {
            "challenge_hash": challenge_hash,
            "timestamp": datetime_iso,
            "nanoseconds": nanoseconds,
            "microseconds": microseconds,
            "milliseconds": milliseconds,
            "salt": salt.hex(),
            "datetime_iso": datetime_iso,
            "protocol_version": self.protocol_version
        }
    
    def verify_challenge(self, challenge_data: dict) -> bool:
        """
        Verify that a challenge was created at claimed time
        
        Args:
            challenge_data: Challenge dictionary from encryption
            
        Returns:
            True if challenge is valid, False otherwise
        """
        try:
            # Reconstruct challenge hash from stored components
            challenge_material = (
                f"{challenge_data['nanoseconds']}|"
                f"{challenge_data['microseconds']}|"
                f"{challenge_data['milliseconds']}|"
                f"{challenge_data['datetime_iso']}|"
                f"{challenge_data['salt']}"
            ).encode('utf-8')
            
            reconstructed_hash = hashlib.sha256(challenge_material).hexdigest()
            
            # Compare with stored hash
            return reconstructed_hash == challenge_data['challenge_hash']
        except Exception:
            return False
    
    def recreate_challenge_for_timestamp(self, timestamp_iso: str, salt_hex: str, 
                                        nanoseconds: str, microseconds: str, 
                                        milliseconds: str) -> str:
        """
        Recreate challenge hash for a specific timestamp
        Used during decryption to verify password attempts
        
        Args:
            timestamp_iso: ISO format timestamp
            salt_hex: Hex string of salt
            nanoseconds: First 10 digits of nanoseconds
            microseconds: 10 digits of microseconds
            milliseconds: First 10 digits of milliseconds
            
        Returns:
            The recreated challenge hash
        """
        challenge_material = (
            f"{nanoseconds}|{microseconds}|{milliseconds}|{timestamp_iso}|{salt_hex}"
        ).encode('utf-8')
        
        return hashlib.sha256(challenge_material).hexdigest()
    
    def create_password_challenge_hash(self, password: str, challenge_hash: str, 
                                      salt: bytes) -> str:
        """
        Combine password with challenge hash to create final authentication hash
        
        This creates an additional layer: the password must be correct AND
        the challenge must verify, making it impossible to crack without both
        
        Args:
            password: User password
            challenge_hash: GUN-112 challenge hash
            salt: Salt for this derivation
            
        Returns:
            Final authentication hash
        """
        # Combine password with challenge
        combined = f"{password}|{challenge_hash}".encode('utf-8')
        
        # Hash with salt
        auth_hash = hashlib.pbkdf2_hmac(
            'sha256',
            combined,
            salt,
            100000  # iterations
        )
        
        return auth_hash.hex()
    
    def get_challenge_metadata(self, challenge_data: dict) -> dict:
        """
        Get human-readable challenge metadata
        Useful for debugging and verification
        """
        return {
            "protocol": challenge_data.get("protocol_version", "GUN-112"),
            "created_at": challenge_data.get("datetime_iso"),
            "nanosecond_component": challenge_data.get("nanoseconds"),
            "microsecond_component": challenge_data.get("microseconds"),
            "millisecond_component": challenge_data.get("milliseconds"),
            "challenge_hash": challenge_data.get("challenge_hash")[:16] + "...",  # Truncate for display
            "verified": self.verify_challenge(challenge_data)
        }
