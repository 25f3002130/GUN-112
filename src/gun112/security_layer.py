"""
Security layer with rate limiting and attempt tracking
Protects against brute-force and dictionary attacks
"""
from datetime import datetime, timedelta
from typing import Dict, Tuple, Optional
import json
import os


class SecurityLayer:
    """
    Implements rate limiting, attempt tracking, and anti-brute-force measures
    """
    
    def __init__(self, max_attempts: int = 5, lockout_duration: timedelta = None):
        self.max_attempts = max_attempts
        self.lockout_duration = lockout_duration or timedelta(minutes=15)
        self.attempt_tracker: Dict[str, Dict] = {}
        self.lockout_file = ".security/lockout_log.json"
        self._ensure_storage()
    
    def _ensure_storage(self):
        """Ensure storage directory exists"""
        os.makedirs(".security", exist_ok=True)
    
    def _load_lockout_log(self) -> Dict:
        """Load lockout log from file"""
        if os.path.exists(self.lockout_file):
            try:
                with open(self.lockout_file, 'r') as f:
                    return json.load(f)
            except:
                return {}
        return {}
    
    def _save_lockout_log(self):
        """Save lockout log to file"""
        with open(self.lockout_file, 'w') as f:
            json.dump(self.attempt_tracker, f, indent=2)
    
    def record_attempt(self, identifier: str, success: bool = False) -> Tuple[bool, str]:
        """
        Record a decryption attempt for an identifier (e.g., file hash)
        
        Args:
            identifier: Unique identifier for the resource (file hash, etc)
            success: Whether the attempt was successful
            
        Returns:
            Tuple of (allowed: bool, message: str)
        """
        current_time = datetime.utcnow()
        
        if identifier not in self.attempt_tracker:
            self.attempt_tracker[identifier] = {
                "attempts": 0,
                "last_attempt": None,
                "locked_until": None,
                "successful": False
            }
        
        entry = self.attempt_tracker[identifier]
        
        # Check if currently locked
        if entry["locked_until"]:
            locked_until = datetime.fromisoformat(entry["locked_until"])
            if current_time < locked_until:
                remaining = locked_until - current_time
                return False, f"Too many failed attempts. Try again in {int(remaining.total_seconds())} seconds"
            else:
                # Lockout period expired, reset
                entry["attempts"] = 0
                entry["locked_until"] = None
        
        # Record attempt
        entry["attempts"] += 1
        entry["last_attempt"] = current_time.isoformat()
        
        if success:
            # Success - reset attempts
            entry["attempts"] = 0
            entry["successful"] = True
            entry["last_attempt"] = current_time.isoformat()
            self._save_lockout_log()
            return True, "Decryption successful"
        
        # Failed attempt
        if entry["attempts"] >= self.max_attempts:
            # Lock out
            locked_until = current_time + self.lockout_duration
            entry["locked_until"] = locked_until.isoformat()
            self._save_lockout_log()
            return False, f"Maximum attempts exceeded. Account locked for {int(self.lockout_duration.total_seconds())} seconds"
        
        self._save_lockout_log()
        remaining = self.max_attempts - entry["attempts"]
        return True, f"Decryption failed. {remaining} attempts remaining"
    
    def is_locked(self, identifier: str) -> bool:
        """Check if identifier is currently locked"""
        if identifier not in self.attempt_tracker:
            return False
        
        entry = self.attempt_tracker[identifier]
        if not entry["locked_until"]:
            return False
        
        locked_until = datetime.fromisoformat(entry["locked_until"])
        return datetime.utcnow() < locked_until
    
    def get_status(self, identifier: str) -> Dict:
        """Get security status for identifier"""
        if identifier not in self.attempt_tracker:
            return {
                "attempts": 0,
                "locked": False,
                "remaining_attempts": self.max_attempts
            }
        
        entry = self.attempt_tracker[identifier]
        is_locked = self.is_locked(identifier)
        
        return {
            "attempts": entry["attempts"],
            "locked": is_locked,
            "remaining_attempts": max(0, self.max_attempts - entry["attempts"]),
            "last_attempt": entry["last_attempt"],
            "locked_until": entry["locked_until"]
        }
    
    def reset_attempts(self, identifier: str):
        """Reset attempts for an identifier"""
        if identifier in self.attempt_tracker:
            self.attempt_tracker[identifier] = {
                "attempts": 0,
                "last_attempt": None,
                "locked_until": None,
                "successful": False
            }
            self._save_lockout_log()
