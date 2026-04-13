import re
import math
import secrets
import string
import hashlib

class PasswordAnalyzer:
    def __init__(self):
        # Common weak patterns
        self.common_passwords = ["password123", "12345678", "qwertyuiop", "admin123"]

    def calculate_entropy(self, password):
        """Calculates the Shannon Entropy of the password."""
        if not password:
            return 0
        character_set = 0
        if any(c.islower() for c in password): character_set += 26
        if any(c.isupper() for c in password): character_set += 26
        if any(c.isdigit() for c in password): character_set += 10
        if any(c in string.punctuation for c in password): character_set += 32
        
        entropy = len(password) * math.log2(character_set) if character_set > 0 else 0
        return round(entropy, 2)

    def evaluate(self, password):
        score = 0
        feedback = []

        # 1. Length Check
        if len(password) >= 12: score += 2
        elif len(password) >= 8: score += 1
        else: feedback.append("Increase length to at least 12 characters.")

        # 2. Complexity Checks
        if re.search(r"[A-Z]", password): score += 1
        else: feedback.append("Add uppercase letters.")
        
        if re.search(r"[a-z]", password): score += 1
        
        if re.search(r"\d", password): score += 1
        else: feedback.append("Add numbers.")
        
        if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password): score += 1
        else: feedback.append("Add special characters.")

        # 3. Pattern/Uniqueness Check
        if password.lower() in self.common_passwords:
            score = 0
            feedback.append("This is a very common password. Avoid it!")

        # Classification
        if score >= 5: strength = "Strong"
        elif score >= 3: strength = "Medium"
        else: strength = "Weak"

        return {
            "score": score,
            "strength": strength,
            "entropy": self.calculate_entropy(password),
            "feedback": feedback
        }

    def generate_strong_password(self, length=16):
        alphabet = string.ascii_letters + string.digits + string.punctuation
        return ''.join(secrets.choice(alphabet) for _ in range(length))

    def hash_password(self, password):
        """Hashes password for secure storage."""
        return hashlib.sha256(password.encode()).hexdigest()