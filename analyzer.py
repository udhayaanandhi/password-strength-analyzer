import re
import math
import secrets
import string
import hashlib
import urllib.request
import urllib.error

class PasswordAnalyzer:
    def __init__(self):
        pass

    def check_pwned(self, password):
        """Checks if the password has been exposed in data breaches using Have I Been Pwned API."""
        sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
        prefix = sha1_hash[:5]
        suffix = sha1_hash[5:]
        url = f"https://api.pwnedpasswords.com/range/{prefix}"
        
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'ShieldCheck-Analyzer'})
            with urllib.request.urlopen(req, timeout=3) as response:
                if response.status == 200:
                    hashes = (line.decode('utf-8').split(':') for line in response)
                    for h, count in hashes:
                        if h == suffix:
                            return int(count)
            return 0
        except urllib.error.URLError:
            # Silently fail if API is unreachable rather than breaking the app
            return 0

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

    def assess_patterns(self, password, feedback, score):
        """Checks for repeated or sequential patterns."""
        # Repeating characters e.g. 'aaaaa'
        if re.search(r'(.)\1{2,}', password):
            feedback.append("Avoid repeating consecutive characters.")
            score -= 1
            
        # Sequential characters (simple check for sequences like '123' or 'abc')
        seqs = ['01234567890', 'abcdefghijklmnopqrstuvwxyz', 'qwertyuiop', 'asdfghjkl']
        lower_pass = password.lower()
        for seq in seqs:
            for i in range(len(seq) - 3):
                if seq[i:i+4] in lower_pass or seq[i:i+4][::-1] in lower_pass:
                    feedback.append("Avoid standard sequential/keyboard patterns (e.g., '1234', 'qwer').")
                    score -= 1
                    return score # Break early if one pattern is found
        return score

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

        # 3. Patterns Check
        score = self.assess_patterns(password, feedback, score)

        # 4. Have I Been Pwned API Check
        pwned_count = self.check_pwned(password)
        if pwned_count > 0:
            score = -10 # Heavy penalty
            feedback.append(f"CRITICAL: This password has been exposed in {pwned_count:,} data breaches! Do not use it.")

        # Clamp max score at lower bounds
        score = max(0, score)

        # Classification
        if score >= 5 and pwned_count == 0: strength = "Strong"
        elif score >= 3 and pwned_count == 0: strength = "Medium"
        else: strength = "Weak"

        return {
            "score": score,
            "strength": strength,
            "entropy": self.calculate_entropy(password),
            "feedback": feedback
        }

    def generate_strong_password(self, length=16):
        """Generates a secure password ensuring at least one of each character type."""
        if length < 4:
            length = 4
            
        alphabet = string.ascii_letters + string.digits + string.punctuation
        while True:
            password = ''.join(secrets.choice(alphabet) for _ in range(length))
            if (any(c.islower() for c in password)
                and any(c.isupper() for c in password)
                and sum(c.isdigit() for c in password) >= 2
                and any(c in string.punctuation for c in password)):
                return password

    def hash_password(self, password):
        """Hashes password for secure storage."""
        return hashlib.sha256(password.encode()).hexdigest()