# PasswordAnalyzer
A Python-based cybersecurity tool for analyzing password strength, detecting common patterns, and checking against known weak passwords.

## Features
- **Entropy Calculation** - Measures password randomness in bits
- **Complexity Analysis** - Checks for uppercase, lowercase, digits, special characters
- **Pattern Detection** - Identifies repeated characters, sequences, keyboard walks
- **Common Password Detection** - Checks against list of frequently used passwords
- **Detailed Reporting** - Provides actionable security recommendations

## Installation
```bash
git clone https://github.com/Eniphesoj/PasswordAnalyzer.git
cd PasswordAnalyzer
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

## Usage
```bash
python password_analyzer.py
```

Enter passwords when prompted to see detailed analysis.

## Example Output
```
==================================================
PASSWORD ANALYSIS REPORT
==================================================
Password: ************
Strength: Strong (8/10)
Entropy: 65.47 bits
Length: 12 characters

Complexity Checks:
  ✓ Length
  ✓ Has Lowercase
  ✓ Has Uppercase
  ✓ Has Digits
  ✓ Has Special
  ✓ No Common Patterns
==================================================
```

## How It Works

**Strength Scoring (0-10 points):**
- Length 12+ characters: +2
- Lowercase letters: +1
- Uppercase letters: +1
- Digits: +1
- Special characters: +2
- No common patterns: +2
- Not in common password list: +1

**Strength Levels:**
- 9-10: Very Strong
- 7-8: Strong
- 5-6: Medium
- 0-4: Weak

## License
MIT License


