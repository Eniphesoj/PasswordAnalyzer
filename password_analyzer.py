
import math
import re
import hashlib
import requests
from time import sleep

#entropy calculation function
def calculate_entropy(password):
    # calculate password entropy in bits. Higher entropy means a stronger password.
    pool_size= 0   # determine character pool size based on types of characters used
    if re.search(r'[a-z]', password):
        pool_size += 26  # lowercase letters
    if re.search(r'[A-Z]', password):
        pool_size += 26  # uppercase letters
    if re.search(r'[0-9]', password):
        pool_size += 10  # digits
    if re.search(r'[^a-zA-Z0-9]', password):
        pool_size += 32  # common special characters

    # calculate entropy
    if pool_size == 0:
        return 0
    
    entropy = len(password) * math.log2(pool_size)
    return entropy

# pattern detection function
def has_common_patterns(password):
    # detect common weak patterns in passwords
    password_lower = password.lower()

    # check for repeated characters/ common sequence
    if re.search(r'(.)\1{2,}', password):  # three or more repeated characters
        return True
    
    #check for sequential characters
    sequences = ['123', 'abc', 'qwerty', 'password', 'letmein', 'admin', 'welcome', 'asdf']
    for seq in sequences:
        if seq in password_lower or seq[::-1] in password_lower:  # check for sequence and its reverse
            return True
        
    # check for keyboard walks
    keyboard_patterns = ['qwerty', 'asdf', 'zxcv', '1234567890', '1q2w3e']
    for pattern in keyboard_patterns:
        if pattern in password_lower:
            return True
        
    return False

# complexity checker function
def check_complexity(password):
    # check if password meets complexity requirements. returns a dictionary of complexity checks
    checks = {
        'length': len(password) >= 12,  # minimum length requirement
        'has_lowercase': bool(re.search(r'[a-z]', password)),  # contains lowercase letter
        'has_uppercase': bool(re.search(r'[A-Z]', password)),  # contains uppercase letter
        'has_digit': bool(re.search(r'[0-9]', password)),  # contains digit
        'has_special_char': bool(re.search(r'[^a-zA-Z0-9]', password)),  # contains special character
        'has_no_common_patterns': not has_common_patterns(password)  # does not contain common patterns
    }
    return checks

# common password loader function
def load_common_passwords(filename= 'common_passwords.txt'):
    # load common password from file
    try:
        with open(filename, 'r') as f:
            return set(line.strip().lower() for line in f)
    except FileNotFoundError:
        print(f"Warning: {filename} not found.")
        return set()
    
# common password checker function
def is_common_password(password, common_passwords):
    # check if password is in the list of common passwords
    return password.lower() in common_passwords
    
def check_pwned_password(password):
    # checks if password has been exposed in cata breaches using HIBP API.
    # uses k-anonimity model -only sends the first 5 chars of hash
    # returns: int: number of times the password appears in breaches (0 if not found)

    # hash the password with SHA-1
    sha1_password = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()

    # split hash into prefix (first 5 chars) and suffix (the rest of the chars)
    prefix = sha1_password[:5]
    suffix = sha1_password[5:]

    #query HIBP API with prefix only
    url = f"https://api.pwnedpasswords.com/range/{prefix}"

    try:
        response =  requests.get(url, timeout=5)
        if response.status_code == 200:
            # parse response (format is "SUFFIX:COUNT")
            hashes = response.text.split('\r\n')

            for hash_line in hashes:
                hash_suffix, count = hash_line.split(':')
                if hash_suffix == suffix:
                    return int(count)  

            # password not found in breach
            return 0
        else: 
            print("Could not check breach database (API error)")
            return -1
    
    except requests.exceptions.RequestException:
        print("Could not check breach database (network error)")
        return -1
    
# main analysis function
def analyze_password(password):
    # perform complete password analysis and return detailed analysis report
    common_passwords = load_common_passwords()

    #calculate scores
    entropy = calculate_entropy(password)
    complexity_checks = check_complexity(password)
    common_password = is_common_password(password, common_passwords)
    breach_count = check_pwned_password(password)

    # determine strength score based on criteria
    score = 0
    if complexity_checks['length']:
        score += 2
    if complexity_checks['has_lowercase']:
        score += 1
    if complexity_checks['has_uppercase']:
        score += 1
    if complexity_checks['has_digit']:
        score += 1
    if complexity_checks['has_special_char']:
        score += 2
    if complexity_checks['has_no_common_patterns']:
        score += 2
    if not common_password:
        score += 1
    if breach_count > 0:
        score = max(0, score - 3) # to redcuce score significantly
    
    # map score to strength level
    if score >= 9:
        strength = 'Very Strong'
    elif score >= 7:
        strength = 'Strong'
    elif score >= 5:
        strength = 'Medium'
    else:
        strength = 'Weak'

    return {
        'password': password,
        'strength': strength,
        'score': score,
        'entropy': round(entropy, 2),
        'length': len(password),
        'complexity': complexity_checks,
        'is_common_password': common_password,
        'breach_count': breach_count
    }

# print function
def print_analysis_report(analysis):
    # display the password report in a formatted report
    print("\n" + "="*50)
    print("PASSWORD ANALYSIS REPORT")
    print("="*50)
    print("="*50)
    print(f"Password: {'*' * len(analysis['password'])}") 
    print(f"Strength: {analysis['strength']} ({analysis['score']}/10)")
    print(f"Entropy: {analysis['entropy']} bits")
    print(f"Length: {analysis['length']} characters")
    print(f"\nComplexity checks: ")
    for checks, passed in analysis['complexity'].items():
        status = "PASS" if passed else "FAIL"
        print(f" {status} {checks.replace('_', ' ').title()}")

    if analysis['is_common_password']:
        print(F"\nWARNING: This password is commonly used.")
    if analysis['breach_count'] > 0:
        print(f"\nCRITICAL: This password has been exposed in {analysis['breach_count']:,} data breaches!")
        print(f" This pasword is NOT SAFE to use anywhere.")
    elif analysis['breach_count'] == 0:
        print(f"\nGood news: Password not found in known data breaches")
    
    print("="*50 + "\n")

def generate_secure_password(length=16, include_special=True):
    """
    Generate a cryptographically secure random password.
    
    Args:
        length (int): Length of password (default 16)
        include_special (bool): Include special characters
        
    Returns:
        str: Generated password
    """
    import secrets
    import string
    
    # Define character sets
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    special = "!@#$%^&*()-_=+[]{}|;:,.<>?"
    
    # Build character pool
    characters = lowercase + uppercase + digits
    if include_special:
        characters += special
    
    # Ensure at least one of each type
    password = [
        secrets.choice(lowercase),
        secrets.choice(uppercase),
        secrets.choice(digits),
    ]
    
    if include_special:
        password.append(secrets.choice(special))
    
    # Fill rest with random characters
    remaining_length = length - len(password)
    password.extend(secrets.choice(characters) for _ in range(remaining_length))
    
    # Shuffle to avoid predictable pattern
    secrets.SystemRandom().shuffle(password)
    
    return ''.join(password)

# main function with CLI
def main():
    print("="*50)
    print("PASSWORD STRENGTH ANALYZER")
    print("="*50)
    print("\nOptions:")
    print(" 1. Analyze a password")
    print(" 2. Generate a secure password")
    print(" 3. Quit")

    while True:
        print("\n" + "-"*50)
        choice = input("Choose an option (1/2/3): ").strip()
        
        if choice == '1':
            # Analyze password
            password = input("\nEnter password to analyze: ")
            if not password:
                print("Please enter a password.")
                continue
            print("\nAnalyzing... (checking breach database)")
            analysis = analyze_password(password)
            print_analysis_report(analysis)

            # recommendations for improving password strength
            if analysis['score'] < 7:
                print("Recommendations to improve password strength:")
                if not analysis['complexity']['length']:
                    print("- Use at least 12 characters.")
                if not analysis['complexity']['has_lowercase']:
                    print("- Include lowercase letters.")
                if not analysis['complexity']['has_uppercase']:
                    print("- Include uppercase letters.")
                if not analysis['complexity']['has_digit']:
                    print("- Include digits.")
                if not analysis['complexity']['has_special_char']:
                    print("- Include special characters.")
                if not analysis['complexity']['has_no_common_patterns']:
                    print("- Avoid common patterns and sequences.")
                if analysis['breach_count'] > 0:
                    print("- NEVER use this password - it's been breached!")

        elif choice == '2':
                # Generate password
                try:
                    length = input("\nPassword length (recommended 16): ").strip()
                    length = int(length) if length else 16
                    
                    if length < 12:
                        print("Warning: Passwords shorter than 12 characters are not recommended")
                        confirm = input("Continue anyway? (y/n): ").lower()
                        if confirm != 'y':
                            continue
                    
                    special = input("Include special characters? (y/n, default y): ").strip().lower()
                    include_special = special != 'n'
                    
                    password = generate_secure_password(length, include_special)
                    
                    print("\n" + "="*50)
                    print("GENERATED PASSWORD")
                    print("="*50)
                    print(f"\n{password}\n")
                    print("Save this password securely!")
                    print("="*50)
                    
                    # Analyze the generated password
                    analyze_gen = input("\nAnalyze this password? (y/n): ").lower()
                    if analyze_gen == 'y':
                        print("\nAnalyzing...")
                        analysis = analyze_password(password)
                        print_analysis_report(analysis)
                    
                except ValueError:
                    print("Invalid length. Please enter a number.")
            
        elif choice == '3':
            print("\nGoodbye!")
            break
        
        else:
            print("Invalid option. Please choose 1, 2, or 3.")


if __name__ == "__main__":
    main()