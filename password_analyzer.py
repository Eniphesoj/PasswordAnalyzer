
import math
import re

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

# main analysis function
def analyze_password(password):
    # perform complete password analysis and return detailed analysis report
    common_passwords = load_common_passwords()

    #calculate scores
    entropy = calculate_entropy(password)
    complexity_checks = check_complexity(password)
    common_password = is_common_password(password, common_passwords)

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
        'is_common_password': common_password

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
        print("\nWARNING: This password is commonly used.")

    print("="*50 + "\n")

# main function with CLI
def main():
    print("="*50)
    print("PASSWORD STRENGTH ANALYZER")
    print("="*50)

    while True:
        password = input("\nEnter a password to analyze (or 'exit' to quit): ")
        if password.lower() == 'exit':
            print("Goodbye.")
            break
        if not password:
            print("Please enter a password.")
            continue

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
            if analysis['is_common_password']:
                print("- Avoid using common passwords.")

if __name__ == "__main__":
    main()