import os
import sys

# --- Simulated "Codebase" ---
DUMMY_CODE = """
import os
import requests

def fetch_data(url):
    # Insecure: Using http instead of https, and direct string concatenation
    # This would be flagged by a SAST tool, demonstrating 'shift left' security.
    if url.startswith("http://"):
        print("WARNING: Using insecure HTTP protocol!")
    response = requests.get(url)
    return response.json()

def process_payment(amount, user_id):
    # Insecure: Hardcoded secret (e.g., API key)
    # This would be flagged by a SAST or secret scanning tool, stopping the pipeline early.
    API_KEY = "sk_test_hardcoded_secret_12345"
    print(f"Processing payment for {user_id} with amount {amount} using key {API_KEY}")
    # ... actual payment logic ...

def main():
    print("Application started.")
    # Example usage
    data = fetch_data("http://example.com/api/data") # This will trigger an SAST warning
    process_payment(100, "user123") # This will trigger an SAST warning
    print("Application finished.")

if __name__ == "__main__":
    main()
"""

DUMMY_REQUIREMENTS = """
requests==2.25.1
flask==1.1.2
# Known vulnerable dependency for demonstration (urllib3 < 1.26.0 had issues)
# A real SCA tool would flag this, demonstrating early dependency vulnerability detection.
urllib3==1.25.10
"""

# --- Simulated Security Checks ---

def run_sast_check(code_content):
    """
    Simulates a Static Application Security Testing (SAST) check.
    Looks for common insecure patterns in the code.
    """
    print("\n--- Running SAST (Static Analysis) ---")
    issues_found = []

    # Check for hardcoded secrets
    if "API_KEY = \"sk_test_hardcoded_secret_" in code_content:
        issues_found.append("Hardcoded API key found. Use environment variables or a secret manager.")

    # Check for insecure protocol usage (e.g., http instead of https)
    if "http://" in code_content and "requests.get" in code_content:
        issues_found.append("Insecure HTTP protocol usage detected in network requests.")

    if issues_found:
        print("SAST FAILED! Issues found:")
        for issue in issues_found:
            print(f"  - {issue}")
        return False # Fail the pipeline early due to security issues
    else:
        print("SAST PASSED. No critical issues found.")
        return True

def run_sca_check(requirements_content):
    """
    Simulates a Software Composition Analysis (SCA) check.
    Looks for known vulnerable dependencies.
    """
    print("\n--- Running SCA (Dependency Analysis) ---")
    issues_found = []
    # Example: versions known to have issues (simplified for demonstration)
    vulnerable_deps = {
        "urllib3": ["1.25.10", "1.26.0"], 
        "flask": ["1.0.0", "1.1.0"],
    }

    for line in requirements_content.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            dep_name, dep_version = line.split("==")
            if dep_name in vulnerable_deps and dep_version in vulnerable_deps[dep_name]:
                issues_found.append(f"Vulnerable version of '{dep_name}' detected: {dep_version}. Please update.")
        except ValueError:
            pass # Malformed line, ignore for this simple example

    if issues_found:
        print("SCA FAILED! Vulnerable dependencies found:")
        for issue in issues_found:
            print(f"  - {issue}")
        return False # Fail the pipeline early due to vulnerable dependencies
    else:
        print("SCA PASSED. No known vulnerable dependencies found.")
        return True

def run_unit_tests():
    """
    Simulates running unit tests.
    """
    print("\n--- Running Unit Tests ---")
    # In a real scenario, this would execute actual test files.
    # For this example, we'll just simulate a pass/fail.
    test_success = True # Assume tests pass if security checks didn't stop us
    if test_success:
        print("Unit tests PASSED.")
        return True
    else:
        print("Unit tests FAILED.")
        return False

def run_dast_check():
    """
    Simulates a very basic Dynamic Application Security Testing (DAST) check.
    This would typically run against a deployed application.
    """
    print("\n--- Running DAST (Dynamic Analysis) ---")
    # A real DAST tool would scan a running application for vulnerabilities.
    # This is a placeholder to show it's part of the pipeline.
    print("DAST check completed (simulated). No critical issues found.")
    return True

def deploy_application():
    """
    Simulates deploying the application.
    """
    print("\n--- Deploying Application ---")
    print("Application deployed successfully to staging environment (simulated).")
    return True

# --- Main DevSecOps CI/CD Pipeline Simulation ---

def main_pipeline():
    print("--- Starting DevSecOps CI/CD Pipeline ---")

    # Step 1: Code Commit (Implicit - we have the DUMMY_CODE)
    print("\n--- Code Changes Detected (Simulated) ---")

    # Step 2: Pre-build Security Checks (Shift Left!)
    # This is where DevSecOps integrates security early in the CI/CD process.
    if not run_sast_check(DUMMY_CODE):
        print("\nPipeline stopped due to SAST failures. Fix security issues before proceeding.")
        sys.exit(1) # Fail early to prevent insecure code from progressing

    if not run_sca_check(DUMMY_REQUIREMENTS):
        print("\nPipeline stopped due to SCA failures. Update vulnerable dependencies.")
        sys.exit(1) # Fail early to prevent vulnerable dependencies from being built/deployed

    # Step 3: Build and Test (CI)
    if not run_unit_tests():
        print("\nPipeline stopped due to Unit Test failures.")
        sys.exit(1)

    # Step 4: Post-build/Pre-deployment Security Checks (Optional, but good practice)
    # Could include container image scanning, IaC scanning, etc.

    # Step 5: Deployment (CD)
    if not deploy_application():
        print("\nPipeline stopped due to deployment failures.")
        sys.exit(1)

    # Step 6: Post-deployment Security Checks (DAST)
    # DAST typically runs against a running application, usually in a staging environment.
    if not run_dast_check():
        print("\nPipeline stopped due to DAST failures. Fix security issues in deployed app.")
        sys.exit(1)

    print("\n--- DevSecOps CI/CD Pipeline Completed Successfully! ---")
    print("Application is secure and ready for production (simulated).")

if __name__ == "__main__":
    main_pipeline()
