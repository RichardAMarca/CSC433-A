import hashlib
import os
import json

def calculate_file_hash(filepath):
    """Calculates the SHA256 hash of a file."""
    hasher = hashlib.sha256()
    with open(filepath, 'rb') as f:
        while True:
            chunk = f.read(4096)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()

def create_baseline(monitored_paths, baseline_file="baseline.json"):
    """Creates a baseline of file hashes."""
    baseline = {}
    for path in monitored_paths:
        if os.path.isfile(path):
            baseline[path] = calculate_file_hash(path)
        elif os.path.isdir(path):
            for root, _, files in os.walk(path):
                for file in files:
                    filepath = os.path.join(root, file)
                    baseline[filepath] = calculate_file_hash(filepath)
    with open(baseline_file, 'w') as f:
        json.dump(baseline, f, indent=4)
    print("Baseline created successfully.")

def check_integrity(baseline_file="baseline.json"):
    """Checks file integrity against the baseline."""
    if not os.path.exists(baseline_file):
        print("Error: Baseline file not found. Create baseline first.")
        return

    with open(baseline_file, 'r') as f:
        baseline = json.load(f)

    violations_found = False
    for filepath, stored_hash in baseline.items():
        if not os.path.exists(filepath):
            print(f"Alert: File removed - {filepath}")
            violations_found = True
            continue
        current_hash = calculate_file_hash(filepath)
        if current_hash != stored_hash:
            print(f"Alert: File modified - {filepath}")
            violations_found = True
   
    if not violations_found:
        print("No integrity violations detected.")

# Usage example:
# monitored_items = ["/path/to/important_file.txt", "/path/to/sensitive_directory"]
# create_baseline(monitored_items)
# check_integrity()
# Input data

data_to_hash = "Hello, Python SHA384!"

# Create a SHA384 hash object
sha384_hasher = hashlib.sha384()

# Update the hash object with the encoded data
sha384_hasher.update(data_to_hash.encode('utf-8'))

# Get the hexadecimal representation of the hash
sha384_result = sha384_hasher.hexdigest()

# Print the result
print(f"Original Data: {data_to_hash}")
print(f"SHA384 Hash: {sha384_result}") 
