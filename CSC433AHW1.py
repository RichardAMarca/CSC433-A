import hashlib
import os
import json
import time

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

# First new feature: Monitor log files for new detections
LOG_DIR = "samplelogs"
LOG_HISTORY_FILE = "log_history.json"

def get_log_files(log_dir=LOG_DIR):
    """Returns a sorted list of log files in the directory."""
    if not os.path.exists(log_dir):
        return []
    return sorted([f for f in os.listdir(log_dir) if f.endswith('.txt')])

def inform_new_log_files(prev_files, log_dir=LOG_DIR):
    """Informs the user if new log files have been detected."""
    current_files = get_log_files(log_dir)
    new_files = set(current_files) - set(prev_files)
    if new_files:
        print(f"New log files detected: {', '.join(new_files)}")
    return current_files

def parse_hashes_from_logs(log_dir=LOG_DIR):
    """Parses all detected hashes from log files in the directory."""
    hash_counts = {}
    for log_file in get_log_files(log_dir):
        with open(os.path.join(log_dir, log_file), 'r') as f:
            for line in f:
                if "Detected hash:" in line:
                    hash_val = line.strip().split("Detected hash:")[-1].strip()
                    hash_counts[hash_val] = hash_counts.get(hash_val, 0) + 1
    return hash_counts

# Second new feature: Detect replicated hashes
def detect_replicated_hashes(hash_counts):
    """Identifies hashes that have been replicated before."""
    for hash_val, count in hash_counts.items():
        if count > 1:
            print(f"WARNING: Hash {hash_val} has been detected {count} times. Possible spoofing or imitation.")

def monitor_logs_and_hashes():
    """Monitors for new log files and checks for repeated hashes every 5 seconds."""
    print("Monitoring log files for new detections and repeated hashes...")
    prev_files = get_log_files()
    while True:
        time.sleep(5)  # Check every 5 seconds
        prev_files = inform_new_log_files(prev_files)
        hash_counts = parse_hashes_from_logs()
        detect_replicated_hashes(hash_counts)
        print("---")

# Usage example:
# monitored_items = ["/path/to/important_file.txt", "/path/to/sensitive_directory"]
# monitor_logs_and_hashes()
# create_baseline(monitored_items)
# check_integrity()