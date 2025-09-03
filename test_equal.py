#!/usr/bin/env python3
"""
Enhanced Payload Mutation Generator Script
Generates 100 mutations for each technique and payload using pobf.py
Features:
- Skip already generated files
- Retry on crashes/failures
- Regenerate 0-byte files
- Resume interrupted sessions
"""

import os
import subprocess
import sys
from pathlib import Path
import shutil
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import json

# Configuration
MUTATIONS_PER_TECHNIQUE = 100
ORIGINAL_PL_DIR = "original_pl"
OUTPUT_BASE_DIR = "equal_comp"
POBF_SCRIPT = "pobf.py"
POBF_SCRIPT86 = "pobf86.py"
MAX_RETRIES = 6 # Maximum retries for failed mutations
MIN_FILE_SIZE = 1  # Minimum file size in bytes (files smaller than this are considered failed)

# Define mutation techniques with their corresponding flags
MUTATION_TECHNIQUES = {
    "eq": "--equal-instructions",
    "bcf": "--bogus-cf",
    "nop": "--insert-nop",
    "ibp": "--instruction-block-permutation",
    "pii": "--position-independent-instr",
    "eq_nop_ibp": "-eq -nop -ibp",
    "eq_nop_pii": "-eq -nop -pii",
    "eq_nop_bcf": "-eq -nop -bcf"
}

# Thread-safe counter for progress tracking
class ProgressCounter:
    def __init__(self, total):
        self.count = 0
        self.total = total
        self.lock = threading.Lock()
        self.skipped = 0
        self.regenerated = 0
    
    def increment(self):
        with self.lock:
            self.count += 1
            return self.count
    
    def increment_skipped(self):
        with self.lock:
            self.skipped += 1
            return self.skipped
    
    def increment_regenerated(self):
        with self.lock:
            self.regenerated += 1
            return self.regenerated

def ensure_directory(path):
    """Create directory if it doesn't exist"""
    Path(path).mkdir(parents=True, exist_ok=True)

def is_file_valid(file_path):
    """Check if file exists and is not zero bytes"""
    if not os.path.exists(file_path):
        return False
    
    try:
        size = os.path.getsize(file_path)
        return size >= MIN_FILE_SIZE
    except OSError:
        return False

def get_payload_files(base_dir):
    """Get all payload files from original_pl directory"""
    payloads = {}
    
    for arch in ['x64', 'x86']:
        arch_dir = os.path.join(base_dir, arch)
        if os.path.exists(arch_dir):
            payloads[arch] = []
            for file in os.listdir(arch_dir):
                file_path = os.path.join(arch_dir, file)
                if os.path.isfile(file_path):
                    payloads[arch].append(file)
    
    return payloads

def count_existing_mutations(output_dir, payload_name):
    """Count how many valid mutations already exist"""
    if not os.path.exists(output_dir):
        return 0, 0, 0  # valid, invalid, missing
    
    valid = 0
    invalid = 0
    
    for i in range(1, MUTATIONS_PER_TECHNIQUE + 1):
        output_filename = f"{payload_name}_mut_{i}.bin"
        output_path = os.path.join(output_dir, output_filename)
        
        if is_file_valid(output_path):
            valid += 1
        elif os.path.exists(output_path):
            invalid += 1
    
    missing = MUTATIONS_PER_TECHNIQUE - valid - invalid
    return valid, invalid, missing

def generate_single_mutation_with_retry(args):
    """Generate a single mutation with retry logic"""
    payload_path, technique_flag, output_path, mutation_num, progress_counter, force_regenerate = args
    
    # Check if file already exists and is valid (unless force regeneration)
    if not force_regenerate and is_file_valid(output_path):
        progress_counter.increment_skipped()
        return True
    
    # If file exists but is invalid, remove it
    if os.path.exists(output_path):
        try:
            os.remove(output_path)
            progress_counter.increment_regenerated()
        except OSError:
            pass
    
    script = POBF_SCRIPT if "x64" in payload_path else POBF_SCRIPT86
    
    # Retry logic
    for attempt in range(MAX_RETRIES):
        try:
            # In generate_single_mutation_with_retry function
            cmd = ["python", script, payload_path]

            # Split the technique_flag if it contains spaces
            if ' ' in technique_flag:
                cmd.extend(technique_flag.split())
            else:
                cmd.append(technique_flag)

            cmd.extend(["--output", output_path])
            # cmd = [
            #     "python", script,
            #     payload_path,
            #     technique_flag,
            #     "--output", output_path
            # ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=60  # Increased timeout to 60 seconds
            )
            
            if result.returncode == 0 and is_file_valid(output_path):
                # Success
                current = progress_counter.increment()
                if current % 50 == 0:  # More frequent updates
                    print(f"    Progress: {current}/{progress_counter.total} mutations completed "
                          f"(skipped: {progress_counter.skipped}, regenerated: {progress_counter.regenerated})")
                return True
            else:
                # Failed, but don't break yet - try again
                if os.path.exists(output_path):
                    try:
                        os.remove(output_path)
                    except OSError:
                        pass
                
                if attempt < MAX_RETRIES - 1:
                    print(f"    Attempt {attempt + 1} failed for mutation {mutation_num}, retrying...")
                    time.sleep(0.5)  # Short delay before retry
                
        except subprocess.TimeoutExpired:
            print(f"    Mutation {mutation_num} timed out on attempt {attempt + 1}")
            if attempt < MAX_RETRIES - 1:
                time.sleep(1)  # Longer delay after timeout
        except Exception as e:
            print(f"    Error on attempt {attempt + 1} for mutation {mutation_num}: {str(e)}")
            if attempt < MAX_RETRIES - 1:
                time.sleep(0.5)
    
    print(f"    Warning: Mutation {mutation_num} failed after {MAX_RETRIES} attempts")
    return False

def generate_mutations_for_payload(payload_path, payload_name, arch, technique_name, technique_flag):
    """Generate all mutations for a specific payload and technique"""
    
    # Create output directory
    output_dir = os.path.join(OUTPUT_BASE_DIR, arch, payload_name, technique_name)
    ensure_directory(output_dir)
    
    # Check existing mutations
    valid, invalid, missing = count_existing_mutations(output_dir, payload_name)
    
    print(f"\n  Technique: {technique_name}")
    print(f"    Existing: {valid} valid, {invalid} invalid, {missing} missing")
    
    if valid == MUTATIONS_PER_TECHNIQUE:
        print(f"    All mutations already exist and are valid. Skipping.")
        return valid, 0
    
    # Determine which mutations need to be generated
    tasks = []
    progress_counter = ProgressCounter(MUTATIONS_PER_TECHNIQUE - valid)
    
    for i in range(1, MUTATIONS_PER_TECHNIQUE + 1):
        output_filename = f"{payload_name}_mut_{i}.bin"
        output_path = os.path.join(output_dir, output_filename)
        
        # Add to tasks if file doesn't exist or is invalid
        if not is_file_valid(output_path):
            force_regenerate = os.path.exists(output_path)  # Force if file exists but is invalid
            tasks.append((payload_path, technique_flag, output_path, i, progress_counter, force_regenerate))
    
    if not tasks:
        print(f"    No mutations needed.")
        return valid, 0
    
    print(f"    Generating {len(tasks)} mutations...")
    
    # Execute mutations in parallel
    successful = valid  # Start with already valid files
    failed = 0
    
    # Use fewer workers to avoid overwhelming the system when retrying
    max_workers = min(20, len(tasks), os.cpu_count() or 4)
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(generate_single_mutation_with_retry, task) for task in tasks]
        
        for future in as_completed(futures):
            if future.result():
                successful += 1
            else:
                failed += 1
    
    # Final count to verify
    final_valid, final_invalid, final_missing = count_existing_mutations(output_dir, payload_name)
    
    print(f"    Final result: {final_valid} valid mutations "
          f"(skipped: {progress_counter.skipped}, regenerated: {progress_counter.regenerated})")
    
    return final_valid, final_invalid + final_missing

def save_progress(payload_count, total_payloads, arch, payload_file):
    """Save progress to a file for resumption"""
    progress_data = {
        'payload_count': payload_count,
        'total_payloads': total_payloads,
        'current_arch': arch,
        'current_payload': payload_file,
        'timestamp': time.time()
    }
    
    try:
        with open('.mutation_progress.json', 'w') as f:
            json.dump(progress_data, f)
    except Exception:
        pass  # Ignore errors in progress saving

def load_progress():
    """Load progress from file if it exists"""
    try:
        if os.path.exists('.mutation_progress.json'):
            with open('.mutation_progress.json', 'r') as f:
                return json.load(f)
    except Exception:
        pass
    return None

def cleanup_progress():
    """Remove progress file when complete"""
    try:
        if os.path.exists('.mutation_progress.json'):
            os.remove('.mutation_progress.json')
    except Exception:
        pass

def main():
    """Main execution function"""
    
    print("=" * 80)
    print("ENHANCED PAYLOAD MUTATION GENERATOR WITH RECOVERY")
    print("=" * 80)
    
    # Check if pobf.py exists
    if not os.path.exists(POBF_SCRIPT):
        print(f"Error: {POBF_SCRIPT} not found in current directory!")
        sys.exit(1)
    
    if not os.path.exists(POBF_SCRIPT86):
        print(f"Error: {POBF_SCRIPT86} not found in current directory!")
        sys.exit(1)
    
    # Check if original_pl directory exists
    if not os.path.exists(ORIGINAL_PL_DIR):
        print(f"Error: {ORIGINAL_PL_DIR} directory not found!")
        sys.exit(1)
    
    # Get all payload files
    print(f"\nScanning {ORIGINAL_PL_DIR} for payloads...")
    payloads = get_payload_files(ORIGINAL_PL_DIR)
    
    total_payloads = sum(len(files) for files in payloads.values())
    if total_payloads == 0:
        print("No payload files found!")
        sys.exit(1)
    
    print(f"Found {total_payloads} payload(s):")
    for arch, files in payloads.items():
        if files:
            print(f"  {arch}: {len(files)} file(s)")
    
    # Check for previous progress
    progress_data = load_progress()
    if progress_data:
        elapsed = time.time() - progress_data['timestamp']
        print(f"\nFound previous session from {elapsed/3600:.1f} hours ago:")
        print(f"  Was processing payload {progress_data['payload_count']}/{progress_data['total_payloads']}")
        print(f"  Last file: {progress_data['current_arch']}/{progress_data['current_payload']}")
        
        resume = input("Resume from previous session? (y/n): ")
        if resume.lower() != 'y':
            cleanup_progress()
            progress_data = None
    
    # Calculate total mutations
    total_mutations = total_payloads * len(MUTATION_TECHNIQUES) * MUTATIONS_PER_TECHNIQUE
    print(f"\nConfiguration:")
    print(f"  Max retries per mutation: {MAX_RETRIES}")
    print(f"  Minimum file size: {MIN_FILE_SIZE} bytes")
    print(f"  Total mutations possible: {total_mutations:,}")
    
    # Create base output directory
    ensure_directory(OUTPUT_BASE_DIR)
    
    # Start timing
    start_time = time.time()
    
    # Process each payload
    total_successful = 0
    total_failed = 0
    payload_count = 0
    start_from_payload = 0
    
    # If resuming, find where to start
    if progress_data:
        start_from_payload = progress_data['payload_count']
    
    for arch, files in payloads.items():
        for payload_file in files:
            payload_count += 1
            
            # Skip if resuming and haven't reached the right payload yet
            if payload_count < start_from_payload:
                continue
            
            payload_path = os.path.join(ORIGINAL_PL_DIR, arch, payload_file)
            payload_name = os.path.splitext(payload_file)[0]
            
            print(f"\n{'=' * 60}")
            print(f"Processing payload {payload_count}/{total_payloads}: {arch}/{payload_file}")
            print(f"{'=' * 60}")
            
            # Save progress
            save_progress(payload_count, total_payloads, arch, payload_file)
            
            # Generate mutations for each technique
            for technique_name, technique_flag in MUTATION_TECHNIQUES.items():
                successful, failed = generate_mutations_for_payload(
                    payload_path, 
                    payload_name, 
                    arch, 
                    technique_name, 
                    technique_flag
                )
                total_successful += successful
                total_failed += failed
    
    # Calculate and display summary
    elapsed_time = time.time() - start_time
    
    print("\n" + "=" * 80)
    print("MUTATION GENERATION COMPLETE")
    print("=" * 80)
    print(f"Total time: {elapsed_time:.2f} seconds ({elapsed_time/60:.2f} minutes)")
    print(f"Total mutations generated: {total_successful:,}")
    print(f"Failed/missing mutations: {total_failed:,}")
    if total_successful + total_failed > 0:
        print(f"Success rate: {(total_successful/(total_successful+total_failed)*100):.1f}%")
    print(f"Average time per mutation: {elapsed_time/(total_successful+total_failed) if total_successful+total_failed > 0 else 0:.3f} seconds")
    print(f"\nOutput directory: {os.path.abspath(OUTPUT_BASE_DIR)}")
    
    # Clean up progress file
    cleanup_progress()
    
    # Show summary of what was accomplished
    if total_failed > 0:
        print(f"\nNote: {total_failed} mutations failed after {MAX_RETRIES} retries each.")
        print("You can run this script again to retry failed mutations.")

def clean_broken():
    for root, dirs, files in os.walk(OUTPUT_BASE_DIR):
        for dir_name in dirs:
            if "eq_nop" in dir_name:
                shutil.rmtree(os.path.join(root, dir_name))

if __name__ == "__main__":
    try:
        clean_broken()
        main()
    except KeyboardInterrupt:
        print("\n\nOperation interrupted by user.")
        print("Progress has been saved. Run the script again to resume.")
        sys.exit(1)
    except Exception as e:
        print(f"\nUnexpected error: {str(e)}")
        import traceback
        traceback.print_exc()
        sys.exit(1)