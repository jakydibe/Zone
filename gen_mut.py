#!/usr/bin/env python3
"""
Generate mutations for all payload files in the original_pl directory
using pobf scripts.

Features
--------
• Processes all .bin files from original_pl/x64 and original_pl/x86
• Generates one mutation file per (payload, technique)
• Generates combination runs with --equal-instructions and --insert-nop
• Skips already generated files for easy resume after interruption
"""

import argparse
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed


# ────────────────────────────── helpers ──────────────────────────────
def find_payloads(input_dir: Path):
    """
    Find all .bin files in x64 and x86 subdirectories.
    Returns two lists:
      - x64 payload names
      - x86 payload names
    """
    x64_list = []
    x86_list = []
    
    x64_dir = input_dir / 'x64'
    x86_dir = input_dir / 'x86'
    
    if x64_dir.exists():
        x64_list = [f.name for f in x64_dir.glob('*.bin')]
        x64_list.sort()
    
    if x86_dir.exists():
        x86_list = [f.name for f in x86_dir.glob('*.bin')]
        x86_list.sort()
    
    return x64_list, x86_list


def generate_tasks(arch: str,
                   payload_name: str,
                   input_dir: Path,
                   output_dir: Path,
                   techniques: list[tuple[list[str], str]],
                   mutations_per_tech: int,
                   skip_existing: bool = True):
    """
    Build (pobf_script, input_file, list_of_flags, output_file) tuples.
    `techniques` items are ([flag, flag, …], label).
    If skip_existing is True, skip files that already exist.
    """
    script = 'pobf.py' if arch == 'x64' else 'pobf86.py'
    base = payload_name.removesuffix('.bin')
    in_file = input_dir / arch / payload_name

    tasks = []
    skipped = 0
    for flags, label in techniques:
        out_subdir = output_dir / arch
        out_subdir.mkdir(parents=True, exist_ok=True)
        for i in range(1, mutations_per_tech + 1):
            out_file = out_subdir / f"{base}_{label}_{i}.bin"
            # Skip if file already exists
            if skip_existing and out_file.exists():
                skipped += 1
                continue
            tasks.append((script, in_file, flags, out_file))
    
    if skipped > 0:
        print(f"[INFO] Skipping {skipped} existing files for {payload_name}")
    
    return tasks


def run_mutation(pobf_script: str, input_file: Path,
                 flags: list[str], out_file: Path):
    """Run a single mutation unless output already exists."""
    # Double-check in case file was created between task generation and execution
    if out_file.exists():
        print(f"[SKIP] {out_file} already exists")
        return
    cmd = ['python', pobf_script, str(input_file), *flags, '-o', str(out_file)]
    try:
        subprocess.run(cmd, check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"[OK]   {out_file}")
    except subprocess.CalledProcessError as exc:
        print(f"[ERROR] {out_file}: {exc.stderr.decode().strip()}")


def count_existing_files(output_dir: Path, x64_names: list, x86_names: list,
                         techniques: list, mutations_per_tech: int):
    """Count how many files already exist to give progress information."""
    total_expected = 0
    existing_count = 0
    
    for arch, names in (('x64', x64_names), ('x86', x86_names)):
        arch_dir = output_dir / arch
        if not arch_dir.exists():
            total_expected += len(names) * len(techniques) * mutations_per_tech
            continue
            
        for name in names:
            base = name.removesuffix('.bin')
            for _, label in techniques:
                for i in range(1, mutations_per_tech + 1):
                    total_expected += 1
                    out_file = arch_dir / f"{base}_{label}_{i}.bin"
                    if out_file.exists():
                        existing_count += 1
    
    return existing_count, total_expected


# ─────────────────────────────── main ────────────────────────────────
def main():
    p = argparse.ArgumentParser(
        description="Generate binary mutations from original payloads")
    p.add_argument('--input-dir', default='original_pl',
                   help='Input directory containing x64 and x86 subdirs')
    p.add_argument('--output-dir', default='mutations/mutations',
                   help='Output directory for generated mutations')
    p.add_argument('--threads', type=int, default=10,
                   help='Number of parallel threads')
    p.add_argument('--mutations-per-tech', type=int, default=10,
                   help='Number of mutations per technique')
    p.add_argument('--no-skip-existing', action='store_true',
                   help="Regenerate files even if they already exist")
    args = p.parse_args()

    input_dir = Path(args.input_dir)
    output_dir = Path(args.output_dir)
    skip_existing = not args.no_skip_existing
    
    # Check if input directory exists
    if not input_dir.exists():
        print(f"[ERROR] Input directory '{input_dir}' not found.")
        return
    
    # ----- techniques -------------------------------------------------
    # single-technique list
    singles = [
        (['--equal-instructions'], 'eq'),
        (['--bogus-cf'],           'bcf'),
        (['--insert-nop'],         'nop'),
        (['--instruction-block-permutation'], 'ibp'),
        (['--position-independent-instr'],    'pii'),
    ]

    # combo: eq + nop + (each remaining technique)
    combo_base_flags = ['--equal-instructions', '--insert-nop']
    combo_base_label = ['eq', 'nop']
    combos = []
    for flags, label in singles:
        if flags[0] in combo_base_flags:
            continue
        combos.append((combo_base_flags + flags,
                    '_'.join(combo_base_label + [label])))

    # extra requested 2-way combos
    extra_pairs = [
        (['--insert-nop', '--equal-instructions'],           'nop_eq'),
        (['--insert-nop', '--position-independent-instr'],   'nop_pii'),
        (['--insert-nop', '--bogus-cf'],                     'nop_bcf'),
        (['--insert-nop', '--instruction-block-permutation'],'nop_ibp'),
        (['--equal-instructions', '--position-independent-instr'], 'eq_pii'),
        (['--equal-instructions', '--bogus-cf'],             'eq_bcf'),
        (['--equal-instructions', '--instruction-block-permutation'], 'eq_ibp'),
    ]

    combos.extend(extra_pairs)

    # optional all-in-one (uncomment if needed)
    # all_combo = (combo_base_flags + [f[0] for f in singles
    #                                  if f[0] not in combo_base_flags],
    #              '_'.join(combo_base_label + ['bcf', 'ibp', 'pii']))
    # combos.append(all_combo)

    techniques = singles + combos
    print(f"[INFO] {len(techniques)} techniques configured")
    # ------------------------------------------------------------------

    # Find all payload files
    x64, x86 = find_payloads(input_dir)
    print(f"[INFO] Found {len(x64)} x64 payloads in {input_dir}/x64")
    print(f"[INFO] Found {len(x86)} x86 payloads in {input_dir}/x86")
    
    if not x64 and not x86:
        print("[ERROR] No .bin files found in input directories")
        return
    
    # Show progress information
    if skip_existing:
        existing, total = count_existing_files(output_dir, x64, x86, 
                                              techniques, args.mutations_per_tech)
        remaining = total - existing
        print(f"[INFO] Progress: {existing}/{total} files already exist")
        print(f"[INFO] {remaining} files to generate")
        if remaining == 0:
            print("[INFO] All files already generated. Nothing to do.")
            print("[INFO] Use --no-skip-existing to regenerate all files.")
            return
    else:
        total = (len(x64) + len(x86)) * len(techniques) * args.mutations_per_tech
        print(f"[INFO] Will generate {total} total mutations")
    
    # Generate tasks
    all_tasks = []
    for arch, names in (('x64', x64), ('x86', x86)):
        for name in names:
            tasks = generate_tasks(
                arch, name, input_dir, output_dir,
                techniques, args.mutations_per_tech, skip_existing)
            all_tasks.extend(tasks)
    
    if not all_tasks:
        print("[INFO] No tasks to run. All files already exist.")
        return
    
    print(f"[INFO] Starting generation of {len(all_tasks)} mutations...")
    print(f"[INFO] Using {args.threads} threads")
    
    completed = 0
    errors = 0
    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = [pool.submit(run_mutation, *t) for t in all_tasks]
        for future in as_completed(futures):
            completed += 1
            try:
                future.result()
            except Exception as e:
                errors += 1
                print(f"[ERROR] Task failed: {e}")
            
            if completed % 100 == 0:
                print(f"[PROGRESS] Completed {completed}/{len(all_tasks)} tasks")
    
    print(f"[INFO] Completed all {completed} tasks")
    if errors > 0:
        print(f"[WARNING] {errors} tasks failed")


if __name__ == '__main__':
    main()