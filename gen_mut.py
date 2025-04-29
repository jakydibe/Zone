#!/usr/bin/env python3
"""
Read a CSV-style report file, filter working payloads, and generate mutations
using pobf scripts.

New in this version
-------------------
• Still generates one mutation file per (payload, technique) as before.
• *Additionally* generates combination runs that always include
  --equal-instructions and --insert-nop plus each remaining technique.
  Example labels:  eq_nop_bcf, eq_nop_ibp, eq_nop_pii
• Also generates a single “everything on” combination: eq_nop_bcf_ibp_pii
"""

import argparse
import subprocess
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed


# ────────────────────────────── helpers ──────────────────────────────
def parse_report(report_path: Path):
    """
    Parse the report file and return two lists:
      - x64 payload names
      - x86 payload names
    """
    x64_list = []
    x86_list = []
    with report_path.open() as rf:
        for line in rf:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            parts = line.split(',', 3)
            if len(parts) < 3:
                continue
            payload_path, _, status = parts[0], parts[1], parts[2]
            if status != 'OK':
                continue
            name = payload_path.split('/')[-1]
            if '/x64/' in payload_path or payload_path.startswith('x64/'):
                x64_list.append(name)
            elif '/x86/' in payload_path or payload_path.startswith('x86/'):
                x86_list.append(name)
    return x64_list, x86_list


def generate_tasks(arch: str,
                   payload_name: str,
                   input_dir: Path,
                   output_dir: Path,
                   techniques: list[tuple[list[str], str]],
                   mutations_per_tech: int):
    """
    Build (pobf_script, input_file, list_of_flags, output_file) tuples.
    `techniques` items are ([flag, flag, …], label).
    """
    script = 'pobf.py' if arch == 'x64' else 'pobf86.py'
    base = payload_name.removesuffix('.bin')
    in_file = input_dir / arch / payload_name

    tasks = []
    for flags, label in techniques:
        out_subdir = output_dir / arch
        out_subdir.mkdir(parents=True, exist_ok=True)
        for i in range(1, mutations_per_tech + 1):
            out_file = out_subdir / f"{base}_{label}_{i}.bin"
            tasks.append((script, in_file, flags, out_file))
    return tasks


def run_mutation(pobf_script: str, input_file: Path,
                 flags: list[str], out_file: Path):
    """Run a single mutation unless output already exists."""
    if out_file.exists():
        print(f"[SKIP] {out_file} already exists")
        return
    cmd = ['python3', pobf_script, str(input_file), *flags, '-o', str(out_file)]
    try:
        subprocess.run(cmd, check=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        print(f"[OK]   {out_file}")
    except subprocess.CalledProcessError as exc:
        print(f"[ERROR] {out_file}: {exc.stderr.decode().strip()}")


# ─────────────────────────────── main ────────────────────────────────
def main():
    p = argparse.ArgumentParser(
        description="Filter report and generate binary mutations")
    p.add_argument('--report-file', default='test_report.txt')
    p.add_argument('--input-dir', default='new_pl/output')
    p.add_argument('--output-dir', default='mutations')
    p.add_argument('--threads', type=int, default=10)
    p.add_argument('--mutations-per-tech', type=int, default=10)
    args = p.parse_args()

    report_path = Path(args.report_file)
    if not report_path.exists():
        print(f"[ERROR] Report file '{report_path}' not found.")
        return
    


    # ----- techniques -------------------------------------------------
    # single-technique list (exactly as before)
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

    # optional all-in-one
    # all_combo = (combo_base_flags + [f[0] for f in singles
    #                                  if f[0] not in combo_base_flags],
    #              '_'.join(combo_base_label + ['bcf', 'ibp', 'pii']))
    # combos.append(all_combo)

    techniques = singles + combos
    print(f"[INFO] {len(techniques)} techniques: {techniques}")
    # exit(0)
    # ------------------------------------------------------------------

    input_dir = Path(args.input_dir)
    output_dir = Path(args.output_dir)

    x64, x86 = parse_report(report_path)
    print(f"[INFO] Found {len(x64)} x64 and {len(x86)} x86 payloads")
    all_tasks = []
    for arch, names in (('x64', x64), ('x86', x86)):
        for name in names:
            all_tasks.extend(generate_tasks(
                arch, name, input_dir, output_dir,
                techniques, args.mutations_per_tech))

    with ThreadPoolExecutor(max_workers=args.threads) as pool:
        futures = [pool.submit(run_mutation, *t) for t in all_tasks]
        for _ in as_completed(futures):
            pass


if __name__ == '__main__':
    main()
