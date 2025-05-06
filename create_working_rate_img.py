#!/usr/bin/env python3
import os
import csv
import argparse
import matplotlib.pyplot as plt

# base techniques
SINGLES = ['nop', 'eq', 'pii', 'bcf', 'ibp']
# valid 3-way combos using eq_nop_<third>
THIRDS = ['pii', 'bcf', 'ibp']
COMBOS = [f'eq_nop_{t}' for t in THIRDS]

# plotting categories in order
CATEGORIES = SINGLES + COMBOS

def parse_args():
    p = argparse.ArgumentParser(
        description="Generate per-architecture bar charts of working rate by technique."
    )
    p.add_argument('input_txt',
                   help="Path to the .txt file (CSV lines: file,operation,RESULT, …)")
    p.add_argument('outdir',
                   help="Directory where x86_working_rate.png and x64_working_rate.png will be saved")
    return p.parse_args()

def classify(parts):
    """
    Given filename.split('_'), return:
      - a single technique (e.g. 'nop')
      - a combo 'eq_nop_bcf', etc.
    or None if it doesn't match.
    """
    found = {t for t in SINGLES if t in parts}

    # single-tech
    if len(found) == 1:
        return found.pop()

    # combo: must have both nop & eq + exactly one third
    if 'nop' in found and 'eq' in found:
        thirds = found & set(THIRDS)
        if len(thirds) == 1:
            return f'eq_nop_{thirds.pop()}'

    return None

def make_bar_chart(rates, labels, title, out_path, y_max=None):
    fig, ax = plt.subplots()
    x = range(len(labels))
    ax.bar(x, rates)
    if y_max is not None:
        ax.set_ylim(0, y_max)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=30, ha='right')
    ax.set_ylabel('Working rate (%)')
    ax.set_xlabel('Technique / Combo')
    ax.set_title(title)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close(fig)
    print(f'→ Saved {out_path}')

def main():
    args = parse_args()
    os.makedirs(args.outdir, exist_ok=True)

    # stats: arch → category → [total, successes]
    stats = {
        'x86': {cat: [0, 0] for cat in CATEGORIES},
        'x64': {cat: [0, 0] for cat in CATEGORIES},
    }

    # read CSV-style .txt
    with open(args.input_txt, newline='') as f:
        reader = csv.reader(f)
        for row in reader:
            if len(row) < 3:
                continue
            path, operation, result = row[0], row[1], row[2].upper()
            arch = 'x64' if path.startswith('x64/') or '/x64/' in path else 'x86'
            name = os.path.basename(path)
            parts = name.rsplit('.', 1)[0].split('_')
            cat = classify(parts)
            if not cat:
                continue

            stats[arch][cat][0] += 1
            if 'OK' in result:
                stats[arch][cat][1] += 1

    # compute shared y-limit for working rates
    all_rates = []
    for arch in ('x86', 'x64'):
        for cat in CATEGORIES:
            total, success = stats[arch][cat]
            rate = (success / total * 100) if total > 0 else 0
            all_rates.append(rate)
    max_rate = max(all_rates) if all_rates else 0

    # build and save charts
    for arch in ('x86', 'x64'):
        rates = []
        for cat in CATEGORIES:
            total, success = stats[arch][cat]
            rate = (success / total * 100) if total > 0 else 0
            rates.append(rate)

        out_png = os.path.join(args.outdir, f'{arch}_working_rate.png')
        make_bar_chart(
            rates,
            CATEGORIES,
            f'Working rate by technique ({arch})',
            out_png,
            y_max=max_rate
        )

if __name__ == '__main__':
    main()
