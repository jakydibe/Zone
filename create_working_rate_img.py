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
SBLEUR = ['eq_nop', 'eq_bcf', 'eq_ibp', 'eq_pii', 'nop_bcf', 'nop_ibp', 'nop_pii']

rates86 = []
rates64 = []
# plotting categories in order
CATEGORIES = SINGLES + COMBOS + SBLEUR

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
      - a 2-way combo like 'eq_bcf', 'nop_ibp', etc.
    or None if it doesn't match.
    """
    found = {t for t in SINGLES if t in parts}

    # single-tech
    if len(found) == 1:
        return found.pop()

    # 3-way combos: eq + nop + one of THIRDS
    if 'nop' in found and 'eq' in found:
        thirds = found & set(THIRDS)
        if len(thirds) == 1:
            return f'eq_nop_{thirds.pop()}'

    # 2-way combos (SBLEUR)
    if len(found) == 2:
        # sort to keep consistent order with CATEGORIES
        a, b = found
        return f'{a}_{b}'

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
    plt.savefig(out_path,dpi=300)
    plt.close(fig)
    print(f'→ Saved {out_path}')


# ── NEW helper ────────────────────────────────────────────────────────────────
def make_scatter_plot(rates, labels, title, out_path, y_max=None, marker='o'):
    """Draw a scatter plot and print exact values above the points."""
    fig, ax = plt.subplots(figsize=(12, 6))




    x = range(len(labels))
    ax.scatter(x, rates64, s=90, color='orange',alpha=0.5, marker=marker, edgecolors='black', label='x64')
    ax.scatter(x, rates86, s=90, color='blue',alpha=0.5, marker=marker, edgecolors='black', label='x86')
    # ax.plot(x, rates64, marker='s', color='green', markersize=8, label='x64')
    # ax.plot(x, rates86, marker='o', color='blue', markersize=8, label='x86')

    # also plot an average for each arch
    avg64 = sum(rates64) / len(rates64) if rates64 else 0
    avg86 = sum(rates86) / len(rates86) if rates86 else 0
    ax.plot(x, [avg64] * len(x), color='orange',alpha=0.2, linestyle='--', label=f'Avg x64: {avg64:.1f}%')
    ax.text(len(x) - 1, avg64 + 2, f'', ha='right', va='bottom', fontsize=6, color='orange', alpha=0.5)
    ax.plot(x, [avg86] * len(x), color='blue',alpha=0.15, linestyle='--', label=f'Avg x86: {avg86:.1f}%')
    ax.text(len(x) - 1, avg86 + 2, f'', ha='right', va='bottom', fontsize=6, color='blue', alpha=0.5)
    
    # label each point with its exact percentage
    for xi, yi in zip(x, rates64):
        ax.text(xi, yi + 2, f'{yi:.1f}%', ha='center', va='bottom', fontsize=8, color='grey')
    for xi, yi in zip(x, rates86):
        ax.text(xi, yi + 2, f'{yi:.1f}%', ha='center', va='bottom', fontsize=8, color='grey')

    # if y_max is not None:
    # ax.set_ylim(0, y_max * 1.05)   # +5 % headroom
    ax.set_ylim(0,100)
    # else:
    #     ax.set_ylim(0, max(rates) * 1.1 if rates else 1)

    # aggiungi una legenda per i colori

    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=30, ha='right', fontsize=18)
    ax.set_ylabel('Working rate (%)', fontsize=20)
    ax.set_xlabel('Technique / Combo', fontsize=20)
    ax.set_title(title, fontsize=20)
    ax.grid(True, axis='y', alpha=0.3)
    # in alto a destra la legenda
    ax.legend(loc='upper right', fontsize=8)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close(fig)
    print(f'→ Saved {out_path}')
# ──────────────────────────────────────────────────────────────────────────────


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
            if arch == 'x86':
                rates86.append(rate)
            elif arch == 'x64':
                rates64.append(rate)
            rates.append(rate)

    out_png = os.path.join(args.outdir, f'working_rate.png')
    print ("rates:", rates)
    make_scatter_plot(
        rates,
        CATEGORIES,
        f'Working rate by technique',
        out_png,
        y_max=max_rate,
        marker='o'
    )
if __name__ == '__main__':
    main()
