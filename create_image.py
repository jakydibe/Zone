#!/usr/bin/env python3
import os
import json
import argparse
from collections import defaultdict
import matplotlib.pyplot as plt

# base techniques
SINGLES = ['nop', 'eq', 'pii', 'bcf', 'ibp']
# valid 3-way combos now using eq_nop_<third>
THIRDS = ['pii', 'bcf', 'ibp']
COMBOS = [f'eq_nop_{t}' for t in THIRDS]

# full list of categories in plotting order
CATEGORIES = SINGLES + COMBOS

def parse_args():
    p = argparse.ArgumentParser(
        description="Generate per-architecture charts of total and average detections by technique/combo."
    )
    p.add_argument('report', help="Path to the JSON report file")
    p.add_argument('outdir', help="Directory where the PNGs will be saved")
    return p.parse_args()

def classify(parts):
    """
    Given the filename split on '_', return one of:
      - a single technique (e.g. 'nop')
      - a combo 'eq_nop_bcf' / 'eq_nop_pii' / 'eq_nop_ibp'
    or None if it doesn't match the allowed patterns.
    """
    found = {t for t in SINGLES if t in parts}

    # single-tech payload
    if len(found) == 1:
        return found.pop()

    # combo: must have both nop & eq, plus exactly one of the THIRDS
    if 'nop' in found and 'eq' in found:
        thirds = found & set(THIRDS)
        if len(thirds) == 1:
            return f'eq_nop_{thirds.pop()}'

    return None

def make_bar_chart(values, labels, title, ylabel, out_path):
    fig, ax = plt.subplots()
    x = range(len(labels))
    ax.bar(x, values)
    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=30, ha='right')
    ax.set_ylabel(ylabel)
    ax.set_xlabel('Technique / Combo')
    ax.set_title(title)
    plt.tight_layout()
    plt.savefig(out_path)
    plt.close(fig)
    print(f'→ Saved {out_path}')



def main():
    args = parse_args()
    averagex64_dets = 0
    averagex86_dets = 0
    x64_pl_num = 0
    x86_pl_num = 0
    with open(args.report, 'r') as f:
        records = json.load(f)

    # initialize sums and counts per arch & category
    total_detections = {arch: {cat: 0 for cat in CATEGORIES} for arch in ('x86','x64')}
    payload_counts   = {arch: {cat: 0 for cat in CATEGORIES} for arch in ('x86','x64')}

    for rec in records:
        path = rec.get('file','')
        arch = 'x64' if '\\x64\\' in path or '/x64/' in path else 'x86'
        name = os.path.basename(path)
        parts = name.rsplit('.',1)[0].split('_')
        cat = classify(parts)
        if not cat:
            continue

        # accumulate
        payload_counts[arch][cat]   += 1
        total_detections[arch][cat] += rec.get('malicious', 0)
        if arch == 'x64':
            averagex64_dets += rec.get('malicious', 0)
            x64_pl_num += 1
        else:
            averagex86_dets += rec.get('malicious', 0)
            x86_pl_num += 1

    print(f"Average x64 detections: {averagex64_dets/x64_pl_num:.2f}")
    print(f"Average x86 detections: {averagex86_dets/x86_pl_num:.2f}")
    os.makedirs(args.outdir, exist_ok=True)

    # for each architecture, plot total & average
    for arch in ('x86','x64'):
        # TOTAL DETECTIONS
        totals = [ total_detections[arch][c] for c in CATEGORIES ]
        make_bar_chart(
            totals,
            CATEGORIES,
            f'Total detections by category ({arch})',
            'Total detections',
            os.path.join(args.outdir, f'{arch}.png')
        )

        # AVERAGE DETECTIONS PER FILE
        avgs = []
        for c in CATEGORIES:
            cnt = payload_counts[arch][c]
            avgs.append( (total_detections[arch][c] / cnt) if cnt > 0 else 0 )
        make_bar_chart(
            avgs,
            CATEGORIES,
            f'Average detections per payload ({arch})',
            'Avg detections per file',
            os.path.join(args.outdir, f'{arch}_avg.png')
        )

if __name__ == '__main__':
    main()
