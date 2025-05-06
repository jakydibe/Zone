#!/usr/bin/env python3
import json
import argparse

def parse_args():
    p = argparse.ArgumentParser(
        description="Compute average detections for x64 and x86 payloads."
    )
    p.add_argument('jsonfile', help="Path to the JSON file")
    return p.parse_args()

def main():
    args = parse_args()

    with open(args.jsonfile, 'r') as f:
        records = json.load(f)

    sums = {'x86': 0, 'x64': 0}
    counts = {'x86': 0, 'x64': 0}

    for rec in records:
        path = rec.get('file', '').lower()
        arch = 'x64' if '\\x64\\' in path or '/x64/' in path else 'x86'
        det = rec.get('malicious', 0)
        sums[arch] += det
        counts[arch] += 1

    for arch in ('x86', 'x64'):
        if counts[arch]:
            avg = sums[arch] / counts[arch]
            print(f'Average detections for {arch}: {avg:.2f}')
        else:
            print(f'No records for {arch}')

if __name__ == '__main__':
    main()
