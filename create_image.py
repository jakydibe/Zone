#!/usr/bin/env python3
import os
import sys
import json
import matplotlib.pyplot as plt

SINGLES = ['nop', 'eq', 'pii', 'bcf', 'ibp']
THIRDS = ['pii', 'bcf', 'ibp']
CATEGORIES = SINGLES + [f'eq_nop_{t}' for t in THIRDS]

def classify(parts):
    found = {t for t in SINGLES if t in parts}
    if len(found) == 1:
        return found.pop()
    if 'nop' in found and 'eq' in found:
        thirds = found & set(THIRDS)
        if len(thirds) == 1:
            return f'eq_nop_{thirds.pop()}'
    return None

def load_rates(report_path):
    with open(report_path, 'r') as f:
        records = json.load(f)

    total = next((rec["total"] for rec in records if "total" in rec and rec["total"] > 0), None)
    if total is None:
        print("Warning: no 'total' field found, assuming 70")
        total = 76

    data = {"x86": {cat: [] for cat in CATEGORIES},
            "x64": {cat: [] for cat in CATEGORIES}}

    for rec in records:
        path = rec.get("file", "")
        arch = "x64" if "/x64/" in path or "\\x64\\" in path else "x86"
        name = os.path.basename(path)
        parts = name.rsplit('.', 1)[0].split('_')
        cat = classify(parts)
        if not cat:
            continue
        rate = (rec.get("malicious", 0) / total) * 100
        data[arch][cat].append(rate)

    # Compute average per category
    avg = {"x86": [], "x64": []}
    for cat in CATEGORIES:
        for arch in ["x86", "x64"]:
            values = data[arch][cat]
            avg[arch].append(sum(values) / len(values) if values else 0)
    return avg

def plot_comparison(avg_rates, output_path):
    x = range(len(CATEGORIES))
    fig, ax = plt.subplots(figsize=(12, 6))

    # ax.plot(x, avg_rates["x86"], marker='o', label='x86', color='blue',alpha=0.5)
    # ax.plot(x, avg_rates["x64"], marker='s', label='x64', color='orange',alpha=0.5)
    # scatter plot
    rates64 = avg_rates["x64"]
    rates86 = avg_rates["x86"]
    ax.scatter(x, rates64, s=90, color='orange',alpha=0.5, marker='s', edgecolors='black', label='x64')
    ax.scatter(x, rates86, s=90, color='blue',alpha=0.5, marker='s', edgecolors='black', label='x86')

    # also plot an average for each arch
    avg64 = sum(rates64) / len(rates64) if rates64 else 0
    avg86 = sum(rates86) / len(rates86) if rates86 else 0
    ax.plot(x, [avg64] * len(x), color='orange',alpha=0.2, linestyle='--', label=f'Avg x64: {avg64:.1f}%')
    ax.text(len(x) - 1.4, avg64 + 0.1, f'', ha='right', va='bottom', fontsize=10, color='orange', alpha=0.5)
    ax.plot(x, [avg86] * len(x), color='blue',alpha=0.15, linestyle='--', label=f'Avg x86: {avg86:.1f}%')
    ax.text(len(x) - 1.4, avg86 + 0.1, f'', ha='right', va='bottom', fontsize=10, color='blue', alpha=0.5)
    # Add exact values
    for i in x:
        highest = max(avg_rates["x86"][i], avg_rates["x64"][i])
        if avg_rates["x86"][i] > avg_rates["x64"][i]:
        
            ax.text(i, highest + 0.5, f'{avg_rates["x86"][i]:.1f}%', ha='center', va='bottom', fontsize=13, color='grey')
            ax.text(i, highest + 0.2, f'{avg_rates["x64"][i]:.1f}%', ha='center', va='bottom', fontsize=13, color='grey')
        else:
            ax.text(i, highest + 0.5, f'{avg_rates["x64"][i]:.1f}%', ha='center', va='bottom', fontsize=13, color='grey')
            ax.text(i, highest + 0.2, f'{avg_rates["x86"][i]:.1f}%', ha='center', va='bottom', fontsize=13, color='grey')
    ax.set_xticks(x)
    ax.set_xticklabels(CATEGORIES, rotation=45, ha='right', fontsize=18)
    ax.set_ylabel("Detection Rate (%)", fontsize=20)
    ax.set_title("Detection Rate Comparison (x86 vs x64)", fontsize=20)
    ax.set_xlabel("Obfuscation techniques", fontsize=20)
    ax.set_ylim(0, 4)
    ax.grid(True, axis='y', alpha=0.3)
    ax.legend()
    plt.tight_layout()
    plt.savefig(output_path)
    print(f"Saved to {output_path}")

def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} report.json output.png")
        sys.exit(1)
    report_path = sys.argv[1]
    output_path = sys.argv[2]

    avg_rates = load_rates(report_path)
    plot_comparison(avg_rates, output_path)

if __name__ == "__main__":
    main()
