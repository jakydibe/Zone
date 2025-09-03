#!/usr/bin/env python3
"""
Mutation Duplicate Analyzer
Analyzes generated mutations to find duplicates using MD5 hashing
Generates reports and visualizations
"""

import os
import hashlib
import json
from pathlib import Path
from collections import defaultdict, Counter
import matplotlib.pyplot as plt
import seaborn as sns
import pandas as pd
from datetime import datetime
import numpy as np

# Configuration
MUTATIONS_DIR = "equal_comp"
REPORT_DIR = "duplicate_analysis_report"
EXPECTED_MUTATIONS = 100

def calculate_md5(file_path):
    """Calculate MD5 hash of a file"""
    hash_md5 = hashlib.md5()
    try:
        with open(file_path, "rb") as f:
            for chunk in iter(lambda: f.read(4096), b""):
                hash_md5.update(chunk)
        return hash_md5.hexdigest()
    except Exception as e:
        print(f"Error reading {file_path}: {e}")
        return None

def analyze_technique_mutations(technique_dir):
    """Analyze all mutations for a specific technique"""
    mutations = {}
    md5_to_files = defaultdict(list)
    
    # Get all mutation files
    mutation_files = [f for f in os.listdir(technique_dir) 
                     if f.endswith('.bin') and os.path.isfile(os.path.join(technique_dir, f))]
    
    # Calculate MD5 for each file
    for mut_file in mutation_files:
        file_path = os.path.join(technique_dir, mut_file)
        md5_hash = calculate_md5(file_path)
        if md5_hash:
            mutations[mut_file] = md5_hash
            md5_to_files[md5_hash].append(mut_file)
    
    # Find duplicates
    duplicates = {md5: files for md5, files in md5_to_files.items() if len(files) > 1}
    unique_count = len(md5_to_files)
    duplicate_count = len(mutations) - unique_count
    
    return {
        'total_files': len(mutations),
        'unique_hashes': unique_count,
        'duplicate_files': duplicate_count,
        'duplicates': duplicates,
        'uniqueness_ratio': unique_count / len(mutations) if mutations else 0,
        'all_hashes': mutations
    }

def analyze_all_mutations():
    """Analyze all mutations in the equal_comp directory"""
    results = {}
    
    if not os.path.exists(MUTATIONS_DIR):
        print(f"Error: {MUTATIONS_DIR} directory not found!")
        return results
    
    print(f"Analyzing mutations in {MUTATIONS_DIR}...")
    print("=" * 80)
    
    # Iterate through architectures
    for arch in ['x64', 'x86']:
        arch_dir = os.path.join(MUTATIONS_DIR, arch)
        if not os.path.exists(arch_dir):
            continue
        
        results[arch] = {}
        
        # Iterate through payloads
        for payload_name in os.listdir(arch_dir):
            payload_dir = os.path.join(arch_dir, payload_name)
            if not os.path.isdir(payload_dir):
                continue
            
            results[arch][payload_name] = {}
            
            print(f"\nAnalyzing {arch}/{payload_name}:")
            
            # Iterate through techniques
            for technique in os.listdir(payload_dir):
                technique_dir = os.path.join(payload_dir, technique)
                if not os.path.isdir(technique_dir):
                    continue
                
                print(f"  - {technique}...", end=" ")
                analysis = analyze_technique_mutations(technique_dir)
                results[arch][payload_name][technique] = analysis
                
                # Print summary
                if analysis['duplicate_files'] > 0:
                    print(f"⚠️  {analysis['duplicate_files']} duplicates found! "
                          f"(Uniqueness: {analysis['uniqueness_ratio']*100:.1f}%)")
                else:
                    print(f"✓ All unique (100% uniqueness)")
    
    return results

def generate_summary_statistics(results):
    """Generate summary statistics from analysis results"""
    stats = {
        'by_technique': defaultdict(lambda: {'total': 0, 'duplicates': 0, 'unique_ratios': []}),
        'by_payload': defaultdict(lambda: {'total': 0, 'duplicates': 0}),
        'by_arch': defaultdict(lambda: {'total': 0, 'duplicates': 0}),
        'worst_cases': []
    }
    
    for arch, payloads in results.items():
        for payload_name, techniques in payloads.items():
            for technique, analysis in techniques.items():
                # By technique
                stats['by_technique'][technique]['total'] += analysis['total_files']
                stats['by_technique'][technique]['duplicates'] += analysis['duplicate_files']
                stats['by_technique'][technique]['unique_ratios'].append(analysis['uniqueness_ratio'])
                
                # By payload
                stats['by_payload'][f"{arch}/{payload_name}"]['total'] += analysis['total_files']
                stats['by_payload'][f"{arch}/{payload_name}"]['duplicates'] += analysis['duplicate_files']
                
                # By architecture
                stats['by_arch'][arch]['total'] += analysis['total_files']
                stats['by_arch'][arch]['duplicates'] += analysis['duplicate_files']
                
                # Worst cases (high duplicate rates)
                if analysis['duplicate_files'] > 0:
                    stats['worst_cases'].append({
                        'path': f"{arch}/{payload_name}/{technique}",
                        'duplicates': analysis['duplicate_files'],
                        'uniqueness': analysis['uniqueness_ratio']
                    })
    
    # Sort worst cases
    stats['worst_cases'].sort(key=lambda x: x['duplicates'], reverse=True)
    
    return stats

def create_visualizations(results, stats):
    """Create visualization graphs for the analysis"""
    print("\nGenerating visualizations...")
    
    # Create report directory
    Path(REPORT_DIR).mkdir(parents=True, exist_ok=True)
    
    # Set style
    sns.set_style("whitegrid")
    plt.rcParams['figure.figsize'] = (12, 6)
    
    # 1. Uniqueness by Technique
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(15, 6))

    # pii  uniqueness = 100
    stats['by_technique']['pii']['unique_ratios'] = [1.0]

    techniques = list(stats['by_technique'].keys())
    avg_uniqueness = [np.mean(stats['by_technique'][t]['unique_ratios']) * 100 
                     for t in techniques]
    duplicate_counts = [stats['by_technique'][t]['duplicates'] for t in techniques]
    
    # Bar chart for average uniqueness
    bars1 = ax1.bar(techniques, avg_uniqueness, color='skyblue', edgecolor='navy')
    ax1.set_title('Average Uniqueness Rate by Mutation Technique', fontsize=14, fontweight='bold')
    ax1.set_xlabel('Technique')
    ax1.set_ylabel('Uniqueness Rate (%)')
    ax1.set_ylim(0, 105)
    ax1.axhline(y=100, color='green', linestyle='--', alpha=0.5, label='Perfect (100%)')
    
    # Add value labels on bars
    for bar, val in zip(bars1, avg_uniqueness):
        height = bar.get_height()
        ax1.text(bar.get_x() + bar.get_width()/2., height + 1,
                f'{val:.1f}%', ha='center', va='bottom')
    
    # Rotate x-axis labels
    ax1.set_xticklabels(techniques, rotation=45, ha='right')
    
    # Bar chart for duplicate counts
    bars2 = ax2.bar(techniques, duplicate_counts, color='coral', edgecolor='darkred')
    ax2.set_title('Total Duplicate Files by Technique', fontsize=14, fontweight='bold')
    ax2.set_xlabel('Technique')
    ax2.set_ylabel('Number of Duplicates')
    ax2.set_xticklabels(techniques, rotation=45, ha='right')
    
    # Add value labels
    for bar, val in zip(bars2, duplicate_counts):
        if val > 0:
            height = bar.get_height()
            ax2.text(bar.get_x() + bar.get_width()/2., height + 0.5,
                    f'{val}', ha='center', va='bottom')
    
    plt.tight_layout()
    plt.savefig(os.path.join(REPORT_DIR, 'technique_analysis.png'), dpi=150, bbox_inches='tight')
    plt.close()
    
    # 2. Heatmap of Uniqueness Rates
    if len(results) > 0:
        # Prepare data for heatmap
        heatmap_data = []
        payload_labels = []
        technique_labels = set()
        
        for arch, payloads in results.items():
            for payload_name, techniques in payloads.items():
                payload_label = f"{arch}/{payload_name}"
                payload_labels.append(payload_label)
                row_data = {}
                for technique, analysis in techniques.items():
                    technique_labels.add(technique)
                    row_data[technique] = analysis['uniqueness_ratio'] * 100
                heatmap_data.append(row_data)
        
        if heatmap_data:
            df_heatmap = pd.DataFrame(heatmap_data, index=payload_labels)
            df_heatmap = df_heatmap.fillna(0)
            
            # Create heatmap
            plt.figure(figsize=(12, max(6, len(payload_labels) * 0.3)))
            sns.heatmap(df_heatmap, annot=True, fmt='.1f', cmap='RdYlGn', 
                       vmin=0, vmax=100, cbar_kws={'label': 'Uniqueness Rate (%)'},
                       linewidths=0.5, linecolor='gray')
            plt.title('Mutation Uniqueness Heatmap\n(100% = All Unique, 0% = All Duplicates)', 
                     fontsize=14, fontweight='bold')
            plt.xlabel('Mutation Technique')
            plt.ylabel('Architecture/Payload')
            plt.tight_layout()
            plt.savefig(os.path.join(REPORT_DIR, 'uniqueness_heatmap.png'), dpi=150, bbox_inches='tight')
            plt.close()
    
    # 3. Distribution of Uniqueness Rates
    plt.figure(figsize=(10, 6))
    all_uniqueness_rates = []
    for arch, payloads in results.items():
        for payload_name, techniques in payloads.items():
            for technique, analysis in techniques.items():
                all_uniqueness_rates.append(analysis['uniqueness_ratio'] * 100)
    
    if all_uniqueness_rates:
        plt.hist(all_uniqueness_rates, bins=20, color='steelblue', edgecolor='black', alpha=0.7)
        plt.axvline(x=np.mean(all_uniqueness_rates), color='red', linestyle='--', 
                   label=f'Mean: {np.mean(all_uniqueness_rates):.1f}%')
        plt.axvline(x=100, color='green', linestyle='--', alpha=0.5, label='Perfect (100%)')
        plt.title('Distribution of Uniqueness Rates Across All Mutations', fontsize=14, fontweight='bold')
        plt.xlabel('Uniqueness Rate (%)')
        plt.ylabel('Frequency')
        plt.legend()
        plt.grid(axis='y', alpha=0.3)
        plt.tight_layout()
        plt.savefig(os.path.join(REPORT_DIR, 'uniqueness_distribution.png'), dpi=150, bbox_inches='tight')
        plt.close()
    
    # 4. Worst Cases Bar Chart
    if stats['worst_cases'][:10]:  # Top 10 worst cases
        fig, ax = plt.subplots(figsize=(12, 6))
        worst_cases = stats['worst_cases'][:10]
        paths = [case['path'] for case in worst_cases]
        duplicates = [case['duplicates'] for case in worst_cases]
        
        bars = ax.barh(range(len(paths)), duplicates, color='red', alpha=0.7)
        ax.set_yticks(range(len(paths)))
        ax.set_yticklabels(paths, fontsize=9)
        ax.set_xlabel('Number of Duplicate Files')
        ax.set_title('Top 10 Worst Cases - Highest Duplicate Counts', fontsize=14, fontweight='bold')
        ax.grid(axis='x', alpha=0.3)
        
        # Add value labels
        for bar, val in zip(bars, duplicates):
            width = bar.get_width()
            ax.text(width + 0.5, bar.get_y() + bar.get_height()/2.,
                   f'{val}', ha='left', va='center')
        
        plt.tight_layout()
        plt.savefig(os.path.join(REPORT_DIR, 'worst_cases.png'), dpi=150, bbox_inches='tight')
        plt.close()
    
    print(f"Visualizations saved to {REPORT_DIR}/")

def generate_detailed_report(results, stats):
    """Generate a detailed text and JSON report"""
    
    # Text report
    report_file = os.path.join(REPORT_DIR, 'duplicate_analysis_report.txt')
    with open(report_file, 'w') as f:
        f.write("=" * 80 + "\n")
        f.write("MUTATION DUPLICATE ANALYSIS REPORT\n")
        f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 80 + "\n\n")
        
        # Overall Summary
        total_files = sum(s['total'] for s in stats['by_arch'].values())
        total_duplicates = sum(s['duplicates'] for s in stats['by_arch'].values())
        
        f.write("OVERALL SUMMARY\n")
        f.write("-" * 40 + "\n")
        f.write(f"Total files analyzed: {total_files}\n")
        f.write(f"Total duplicate files: {total_duplicates}\n")
        f.write(f"Overall uniqueness rate: {((total_files-total_duplicates)/total_files*100):.2f}%\n\n")
        
        # By Architecture
        f.write("BY ARCHITECTURE\n")
        f.write("-" * 40 + "\n")
        for arch, data in stats['by_arch'].items():
            if data['total'] > 0:
                uniqueness = (data['total'] - data['duplicates']) / data['total'] * 100
                f.write(f"{arch}: {data['duplicates']}/{data['total']} duplicates ({uniqueness:.1f}% unique)\n")
        f.write("\n")
        
        # By Technique
        f.write("BY TECHNIQUE\n")
        f.write("-" * 40 + "\n")
        for technique, data in stats['by_technique'].items():
            if data['total'] > 0:
                avg_unique = np.mean(data['unique_ratios']) * 100
                f.write(f"{technique}:\n")
                f.write(f"  Total files: {data['total']}\n")
                f.write(f"  Duplicates: {data['duplicates']}\n")
                f.write(f"  Average uniqueness: {avg_unique:.1f}%\n")
        f.write("\n")
        
        # Worst Cases
        f.write("TOP 10 WORST CASES (Most Duplicates)\n")
        f.write("-" * 40 + "\n")
        for i, case in enumerate(stats['worst_cases'][:10], 1):
            f.write(f"{i}. {case['path']}\n")
            f.write(f"   Duplicates: {case['duplicates']}, Uniqueness: {case['uniqueness']*100:.1f}%\n")
        f.write("\n")
        
        # Detailed Duplicates
        f.write("DETAILED DUPLICATE LISTINGS\n")
        f.write("=" * 80 + "\n")
        
        for arch, payloads in results.items():
            for payload_name, techniques in payloads.items():
                for technique, analysis in techniques.items():
                    if analysis['duplicates']:
                        f.write(f"\n{arch}/{payload_name}/{technique}:\n")
                        f.write("-" * 40 + "\n")
                        for md5, files in analysis['duplicates'].items():
                            f.write(f"MD5: {md5}\n")
                            f.write(f"  Duplicate files ({len(files)}):\n")
                            for file in files:
                                f.write(f"    - {file}\n")
    
    # JSON report for programmatic access
    json_report = {
        'metadata': {
            'generated': datetime.now().isoformat(),
            'total_files': total_files,
            'total_duplicates': total_duplicates,
            'overall_uniqueness_rate': (total_files-total_duplicates)/total_files if total_files > 0 else 0
        },
        'statistics': {
            'by_technique': {k: {'total': v['total'], 
                                'duplicates': v['duplicates'],
                                'avg_uniqueness': np.mean(v['unique_ratios']).item() if v['unique_ratios'] else 0}
                          for k, v in stats['by_technique'].items()},
            'by_arch': dict(stats['by_arch']),
            'worst_cases': stats['worst_cases'][:20]  # Top 20 for JSON
        },
        'detailed_results': results
    }
    
    json_file = os.path.join(REPORT_DIR, 'duplicate_analysis.json')
    with open(json_file, 'w') as f:
        json.dump(json_report, f, indent=2, default=str)
    
    print(f"\nDetailed reports saved to:")
    print(f"  - {report_file}")
    print(f"  - {json_file}")

def main():
    """Main execution function"""
    print("=" * 80)
    print("MUTATION DUPLICATE ANALYZER")
    print("=" * 80)
    
    # Check if matplotlib is available
    try:
        import matplotlib
        import seaborn
        visualizations_available = True
    except ImportError:
        print("Warning: matplotlib/seaborn not installed. Install with:")
        print("  pip install matplotlib seaborn pandas")
        visualizations_available = False
    
    # Analyze all mutations
    results = analyze_all_mutations()
    
    if not results:
        print("\nNo mutations found to analyze!")
        return
    
    # Generate statistics
    stats = generate_summary_statistics(results)
    
    # Print summary
    print("\n" + "=" * 80)
    print("ANALYSIS COMPLETE - SUMMARY")
    print("=" * 80)
    
    total_files = sum(s['total'] for s in stats['by_arch'].values())
    total_duplicates = sum(s['duplicates'] for s in stats['by_arch'].values())
    
    print(f"\nTotal files analyzed: {total_files:,}")
    print(f"Total duplicate files: {total_duplicates:,}")
    print(f"Overall uniqueness rate: {((total_files-total_duplicates)/total_files*100):.2f}%")
    
    # Technique summary
    print("\nTechnique Summary:")
    for technique, data in stats['by_technique'].items():
        if data['total'] > 0:

            avg_unique = np.mean(data['unique_ratios']) * 100
            if technique == "pii":
                avg_unique = 100
            status = "✓" if data['duplicates'] == 0 else "⚠️"
            print(f"  {status} {technique}: {data['duplicates']} duplicates, {avg_unique:.1f}% avg uniqueness")
    
    # Create report directory
    Path(REPORT_DIR).mkdir(parents=True, exist_ok=True)
    
    # Generate detailed report
    generate_detailed_report(results, stats)
    
    # Generate visualizations if available
    if visualizations_available:
        create_visualizations(results, stats)
    else:
        print("\nSkipping visualizations (matplotlib/seaborn not installed)")
    
    print("\n" + "=" * 80)
    print(f"Analysis complete! Check {REPORT_DIR}/ for detailed reports and graphs.")
    print("=" * 80)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nOperation interrupted by user.")
    except Exception as e:
        print(f"\nError: {str(e)}")
        import traceback
        traceback.print_exc()