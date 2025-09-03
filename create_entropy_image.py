import os
import sys
import matplotlib.pyplot as plt
import math


x64_avg_len = 0
x86_avg_len = 0

x64_avg_entropy = 0
x86_avg_entropy = 0


def calculate_entropy(filename):
    entropy = 0
    with open(filename, "rb") as file:
        counters = {byte: 0 for byte in range(2 ** 8)}  # start all counters with zeros

        for byte in file.read():  # read in chunks for large files
            counters[byte] += 1  # increase counter for specified byte

        filesize = file.tell()  # we can get file size by reading current position

        probabilities = [counter / filesize for counter in counters.values()]  # calculate probabilities for each byte

        entropy = -sum(probability * math.log2(probability) for probability in probabilities if probability > 0)  # final sum

        # print(entropy)
        file.close()

    return entropy

def plot_metric(data, metric_name, ylabel, title, output_path, orig64, orig86, ylim_range=None):
    """Plot comparison graph for a given metric"""
    x = range(len(CATEGORIES))
    fig, ax = plt.subplots(figsize=(12, 6))
    
    # Extract values for each architecture
    values_x64 = [data["x64"][cat] for cat in CATEGORIES]
    values_x86 = [data["x86"][cat] for cat in CATEGORIES]
    
    # Get original values (first element)
    original_x64 = orig64
    original_x86 = orig86

    # values_x64 = values_x64[1:]  # Exclude original for plotting
    # values_x86 = values_x86[1:]
    
    # Plot horizontal lines for original values
    ax.axhline(y=original_x64, color='orange', alpha=0.3, linestyle='--', 
            label=f'Original x64: {original_x64:.2f}')
    ax.axhline(y=original_x86, color='blue', alpha=0.3, linestyle='--', 
            label=f'Original x86: {original_x86:.2f}')
    
    # Scatter plot for techniques 
    ax.scatter(x, values_x64, s=90, color='orange', alpha=0.5, 
            marker='o', edgecolors='black', label='x64 techniques')
    ax.scatter(x, values_x86, s=90, color='blue', alpha=0.5, 
            marker='o', edgecolors='black', label='x86 techniques')
    
    # Mark the original point differently
    # ax.scatter([0], [original_x64], s=120, color='orange', alpha=0.7, 
    #         marker='D', edgecolors='black', linewidths=2)
    # ax.scatter([0], [original_x86], s=120, color='blue', alpha=0.7, 
    #         marker='D', edgecolors='black', linewidths=2)
    
    # Add value labels
    for i in x:
        if metric_name == "entropy":
            # For entropy, show more decimal places
            ax.text(i, values_x64[i] + 0.05, f'{values_x64[i]:.3f}', 
                ha='center', va='bottom', fontsize=9, color='orange')
            ax.text(i, values_x86[i] - 0.05, f'{values_x86[i]:.3f}', 
                ha='center', va='top', fontsize=9, color='blue')
        else:
            # For length, show as integers or with K notation
            if values_x64[i] > 10000:
                ax.text(i, values_x64[i] + 500, f'{values_x64[i]/1000:.1f}K', 
                    ha='center', va='bottom', fontsize=9, color='orange')
                ax.text(i, values_x86[i] - 500, f'{values_x86[i]/1000:.1f}K', 
                    ha='center', va='top', fontsize=9, color='blue')
            else:
                ax.text(i, values_x64[i] + 50, f'{values_x64[i]:.0f}', 
                    ha='center', va='bottom', fontsize=9, color='orange')
                ax.text(i, values_x86[i] - 50, f'{values_x86[i]:.0f}', 
                    ha='center', va='top', fontsize=9, color='blue')
    
    # Set x-axis
    ax.set_xticks(x)
    ax.set_xticklabels(CATEGORIES, rotation=45, ha='right', fontsize=14)
    
    # Set labels and title
    ax.set_ylabel(ylabel, fontsize=18)
    ax.set_title(title, fontsize=20)
    ax.set_xlabel("Obfuscation Techniques", fontsize=20)
    
    # Set y-axis limits if provided
    if ylim_range:
        ax.set_ylim(ylim_range)
    
    # Add grid
    ax.grid(True, axis='y', alpha=0.3)
    
    # Add legend
    ax.legend(loc='best')
    
    # Adjust layout and save
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"Saved {metric_name} plot to {output_path}")
    plt.show()





if __name__ == "__main__":
    original_files_x64 = []
    original_files_x86 = []

    for root, dirs, files in os.walk("original_pl"):
        print(f"Checking directory: {root}")
        for file in files:
            if "x64" in file:
                original_files_x64.append(os.path.join(root, file))
            else:
                original_files_x86.append(os.path.join(root, file))

    # print(f"x64 files found: {original_files_x64}")
    # print(f"x86 files found: {original_files_x86}")


    tmp_len = 0
    tmp_len2 = 0

    tmp_entr = 0
    for x,file in enumerate(original_files_x64):
        tmp_entr += calculate_entropy(file)
        tmp_len += os.path.getsize(file)
        tmp_len2 = x
    x64_avg_len = tmp_len/tmp_len2
    x64_avg_entropy = tmp_entr/tmp_len2

    tmp_len = 0
    tmp_len2 = 0

    tmp_entr = 0

    for x,file in enumerate(original_files_x86):
        tmp_entr += calculate_entropy(file)
        tmp_len += os.path.getsize(file)
        tmp_len2 = x
    x86_avg_len = tmp_len/tmp_len2
    x86_avg_entropy = tmp_entr/tmp_len2

    print(f"x86 len: {x86_avg_len}")
    print(f"x64 avg len {x64_avg_len}")

    print(f"x64 avg entr: {x64_avg_entropy}")
    print(f"x86 avg entr: {x86_avg_entropy}")

    nop_x64_len = 0
    nop_x86_len = 0
    nop_x64_entr = 0
    nop_x86_entr = 0

    eq_x64_len = 0
    eq_x86_len = 0
    eq_x64_entr = 0
    eq_x86_entr = 0

    bcf_x64_len = 0
    bcf_x86_len = 0
    bcf_x64_entr = 0
    bcf_x86_entr = 0

    ibp_x64_len = 0
    ibp_x86_len = 0
    ibp_x64_entr = 0
    ibp_x86_entr = 0

    pii_x64_len = 0
    pii_x86_len = 0
    pii_x64_entr = 0
    pii_x86_entr = 0

    eq_nop_pii_x64_len = 0
    eq_nop_pii_x86_len = 0
    eq_nop_pii_x64_entr = 0
    eq_nop_pii_x86_entr = 0

    eq_nop_bcf_x64_len = 0
    eq_nop_bcf_x86_len = 0
    eq_nop_bcf_x64_entr = 0
    eq_nop_bcf_x86_entr = 0

    eq_nop_ibp_x64_len = 0
    eq_nop_ibp_x86_len = 0
    eq_nop_ibp_x64_entr = 0
    eq_nop_ibp_x86_entr = 0


    n_x64_nop = 0
    n_x86_nop = 0

    n_x64_eq = 0
    n_x86_eq = 0

    n_x64_bcf = 0
    n_x86_bcf = 0

    n_x64_ibp = 0
    n_x86_ibp = 0

    n_x64_pii = 0
    n_x86_pii = 0

    n_x64_eq_nop_pii = 0
    n_x86_eq_nop_pii = 0

    n_x64_eq_nop_bcf = 0
    n_x86_eq_nop_bcf = 0

    n_x64_eq_nop_ibp = 0
    n_x86_eq_nop_ibp = 0

    for root, dirs, files in os.walk("mutations"):

        if "x64" in root:

            for file in files:
                if "eq_nop_pii" in file:
                    eq_nop_pii_x64_len += os.path.getsize(os.path.join(root, file))
                    eq_nop_pii_x64_entr += calculate_entropy(os.path.join(root, file))
                    n_x64_eq_nop_pii += 1
                elif "eq_nop_bcf" in file:
                    eq_nop_bcf_x64_len += os.path.getsize(os.path.join(root, file))
                    eq_nop_bcf_x64_entr += calculate_entropy(os.path.join(root, file))
                    n_x64_eq_nop_bcf += 1
                elif "eq_nop_ibp" in file:
                    eq_nop_ibp_x64_len += os.path.getsize(os.path.join(root, file))
                    eq_nop_ibp_x64_entr += calculate_entropy(os.path.join(root, file))
                    n_x64_eq_nop_ibp += 1
                elif "nop" in file:
                    nop_x64_len += os.path.getsize(os.path.join(root, file))
                    nop_x64_entr += calculate_entropy(os.path.join(root, file))
                    n_x64_nop += 1
                elif "eq" in file:
                    eq_x64_len += os.path.getsize(os.path.join(root, file))
                    eq_x64_entr += calculate_entropy(os.path.join(root, file))
                    n_x64_eq += 1
                elif "bcf" in file:
                    bcf_x64_len += os.path.getsize(os.path.join(root, file))
                    bcf_x64_entr += calculate_entropy(os.path.join(root, file))
                    n_x64_bcf += 1
                elif "ibp" in file:
                    ibp_x64_len += os.path.getsize(os.path.join(root, file))
                    ibp_x64_entr += calculate_entropy(os.path.join(root, file))
                    n_x64_ibp += 1
                elif "pii" in file:
                    pii_x64_len += os.path.getsize(os.path.join(root, file))
                    pii_x64_entr += calculate_entropy(os.path.join(root, file))
                    n_x64_pii += 1

        else:
            for file in files:
                if "eq_nop_pii" in file:
                    eq_nop_pii_x86_len += os.path.getsize(os.path.join(root, file))
                    eq_nop_pii_x86_entr += calculate_entropy(os.path.join(root, file))
                    n_x86_eq_nop_pii += 1
                elif "eq_nop_bcf" in file:
                    eq_nop_bcf_x86_len += os.path.getsize(os.path.join(root, file))
                    eq_nop_bcf_x86_entr += calculate_entropy(os.path.join(root, file))
                    n_x86_eq_nop_bcf += 1
                elif "eq_nop_ibp" in file:
                    eq_nop_ibp_x86_len += os.path.getsize(os.path.join(root, file))
                    eq_nop_ibp_x86_entr += calculate_entropy(os.path.join(root, file))
                    n_x86_eq_nop_ibp += 1
                elif "nop" in file:
                    nop_x86_len += os.path.getsize(os.path.join(root, file))
                    nop_x86_entr += calculate_entropy(os.path.join(root, file))
                    n_x86_nop += 1
                elif "eq" in file:
                    eq_x86_len += os.path.getsize(os.path.join(root, file))
                    eq_x86_entr += calculate_entropy(os.path.join(root, file))
                    n_x86_eq += 1
                elif "bcf" in file:
                    bcf_x86_len += os.path.getsize(os.path.join(root, file))
                    bcf_x86_entr += calculate_entropy(os.path.join(root, file))
                    n_x86_bcf += 1
                elif "ibp" in file:
                    ibp_x86_len += os.path.getsize(os.path.join(root, file))
                    ibp_x86_entr += calculate_entropy(os.path.join(root, file))
                    n_x86_ibp += 1
                elif "pii" in file:
                    pii_x86_len += os.path.getsize(os.path.join(root, file))
                    pii_x86_entr += calculate_entropy(os.path.join(root, file))
                    n_x86_pii += 1


    x64_nop_avg_entr = nop_x64_entr / n_x64_nop if n_x64_nop > 0 else 0
    x86_nop_avg_entr = nop_x86_entr / n_x86_nop if n_x86_nop > 0 else 0
    x64_eq_avg_entr = eq_x64_entr / n_x64_eq if n_x64_eq > 0 else 0
    x86_eq_avg_entr = eq_x86_entr / n_x86_eq if n_x86_eq > 0 else 0
    x64_bcf_avg_entr = bcf_x64_entr / n_x64_bcf if n_x64_bcf > 0 else 0
    x86_bcf_avg_entr = bcf_x86_entr / n_x86_bcf if n_x86_bcf > 0 else 0
    x64_ibp_avg_entr = ibp_x64_entr / n_x64_ibp if n_x64_ibp > 0 else 0
    x86_ibp_avg_entr = ibp_x86_entr / n_x86_ibp if n_x86_ibp > 0 else 0
    x64_pii_avg_entr = pii_x64_entr / n_x64_pii if n_x64_pii > 0 else 0
    x86_pii_avg_entr = pii_x86_entr / n_x86_pii if n_x86_pii > 0 else 0
    x64_eq_nop_pii_avg_entr = eq_nop_pii_x64_entr / n_x64_eq_nop_pii if n_x64_eq_nop_pii > 0 else 0
    x86_eq_nop_pii_avg_entr = eq_nop_pii_x86_entr / n_x86_eq_nop_pii if n_x86_eq_nop_pii > 0 else 0
    x64_eq_nop_bcf_avg_entr = eq_nop_bcf_x64_entr / n_x64_eq_nop_bcf if n_x64_eq_nop_bcf > 0 else 0
    x86_eq_nop_bcf_avg_entr = eq_nop_bcf_x86_entr / n_x86_eq_nop_bcf if n_x86_eq_nop_bcf > 0 else 0
    x64_eq_nop_ibp_avg_entr = eq_nop_ibp_x64_entr / n_x64_eq_nop_ibp if n_x64_eq_nop_ibp > 0 else 0
    x86_eq_nop_ibp_avg_entr = eq_nop_ibp_x86_entr / n_x86_eq_nop_ibp if n_x86_eq_nop_ibp > 0 else 0
    print(f"x64 nop avg entr: {x64_nop_avg_entr}")
    print(f"x86 nop avg entr: {x86_nop_avg_entr}")
    print(f"x64 eq avg entr: {x64_eq_avg_entr}")
    print(f"x86 eq avg entr: {x86_eq_avg_entr}")
    print(f"x64 bcf avg entr: {x64_bcf_avg_entr}")
    print(f"x86 bcf avg entr: {x86_bcf_avg_entr}")
    print(f"x64 ibp avg entr: {x64_ibp_avg_entr}")
    print(f"x86 ibp avg entr: {x86_ibp_avg_entr}")
    print(f"x64 pii avg entr: {x64_pii_avg_entr}")
    print(f"x86 pii avg entr: {x86_pii_avg_entr}")
    print(f"x64 eq_nop_pii avg entr: {x64_eq_nop_pii_avg_entr}")
    print(f"x86 eq_nop_pii avg entr: {x86_eq_nop_pii_avg_entr}")
    print(f"x64 eq_nop_bcf avg entr: {x64_eq_nop_bcf_avg_entr}")
    print(f"x86 eq_nop_bcf avg entr: {x86_eq_nop_bcf_avg_entr}")
    print(f"x64 eq_nop_ibp avg entr: {x64_eq_nop_ibp_avg_entr}")
    print(f"x86 eq_nop_ibp avg entr: {x86_eq_nop_ibp_avg_entr}")

    x64_nop_avg_len = nop_x64_len / n_x64_nop if n_x64_nop > 0 else 0
    x86_nop_avg_len = nop_x86_len / n_x86_nop if n_x86_nop > 0 else 0
    x64_eq_avg_len = eq_x64_len / n_x64_eq if n_x64_eq > 0 else 0
    x86_eq_avg_len = eq_x86_len / n_x86_eq if n_x86_eq > 0 else 0
    x64_bcf_avg_len = bcf_x64_len / n_x64_bcf if n_x64_bcf > 0 else 0
    x86_bcf_avg_len = bcf_x86_len / n_x86_bcf if n_x86_bcf > 0 else 0
    x64_ibp_avg_len = ibp_x64_len / n_x64_ibp if n_x64_ibp > 0 else 0
    x86_ibp_avg_len = ibp_x86_len / n_x86_ibp if n_x86_ibp > 0 else 0
    x64_pii_avg_len = pii_x64_len / n_x64_pii if n_x64_pii > 0 else 0
    x86_pii_avg_len = pii_x86_len / n_x86_pii if n_x86_pii > 0 else 0
    x64_eq_nop_pii_avg_len = eq_nop_pii_x64_len / n_x64_eq_nop_pii if n_x64_eq_nop_pii > 0 else 0
    x86_eq_nop_pii_avg_len = eq_nop_pii_x86_len / n_x86_eq_nop_pii if n_x86_eq_nop_pii > 0 else 0
    x64_eq_nop_bcf_avg_len = eq_nop_bcf_x64_len / n_x64_eq_nop_bcf if n_x64_eq_nop_bcf > 0 else 0
    x86_eq_nop_bcf_avg_len = eq_nop_bcf_x86_len / n_x86_eq_nop_bcf if n_x86_eq_nop_bcf > 0 else 0
    x64_eq_nop_ibp_avg_len = eq_nop_ibp_x64_len / n_x64_eq_nop_ibp if n_x64_eq_nop_ibp > 0 else 0
    x86_eq_nop_ibp_avg_len = eq_nop_ibp_x86_len / n_x86_eq_nop_ibp if n_x86_eq_nop_ibp > 0 else 0
    print(f"x64 nop avg len: {x64_nop_avg_len}")
    print(f"x86 nop avg len: {x86_nop_avg_len}")
    print(f"x64 eq avg len: {x64_eq_avg_len}")

    print(f"x86 eq avg len: {x86_eq_avg_len}")
    print(f"x64 bcf avg len: {x64_bcf_avg_len}")
    print(f"x86 bcf avg len: {x86_bcf_avg_len}")
    print(f"x64 ibp avg len: {x64_ibp_avg_len}")
    print(f"x86 ibp avg len: {x86_ibp_avg_len}")
    print(f"x64 pii avg len: {x64_pii_avg_len}")
    print(f"x86 pii avg len: {x86_pii_avg_len}")
    print(f"x64 eq_nop_pii avg len: {x64_eq_nop_pii_avg_len}")
    print(f"x86 eq_nop_pii avg len: {x86_eq_nop_pii_avg_len}")
    print(f"x64 eq_nop_bcf avg len: {x64_eq_nop_bcf_avg_len}")
    print(f"x86 eq_nop_bcf avg len: {x86_eq_nop_bcf_avg_len}")
    print(f"x64 eq_nop_ibp avg len: {x64_eq_nop_ibp_avg_len}")
    print(f"x86 eq_nop_ibp avg len: {x86_eq_nop_ibp_avg_len}")




    #!/usr/bin/env python3
    import matplotlib.pyplot as plt
    import numpy as np

    # Categories for x-axis (matching the second script's style)
    CATEGORIES = ['nop', 'eq', 'pii', 'bcf', 'ibp', 'eq_nop_pii', 'eq_nop_bcf', 'eq_nop_ibp']

    # Data extracted from the first script's output
    # You'll need to replace these with actual values from running your first script
    entropy_data = {
        "x64": {
            # "Original": x64_avg_entropy,
            "nop": x64_nop_avg_entr,
            "eq": x64_eq_avg_entr,
            "pii": x64_pii_avg_entr,
            "bcf": x64_bcf_avg_entr,
            "ibp": x64_ibp_avg_entr,
            "eq_nop_pii": x64_eq_nop_pii_avg_entr,
            "eq_nop_bcf": x64_eq_nop_bcf_avg_entr,
            "eq_nop_ibp": x64_eq_nop_ibp_avg_entr
        },
        "x86": {
            # "Original": x86_avg_entropy,
            "nop": x86_nop_avg_entr,
            "eq": x86_eq_avg_entr,
            "pii": x86_pii_avg_entr,
            "bcf": x86_bcf_avg_entr,
            "ibp": x86_ibp_avg_entr,
            "eq_nop_pii": x86_eq_nop_pii_avg_entr,
            "eq_nop_bcf": x86_eq_nop_bcf_avg_entr,
            "eq_nop_ibp": x86_eq_nop_ibp_avg_entr
        }
    }

    length_data = {
        "x64": {
            # "Original": x64_avg_len,
            "nop": x64_nop_avg_len,
            "eq": x64_eq_avg_len,
            "pii": x64_pii_avg_len,
            "bcf": x64_bcf_avg_len,
            "ibp": x64_ibp_avg_len,
            "eq_nop_pii": x64_eq_nop_pii_avg_len,
            "eq_nop_bcf": x64_eq_nop_bcf_avg_len,
            "eq_nop_ibp": x64_eq_nop_ibp_avg_len
        },
        "x86": {
            # "Original": x86_avg_len,
            "nop": x86_nop_avg_len,
            "eq": x86_eq_avg_len,
            "pii": x86_pii_avg_len,
            "bcf": x86_bcf_avg_len,
            "ibp": x86_ibp_avg_len,
            "eq_nop_pii": x86_eq_nop_pii_avg_len,
            "eq_nop_bcf": x86_eq_nop_bcf_avg_len,
            "eq_nop_ibp": x86_eq_nop_ibp_avg_len
        }
    }


    
    # Plot entropy comparison
    plot_metric(
        entropy_data, 
        "entropy",
        "Average Entropy (bits)", 
        "Binary Entropy Comparison (x86 vs x64)",
        "entropy_comparison.png",
        orig64=x64_avg_entropy,
        orig86=x86_avg_entropy,
        ylim_range=None
    )
    
    # Plot length comparison
    plot_metric(
        length_data,
        "length", 
        "Average File Size (bytes)", 
        "Binary File Size Comparison (x86 vs x64)",
        "length_comparison.png",
        orig64=x64_avg_len,
        orig86=x86_avg_len,
        ylim_range=None
    )
    
    print("\nBoth plots have been generated successfully!")
    print("Please update the data dictionaries with actual values from your analysis.")

    

            
