import os
import sys
import matplotlib.pyplot as plt
import math
import numpy as np
from collections import Counter
from sklearn.metrics.pairwise import cosine_similarity as sklearn_cosine_similarity
from capstone import *
import re
# Global variables for averages
x64_avg_len = 0
x86_avg_len = 0
x64_avg_entropy = 0
x86_avg_entropy = 0


BASIC = {"nop", "eq", "pii", "bcf", "ibp"}

def has_tag(name: str, tag: str) -> bool:
    # match del tag come token separato (underscore, inizio/fine, ecc.)
    return re.search(rf'(?<![A-Za-z0-9]){tag}(?![A-Za-z0-9])', name) is not None

def tags_in(name: str):
    base = os.path.basename(name)
    return {t for t in BASIC if has_tag(base, t)}


def disassemble_file(filename, is_x64=True):
    """
    Disassemble a binary file and return assembly code as string
    
    Parameters:
    -----------
    filename : str
        Path to the binary file
    is_x64 : bool
        True for x64 architecture, False for x86
        
    Returns:
    --------
    str
        Assembly code with one instruction per line
    """
    # Read the binary file
    with open(filename, 'rb') as f:
        code = f.read()
    
    # Setup Capstone disassembler
    if is_x64:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
    else:
        md = Cs(CS_ARCH_X86, CS_MODE_32)
    
    # Enable skipdata to handle non-instruction bytes
    md.skipdata = False
    # Enable detail mode to get more instruction information
    md.detail = True
    
    # Disassemble and build assembly string
    asm_lines = []
    for insn in md.disasm(code, 0x0):
        # Add the mnemonic (opcode) to our list
        asm_lines.append(insn.mnemonic)
    
    return '\n'.join(asm_lines)

# def calculate_entropy(filename):
#     """Calculate Shannon entropy of a file"""
#     entropy = 0
#     with open(filename, "rb") as file:
#         counters = {byte: 0 for byte in range(2 ** 8)}
        
#         for byte in file.read():
#             counters[byte] += 1
        
#         filesize = file.tell()
        
#         if filesize == 0:
#             return 0
            
#         probabilities = [counter / filesize for counter in counters.values()]
#         entropy = -sum(probability * math.log2(probability) for probability in probabilities if probability > 0)
        
#     return entropy

import math
from collections import Counter

def calculate_entropy(filename) -> float:
    """
    Calculate Shannon entropy of assembly code based on token frequency.
    Tokens include both opcodes and operands (not just raw bytes).

    Parameters
    ----------
    asm : str
        Assembly code snippet (one instruction per line).

    Returns
    -------
    float
        Shannon entropy value.
    """

    asm = ""


    if "x64" in filename:
        asm = disassemble_file(filename, True)
    elif "x86" in filename:
        asm = disassemble_file(filename, False)

    # Tokenize assembly (opcodes + operands)
    def tokenize(asm: str):
        tokens = []
        for line in asm.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = [tok.strip() for tok in line.replace(',', ' ').split() if tok.strip()]
            tokens.extend(parts)
        return tokens

    tokens = tokenize(asm)

    if not tokens:
        return 0.0

    # Count frequency of each token
    counter = Counter(tokens)
    total_tokens = sum(counter.values())

    # Compute Shannon entropy
    entropy = -sum(
        (count / total_tokens) * math.log2(count / total_tokens)
        for count in counter.values()
    )

    return entropy



def calculate_entropy_change_percentage(technique_entropy, original_entropy):
    """
    Calculate the percentage change in entropy compared to original
    Returns: percentage change (positive = increase, negative = decrease)
    """
    if original_entropy == 0:
        return 0
    
    percentage_change = ((technique_entropy - original_entropy) / original_entropy) * 100
    return percentage_change

def calculate_entropy_variance(filename, window_size=128):
    """
    Calculate entropy variance - measures how entropy is distributed across the file
    Returns: variance of entropy values and coefficient of variation
    """
    with open(filename, "rb") as file:
        data = file.read()
    
    if len(data) < window_size:
        return 0, 0
    
    entropies = []
    for i in range(0, len(data) - window_size + 1, window_size // 2):  # Overlapping windows
        chunk = data[i:i + window_size]
        
        # Calculate entropy for this chunk
        byte_counts = Counter(chunk)
        chunk_size = len(chunk)
        
        if chunk_size == 0:
            continue
            
        chunk_entropy = 0
        for count in byte_counts.values():
            if count > 0:
                probability = count / chunk_size
                chunk_entropy -= probability * math.log2(probability)
        
        entropies.append(chunk_entropy)
    
    if len(entropies) < 2:
        return 0, 0
    
    # Calculate variance and coefficient of variation
    variance = np.var(entropies)
    mean_entropy = np.mean(entropies)
    
    # Coefficient of variation (CV) = std_dev / mean
    # Useful for comparing variance across files with different mean entropies
    cv = np.std(entropies) / mean_entropy if mean_entropy > 0 else 0
    
    return variance, cv

def get_byte_frequency_vector(filename):
    """Get normalized byte frequency vector for cosine similarity calculation"""
    freq_vector = np.zeros(256)
    
    with open(filename, "rb") as file:
        data = file.read()
        
    if len(data) == 0:
        return freq_vector
    
    for byte in data:
        freq_vector[byte] += 1
    
    # Normalize
    total = np.sum(freq_vector)
    if total > 0:
        freq_vector = freq_vector / total
    
    return freq_vector

def cosine_similarity(vec1, vec2):
    """Calculate cosine similarity between two vectors"""
    dot_product = np.dot(vec1, vec2)
    norm1 = np.linalg.norm(vec1)
    norm2 = np.linalg.norm(vec2)
    
    if norm1 == 0 or norm2 == 0:
        return 0
    
    return dot_product / (norm1 * norm2)



# def cosine_similarity_on_asm(asm1: str, asm2: str) -> float:
#     """
#     Compute cosine similarity between two assembly code snippets
#     based on opcode frequency vectors.
    
#     Parameters
#     ----------
#     asm1 : str
#         Assembly code snippet 1 (one instruction per line).
#     asm2 : str
#         Assembly code snippet 2 (one instruction per line).
    
#     Returns
#     -------
#     float
#         Cosine similarity score between 0.0 (completely different) and 1.0 (identical).
#     """
    
#     # Extract opcodes (each line is already just the opcode from our disassemble_file function)
#     tokens1 = [line.strip() for line in asm1.splitlines() if line.strip()]
#     tokens2 = [line.strip() for line in asm2.splitlines() if line.strip()]
    
#     # Handle empty assembly
#     if not tokens1 or not tokens2:
#         return 0.0
    
#     # Count opcode frequencies
#     counter1 = Counter(tokens1)
#     counter2 = Counter(tokens2)
    
#     # Build a joint vocabulary of opcodes
#     all_opcodes = list(set(counter1.keys()) | set(counter2.keys()))
    
#     # Handle case with no opcodes
#     if not all_opcodes:
#         return 0.0
    
#     # Convert counts into aligned vectors
#     vec1 = np.array([counter1[op] for op in all_opcodes]).reshape(1, -1)
#     vec2 = np.array([counter2[op] for op in all_opcodes]).reshape(1, -1)
    
#     # Compute cosine similarity
#     sim = sklearn_cosine_similarity(vec1, vec2)[0][0]
#     return sim


def cosine_similarity_on_asm(asm1: str, asm2: str) -> float:
    """
    Compute cosine similarity between two assembly code snippets
    based on full token frequency vectors (opcodes + operands).
    
    This matches the approach used in the "Can LLMs Obfuscate Code?"
    paper, where cosine similarity is computed over assembly symbols,
    not just opcodes.

    Parameters
    ----------
    asm1 : str
        Assembly code snippet 1 (one instruction per line).
    asm2 : str
        Assembly code snippet 2 (one instruction per line).
    
    Returns
    -------
    float
        Cosine similarity score between 0.0 (completely different) 
        and 1.0 (identical).
    """

    # Tokenize each line into opcode + operands (split on whitespace, commas, etc.)
    def tokenize(asm: str):
        tokens = []
        for line in asm.splitlines():
            line = line.strip()
            if not line:
                continue
            # Split by spaces, commas, and tabs
            parts = [tok.strip() for tok in line.replace(',', ' ').split() if tok.strip()]
            tokens.extend(parts)
        return tokens

    tokens1 = tokenize(asm1)
    tokens2 = tokenize(asm2)

    # Handle empty assembly
    if not tokens1 or not tokens2:
        return 0.0

    # Count token frequencies
    counter1 = Counter(tokens1)
    counter2 = Counter(tokens2)

    # Build joint vocabulary
    all_tokens = list(set(counter1.keys()) | set(counter2.keys()))
    if not all_tokens:
        return 0.0

    # Convert counts into aligned vectors
    vec1 = np.array([counter1[tok] for tok in all_tokens]).reshape(1, -1)
    vec2 = np.array([counter2[tok] for tok in all_tokens]).reshape(1, -1)

    # Compute cosine similarity
    return sklearn_cosine_similarity(vec1, vec2)[0][0]

def plot_metric(data, metric_name, ylabel, title, output_path, orig64, orig86, ylim_range=None):
    """Plot comparison graph for a given metric"""
    x = range(len(CATEGORIES))
    fig, ax = plt.subplots(figsize=(12, 6))
    
    values_x64 = [data["x64"][cat] for cat in CATEGORIES]
    values_x86 = [data["x86"][cat] for cat in CATEGORIES]
    
    original_x64 = orig64
    original_x86 = orig86
    
    # Format labels based on metric type
    if metric_name == "entropy_change":
        label_format = lambda v: f'{v:+.1f}%'
        orig_label_x64 = 'Original x64: 0% (baseline)'
        orig_label_x86 = 'Original x86: 0% (baseline)'
        # For entropy change, the baseline is 0%
        original_x64 = 0
        original_x86 = 0
    elif metric_name in ["cosine_similarity", "asm_cosine_similarity"]:
        label_format = lambda v: f'{v:.3f}'
        orig_label_x64 = f'Original x64: {original_x64:.3f}'
        orig_label_x86 = f'Original x86: {original_x86:.3f}'
    else:
        label_format = lambda v: f'{v:.3f}'
        orig_label_x64 = f'Original x64: {original_x64:.3f}'
        orig_label_x86 = f'Original x86: {original_x86:.3f}'
    
    # Plot horizontal lines for original values
    ax.axhline(y=original_x64, color='orange', alpha=0.3, linestyle='--', 
            label=orig_label_x64)
    ax.axhline(y=original_x86, color='blue', alpha=0.3, linestyle='--', 
            label=orig_label_x86)
    
    # Scatter plot for techniques 
    ax.scatter(x, values_x64, s=90, color='orange', alpha=0.5, 
            marker='o', edgecolors='black', label='x64 techniques')
    ax.scatter(x, values_x86, s=90, color='blue', alpha=0.5, 
            marker='o', edgecolors='black', label='x86 techniques')
    
    # Add value labels
    for i in x:
        if metric_name == "entropy_change":
            # Show as percentage with + or - sign
            ax.text(i, values_x64[i] + max(abs(min(values_x64)), abs(max(values_x64))) * 0.02, 
                    f'{values_x64[i]:+.1f}%', 
                    ha='center', va='bottom', fontsize=9, color='orange')
            ax.text(i, values_x86[i] - max(abs(min(values_x86)), abs(max(values_x86))) * 0.02, 
                    f'{values_x86[i]:+.1f}%', 
                    ha='center', va='top', fontsize=9, color='blue')
        elif metric_name in ["cosine_similarity", "asm_cosine_similarity"]:
            # Show with 3 decimals, values between 0-1
            ax.text(i, values_x64[i] + 0.02, f'{values_x64[i]:.3f}', 
                ha='center', va='bottom', fontsize=9, color='orange')
            ax.text(i, values_x86[i] - 0.02, f'{values_x86[i]:.3f}', 
                ha='center', va='top', fontsize=9, color='blue')
        elif metric_name in ["entropy", "entropy_variance"]:
            ax.text(i, values_x64[i] + 0.01, f'{values_x64[i]:.3f}', 
                ha='center', va='bottom', fontsize=9, color='orange')
            ax.text(i, values_x86[i] - 0.01, f'{values_x86[i]:.3f}', 
                ha='center', va='top', fontsize=9, color='blue')
        else:
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
    
    # Set special y-axis limits for cosine similarity (0 to 1)
    if metric_name in ["cosine_similarity", "asm_cosine_similarity"]:
        ax.set_ylim([0, 1.05])
    elif ylim_range:
        ax.set_ylim(ylim_range)
    
    ax.set_xticks(x)
    ax.set_xticklabels(CATEGORIES, rotation=45, ha='right', fontsize=14)
    ax.set_ylabel(ylabel, fontsize=14)
    ax.set_title(title, fontsize=16)
    ax.set_xlabel("Obfuscation Techniques", fontsize=16)
    
    ax.grid(True, axis='y', alpha=0.3)
    ax.legend(loc='best')
    
    plt.tight_layout()
    plt.savefig(output_path, dpi=300, bbox_inches='tight')
    print(f"Saved {metric_name} plot to {output_path}")
    plt.show()

def plot_combined_metrics(entropy_data, entropy_change_data, cosine_data, asm_cosine_data, length_data, variance_data,
                         x64_orig_entropy, x86_orig_entropy, x64_orig_variance, x86_orig_variance, 
                         x64_orig_len, x86_orig_len):
    """Create a 2x3 subplot with all metrics"""
    fig, axes = plt.subplots(2, 3, figsize=(20, 12))
    x = range(len(CATEGORIES))
    
    metrics = [
        (entropy_data, "Shannon Entropy", "Entropy (bits)", axes[0, 0], 'entropy'),
        (entropy_change_data, "Entropy Change from Original", "Change (%)", axes[0, 1], 'entropy_change'),
        (variance_data, "Entropy Variance", "Variance", axes[0, 2], 'variance'),
        (cosine_data, "Byte-level Cosine Similarity", "Similarity Score", axes[1, 0], 'cosine'),
        (asm_cosine_data, "Assembly-level Cosine Similarity", "Similarity Score", axes[1, 1], 'asm_cosine'),
        (length_data, "File Size", "Size (bytes)", axes[1, 2], 'length')
    ]
    
    for data, title, ylabel, ax, metric_type in metrics:
        values_x64 = [data["x64"][cat] for cat in CATEGORIES]
        values_x86 = [data["x86"][cat] for cat in CATEGORIES]
        
        # Add horizontal lines for original values based on metric type
        if metric_type == 'entropy':
            ax.axhline(y=x64_orig_entropy, color='orange', alpha=0.3, linestyle='--', 
                      label=f'Original x64: {x64_orig_entropy:.3f}', linewidth=1.5)
            ax.axhline(y=x86_orig_entropy, color='blue', alpha=0.3, linestyle='--', 
                      label=f'Original x86: {x86_orig_entropy:.3f}', linewidth=1.5)
        elif metric_type == 'entropy_change':
            # For entropy change, baseline is 0%
            ax.axhline(y=0, color='gray', alpha=0.3, linestyle='--', 
                      label='Original: 0% (baseline)', linewidth=1.5)
            # Add color bands for positive/negative changes
            ax.axhspan(0, max(max(values_x64), max(values_x86)) * 1.1, alpha=0.05, color='green')
            ax.axhspan(min(min(values_x64), min(values_x86)) * 1.1, 0, alpha=0.05, color='red')
        elif metric_type == 'variance':
            ax.axhline(y=x64_orig_variance, color='orange', alpha=0.3, linestyle='--', 
                      label=f'Original x64: {x64_orig_variance:.3f}', linewidth=1.5)
            ax.axhline(y=x86_orig_variance, color='blue', alpha=0.3, linestyle='--', 
                      label=f'Original x86: {x86_orig_variance:.3f}', linewidth=1.5)
        elif metric_type in ['cosine', 'asm_cosine']:
            # For cosine similarity, original compared to itself = 1.0
            ax.axhline(y=1.0, color='gray', alpha=0.3, linestyle='--', 
                      label='Original (self-similarity): 1.000', linewidth=1.5)
        elif metric_type == 'length':
            ax.axhline(y=x64_orig_len, color='orange', alpha=0.3, linestyle='--', 
                      label=f'Original x64: {x64_orig_len:.0f}', linewidth=1.5)
            ax.axhline(y=x86_orig_len, color='blue', alpha=0.3, linestyle='--', 
                      label=f'Original x86: {x86_orig_len:.0f}', linewidth=1.5)
        
        # Plot the data points
        ax.plot(x, values_x64, 'o-', color='orange', alpha=0.7, 
                markersize=8, linewidth=2, label='x64')
        ax.plot(x, values_x86, 's-', color='blue', alpha=0.7, 
                markersize=8, linewidth=2, label='x86')
        
        # Set y-axis limits for cosine similarity
        if "Cosine" in title:
            ax.set_ylim([0, 1.05])
        
        ax.set_xticks(x)
        ax.set_xticklabels(CATEGORIES, rotation=45, ha='right', fontsize=10)
        ax.set_ylabel(ylabel, fontsize=12)
        ax.set_title(title, fontsize=14, fontweight='bold')
        ax.grid(True, alpha=0.3)
        ax.legend(loc='best', fontsize=9)
    
    plt.suptitle("Comprehensive Binary Obfuscation Analysis", fontsize=16, y=1.02)
    plt.tight_layout()
    plt.savefig("combined_analysis.png", dpi=300, bbox_inches='tight')
    print("Saved combined analysis plot to combined_analysis.png")
    plt.show()

if __name__ == "__main__":
    # Categories for analysis
    CATEGORIES = ['nop', 'eq', 'pii', 'bcf', 'ibp', 'eq_nop_pii', 'eq_nop_bcf', 'eq_nop_ibp', 'eq_nop', 'eq_pii', 'eq_bcf', 'eq_ibp', 'nop_pii', 'nop_bcf', 'nop_ibp']
    
    # Process original files
    original_files_x64 = []
    original_files_x86 = []
    
    for root, dirs, files in os.walk("original_pl"):
        print(f"Checking directory: {root}")
        for file in files:
            if "x64" in file:
                original_files_x64.append(os.path.join(root, file))
            else:
                original_files_x86.append(os.path.join(root, file))
    
    # Calculate original averages
    tmp_len = 0
    tmp_entr = 0
    tmp_variance = 0
    x64_orig_vectors = []
    x64_orig_asm_list = []
    
    for x, file in enumerate(original_files_x64):
        tmp_entr += calculate_entropy(file)
        tmp_len += os.path.getsize(file)
        variance, _ = calculate_entropy_variance(file)
        tmp_variance += variance
        x64_orig_vectors.append(get_byte_frequency_vector(file))
        # Disassemble for ASM analysis
        asm_code = disassemble_file(file, is_x64=True)
        x64_orig_asm_list.append(asm_code)
    
    if len(original_files_x64) > 0:
        x64_avg_len = tmp_len / len(original_files_x64)
        x64_avg_entropy = tmp_entr / len(original_files_x64)
        x64_avg_variance = tmp_variance / len(original_files_x64)
        x64_avg_vector = np.mean(x64_orig_vectors, axis=0)
        # Concatenate all original ASM for comparison
        x64_orig_asm_combined = '\n'.join(x64_orig_asm_list)
    
    tmp_len = 0
    tmp_entr = 0
    tmp_variance = 0
    x86_orig_vectors = []
    x86_orig_asm_list = []
    
    for x, file in enumerate(original_files_x86):
        tmp_entr += calculate_entropy(file)
        tmp_len += os.path.getsize(file)
        variance, _ = calculate_entropy_variance(file)
        tmp_variance += variance
        x86_orig_vectors.append(get_byte_frequency_vector(file))
        # Disassemble for ASM analysis
        asm_code = disassemble_file(file, is_x64=False)
        x86_orig_asm_list.append(asm_code)
    
    if len(original_files_x86) > 0:
        x86_avg_len = tmp_len / len(original_files_x86)
        x86_avg_entropy = tmp_entr / len(original_files_x86)
        x86_avg_variance = tmp_variance / len(original_files_x86)
        x86_avg_vector = np.mean(x86_orig_vectors, axis=0)
        # Concatenate all original ASM for comparison
        x86_orig_asm_combined = '\n'.join(x86_orig_asm_list)
    
    print(f"\nOriginal File Statistics:")
    print(f"x64 - Len: {x64_avg_len:.0f}, Entropy: {x64_avg_entropy:.3f}, Variance: {x64_avg_variance:.3f}")
    print(f"x86 - Len: {x86_avg_len:.0f}, Entropy: {x86_avg_entropy:.3f}, Variance: {x86_avg_variance:.3f}")
    
    # Initialize dictionaries for all metrics
    results = {
        "entropy": {"x64": {}, "x86": {}},
        "entropy_change": {"x64": {}, "x86": {}},
        "entropy_variance": {"x64": {}, "x86": {}},
        "cosine_similarity": {"x64": {}, "x86": {}},
        "asm_cosine_similarity": {"x64": {}, "x86": {}},  # New metric
        "length": {"x64": {}, "x86": {}}
    }
    
    # Process mutations
    for technique in CATEGORIES:
        for arch in ["x64", "x86"]:
            tech_files = []
            
            # Find files for this technique and architecture
            for root, dirs, files in os.walk("mutations"):
                if arch in root:
                    for file in files:
                        if technique == "eq_nop_pii" and "eq_nop_pii" in file:
                            tech_files.append(os.path.join(root, file))
                        elif technique == "eq_nop_bcf" and "eq_nop_bcf" in file:
                            tech_files.append(os.path.join(root, file))
                        elif technique == "eq_nop_ibp" and "eq_nop_ibp" in file:
                            tech_files.append(os.path.join(root, file))
                        elif technique == "eq_nop" and "nop_eq" in file:
                            tech_files.append(os.path.join(root, file))
                        elif technique == "eq_pii" and "eq_pii" in file:
                            tech_files.append(os.path.join(root, file))
                        elif technique == "eq_bcf" and "eq_bcf" in file:
                            tech_files.append(os.path.join(root, file))
                        elif technique == "eq_ibp" and "eq_ibp" in file:
                            tech_files.append(os.path.join(root, file))
                        elif technique == "nop_pii" and "nop_pii" in file and "eq_nop_pii" not in file:
                            tech_files.append(os.path.join(root, file))
                        elif technique == "nop_bcf" and "nop_bcf" in file and "eq_nop_bcf" not in file:
                            tech_files.append(os.path.join(root, file))
                        elif technique == "nop_ibp" and "nop_ibp" in file and "eq_nop_ibp" not in file:
                            tech_files.append(os.path.join(root, file))
                        elif technique in ["nop", "eq", "bcf", "ibp", "pii"]:
                            others = {"nop", "eq", "bcf", "ibp", "pii"} - {technique}
                            if has_tag(file, technique) and not any(has_tag(file, t) for t in others):
                                tech_files.append(os.path.join(root, file))

            
            # Calculate metrics for this technique
            if tech_files:
                total_entropy = 0
                total_variance = 0
                total_length = 0
                total_cosine = 0
                total_asm_cosine = 0
                
                orig_entropy = x64_avg_entropy if arch == "x64" else x86_avg_entropy
                orig_vector = x64_avg_vector if arch == "x64" else x86_avg_vector
                orig_asm = x64_orig_asm_combined if arch == "x64" else x86_orig_asm_combined
                is_x64 = (arch == "x64")
                
                # Collect ASM for all files of this technique
                technique_asm_list = []
                
                for file in tech_files:
                    # Basic metrics
                    entropy = calculate_entropy(file)
                    total_entropy += entropy
                    variance, _ = calculate_entropy_variance(file)
                    total_variance += variance
                    total_length += os.path.getsize(file)
                    
                    # Byte-level cosine similarity
                    file_vector = get_byte_frequency_vector(file)
                    total_cosine += cosine_similarity(orig_vector, file_vector)
                    
                    # Disassemble for ASM analysis
                    try:
                        asm_code = disassemble_file(file, is_x64=is_x64)
                        technique_asm_list.append(asm_code)
                    except Exception as e:
                        print(f"Warning: Failed to disassemble {file}: {e}")
                        technique_asm_list.append("")
                
                # Combine all ASM for this technique and calculate similarity
                technique_asm_combined = '\n'.join(technique_asm_list)
                
                # Calculate ASM-level cosine similarity
                try:
                    asm_similarity = cosine_similarity_on_asm(orig_asm, technique_asm_combined)
                    total_asm_cosine = asm_similarity
                except Exception as e:
                    print(f"Warning: Failed to calculate ASM similarity for {arch} {technique}: {e}")
                    total_asm_cosine = 0
                
                n_files = len(tech_files)
                avg_entropy = total_entropy / n_files
                
                results["entropy"][arch][technique] = avg_entropy
                results["entropy_change"][arch][technique] = calculate_entropy_change_percentage(avg_entropy, orig_entropy)
                results["entropy_variance"][arch][technique] = total_variance / n_files
                results["length"][arch][technique] = total_length / n_files
                results["cosine_similarity"][arch][technique] = total_cosine / n_files
                results["asm_cosine_similarity"][arch][technique] = total_asm_cosine  # Already averaged
                
                print(f"{arch} {technique}: {n_files} files processed")
            else:
                # Set defaults if no files found
                results["entropy"][arch][technique] = 0
                results["entropy_change"][arch][technique] = 0
                results["entropy_variance"][arch][technique] = 0
                results["length"][arch][technique] = 0
                results["cosine_similarity"][arch][technique] = 0
                results["asm_cosine_similarity"][arch][technique] = 0
    
    # Print summary statistics
    print("\n=== ANALYSIS RESULTS ===")
    for metric in ["entropy", "entropy_change", "entropy_variance", "cosine_similarity", "asm_cosine_similarity", "length"]:
        print(f"\n{metric.upper()}:")
        for arch in ["x64", "x86"]:
            print(f"  {arch}:")
            for tech in CATEGORIES:
                value = results[metric][arch][tech]
                if metric == "length":
                    print(f"    {tech}: {value:.0f}")
                elif metric == "entropy_change":
                    print(f"    {tech}: {value:+.1f}%")  # Show + or - sign
                else:
                    print(f"    {tech}: {value:.3f}")
    
    # Generate individual plots
    plot_metric(
        results["entropy"], 
        "entropy",
        "Average Shannon Entropy (bits)", 
        "Binary Entropy Comparison (x86 vs x64)",
        "entropy_comparison.png",
        orig64=x64_avg_entropy,
        orig86=x86_avg_entropy
    )
    
    plot_metric(
        results["entropy_change"],
        "entropy_change", 
        "Delta Entropy (%)", 
        "Delta Entropy (x86 vs x64)",
        "entropy_change_comparison.png",
        orig64=0,  # Baseline is 0% for change
        orig86=0
    )
    
    # plot_metric(
    #     results["entropy_variance"],
    #     "entropy_variance", 
    #     "Entropy Variance", 
    #     "Entropy Distribution Variance (x86 vs x64)",
    #     "entropy_variance_comparison.png",
    #     orig64=x64_avg_variance,
    #     orig86=x86_avg_variance
    # )
    
    # plot_metric(
    #     results["cosine_similarity"],
    #     "cosine_similarity", 
    #     "Cosine Similarity Score", 
    #     "Byte-level Cosine Similarity to Original (x86 vs x64)",
    #     "byte_cosine_similarity_comparison.png",
    #     orig64=1.0,  # Original compared to itself = 1.0
    #     orig86=1.0
    # )
    
    plot_metric(
        results["asm_cosine_similarity"],
        "asm_cosine_similarity", 
        "Cosine Similarity Score", 
        "Assembly-level Cosine Similarity to Original (x86 vs x64)",
        "asm_cosine_similarity_comparison.png",
        orig64=1.0,  # Original compared to itself = 1.0
        orig86=1.0
    )
    
    plot_metric(
        results["length"],
        "length", 
        "Average File Size (bytes)", 
        "Binary File Size Comparison (x86 vs x64)",
        "length_comparison.png",
        orig64=x64_avg_len,
        orig86=x86_avg_len
    )
    
    # Generate combined plot
    plot_combined_metrics(
        results["entropy"],
        results["entropy_change"], 
        results["cosine_similarity"],
        results["asm_cosine_similarity"],
        results["length"],
        results["entropy_variance"],
        x64_avg_entropy, x86_avg_entropy,
        x64_avg_variance, x86_avg_variance,
        x64_avg_len, x86_avg_len
    )
    
    print("\n✅ All plots have been generated successfully!")
    print("Generated files:")
    print("  - entropy_comparison.png")
    print("  - entropy_change_comparison.png")
    print("  - entropy_variance_comparison.png")
    print("  - byte_cosine_similarity_comparison.png")
    print("  - asm_cosine_similarity_comparison.png")
    print("  - length_comparison.png")
    print("  - combined_analysis.png")