import re
import json
import math
import numpy as np
from pathlib import Path
import matplotlib.pyplot as plt
from argparse import ArgumentParser

DATASET_HOME = Path(__file__).parent.parent.parent / "Datasets"
COREUTILS_ARM_HOME = DATASET_HOME / "coreutils-arm"
COREUTILS_MIPS_HOME = DATASET_HOME / "coreutils-mips"
COREUTILS_ARM_LLVM_HOME = DATASET_HOME / "coreutils-arm-llvm"
COREUTILS_MIPS_LLVM_HOME = DATASET_HOME / "coreutils-mips-llvm"
LOADSTAR_HOME = DATASET_HOME / "Loadstar"
OPENSSL_X64_HOME = DATASET_HOME / "OpenSSL-x64"


def get_method_results(dataset_results, method_name):
    if method_name in dataset_results:
        return dataset_results[method_name]

    target = method_name.lower()
    for key, value in dataset_results.items():
        if key.lower() == target:
            return value
    return None

def get_file_size(dataset, binary):
    if dataset == "arm32_coreutils":
        binary_dir = COREUTILS_ARM_HOME / "build-output-armv4" / "stripped" / "usr" / "local" / "bin"
    elif dataset == "mips_coreutils":
        binary_dir = COREUTILS_MIPS_HOME / "build-output-mips" / "stripped" / "usr" / "local" / "bin"
    elif dataset == "arm32_coreutils_llvm":
        binary_dir = COREUTILS_ARM_LLVM_HOME / "build-output-armv4" / "stripped" / "usr" / "local" / "bin"
    elif dataset == "mips_coreutils_llvm":
        binary_dir = COREUTILS_MIPS_LLVM_HOME / "build-output-mips" / "stripped" / "usr" / "local" / "bin"
    elif dataset == "Loadstar":
        ns1_pattern = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}\.PRG$')
        ns2_pattern = re.compile(r'^\d{1,3}(?:_[A-Za-z0-9]+)?\.PRG$')
        ns3_pattern = re.compile(r'^[A-Za-z0-9_]+\.app$')
        if ns1_pattern.match(binary):
            binary_dir = LOADSTAR_HOME / "Dataset" / "NS_1" / "bins"
        elif ns2_pattern.match(binary):
            binary_dir = LOADSTAR_HOME / "Dataset" / "NS_2" / "bins"
        elif ns3_pattern.match(binary):
            binary_dir = LOADSTAR_HOME / "Dataset" / "NS_3" / "bins"
    elif dataset == "openssl_x64":
        binary_dir = OPENSSL_X64_HOME / "bins"
    else:
        raise ValueError(f"Unknown dataset: {dataset}")
    binary_path = binary_dir / binary
    if not binary_path.exists():
        raise FileNotFoundError(f"Binary file {binary_path} does not exist.")
    return binary_path.stat().st_size
    
def format_size(size_bytes):
    if size_bytes == 0: return "0B"
    size_name = ("B", "KB", "MB", "GB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    p = math.pow(1024, i)
    s = round(size_bytes / p, 1)
    return f"{s}{size_name[i]}"

def get_target_key(dataset, binary):
    """Maps dataset and binary to the specific ordered titles requested."""
    if dataset == "arm32_coreutils":
        return "Coreutils - ARM32 - gcc"
    if dataset == "mips_coreutils":
        return "Coreutils - MIPS - gcc"
    if dataset == "arm32_coreutils_llvm":
        return "Coreutils - ARM32 - LLVM"
    if dataset == "mips_coreutils_llvm":
        return "Coreutils - MIPS - LLVM"
    
    if dataset == "Loadstar":
        # ns1_pattern = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}\.PRG$')
        # ns2_pattern = re.compile(r'^\d{1,3}(?:_[A-Za-z0-9]+)?\.PRG$')
        # ns3_pattern = re.compile(r'^[A-Za-z0-9_]+\.app$')
        
        # if ns1_pattern.match(binary):
        #     return "Loadstar NS1"
        # elif ns2_pattern.match(binary):
        #     return "Loadstar NS2"
        # elif ns3_pattern.match(binary):
        #     return "Loadstar NS3"
        return "Loadstar"
    if dataset == "openssl_x64":
        return "OpenSSL - x64"
    return None

if __name__ == '__main__':
    args = ArgumentParser()
    args.add_argument("--results", type=str, required=True, help="Path to the results directory")
    args = args.parse_args()

    results_file = Path(args.results)
    if not results_file.exists():
        print(f"Results file {results_file} does not exist.")
        exit(1)
    
    with open(results_file, "r") as f:
        results = json.load(f)

    plot_order = [
        "Coreutils - ARM32 - gcc",
        "Coreutils - MIPS - gcc",
        "Coreutils - ARM32 - LLVM",
        "Coreutils - MIPS - LLVM",
        "OpenSSL - x64",
        "Loadstar",
    ]
    raw_plot_data = {key: [] for key in plot_order}

    # 1. Collect Data and Calculate Individual Ratios
    for dataset in results:
        dataset_result_nsda = get_method_results(results[dataset], "NSDA")
        if not isinstance(dataset_result_nsda, dict):
            continue
        for binary, res in dataset_result_nsda.items():
            target_key = get_target_key(dataset, binary)
            if target_key in raw_plot_data:
                pre, train, post = res[2], res[3], res[4]
                size = int(get_file_size(dataset, binary))
                
                total_time = pre + train + post
                # Avoid division by zero if total_time is 0
                ratio = (train / total_time) if total_time > 0 else 0
                
                raw_plot_data[target_key].append({
                    'size': size, 'pre': pre, 'train': train, 'post': post, 'ratio': ratio
                })

    # 2. Terminal Output: Statistics Summary
    print("\n" + "="*60)
    print(f"{'Dataset / Subset':<20} | {'Train Min/Max (s)':<20} | {'Ratio Min/Max':<15}")
    print("-"*60)

    for key in plot_order:
        entries = raw_plot_data[key]
        if not entries:
            continue

        train_times = [e['train'] for e in entries]
        ratios = [e['ratio'] for e in entries]

        min_t, max_t = min(train_times), max(train_times)
        min_r, max_r = min(ratios), max(ratios)

        print(f"{key:<20} | {min_t:>7.2f}s / {max_t:>7.2f}s | {min_r:>6.2%} / {max_r:>6.2%}")
    
    print("="*60 + "\n")

    # 3. Aggregate Data into Bins for Plotting
    NUM_BINS = 12 
    final_plot_data = {}
    for key in plot_order:
        entries = raw_plot_data[key]
        if not entries: continue
        
        entries.sort(key=lambda x: x['size'])
        chunks = np.array_split(entries, min(NUM_BINS, len(entries)))
        aggregated = []
        for c in chunks:
            if len(c) == 0: continue
            aggregated.append({
                'avg_size': np.mean([e['size'] for e in c]),
                'avg_pre': np.mean([e['pre'] for e in c]),
                'avg_train': np.mean([e['train'] for e in c]),
                'avg_post': np.mean([e['post'] for e in c])
            })
        final_plot_data[key] = aggregated

    # 4. Setup Figure Grid (Single Line, Low Height)
    num_plots = len(final_plot_data)
    fig, axes = plt.subplots(1, num_plots, figsize=(4.2 * num_plots, 3.5), layout="constrained")
    axes_list = axes if num_plots > 1 else [axes]

    # 5. Draw Subplots
    for idx, title in enumerate(final_plot_data.keys()):
        ax = axes_list[idx]
        entries = final_plot_data[title]
        
        labels = [format_size(e['avg_size']) for e in entries]
        pre = np.array([e['avg_pre'] for e in entries])
        train = np.array([e['avg_train'] for e in entries])
        post = np.array([e['avg_post'] for e in entries])
        
        x = np.arange(len(labels))
        width = 0.8 

        ax.bar(x, pre, width, label='Pre-processing', color='#3498db', edgecolor='white', linewidth=0.3)
        ax.bar(x, train, width, bottom=pre, label='Training', color='#e67e22', edgecolor='white', linewidth=0.3)
        ax.bar(x, post, width, bottom=pre+train, label='Post-processing', color='#2ecc71', edgecolor='white', linewidth=0.3)

        ax.set_title(title, fontsize=11, fontweight='bold')
        ax.set_ylabel("Avg Time (s)", fontsize=9)
        ax.set_xticks(x)
        ax.set_xticklabels(labels, rotation=45, ha='right', fontsize=8)
        ax.grid(axis='y', linestyle='--', alpha=0.3)
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)

    handles, labels = axes_list[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc='upper center', ncol=3, bbox_to_anchor=(0.5, 1.12), fontsize=10)

    plt.savefig("efficiency_plot_new.pdf", dpi=300, bbox_inches='tight')
    print("Ordered single-line figure saved.")