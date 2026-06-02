import sys
import rich
import subprocess

from pathlib import Path

CONFIGS_DIR = "./configs"
EXP_CONFIGS = {
    0: "demo.toml",
    1: "main.toml",
    2: "main-12.toml",
    3: "chromium-pe-x64.toml"
}

def parse_args():
    import argparse
    parser = argparse.ArgumentParser(description='Docker entrypoint for NSDA-AE')
    
    subparser = parser.add_subparsers(
        dest="action", 
        required=True, 
        help="Action to perform: 'exp' for running experiments, 'show' for showing results"
    )

    exp_parser = subparser.add_parser('exp', help='Run experiments')
    exp_parser.add_argument('exp_id', type=int, help='Experiment ID to run')

    show_parser = subparser.add_parser('show', help='Show results')
    show_parser.add_argument('exp_id', type=int, help='Experiment ID to show results for')
    show_parser.add_argument('result_file', type=str, help='Path to the result file to show')

    args = parser.parse_args()
    return args

def run_experiment(exp_id: int) -> str | None:
    result_file = f"exp_{exp_id}_results.json"
    config_file = EXP_CONFIGS.get(exp_id)
    if not config_file:
        rich.print(f"[red]Error:[/red] Invalid experiment ID: {exp_id}")
        return None
    config_path = Path(CONFIGS_DIR) / config_file
    if not config_path.exists():
        rich.print(f"[red]Error:[/red] Config file not found: {config_path}")
        return None
    rich.print(f"Running experiment {exp_id} with config: {config_path}")

    try:
        commands = [sys.executable, "./src/cli.py", "--config", str(config_path), "--result-file", result_file]
        result = subprocess.run(commands, check=True)

    except Exception as e:
        rich.print(f"[red]Error running experiment:[/red] {e}")
        return None

    return result_file

def show_average_table(result_file: str):
    import json
    import re
    import numpy as np
    from rich.table import Table
    from rich.console import Console
    from rich import box

    with open(result_file, 'r') as f:
        results = json.load(f)

    def get_subset_name(dataset: str, binary: str):
        if dataset == "arm32_coreutils":
            return "Coreutils - ARM32"
        if dataset == "mips_coreutils":
            return "Coreutils - MIPS"
        if dataset == "arm32_coreutils_llvm":
            return "Coreutils - ARM32 - LLVM"
        if dataset == "mips_coreutils_llvm":
            return "Coreutils - MIPS - LLVM"
        if dataset == "openssl_x64":
            return "OpenSSL - x64"
        if dataset == "loadstar":
            ns1 = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}\.PRG$')
            ns2 = re.compile(r'^\d{1,3}(?:_[A-Za-z0-9]+)?\.PRG$')
            ns3 = re.compile(r'^[A-Za-z0-9_]+\.app$')
            if ns1.match(binary):
                return "PLC - NS1"
            elif ns2.match(binary):
                return "PLC - NS2"
            elif ns3.match(binary):
                return "PLC - NS3"
        return None

    def f1(p, r):
        return 2 * p * r / (p + r) if (p + r) > 0 else 0.0

    rows_order = [
        "Coreutils - ARM32", "Coreutils - MIPS",
        "Coreutils - ARM32 - LLVM", "Coreutils - MIPS - LLVM",
        "OpenSSL - x64",
        "PLC - NS1", "PLC - NS2", "PLC - NS3",
    ]
    cols = ["ghidra", "ddisasm", "loadstar", "nsda", "probnsda"]

    # Aggregate per (subset, tool)
    stats = {row: {col: {"p": [], "r": [], "f1": []} for col in cols} for row in rows_order}

    for dataset, tools_dict in results.items():
        for tool, binaries_dict in tools_dict.items():
            if tool not in cols:
                continue
            for binary, res in binaries_dict.items():
                subset = get_subset_name(dataset, binary)
                if subset is None:
                    continue
                p, r = res[0], res[1]
                stats[subset][tool]["p"].append(p)
                stats[subset][tool]["r"].append(r)
                stats[subset][tool]["f1"].append(f1(p, r))

    # Only show tools and rows that have at least one data point
    active_cols = [c for c in cols if any(stats[row][c]["p"] for row in rows_order)]
    active_rows = [row for row in rows_order if any(stats[row][c]["p"] for c in active_cols)]

    # Build rich table
    console = Console()
    table = Table(
        title=f"Average Performance — {Path(result_file).name}",
        box=box.SIMPLE_HEAD,
        show_lines=True,
    )
    table.add_column("Dataset", style="bold cyan", no_wrap=True)
    for col in active_cols:
        label = col.upper()
        table.add_column(f"{label}\nPrec",   justify="right", style="green")
        table.add_column(f"{label}\nRecall", justify="right", style="yellow")
        table.add_column(f"{label}\nF1",     justify="right", style="magenta")

    for row_name in active_rows:
        cells: list[str] = [row_name]
        for col in active_cols:
            data = stats[row_name][col]
            if data["p"]:
                avg_p  = np.mean(data["p"])
                avg_r  = np.mean(data["r"])
                avg_f1 = np.mean(data["f1"])
                cells += [f"{avg_p:.4f}", f"{avg_r:.4f}", f"{avg_f1:.4f}"]
            else:
                cells += ["—", "—", "—"]
        table.add_row(*cells)

    console.print(table)


def save_efficiency_plot(exp_id: int, result_file: str):
    import json
    import math
    import re
    import numpy as np
    import matplotlib.pyplot as plt

    datasets_home = Path("./Datasets")
    coreutils_home = datasets_home / "coreutils"
    loadstar_home = datasets_home / "Loadstar"
    openssl_x64_home = datasets_home / "OpenSSL-x64"

    def get_method_results(dataset_results: dict, method_name: str):
        if method_name in dataset_results:
            return dataset_results[method_name]
        target = method_name.lower()
        for key, value in dataset_results.items():
            if key.lower() == target:
                return value
        return None

    def get_file_size(dataset: str, binary: str) -> int:
        dataset_key = dataset.lower()
        if dataset_key == "arm32_coreutils":
            binary_dir = coreutils_home / "arm32-gcc" / "stripped" / "usr" / "local" / "bin"
        elif dataset_key == "mips_coreutils":
            binary_dir = coreutils_home / "mips-gcc" / "stripped" / "usr" / "local" / "bin"
        elif dataset_key == "arm32_coreutils_llvm":
            binary_dir = coreutils_home / "arm32-llvm" / "stripped" / "usr" / "local" / "bin"
        elif dataset_key == "mips_coreutils_llvm":
            binary_dir = coreutils_home / "mips-llvm" / "stripped" / "usr" / "local" / "bin"
        elif dataset_key == "loadstar":
            ns1_pattern = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}\.PRG$')
            ns2_pattern = re.compile(r'^\d{1,3}(?:_[A-Za-z0-9]+)?\.PRG$')
            ns3_pattern = re.compile(r'^[A-Za-z0-9_]+\.app$')
            if ns1_pattern.match(binary):
                binary_dir = loadstar_home / "Dataset" / "NS_1" / "bins"
            elif ns2_pattern.match(binary):
                binary_dir = loadstar_home / "Dataset" / "NS_2" / "bins"
            elif ns3_pattern.match(binary):
                binary_dir = loadstar_home / "Dataset" / "NS_3" / "bins"
            else:
                raise ValueError(f"Unknown Loadstar binary pattern: {binary}")
        elif dataset_key == "openssl_x64":
            binary_dir = openssl_x64_home / "bins"
        else:
            raise ValueError(f"Unknown dataset: {dataset}")

        binary_path = binary_dir / binary
        if not binary_path.exists():
            raise FileNotFoundError(f"Binary file {binary_path} does not exist")
        return int(binary_path.stat().st_size)

    def format_size(size_bytes: float) -> str:
        if size_bytes == 0:
            return "0B"
        size_name = ("B", "KB", "MB", "GB")
        i = int(math.floor(math.log(size_bytes, 1024)))
        p = math.pow(1024, i)
        s = round(size_bytes / p, 1)
        return f"{s}{size_name[i]}"

    def get_target_key(dataset: str, binary: str):
        dataset_key = dataset.lower()
        if dataset_key == "arm32_coreutils":
            return "Coreutils - ARM32 - gcc"
        if dataset_key == "mips_coreutils":
            return "Coreutils - MIPS - gcc"
        if dataset_key == "arm32_coreutils_llvm":
            return "Coreutils - ARM32 - LLVM"
        if dataset_key == "mips_coreutils_llvm":
            return "Coreutils - MIPS - LLVM"
        if dataset_key == "openssl_x64":
            return "OpenSSL - x64"
        if dataset_key == "loadstar":
            return "Loadstar"
        return None

    with open(result_file, "r") as f:
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

    for dataset, dataset_results in results.items():
        dataset_result_nsda = get_method_results(dataset_results, "NSDA")
        if not isinstance(dataset_result_nsda, dict):
            continue

        for binary, res in dataset_result_nsda.items():
            if not isinstance(res, list) or len(res) < 5:
                continue
            target_key = get_target_key(dataset, binary)
            if target_key not in raw_plot_data:
                continue

            pre, train, post = float(res[2]), float(res[3]), float(res[4])
            size = get_file_size(dataset, binary)
            raw_plot_data[target_key].append({
                "size": size,
                "pre": pre,
                "train": train,
                "post": post,
            })

    num_bins = 12
    final_plot_data = {}
    for key in plot_order:
        entries = raw_plot_data[key]
        if not entries:
            continue
        entries.sort(key=lambda x: x["size"])
        chunks = np.array_split(entries, min(num_bins, len(entries)))
        aggregated = []
        for chunk in chunks:
            if len(chunk) == 0:
                continue
            aggregated.append({
                "avg_size": np.mean([e["size"] for e in chunk]),
                "avg_pre": np.mean([e["pre"] for e in chunk]),
                "avg_train": np.mean([e["train"] for e in chunk]),
                "avg_post": np.mean([e["post"] for e in chunk]),
            })
        final_plot_data[key] = aggregated

    if not final_plot_data:
        rich.print("[yellow]No NSDA timing data found for efficiency plotting.[/yellow]")
        return

    num_plots = len(final_plot_data)
    fig, axes = plt.subplots(1, num_plots, figsize=(4.2 * num_plots, 3.5), layout="constrained")
    axes_list = axes if num_plots > 1 else [axes]

    for idx, title in enumerate(final_plot_data.keys()):
        ax = axes_list[idx]
        entries = final_plot_data[title]
        labels = [format_size(e["avg_size"]) for e in entries]
        pre = np.array([e["avg_pre"] for e in entries])
        train = np.array([e["avg_train"] for e in entries])
        post = np.array([e["avg_post"] for e in entries])

        x = np.arange(len(labels))
        width = 0.8
        ax.bar(x, pre, width, label="Pre-processing", color="#3498db", edgecolor="white", linewidth=0.3)
        ax.bar(x, train, width, bottom=pre, label="Training", color="#e67e22", edgecolor="white", linewidth=0.3)
        ax.bar(x, post, width, bottom=pre + train, label="Post-processing", color="#2ecc71", edgecolor="white", linewidth=0.3)

        ax.set_title(title, fontsize=11, fontweight="bold")
        ax.set_ylabel("Avg Time (s)", fontsize=9)
        ax.set_xticks(x)
        ax.set_xticklabels(labels, rotation=45, ha="right", fontsize=8)
        ax.grid(axis="y", linestyle="--", alpha=0.3)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)

    handles, labels = axes_list[0].get_legend_handles_labels()
    fig.legend(handles, labels, loc="upper center", ncol=3, bbox_to_anchor=(0.5, 1.12), fontsize=10)

    output_path = Path("./eval_results") / f"exp_{exp_id}_efficiency_plot.pdf"
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output_path, dpi=300, bbox_inches="tight")
    plt.close(fig)
    rich.print(f"[green]Saved efficiency plot:[/green] {output_path}")

def show_results(exp_id: int, result_file: str):
    if exp_id not in EXP_CONFIGS:
        rich.print(f"[red]Error:[/red] Invalid experiment ID: {exp_id}")
        return
    if not Path(result_file).exists():
        rich.print(f"[red]Error:[/red] Result file not found: {result_file}")
        return
    rich.print(f"Showing results for experiment {exp_id} from file: {result_file}")
    show_average_table(result_file)
    save_efficiency_plot(exp_id, result_file)


def main():
    args = parse_args()

    action = args.action
    if action == 'exp':
        exp_id = args.exp_id
        run_experiment(exp_id)

    if action == 'show':
        exp_id = args.exp_id
        result_file = args.result_file
        show_results(exp_id, result_file)


if __name__ == '__main__':
    main()