import json
import re
import matplotlib.pyplot as plt
from collections import defaultdict

# ------------------------------
# Load Data
# ------------------------------
JSON_FILE = "/home/zhaoqi.xiao/Projects/NSDA/eval_results/20251207_081707.json"

with open(JSON_FILE, "r") as f:
    data = json.load(f)

# ------------------------------
# Regex Patterns
# ------------------------------
ns1_pattern = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}\.PRG$')
ns2_pattern = re.compile(r'^\d{1,3}(?:_[A-Za-z0-9]+)?\.PRG$')
ns3_pattern = re.compile(r'^[A-Za-z0-9_]+\.app$')

def classify_subset(filename):
    if ns1_pattern.match(filename): return "NS1"
    if ns2_pattern.match(filename): return "NS2"
    if ns3_pattern.match(filename): return "NS3"
    return "Unknown"

# ------------------------------
# Data Structure
# ------------------------------
metrics = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))

for dataset, tools in data.items():
    for tool, items in tools.items():
        for fname, vals in items.items():
            p, r = vals[0], vals[1]
            subset = classify_subset(fname) if dataset == "Loadstar" else "default"
            metrics[dataset][subset][tool].append((p, r, fname))

# ------------------------------
# F1
# ------------------------------
def f1(p, r):
    return 0.0 if (p + r == 0) else 2 * p * r / (p + r)

# ------------------------------
# Beautiful Color Palette
# ------------------------------
colors = {
    "Ghidra":   "#4E79A7",  # Blue
    "NSDA":     "#59A14F",  # Green
    "Loadstar": "#E15759",  # Red
}

# ------------------------------
# Plotting
# ------------------------------
datasets = [(d, s) for d in metrics for s in metrics[d]]
n = len(datasets)

fig, axes = plt.subplots(n, 3, figsize=(20, 5 * n))
axes = axes.reshape(n, 3)

for row, (dataset, subset) in enumerate(datasets):
    subset_data = metrics[dataset][subset]

    for method, pts in subset_data.items():
        precs = [p for p, r, f in pts]
        recs = [r for p, r, f in pts]
        f1s  = [f1(p, r) for p, r, f in pts]

        avg_p = sum(precs) / len(precs)
        avg_r = sum(recs) / len(recs)
        avg_f = sum(f1s) / len(f1s)

        x = range(len(pts))
        color = colors.get(method, "black")

        # ----- Main curves -----
        axes[row, 0].plot(x, precs, label=f"{method} (avg={avg_p:.4f})",
                          color=color, linewidth=2)
        axes[row, 1].plot(x, recs, label=f"{method} (avg={avg_r:.4f})",
                          color=color, linewidth=2)
        axes[row, 2].plot(x, f1s,  label=f"{method} (avg={avg_f:.4f})",
                          color=color, linewidth=2)

        # ----- Horizontal average lines -----
        # Precision
        axes[row, 0].axhline(avg_p, linestyle="--", linewidth=2,
                             color=color, alpha=0.6,
                             label=f"{method} avg line")

        # Recall
        axes[row, 1].axhline(avg_r, linestyle="--", linewidth=2,
                             color=color, alpha=0.6,
                             label=f"{method} avg line")

        # F1
        axes[row, 2].axhline(avg_f, linestyle="--", linewidth=2,
                             color=color, alpha=0.6,
                             label=f"{method} avg line")

    # Titles
    axes[row, 0].set_title(f"{dataset} – {subset} : Precision")
    axes[row, 1].set_title(f"{dataset} – {subset} : Recall")
    axes[row, 2].set_title(f"{dataset} – {subset} : F1-score")

    # Labels for each column
    for col in range(3):
        axes[row, col].set_xlabel("Datapoint index (JSON order)")
        axes[row, col].grid(True, linestyle="--", alpha=0.4)
        axes[row, col].legend(fontsize=8)

    axes[row, 0].set_ylabel("Precision")
    axes[row, 1].set_ylabel("Recall")
    axes[row, 2].set_ylabel("F1")

plt.tight_layout()
plt.savefig("evaluation_plots.png", dpi=300)
