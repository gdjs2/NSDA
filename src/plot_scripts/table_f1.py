import json
import re
import csv
import numpy as np
from pathlib import Path
from argparse import ArgumentParser

def get_subset_name(dataset, binary):
    if dataset == "arm32_coreutils":
        return "Coreutils - ARM32"
    if dataset == "mips_coreutils":
        return "Coreutils - MIPS"
    if dataset == "arm32_coreutils_llvm":
        return "Coreutils - ARM32 - LLVM"
    if dataset == "mips_coreutils_llvm":
        return "Coreutils - MIPS - LLVM"
    
    if dataset == "Loadstar":
        ns1_pattern = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}\.PRG$')
        ns2_pattern = re.compile(r'^\d{1,3}(?:_[A-Za-z0-9]+)?\.PRG$')
        ns3_pattern = re.compile(r'^[A-Za-z0-9_]+\.app$')
        
        if ns1_pattern.match(binary):
            return "PLC - NS1"
        elif ns2_pattern.match(binary):
            return "PLC - NS2"
        elif ns3_pattern.match(binary):
            return "PLC - NS3"
    return None

def calculate_f1(p, r):
    return 2 * (p * r) / (p + r) if (p + r) > 0 else 0.0

if __name__ == '__main__':
    args = ArgumentParser()
    args.add_argument("--results", type=str, required=True, help="Path to results JSON")
    args = args.parse_args()

    with open(args.results, "r") as f:
        results = json.load(f)

    # Specific rows and columns order
    rows = ["Coreutils - ARM32", "Coreutils - MIPS", "Coreutils - ARM32 - LLVM", "Coreutils - MIPS - LLVM", "PLC - NS1", "PLC - NS2", "PLC - NS3"]
    cols = ["Ghidra", "Ddisasm", "Loadstar", "NSDA", "ProbNSDA"]
    
    # Store lists of metrics: table_stats[row][col] = {"p": [], "r": [], "f1": []}
    table_stats = {row: {col: {"p": [], "r": [], "f1": []} for col in cols} for row in rows}

    # 1. Parse and Aggregate Data
    for dataset, tools_dict in results.items():
        for tool, binaries_dict in tools_dict.items():
            if tool not in cols:
                continue
                
            for binary, res_obj in binaries_dict.items():
                row_name = get_subset_name(dataset, binary)
                if row_name in rows:
                    p, r = res_obj[0], res_obj[1]
                    f1 = calculate_f1(p, r)
                    table_stats[row_name][tool]["p"].append(p)
                    table_stats[row_name][tool]["r"].append(r)
                    table_stats[row_name][tool]["f1"].append(f1)

    # 2. Write to CSV
    output_file = "nsda_performance_metrics.csv"
    with open(output_file, mode='w', newline='') as f:
        writer = csv.writer(f)
        
        # Create Header Row: [Dataset, Ghidra_P, Ghidra_R, Ghidra_F1, Ddisasm_P, ...]
        header = ["Dataset"]
        for col in cols:
            header.extend([f"{col}_Precision", f"{col}_Recall", f"{col}_F1"])
        writer.writerow(header)

        # Create Data Rows
        for row_name in rows:
            csv_row = [row_name]
            for col_name in cols:
                data = table_stats[row_name][col_name]
                if data["p"]:
                    avg_p = np.mean(data["p"])
                    avg_r = np.mean(data["r"])
                    avg_f1 = np.mean(data["f1"])
                    csv_row.extend([round(avg_p, 4), round(avg_r, 4), round(avg_f1, 4)])
                else:
                    csv_row.extend(["N/A", "N/A", "N/A"])
            writer.writerow(csv_row)

    print(f"Performance table successfully saved to {output_file}")