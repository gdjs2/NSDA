import re
import json
import argparse

from pathlib import Path
from loguru import logger

if __name__ == "__main__":
    args = argparse.ArgumentParser()
    args.add_argument("-f", "--file", type=str, required=True, help="Path to the results file.")
    parsed_args = args.parse_args()

    result_path = Path(parsed_args.file)
    if not result_path.exists():
        logger.error(f"Results file {result_path} does not exist.")
        exit(1)
    
    ns1_pattern = re.compile(r'^\d{1,3}(?:\.\d{1,3}){3}\.PRG$')
    ns2_pattern = re.compile(r'^\d{1,3}(?:_[A-Za-z0-9]+)?\.PRG$')
    ns3_pattern = re.compile(r'^[A-Za-z0-9_]+\.app$')

    ns1_code_precisions = []
    ns1_code_recalls = []
    ns2_code_precisions = []
    ns2_code_recalls = []
    ns3_code_precisions = []
    ns3_code_recalls = []

    ns1_data_precisions = []
    ns1_data_recalls = []
    ns2_data_precisions = []
    ns2_data_recalls = []
    ns3_data_precisions = []
    ns3_data_recalls = []

    with open(result_path, "r") as f:
        results = json.load(f)
    for dataset_name, dataset_results in results.items():
        for bin_name, metrics in dataset_results.items():
            if ns1_pattern.match(bin_name):
                ns1_code_precisions.append(metrics[0])
                ns1_code_recalls.append(metrics[1])
                ns1_data_precisions.append(metrics[2])
                ns1_data_recalls.append(metrics[3])
            elif ns2_pattern.match(bin_name):
                ns2_code_precisions.append(metrics[0])
                ns2_code_recalls.append(metrics[1])
                ns2_data_precisions.append(metrics[2])
                ns2_data_recalls.append(metrics[3])
            elif ns3_pattern.match(bin_name):
                ns3_code_precisions.append(metrics[0])
                ns3_code_recalls.append(metrics[1])
                ns3_data_precisions.append(metrics[2])
                ns3_data_recalls.append(metrics[3])
    
    ns1_avg_code_precision = sum(ns1_code_precisions) / len(ns1_code_precisions) if ns1_code_precisions else 0.0
    ns1_avg_code_recall = sum(ns1_code_recalls) / len(ns1_code_recalls) if ns1_code_recalls else 0.0
    ns2_avg_code_precision = sum(ns2_code_precisions) / len(ns2_code_precisions) if ns2_code_precisions else 0.0
    ns2_avg_code_recall = sum(ns2_code_recalls) / len(ns2_code_recalls) if ns2_code_recalls else 0.0
    ns3_avg_code_precision = sum(ns3_code_precisions) / len(ns3_code_precisions) if ns3_code_precisions else 0.0
    ns3_avg_code_recall = sum(ns3_code_recalls) / len(ns3_code_recalls) if ns3_code_recalls else 0.0

    ns1_avg_data_precision = sum(ns1_data_precisions) / len(ns1_data_precisions) if ns1_data_precisions else 0.0
    ns1_avg_data_recall = sum(ns1_data_recalls) / len(ns1_data_recalls) if ns1_data_recalls else 0.0
    ns2_avg_data_precision = sum(ns2_data_precisions) / len(ns2_data_precisions) if ns2_data_precisions else 0.0
    ns2_avg_data_recall = sum(ns2_data_recalls) / len(ns2_data_recalls) if ns2_data_recalls else 0.0
    ns3_avg_data_precision = sum(ns3_data_precisions) / len(ns3_data_precisions) if ns3_data_precisions else 0.0
    ns3_avg_data_recall = sum(ns3_data_recalls) / len(ns3_data_recalls) if ns3_data_recalls else 0.0

    logger.info(f"NS1 - Average Code Precision: {ns1_avg_code_precision:.4f}, Average Code Recall: {ns1_avg_code_recall:.4f}")
    logger.info(f"NS1 - Average Data Precision: {ns1_avg_data_precision:.4f}, Average Data Recall: {ns1_avg_data_recall:.4f}")
    logger.info(f"NS2 - Average Code Precision: {ns2_avg_code_precision:.4f}, Average Code Recall: {ns2_avg_code_recall:.4f}")
    logger.info(f"NS2 - Average Data Precision: {ns2_avg_data_precision:.4f}, Average Data Recall: {ns2_avg_data_recall:.4f}")
    logger.info(f"NS3 - Average Code Precision: {ns3_avg_code_precision:.4f}, Average Code Recall: {ns3_avg_code_recall:.4f}")
    logger.info(f"NS3 - Average Data Precision: {ns3_avg_data_precision:.4f}, Average Data Recall: {ns3_avg_data_recall:.4f}")

