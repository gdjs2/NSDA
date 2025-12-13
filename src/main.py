import sys
import pyghidra
import toml
import argparse

from pathlib import Path
from loguru import logger
from datetime import datetime
from DataLoader import DataLoader, Data
from DataLoaderRegistry import DATALOADER_REGISTRY
from EvaluatorRegistry import EVALUATOR_REGISTRY
from Evaluator import Evaluator

# open("debug.log", "w").close()
# logger.remove()
# logger.add("debug.log", level="INFO")

# logger.remove()
# logger.add(sys.stderr, level="INFO")

def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="NSDA Evaluation")
    parser.add_argument(
        "-c",
        "--config",
        type=str,
        default="config.toml",
        help="Path to the configuration TOML file."
    )
    return parser.parse_args()

def load_config(config_path: str) -> dict:
    """Load configuration from a TOML file."""
    try:
        with open(config_path, "r") as f:
            config = toml.load(f)
        logger.info(f"Configuration loaded from {config_path}.")
        return config
    except Exception as e:
        logger.error(f"Failed to load configuration from {config_path}: {e}")
        raise

def _eval_data(
    evaluator: Evaluator,
    data: Data, 
    base: int | None,
    language: str,
    args: dict,
) -> tuple[float, float, float, float, float, list[int], list[int]]:
    return evaluator.evaluate(
        binary_path=data.binary_path,
        code_set=data.code_set,
        base=base,
        language=language,
        args=args
    )

def _eval_dataset(
    evaluators: dict,
    data: dict[str, Data], 
    base: int | None,
    language: str = "ARM:LE:32:v5",
    subset: set[str] | None = None,
) -> dict[str, dict[str, tuple[float, float, float, float, float, list[int], list[int]]]]:   # [code_precision, code_recall, preprocessing_time, training_time, redisassemble_time, error_code_list, error_data_list]
    if subset is None: logger.info(f"Evaluating dataset with {len(data)} samples.")
    else: logger.info(f"Evaluating subset with {len(subset)} samples from dataset with {len(data)} samples.")
    results = {}
    for evaluator_name, evaluator_info in evaluators.items():
        evaluator = evaluator_info["cls"]
        args = evaluator_info.get("args", {})
        logger.info(f"Using evaluator: {evaluator_name} with args: {args}")
        results[evaluator_name] = {}
        for idx, (data_name, data_instance) in enumerate(data.items()):
            if subset is not None and data_name not in subset:
                logger.debug(f"Skipping sample {data_name} as it's not in the specified subset.")
                continue
            logger.info(f"Evaluating sample {idx+1}/{len(data)}: {data_name} from {data_instance.binary_path}")
            code_precision, code_recall, preprocessing_time, training_time, redisassemble_time, error_code_list, error_data_list = _eval_data(
                evaluator,
                data_instance,
                base=base,
                language=language,
                args=args
            )
            results[evaluator_name][data_name] = (code_precision, code_recall, preprocessing_time, training_time, redisassemble_time, error_code_list, error_data_list)
            logger.info(f"Sample {data_name}: Code Precision={code_precision:.5f}, Code Recall={code_recall:.5f}, Preprocessing Time={preprocessing_time:.2f}s, Training Time={training_time:.2f}s, Redisassemble Time={redisassemble_time:.2f}s")
    return results
        
def _eval_datasets(
    evaluators: dict,
    datasets: list[str], 
    datasets_config: dict,
    subset_flg: bool = False
) -> dict[str, dict[str, dict[str, tuple[float, float, float, float, float, list[int], list[int]]]]]: # [dataset_name][data_name] = (code_precision, code_recall, preprocessing_time, training_time, redisassemble_time, error_code_list, error_data_list)
    logger.info(f"Dataset to be evaluated: {datasets}")
    results = {}
    for dataset_name in datasets:
        dataset_config = datasets_config[dataset_name.lower()]
        dataset_home = dataset_config["path"]
        dataloader_name = dataset_config["loader"]
        dataloader_cls = DATALOADER_REGISTRY.get(dataloader_name)
        
        if dataloader_cls is None:
            logger.error(f"Dataloader {dataloader_name} not found in registry.")
            continue
        dataloader: DataLoader = dataloader_cls()
        data = dataloader.load(dataset_home)
        if data is None:
            logger.error(f"Failed to load data for dataset {dataset_name} using {dataloader_name}.")
            continue
        logger.debug(f"Loaded {len(data)} samples from dataset {dataset_name} using {dataloader_name}.")
        results[dataset_name] = _eval_dataset(
            evaluators,
            data, 
            base=dataset_config.get("base", None),
            language=dataset_config.get("language", None),
            subset=None if not subset_flg else set(dataset_config.get("subset", []))
        )
    return results

def dump_result(
    results: dict[str, dict[str, dict[str, tuple[float, float, float, float, float, list[int], list[int]]]]],
    result_path: str,
    dump_error_list: bool = False
):
    import json
    root = Path(result_path)
    root.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    result_file = root / f"{timestamp}.json"
    processed_result = {}

    for dataset_name, r in results.items():
        processed_result[dataset_name] = {}
        for evaluator_name, evaluator_results in r.items():
            processed_result[dataset_name][evaluator_name] = {}
            for data_name, metrics in evaluator_results.items():
                if dump_error_list:
                    error_code_list, error_data_list = metrics[-2], metrics[-1]
                    error_code_list_str = [hex(code) for code in error_code_list]
                    error_data_list_str = [hex(code) for code in error_data_list]
                    processed_result[dataset_name][evaluator_name][data_name] = (*metrics[:5], error_code_list_str, error_data_list_str)
                else:
                    processed_result[dataset_name][evaluator_name][data_name] = metrics[:5]

    with open(result_file, "w") as f:
        json.dump(processed_result, f, indent=4)
    logger.info(f"Dumped evaluation results to {result_file}.")

def config_logger(
        log_file: str | None = None, 
        log_level: str | None = None
):
    logger.remove()
    if log_level is None:
        log_level = "INFO"
    else:
        log_level = log_level.upper()
    if log_file is None or log_file == "stderr":
        logger.add(sys.stderr, level=log_level)
    elif log_file == "stdout":
        logger.add(sys.stdout, level=log_level)
    else: # files
        logger.add(log_file, level=log_level)
    return 

if __name__ == "__main__":
    ns = _parse_args()
    config = load_config(ns.config)

    config_logger(
        log_file=config["config"]["log_file"], 
        log_level=config["config"]["log_level"]
    )

    logger.info(f"Starting evaluation with config: {config}")
    logger.info(f"Evaluator: {config['config']['evaluator']}")
    logger.info(f"Evaluation type: {config['config']['eval_type']}")
    logger.info(f"Ghidra Home: {config['config']['ghidra_home']}")

    # Set Ghidra Home Env for pyghidra
    # os.environ["GHIDRA_INSTALL_DIR"] = config["config"]["ghidra_home"]
    if not pyghidra.started():
        pyghidra.start(install_dir=config["config"]["ghidra_home"])

    results = {}
    evaluators = {}
    # Load evaluators
    for evaluator_name in config["config"]["evaluator"]:
        evaluators[evaluator_name] = {
            "cls": EVALUATOR_REGISTRY[f"{evaluator_name}Evaluator"](),
            "args": config["evaluator"].get(evaluator_name.lower(), {})
        }

    logger.info(evaluators)
    if config["config"]["eval_type"] == "Dataset Evaluation":   # Wholeset evaluation
        results = _eval_datasets(
            evaluators=evaluators,
            datasets=config["config"]["datasets"],
            datasets_config=config["dataset"]
        )

    elif config["config"]["eval_type"] == "Subset Evaluation":    # Subset evaluation
        results = _eval_datasets(
            evaluators=evaluators,
            datasets=config["config"]["datasets"],
            datasets_config=config["dataset"],
            subset_flg=True
        )
    else:
        logger.error(f"Unknown evaluation type: {config['config']['eval_type']}")

    if config["config"].get("dump_json", False):
        dump_result(
            results, 
            config["config"].get("result_path", "./"),
            dump_error_list=config["config"].get("dump_error_list", False)
        )

