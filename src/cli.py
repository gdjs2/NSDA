import os
import sys
import toml
import pyghidra
import questionary

from pathlib import Path
from loguru import logger
from datetime import datetime

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.live import Live
from rich.progress import Progress
from rich.spinner import Spinner

from DataLoader import Data, DataLoader
from DataLoaderRegistry import DATALOADER_REGISTRY
from Evaluator import Evaluator
from EvaluatorRegistry import EVALUATOR_REGISTRY

DEFAULT_CONFIG_FILE = "config_default.toml"
CONFIG_FILE = "config.toml"
console = Console()

EVALUATOR_NAME_MAP = {
    "nsda": "NSDA",
    "ghidra": "Ghidra",
    "nsdaworules": "NSDAWoRules",
    "probnsda": "ProbNSDA",
    "ddisasm": "Ddisasm",
    "loadstar": "LoadStar",
}

# --- Utility Functions ---

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

def check_config():
    if not os.path.exists(CONFIG_FILE):
        console.print(f"[bold yellow]Warning: '{CONFIG_FILE}' not found. Checking for default configuration ({DEFAULT_CONFIG_FILE})...[/bold yellow]")
        if not os.path.exists(DEFAULT_CONFIG_FILE):
            console.print(f"[bold red]Error: Default configuration '{DEFAULT_CONFIG_FILE}' not found. [/bold red]")
            sys.exit(1)
        else:
            console.print(f"[bold green]Found default configuration. Copying to '{CONFIG_FILE}'...[/bold green]")
            with open(DEFAULT_CONFIG_FILE, "r") as src, open(CONFIG_FILE, "w") as dst:
                dst.write(src.read())
            console.print(f"[bold green]Default configuration copied successfully.[/bold green]")

def load_config():
    if not os.path.exists(CONFIG_FILE):
        console.print(f"[bold red]Error: '{CONFIG_FILE}' not found.[/bold red]")
        sys.exit(1)
    return toml.load(CONFIG_FILE)

def save_config(config_data):
    """Rule 1: Save back to the configuration file immediately."""
    with open(CONFIG_FILE, "w") as f:
        toml.dump(config_data, f)
    console.print(f"[italic green]  ➜ Settings saved to {CONFIG_FILE}[/italic green]")

def check_eval_type(config):
    """Check the evaluation type and enforce subset field for each dataset."""
    eval_type = config["config"].get("eval_type", "Dataset Evaluation")
    
    for _, ds_config in config.get("dataset", {}).items():
        if eval_type == "Dataset Evaluation":
            if "subset" in ds_config:
                del ds_config["subset"]
        elif eval_type == "Subset Evaluation":
            if "subset" not in ds_config:
                ds_config["subset"] = []

def format_val(key, val):
    """Helper to neatly format values (e.g., ints to hex for base addresses)."""
    if key == "base" and isinstance(val, int):
        return hex(val)
    if isinstance(val, list):
        return ", ".join(val) if val else "[]"
    return str(val)

# --- Field Editor Logic ---

def edit_field(section_dict, key, prompt_prefix):
    """Dynamically prompts for a value based on its current type."""
    val = section_dict[key]
    
    if isinstance(val, bool):
        res = questionary.confirm(f"{prompt_prefix} {key}:", default=val).ask()
        if res is not None: section_dict[key] = res
            
    elif isinstance(val, int):
        current_str = hex(val) if key == "base" else str(val)
        res = questionary.text(f"{prompt_prefix} {key} (int/hex):", default=current_str).ask()
        if res is not None:
            try:
                section_dict[key] = int(res, 0) # Handles both "10" and "0x10"
            except ValueError:
                console.print("[red]Invalid integer format.[/red]")
                
    elif isinstance(val, list):
        current_str = ", ".join(val)
        res = questionary.text(f"{prompt_prefix} {key} (comma-separated):", default=current_str).ask()
        if res is not None:
            section_dict[key] = [x.strip() for x in res.split(",") if x.strip()]
            
    else: # Default to string
        if key == "log_level":
            res = questionary.select(
                f"{prompt_prefix} {key}:", 
                choices=["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"],
                default=str(val).upper()
            ).ask()
            if res is not None: section_dict[key] = res.lower()
        else:
            res = questionary.text(f"{prompt_prefix} {key}:", default=str(val)).ask()
            if res is not None: section_dict[key] = res

# --- Submenus ---

def global_settings_menu(config):
    while True:
        c_dict = config["config"]
        keys = ["ghidra_home", "eval_type", "dump_json", "dump_error_list", "result_path", "log_file", "log_level"]
        
        choices = [questionary.Choice(f"{k} [{format_val(k, c_dict.get(k, 'N/A'))}]", value=k) for k in keys]
        choices.append(questionary.Choice("<- Back to Main Menu", value="BACK"))
        
        choice = questionary.select("Global Configurations", choices=choices).ask()
        if choice == "BACK" or choice is None: break

        if choice == "eval_type":
            res = questionary.select(
                "Select Evaluation Type:", 
                choices=["Dataset Evaluation", "Subset Evaluation"],
                default=c_dict.get("eval_type", "Dataset Evaluation")
            ).ask()
            if res:
                c_dict["eval_type"] = res
                check_eval_type(config)
        else:
            edit_field(c_dict, choice, "Set")
            
        save_config(config)

def datasets_evaluator_selection_menu(config):
    """Select the datasets and evaluators to activate."""
    c_dict = config["config"]
    
    # Get all available items from TOML tables, mapping case safely
    all_ds = list(config.get("dataset", {}).keys())
    all_ev = list(config.get("evaluator", {}).keys())
    
    # Normalize current selections to lowercase to match TOML tables
    cur_ds = [d.lower() for d in c_dict.get("datasets", [])]
    cur_ev = [e.lower() for e in c_dict.get("evaluator", [])]

    selected_ds = questionary.checkbox(
        "Select DATASET(s) to evaluate:",
        choices=[questionary.Choice(ds, checked=ds.lower() in cur_ds) for ds in all_ds],
    ).ask()
    
    if selected_ds is not None:
        c_dict["datasets"] = selected_ds
        save_config(config)

    selected_ev = questionary.checkbox(
        "Select EVALUATOR(s) to run:",
        choices=[questionary.Choice(ev, checked=ev.lower() in cur_ev) for ev in all_ev],
    ).ask()
    
    if selected_ev is not None:
        c_dict["evaluator"] = selected_ev
        save_config(config)

def configure_datasets_menu(config):
    """Datasets Configuration submenu."""
    while True:
        selected_ds = [d.lower() for d in config["config"].get("datasets", [])]
        if not selected_ds:
            console.print("[yellow]No datasets currently selected. Go back and select them first.[/yellow]")
            return

        ds_choice = questionary.select(
            "Select Dataset to Configure", 
            choices=selected_ds + [questionary.Choice("<- Back", value="BACK")]
        ).ask()
        
        if ds_choice == "BACK" or ds_choice is None: break

        # Inner loop for specific dataset
        while True:
            ds_config = config["dataset"][ds_choice]
            keys = list(ds_config.keys())
            
            choices = [questionary.Choice(f"{k} [{format_val(k, ds_config[k])}]", value=k) for k in keys]
            choices.append(questionary.Choice("<- Back", value="BACK"))
            
            field_choice = questionary.select(f"Configuring Dataset: {ds_choice}", choices=choices).ask()
            if field_choice == "BACK" or field_choice is None: break
            
            edit_field(ds_config, field_choice, f"[{ds_choice}]")
            save_config(config)

def configure_evaluators_menu(config):
    """Evaluators Configuration submenu."""
    while True:
        selected_ev = [e.lower() for e in config["config"].get("evaluator", [])]
        if not selected_ev:
            console.print("[yellow]No evaluators currently selected. Go back and select them first.[/yellow]")
            return

        ev_choice = questionary.select(
            "Select Evaluator to Configure", 
            choices=selected_ev + [questionary.Choice("<- Back", value="BACK")]
        ).ask()
        
        if ev_choice == "BACK" or ev_choice is None: break

        # Inner loop for specific evaluator
        while True:
            ev_config = config["evaluator"][ev_choice]
            keys = list(ev_config.keys())
            
            choices = [questionary.Choice(f"{k} [{format_val(k, ev_config[k])}]", value=k) for k in keys]
            choices.append(questionary.Choice("<- Back", value="BACK"))
            
            field_choice = questionary.select(f"Configuring Evaluator: {ev_choice}", choices=choices).ask()
            if field_choice == "BACK" or field_choice is None: break

            if field_choice == "keep_ghidra_prj":
                res = questionary.confirm("keep_ghidra_prj:", default=ev_config[field_choice]).ask()
                if res is not None:
                    ev_config["keep_ghidra_prj"] = res
                    if res and "keep_ghidra_prj_path" not in ev_config:
                        ev_config["keep_ghidra_prj_path"] = "./saved_ghidra_prjs"
                    elif not res and "keep_ghidra_prj_path" in ev_config:
                        del ev_config["keep_ghidra_prj_path"] # Path must be None/removed
            else:
                edit_field(ev_config, field_choice, f"[{ev_choice}]")
            
            save_config(config)

def display_summary(config):
    console.print("\n")
    table = Table(title="Final Configuration Status", show_header=True, header_style="bold green")
    table.add_column("Section", style="cyan")
    table.add_column("Key", style="magenta")
    table.add_column("Value", style="yellow")

    c_dict = config["config"]
    table.add_row("Global", "Eval Type", str(c_dict.get("eval_type")))
    table.add_row("Global", "Active Datasets", ", ".join(c_dict.get("datasets", [])))
    table.add_row("Global", "Active Evaluators", ", ".join(c_dict.get("evaluator", [])))
    
    console.print(Panel(table, expand=False, border_style="green"))
    console.print(f"[bold green]✅ Wizard Complete. Final configs saved to '{CONFIG_FILE}'.[/bold green]\n")

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
# --- Evaluation Logic ---

def _eval_data(
    evaluator: Evaluator,
    data: Data, 
    base: int | None,
    language: str,
    spinner: Spinner,
    args: dict
) -> tuple[float, float, float, float, float, list[int], list[int]]:
    return evaluator.evaluate(
        binary_path=data.binary_path,
        code_set=data.code_set,
        base=base,
        language=language,
        args=args,
        spinner=spinner
    )

def _eval_dataset(
    evaluators: dict,
    data: dict[str, Data], 
    base: int | None,
    language: str = "ARM:LE:32:v5",
    subset: set[str] | None = None,
) -> dict[str, dict[str, tuple[float, float, float, float, float, list[int], list[int]]]]:   # [code_precision, code_recall, preprocessing_time, training_time, redisassemble_time, error_code_list, error_data_list]
    if subset is None: console.print(f"[bold cyan]Evaluating dataset with {len(data)} samples.[/bold cyan]")
    else: console.print(f"[bold cyan]Evaluating subset with {len(subset)} samples from dataset with {len(data)} samples.[/bold cyan]")
    results = {}

    for evaluator_name, evaluator_info in evaluators.items():
        evaluator = evaluator_info["cls"]
        args = evaluator_info.get("args", {})
        console.print(f"[bold cyan]Using evaluator: {evaluator_name} with args: {args}[/bold cyan]")
        results[evaluator_name] = {}

        acc_precision, acc_recall= 0.0, 0.0
        cnt = 0

        progress = Progress()
        main_task = progress.add_task(f"[bold cyan]Evaluating Datasets with {evaluator_name}...[/bold cyan]", total=len(data))
        spinner = Spinner("dots", text="[bold yellow]Working...[/bold yellow]")
        render_group = Group(
            progress,
            spinner
        )

        with Live(render_group, refresh_per_second=4):
            for (data_name, data_instance) in data.items():

                avg_precision = acc_precision / cnt if cnt > 0 else 0.0
                avg_recall = acc_recall / cnt if cnt > 0 else 0.0
                avg_f1 = (2 * avg_precision * avg_recall / (avg_precision + avg_recall)) if (avg_precision + avg_recall) > 0 else 0.0
                progress.update(main_task, description=f"Evaluating {data_name} with {evaluator_name} (Avg Precision: {avg_precision:.2f}, Avg Recall: {avg_recall:.2f}, Avg F1: {avg_f1:.2f})...")

                if subset is not None and data_name not in subset:
                    progress.update(main_task, advance=1)
                    # console.print(f"[bold yellow]Skipping sample {data_name} as it's not in the specified subset.[/bold yellow]")
                    continue

                code_precision, code_recall, preprocessing_time, training_time, redisassemble_time, error_code_list, error_data_list = _eval_data(
                    evaluator,
                    data_instance,
                    base=base,
                    language=language,
                    spinner=spinner,
                    args=args
                )
                results[evaluator_name][data_name] = (code_precision, code_recall, preprocessing_time, training_time, redisassemble_time, error_code_list, error_data_list)
                # logger.info(f"Sample {data_name}: Code Precision={code_precision:.5f}, Code Recall={code_recall:.5f}, Preprocessing Time={preprocessing_time:.2f}s, Training Time={training_time:.2f}s, Redisassemble Time={redisassemble_time:.2f}s")
                acc_precision += code_precision
                acc_recall += code_recall
                cnt += 1

                progress.update(main_task, advance=1)

            
    return results

def _eval_datasets(
    evaluators: dict,
    datasets: list[str], 
    datasets_config: dict,
    subset_flg: bool = False
) -> dict[str, dict[str, dict[str, tuple[float, float, float, float, float, list[int], list[int]]]]]: # [dataset_name][data_name] = (code_precision, code_recall, preprocessing_time, training_time, redisassemble_time, error_code_list, error_data_list)
    results = {}
    for dataset_name in datasets:
        dataset_config = datasets_config[dataset_name.lower()]
        dataset_home = dataset_config["path"]
        dataloader_name = dataset_config["loader"]
        dataloader_cls = DATALOADER_REGISTRY.get(dataloader_name)
        
        if dataloader_cls is None:
            console.print(f"[bold red]Error: DataLoader '{dataloader_name}' not found for dataset '{dataset_name}'. Skipping...[/bold red]")
            continue
        dataloader: DataLoader = dataloader_cls()
        with console.status(f"[bold cyan]Loading dataset {dataset_name}...[/bold cyan]") as status:
            data = dataloader.load(dataset_home)
        if data is None:
            console.print(f"[bold red]Error: Failed to load data for dataset {dataset_name} using {dataloader_name}. Skipping...[/bold red]")
            continue
        console.print(f"[bold cyan]Loaded {len(data)} samples from dataset {dataset_name} using {dataloader_name}.[/bold cyan]")
        results[dataset_name] = _eval_dataset(
            evaluators,
            data, 
            base=dataset_config.get("base", None),
            language=dataset_config.get("language", None),
            subset=None if not subset_flg else set(dataset_config.get("subset", []))
        )
    return results

def start_evaluation(config):
    """Starts the evaluation process."""
    with console.status("[bold cyan]Starting Evaluation...[/bold cyan]") as status:
        status.update("[bold cyan]Starting PyGhidra...[/bold cyan]")
        if not pyghidra.started():
            pyghidra.start(install_dir=config["config"]["ghidra_home"])
    
        results = {}
        evaluators = {}

        # Load evaluators
        for evaluator_name in config["config"]["evaluator"]:
            status.update(f"[bold cyan]Loading Evaluators ({evaluator_name})...[/bold cyan]")
            evaluators[evaluator_name] = {
                "cls": EVALUATOR_REGISTRY[f"{EVALUATOR_NAME_MAP[evaluator_name]}Evaluator"](),
                "args": config["evaluator"].get(evaluator_name.lower(), {})
            }

    if config["config"]["eval_type"] == "Dataset Evaluation":   # Wholeset evaluation
        results = _eval_datasets(
            evaluators=evaluators,
            datasets=config["config"]["datasets"],
            datasets_config=config["dataset"],
        )
    elif config["config"]["eval_type"] == "Subset Evaluation":    # Subset evaluation
        results = _eval_datasets(
            evaluators=evaluators,
            datasets=config["config"]["datasets"],
            datasets_config=config["dataset"],
            subset_flg=True
        )
    else:
        console.print(f"[bold red]Unknown evaluation type: {config['config']['eval_type']}[/bold red]")
        return
    
    if config["config"].get("dump_json", False):
        dump_result(
            results, 
            config["config"].get("result_path", "./"),
            dump_error_list=config["config"].get("dump_error_list", False)
        )
        

# --- Main Flow ---

def main():
    console.print("[bold cyan]Starting Configuration Wizard...[/bold cyan]")

    # 1. Check for config file
    check_config()

    # 2. Load config
    config = load_config()

    # 3. Check evaluation type
    check_eval_type(config)

    while True:
        menu_choice = questionary.select(
            "Main Menu - Select a section to configure:",
            choices=[
                questionary.Choice("1. Global Configurations (GHIDRA_HOME, Paths, Logic)", value="GLOBAL"),
                questionary.Choice("2. Select Target Datasets & Evaluators", value="SELECT"),
                questionary.Choice("3. Configure Selected Datasets", value="DATASETS"),
                questionary.Choice("4. Configure Selected Evaluators", value="EVALUATORS"),
                questionary.Choice("5. Show Summary & Exit", value="EXIT")
            ]
        ).ask()

        if menu_choice == "GLOBAL":
            global_settings_menu(config)
        elif menu_choice == "SELECT":
            datasets_evaluator_selection_menu(config)
        elif menu_choice == "DATASETS":
            configure_datasets_menu(config)
        elif menu_choice == "EVALUATORS":
            configure_evaluators_menu(config)
        elif menu_choice == "EXIT" or menu_choice is None:
            display_summary(config)
            break
    
    config_logger(
        log_file=config["config"]["log_file"], 
        log_level=config["config"]["log_level"]
    )
    start_evaluation(config)

if __name__ == "__main__":
    main()