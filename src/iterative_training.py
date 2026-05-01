import ltn
import shutil
import pyghidra
import tempfile

from pathlib import Path
from loguru import logger
from datetime import datetime
from rich.spinner import Spinner
from ltn_helper import train, evaluate
from my_program_helper import MyProgram

from ghidra.program.flatapi import FlatProgramAPI  # type: ignore
from ghidra.program.model.listing import Program  # type: ignore


def redisasemble(
        CodeBlock: ltn.Predicate, 
        flat_api: FlatProgramAPI,
        my_program: MyProgram,
        spinner: Spinner | None = None
    ) -> bool:
    """
    Re-disassemble the blocks using the trained CodeBlock model.
    """
    flg = True
    transaction_id = flat_api.getCurrentProgram().startTransaction("Redisassemble blocks")
    try:
        for idx, (block, emb) in enumerate(zip(my_program.blocks, my_program.embeddings)):
            if spinner: spinner.update(text=f"[bold yellow]Redisassembling block {idx + 1}/{len(my_program.blocks)}...[/bold yellow]")
            if CodeBlock(ltn.Constant(emb)).value >= .50 and block.type != "Code" and not block.failed_disasm_flg and block.is_executable:
                flat_api.clearListing(block.start_address, block.end_address)
                if flat_api.disassemble(block.start_address):
                    flg = False
                # logger.debug(f"Re-disassembled block {block.start_address} in {binary_path}")
    finally:
        flat_api.getCurrentProgram().endTransaction(transaction_id, True)
    return flg

def delete_ghidra_cache(ghidra_project_path: str):
    if Path(ghidra_project_path).exists() and Path(ghidra_project_path).is_dir():
        shutil.rmtree(ghidra_project_path)
        logger.info(f"Deleted ghidra cache folder {ghidra_project_path}")

def save_ghidra_cache(source_path: str, saved_path: str, suffix: str | None = None):
    path = Path(source_path)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    des_path = Path(saved_path) / f"{timestamp}_{path.name}__{suffix}"
    if path.exists() and path.is_dir():
        if not des_path.parent.exists():
            des_path.parent.mkdir(parents=True)
        shutil.move(path, des_path)
        logger.info(f"Save ghidra cache folder {path.name} to {des_path}")

def iterative_training(
    binary_path: str, 
    code_set: set[int],
    base: int | None,
    iteration_limit: int = 1,
    epoches_limit: int = 500,
    keep_ghidra_prj: bool = False,
    keep_ghidra_prj_path: str | None = None,
    without_nn: bool = False,
    language: str = "ARM:LE:32:v5",
    without_rules: bool = False,
    spinner: Spinner | None = None,
) -> tuple[float, float, float, float, float, list[int], list[int]]: # Code Precision, Code Recall, Data Precision, Data Recall, Preprocessing Time, Training Time, Redisassemble Time
    # Whether all iterations are finished
    finish_flg = False
    # Iteration count
    iteration_cnt = 0

    # Create temporary Ghidra project for this evaluation
    ghidra_project_path = tempfile.mkdtemp(prefix="ghidra_project_")
    logger.info(f"Created temporary Ghidra project at {ghidra_project_path}")

    auto_analyze_time = .0
    loading_time = .0
    total_preprocess_time = .0
    total_training_time = .0
    total_postprocess_time = .0

    binary_name = Path(binary_path).stem

# Create a new project, import binary, auto-analysis - Once per program - Start ======================
    loading_time = datetime.now()
    with pyghidra.open_project(path=ghidra_project_path, name=binary_name, create=True) as project:
        # Load binary program
        from ghidra.program.flatapi import FlatProgramAPI  # type: ignore
        loader = pyghidra.program_loader().project(project).source(binary_path).language(language)
        if spinner: spinner.update(text=f"[bold yellow]Loading binary {binary_name}...[/bold yellow]")
        with loader.load() as load_result:
            nsda_domain_object_user = "nsda_user"
            program: Program = load_result.getPrimaryDomainObject(nsda_domain_object_user)

            # Set image base if provided
            if base is not None:
                base_addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(base)
                transaction_id = program.startTransaction("Set image base")
                try:
                    program.setImageBase(base_addr, True)
                finally:
                    program.endTransaction(transaction_id, True)
            
            # Get flat API
            flat_api = FlatProgramAPI(program)
            loading_time = (datetime.now() - loading_time).total_seconds()
            logger.info(f"Loaded binary {binary_name} in {loading_time:.2f}s")

            # Ghidra Auto-analysis
            if spinner: spinner.update(text=f"[bold yellow]Performing Auto-Analysis...[/bold yellow]")
            transaction_id = program.startTransaction("Run Auto-Analysis")
            auto_analyze_time = datetime.now()
            try:
                flat_api.analyzeAll(program)
            finally:
                program.endTransaction(transaction_id, True)
            auto_analyze_time = (datetime.now() - auto_analyze_time).total_seconds()
            logger.info(f"Auto-analysis completed in {auto_analyze_time:.2f}s")
            total_preprocess_time += loading_time + auto_analyze_time
# Create a new project, import binary, auto-analysis - Once per program - End ======================
# Iterative training loop - Start ==================================================================
            # Initialize MyProgram instance with the loaded program
            # Start iteration
            while not finish_flg and iteration_cnt < iteration_limit:
                CodeBlock = None
                iteration_cnt += 1

                if spinner: spinner.update(text=f"[bold yellow]Iteration {iteration_cnt}/{iteration_limit} Preprocessing program. ")
                # Preprocess
                start = datetime.now()
                my_program = MyProgram(flat_api, without_nn=without_nn, spinner=spinner)
                preprocess_time = (datetime.now() - start).total_seconds()
                total_preprocess_time += preprocess_time
                logger.info(f"Program preprocessed in {preprocess_time:.2f}s with {len(my_program.blocks)} blocks")

                # Training
                start = datetime.now()
                CodeBlock, _ = train(my_program, CodeBlock, epoches_limit, wo_rules=without_rules, spinner=spinner)
                training_time = (datetime.now() - start).total_seconds()
                total_training_time += training_time
                logger.info(f"Training completed in {training_time:.2f}s")

                # Postprocess
                ## Redisassemble
                start = datetime.now()
                finish_flg = redisasemble(CodeBlock, flat_api, my_program, spinner)
                redisassemble_time = (datetime.now() - start).total_seconds()
                logger.info(f"Redisassemble completed in {redisassemble_time:.2f}s")
                ## Re-analyze changes after redisassemble
                if spinner: spinner.update(text=f"[bold yellow]Re-analyzing after redisassemble...[/bold yellow]")
                transaction_id = program.startTransaction("Re-analyze after redisassemble")
                start = datetime.now()
                try:
                    flat_api.analyzeChanges(program)
                finally:
                    program.endTransaction(transaction_id, True)
                reanalyze_time = (datetime.now() - start).total_seconds()
                logger.info(f"Re-analyze after redisassemble completed in {reanalyze_time:.2f}s")
                total_postprocess_time += reanalyze_time + redisassemble_time
            # Release the program to free up resources
            program.release(nsda_domain_object_user)
# Iterative training loop - End ==================================================================

    if keep_ghidra_prj and keep_ghidra_prj_path: 
        save_ghidra_cache(ghidra_project_path, keep_ghidra_prj_path, "nsda" if not without_nn else "fuzzy_nsda")
    else: delete_ghidra_cache(ghidra_project_path)
    code_precision, code_recall, error_code_list, error_data_list = evaluate(my_program, code_set)
    return code_precision, code_recall, total_preprocess_time, total_training_time, total_postprocess_time, error_code_list, error_data_list