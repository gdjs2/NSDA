from loguru import logger
import pyghidra

from pathlib import Path
from abc import ABC, abstractmethod
from datetime import datetime
from EvaluatorRegistry import register_evaluator

from rich.spinner import Spinner

class Evaluator(ABC):
    @abstractmethod
    def evaluate(
        self, 
        binary_path: str,
        base: int | None, 
        language: str,
        code_set: set[int],
        spinner: Spinner | None,
        args: dict,
        aux: dict | None = None
    ) -> tuple[float, float, float, float, float, list[int], list[int]]:
        """
        Evaluate predictions against ground truth and return metrics.
        
        :param self: Self
        :param binary_path: Path to the binary file to evaluate.
        :type binary_path: str
        :param base: Optional base address for the binary.
        :type base: int | None
        :param code_set: Set of ground truth code addresses.
        :type code_set: set[int]
        :param args: Additional arguments for evaluator.
        :type args: dict
        :param aux: Additional auxiliary information for evaluator.
        :type aux: dict | None
        :return: A tuple containing evaluation metrics: 
            - Code Precision (float)
            - Code Recall (float)
            - Preprocessing Time (float)
            - Training Time (float)
            - Redisassemble Time (float)
            - List of error code addresses (Debug use, list[int])
            - List of error data addresses (Debug use, list[int])
        :rtype: tuple[float, float, float, float, float, list[int], list[int]]
        
        """
        pass

@register_evaluator
class NSDAEvaluator(Evaluator):
    def evaluate(
        self, 
        binary_path: str,
        base: int | None,
        language: str,
        code_set: set[int],
        spinner: Spinner | None,
        args: dict,
        aux: dict | None = None
    ) -> tuple[float, float, float, float, float, list[int], list[int]]:
        """
        NSDA Evaluator. 
        See Evaluator.evaluate for parameter descriptions.

        :param args: Additional arguments for evaluator.
        :type args: dict
            - iteration_limit (int): Maximum number of iterations for training.
            - epoches_limit (int): Maximum number of epochs for training.
            - keep_ghidra_prj (bool): Whether to keep the Ghidra project after evaluation.
            - keep_ghidra_prj_path (str | None): Path to save the Ghidra project if keeping.

        :return: A tuple containing evaluation metrics: 
            - Code Precision (float) 
            - Code Recall (float)
            - Preprocessing Time (float)
            - Training Time (float)
            - Redisassemble Time (float)
            - List of error code addresses (Debug use, list[int])
            - List of error data addresses (Debug use, list[int])
        :rtype: tuple[float, float, float, float, float, list[int], list[int]]
        """
        from iterative_training import iterative_training, iterative_training_legacy
        return (
            iterative_training(binary_path, code_set, base=base, iteration_limit=args["iteration_limit"], epoches_limit=args["epoches_limit"], keep_ghidra_prj=args["keep_ghidra_prj"], keep_ghidra_prj_path=args["keep_ghidra_prj_path"], language=language, spinner=spinner)
            if not args.get("legacy", False) else iterative_training_legacy(binary_path, code_set, base=base, iteration_limit=args["iteration_limit"], epoches_limit=args["epoches_limit"], keep_ghidra_prj=args["keep_ghidra_prj"], keep_ghidra_prj_path=args["keep_ghidra_prj_path"], language=language, spinner=spinner)
        )
            

@register_evaluator
class NSDAWoRulesEvaluator(Evaluator):
    def evaluate(
        self, 
        binary_path: str,
        base: int | None,
        language: str,
        code_set: set[int],
        spinner: Spinner | None,
        args: dict,
        aux: dict | None = None
    ) -> tuple[float, float, float, float, float, list[int], list[int]]:
        """
        NSDA Evaluator without logic rules.
        See Evaluator.evaluate for parameter descriptions.

        :param args: Additional arguments for evaluator.
        :type args: dict
            - iteration_limit (int): Maximum number of iterations for training.
            - epoches_limit (int): Maximum number of epochs for training.
            - keep_ghidra_prj (bool): Whether to keep the Ghidra project after evaluation.
            - keep_ghidra_prj_path (str | None): Path to save the Ghidra project if keeping.

        :return: A tuple containing evaluation metrics: 
            - Code Precision (float) 
            - Code Recall (float)
            - Preprocessing Time (float)
            - Training Time (float)
            - Redisassemble Time (float)
            - List of error code addresses (Debug use, list[int])
            - List of error data addresses (Debug use, list[int])
        :rtype: tuple[float, float, float, float, float, list[int], list[int]]
        """
        from iterative_training import iterative_training, iterative_training_legacy
        return (
            iterative_training(binary_path, code_set, base=base, iteration_limit=args["iteration_limit"], epoches_limit=args["epoches_limit"], keep_ghidra_prj=args["keep_ghidra_prj"], keep_ghidra_prj_path=args["keep_ghidra_prj_path"], language=language, without_rules=True, spinner=spinner)
            if not args.get("legacy", False) else iterative_training_legacy(binary_path, code_set, base=base, iteration_limit=args["iteration_limit"], epoches_limit=args["epoches_limit"], keep_ghidra_prj=args["keep_ghidra_prj"], keep_ghidra_prj_path=args["keep_ghidra_prj_path"], language=language, without_rules=True, spinner=spinner)
        )

@register_evaluator
class ProbNSDAEvaluator(Evaluator):
    def evaluate(
        self,
        binary_path: str,
        base: int,
        language: str,
        code_set: set[int],
        args: dict,
        spinner: Spinner | None,
        aux: dict | None = None
    ) -> tuple[float, float, float, float, float, list[int], list[int]]:
        """
        Probabilistic NSDA Evaluator without neural network.
        See Evaluator.evaluate for parameter descriptions.

        :param args: Additional arguments for evaluator.
        :type args: dict
            - iteration_limit (int): Maximum number of iterations for training.
            - epoches_limit (int): Maximum number of epochs for training.
            - keep_ghidra_prj (bool): Whether to keep the Ghidra project after evaluation.
            - keep_ghidra_prj_path (str | None): Path to save the Ghidra project if keeping.
        :return: A tuple containing evaluation metrics:
            - Code Precision (float) 
            - Code Recall (float)
            - Preprocessing Time (float)
            - Training Time (float)
            - Redisassemble Time (float)
            - List of error code addresses (Debug use, list[int])
            - List of error data addresses (Debug use, list[int])
        :rtype: tuple[float, float, float, float, float, list[int], list[int]]
        """
        from iterative_training import iterative_training, iterative_training_legacy
        return (
            iterative_training(binary_path, code_set, base=base, iteration_limit=args["iteration_limit"], epoches_limit=args["epoches_limit"], keep_ghidra_prj=args["keep_ghidra_prj"], keep_ghidra_prj_path=args["keep_ghidra_prj_path"], without_nn=True, language=language, spinner=spinner)
            if not args.get("legacy", False) else iterative_training_legacy(binary_path, code_set, base=base, iteration_limit=args["iteration_limit"], epoches_limit=args["epoches_limit"], keep_ghidra_prj=args["keep_ghidra_prj"], keep_ghidra_prj_path=args["keep_ghidra_prj_path"], without_nn=True, language=language, spinner=spinner)
        )

@register_evaluator
class GhidraEvaluator(Evaluator):
    def _evaluate(
        self, 
        binary_path: str,
        base: int | None,
        language: str,
        code_set: set[int],
        args: dict,
        spinner: Spinner | None,
        aux: dict | None = None
    ) -> tuple[float, float, float, float, float, list[int], list[int]]:
        """
        Ghidra Evaluator.
        See Evaluator.evaluate for parameter descriptions.

        :param args: Additional arguments for evaluator.
        :type args: dict
            - keep_ghidra_prj (bool): Whether to keep the Ghidra project after evaluation.
            - keep_ghidra_prj_path (str | None): Path to save the Ghidra project if keeping.
        :return: A tuple containing evaluation metrics:
            - Code Precision (float) 
            - Code Recall (float)
            - Preprocessing Time (float)
            - Training Time (float)
            - Redisassemble Time (float)
            - List of error code addresses (Debug use, list[int])
            - List of error data addresses (Debug use, list[int])
        :rtype: tuple[float, float, float, float, float, list[int], list[int]]
        """
        import tempfile

        from pathlib import Path
        from iterative_training import delete_ghidra_cache, save_ghidra_cache
        from ghidra.program.model.address import AddressSpace # type: ignore
        from ghidra.program.model.listing import Program, Instruction, CodeUnitIterator # type: ignore
        
        auto_analyze_time = .0
        total_process_time = .0

        ghidra_project_path = tempfile.mkdtemp(prefix="ghidra_project_")
        logger.info(f"Created temporary Ghidra project at {ghidra_project_path}")
        binary_name = Path(binary_path).stem

        code_results_set = set()
        data_results_set = set()

# Loading binary and auto-analysis - Start ======================================================
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
                    from ghidra.app.plugin.core.analysis import AutoAnalysisManager # type: ignore
                    mgr = AutoAnalysisManager.getAnalysisManager(program)
                    mgr.initializeOptions()
                    mgr.reAnalyzeAll(None) # type: ignore
                    flat_api.analyzeChanges(program)
                finally:
                    program.endTransaction(transaction_id, True)
                auto_analyze_time = (datetime.now() - auto_analyze_time).total_seconds()
                logger.info(f"Auto-analysis completed in {auto_analyze_time:.2f}s")
                total_process_time = loading_time + auto_analyze_time
# Loading binary and auto-analysis - End ======================================================
                
                memory = program.getMemory()
                listing = program.getListing()
                
                total_block = len(memory.getBlocks())
                instr_cnt = 0

                for idx, mry_block in enumerate(memory.getBlocks()):
                    start_addr = mry_block.getStart()
                    end_addr = mry_block.getEnd()

                    if start_addr.getAddressSpace().getType() != AddressSpace.TYPE_RAM:
                        continue

                    addr = start_addr
                    while addr < end_addr:
                        code_unit = listing.getCodeUnitAt(addr)
                        progress = (addr.getOffset() - start_addr.getOffset()) * 100 / (end_addr.getOffset() - start_addr.getOffset())
                        if spinner:
                            spinner.update(text=f"Block [{mry_block.getStart()}-{mry_block.getEnd()}] {idx+1}/{total_block} {progress:.2f}% {instr_cnt} instructions")

                        if isinstance(code_unit, Instruction): 
                            code_results_set.update(range(addr.getOffset(), addr.getOffset() + code_unit.getLength()))
                            instr_cnt += 1
                        else:
                            data_results_set.update(range(addr.getOffset(), addr.getOffset() + code_unit.getLength()))
                        addr = addr.add(code_unit.getLength())
                        
                load_result.save(pyghidra.task_monitor())
                program.release(nsda_domain_object_user)

        error_code_list = list(code_results_set - code_set)
        error_data_list = list(data_results_set & code_set)
        tp = len(code_results_set & code_set)
        fp = len(code_results_set - code_set)
        fn = len(code_set - code_results_set)

        precision = tp / (tp + fp) if tp + fp > 0 else 0
        recall = tp / (tp + fn) if tp + fn > 0 else 0

        if args.get("keep_ghidra_prj") and args.get("keep_ghidra_prj_path"): 
            save_ghidra_cache(ghidra_project_path, args["keep_ghidra_prj_path"], "ghidra")
        else: delete_ghidra_cache(ghidra_project_path)

        return precision, recall, total_process_time, 0.0, 0.0, error_code_list, error_data_list

    def _evaluate_legacy(
        self, 
        binary_path: str,
        base: int | None,
        language: str,
        code_set: set[int],
        args: dict,
        spinner: Spinner | None,
        aux: dict | None = None
    ) -> tuple[float, float, float, float, float, list[int], list[int]]:
        import tempfile

        from pathlib import Path
        from iterative_training import delete_ghidra_cache, save_ghidra_cache
        from ghidra.program.model.address import AddressSpace # type: ignore
        from ghidra.program.model.listing import Program, Instruction, CodeUnitIterator # type: ignore
        
        auto_analyze_time = .0
        total_process_time = .0

        ghidra_project_path = tempfile.mkdtemp(prefix="ghidra_project_")
        logger.info(f"Created temporary Ghidra project at {ghidra_project_path}")
        binary_name = Path(binary_path).stem

        code_results_set = set()
        data_results_set = set()

# Loading binary and auto-analysis - Start ======================================================
        loading_time = datetime.now()
        
        with pyghidra.open_program(
            binary_path, 
            ghidra_project_path,
            binary_name,
            analyze = False,
            language = language
        ) as flat_api:

            program = flat_api.getCurrentProgram()
            if base is not None:
                base_addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(base)
                transaction_id = program.startTransaction("Set image base")
                try:
                    program.setImageBase(base_addr, True)
                finally:
                    program.endTransaction(transaction_id, True)
            
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
            total_process_time += loading_time + auto_analyze_time
# Loading binary and auto-analysis - End ======================================================
                
            memory = program.getMemory()
            listing = program.getListing()
            
            total_block = len(memory.getBlocks())
            instr_cnt = 0

            for idx, mry_block in enumerate(memory.getBlocks()):
                start_addr = mry_block.getStart()
                end_addr = mry_block.getEnd()

                if start_addr.getAddressSpace().getType() != AddressSpace.TYPE_RAM:
                    continue

                addr = start_addr
                while addr < end_addr:
                    code_unit = listing.getCodeUnitAt(addr)
                    progress = (addr.getOffset() - start_addr.getOffset()) * 100 / (end_addr.getOffset() - start_addr.getOffset())
                    if spinner:
                        spinner.update(text=f"Block [{mry_block.getStart()}-{mry_block.getEnd()}] {idx+1}/{total_block} {progress:.2f}% {instr_cnt} instructions")

                    if isinstance(code_unit, Instruction): 
                        code_results_set.update(range(addr.getOffset(), addr.getOffset() + code_unit.getLength()))
                        instr_cnt += 1
                    else:
                        data_results_set.update(range(addr.getOffset(), addr.getOffset() + code_unit.getLength()))
                    addr = addr.add(code_unit.getLength())

        error_code_list = list(code_results_set - code_set)
        error_data_list = list(data_results_set & code_set)
        tp = len(code_results_set & code_set)
        fp = len(code_results_set - code_set)
        fn = len(code_set - code_results_set)

        precision = tp / (tp + fp) if tp + fp > 0 else 0
        recall = tp / (tp + fn) if tp + fn > 0 else 0

        if args.get("keep_ghidra_prj") and args.get("keep_ghidra_prj_path"): 
            save_ghidra_cache(ghidra_project_path, args["keep_ghidra_prj_path"], "ghidra")
        else: delete_ghidra_cache(ghidra_project_path)

        return precision, recall, total_process_time, 0.0, 0.0, error_code_list, error_data_list

    def evaluate(
        self, 
        binary_path: str,
        base: int | None,
        language: str,
        code_set: set[int],
        args: dict,
        spinner: Spinner | None,
        aux: dict | None = None
    ) -> tuple[float, float, float, float, float, list[int], list[int]]:
        legacy = args.get("legacy", False)
        if not legacy:
            return self._evaluate(
                binary_path, 
                base, 
                language, 
                code_set, 
                args, 
                spinner, 
                aux
            )
        else:
            return self._evaluate_legacy(
                binary_path,
                base,
                language,
                code_set,
                args,
                spinner,
                aux
            )

@register_evaluator
class LoadstarEvaluator(Evaluator):
    def __init__(self):
        import os
        import warnings

        os.environ['TF_CPP_MIN_LOG_LEVEL'] = '2'
        
        import tensorflow as tf
        tf.get_logger().setLevel('ERROR')
        warnings.filterwarnings('ignore')

        gpus  = tf.config.list_physical_devices('GPU')
        if gpus:
            try:
                for gpu in gpus:
                    tf.config.experimental.set_memory_growth(gpu, True)
                logger.info(f"Enabled memory growth for {len(gpus)} GPU(s)")
            except RuntimeError as e:
                logger.error(f"Failed to set memory growth: {e}")

    def evaluate(
        self, 
        binary_path: str,
        base: int,
        language: str,
        code_set: set[int],
        args: dict,
        spinner: Spinner | None,
        aux: dict | None = None
    ) -> tuple[float, float, float, float, float, list[int], list[int]]:
        """
        Loadstar Evaluator.
        See Evaluator.evaluate for parameter descriptions.
        :param args: Additional arguments for evaluator.
        :type args: dict
            - loadstar_home (str): Path to Loadstar home directory.
            - tokenizer_path (str): Path to the tokenizer file.
            - weights_path (str): Path to the model weights file.
            - maxlen (int): Maximum length for tokenization.
            - batch_size (int): Batch size for inference.
            - vocab_size (int): Vocabulary size for the model.
            - embedding_dim (int): Embedding dimension for the model.
            - lstm_units (int): Number of LSTM units for the model.
        :return: A tuple containing evaluation metrics:
            - Code Precision (float) 
            - Code Recall (float)
            - Preprocessing Time (float)
            - Inference Time (float)
            - Redisassemble Time (float)
            - List of error code addresses (Debug use, list[int])
            - List of error data addresses (Debug use, list[int])
        :rtype: tuple[float, float, float, float, float, list[int], list[int]]
        """
        import sys
        import r2pipe
        import pickle
        import pandas as pd
        from pathlib import Path
        from loguru import logger
        
        from tensorflow import keras # type: ignore
        from tensorflow.keras import layers # type: ignore

        # Add Loadstar to path to import e2e_pipeline
        loadstar_home = Path(args["loadstar_home"])
        loadstar_home_str = str(loadstar_home)
        if loadstar_home_str not in sys.path:
            sys.path.insert(0, loadstar_home_str)
        
        # Import Loadstar's functions
        from e2e_pipeline import safe_tokenize
        
        STEP = 4

        start_time = datetime.now()
        r2 = r2pipe.open(binary_path, flags=["-a", "arm", "-b", "32", "-m", f"{base:#x}"] + ["-e", "bin.relocs.apply=true"])

        info = r2.cmdj(r"ij")
        if info is None:
            logger.error("r2: Get file info failed")
            raise RuntimeError
        
        inst_list = []
        addr_list = []
        file_size = info["core"]["size"]
        if args["llvm_arm32"]:
            base = 65536
        else:
            pass
        offset = base
        while offset < base + file_size:
            instr = r2.cmdj(f"pdj 1 @ {offset:#x}")
            if not instr or instr[0].get("type") == "invalid": 
                instr = "invalid"
            else: instr = instr[0]["opcode"]
            addr_list.append(offset)
            offset += STEP
            inst_list.append(instr)
        process_time = (datetime.now() - start_time).total_seconds()
        
        # Load tokenizer and prepare model parameters
        inference_start = datetime.now()
        tokenizer_path = loadstar_home / args["tokenizer_path"]
        weights_path = loadstar_home / args.get("weights_path", "new_weights.weights.h5")
        maxlen = args["maxlen"]
        batch_size = args["batch_size"]
        
        # Model hyperparameters (can be overridden via args)
        vocab_size = args.get("vocab_size", 651997)
        embedding_dim = args.get("embedding_dim", 128)
        lstm_units = args.get("lstm_units", 64)
        
        with tokenizer_path.open("rb") as f:
            tokenizer = pickle.load(f)
        
        # Build model architecture
        def build_model(vocab_size, embedding_dim, maxlen, lstm_units):
            model = keras.Sequential([
                layers.Embedding(input_dim=vocab_size, output_dim=embedding_dim, input_length=maxlen, name='embedding'),
                layers.LSTM(lstm_units, return_sequences=False, name='lstm'),
                layers.Flatten(name='flatten'),
                layers.Dense(16, activation='relu', name='dense'),
                layers.Dropout(0.5, name='dropout'),
                layers.Dense(16, activation='relu', name='dense_1'),
                layers.Dropout(0.5, name='dropout_1'),
                layers.Dense(2, activation='softmax', name='dense_2')
            ])
            
            # Compile model (required before loading weights)
            model.compile(
                optimizer='adam',
                loss='sparse_categorical_crossentropy',
                metrics=['accuracy']
            )
            
            # Build the model with input shape
            model.build((None, maxlen))
            
            return model
        
        # Create model and load weights
        model = build_model(vocab_size, embedding_dim, maxlen, lstm_units)
        model.load_weights(str(weights_path))
        
        # Use Loadstar's tokenization function
        X = safe_tokenize(inst_list, tokenizer, maxlen)
        raw_preds = model.predict(X, batch_size=batch_size, verbose=0)
        
        # Get predictions
        import numpy as np
        if raw_preds.ndim > 1 and raw_preds.shape[-1] > 1:
            pred_labels = raw_preds.argmax(axis=1).astype(int).tolist()
        else:
            pred_labels = np.rint(raw_preds.flatten()).astype(int).tolist()
        
        # Convert instruction-level to byte-level 
        predict_codeset = set()
        predict_dataset = set()
        for idx, pred in enumerate(pred_labels):
            current_address = addr_list[idx]
            if pred == 0:
                predict_codeset.update(range(current_address, current_address + STEP))
            else:
                predict_dataset.update(range(current_address, current_address + STEP))
        
        inference_time = (datetime.now() - inference_start).total_seconds()
        
        tp = len(predict_codeset & code_set)
        fp = len(predict_codeset - code_set)
        fn = len(code_set - predict_codeset)
        code_precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        code_recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0

        error_code_list = list(predict_codeset - code_set)
        error_data_list = list(predict_dataset & code_set)

        # delete TensorFlow/Keras model to free up resources (memory leak prevention)
        del model
        import gc
        gc.collect()
        from tensorflow.keras import backend as K # type: ignore
        K.clear_session()
        r2.quit()
        
        return code_precision, code_recall, process_time, inference_time, 0.0, error_code_list, error_data_list

@register_evaluator
class DDisasmEvaluator(Evaluator):
    def __init__(self):
        import tempfile
        from pathlib import Path

        self.workdir = Path(tempfile.gettempdir())
        self.workdir.mkdir(parents=True, exist_ok=True)
    
    def evaluate(
            self,
            binary_path: str,
            base: int,
            language: str,
            code_set: set[int],
            args: dict,
            spinner: Spinner | None,
            aux: dict | None = None
    ) -> tuple[float, float, float, float, float, list[int], list[int]]:
        import gtirb
        import ddisasm
        import subprocess
        from datetime import datetime
        from pathlib import Path

        STEP = 4

        binary_name = Path(binary_path).stem
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        ir_file = self.workdir / f"{binary_name}_{timestamp}.gtirb"
        
        start_time = datetime.now()
        with ddisasm.ddisasm_path() as tool_path:
            cmd = [tool_path, "--ir", str(ir_file), binary_path]
            subprocess.run(cmd, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        process_time = (datetime.now() - start_time).total_seconds()

        ir = gtirb.ir.IR.load_protobuf(ir_file)
        predict_codeset = set()
        predict_dataset = set()
        for codeblock in ir.code_blocks:
            if codeblock.address is None:
                logger.warning("Ddisasm detects codeblock without start address")
                continue
            # for addr in range(codeblock.address, codeblock.address + codeblock.size, STEP):
            predict_codeset.update(range(codeblock.address, codeblock.address + codeblock.size))

        for datablock in ir.data_blocks:
            if datablock.address is None:
                logger.warning("Ddisasm detects datablock without start address")
                continue
            # for addr in range(datablock.address, datablock.address + datablock.size, STEP):
            predict_dataset.update(range(datablock.address, datablock.address + datablock.size))

        tp = len(predict_codeset & code_set)
        fp = len(predict_codeset - code_set)
        fn = len(code_set - predict_codeset)
        code_precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        code_recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0

        error_code_list = list(predict_codeset - code_set)
        error_data_list = list(predict_dataset & code_set)

        return code_precision, code_recall, process_time, 0.0, 0.0, error_code_list, error_data_list

@register_evaluator
class SegmentedNSDAEvaluator(Evaluator):
    def evaluate(
        self, 
        binary_path: str,
        base: int | None,
        language: str,
        code_set: set[int],
        spinner: Spinner | None,
        args: dict,
        aux: dict | None = None
    ):
        """
        Segmented NSDA Evaluator.
        This function will keep the ghidra project to keep_ghidra_prj_path by default.

        :param args: Additional arguments for evaluator.
        :type args: dict
            - iteration_limit (int): Maximum number of iterations for training.
            - epoches_limit (int): Maximum number of epochs for training.
            - keep_ghidra_prj_path (str | None): Path to save the Ghidra project if keeping. 
            - function_level (bool): Whether to perform function-level evaluation (default: False).
            - segment_size(int): Segment size for segmented iterative training (default: 1MB).
        :return: A tuple containing evaluation metrics. (Currently returns dummy values, to be implemented)
        :rtype: tuple[float, float, float, float, float, list[int], list[int]]
        """
        skip_training = args.get("skip_training", False)
        project_path = args.get("project_path", None)
        project_name = args.get("project_name", None)
        file_system_name = args.get("file_system_name", None)
        preprocessing_time = training_time = postprocessing_time = .0

        if skip_training and project_path and project_name and file_system_name:
            logger.info("Skipping training and using existing Ghidra project for evaluation")
            logger.info(f"Project path: {project_path}, Project name: {project_name}, File system name: {file_system_name}")
        else:
            from iterative_training import segmented_iterative_training

            (
                project_path, project_name, file_system_name, 
                preprocessing_time, training_time, postprocessing_time
            ) = segmented_iterative_training(
                binary_path = binary_path,
                base = base,
                segment_size = args.get("segment_size", 1 << 20),  # Default to 1MB
                keep_ghidra_prj_path = args["keep_ghidra_prj_path"],
                iteration_limit = args["iteration_limit"],
                epoches_limit = args["epoches_limit"],
                language = language,
                spinner = spinner
            )

        is_function_level = args.get("function_level", False)
        # If bytes-level evaluation
        if not is_function_level:
            from segmented_helper import byte_level_evaluate
            (
                precision, recall, 
                error_code_list, error_data_list
            ) = byte_level_evaluate(
                project_path = str(project_path),
                project_name = project_name,
                file_system_name = file_system_name,
                code_set = code_set,
                base = base,
                spinner = spinner
            )
            
            return (
                precision, recall,
                preprocessing_time, training_time, postprocessing_time,
                error_code_list, error_data_list
            )
        else:
            from segmented_helper import function_level_evaluate
            if aux is None or "function_boundaries" not in aux:
                raise ValueError("Function boundaries are required for function-level evaluation")
            (
                precision, recall, error_code_list
            ) = function_level_evaluate(
                project_path = str(project_path),
                project_name = project_name,
                file_system_name = file_system_name,
                code_set = code_set,
                function_boundaries = aux["function_boundaries"],
                base = base,
                spinner = spinner
            )

            return (
                precision, recall,
                preprocessing_time, training_time, postprocessing_time,
                error_code_list, []
            )
        

