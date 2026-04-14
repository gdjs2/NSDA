from loguru import logger
import pyghidra

from abc import ABC, abstractmethod
from bitarray import bitarray
from datetime import datetime
from EvaluatorRegistry import register_evaluator

class Evaluator(ABC):
    @abstractmethod
    def evaluate(
        self, 
        binary_path: str,
        base: int | None, 
        language: str,
        code_set: set[int],
        args: dict
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
        args: dict,
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
        from iterative_training import iterative_training
        return iterative_training(binary_path, code_set, base=base, iteration_limit=args["iteration_limit"], epoches_limit=args["epoches_limit"], keep_ghidra_prj=args["keep_ghidra_prj"], keep_ghidra_prj_path=args["keep_ghidra_prj_path"], language=language)

@register_evaluator
class NSDAWoRulesEvaluator(Evaluator):
    def evaluate(
        self, 
        binary_path: str,
        base: int | None,
        language: str,
        code_set: set[int],
        args: dict,
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
        from iterative_training import iterative_training
        return iterative_training(binary_path, code_set, base=base, iteration_limit=args["iteration_limit"], epoches_limit=args["epoches_limit"], keep_ghidra_prj=args["keep_ghidra_prj"], keep_ghidra_prj_path=args["keep_ghidra_prj_path"], language=language, without_rules=True)

@register_evaluator
class ProbNSDAEvaluator(Evaluator):
    def evaluate(
        self,
        binary_path: str,
        base: int,
        language: str,
        code_set: set[int],
        args: dict,
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
        from iterative_training import iterative_training
        return iterative_training(binary_path, code_set, base=base, iteration_limit=args["iteration_limit"], epoches_limit=args["epoches_limit"], keep_ghidra_prj=args.get("keep_ghidra_prj", False), keep_ghidra_prj_path=args.get("keep_ghidra_prj_path"), without_nn=True, language=language)
    
@register_evaluator
class GhidraEvaluator(Evaluator):
    def evaluate(
        self, 
        binary_path: str,
        base: int | None,
        language: str,
        code_set: set[int],
        args: dict,
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
        from my_program_helper import MyProgram
        from iterative_training import delete_ghidra_cache, save_ghidra_cache
        from ghidra.program.model.address import AddressSpace # pyright: ignore[reportMissingImports]
        
        delete_ghidra_cache(binary_path)
        start_time = datetime.now()
        with pyghidra.open_program(binary_path, language=language) as flat_api:
            my_program = MyProgram(flat_api, base=base)

        process_time = (datetime.now() - start_time).total_seconds()
        if args.get("keep_ghidra_prj") and args.get("keep_ghidra_prj_path"): 
            save_ghidra_cache(binary_path, args["keep_ghidra_prj_path"], "ghidra")
        else: delete_ghidra_cache(binary_path)

        if args.get("dump_blocks_path") is not None:
            my_program.dump_blocks(args["dump_blocks_path"])

        tp = fp = fn = 0
        error_code_list = []
        error_data_list = []

        for block in my_program.blocks:
            logger.debug(f"{block}")
            # space = block.start_address.getAddressSpace()
            if block.start_address.getAddressSpace().getType() != AddressSpace.TYPE_RAM:
                break

            block_offsets = set(range(block.start_address.getOffset(), block.end_address.getOffset(), 4))
            hits = block_offsets & code_set
            if block.type == "Code":
                tp += len(hits)
                fp += len(block_offsets - hits)
                error_code_list.extend(block_offsets - hits)
            else:
                fn += len(hits)
                error_data_list.extend(hits)
        code_precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        code_recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        return code_precision, code_recall, process_time, 0.0, 0.0, error_code_list, error_data_list

@register_evaluator
class LoadstarEvaluator(Evaluator):
    def evaluate(
        self, 
        binary_path: str,
        base: int,
        language: str,
        code_set: set[int],
        args: dict
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
        from tensorflow import keras # pyright: ignore[reportAttributeAccessIssue] 
        from tensorflow.keras import layers # pyright: ignore[reportMissingImports]
        
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
                predict_codeset.add(current_address)
            else:
                predict_dataset.add(current_address)
        
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
        from tensorflow.keras import backend as K # pyright: ignore[reportMissingImports]
        K.clear_session()
        r2.quit()
        
        return code_precision, code_recall, process_time, inference_time, 0.0, error_code_list, error_data_list

@register_evaluator
class DdisasmEvaluator(Evaluator):
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
            args: dict
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
            for addr in range(codeblock.address, codeblock.address + codeblock.size, STEP):
                predict_codeset.add(addr)

        for datablock in ir.data_blocks:
            if datablock.address is None:
                logger.warning("Ddisasm detects datablock without start address")
                continue
            for addr in range(datablock.address, datablock.address + datablock.size, STEP):
                predict_dataset.add(addr)

        tp = len(predict_codeset & code_set)
        fp = len(predict_codeset - code_set)
        fn = len(code_set - predict_codeset)
        code_precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        code_recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0

        error_code_list = list(predict_codeset - code_set)
        error_data_list = list(predict_dataset & code_set)

        return code_precision, code_recall, process_time, 0.0, 0.0, error_code_list, error_data_list


        
