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
        labels: bitarray,
        args: dict
    ) -> tuple[float, float, float, float, float, float, float]:
        """Evaluate predictions against ground truth and return metrics."""
        pass

@register_evaluator
class NSDAEvaluator(Evaluator):
    def evaluate(
        self, 
        binary_path: str,
        labels: bitarray,
        args: dict
    ) -> tuple[float, float, float, float, float, float, float]:
        from iterative_training import iterative_training
        return iterative_training(binary_path, labels, iteration_limit=args["iteration_limit"], epoches_limit=args["epoches_limit"])

@register_evaluator
class GhidraEvaluator(Evaluator):
    def evaluate(
        self, 
        binary_path: str,
        labels: bitarray,
        args: dict
    ) -> tuple[float, float, float, float, float, float, float]:
        from my_program_helper import MyProgram
        from iterative_training import delete_ghidra_cache
        delete_ghidra_cache(binary_path)
        start_time = datetime.now()
        with pyghidra.open_program(binary_path, language='ARM:LE:32:v4') as flat_api:
            my_program = MyProgram(flat_api)
        process_time = (datetime.now() - start_time).total_seconds()
        delete_ghidra_cache(binary_path)
        
        predictions = bitarray()
        for block in my_program.blocks:
            if block.type == "Code":
                predictions.extend('0'*block.size)
            else:
                predictions.extend('1'*block.size)
        if len(predictions) > len(labels):
            predictions = predictions[:len(labels)]
        elif len(predictions) < len(labels):
            labels = labels[:len(predictions)]
        
        code_pred = ~predictions
        code_labels = ~labels
        tp = (code_pred & code_labels).count()
        fp = (code_pred & ~code_labels).count()
        fn = (~code_pred & code_labels).count()
        code_precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        code_recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0

        tp = (predictions & labels).count()
        fp = (predictions & ~labels).count()
        fn = (~predictions & labels).count()
        data_precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        data_recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        return code_precision, code_recall, data_precision, data_recall, process_time, 0.0, 0.0

@register_evaluator
class LoadstarEvaluator(Evaluator):
    def evaluate(
        self, 
        binary_path: str,
        labels: bitarray,
        args: dict
    ) -> tuple[float, float, float, float, float, float, float]:
        import sys
        from pathlib import Path
        import pandas as pd
        import pickle
        from loguru import logger
        from tensorflow.keras.models import load_model
        
        # Add Loadstar to path to import e2e_pipeline
        loadstar_home = Path(args["loadstar_home"])
        sys.path.insert(0, str(loadstar_home))
        
        # Import Loadstar's functions
        from e2e_pipeline import safe_tokenize
        
        start_time = datetime.now()
        
        # Find corresponding CSV file
        binary_path_obj = Path(binary_path)
        binary_name = binary_path_obj.stem
        labeled_dir = binary_path_obj.parent.parent / "labeled"
        csv_path = labeled_dir / f"{binary_name}.csv"
        
        if not csv_path.exists():
            raise FileNotFoundError(f"CSV file not found: {csv_path}")
        
        logger.debug(f"LoadstarEvaluator: Reading {csv_path}")
        
        # Read CSV
        df = pd.read_csv(csv_path)
        if "inst" not in df.columns:
            raise KeyError(f"'inst' column not found in {csv_path}")
        
        inst_list = df["inst"].astype(str).tolist()
        process_time = (datetime.now() - start_time).total_seconds()
        
        # Load model and tokenizer
        inference_start = datetime.now()
        model_path = loadstar_home / args["model_path"]
        tokenizer_path = loadstar_home / args["tokenizer_path"]
        maxlen = args["maxlen"]
        batch_size = args["batch_size"]
        
        with tokenizer_path.open("rb") as f:
            tokenizer = pickle.load(f)
        model = load_model(str(model_path))
        
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
        predictions = bitarray()
        for pred in pred_labels:
            predictions.extend('0000' if pred == 0 else '1111')
        
        inference_time = (datetime.now() - inference_start).total_seconds()
        
        # Align and calculate metrics
        min_len = min(len(predictions), len(labels))
        predictions = predictions[:min_len]
        labels = labels[:min_len]
        
        # Code metrics
        code_pred = ~predictions
        code_labels = ~labels
        tp = (code_pred & code_labels).count()
        fp = (code_pred & ~code_labels).count()
        fn = (~code_pred & code_labels).count()
        code_precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        code_recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0

        # Data metrics
        tp = (predictions & labels).count()
        fp = (predictions & ~labels).count()
        fn = (~predictions & labels).count()
        data_precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        data_recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        
        return code_precision, code_recall, data_precision, data_recall, process_time, inference_time, 0.0
