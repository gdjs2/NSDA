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
        import r2pipe
        import pickle
        import pandas as pd
        from pathlib import Path
        from loguru import logger
        from tensorflow import keras
        from tensorflow.keras import layers
        
        # Add Loadstar to path to import e2e_pipeline
        loadstar_home = Path(args["loadstar_home"])
        sys.path.insert(0, str(loadstar_home))
        
        # Import Loadstar's functions
        from e2e_pipeline import safe_tokenize
        
        start_time = datetime.now()
        r2 = r2pipe.open(binary_path, flags=["-a", "arm", "-b", "32"])
        offset, step = 0, 4
        info = r2.cmdj(r"ij")
        if info is None:
            logger.error("r2: Get file info failed")
            raise RuntimeError
        
        inst_list = []
        file_size = info["core"]["size"]
        while offset < file_size:
            instr = r2.cmdj(f"pdj 1 @ {offset}")
            if not instr: instr = "invalid"
            else: instr = instr[0]["disasm"]
            offset += step
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
