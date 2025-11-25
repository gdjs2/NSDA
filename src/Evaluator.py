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
