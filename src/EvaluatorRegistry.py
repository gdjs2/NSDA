EVALUATOR_REGISTRY = {}

def register_evaluator(cls):
    """Decorator to register an evaluator class."""
    EVALUATOR_REGISTRY[cls.__name__] = cls
    return cls