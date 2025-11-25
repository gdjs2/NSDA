DATALOADER_REGISTRY = {}

def register_dataloader(cls):
    """Decorator to register a dataloader class."""
    DATALOADER_REGISTRY[cls.__name__] = cls
    return cls