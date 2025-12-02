import csv

from bitarray import bitarray
from pathlib import Path
from abc import ABC, abstractmethod
from loguru import logger
from DataLoaderRegistry import register_dataloader

class Data:
    def __init__(
        self, 
        name: str, 
        binary_path: str,
        labels: bitarray, # byte-level labels, 0-code, 1-data
        subset: str | None = None
    ):
        self.name = name
        self.binary_path = binary_path
        self.labels = labels
        self.subset = subset

class DataLoader(ABC):
    @abstractmethod
    def load(self, source_path: str) -> dict[str, Data]:
        """Load data from the specified source path."""
        pass
    
    # @abstractmethod
    # def load_single_data(self, binary_name: str) -> Data | None:
    #     """Load a single data instance from binary and label files."""
    #     pass

@register_dataloader
class LoadstarDataLoader(DataLoader):        
    # def load_single_data(self, binary_name: str) -> Data | None:
        
    #     if not bin_path.exists():
    #         logger.warning(f"Binary file {bin_path} does not exist. Skipping.")
    #         return None
    #     if not lab_path.exists():
    #         logger.warning(f"Label file {lab_path} does not exist. Skipping.")
    #         return None
    #     with open(lab_path, "r") as f:
    #         reader = csv.reader(f)
    #         reader.__next__()  # Skip header
    #         byte_labels = bitarray()
    #         for row in reader:
    #             byte_labels.extend("1111" if row[1] == "1" else "0000")
    #     return Data(
    #         name=bin_path.stem,
    #         binary_path=str(bin_path),
    #         labels=byte_labels
    #     )
    
    def _load(self, subset_path: str, subset_name: str | None) -> dict[str, Data] | None:
        # Implementation for loading subset of loadstar dataset
        bins_dir = Path(subset_path) / "bins"
        labels_dir = Path(subset_path) / "labeled"
        if not bins_dir.exists() or not labels_dir.exists():
            logger.warning(f"Required directories (./bins or ./labeled) not found in {subset_path}. Return None.")
            return None

        data_dict = {}
        binaries = list(bins_dir.glob("*.PRG")) + list(bins_dir.glob("*.app"))
        for b in binaries:
            stem = b.stem
            label_file = labels_dir / f"{stem}.csv"
            if not label_file.exists():
                logger.warning(f"Label file {label_file} does not exist. Skipping.")
                continue
            with open(label_file, "r") as f:
                reader = csv.reader(f)
                reader.__next__()  # Skip header
                byte_labels = bitarray()
                for row in reader:
                    byte_labels.extend("1111" if row[1] == "1" else "0000")
            data_dict[b.name] = Data(
                name=b.name,
                binary_path=str(b),
                labels=byte_labels,
                subset=subset_name
            )
        return data_dict

    def load(self, loadstar_home: str) -> dict[str, Data]:
        home = Path(loadstar_home)
        dataset_config = {
            "NS_1": home / "Dataset" / "NS_1",
            "NS_2": home / "Dataset" / "NS_2",
            "NS_3": home / "Dataset" / "NS_3",
        }

        data_dict = {}
        for subset_name, path in dataset_config.items():
            subset_data = self._load(str(path), subset_name)
            if subset_data is not None:
                data_dict.update(subset_data)
        
        return data_dict

@register_dataloader
class ARMCoreutilsDataLoader(DataLoader):
    def load(self, coreutils_arm_home: str) -> dict[str, Data]:
        home = Path(coreutils_arm_home)
        binary_path = home / "build-output" / "usr" / "arm32"
        label_path = home / "labeled"
        binaries = list(binary_path.glob("*"))

        data_dict = {}
        for b in binaries:
            stem = b.stem
            label_file = label_path / f"{stem}.csv"
            if not label_file.exists():
                logger.warning(f"Label file {label_file} does not exist. Skipping.")
                continue
            with open(label_file, "r") as f:
                reader = csv.reader(f)
                reader.__next__()
                byte_labels = bitarray()
                for row in reader:
                    start, end, label = map(int, row)
                    size = end - start
                    byte_labels.extend("1" * size if label == 1 else "0" * size)
            
            data_dict[b.name] = Data(
                name=b.name,
                binary_path=str(b),
                labels=byte_labels,
                subset=None
            )
        return data_dict