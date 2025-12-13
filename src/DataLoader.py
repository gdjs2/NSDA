import csv

from bitarray import bitarray
from pathlib import Path
from abc import ABC, abstractmethod
from loguru import logger
from DataLoaderRegistry import register_dataloader

class Data:
    """
    Data class representing a binary and its associated ground truth code set.
    """
    def __init__(
        self, 
        name: str, 
        binary_path: str,
        code_set: set[int],
        subset: str | None = None
    ):
        """
        Initialize a Data instance.
        
        :param self: The instance of the Data class.
        :param name: The name of this Data in Dataset.
        :type name: str
        :param binary_path: The file path to the binary.
        :type binary_path: str
        :param code_set: The set of ground truth code addresses.
        :type code_set: set[int]
        :param subset: The subset this Data belongs to, if any.
        :type subset: str | None
        """
        self.name = name
        self.binary_path = binary_path
        self.code_set = code_set
        self.subset = subset

class DataLoader(ABC):
    """
    Abstract base class for data loaders.
    """
    @abstractmethod
    def load(self, source_path: str) -> dict[str, Data] | None:
        """
        Load data from the specified source path.

        :param self: The instance of the DataLoader class.
        :param source_path: The path to load data from.
        :type source_path: str
        :return: A dictionary mapping data names to Data instances, or None if loading fails.
        :rtype: dict[str, Data] | None
        """
        pass

@register_dataloader
class LoadstarDataLoader(DataLoader):
    """
    DataLoader for the Loadstar dataset.
    """
    def _load(self, subset_path: str, subset_name: str | None) -> dict[str, Data] | None:
        """
        Load data from a specific subset path.
        
        :param self: The instance of the LoadstarDataLoader class.
        :param subset_path: The path to the subset directory.
        :type subset_path: str
        :param subset_name: The name of the subset.
        :type subset_name: str | None
        :return: A dictionary mapping data names to Data instances, or None if required directories are missing.
        :rtype: dict[str, Data] | None
        """
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
                code_set = set()
                offset = 0x0
                for row in reader:
                    if row[1] == "0":
                        code_set.add(offset)
                    offset += 4
            data_dict[b.name] = Data(
                name=b.name,
                binary_path=str(b),
                code_set=code_set,
                subset=subset_name
            )
        return data_dict

    def load(self, loadstar_home: str) -> dict[str, Data] | None:
        """
        Load data from the Loadstar dataset home directory.
        
        :param self: The instance of the LoadstarDataLoader class.
        :param loadstar_home: The path to the Loadstar dataset home directory.
        :type loadstar_home: str
        :return: A dictionary mapping data names to Data instances, or None if loading fails.
        :rtype: dict[str, Data]
        """
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
    """
    DataLoader for the ARM32 Coreutils dataset.
    """
    def load(self, coreutils_arm_home: str) -> dict[str, Data] | None:
        """
        Load data from the ARM32 Coreutils dataset home directory.
        
        :param self: The instance of the ARMCoreutilsDataLoader class.
        :param coreutils_arm_home: The path to the ARM32 Coreutils dataset home directory.
        :type coreutils_arm_home: str
        :return: A dictionary mapping data names to Data instances, or None if loading fails.
        :rtype: dict[str, Data] | None
        """
        home = Path(coreutils_arm_home)
        binary_path = home / "build-output-armv4" / "stripped" / "usr" / "local" / "bin"
        label_path = home / "build-output-armv4" / "labels"
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
                code_set = set()
                for row in reader:
                    if row[3] == "0":
                        code_set.add(int(row[0], 16))
            
            data_dict[b.name] = Data(
                name=b.name,
                binary_path=str(b),
                code_set=code_set,
                subset=None
            )
        return data_dict

@register_dataloader
class MIPSCoreutilsDataLoader(DataLoader):
    """
    DataLoader for the MIPS Coreutils dataset.
    """
    def load(self, coreutils_mips_home: str) -> dict[str, Data] | None:
        """
        Load data from the MIPS Coreutils dataset home directory.
        
        :param self: The instance of the MIPSCoreutilsDataLoader class.
        :param coreutils_mips_home: The path to the MIPS Coreutils dataset home directory.
        :type coreutils_mips_home: str
        :return: A dictionary mapping data names to Data instances, or None if loading fails.
        :rtype: dict[str, Data] | None
        """
        home = Path(coreutils_mips_home)
        binary_path = home / "build-output-mips" / "stripped" / "usr" / "local" / "bin"
        label_path = home / "build-output-mips" / "labels"
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
                code_set = set()
                for row in reader:
                    if row[3] == "0":
                        code_set.add(int(row[0], 16))
            
            data_dict[b.name] = Data(
                name=b.name,
                binary_path=str(b),
                code_set=code_set,
                subset=None
            )
        return data_dict