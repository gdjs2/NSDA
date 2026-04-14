import pyghidra
from loguru import logger

logger.remove()
logger.add("/tmp/test_single_binary.log", level="INFO")

pyghidra.start(install_dir="/opt/ghidra_11.3.2_PUBLIC")

from iterative_training import iterative_training
iterative_training(
    binary_path="/home/zhaoqi.xiao/Downloads/0105_Application.app",
    code_set=set(),
    base=0x0,
    iteration_limit=10,
    epoches_limit=2000,
    keep_ghidra_prj=True,
    keep_ghidra_prj_path="/tmp/0105_Application.app",
    without_nn=False,
    language="ARM:LE:32:v5"
)