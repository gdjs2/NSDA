import bisect
import pyghidra

from rich.spinner import Spinner
from ghidra.program.model.listing import Instruction # type: ignore
from ghidra.program.model.address import AddressSpace # type: ignore

def byte_level_evaluate(
    project_path: str,
    project_name: str,
    file_system_name: str,
    code_set: set[int],
    base: int | None = None,
    spinner: Spinner | None = None
) -> tuple[float, float, list[int], list[int]]:
    """
    OpenSSL evaluation
    """
    code_results_set = set()
    data_results_set = set()

    with pyghidra.open_project(project_path, project_name) as project:
        with pyghidra.program_context(project, file_system_name) as program:

            if base is not None:
                base_addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(base)
                transaction_id = program.startTransaction("Set image base")
                try:
                    program.setImageBase(base_addr, True)
                finally:
                    program.endTransaction(transaction_id, True)

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
                        data_results_set.add(range(addr.getOffset(), addr.getOffset() + code_unit.getLength()))
                    addr = addr.add(code_unit.getLength())
    
    error_code_list = list(code_results_set - code_set)
    error_data_list = list(data_results_set & code_set)
    tp = len(code_results_set & code_set)
    fp = len(code_results_set - code_set)
    fn = len(code_set - code_results_set)

    precision = tp / (tp + fp) if tp + fp > 0 else 0
    recall = tp / (tp + fn) if tp + fn > 0 else 0
    return precision, recall, error_code_list, error_data_list

def is_address_in_function(address, starts, code_list):
    # bisect_right finds the index where 'address' would be inserted to maintain order.
    # Therefore, the function boundary it MIGHT belong to is exactly one index to the left (-1).
    idx = bisect.bisect_right(starts, address) - 1
    
    # Check if the index is valid and if the address is within the end boundary
    if idx >= 0:
        start, end = code_list[idx]
        if start <= address <= end:  # (Change <= to < if your end boundary is exclusive)
            return True
            
    return False

def function_level_evaluate(
    project_path: str,
    project_name: str,
    file_system_name: str,
    code_set: set[int],
    function_boundaries: set[tuple[int, int]],
    base: int | None = None,
    spinner: Spinner | None = None
) -> tuple[float, float, list[int]]:
    """
    Chromium evaluation
    """
    code_results_set = set()

    starts = sorted(code_set)
    code_list = sorted(function_boundaries)
    
    with pyghidra.open_project(project_path, project_name) as project:
        with pyghidra.program_context(project, file_system_name) as program:

            if base is not None:
                base_addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(base)
                transaction_id = program.startTransaction("Set image base")
                try:
                    program.setImageBase(base_addr, True)
                finally:
                    program.endTransaction(transaction_id, True)
            
            functions = list(program.getFunctionManager().getFunctions(True))
            total_func = len(functions)

            for idx, func in enumerate(functions):
                if spinner: spinner.update(text=f"Processing function [{func.getName()}@{func.getEntryPoint()}] {idx * 100 / total_func:.2f}%")
                func_address = func.getEntryPoint().getOffset()
                if is_address_in_function(func_address, starts, code_list) and func_address not in code_set:
                    continue
                code_results_set.add(func_address)

    error_code_list = list(code_results_set - code_set)

    tp = len(code_results_set & code_set)
    fp = len(code_results_set - code_set)
    fn = len(code_set - code_results_set)
    precision = tp / (tp + fp) if tp + fp > 0 else 0
    recall = tp / (tp + fn) if tp + fn > 0 else 0
    return precision, recall, error_code_list
    