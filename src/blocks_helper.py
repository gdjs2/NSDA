import torch
import pyghidra

from sys import argv
from loguru import logger
from rich.spinner import Spinner
from typing import Literal, Self

from ghidra.program.model.address import Address # type: ignore
from ghidra.program.model.pcode import PcodeOp # type: ignore
from ghidra.program.model.listing import Instruction, Listing, Program # type: ignore
from ghidra.program.model.scalar import Scalar # type: ignore
from ghidra.program.model.mem import Memory # type: ignore
from ghidra.program.model.symbol import ReferenceManager # type: ignore
from ghidra.app.util import PseudoDisassembler, PseudoDisassemblerContext, PseudoInstruction # type: ignore

COMPARISON_OPCODES = [
    PcodeOp.INT_EQUAL,
    PcodeOp.INT_NOTEQUAL,
    PcodeOp.INT_LESS,
    PcodeOp.INT_LESSEQUAL,
    PcodeOp.INT_SLESS,
    PcodeOp.INT_SLESSEQUAL,
]

ARITHMETIC_OPCODES = [
    PcodeOp.INT_ADD, 
    PcodeOp.INT_SUB, 
    PcodeOp.INT_MULT, 
    PcodeOp.INT_DIV
]

class Block:
    """
    Represents a block of code or data in the program.
    Attributes:
        start_address (Address): The starting address of the block.
        end_address (Address): The ending address of the block.
        type (Literal["Code", "Data", "Unknown"]): The type of the block, either "Code" or "Data".
        section_name (str): The name of the section the block belongs to.
        cond_branch_flg (bool|None): Flag indicating if the block contains conditional branches.
        def_use_flg (bool|None): Flag indicating if the block has def-use relationships.
        very_short_flg (bool|None): Flag indicating if the block is very short.
        high_zero_rate_flg (bool|None): Flag indicating if the block has a high rate of zero bytes.
        high_def_use_rate_flg (bool|None): Flag indicating if the block has a high def-use rate.
        high_cont_printable_char_rate_flg (bool|None): Flag indicating if the block has a high rate of continuous printable characters.
        feature_vector (list[float]|None): Feature vector representing various characteristics of the block.
        pseudo_instrs (list[PseudoInstruction]|None): List of pseudo instructions in the block.
    """
    def __init__(
            self: Self, 
            start_address: Address, 
            end_address: Address, 
            type: Literal["Code", "Data", "Unknown"], 
            section_name: str,
            is_executable: bool 
        ) -> None:
        """
        Initializes a Block instance.
        Args:
            start_address (Address): The starting address of the block.
            end_address (Address): The ending address of the block.
            type (str): The type of the block, either "Code" or "Data".
            section_name (str): The name of the section the block belongs to.
            is_executable (bool): Flag indicating if the block is executable.
        """
        self.start_address: Address = start_address
        self.end_address: Address = end_address
        self.type: Literal["Code", "Data", "Unknown"] = type
        self.section_name: str = section_name
        self.is_executable: bool = is_executable
        self.cond_branch_flg: bool|None = None
        self.def_use_flg: bool|None = None
        self.very_short_flg: bool|None = None
        self.high_zero_rate_flg: bool|None = None
        self.high_def_use_rate_flg: bool|None = None
        self.high_cont_printable_char_rate_flg: bool|None = None
        self.failed_disasm_flg: bool|None = None

        self.feature_vector: list[float]|None = None
        self.pseudo_instrs: list[PseudoInstruction]|None = None

    def __repr__(self: Self) -> str:
        return (
            f"{self.type}Block:\n"
            f"  Address Range : [{self.start_address} - {self.end_address}] (l{self.start_address.getOffset()//4 + 1} - l{self.end_address.getOffset()//4 + 1})\n"
            f"  Section       : [{self.section_name}]\n"
            f"  Flags:\n"
            f"    cond_branch        : {self.cond_branch_flg}\n"
            f"    def_use            : {self.def_use_flg}\n"
            f"    very_short         : {self.very_short_flg}\n"
            f"    high_zero_rate     : {self.high_zero_rate_flg}\n"
            f"    high_def_use_rate  : {self.high_def_use_rate_flg}\n"
            f"    high_printable_char: {self.high_cont_printable_char_rate_flg}\n"
            f"    failed_disasm      : {self.failed_disasm_flg}\n"
            f"  Feature Vector: {self.feature_vector}"
        )

    def __str__(self: Self) -> str:
        return (
            f"{self.type}Block @ [{self.start_address} - {self.end_address}]"
        )

    @property
    def size(self: Self) -> int:
        """
        Get the size of the block in bytes.
        Returns:
            int: The size of the block.
        """
        return self.end_address.subtract(self.start_address) + 1

def extract_all_blocks(listing: Listing, memory: Memory, spinner: Spinner | None = None) -> list[Block]:
    """
    Extract all code and data blocks from the program's listing and memory.
    Args:
        listing (Listing): The program's listing containing code units.
        memory (Memory): The program's memory containing blocks.
        spinner (Spinner | None): Optional spinner for displaying progress.
    Returns:
        list[Block]: A combined list of code and data Block instances.
    """
    blocks: list[Block] = []
    total = len(memory.getBlocks())

    for idx, mmry_blk in enumerate(memory.getBlocks()):
        
        if spinner: spinner.update(text=f"[bold yellow]Extracting blocks and edges from the program {idx + 1}/{total}...[/bold yellow]")

        addr = mmry_blk.getStart()
        blk_end_addr = mmry_blk.getEnd().subtract(1)

        is_executable = mmry_blk.isExecute()

        in_code_block = False
        code_start = None

        in_data_block = False
        data_start = None

        in_unknown_block = False
        unknown_start = None

        start_offset = addr.getOffset()
        end_offset = blk_end_addr.getOffset()

        while addr <= blk_end_addr:
            current_offset = addr.getOffset()
            if spinner: spinner.update(text=f"[bold yellow]Extracting blocks and edges from the program {idx + 1}/{total}... ({(current_offset - start_offset) * 100 // (end_offset - start_offset + 1)}%) [/bold yellow]")

            code_unit = listing.getCodeUnitAt(addr)

            if isinstance(code_unit, Instruction):
                code_unit: Instruction = code_unit
                # Close any ongoing data block
                if in_data_block:
                    block_end = code_unit.getMinAddress().subtract(1)
                    blocks.append(Block(data_start, block_end, "Data", mmry_blk.getName(), is_executable))
                    in_data_block = False
                    data_start = None
                
                if in_unknown_block:
                    block_end = code_unit.getMinAddress().subtract(1)
                    blocks.append(Block(unknown_start, block_end, "Unknown", mmry_blk.getName(), is_executable))
                    in_unknown_block = False
                    unknown_start = None

                if not in_code_block:
                    code_start = addr
                    in_code_block = True

                flow_type = code_unit.getFlowType()

                if flow_type is not None and (flow_type.isCall() or flow_type.isJump() or flow_type.isTerminal()):
                    block_end = code_unit.getMaxAddress()
                    blocks.append(Block(code_start, block_end, "Code", mmry_blk.getName(), is_executable))
                    in_code_block = False
                    code_start = None

            else:
                if code_unit.getMnemonicString() == "??": # Unknown Block
                    # Close any ongoing code block
                    if in_code_block:
                        block_end = code_unit.getMinAddress().subtract(1)
                        blocks.append(Block(code_start, block_end, "Code", mmry_blk.getName(), is_executable))
                        in_code_block = False
                        code_start = None

                    if in_data_block:
                        block_end = code_unit.getMinAddress().subtract(1)
                        blocks.append(Block(data_start, block_end, "Data", mmry_blk.getName(), is_executable))
                        in_data_block = False
                        data_start = None

                    if not in_unknown_block:
                        unknown_start = addr
                        in_unknown_block = True
                else: # Data Block
                    # Close any ongoing code block
                    if in_code_block:
                        block_end = code_unit.getMinAddress().subtract(1)
                        blocks.append(Block(code_start, block_end, "Code", mmry_blk.getName(), is_executable))
                        in_code_block = False
                        code_start = None

                    if in_unknown_block:
                        block_end = code_unit.getMinAddress().subtract(1)
                        blocks.append(Block(unknown_start, block_end, "Unknown", mmry_blk.getName(), is_executable))
                        in_unknown_block = False
                        unknown_start = None

                    if not in_data_block:
                        data_start = addr
                        in_data_block = True

            addr = addr.add(code_unit.getLength())

        # Handle block at the very end
        if in_code_block:
            blocks.append(Block(code_start, blk_end_addr, "Code", mmry_blk.getName(), is_executable))
        if in_data_block:
            blocks.append(Block(data_start, blk_end_addr, "Data", mmry_blk.getName(), is_executable))
        if in_unknown_block:
            blocks.append(Block(unknown_start, blk_end_addr, "Unknown", mmry_blk.getName(), is_executable))

    return blocks

def pseudo_disassemble_blocks(blocks: list[Block], program: Program, spinner: Spinner | None = None) -> None:
    """
    Pseudo disassemble the blocks using the PseudoDisassembler, default in ARM mode (SEE TODO).
    Args:
        blocks (list[Block]): The list of blocks to pseudo disassemble.
        program (Program): The program containing the blocks.
    Returns:
        None: The blocks will be updated in place with their pseudo instructions.
    """
    pseudo_disassembler = PseudoDisassembler(program)
    alignment = program.getLanguage().getInstructionAlignment()
    total = len(blocks)

    for idx, block in enumerate(blocks):
        if spinner: spinner.update(text=f"[bold yellow]Pseudo disassembling block {idx + 1}/{total}...[/bold yellow]")
        ctx = PseudoDisassemblerContext(program.getProgramContext())
        # tmode_reg = program.getRegister("TMode")
        # If you don't care about thumb mode, just comment the next line
        # ctx.setValue(tmode_reg, block.start_address, BigInteger.ZERO)
        ctx.flowStart(block.start_address)

        instrs: list[PseudoInstruction] = []
        addr = block.start_address
        while addr <= block.end_address:
            instr = pseudo_disassembler.disassemble(addr, ctx, False)
            instrs.append(instr)
            if instr is not None:
                addr = instr.getMaxAddress().next()
            else:
                block.failed_disasm_flg = True
                addr = addr.add(alignment)
        if block.failed_disasm_flg is None:
            block.failed_disasm_flg = False
        block.pseudo_instrs = instrs

def split_data_blocks(blocks: list[Block], spinner: Spinner | None = None) -> list[Block]:
    splited_blocks = []
    total = len(blocks)
    for idx, block in enumerate(blocks):
        if spinner: spinner.update(text=f"[bold yellow]Splitting data blocks {idx + 1}/{total}...[/bold yellow]")
        if block.type == "Code" or block.pseudo_instrs is None:
            splited_blocks.append(block)
            continue
        last_instr_idx = 0
        last_instr_address = block.start_address
        for idx, instr in enumerate(block.pseudo_instrs):
            if instr is None: continue
            flow_type = instr.getFlowType()
            if flow_type is not None and (flow_type.isCall() or flow_type.isJump() or flow_type.isTerminal()):
                # logger.debug(f"Split {block} @ {instr.getMaxAddress()} by {instr}, flow type: {instr.getFlowType()}")
                new_block = Block(last_instr_address, instr.getMaxAddress(), block.type, block.section_name, block.is_executable)
                new_block.pseudo_instrs = block.pseudo_instrs[last_instr_idx:idx + 1]
                new_block.failed_disasm_flg = None in new_block.pseudo_instrs
                splited_blocks.append(new_block)
                last_instr_idx = idx + 1
                last_instr_address = instr.getMaxAddress().add(1)
        # Append any remaining instructions as a new block
        if last_instr_idx < len(block.pseudo_instrs):
            new_block = Block(last_instr_address, block.end_address, block.type, block.section_name, block.is_executable)
            new_block.pseudo_instrs = block.pseudo_instrs[last_instr_idx:]
            splited_blocks.append(new_block)
            new_block.failed_disasm_flg = None in new_block.pseudo_instrs

    return splited_blocks

def get_string_number(block: Block, refs: ReferenceManager, listing: Listing) -> int:
    """
    Get the string number of the block.
    Args:
        block (Block): The block to analyze.
        refs (ReferenceManager): The reference manager to get references from.
        listing (Listing): The program's listing to get data from.
    Returns:
        int: The number of strings in the block.
    """
    string_number = 0
    if not block.pseudo_instrs: 
        return string_number
    for instr in block.pseudo_instrs:
        if instr is None: continue
        addr = instr.getAddress()
        references = refs.getReferencesFrom(addr)
        for ref in references:
            to_addr = ref.getToAddress()
            data = listing.getDataAt(to_addr)
            if data and data.hasStringValue():
                string_number += 1
    return string_number

def get_num_constant(block: Block) -> int:
    """
    Get the number of constant values in the block.
    Args:
        block (Block): The block to analyze.
    Returns:
        int: The number of constant values in the block.
    """
    constant_count = 0
    if not block.pseudo_instrs:
        return constant_count
    for instr in block.pseudo_instrs:
        if instr is None: continue
        for i in range(instr.getNumOperands()):
            objs = instr.getOpObjects(i)
            for obj in objs:
                if isinstance(obj, Scalar) or isinstance(obj, Address):
                    constant_count += 1
    return constant_count

def get_transfer_number(block: Block) -> int:
    """
    Get the number of transfer instructions in the block.
    Args:
        block (Block): The block to analyze.
    Returns:
        int: The number of transfer instructions in the block.
    """
    transfer_count = 0
    if not block.pseudo_instrs:
        return transfer_count
    for instr in block.pseudo_instrs:
        if instr is None: continue
        if instr.getFlowType().isCall() or instr.getFlowType().isJump() or instr.getFlowType().isTerminal():
            transfer_count += 1
    return transfer_count

def get_call_number(block: Block) -> int:
    """
    Get the number of call instructions in the block.
    Args:
        block (Block): The block to analyze.
    Returns:
        int: The number of call instructions in the block.
    """
    call_count = 0
    if not block.pseudo_instrs:
        return call_count
    for instr in block.pseudo_instrs:
        if instr is None: continue
        if instr.getFlowType().isCall():
            call_count += 1
    return call_count

def get_instr_number(block: Block) -> int:
    """
    Get the number of instructions in the block.
    Args:
        block (Block): The block to analyze.
    Returns:
        int: The number of instructions in the block.
    """
    return sum(i is not None for i in block.pseudo_instrs) if block.pseudo_instrs else 0

def get_arithmetic_number(block: Block) -> int:
    """
    Get the number of arithmetic instructions in the block.
    """
    arithmetic_count = 0
    if not block.pseudo_instrs:
        return arithmetic_count
    for instr in block.pseudo_instrs:
        if instr is None: continue
        pcode_ops = instr.getPcode()
        for op in pcode_ops:
            if op.getOpcode() in ARITHMETIC_OPCODES:
                arithmetic_count += 1
    return arithmetic_count

def get_zero_bytes_number(block: Block, memory: Memory) -> int:
    """
    Get the number of zero bytes in the block. This function will also set the `high_zero_rate_flg` attribute of the block.
    Args:
        block (Block): The block to analyze.
        memory (Memory): The program's memory to read bytes from.
    Returns:
        int: The number of zero bytes in the block.
    """
    zero_bytes_cnt = 0
    addr = block.start_address
    while addr <= block.end_address:
        try:
            data = memory.getByte(addr) & 0xFF
            if data == 0:
                zero_bytes_cnt += 1
        except:
            pass
        addr = addr.add(1)
    if zero_bytes_cnt * 2 >= block.end_address.subtract(block.start_address):
        block.high_zero_rate_flg = True
    else:
        block.high_zero_rate_flg = False
    return zero_bytes_cnt

def get_def_use_number(block: Block) -> int:
    """
    Get the number of def-use relationships in the block. This function will also set the `high_def_use_rate_flg` attribute of the block.
    Args:
        block (Block): The block to analyze.
        memory (Memory): The program's memory to read bytes from.
    Returns:
        int: The number of def-use relationships in the block.
    """
    def_use_cnt = 0
    defs = {}
    if block.pseudo_instrs is None:
        block.high_def_use_rate_flg = False
        return def_use_cnt
    for i, instr in enumerate(block.pseudo_instrs):
        for d in defs:
            if defs[d] - i > 16:
                del defs[d]
        if instr is None: continue
        pcode_ops = instr.getPcode()
        instr_def = {}
        for op in pcode_ops:
            uses = op.getInputs()
            for use in uses:
                if use in defs:
                    def_use_cnt += 1
            instr_def[op.getOutput()] = i
        defs.update(instr_def)
    
    if def_use_cnt * 3 >= block.end_address.subtract(block.start_address):
    # if def_use_cnt >= 1:
        block.high_def_use_rate_flg = True
    else:
        block.high_def_use_rate_flg = False
    return def_use_cnt

def get_printable_char_number(block: Block, memory: Memory) -> int:
    """
    Get the number of printable characters in the block. This function will also set the `high_cont_printable_char_rate_flg` attribute of the block.
    Args:
        block (Block): The block to analyze.
        memory (Memory): The program's memory to read bytes from.
    Returns:
        int: The number of printable characters in the block.
    """
    printable_count = 0
    continous_printable_count = 0
    addr = block.start_address
    while addr <= block.end_address:
        try:
            data = memory.getByte(addr) & 0xFF
            if data >= 32 and data <= 126:  # ASCII printable range
                printable_count += 1
                continous_printable_count += 1
            else:
                continous_printable_count = 0
        except: # Reading memory may fail if the address is not valid
            pass
        addr = addr.add(1)
    if continous_printable_count * 2 >= block.end_address.subtract(block.start_address):
        block.high_cont_printable_char_rate_flg = True
    else:
        block.high_cont_printable_char_rate_flg = False
    return printable_count

def analyze_memory_features(block: Block, memory: Memory) -> tuple[int, int]:
    """
    Analyze memory-related features in a single memory scan.
    Args:
        block (Block): The block to analyze.
        memory (Memory): The program's memory to read bytes from.
    Returns:
        tuple[int, int]: (zero_bytes_count, printable_count)
    """
    zero_bytes_cnt = 0
    printable_count = 0
    continous_printable_count = 0

    addr = block.start_address
    while addr <= block.end_address:
        try:
            data = memory.getByte(addr) & 0xFF

            if data == 0:
                zero_bytes_cnt += 1

            if 32 <= data <= 126:  # ASCII printable range
                printable_count += 1
                continous_printable_count += 1
            else:
                continous_printable_count = 0
        except:  # Reading memory may fail if the address is not valid
            pass

        addr = addr.add(1)

    block_span = block.end_address.subtract(block.start_address)
    block.high_zero_rate_flg = zero_bytes_cnt * 2 >= block_span
    block.high_cont_printable_char_rate_flg = continous_printable_count * 2 >= block_span

    return zero_bytes_cnt, printable_count

def analyze_instruction_features(block, refs, listing):
    string_number = 0
    constant_count = 0
    transfer_count = 0
    call_count = 0
    instr_count = 0
    arithmetic_count = 0
    def_use_cnt = 0

    defs = {}

    if not block.pseudo_instrs:
        block.high_def_use_rate_flg = False
        return (0,0,0,0,0,0,0)

    for i, instr in enumerate(block.pseudo_instrs):

        if instr is None:
            continue

        instr_count += 1

        addr = instr.getAddress()
        flow = instr.getFlowType()

        # transfer + call
        if flow.isCall():
            call_count += 1
            transfer_count += 1
        elif flow.isJump() or flow.isTerminal():
            transfer_count += 1

        # references → strings
        for ref in refs.getReferencesFrom(addr):
            data = listing.getDataAt(ref.getToAddress())
            if data and data.hasStringValue():
                string_number += 1

        # constants
        for iop in range(instr.getNumOperands()):
            for obj in instr.getOpObjects(iop):
                if isinstance(obj, Scalar) or isinstance(obj, Address):
                    constant_count += 1

        # pcode
        pcode_ops = instr.getPcode()
        instr_def = {}

        for op in pcode_ops:

            if op.getOpcode() in ARITHMETIC_OPCODES:
                arithmetic_count += 1

            for use in op.getInputs():
                if use in defs:
                    def_use_cnt += 1

            out = op.getOutput()
            if out is not None:
                instr_def[out] = i

        defs.update(instr_def)

        # prune old defs
        for d in list(defs):
            if defs[d] - i > 16:
                del defs[d]

    block_size = block.end_address.subtract(block.start_address)

    block.high_def_use_rate_flg = def_use_cnt * 3 >= block_size

    return (
        string_number,
        constant_count,
        transfer_count,
        call_count,
        instr_count,
        arithmetic_count,
        def_use_cnt,
    )



def get_feature_vector(blocks, refs, listing, memory, spinner=None):

    for idx, block in enumerate(blocks):

        if spinner:
            spinner.update(
                text=f"[bold yellow]Getting feature vectors for block {idx+1}/{len(blocks)}...[/bold yellow]"
            )

        block_size = block.end_address.subtract(block.start_address) + 1

        (
            string_number,
            constant_count,
            transfer_count,
            call_count,
            instr_count,
            arithmetic_count,
            def_use_cnt
        ) = analyze_instruction_features(block, refs, listing)

        zero_bytes_cnt, printable_count = analyze_memory_features(block, memory)

        block.feature_vector = [
            string_number / block_size,
            constant_count / block_size,
            transfer_count / block_size,
            call_count / block_size,
            instr_count / block_size,
            arithmetic_count / block_size,
            zero_bytes_cnt / block_size,
            def_use_cnt / block_size,
            printable_count / block_size,
        ]

def check_compare_branch(blocks: list[Block], program: Program, spinner: Spinner | None = None) -> None:
    """
    Check conditional branches in the blocks following a comparison instructions. 
    This function will set the `cond_branch_flg` attribute of the block.
    Args:
        blocks (list[Block]): The list of blocks to analyze.
        program (Program): The program containing the blocks.
        spinner (Spinner | None): Spinner object for progress indication.
    Returns:
        None: The blocks will be updated in place with their conditional branch flags.
    """
    for idx, block in enumerate(blocks):
        if spinner: spinner.update(text=f"[bold yellow]Checking compare branch for block {idx + 1}/{len(blocks)}...[/bold yellow]")
        if block.pseudo_instrs is None: 
            block.cond_branch_flg = None
            continue
        instrs = block.pseudo_instrs[::-1]  # Reverse the order to check from the end
        first_instr = instrs[0]
        if first_instr is None:
            block.cond_branch_flg = None
        elif first_instr.getFlowType().isConditional():
            # Check if the second instruction is a comparison
            detect_comp_flg = False
            for instr in instrs[1:]:
                if instr is None: continue
                pcode_ops = instr.getPcode()
                if any(op.getOpcode() in COMPARISON_OPCODES for op in pcode_ops):
                    detect_comp_flg = True
                    break
            block.cond_branch_flg = detect_comp_flg
    return

def generate_embeddings_from_feature_vector(blocks: list[Block], spinner: Spinner | None = None) -> torch.Tensor:
    """
    Generate embeddings from the feature vector of the blocks.
    Args:
        blocks (list[Block]): The list of blocks to generate embeddings from.
        spinner (Spinner | None): Spinner object for progress indication.
    Returns:
        torch.Tensor: A tensor containing the embeddings for each block.
    """
    embeddings = []
    total = len(blocks)
    for idx, block in enumerate(blocks):
        if spinner: spinner.update(text=f"[bold yellow]Generating embedding for block {idx + 1}/{total}...[/bold yellow]")
        embeddings.append(torch.tensor(block.feature_vector, dtype=torch.float32))
    return torch.stack(embeddings, dim=0)

def generate_random_embeddings(blocks, dim=16):
    n = len(blocks)
    embeddings = torch.randn(n, dim)
    return embeddings
