import os
import networkx as nx

from rich.spinner import Spinner
from blocks_helper import *
from ghidra.program.flatapi import FlatProgramAPI # pyright: ignore[reportMissingImports]
from ghidra.program.model.address import AddressSet # pyright: ignore[reportMissingImports]

def _get_fallthrough_edges(blocks: list[Block]):
    """
    Get fallthrough edges from the blocks.
    Args:
        blocks (list[Block]): List of code blocks.
    Returns:
        list[tuple[Block, Block]]: List of tuples representing fallthrough edges.
    """
    fall_through_edges = []
    blocks.sort(key=lambda b: b.start_address)

    for i in range(len(blocks) - 1):
        current_block = blocks[i]
        if current_block.pseudo_instrs is None:
            continue
        last_instr = current_block.pseudo_instrs[-1]
        if last_instr is None: continue
        if last_instr.hasFallthrough():
            next_block = blocks[i + 1]
            if next_block is not None:
                fall_through_edges.append((current_block, next_block))
    return fall_through_edges

def _bisearch_addr_in_blocks(blocks: list[Block], addr: Address) -> Block|None:
    """
    Binary search to find the block containing the address.
    Make sure blocks are sorted by (section_name, start_address).
    Args:
        blocks (list[Block]): List of blocks to search.
        addr (Address): Address to find.
    Returns:
        Block | None: The block containing the address, or None if not found.
    """
    left, right = 0, len(blocks)
    while left < right:
        mid = (left + right) >> 1
        if blocks[mid].start_address <= addr <= blocks[mid].end_address:
            return blocks[mid]
        elif addr < blocks[mid].start_address:
            right = mid
        elif addr > blocks[mid].end_address:
            left = mid + 1
    # logger.error(f"Address {addr} not found in blocks. May be a external reference.")
    return None

def _get_call_edges(blocks: list[Block], listing: Listing, spinner: Spinner | None = None) -> list[tuple[Block, Block]]:
    """
    Get call edges between blocks.
    Args:
        blocks (list[Block]): List of code blocks.
        listing (Listing): Ghidra listing object to get instructions and references.
        spinner (Spinner | None): Spinner object for progress indication.
    Returns:
        list[tuple[Block, Block]]: List of tuples representing call edges.
    """
    call_edges = []
    blocks.sort(key=lambda b: b.start_address)

    for idx, block in enumerate(blocks):
        if spinner: spinner.update(text=f"[bold yellow]Extracting call edges from block {idx + 1}/{len(blocks)}...[/bold yellow]")
        if block.type != 'Code': continue
        addr_set = AddressSet(block.start_address, block.end_address)
        instructions = listing.getInstructions(addr_set, True)
        for instr in instructions:
            refs = instr.getReferencesFrom()
            for ref in refs:
                if ref.getReferenceType().isFlow():
                    target_block = _bisearch_addr_in_blocks(blocks, ref.getToAddress())
                    if target_block is not None:
                        call_edges.append((block, target_block))
    return call_edges

def create_graph(
    flat_api: FlatProgramAPI, 
    spinner: Spinner | None = None,
    start_addr: Address | None = None,
    end_addr: Address | None = None,
) -> nx.DiGraph:
    """
    Create a directed graph from the functions in the program.
    Args:
        flat_api (FlatProgramAPI): Flat API instance to interact with the Ghidra program.
        spinner (Spinner | None): Spinner object for progress indication.
        start_addr (Address | None): The starting address of the range to analyze.
        end_addr (Address | None): The ending address of the range to analyze.
    Returns:
        nx.DiGraph: Relational graph of the program.
    """
    program = flat_api.getCurrentProgram()
    listing = program.getListing()
    memory = program.getMemory()

    if spinner: spinner.update(text=f"[bold yellow]Extracting blocks and edges from the program...[/bold yellow]")
    if start_addr is not None and end_addr is not None:
        blocks = extract_blocks_in_range(listing, memory, start_addr, end_addr, spinner)
    else:
        blocks = extract_all_blocks(listing, memory, spinner)
    blocks.sort(key=lambda b: b.start_address)
    
    if spinner: spinner.update(text=f"[bold yellow]Performing pseudo-disassembly...[/bold yellow]")
    pseudo_disassemble_blocks(blocks, program, spinner)
    if spinner: spinner.update(text=f"[bold yellow]Splitting data blocks...[/bold yellow]")
    blocks = split_data_blocks(blocks, spinner)

    # fall_through_edges = _get_fallthrough_edges(blocks)
    if spinner: spinner.update(text=f"[bold yellow]Extracting call edges from the program...[/bold yellow]")
    call_edges = _get_call_edges(blocks, listing, spinner)
            
    graph = nx.DiGraph()
    graph.add_nodes_from(blocks)
    # graph.add_edges_from(fall_through_edges, type="fallthrough")
    graph.add_edges_from(call_edges, type="call")

    return graph
    
    
if __name__ == "__main__":
    with pyghidra.open_program('/home/zhaoqi.xiao/Projects/Loadstar/Dataset/NS_3/bins/xor_st.app', language='ARM:LE:32:v4') as flat_api:
        graph = create_graph(flat_api)
        blocks = list(graph.nodes)
        blocks.sort(key=lambda b: b.start_address)

    time_stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    if argv[1] == "debug":
        if not os.path.exists(f"./debug/{time_stamp}"):
            os.makedirs(f"./debug/{time_stamp}")
        with open(f"./debug/{time_stamp}/graph_helper_blocks.txt", "w") as f:
            for block in blocks:
                f.write(f"{block}\n")

        with open(f"./debug/{time_stamp}/graph_helper_edges.txt", "w") as f:
            for u, v in graph.edges():
                f.write(f"{u} -> {v} ({graph[u][v]['type']})\n")
    
        logger.info(f"Debug information saved to ./debug/graph_helper_blocks.txt and ./debug/graph_helper_edges.txt")