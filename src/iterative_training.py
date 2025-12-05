import math
import shutil
import argparse

from ltn_helper import *
from pathlib import Path
from datetime import datetime
from functools import reduce
from bitarray import bitarray

results = []

geomean = lambda x: math.exp(sum(map(math.log, x)) / len(x))

def redisasemble(
        CodeBlock: ltn.Predicate, 
        binary_path: str,
        my_program: MyProgram
    ) -> bool:
    """
    Re-disassemble the blocks using the trained CodeBlock model.
    """
    flg = True
    with pyghidra.open_program(binary_path, language='ARM:LE:32:v5') as flat_api:
        for block, emb in zip(my_program.blocks, my_program.embeddings):
            if CodeBlock(ltn.Constant(emb)).value >= 0.5 and block.type == "Data" and not block.failed_disasm_flg:
                flat_api.clearListing(block.start_address, block.end_address)
            if flat_api.disassemble(block.start_address):
                flg = False
            # logger.debug(f"Re-disassembled block {block.start_address} in {binary_path}")
    return flg

def delete_ghidra_cache(binary_path: str):
    ghidra_folder = f"{binary_path}_ghidra"
    if Path(ghidra_folder).exists() and Path(ghidra_folder).is_dir():
        shutil.rmtree(ghidra_folder)
        logger.info(f"Deleted ghidra cache folder {ghidra_folder}")

def iterative_training(
    binary_path: str, 
    code_set: set[int],
    base: int | None,
    iteration_limit: int = 1,
    epoches_limit: int = 500
) -> tuple[float, float, float, float, float, list[int], list[int]]: # Code Precision, Code Recall, Data Precision, Data Recall, Preprocessing Time, Training Time, Redisassemble Time
    finish_flg = False
    iteration_cnt = 0
    delete_ghidra_cache(binary_path)

    total_training_time = .0
    total_redisassemble_time = .0
    while not finish_flg and iteration_cnt < iteration_limit:
        CodeBlock = None
        iteration_cnt += 1
        preprocess_start_time = datetime.now()
        with pyghidra.open_program(binary_path, language='ARM:LE:32:v5') as flat_api:
            my_program = MyProgram(flat_api, base=base)
        preprocess_time = (datetime.now() - preprocess_start_time).total_seconds()
        logger.info(f"Program preprocessed in {preprocess_time:.2f}s with {len(my_program.blocks)} blocks")
        training_start_time = datetime.now()
        CodeBlock, _ = train(my_program, CodeBlock, epoches_limit)
        total_training_time += (datetime.now() - training_start_time).total_seconds()
        redisasemble_start_time = datetime.now()
        finish_flg = redisasemble(CodeBlock, binary_path, my_program)
        total_redisassemble_time += (datetime.now() - redisasemble_start_time).total_seconds()
    delete_ghidra_cache(binary_path)
    code_precision, code_recall, error_code_list, error_data_list = evaluate(my_program, code_set)
    return code_precision, code_recall, preprocess_time, total_training_time, total_redisassemble_time, error_code_list, error_data_list

# def main(binaries, gt):
#     finish = False
#     iteration = 0
#     # Check and delete any "{binary}_ghidra" folders if they exist
#     for prg_file in binaries:
#         ghidra_folder = f"{prg_file}_ghidra"
#         if Path(ghidra_folder).exists() and Path(ghidra_folder).is_dir():
#             shutil.rmtree(ghidra_folder)
#             logger.info(f"Deleted existing folder {ghidra_folder}")

#     whole_start_time = datetime.now()
#     while not finish and iteration < 4:
#         CodeBlock = None
#         code_f1s, data_f1s = [], []
#         iteration += 1
#         my_programs: dict[Path, MyProgram] = {}

#         process_times: list[tuple[str, float]] = []

#         for prg_file in binaries:
#             start_time = datetime.now()
#             with pyghidra.open_program(prg_file, language='ARM:LE:32:v4') as flat_api:
#                 my_program = MyProgram(flat_api)
#             process_times.append((prg_file.name, (datetime.now() - start_time).total_seconds()))
#             logger.info(f"Program {prg_file.name} preprocessed in {process_times[-1][1]:.2f}s")
#             my_programs[prg_file] = my_program
#         logger.info(f"All programs preprocessed in {sum(t[1] for t in process_times):.2f}s, total blocks: {sum(len(prg.blocks) for prg in my_programs.values())}")

#         # Small epoches is the epochs for training on each program
#         # We will train on all binaries for a few epochs, which is large_epochs
#         small_epochs = 300
#         large_epochs = 3
#         logger.info(f"Start training with {len(my_programs)} programs, small epochs: {small_epochs}, large epochs: {large_epochs}")

#         for i in range(large_epochs):
#             for prg_file in my_programs:
#                 logger.info(f"Training epoch {i + 1}/{large_epochs} on {prg_file.name}")
#                 CodeBlock, loss = train(my_programs[prg_file], CodeBlock, small_epochs)

#         logger.info("Training finished")

#         if CodeBlock is None:
#             logger.error("CodeBlock is None, training failed.")
#             raise RuntimeError("CodeBlock is None, training failed.")

#         finish = redisasemble(CodeBlock, my_programs)

#         timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
#         if CodeBlock is None:
#             logger.error("CodeBlock is None, training failed.")
#             exit(1)

#         for prg_file, gt_file in zip(my_programs, gt):
#             try:
#                 results = evaluate(my_programs[prg_file], CodeBlock, 0.5, gt_file, Path(f"debug/{timestamp}/{prg_file.name}"), True)
#                 code_f1s.append(results["code_f1"])
#                 data_f1s.append(results["data_f1"])
#             except Exception as e:
#                 logger.info(f"Error evaluating {gt_file}: {e}")
        
#         with open(f"debug/{timestamp}/batch_results.txt", "w") as f:
#             f.write(f"Binaires: {binaries}\n")
#             f.write(f"Code F1 scores: {code_f1s}\n")
#             f.write(f"Data F1 scores: {data_f1s}\n")
#         logger.info(f"F1 Score Geomean: {geomean(code_f1s):.5f} for code, {geomean(data_f1s):.5f} for data")

#         if CodeBlock: torch.save(CodeBlock.state_dict(), f"debug/{timestamp}/CodeBlock.pth")
#         logger.info(f"Saved CodeBlock model to debug/{timestamp}/CodeBlock.pth")

#     return {
#         "bin_name": prg_file.name,
#         "code_f1": code_f1s,
#         "data_f1": data_f1s,
#         # "training_time": results["time"],
#         "total_time": (datetime.now() - whole_start_time).total_seconds()
#     }

# if __name__ == "__main__":
#     parser = argparse.ArgumentParser(description="Batch training and evaluation script.")
#     parser.add_argument('--single_training', type=str)
#     parser.add_argument('--batch_training', type=str)
#     parser.add_argument('--binary_folder', type=str, help='Path to the binary folder')
#     parser.add_argument('--test_binary', type=str, help='Path to the test binary')
#     args = parser.parse_args()

#     if args.test_binary:
#         bin_file = Path(args.test_binary)
#         gt = [Path(p).with_name(Path(p).name).with_suffix('.txt').as_posix().replace("/bins/", "/fixed_labeled/") for p in [bin_file]]
#         if "ghidra" in bin_file.name or not os.path.exists(gt[0]):
#             logger.error(f"Test binary {bin_file} or its ground truth {gt[0]} does not exist.")
#         else:
#             result = main([bin_file], gt)
#             print(f"{result}\n")
            

#     dataset = "ns_1" if "NS_1" in args.binary_folder else "ns_3" if "NS_3" in args.binary_folder else "ns_2"
#     result_file = open(f"{dataset}_results.txt", "w") 
#     if args.batch_training:
#         binaries, gt = binary_input(args.binary_folder)
#         result = main(binaries[:5], gt)
#         result_file.write(f"{result}\n")
#         result_file.close()
#     elif args.single_training:
#         result_list = []
#         for bin in os.listdir(args.binary_folder):
#             bin_name = Path(bin).stem
#             # if "ton_ld" not in bin_name:
#             #     continue
#             bin_file = Path(f"{args.binary_folder}/{bin}")
#             gt = [Path(p).with_name(Path(p).name).with_suffix('.txt').as_posix().replace("/bins/", "/fixed_labeled/") for p in [bin_file]]
#             if "ghidra" in bin or not os.path.exists(gt[0]):
#                 continue
        
#             try:
#                 result = main([bin_file], gt)
#                 print(result)
#                 result_list.append(result)
#             except Exception as e:
#                 logger.error(f"Error processing {bin_file}: {e}")

#         for i in result_list:
#             result_file.write(f"{i}\n")
#         result_file.close()
