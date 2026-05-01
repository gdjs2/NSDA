from my_program_helper import *
from my_models import MLPClassifier
from ltn import fuzzy_ops
from datetime import datetime

from rich.spinner import Spinner

from ghidra.program.model.address import AddressSpace # type: ignore

def train(
        my_program: MyProgram,
        CodeBlock: ltn.Predicate|None = None, 
        epochs: int = 1000,
        wo_rules: bool = False,
        spinner: Spinner | None = None
    ) -> tuple[ltn.Predicate, float]:
    """
    Single iteration of training
    Args:
        my_program (MyProgram): The program containing the embeddings and blocks.
        CodeBlock (ltn.Predicate | None): Optional predicate for code blocks, if None, a new one will be created.
        epochs (int): Number of training epochs.
        progress (Progress | None): Optional progress bar for training, if None, no progress bar will be shown.
    Returns:
        tuple[ltn.Predicate, float]: The trained program, the CodeBlock predicate, and the final loss value.
    """
    if not CodeBlock: 
        CodeBlock = ltn.Predicate(MLPClassifier(input_dim=my_program.embeddings.size(1), hidden_dim1=32, hidden_dim2=64).to(ltn.device))

    SatAgg = fuzzy_ops.SatAgg(fuzzy_ops.AggregPMeanError(p=4))
    Forall = ltn.Quantifier(fuzzy_ops.AggregPMeanError(p=4), quantifier='f')

    Equiv = ltn.Connective(fuzzy_ops.Equiv(fuzzy_ops.AndProd(), fuzzy_ops.ImpliesReichenbach()))
    Implies = ltn.Connective(fuzzy_ops.ImpliesReichenbach())
    Not = ltn.Connective(fuzzy_ops.NotStandard())

    x_call, y_call= my_program.get_rel_vars("call")
    x_ft, y_ft = my_program.get_rel_vars("fallthrough")

    cond_brch_t = my_program.get_identity_vars("cond_branch_flg", True)
    cond_brch_f = my_program.get_identity_vars("cond_branch_flg", False)
    high_zero_rate = my_program.get_identity_vars("high_zero_rate_flg", True)
    high_cont_printable_char_rate = my_program.get_identity_vars("high_cont_printable_char_rate_flg", True)
    failed_disasm = my_program.get_identity_vars("failed_disasm_flg", True)

    disasm_gt_cb = my_program.get_identity_vars("type", "Code")
    disasm_gt_db = my_program.get_identity_vars("type", "Data")

    optimizer = torch.optim.Adam(list(CodeBlock.parameters()), lr=0.001)

    start = datetime.now()

    for epoch in range(epochs):
        
        if x_ft and y_ft:
            ltn.diag(x_ft, y_ft)
        if x_call and y_call:
            ltn.diag(x_call, y_call)

        optimizer.zero_grad()

        sat_agg_list = []
        if disasm_gt_cb: 
            sat_agg_list.append(Forall([disasm_gt_cb], CodeBlock(disasm_gt_cb)))
        if disasm_gt_db:
            sat_agg_list.append(Forall([disasm_gt_db], Not(CodeBlock(disasm_gt_db))))
        if wo_rules:
            pass
        else:
            if cond_brch_t:
                sat_agg_list.append(Forall([cond_brch_t], CodeBlock(cond_brch_t)))
            if cond_brch_f:
                sat_agg_list.append(Forall([cond_brch_f], Not(CodeBlock(cond_brch_f))))
            if high_zero_rate:
                sat_agg_list.append(Forall([high_zero_rate], Not(CodeBlock(high_zero_rate))))
            if x_ft and y_ft:
                sat_agg_list.append(Forall([x_ft, y_ft], Implies(CodeBlock(x_ft), CodeBlock(y_ft))))
            if x_call and y_call:
                sat_agg_list.append(Forall([x_call, y_call], Equiv(CodeBlock(x_call), CodeBlock(y_call))))
            if high_cont_printable_char_rate:
                sat_agg_list.append(Forall([high_cont_printable_char_rate], Not(CodeBlock(high_cont_printable_char_rate))))
            if failed_disasm:
                sat_agg_list.append(Forall([failed_disasm], Not(CodeBlock(failed_disasm))))

        sat_agg = SatAgg(*sat_agg_list)

        loss = 1. - sat_agg
        loss.backward()
        optimizer.step()
        if epoch % 100 == 0:
            logger.info(f"Epoch {epoch}, Loss: {loss.item():.5f}")
            if spinner: spinner.update(text=f"[bold yellow]Training... Epoch {epoch}/{epochs}, Loss: {loss.item():.2f}[/bold yellow]")
        if loss.item() < 0.01:
            logger.info(f"Early stopping at epoch {epoch}, Loss: {loss.item():.5f}")
            break

    logger.info(f"Training completed in {(datetime.now() - start).total_seconds():.2f}s, final loss: {loss.item():.5f}")

    return (CodeBlock, loss.item())

def evaluate(
    my_program: MyProgram,
    code_set: set[int],
) -> tuple[float, float, list[int], list[int]]:
    
    tp = fp = fn = 0
    error_code_list = []
    error_data_list = []

    code_results_set = set()
    data_results_set = set()

    for block in my_program.blocks:
        logger.debug(f"{block}")
        # space = block.start_address.getAddressSpace()
        if block.start_address.getAddressSpace().getType() != AddressSpace.TYPE_RAM:
            break
        # block_offsets = set(range(block.start_address.getOffset(), block.end_address.getOffset(), 4))
        if block.type == "Code":
            code_results_set.update(range(block.start_address.getOffset(), block.end_address.getOffset(), 4))
        else:
            data_results_set.update(range(block.start_address.getOffset(), block.end_address.getOffset(), 4))

    hits = code_results_set & code_set
    error_code_list = list(code_results_set - code_set)
    error_data_list = list(data_results_set & code_set)

    tp = len(hits)
    fp = len(error_code_list)
    fn = len(error_data_list)
    code_precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    code_recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0

    return (code_precision, code_recall, error_code_list, error_data_list)