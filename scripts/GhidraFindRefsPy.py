## ###
#  IP: GHIDRA
##
# Lists references to supplied addresses and resolves the containing function when possible.
# Usage: GhidraFindRefsPy.py 0x140C57478 0x14002BFA0
#@category Codex.Python
#@runtime Jython

from ghidra.program.model.address import Address
from ghidra.program.model.scalar import Scalar


def _parse_addresses():
    args = list(getScriptArgs())
    if not args:
        raise ValueError("Expected at least one address argument.")
    return [toAddr(value) for value in args]


def _get_function_name(addr):
    func = getFunctionContaining(addr)
    if func is None:
        return "<no-function>"
    return "%s @ %s" % (func.getName(), func.getEntryPoint())


def _iter_refs(addr):
    refs = getReferencesTo(addr)
    if refs is None:
        return []
    return list(refs)


def _match_operand_object(obj, target):
    if isinstance(obj, Address):
        return obj == target
    if isinstance(obj, Scalar):
        return obj.getUnsignedValue() == target.getOffset()
    return False


def _target_texts(target):
    offset = target.getOffset()
    return [
        "0x%x" % offset,
        "+ 0x%x" % offset,
        "+0x%x" % offset,
        "%x" % offset,
    ]


def _scan_instruction_operands(target):
    listing = currentProgram.getListing()
    hits = []
    seen = set()
    target_texts = _target_texts(target)
    instructions = listing.getInstructions(True)
    while instructions.hasNext():
        instruction = instructions.next()
        operand_count = instruction.getNumOperands()
        instruction_text = str(instruction).lower()
        for operand_index in range(operand_count):
            objects = instruction.getOpObjects(operand_index)
            if objects is None:
                continue
            matched = False
            for obj in objects:
                if _match_operand_object(obj, target):
                    matched = True
                    break
            if not matched:
                rendered = instruction.getDefaultOperandRepresentation(operand_index)
                if rendered is not None:
                    rendered = rendered.lower()
                    for target_text in target_texts:
                        if target_text in rendered:
                            matched = True
                            break
            if not matched:
                for target_text in target_texts:
                    if target_text in instruction_text:
                        matched = True
                        break
            if matched:
                key = "%s:%d" % (instruction.getAddress(), operand_index)
                if key not in seen:
                    seen.add(key)
                    hits.append((instruction, operand_index))
    return hits


def run():
    for addr in _parse_addresses():
        println("== REFS %s ==" % addr)
        refs = _iter_refs(addr)
        if len(refs) != 0:
            for ref in refs:
                from_addr = ref.getFromAddress()
                println(
                    "%s: %s ; type=%s ; function=%s"
                    % (
                        from_addr,
                        getInstructionAt(from_addr),
                        ref.getReferenceType(),
                        _get_function_name(from_addr),
                    )
                )
        else:
            println("!! no raw references")

        operand_hits = _scan_instruction_operands(addr)
        if len(operand_hits) != 0:
            if len(refs) != 0:
                println("-- operand hits --")
            for instruction, operand_index in operand_hits:
                println(
                    "%s: %s ; operand=%d ; function=%s"
                    % (
                        instruction.getAddress(),
                        instruction,
                        operand_index,
                        _get_function_name(instruction.getAddress()),
                    )
                )
        elif len(refs) == 0:
            println("!! no operand hits")
        println("")


run()
