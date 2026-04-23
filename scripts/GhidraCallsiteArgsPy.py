## ###
#  IP: GHIDRA
##
# Emits nearby Win64 callsite argument setup candidates for supplied CALL addresses.
# Usage: GhidraCallsiteArgsPy.py 0x140679665 0x1406798a5:24
# Optional suffix is the backward instruction budget; default is 20.
#@category Codex.Python
#@runtime Jython

import re

DEFAULT_BACK = 20

_IMM = r"([+-]?0[xX][0-9a-fA-F]+|[+-]?[0-9]+)"
_STACK_WRITE = re.compile(
    r"^[A-Z]+\s+(?:[A-Z]+\s+PTR\s+)?\[RSP(?:\s*\+\s*" + _IMM + r")?\],",
    re.IGNORECASE,
)
_REG_WRITE = re.compile(r"^[A-Z]+\s+([A-Z0-9]+),", re.IGNORECASE)
_REG_UNARY_WRITE = re.compile(r"^SET[A-Z]+\s+([A-Z0-9]+)\s*$", re.IGNORECASE)

_REG_TO_ARG = {
    "RCX": "arg1",
    "ECX": "arg1",
    "CX": "arg1",
    "CL": "arg1",
    "RDX": "arg2",
    "EDX": "arg2",
    "DX": "arg2",
    "DL": "arg2",
    "R8": "arg3",
    "R8D": "arg3",
    "R8W": "arg3",
    "R8B": "arg3",
    "R9": "arg4",
    "R9D": "arg4",
    "R9W": "arg4",
    "R9B": "arg4",
}


def _parse_target(value):
    pieces = value.split(":", 1)
    addr = toAddr(pieces[0])
    back = DEFAULT_BACK
    if len(pieces) > 1 and pieces[1]:
        back = int(pieces[1], 0)
    if back <= 0:
        raise ValueError("Back instruction budget must be positive.")
    return (addr, back)


def _parse_targets():
    args = list(getScriptArgs())
    if not args:
        raise ValueError("Expected at least one CALL address.")
    return [_parse_target(value) for value in args]


def _parse_int(value):
    value = value.strip()
    if value.startswith("+"):
        value = value[1:]
    return int(value, 0)


def _instruction_at(addr):
    listing = currentProgram.getListing()
    instruction = listing.getInstructionAt(addr)
    if instruction is not None:
        return instruction
    disassemble(addr)
    instruction = listing.getInstructionAt(addr)
    if instruction is not None:
        return instruction
    return listing.getInstructionContaining(addr)


def _previous_contiguous(instruction):
    listing = currentProgram.getListing()
    previous = listing.getInstructionBefore(instruction.getAddress())
    if previous is None:
        return None
    if instruction.getAddress().subtract(previous.getMaxAddress()) > 1:
        return None
    return previous


def _stack_arg_for(displacement):
    if displacement < 0x20:
        return "shadow-space"
    if (displacement - 0x20) % 8 != 0:
        return "outgoing-stack-arg-area"
    return "outgoing-stack-arg%d" % (5 + ((displacement - 0x20) // 8))


def _candidate_label(text):
    upper = text.upper()

    match = _REG_WRITE.match(upper)
    if match:
        register = match.group(1)
        if register in _REG_TO_ARG:
            return _REG_TO_ARG[register]

    match = _REG_UNARY_WRITE.match(upper)
    if match:
        register = match.group(1)
        if register in _REG_TO_ARG:
            return _REG_TO_ARG[register]

    match = _STACK_WRITE.match(upper)
    if match:
        displacement = 0
        if match.group(1) is not None:
            displacement = _parse_int(match.group(1))
        return _stack_arg_for(displacement)

    return None


def _is_call(instruction):
    return str(instruction).upper().startswith("CALL ")


def _collect_candidates(call_instruction, back):
    candidates = []
    instruction = _previous_contiguous(call_instruction)
    remaining = back
    while instruction is not None and remaining > 0:
        if _is_call(instruction):
            break
        text = str(instruction)
        label = _candidate_label(text)
        if label is not None:
            candidates.append((instruction, label))
        instruction = _previous_contiguous(instruction)
        remaining -= 1
    candidates.reverse()
    return candidates


def run():
    for addr, back in _parse_targets():
        instruction = _instruction_at(addr)
        println("== CALLSITE ARGS %s back=%d ==" % (addr, back))
        if instruction is None:
            println("!! no instruction available")
            println("")
            continue
        println("call: %s: %s" % (instruction.getAddress(), instruction))
        if not _is_call(instruction):
            println("!! target is not a CALL instruction")

        candidates = _collect_candidates(instruction, back)
        if not candidates:
            println("!! no immediate argument setup candidates before prior CALL/gap")
        for candidate, label in candidates:
            println("%s: %s ; %s-candidate" % (candidate.getAddress(), candidate, label))
        println("")


run()
