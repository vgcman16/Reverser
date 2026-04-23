## ###
#  IP: GHIDRA
##
# Dumps linear instruction windows starting at supplied addresses.
# Usage: GhidraDumpWindowsPy.py 0x140000000:64 0x140001000:32:8
# The optional third field backs up N instructions before dumping.
#@category Codex.Python
#@runtime Jython

DEFAULT_COUNT = 64


def _parse_target(value):
    pieces = value.split(":", 2)
    addr = toAddr(pieces[0])
    count = DEFAULT_COUNT
    back = 0
    if len(pieces) > 1 and pieces[1]:
        count = int(pieces[1], 0)
    if len(pieces) > 2 and pieces[2]:
        back = int(pieces[2], 0)
    return (addr, count, back)


def _parse_targets():
    args = getScriptArgs()
    if len(args) == 0:
        raise ValueError("Expected at least one address or address:count argument.")
    return [_parse_target(value) for value in args]


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


def _format_refs(instruction):
    refs = instruction.getReferencesFrom()
    if refs is None or len(refs) == 0:
        return ""
    rendered = []
    for ref in refs:
        rendered.append("%s(%s)" % (ref.getToAddress(), ref.getReferenceType()))
    return " ; refs=" + ", ".join(rendered)


def _seek_back(instruction, back):
    if back <= 0:
        return instruction
    listing = currentProgram.getListing()
    current = instruction
    remaining = back
    while current is not None and remaining > 0:
        previous = listing.getInstructionBefore(current.getAddress())
        if previous is None:
            break
        # On fresh no-analysis imports, listing.getInstructionBefore() can jump
        # across large undefined gaps into unrelated earlier code. Only walk
        # back through directly contiguous decoded instructions.
        if current.getAddress().subtract(previous.getMaxAddress()) > 1:
            break
        current = previous
        remaining -= 1
    return current


def _dump_window(addr, count, back):
    println("== WINDOW %s count=%d back=%d ==" % (addr, count, back))
    instruction = _instruction_at(addr)
    if instruction is None:
        println("!! no instruction available at %s" % addr)
        println("")
        return

    listing = currentProgram.getListing()
    instruction = _seek_back(instruction, back)
    emitted = 0
    while instruction is not None and emitted < count:
        println("%s: %s%s" % (instruction.getAddress(), instruction, _format_refs(instruction)))
        emitted += 1
        next_addr = instruction.getMaxAddress().next()
        if next_addr is None:
            break
        next_instruction = listing.getInstructionAt(next_addr)
        if next_instruction is None:
            disassemble(next_addr)
            next_instruction = listing.getInstructionAt(next_addr)
        instruction = next_instruction
    println("")


for addr, count, back in _parse_targets():
    _dump_window(addr, count, back)
