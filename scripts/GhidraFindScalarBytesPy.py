## ###
#  IP: GHIDRA
##
# Scans executable memory blocks for little-endian scalar byte patterns.
# Usage: GhidraFindScalarBytesPy.py 0x19C80 0x19A58:8
# Optional width suffixes are in bytes; default is 4.
#@category Codex.Python
#@runtime Jython

from jarray import zeros

DEFAULT_WIDTH = 4


def _parse_target(value):
    pieces = value.split(":", 1)
    scalar = int(pieces[0], 0)
    width = DEFAULT_WIDTH
    if len(pieces) > 1 and pieces[1]:
        width = int(pieces[1], 0)
    if width <= 0:
        raise ValueError("Width must be positive.")
    return (scalar, width)


def _parse_targets():
    args = list(getScriptArgs())
    if not args:
        raise ValueError("Expected at least one scalar argument.")
    return [_parse_target(value) for value in args]


def _pattern_for(scalar, width):
    pieces = []
    remaining = scalar
    for _ in range(width):
        value = remaining & 0xFF
        if value >= 0x80:
            value -= 0x100
        pieces.append(value)
        remaining >>= 8
    pattern = zeros(width, "b")
    for index, value in enumerate(pieces):
        pattern[index] = value
    return pattern


def _pattern_text(pattern):
    rendered = []
    for value in pattern:
        rendered.append("%02x" % (value & 0xFF))
    return " ".join(rendered)


def _iter_exec_blocks():
    for block in currentProgram.getMemory().getBlocks():
        if block.isExecute():
            yield block


def _instruction_text(addr):
    listing = currentProgram.getListing()
    instruction = listing.getInstructionContaining(addr)
    if instruction is None:
        disassemble(addr)
        instruction = listing.getInstructionContaining(addr)
    if instruction is None:
        return "<no-instruction>"
    return "%s @ %s" % (instruction, instruction.getAddress())


def _find_hits_for_block(block, pattern):
    memory = currentProgram.getMemory()
    hits = []
    current = block.getStart()
    while current is not None and current.compareTo(block.getEnd()) <= 0:
        hit = memory.findBytes(current, block.getEnd(), pattern, None, True, monitor)
        if hit is None:
            break
        hits.append(hit)
        current = hit.add(1)
    return hits


def run():
    for scalar, width in _parse_targets():
        pattern = _pattern_for(scalar, width)
        println("== SCALAR 0x%x width=%d pattern=%s ==" % (scalar, width, _pattern_text(pattern)))
        total_hits = 0
        for block in _iter_exec_blocks():
            hits = _find_hits_for_block(block, pattern)
            for hit in hits:
                total_hits += 1
                println(
                    "%s: block=%s ; instruction=%s"
                    % (hit, block.getName(), _instruction_text(hit))
                )
        if total_hits == 0:
            println("!! no executable hits")
        println("")


run()
