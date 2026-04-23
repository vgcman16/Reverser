## ###
#  IP: GHIDRA
##
# Decodes Windows x64 .pdata RUNTIME_FUNCTION entries as begin/end/unwind RVAs.
# Usage: GhidraReadPdataPy.py 0x140EEE270:4
#@category Codex.Python
#@runtime Jython

DEFAULT_COUNT = 8
ENTRY_SIZE = 12


def _parse_target(value):
    pieces = value.split(":", 1)
    addr = toAddr(pieces[0])
    count = DEFAULT_COUNT
    if len(pieces) > 1 and pieces[1]:
        count = int(pieces[1], 0)
    if count <= 0:
        raise ValueError("Count must be positive.")
    return (addr, count)


def _parse_targets():
    args = list(getScriptArgs())
    if not args:
        raise ValueError("Expected at least one pdata address argument.")
    return [_parse_target(value) for value in args]


def _read_dword(addr):
    memory = currentProgram.getMemory()
    value = 0
    for offset in range(4):
        byte_value = memory.getByte(addr.add(offset)) & 0xFF
        value |= byte_value << (offset * 8)
    return value


def _image_base():
    return currentProgram.getImageBase().getOffset()


def _va_for_rva(rva):
    if rva == 0:
        return None
    return toAddr(_image_base() + rva)


def _instruction_text(addr):
    if addr is None:
        return None
    listing = currentProgram.getListing()
    instruction = listing.getInstructionAt(addr)
    if instruction is None:
        try:
            disassemble(addr)
        except Exception:
            pass
        instruction = listing.getInstructionAt(addr)
    if instruction is None:
        return None
    return "%s @ %s" % (instruction, instruction.getAddress())


def _format_target(rva):
    addr = _va_for_rva(rva)
    if addr is None:
        return "0x%08x" % rva
    rendered = "0x%08x -> %s" % (rva, addr)
    instruction = _instruction_text(addr)
    if instruction is not None:
        rendered += " ; " + instruction
    return rendered


def run():
    for addr, count in _parse_targets():
        println("== PDATA %s count=%d ==" % (addr, count))
        for index in range(count):
            slot = addr.add(index * ENTRY_SIZE)
            begin_rva = _read_dword(slot)
            end_rva = _read_dword(slot.add(4))
            unwind_rva = _read_dword(slot.add(8))
            println(
                "%s[%d]: begin=%s ; end=%s ; unwind=%s"
                % (
                    slot,
                    index,
                    _format_target(begin_rva),
                    _format_target(end_rva),
                    _format_target(unwind_rva),
                )
            )
        println("")


run()
