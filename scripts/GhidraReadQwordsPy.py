## ###
#  IP: GHIDRA
##
# Reads little-endian 64-bit values at supplied addresses.
# Usage: GhidraReadQwordsPy.py 0x140BA0630:8 0x140C41920:4
#@category Codex.Python
#@runtime Jython

DEFAULT_COUNT = 8
STRING_PREVIEW_LIMIT = 48


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
        raise ValueError("Expected at least one address argument.")
    return [_parse_target(value) for value in args]


def _read_qword(addr):
    memory = currentProgram.getMemory()
    value = 0
    for offset in range(8):
        byte_value = memory.getByte(addr.add(offset)) & 0xFF
        value |= byte_value << (offset * 8)
    return value


def _to_program_addr(value):
    try:
        candidate = toAddr(value)
    except Exception:
        return None
    if currentProgram.getMemory().contains(candidate):
        return candidate
    return None


def _string_preview(addr):
    memory = currentProgram.getMemory()
    chars = []
    offset = 0
    while offset < STRING_PREVIEW_LIMIT:
        try:
            value = memory.getByte(addr.add(offset)) & 0xFF
        except Exception:
            break
        if value == 0:
            break
        if 32 <= value <= 126:
            chars.append(chr(value))
        else:
            return None
        offset += 1
    if not chars:
        return None
    return "".join(chars)


def _inline_ascii_from_qword(value):
    chars = []
    for offset in range(8):
        byte_value = (value >> (offset * 8)) & 0xFF
        if byte_value == 0:
            break
        if 32 <= byte_value <= 126:
            chars.append(chr(byte_value))
            continue
        return None
    if len(chars) < 2:
        return None
    return "".join(chars)


def _is_executable(addr):
    block = currentProgram.getMemory().getBlock(addr)
    return block is not None and block.isExecute()


def _instruction_for(target):
    listing = currentProgram.getListing()
    instruction = listing.getInstructionAt(target)
    if instruction is not None:
        return instruction

    if _is_executable(target):
        try:
            disassemble(target)
        except Exception:
            pass
        instruction = listing.getInstructionAt(target)
        if instruction is not None:
            return instruction

    return listing.getInstructionContaining(target)


def _annotation_for(target):
    instruction = _instruction_for(target)
    if instruction is not None:
        func = getFunctionContaining(instruction.getAddress())
        if func is not None:
            return "instruction=%s @ %s ; function=%s @ %s" % (
                instruction,
                instruction.getAddress(),
                func.getName(),
                func.getEntryPoint(),
            )
        return "instruction=%s @ %s" % (instruction, instruction.getAddress())

    preview = _string_preview(target)
    if preview is not None:
        return 'ascii="%s"' % preview

    return None


def run():
    for addr, count in _parse_targets():
        println("== QWORDS %s count=%d ==" % (addr, count))
        for index in range(count):
            slot = addr.add(index * 8)
            value = _read_qword(slot)
            line = "%s[%d]: 0x%016x" % (slot, index, value)
            target = _to_program_addr(value)
            if target is not None:
                annotation = _annotation_for(target)
                if annotation is not None:
                    line += " ; target=%s ; %s" % (target, annotation)
                else:
                    line += " ; target=%s" % target
            else:
                inline_ascii = _inline_ascii_from_qword(value)
                if inline_ascii is not None:
                    line += ' ; inline_ascii="%s"' % inline_ascii
            println(line)
        println("")


run()
