## ###
#  IP: GHIDRA
##
# Reads NUL-terminated byte strings at supplied addresses.
# Usage: GhidraReadCStringPy.py 0x140B5E03C 0x140B69720:128
#@category Codex.Python
#@runtime Jython

DEFAULT_MAX = 256


def _parse_target(value):
    pieces = value.split(":", 1)
    addr = toAddr(pieces[0])
    limit = DEFAULT_MAX
    if len(pieces) > 1 and pieces[1]:
        limit = int(pieces[1], 0)
    return (addr, limit)


def _parse_targets():
    args = list(getScriptArgs())
    if not args:
        raise ValueError("Expected at least one address argument.")
    return [_parse_target(value) for value in args]


def _read_c_string(addr, limit):
    memory = currentProgram.getMemory()
    chars = []
    offset = 0
    while offset < limit:
        value = memory.getByte(addr.add(offset)) & 0xFF
        if value == 0:
            break
        if 32 <= value <= 126:
            chars.append(chr(value))
        else:
            chars.append("\\x%02x" % value)
        offset += 1
    return "".join(chars)


def run():
    for addr, limit in _parse_targets():
        println("== CSTRING %s max=%d ==" % (addr, limit))
        println(_read_c_string(addr, limit))
        println("")


run()
