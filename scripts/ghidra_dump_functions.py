def _parse_addresses():
    args = list(getScriptArgs())
    if not args:
        raise ValueError("Expected at least one function address argument.")
    return [toAddr(value) for value in args]


def _get_function(addr):
    func = getFunctionAt(addr)
    if func is None:
        func = getFunctionContaining(addr)
    if func is None:
        raise ValueError("No function found for %s" % addr)
    return func


def _dump_disassembly(func):
    println("== FUNCTION %s @ %s ==" % (func.getName(), func.getEntryPoint()))
    listing = currentProgram.getListing()
    instruction = listing.getInstructionAt(func.getEntryPoint())
    while instruction is not None and instruction.getAddress().compareTo(func.getBody().getMaxAddress()) <= 0:
        println("%s: %s" % (instruction.getAddress(), instruction))
        instruction = instruction.getNext()


def run():
    for addr in _parse_addresses():
        func = _get_function(addr)
        _dump_disassembly(func)
        println("")


run()
