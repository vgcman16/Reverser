## ###
#  IP: GHIDRA
##
# Tracks simple Win64 function-entry RSP/RBP offsets and labels stack references.
# Usage: GhidraWin64StackArgsPy.py 0x140000000:128
#@category Codex.Python
#@runtime Jython

import re

DEFAULT_COUNT = 128

_IMM = r"([+-]?0[xX][0-9a-fA-F]+|[+-]?[0-9]+)"
_STACK_REF = re.compile(r"\[(RSP|RBP)(?:\s*\+\s*" + _IMM + r")?\]", re.IGNORECASE)


def _parse_target(value):
    pieces = value.split(":", 1)
    addr = toAddr(pieces[0])
    count = DEFAULT_COUNT
    if len(pieces) > 1 and pieces[1]:
        count = int(pieces[1], 0)
    return (addr, count)


def _parse_targets():
    args = list(getScriptArgs())
    if len(args) == 0:
        raise ValueError("Expected at least one function-entry address.")
    return [_parse_target(value) for value in args]


def _parse_int(value):
    value = value.strip()
    if value.startswith("+"):
        value = value[1:]
    return int(value, 0)


def _signed_hex(value):
    if value < 0:
        return "-0x%x" % abs(value)
    return "+0x%x" % value


def _entry_label(offset):
    if offset == 0:
        return "return-address"
    if offset >= 0x8 and offset < 0x28:
        return "shadow-space"
    if offset >= 0x28:
        if (offset - 0x28) % 8 == 0:
            index = 5 + ((offset - 0x28) // 8)
            return "stack-arg%d" % index
        return "stack-argument-area"
    return "local-or-saved-register"


def _rsp_slot_label(displacement, entry_kind):
    if entry_kind != "local-or-saved-register":
        return None
    if displacement >= 0x20 and displacement <= 0x40 and (displacement - 0x20) % 8 == 0:
        index = 5 + ((displacement - 0x20) // 8)
        return "current-rsp-outgoing-arg%d-slot-candidate" % index
    if displacement >= 0 and displacement < 0x20:
        return "current-rsp-shadow-space"
    return None


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


def _next_instruction(instruction):
    next_addr = instruction.getMaxAddress().next()
    if next_addr is None:
        return None
    listing = currentProgram.getListing()
    next_instruction = listing.getInstructionAt(next_addr)
    if next_instruction is None:
        disassemble(next_addr)
        next_instruction = listing.getInstructionAt(next_addr)
    return next_instruction


def _stack_refs(text, rsp_offset, rbp_offset):
    rendered = []
    for match in _STACK_REF.finditer(text):
        base = match.group(1).upper()
        displacement = 0
        if match.group(2) is not None:
            displacement = _parse_int(match.group(2))
        base_offset = rsp_offset
        if base == "RBP":
            base_offset = rbp_offset
        if base_offset is None:
            rendered.append("%s => %s unknown" % (match.group(0), base))
            continue
        entry_offset = base_offset + displacement
        entry_kind = _entry_label(entry_offset)
        label = "%s => entry_rsp%s %s" % (
            match.group(0),
            _signed_hex(entry_offset),
            entry_kind,
        )
        if base == "RSP":
            rsp_label = _rsp_slot_label(displacement, entry_kind)
            if rsp_label is not None:
                label += " ; " + rsp_label
        rendered.append(label)
    return rendered


def _state_events(text, rsp_offset, rbp_offset):
    events = []
    upper = text.upper()

    match = re.match(r"LEA\s+(RSP|RBP),\[(RSP|RBP)(?:\s*\+\s*" + _IMM + r")?\]\s*$", upper)
    if match:
        destination = match.group(1)
        source = match.group(2)
        displacement = 0
        if match.group(3) is not None:
            displacement = _parse_int(match.group(3))
        source_offset = rsp_offset if source == "RSP" else rbp_offset
        if source_offset is not None:
            value = source_offset + displacement
            if destination == "RSP":
                rsp_offset = value
            else:
                rbp_offset = value
            events.append("set %s=entry_rsp%s" % (destination, _signed_hex(value)))

    match = re.match(r"MOV\s+RBP,RSP\s*$", upper)
    if match:
        rbp_offset = rsp_offset
        events.append("set RBP=entry_rsp%s" % _signed_hex(rbp_offset))

    match = re.match(r"SUB\s+RSP," + _IMM + r"\s*$", upper)
    if match:
        rsp_offset -= _parse_int(match.group(1))
        events.append("set RSP=entry_rsp%s" % _signed_hex(rsp_offset))

    match = re.match(r"ADD\s+RSP," + _IMM + r"\s*$", upper)
    if match:
        rsp_offset += _parse_int(match.group(1))
        events.append("set RSP=entry_rsp%s" % _signed_hex(rsp_offset))

    if upper.startswith("PUSH "):
        rsp_offset -= 8
        events.append("set RSP=entry_rsp%s" % _signed_hex(rsp_offset))
    elif upper.startswith("POP "):
        rsp_offset += 8
        events.append("set RSP=entry_rsp%s" % _signed_hex(rsp_offset))

    return (rsp_offset, rbp_offset, events)


def _dump_target(addr, count):
    println("== WIN64 STACK ARGS %s count=%d ==" % (addr, count))
    println("entry model: [entry_rsp+0x28] is stack-arg5; [entry_rsp+0x8..0x27] is shadow-space")

    instruction = _instruction_at(addr)
    if instruction is None:
        println("!! no instruction available at %s" % addr)
        println("")
        return

    rsp_offset = 0
    rbp_offset = None
    emitted = 0
    while instruction is not None and emitted < count:
        text = str(instruction)
        refs = _stack_refs(text, rsp_offset, rbp_offset)
        rsp_offset, rbp_offset, events = _state_events(text, rsp_offset, rbp_offset)
        if refs or events:
            suffix = []
            if refs:
                suffix.append("refs: " + "; ".join(refs))
            if events:
                suffix.append("state: " + "; ".join(events))
            println("%s: %s ; %s" % (instruction.getAddress(), text, " ; ".join(suffix)))
        emitted += 1
        upper = text.upper()
        if upper.startswith("RET") or upper.startswith("INT3"):
            break
        instruction = _next_instruction(instruction)
    println("")


for addr, count in _parse_targets():
    _dump_target(addr, count)
