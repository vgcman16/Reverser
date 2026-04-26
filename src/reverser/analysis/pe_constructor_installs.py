from __future__ import annotations

from pathlib import Path

from reverser.analysis.pe_direct_calls import PEMetadata, parse_int_literal, read_pe_metadata
from reverser.analysis.pe_function_calls import _parse_function_spec
from reverser.analysis.pe_indirect_dispatches import _normalize_register, _parse_memory_operand, _split_operands
from reverser.analysis.pe_registration_records import _scan_range_instructions
from reverser.analysis.pe_runtime_functions import read_pe_runtime_functions


def _hex(value: int) -> str:
    return f"0x{value:x}"


def _normalize_address(value: str | int, metadata: PEMetadata) -> int:
    if isinstance(value, int):
        address = value
    else:
        address = parse_int_literal(str(value))
    normalized, _ = metadata.normalize_va_or_rva(address)
    return normalized


def _target_va(instruction: dict[str, object]) -> int | None:
    value = instruction.get("target_va")
    if value is None:
        return None
    return parse_int_literal(str(value))


def _instruction_excerpt(instruction: dict[str, object]) -> dict[str, object]:
    keys = (
        "address_va",
        "address_rva",
        "raw_bytes",
        "length",
        "mnemonic",
        "operands",
        "instruction",
        "kind",
        "target_va",
        "target_rva",
    )
    return {key: instruction[key] for key in keys if key in instruction}


def _recent_immediate(
    instructions: list[dict[str, object]],
    *,
    registers: set[str],
) -> tuple[int, dict[str, object]] | None:
    for instruction in reversed(instructions):
        if str(instruction.get("mnemonic", "")).upper() != "MOV":
            continue
        if "immediate" not in instruction:
            continue
        operands = _split_operands(instruction.get("operands"))
        if not operands:
            continue
        destination = _normalize_register(operands[0])
        if destination in registers:
            return int(instruction["immediate"]), instruction
    return None


def _recent_assignment(
    instructions: list[dict[str, object]],
    register: str,
) -> dict[str, object] | None:
    for instruction in reversed(instructions):
        operands = _split_operands(instruction.get("operands"))
        if len(operands) < 2:
            continue
        destination = _normalize_register(operands[0])
        if destination != register:
            continue
        source = operands[1]
        payload: dict[str, object] = {
            "register": register,
            "source_instruction": _instruction_excerpt(instruction),
        }
        source_register = _normalize_register(source)
        if source_register is not None:
            payload.update({"kind": "register-copy", "source_register": source_register})
            return payload
        if instruction.get("mnemonic") == "MOV" and "immediate" in instruction:
            payload.update({"kind": "immediate", "value": _hex(int(instruction["immediate"]))})
            return payload
        memory = _parse_memory_operand(source) if "[" in source and "]" in source else None
        if memory is not None:
            payload.update({"kind": "memory-load", "memory": memory})
            return payload
        payload.update({"kind": "expression", "expression": source})
        return payload
    return None


def _constructor_receives_allocator_return(
    instructions: list[dict[str, object]],
) -> bool:
    assignment = _recent_assignment(instructions, "RCX")
    return assignment is not None and assignment.get("kind") == "register-copy" and assignment.get("source_register") == "RAX"


def _constructor_args(
    instructions: list[dict[str, object]],
) -> dict[str, object]:
    args: dict[str, object] = {}
    for register in ("RCX", "RDX", "R8", "R9"):
        assignment = _recent_assignment(instructions, register)
        if assignment is not None:
            args[register] = assignment
    return args


def _slot_pointer_from_lea(instruction: dict[str, object]) -> tuple[str, dict[str, object]] | None:
    if str(instruction.get("mnemonic", "")).upper() != "LEA":
        return None
    operands = _split_operands(instruction.get("operands"))
    if len(operands) < 2:
        return None
    destination = _normalize_register(operands[0])
    if destination is None:
        return None
    memory = _parse_memory_operand(operands[1])
    if memory is None:
        return None
    if memory.get("memory_kind") not in {"base", "base-displacement"}:
        return None
    return destination, memory


def _direct_slot_store(
    instruction: dict[str, object],
    *,
    return_aliases: set[str],
    slot_pointers: dict[str, dict[str, object]],
) -> dict[str, object] | None:
    if str(instruction.get("mnemonic", "")).upper() != "MOV":
        return None
    operands = _split_operands(instruction.get("operands"))
    if len(operands) < 2:
        return None
    source_register = _normalize_register(operands[1])
    if source_register not in return_aliases:
        return None

    destination_memory = _parse_memory_operand(operands[0])
    if destination_memory is None:
        return None

    slot: dict[str, object] = {
        "store_va": instruction["address_va"],
        "store_rva": instruction["address_rva"],
        "store_instruction": instruction["instruction"],
        "stored_register": source_register,
        "destination": destination_memory,
    }
    base_register = destination_memory.get("base_register")
    if destination_memory.get("memory_kind") == "base" and isinstance(base_register, str):
        slot_pointer = slot_pointers.get(base_register)
        if slot_pointer is not None:
            slot.update(
                {
                    "kind": "slot-pointer-store",
                    "slot_pointer_register": base_register,
                    "owner_register": slot_pointer.get("base_register"),
                    "slot_offset": slot_pointer.get("displacement_hex"),
                    "slot_offset_value": slot_pointer.get("displacement"),
                    "slot_pointer_setup_va": slot_pointer.get("setup_va"),
                    "slot_pointer_setup_instruction": slot_pointer.get("setup_instruction"),
                }
            )
            return slot
    if destination_memory.get("memory_kind") == "base-displacement":
        slot.update(
            {
                "kind": "direct-slot-store",
                "owner_register": destination_memory.get("base_register"),
                "slot_offset": destination_memory.get("displacement_hex"),
                "slot_offset_value": destination_memory.get("displacement"),
            }
        )
        return slot
    return None


def _find_install_after_constructor(
    instructions: list[dict[str, object]],
    *,
    constructor_index: int,
    lookahead_instructions: int,
    include_evidence: bool,
) -> dict[str, object] | None:
    return_aliases = {"RAX"}
    slot_pointers: dict[str, dict[str, object]] = {}
    limit = min(len(instructions), constructor_index + 1 + lookahead_instructions)

    for index in range(constructor_index + 1, limit):
        instruction = instructions[index]
        operands = _split_operands(instruction.get("operands"))

        if str(instruction.get("mnemonic", "")).upper() == "MOV" and len(operands) >= 2:
            destination_register = _normalize_register(operands[0])
            source_register = _normalize_register(operands[1])
            if destination_register is not None and source_register in return_aliases:
                return_aliases.add(destination_register)

        slot_pointer = _slot_pointer_from_lea(instruction)
        if slot_pointer is not None:
            register, memory = slot_pointer
            memory = dict(memory)
            memory["setup_va"] = instruction.get("address_va")
            memory["setup_instruction"] = instruction.get("instruction")
            slot_pointers[register] = memory

        install = _direct_slot_store(
            instruction,
            return_aliases=return_aliases,
            slot_pointers=slot_pointers,
        )
        if install is None:
            continue
        install["instruction_distance_from_constructor"] = index - constructor_index
        install["return_aliases_at_store"] = sorted(return_aliases)
        if include_evidence:
            install["evidence"] = {
                "post_constructor_window": [
                    _instruction_excerpt(item)
                    for item in instructions[constructor_index + 1 : min(limit, index + 1)]
                ]
            }
        return install
    return None


def _entry_from_allocator_call(
    instructions: list[dict[str, object]],
    allocator_index: int,
    *,
    allocator_va: int,
    constructor_filter: set[int] | None,
    slot_offset_filter: set[int] | None,
    image_base: int,
    include_evidence: bool,
    lookback_instructions: int,
    lookahead_instructions: int,
) -> dict[str, object] | None:
    setup = instructions[max(0, allocator_index - lookback_instructions) : allocator_index]
    allocation_size = _recent_immediate(setup, registers={"RCX"})
    allocator_secondary_arg = _recent_immediate(setup, registers={"RDX"})
    constructor_limit = min(len(instructions), allocator_index + 1 + lookahead_instructions)

    for constructor_index in range(allocator_index + 1, constructor_limit):
        instruction = instructions[constructor_index]
        if instruction.get("mnemonic") != "CALL":
            continue
        constructor_va = _target_va(instruction)
        if constructor_va is None:
            continue
        if constructor_filter is not None and constructor_va not in constructor_filter:
            continue

        constructor_setup = instructions[allocator_index + 1 : constructor_index]
        if not _constructor_receives_allocator_return(constructor_setup):
            continue

        install = _find_install_after_constructor(
            instructions,
            constructor_index=constructor_index,
            lookahead_instructions=lookahead_instructions,
            include_evidence=include_evidence,
        )
        if install is None:
            continue
        slot_offset_value = install.get("slot_offset_value")
        if slot_offset_filter is not None and slot_offset_value not in slot_offset_filter:
            continue

        entry: dict[str, object] = {
            "allocator_call_va": instructions[allocator_index]["address_va"],
            "allocator_call_rva": instructions[allocator_index]["address_rva"],
            "allocator_va": _hex(allocator_va),
            "allocator_rva": _hex(allocator_va - image_base),
            "constructor_call_va": instruction["address_va"],
            "constructor_call_rva": instruction["address_rva"],
            "constructor_va": _hex(constructor_va),
            "constructor_rva": _hex(constructor_va - image_base),
            "constructor_args": _constructor_args(constructor_setup),
            "install": install,
            "confidence": "high",
        }
        if allocation_size is not None:
            entry["allocation_size"] = _hex(allocation_size[0])
            entry["allocation_size_value"] = allocation_size[0]
            entry["allocation_size_setup_va"] = allocation_size[1]["address_va"]
        if allocator_secondary_arg is not None:
            entry["allocator_secondary_arg"] = _hex(allocator_secondary_arg[0])
            entry["allocator_secondary_arg_value"] = allocator_secondary_arg[0]
            entry["allocator_secondary_arg_setup_va"] = allocator_secondary_arg[1]["address_va"]
        if include_evidence:
            entry["evidence"] = {
                "allocator_setup": [_instruction_excerpt(item) for item in setup],
                "allocator_call": _instruction_excerpt(instructions[allocator_index]),
                "constructor_setup": [_instruction_excerpt(item) for item in constructor_setup],
                "constructor_call": _instruction_excerpt(instruction),
            }
        return entry
    return None


def find_pe_constructor_installs(
    path: str | Path,
    functions: list[str],
    *,
    allocator: str | int,
    constructors: list[str | int] | tuple[str | int, ...] = (),
    slot_offsets: list[str | int] | tuple[str | int, ...] = (),
    lookback_instructions: int = 12,
    lookahead_instructions: int = 40,
    max_installs_per_range: int = 128,
    include_evidence: bool = False,
) -> dict[str, object]:
    if lookback_instructions <= 0:
        raise ValueError("Lookback instruction count must be greater than zero.")
    if lookahead_instructions <= 0:
        raise ValueError("Lookahead instruction count must be greater than zero.")
    if max_installs_per_range <= 0:
        raise ValueError("Max installs per range must be greater than zero.")

    target_path = Path(path)
    data = target_path.read_bytes()
    metadata = read_pe_metadata(data)
    runtime_functions = read_pe_runtime_functions(data, metadata)
    allocator_va = _normalize_address(allocator, metadata)
    constructor_filter = (
        {_normalize_address(constructor, metadata) for constructor in constructors}
        if constructors
        else None
    )
    slot_offset_filter = (
        {parse_int_literal(str(slot_offset)) for slot_offset in slot_offsets}
        if slot_offsets
        else None
    )

    ranges: list[dict[str, object]] = []
    warnings: list[str] = []
    scanned_byte_count = 0
    decoded_instruction_count = 0
    allocator_call_hit_count = 0
    install_hit_count = 0
    returned_install_count = 0

    for function_spec in functions:
        start_va, end_va = _parse_function_spec(function_spec, metadata, runtime_functions)
        instructions, warning, scanned = _scan_range_instructions(
            data,
            metadata,
            runtime_functions,
            start_va=start_va,
            end_va=end_va,
        )
        scanned_byte_count += scanned
        decoded_instruction_count += len(instructions)
        if warning is not None:
            warnings.append(f"Function {function_spec!r} {warning}.")

        installs: list[dict[str, object]] = []
        range_allocator_hit_count = 0
        range_install_hit_count = 0
        for index, instruction in enumerate(instructions):
            if instruction.get("mnemonic") != "CALL" or _target_va(instruction) != allocator_va:
                continue
            allocator_call_hit_count += 1
            range_allocator_hit_count += 1
            entry = _entry_from_allocator_call(
                instructions,
                index,
                allocator_va=allocator_va,
                constructor_filter=constructor_filter,
                slot_offset_filter=slot_offset_filter,
                image_base=metadata.image_base,
                include_evidence=include_evidence,
                lookback_instructions=lookback_instructions,
                lookahead_instructions=lookahead_instructions,
            )
            if entry is None:
                continue
            install_hit_count += 1
            range_install_hit_count += 1
            if len(installs) < max_installs_per_range:
                installs.append(entry)
                returned_install_count += 1

        ranges.append(
            {
                "request": str(function_spec),
                "start_va": _hex(start_va),
                "start_rva": _hex(start_va - metadata.image_base),
                "end_va": _hex(end_va),
                "end_rva": _hex(end_va - metadata.image_base),
                "decoded_instruction_count": len(instructions),
                "allocator_call_hit_count": range_allocator_hit_count,
                "constructor_install_hit_count": range_install_hit_count,
                "constructor_install_count": len(installs),
                "truncated_constructor_install_count": max(0, range_install_hit_count - len(installs)),
                "constructor_installs": installs,
            }
        )

    scan: dict[str, object] = {
        "function_count": len(functions),
        "allocator_va": _hex(allocator_va),
        "allocator_rva": _hex(allocator_va - metadata.image_base),
        "constructor_filter": [_hex(value) for value in sorted(constructor_filter or [])],
        "slot_offset_filter": [_hex(value) for value in sorted(slot_offset_filter or [])],
        "lookback_instructions": lookback_instructions,
        "lookahead_instructions": lookahead_instructions,
        "max_installs_per_range": max_installs_per_range,
        "include_evidence": include_evidence,
        "runtime_function_count": len(runtime_functions),
        "decoded_instruction_count": decoded_instruction_count,
        "scanned_byte_count": scanned_byte_count,
        "allocator_call_hit_count": allocator_call_hit_count,
        "constructor_install_hit_count": install_hit_count,
        "constructor_install_count": returned_install_count,
    }

    return {
        "type": "pe-constructor-installs",
        "target": str(target_path),
        "image_base": _hex(metadata.image_base),
        "scan": scan,
        "ranges": ranges,
        "warnings": warnings,
    }
