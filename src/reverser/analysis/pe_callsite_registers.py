from __future__ import annotations

from pathlib import Path

from reverser.analysis.pe_direct_calls import find_pe_direct_calls, parse_int_literal, read_pe_metadata
from reverser.analysis.pe_indirect_dispatches import _parse_memory_operand
from reverser.analysis.pe_instructions import find_pe_instructions
from reverser.analysis.pe_runtime_functions import RuntimeFunction, function_for_rva, read_pe_runtime_functions


_REGISTER_ALIASES = {
    "AL": "RAX",
    "AX": "RAX",
    "EAX": "RAX",
    "RAX": "RAX",
    "CL": "RCX",
    "CX": "RCX",
    "ECX": "RCX",
    "RCX": "RCX",
    "DL": "RDX",
    "DX": "RDX",
    "EDX": "RDX",
    "RDX": "RDX",
    "BL": "RBX",
    "BX": "RBX",
    "EBX": "RBX",
    "RBX": "RBX",
    "SPL": "RSP",
    "SP": "RSP",
    "ESP": "RSP",
    "RSP": "RSP",
    "BPL": "RBP",
    "BP": "RBP",
    "EBP": "RBP",
    "RBP": "RBP",
    "SIL": "RSI",
    "SI": "RSI",
    "ESI": "RSI",
    "RSI": "RSI",
    "DIL": "RDI",
    "DI": "RDI",
    "EDI": "RDI",
    "RDI": "RDI",
    "R8B": "R8",
    "R8W": "R8",
    "R8D": "R8",
    "R8": "R8",
    "R9B": "R9",
    "R9W": "R9",
    "R9D": "R9",
    "R9": "R9",
    "R10B": "R10",
    "R10W": "R10",
    "R10D": "R10",
    "R10": "R10",
    "R11B": "R11",
    "R11W": "R11",
    "R11D": "R11",
    "R11": "R11",
    "R12B": "R12",
    "R12W": "R12",
    "R12D": "R12",
    "R12": "R12",
    "R13B": "R13",
    "R13W": "R13",
    "R13D": "R13",
    "R13": "R13",
    "R14B": "R14",
    "R14W": "R14",
    "R14D": "R14",
    "R14": "R14",
    "R15B": "R15",
    "R15W": "R15",
    "R15D": "R15",
    "R15": "R15",
}

_NONVOLATILE_REGISTERS = {"RBX", "RBP", "RDI", "RSI", "R12", "R13", "R14", "R15"}


def _hex(value: int) -> str:
    return f"0x{value:x}"


def _canonical_register(register: str) -> str:
    normalized = str(register).strip().upper()
    return _REGISTER_ALIASES.get(normalized, normalized)


def _parse_stack_offset(value: str | int) -> int:
    if isinstance(value, int):
        return value
    raw_value = str(value).strip()
    normalized = raw_value.upper().replace(" ", "")
    if normalized.startswith("[") and normalized.endswith("]"):
        normalized = normalized[1:-1]
    if normalized == "RSP":
        return 0
    if normalized.startswith("RSP+"):
        return parse_int_literal(normalized[4:])
    if normalized.startswith("RSP-"):
        return -parse_int_literal(normalized[4:])
    return parse_int_literal(raw_value)


def _win64_stack_argument_index(offset: int) -> int | None:
    if offset < 0x20 or offset % 8 != 0:
        return None
    return 5 + ((offset - 0x20) // 8)


def _parse_function_filter(
    value: str,
    metadata: object,
    runtime_functions: list[RuntimeFunction],
) -> tuple[int, int]:
    raw_value = str(value)
    separator = ".." if ".." in raw_value else ":"
    if separator not in raw_value:
        _, address_rva = metadata.normalize_va_or_rva(parse_int_literal(raw_value))  # type: ignore[attr-defined]
        function = function_for_rva(runtime_functions, address_rva)
        if function is None:
            raise ValueError(
                f"Function address {value!r} does not resolve to a .pdata runtime function; "
                "pass START:END or START..END instead."
            )
        return metadata.image_base + function.begin_rva, metadata.image_base + function.end_rva  # type: ignore[attr-defined]
    start_raw, end_raw = raw_value.split(separator, 1)
    start_va, _ = metadata.normalize_va_or_rva(parse_int_literal(start_raw))  # type: ignore[attr-defined]
    end_va, _ = metadata.normalize_va_or_rva(parse_int_literal(end_raw))  # type: ignore[attr-defined]
    if end_va <= start_va:
        raise ValueError(f"Function range end must be greater than start: {value!r}.")
    return start_va, end_va


def _callsite_in_ranges(callsite_va: str, ranges: list[tuple[int, int]]) -> bool:
    if not ranges:
        return True
    value = parse_int_literal(callsite_va)
    return any(start_va <= value < end_va for start_va, end_va in ranges)


def _split_operands(operands: object) -> tuple[str, str] | None:
    raw = str(operands or "")
    if "," not in raw:
        return None
    left, right = raw.split(",", 1)
    return left.strip(), right.strip()


def _source_instruction(instruction: dict[str, object]) -> dict[str, object]:
    keys = ("address_va", "address_rva", "raw_bytes", "length", "instruction", "mnemonic", "operands")
    return {key: instruction[key] for key in keys if key in instruction}


def _section_name_for_va(metadata: object, value: int) -> str | None:
    section = metadata.section_for_va(value)  # type: ignore[attr-defined]
    return section.name if section is not None else None


def _static_setup_payload(
    instruction: dict[str, object],
    *,
    metadata: object,
    requested_register: str,
) -> dict[str, object] | None:
    split = _split_operands(instruction.get("operands"))
    if split is None:
        return None
    destination, source = split
    if _canonical_register(destination) != requested_register:
        return None

    mnemonic = str(instruction.get("mnemonic", "")).upper()
    payload: dict[str, object] = {
        "register": requested_register,
        "source_instruction": _source_instruction(instruction),
    }
    source_upper = source.upper()

    if mnemonic == "LEA" and "memory_target_va" in instruction:
        value_va = parse_int_literal(str(instruction["memory_target_va"]))
        payload.update(
            {
                "kind": "rip-relative-address",
                "value_va": _hex(value_va),
                "value_section": _section_name_for_va(metadata, value_va),
            }
        )
        return payload

    memory = _parse_memory_operand(source) if "[" in source and "]" in source else None
    if mnemonic == "LEA" and memory is not None:
        base_register = memory.get("base_register")
        kind = "stack-address" if base_register in {"RSP", "RBP"} else "effective-address"
        payload["kind"] = kind
        payload["memory"] = memory
        if base_register in {"RSP", "RBP"}:
            payload["stack_offset"] = memory.get("displacement_hex", "0x0")
        return payload

    if mnemonic == "MOV" and "immediate" in instruction:
        value = int(instruction["immediate"])
        payload.update({"kind": "immediate", "value": _hex(value)})
        value_section = _section_name_for_va(metadata, value)
        if value_section is not None:
            payload["value_va"] = _hex(value)
            payload["value_section"] = value_section
        return payload

    if mnemonic == "MOV" and source_upper in _REGISTER_ALIASES:
        payload.update({"kind": "register-copy", "source_register": _canonical_register(source_upper)})
        return payload

    if mnemonic == "MOV" and memory is not None:
        payload["kind"] = "memory-load"
        payload["memory"] = memory
        if "memory_target_va" in instruction:
            memory_va = parse_int_literal(str(instruction["memory_target_va"]))
            payload["memory_va"] = _hex(memory_va)
            payload["memory_section"] = _section_name_for_va(metadata, memory_va)
        return payload

    if mnemonic.startswith("CMOV"):
        payload["condition"] = mnemonic[4:]
        if source_upper in _REGISTER_ALIASES:
            payload.update({"kind": "conditional-register-copy", "source_register": _canonical_register(source_upper)})
            return payload
        if memory is not None:
            payload["kind"] = "conditional-memory-load"
            payload["memory"] = memory
            base_register = memory.get("base_register")
            if base_register in {"RSP", "RBP"}:
                payload["stack_offset"] = memory.get("displacement_hex", "0x0")
            if "memory_target_va" in instruction:
                memory_va = parse_int_literal(str(instruction["memory_target_va"]))
                payload["memory_va"] = _hex(memory_va)
                payload["memory_section"] = _section_name_for_va(metadata, memory_va)
            return payload

    if mnemonic == "XOR" and _canonical_register(source_upper) == requested_register:
        payload.update({"kind": "zero", "value": "0x0"})
        return payload

    payload.update({"kind": "unknown-write"})
    return payload


def _resolve_register_origin(
    instructions: list[dict[str, object]],
    start_index: int,
    register: str,
    *,
    max_backtrack_instructions: int,
    metadata: object,
    depth: int = 0,
    seen: frozenset[str] = frozenset(),
) -> dict[str, object]:
    if depth >= 4 or register in seen:
        return {"kind": "unresolved", "reason": "copy-depth-limit", "register": register, "depth": depth}

    lower_bound = max(0, start_index - max_backtrack_instructions)
    for index in range(start_index - 1, lower_bound - 1, -1):
        instruction = instructions[index]
        if instruction.get("kind") == "call" and register not in _NONVOLATILE_REGISTERS:
            return {
                "kind": "unresolved",
                "reason": "prior-call-may-clobber-register",
                "register": register,
                "depth": depth,
                "callsite_va": instruction.get("address_va"),
                "call_instruction": instruction.get("instruction"),
            }

        split = _split_operands(instruction.get("operands"))
        if split is None:
            continue
        destination, _ = split
        if _canonical_register(destination) != register:
            continue

        payload = _static_setup_payload(
            instruction,
            metadata=metadata,
            requested_register=register,
        )
        if payload is None:
            continue
        if payload.get("kind") in {"register-copy", "conditional-register-copy"}:
            source_register = str(payload["source_register"])
            payload["source_origin"] = _resolve_register_origin(
                instructions,
                index,
                source_register,
                max_backtrack_instructions=max_backtrack_instructions,
                metadata=metadata,
                depth=depth + 1,
                seen=seen | {register},
            )
        return payload

    return {
        "kind": "unresolved",
        "reason": "no-static-register-assignment",
        "register": register,
        "depth": depth,
        "searched_instruction_count": start_index - lower_bound,
    }


def _recover_register_setups(
    instructions: list[dict[str, object]],
    *,
    callsite_va: str,
    registers: tuple[str, ...],
    max_backtrack_instructions: int,
    metadata: object,
) -> tuple[dict[str, object], list[str]]:
    call_index = next(
        (index for index, instruction in enumerate(instructions) if instruction.get("address_va") == callsite_va),
        None,
    )
    if call_index is None:
        return {}, [f"{callsite_va}: callsite was not present in decoded instruction window."]

    requested = set(registers)
    recovered: dict[str, object] = {}
    warnings: list[str] = []
    lower_bound = max(0, call_index - max_backtrack_instructions)
    for index in range(call_index - 1, lower_bound - 1, -1):
        instruction = instructions[index]
        if instruction.get("kind") == "call":
            unresolved = ", ".join(sorted(requested))
            if unresolved:
                warnings.append(f"{callsite_va}: stopped before resolving {unresolved} at prior call.")
            break

        split = _split_operands(instruction.get("operands"))
        if split is None:
            continue
        destination, _ = split
        canonical_destination = _canonical_register(destination)
        if canonical_destination not in requested:
            continue

        payload = _static_setup_payload(
            instruction,
            metadata=metadata,
            requested_register=canonical_destination,
        )
        if payload is not None:
            if payload.get("kind") in {"register-copy", "conditional-register-copy"}:
                source_register = str(payload["source_register"])
                payload["source_origin"] = _resolve_register_origin(
                    instructions,
                    index,
                    source_register,
                    max_backtrack_instructions=max_backtrack_instructions,
                    metadata=metadata,
                    seen=frozenset({canonical_destination}),
                )
            recovered[canonical_destination] = payload
            requested.remove(canonical_destination)
        if not requested:
            break
    return recovered, warnings


def _stack_argument_store_payload(
    instruction: dict[str, object],
    source_operand: str,
    *,
    offset: int,
    instructions: list[dict[str, object]],
    instruction_index: int,
    max_backtrack_instructions: int,
    metadata: object,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "stack_offset": _hex(offset),
        "base_register": "RSP",
        "source_instruction": _source_instruction(instruction),
    }
    argument_index = _win64_stack_argument_index(offset)
    if argument_index is not None:
        payload["argument_index"] = argument_index

    mnemonic = str(instruction.get("mnemonic", "")).upper()
    source_upper = source_operand.upper()

    if mnemonic == "MOV" and "immediate" in instruction:
        value = int(instruction["immediate"])
        payload.update({"kind": "immediate", "value": _hex(value)})
        value_section = _section_name_for_va(metadata, value)
        if value_section is not None:
            payload["value_va"] = _hex(value)
            payload["value_section"] = value_section
        return payload

    source_register = _REGISTER_ALIASES.get(source_upper)
    if mnemonic == "MOV" and source_register is not None:
        payload.update({"kind": "register-copy", "source_register": source_register})
        payload["source_origin"] = _resolve_register_origin(
            instructions,
            instruction_index,
            source_register,
            max_backtrack_instructions=max_backtrack_instructions,
            metadata=metadata,
        )
        return payload

    memory = _parse_memory_operand(source_operand) if "[" in source_operand and "]" in source_operand else None
    if mnemonic == "MOV" and memory is not None:
        payload["kind"] = "memory-load"
        payload["memory"] = memory
        if "memory_target_va" in instruction:
            memory_va = parse_int_literal(str(instruction["memory_target_va"]))
            payload["memory_va"] = _hex(memory_va)
            payload["memory_section"] = _section_name_for_va(metadata, memory_va)
        return payload

    payload["kind"] = "unknown-store"
    return payload


def _recover_stack_argument_setups(
    instructions: list[dict[str, object]],
    *,
    callsite_va: str,
    stack_offsets: tuple[int, ...],
    max_backtrack_instructions: int,
    metadata: object,
) -> tuple[dict[str, object], list[str]]:
    call_index = next(
        (index for index, instruction in enumerate(instructions) if instruction.get("address_va") == callsite_va),
        None,
    )
    if call_index is None:
        return {}, [f"{callsite_va}: callsite was not present in decoded instruction window."]

    requested = set(stack_offsets)
    recovered: dict[str, object] = {}
    warnings: list[str] = []
    lower_bound = max(0, call_index - max_backtrack_instructions)
    for index in range(call_index - 1, lower_bound - 1, -1):
        instruction = instructions[index]
        if instruction.get("kind") == "call":
            unresolved = ", ".join(_hex(offset) for offset in sorted(requested))
            if unresolved:
                warnings.append(f"{callsite_va}: stopped before resolving stack arguments {unresolved} at prior call.")
            break

        split = _split_operands(instruction.get("operands"))
        if split is None:
            continue
        destination, source = split
        memory = _parse_memory_operand(destination) if "[" in destination and "]" in destination else None
        if memory is None:
            continue
        if memory.get("base_register") != "RSP":
            continue
        displacement = int(memory.get("displacement", 0))
        if displacement not in requested:
            continue

        recovered[_hex(displacement)] = _stack_argument_store_payload(
            instruction,
            source,
            offset=displacement,
            instructions=instructions,
            instruction_index=index,
            max_backtrack_instructions=max_backtrack_instructions,
            metadata=metadata,
        )
        requested.remove(displacement)
        if not requested:
            break
    return recovered, warnings


def find_pe_callsite_registers(
    path: str | Path,
    targets: list[str | int],
    *,
    registers: list[str] | tuple[str, ...] = ("RCX", "RDX", "R8", "R9"),
    stack_offsets: list[str | int] | tuple[str | int, ...] = (),
    max_backtrack_instructions: int = 16,
    functions: list[str] | tuple[str, ...] = (),
) -> dict[str, object]:
    target_path = Path(path)
    data = target_path.read_bytes()
    metadata = read_pe_metadata(data)
    runtime_functions = read_pe_runtime_functions(data, metadata)
    requested_registers = tuple(dict.fromkeys(_canonical_register(register) for register in registers))
    requested_stack_offsets = tuple(dict.fromkeys(_parse_stack_offset(offset) for offset in stack_offsets))
    function_ranges: list[tuple[int, int]] = []
    function_filters: list[dict[str, object]] = []
    for function_spec in functions:
        start_va, end_va = _parse_function_filter(str(function_spec), metadata, runtime_functions)
        function_ranges.append((start_va, end_va))
        function_filters.append(
            {
                "request": str(function_spec),
                "start_va": _hex(start_va),
                "start_rva": _hex(start_va - metadata.image_base),
                "end_va": _hex(end_va),
                "end_rva": _hex(end_va - metadata.image_base),
            }
        )
    direct_payload = find_pe_direct_calls(target_path, targets)

    window_requests: list[str] = []
    call_window_by_site: dict[str, str] = {}
    warnings: list[str] = []
    for result in direct_payload["results"]:  # type: ignore[index]
        for call in result["calls"]:  # type: ignore[index]
            callsite_va = str(call["callsite_va"])
            if not _callsite_in_ranges(callsite_va, function_ranges):
                continue
            function = call.get("function")
            if isinstance(function, dict):
                start_va = str(function["start_va"])
                end_va = _hex(parse_int_literal(callsite_va) + 5)
                request = f"{start_va}..{end_va}"
                call_window_by_site[callsite_va] = request
                window_requests.append(request)
            else:
                warnings.append(f"{callsite_va}: no containing runtime function; register recovery skipped.")

    instruction_by_request: dict[str, list[dict[str, object]]] = {}
    if window_requests:
        instruction_payload = find_pe_instructions(target_path, window_requests)
        for window in instruction_payload["windows"]:  # type: ignore[index]
            instruction_by_request[str(window["request"])] = list(window.get("instructions", []))
        warnings.extend(str(warning) for warning in instruction_payload.get("warnings", []))

    results: list[dict[str, object]] = []
    for result in direct_payload["results"]:  # type: ignore[index]
        calls: list[dict[str, object]] = []
        for call in result["calls"]:  # type: ignore[index]
            if not _callsite_in_ranges(str(call["callsite_va"]), function_ranges):
                continue
            call_copy = dict(call)
            request = call_window_by_site.get(str(call["callsite_va"]))
            call_warnings: list[str] = []
            registers_payload: dict[str, object] = {}
            stack_arguments_payload: dict[str, object] = {}
            if request is not None:
                registers_payload, call_warnings = _recover_register_setups(
                    instruction_by_request.get(request, []),
                    callsite_va=str(call["callsite_va"]),
                    registers=requested_registers,
                    max_backtrack_instructions=max_backtrack_instructions,
                    metadata=metadata,
                )
                if requested_stack_offsets:
                    stack_warnings: list[str]
                    stack_arguments_payload, stack_warnings = _recover_stack_argument_setups(
                        instruction_by_request.get(request, []),
                        callsite_va=str(call["callsite_va"]),
                        stack_offsets=requested_stack_offsets,
                        max_backtrack_instructions=max_backtrack_instructions,
                        metadata=metadata,
                    )
                    call_warnings.extend(stack_warnings)
            call_copy["registers"] = registers_payload
            if requested_stack_offsets:
                call_copy["stack_arguments"] = stack_arguments_payload
            if request is not None:
                call_copy["instruction_window"] = request
            if call_warnings:
                call_copy["warnings"] = call_warnings
                warnings.extend(call_warnings)
            calls.append(call_copy)
        results.append(
            {
                "target_va": result["target_va"],
                "target_rva": result["target_rva"],
                "hit_count": len(calls),
                "unfiltered_hit_count": result["hit_count"],
                "calls": calls,
            }
        )

    return {
        "type": "pe-callsite-registers",
        "target": str(target_path),
        "image_base": _hex(metadata.image_base),
        "scan": {
            "target_count": len(targets),
            "registers": list(requested_registers),
            "stack_argument_offsets": [_hex(offset) for offset in requested_stack_offsets],
            "max_backtrack_instructions": max_backtrack_instructions,
            "function_filters": function_filters,
            "direct_call_opcode_count": direct_payload["scan"]["direct_call_opcode_count"],  # type: ignore[index]
            "runtime_function_count": direct_payload["scan"]["runtime_function_count"],  # type: ignore[index]
            "instruction_window_count": len(window_requests),
        },
        "results": results,
        "warnings": warnings,
    }
