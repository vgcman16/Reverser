from __future__ import annotations

from pathlib import Path

from reverser.analysis.pe_direct_calls import find_pe_direct_calls, parse_int_literal, read_pe_metadata
from reverser.analysis.pe_instructions import find_pe_instructions


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


def _hex(value: int) -> str:
    return f"0x{value:x}"


def _canonical_register(register: str) -> str:
    normalized = str(register).strip().upper()
    return _REGISTER_ALIASES.get(normalized, normalized)


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

    if mnemonic == "MOV" and source.startswith("["):
        payload["kind"] = "memory-load"
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
    backtrack = instructions[max(0, call_index - max_backtrack_instructions) : call_index]
    for instruction in reversed(backtrack):
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
            recovered[canonical_destination] = payload
            requested.remove(canonical_destination)
        if not requested:
            break
    return recovered, warnings


def find_pe_callsite_registers(
    path: str | Path,
    targets: list[str | int],
    *,
    registers: list[str] | tuple[str, ...] = ("RCX", "RDX", "R8", "R9"),
    max_backtrack_instructions: int = 16,
) -> dict[str, object]:
    target_path = Path(path)
    data = target_path.read_bytes()
    metadata = read_pe_metadata(data)
    requested_registers = tuple(dict.fromkeys(_canonical_register(register) for register in registers))
    direct_payload = find_pe_direct_calls(target_path, targets)

    window_requests: list[str] = []
    call_window_by_site: dict[str, str] = {}
    warnings: list[str] = []
    for result in direct_payload["results"]:  # type: ignore[index]
        for call in result["calls"]:  # type: ignore[index]
            callsite_va = str(call["callsite_va"])
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
            call_copy = dict(call)
            request = call_window_by_site.get(str(call["callsite_va"]))
            call_warnings: list[str] = []
            registers_payload: dict[str, object] = {}
            if request is not None:
                registers_payload, call_warnings = _recover_register_setups(
                    instruction_by_request.get(request, []),
                    callsite_va=str(call["callsite_va"]),
                    registers=requested_registers,
                    max_backtrack_instructions=max_backtrack_instructions,
                    metadata=metadata,
                )
            call_copy["registers"] = registers_payload
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
                "hit_count": result["hit_count"],
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
            "max_backtrack_instructions": max_backtrack_instructions,
            "direct_call_opcode_count": direct_payload["scan"]["direct_call_opcode_count"],  # type: ignore[index]
            "runtime_function_count": direct_payload["scan"]["runtime_function_count"],  # type: ignore[index]
            "instruction_window_count": len(window_requests),
        },
        "results": results,
        "warnings": warnings,
    }
