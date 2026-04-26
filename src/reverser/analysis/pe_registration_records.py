from __future__ import annotations

from pathlib import Path

from reverser.analysis.pe_direct_calls import PEMetadata, parse_int_literal, read_pe_metadata
from reverser.analysis.pe_function_calls import _parse_function_spec
from reverser.analysis.pe_instructions import _decode_instruction_at
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


def _instruction_va(instruction: dict[str, object]) -> int:
    return parse_int_literal(str(instruction["address_va"]))


def _target_va(instruction: dict[str, object]) -> int | None:
    value = instruction.get("target_va")
    if value is None:
        return None
    return parse_int_literal(str(value))


def _memory_target_va(instruction: dict[str, object]) -> int | None:
    value = instruction.get("memory_target_va")
    if value is None:
        return None
    return parse_int_literal(str(value))


def _destination_register(instruction: dict[str, object]) -> str | None:
    register = instruction.get("register")
    if isinstance(register, str):
        return register.upper()
    operands = str(instruction.get("operands", ""))
    if "," not in operands:
        return None
    return operands.split(",", 1)[0].strip().upper()


def _find_recent_immediate(
    instructions: list[dict[str, object]],
    registers: set[str],
) -> tuple[int, dict[str, object]] | None:
    for instruction in reversed(instructions):
        destination = _destination_register(instruction)
        if destination not in registers:
            continue
        if instruction.get("mnemonic") == "MOV" and "immediate" in instruction:
            return int(instruction["immediate"]), instruction
        operands = str(instruction.get("operands", "")).upper().replace(" ", "")
        if instruction.get("mnemonic") == "XOR" and operands in {f"{destination},{destination}"}:
            return 0, instruction
    return None


def _find_recent_memory_target(
    instructions: list[dict[str, object]],
    register: str,
) -> tuple[int, dict[str, object]] | None:
    for instruction in reversed(instructions):
        if _destination_register(instruction) != register:
            continue
        target = _memory_target_va(instruction)
        if target is not None:
            return target, instruction
    return None


def _find_slot_helper(
    instructions: list[dict[str, object]],
    *,
    start_index: int,
    slot_helper_va: int,
    selector: int,
    image_base: int,
    include_evidence: bool,
    lookahead_instructions: int,
) -> dict[str, object] | None:
    limit = min(len(instructions), start_index + 1 + lookahead_instructions)
    for index in range(start_index + 1, limit):
        instruction = instructions[index]
        if instruction.get("mnemonic") != "CALL" or _target_va(instruction) != slot_helper_va:
            continue
        setup = instructions[start_index + 1 : index]
        slot_selector = _find_recent_immediate(setup, {"EDX", "RDX", "DX"})
        table_base = _find_recent_memory_target(setup, "RCX")
        if slot_selector is not None and slot_selector[0] != selector:
            continue

        helper: dict[str, object] = {
            "callsite_va": instruction["address_va"],
            "callsite_rva": instruction["address_rva"],
            "target_va": instruction["target_va"],
            "setup_instruction_count": len(setup),
        }
        if include_evidence:
            helper["setup"] = setup[-8:]
        if slot_selector is not None:
            helper["selector_va"] = slot_selector[1]["address_va"]
        if table_base is not None:
            table_base_va = table_base[0]
            helper["table_base_va"] = _hex(table_base_va)
            helper["table_base_rva"] = _hex(table_base_va - image_base)
            helper["table_base_setup_va"] = table_base[1]["address_va"]
            helper["computed_slot_va"] = _hex(table_base_va + selector * 0x10)
            helper["computed_slot_rva"] = _hex(table_base_va + selector * 0x10 - image_base)
            helper["slot_stride"] = 16
        return helper
    return None


def _find_publish_copy(
    instructions: list[dict[str, object]],
    *,
    start_index: int,
    include_evidence: bool,
    lookahead_instructions: int,
) -> dict[str, object] | None:
    limit = min(len(instructions), start_index + 1 + lookahead_instructions)
    for index in range(start_index + 1, limit):
        instruction = instructions[index]
        if instruction.get("instruction") != "REP MOVSB":
            continue
        setup = instructions[max(start_index + 1, index - 6) : index]
        has_rdi_rax = any(str(item.get("instruction", "")).upper() == "MOV RDI, RAX" for item in setup)
        size = _find_recent_immediate(setup, {"ECX", "RCX", "CX"})
        if not has_rdi_rax or size is None:
            continue
        payload: dict[str, object] = {
            "copy_va": instruction["address_va"],
            "copy_rva": instruction["address_rva"],
            "record_size": size[0],
            "size_setup_va": size[1]["address_va"],
        }
        if include_evidence:
            payload["setup"] = setup
            payload["instruction"] = instruction
        return payload
    return None


def _scan_range_instructions(
    data: bytes,
    metadata: PEMetadata,
    runtime_functions: list[object],
    *,
    start_va: int,
    end_va: int,
) -> tuple[list[dict[str, object]], str | None, int]:
    section = metadata.section_for_va(start_va)
    end_section = metadata.section_for_va(end_va - 1)
    if section is None or end_section is None or section.name != end_section.name:
        return [], "range does not map to one PE section", 0

    start_offset = metadata.rva_to_offset(start_va - metadata.image_base)
    end_offset = metadata.rva_to_offset(end_va - metadata.image_base - 1) + 1
    cursor = start_offset
    instructions: list[dict[str, object]] = []
    while cursor < end_offset:
        instruction = _decode_instruction_at(data, metadata, runtime_functions, section, section.raw_pointer, cursor, end_offset)
        instructions.append(instruction)
        cursor += max(1, int(instruction.get("length", 1)))
    return instructions, None, max(0, end_offset - start_offset)


def _entry_from_constructor_call(
    instructions: list[dict[str, object]],
    index: int,
    *,
    constructor_va: int,
    slot_helper_va: int | None,
    image_base: int,
    include_evidence: bool,
    lookback_instructions: int,
    lookahead_instructions: int,
) -> dict[str, object] | None:
    instruction = instructions[index]
    if instruction.get("mnemonic") != "CALL" or _target_va(instruction) != constructor_va:
        return None

    setup = instructions[max(0, index - lookback_instructions) : index]
    selector = _find_recent_immediate(setup, {"R8W", "R8D", "R8", "R8B"})
    handler = _find_recent_memory_target(setup, "RDX")
    if selector is None or handler is None:
        return None

    selector_value = selector[0]
    handler_va = handler[0]
    flags = _find_recent_immediate(setup, {"R9B", "R9D", "R9", "R9W"})
    entry: dict[str, object] = {
        "constructor_call_va": instruction["address_va"],
        "constructor_call_rva": instruction["address_rva"],
        "constructor_va": _hex(constructor_va),
        "constructor_rva": _hex(constructor_va - image_base),
        "handler_va": _hex(handler_va),
        "handler_rva": _hex(handler_va - image_base),
        "selector": selector_value,
        "selector_hex": _hex(selector_value),
        "selector_setup_va": selector[1]["address_va"],
        "handler_setup_va": handler[1]["address_va"],
        "confidence": "medium",
    }
    if include_evidence:
        entry["evidence"] = {
            "constructor_setup": setup[-12:],
            "constructor_call": instruction,
        }
    if flags is not None:
        entry["flags"] = flags[0]
        entry["flags_hex"] = _hex(flags[0])
        entry["flags_setup_va"] = flags[1]["address_va"]

    helper_index: int | None = None
    if slot_helper_va is not None:
        helper = _find_slot_helper(
            instructions,
            start_index=index,
            slot_helper_va=slot_helper_va,
            selector=selector_value,
            image_base=image_base,
            include_evidence=include_evidence,
            lookahead_instructions=lookahead_instructions,
        )
        if helper is not None:
            entry["slot_helper"] = helper
            helper_call_va = parse_int_literal(str(helper["callsite_va"]))
            for candidate_index, candidate in enumerate(instructions):
                if _instruction_va(candidate) == helper_call_va:
                    helper_index = candidate_index
                    break
            entry["confidence"] = "high"

    publish_start = helper_index if helper_index is not None else index
    publish = _find_publish_copy(
        instructions,
        start_index=publish_start,
        include_evidence=include_evidence,
        lookahead_instructions=lookahead_instructions,
    )
    if publish is not None:
        entry["publish_copy"] = publish
        entry["record_size"] = publish["record_size"]
        entry["confidence"] = "high" if entry.get("slot_helper") is not None else "medium"

    return entry


def find_pe_registration_records(
    path: str | Path,
    ranges: list[str],
    *,
    constructor: str | int,
    slot_helper: str | int | None = None,
    lookback_instructions: int = 16,
    lookahead_instructions: int = 24,
    max_records_per_range: int = 256,
    include_evidence: bool = False,
) -> dict[str, object]:
    if lookback_instructions <= 0:
        raise ValueError("Lookback instruction count must be greater than zero.")
    if lookahead_instructions <= 0:
        raise ValueError("Lookahead instruction count must be greater than zero.")
    if max_records_per_range <= 0:
        raise ValueError("Max records per range must be greater than zero.")

    target_path = Path(path)
    data = target_path.read_bytes()
    metadata = read_pe_metadata(data)
    runtime_functions = read_pe_runtime_functions(data, metadata)
    constructor_va = _normalize_address(constructor, metadata)
    slot_helper_va = _normalize_address(slot_helper, metadata) if slot_helper is not None else None
    results: list[dict[str, object]] = []
    warnings: list[str] = []
    scanned_byte_count = 0
    decoded_instruction_count = 0

    for range_spec in ranges:
        start_va, end_va = _parse_function_spec(range_spec, metadata, runtime_functions)
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
            warnings.append(f"Range {range_spec!r} {warning}.")
        entries: list[dict[str, object]] = []
        hit_count = 0
        for index, instruction in enumerate(instructions):
            if instruction.get("mnemonic") != "CALL" or _target_va(instruction) != constructor_va:
                continue
            entry = _entry_from_constructor_call(
                instructions,
                index,
                constructor_va=constructor_va,
                slot_helper_va=slot_helper_va,
                image_base=metadata.image_base,
                include_evidence=include_evidence,
                lookback_instructions=lookback_instructions,
                lookahead_instructions=lookahead_instructions,
            )
            if entry is None:
                continue
            hit_count += 1
            if len(entries) < max_records_per_range:
                entries.append(entry)
        results.append(
            {
                "request": str(range_spec),
                "start_va": _hex(start_va),
                "start_rva": _hex(start_va - metadata.image_base),
                "end_va": _hex(end_va),
                "end_rva": _hex(end_va - metadata.image_base),
                "decoded_instruction_count": len(instructions),
                "registration_hit_count": hit_count,
                "registration_count": len(entries),
                "truncated_registration_count": max(0, hit_count - len(entries)),
                "registrations": entries,
            }
        )

    scan: dict[str, object] = {
        "range_count": len(ranges),
        "constructor_va": _hex(constructor_va),
        "lookback_instructions": lookback_instructions,
        "lookahead_instructions": lookahead_instructions,
        "max_records_per_range": max_records_per_range,
        "runtime_function_count": len(runtime_functions),
        "decoded_instruction_count": decoded_instruction_count,
        "scanned_byte_count": scanned_byte_count,
        "include_evidence": include_evidence,
    }
    if slot_helper_va is not None:
        scan["slot_helper_va"] = _hex(slot_helper_va)
        scan["slot_formula"] = "table_base + selector*16"

    return {
        "type": "pe-registration-records",
        "target": str(target_path),
        "image_base": _hex(metadata.image_base),
        "scan": scan,
        "ranges": results,
        "warnings": warnings,
    }
