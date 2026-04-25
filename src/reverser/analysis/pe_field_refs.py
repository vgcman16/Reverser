from __future__ import annotations

from pathlib import Path

from reverser.analysis.pe_direct_calls import PEMetadata, PESection, parse_int_literal, read_pe_metadata
from reverser.analysis.pe_instructions import (
    _decode_instruction_at,
    _full_width_immediate_size,
    _operand_size,
    _parse_modrm,
    _read_prefixes,
)
from reverser.analysis.pe_runtime_functions import (
    RuntimeFunction,
    function_for_rva,
    read_pe_runtime_functions,
    runtime_function_to_dict,
)


def _hex(value: int) -> str:
    return f"0x{value:x}"


_BYTE_MODRM_OPCODES = {
    0x00,
    0x02,
    0x08,
    0x0A,
    0x10,
    0x12,
    0x18,
    0x1A,
    0x20,
    0x22,
    0x28,
    0x2A,
    0x30,
    0x32,
    0x38,
    0x3A,
    0x84,
    0x86,
    0x88,
    0x8A,
    0xC6,
    0xF6,
    0xFE,
}

_WORD_MODRM_OPCODES = {
    0x01,
    0x03,
    0x09,
    0x0B,
    0x11,
    0x13,
    0x19,
    0x1B,
    0x21,
    0x23,
    0x29,
    0x2B,
    0x31,
    0x33,
    0x39,
    0x3B,
    0x69,
    0x6B,
    0x85,
    0x87,
    0x89,
    0x8B,
    0x8D,
    0xC7,
    0xF7,
    0xFF,
}

_TWO_BYTE_MODRM_OPCODES = {
    *range(0x10, 0x18),
    *range(0x28, 0x30),
    *range(0x40, 0x50),
    *range(0x90, 0xA0),
    0x2C,
    0x2D,
    0x2E,
    0x2F,
    0x5A,
    0x5B,
    0x6E,
    0x7E,
    0xAF,
    0xB0,
    0xB1,
    0xB6,
    0xB7,
    0xBA,
    0xBE,
    0xBF,
}


def _is_prefix_byte(value: int) -> bool:
    return value in (0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65, 0x66, 0x67, 0xF0, 0xF2, 0xF3) or 0x40 <= value <= 0x4F


def _normalize_registers(registers: list[str] | tuple[str, ...] | None) -> set[str]:
    return {register.upper() for register in registers or []}


def _memory_base_register(memory_operand: str) -> str | None:
    operand = memory_operand
    if ":" in operand:
        operand = operand.split(":", 1)[1]
    if not (operand.startswith("[") and operand.endswith("]")):
        return None
    inner = operand[1:-1]
    separator_positions = [position for position in (inner.find("+"), inner.find("-")) if position >= 0]
    first = inner[: min(separator_positions)] if separator_positions else inner
    first = first.strip().upper()
    if not first or first.startswith("0X") or "*" in first:
        return None
    return first


def _normalize_offsets(offsets: list[str | int]) -> list[int]:
    normalized: list[int] = []
    seen: set[int] = set()
    for offset in offsets:
        value = parse_int_literal(str(offset))
        if value in seen:
            continue
        seen.add(value)
        normalized.append(value)
    return normalized


def _selected_sections(metadata: PEMetadata, section_names: list[str] | None) -> list[PESection]:
    requested_sections = {name.lower() for name in section_names or []}
    return [
        section
        for section in metadata.sections
        if section.raw_size > 0
        and section.is_executable
        and (not requested_sections or section.name.lower() in requested_sections)
    ]


def _instruction_length(data: bytes, opcode_offset: int, opcode: int, parsed_length: int, operand_size: int) -> int:
    if opcode in (0x80, 0x83, 0xC6):
        immediate_size = 1
    elif opcode in (0x81, 0xC7):
        immediate_size = _full_width_immediate_size(operand_size)
    elif opcode == 0x69:
        immediate_size = _full_width_immediate_size(operand_size)
    elif opcode == 0x6B:
        immediate_size = 1
    elif opcode == 0xF6:
        group = (data[opcode_offset + 1] >> 3) & 0x7 if opcode_offset + 1 < len(data) else 0xFF
        immediate_size = 1 if group in (0, 1) else 0
    elif opcode == 0xF7:
        group = (data[opcode_offset + 1] >> 3) & 0x7 if opcode_offset + 1 < len(data) else 0xFF
        immediate_size = _full_width_immediate_size(operand_size) if group in (0, 1) else 0
    else:
        immediate_size = 0
    return 1 + parsed_length + immediate_size


def _field_ref_candidate_at(
    data: bytes,
    metadata: PEMetadata,
    section: PESection,
    raw_start: int,
    cursor: int,
    raw_end: int,
) -> dict[str, object] | None:
    if cursor > raw_start and _is_prefix_byte(data[cursor - 1]):
        return None

    prefixes = _read_prefixes(data, cursor)
    opcode_offset = prefixes.opcode_offset
    if opcode_offset >= raw_end:
        return None

    opcode = data[opcode_offset]
    operand_size = _operand_size(prefixes)
    opcode_byte_count = 1
    rm_size: int | None

    if opcode in _BYTE_MODRM_OPCODES:
        rm_size = 8
    elif opcode in _WORD_MODRM_OPCODES:
        rm_size = operand_size
    elif opcode == 0x0F and opcode_offset + 1 < raw_end and data[opcode_offset + 1] in _TWO_BYTE_MODRM_OPCODES:
        opcode_byte_count = 2
        rm_size = 8 if data[opcode_offset + 1] in range(0x90, 0xA0) else operand_size
    else:
        return None

    instruction_va = metadata.image_base + section.virtual_address + (cursor - raw_start)
    operand_start = opcode_offset + opcode_byte_count
    parsed = _parse_modrm(
        data,
        prefixes=prefixes,
        opcode_offset=opcode_offset,
        operand_start=operand_start,
        instruction_va=instruction_va,
        rm_size=rm_size,
    )
    if parsed is None or parsed.mod == 0x3 or parsed.displacement is None:
        return None

    prefix_length = opcode_offset - cursor
    length = prefix_length + opcode_byte_count + parsed.operand_length
    if opcode_byte_count == 1:
        length = prefix_length + _instruction_length(data, opcode_offset, opcode, parsed.operand_length, operand_size)
    return {
        "displacement": parsed.displacement,
        "length": length,
        "memory_operand": parsed.rm_operand,
    }


def _annotate_reference_function(hit: dict[str, object], metadata: PEMetadata, functions: list[RuntimeFunction]) -> None:
    reference_rva = parse_int_literal(str(hit["reference_rva"]))
    function = function_for_rva(functions, reference_rva)
    if function is None:
        return
    hit["function"] = runtime_function_to_dict(function, metadata)


def find_pe_field_refs(
    path: str | Path,
    offsets: list[str | int],
    *,
    max_hits_per_offset: int = 128,
    section_names: list[str] | None = None,
    base_registers: list[str] | tuple[str, ...] | None = None,
    exclude_stack: bool = False,
) -> dict[str, object]:
    target = Path(path)
    data = target.read_bytes()
    metadata = read_pe_metadata(data)
    runtime_functions = read_pe_runtime_functions(data, metadata)
    normalized_offsets = _normalize_offsets(offsets)
    offset_set = set(normalized_offsets)
    normalized_base_registers = _normalize_registers(base_registers)
    sections = _selected_sections(metadata, section_names)

    hits_by_offset: dict[int, list[dict[str, object]]] = {offset: [] for offset in normalized_offsets}
    hit_counts_by_offset: dict[int, int] = {offset: 0 for offset in normalized_offsets}
    scanned_code_byte_count = 0

    for section in sections:
        raw_start = section.raw_pointer
        raw_end = min(len(data), section.raw_pointer + section.raw_size)
        for cursor in range(raw_start, raw_end):
            scanned_code_byte_count += 1
            candidate = _field_ref_candidate_at(data, metadata, section, raw_start, cursor, raw_end)
            if candidate is None:
                continue
            displacement = int(candidate["displacement"])
            if displacement not in offset_set:
                continue
            base_register = _memory_base_register(str(candidate["memory_operand"]))
            if exclude_stack and base_register in {"RSP", "ESP", "SP", "RBP", "EBP", "BP"}:
                continue
            if normalized_base_registers and base_register not in normalized_base_registers:
                continue

            reference_rva = section.virtual_address + (cursor - raw_start)
            reference_va = metadata.image_base + reference_rva
            decoded = _decode_instruction_at(data, metadata, runtime_functions, section, raw_start, cursor, raw_end)
            hit: dict[str, object] = {
                "kind": "modrm-displacement",
                "reference_va": _hex(reference_va),
                "reference_rva": _hex(reference_rva),
                "section": section.name,
                "raw_offset": _hex(cursor),
                "instruction_length": candidate["length"],
                "memory_operand": candidate["memory_operand"],
                "base_register": base_register,
                "raw_bytes": data[cursor : cursor + int(candidate["length"])].hex(),
            }
            if decoded is not None:
                hit["instruction"] = decoded.get("instruction", "")
                hit["mnemonic"] = decoded.get("mnemonic", "")
                hit["operands"] = decoded.get("operands", "")
            _annotate_reference_function(hit, metadata, runtime_functions)
            hit_counts_by_offset[displacement] += 1
            if len(hits_by_offset[displacement]) < max_hits_per_offset:
                hits_by_offset[displacement].append(hit)

    return {
        "type": "pe-field-refs",
        "target": str(target),
        "image_base": _hex(metadata.image_base),
        "scan": {
            "section_filter": section_names or [],
            "sections_scanned": [
                {
                    "name": section.name,
                    "virtual_address": _hex(section.virtual_address),
                    "virtual_size": _hex(section.virtual_size),
                    "raw_pointer": _hex(section.raw_pointer),
                    "raw_size": _hex(section.raw_size),
                }
                for section in sections
            ],
            "offset_count": len(normalized_offsets),
            "scanned_code_byte_count": scanned_code_byte_count,
            "runtime_function_count": len(runtime_functions),
            "max_hits_per_offset": max_hits_per_offset,
            "base_register_filter": sorted(normalized_base_registers),
            "exclude_stack": exclude_stack,
        },
        "results": [
            {
                "offset": _hex(offset),
                "hit_count": hit_counts_by_offset[offset],
                "returned_hit_count": len(hits_by_offset[offset]),
                "truncated_hit_count": max(0, hit_counts_by_offset[offset] - len(hits_by_offset[offset])),
                "hits": hits_by_offset[offset],
            }
            for offset in normalized_offsets
        ],
    }
