from __future__ import annotations

import struct
from pathlib import Path

from reverser.analysis.pe_direct_calls import PEMetadata, PESection, parse_int_literal, read_pe_metadata


def _hex(value: int) -> str:
    return f"0x{value:x}"


_RIP_RELATIVE_OPCODES = {
    0x03: "add-load",
    0x2B: "sub-load",
    0x39: "cmp-store",
    0x3B: "cmp-load",
    0x85: "test",
    0x87: "xchg",
    0x88: "mov-store-byte",
    0x89: "mov-store",
    0x8A: "mov-load-byte",
    0x8B: "mov-load",
    0x8D: "lea",
}


def _normalize_targets(targets: list[str | int], metadata: PEMetadata) -> list[tuple[int, int]]:
    normalized: list[tuple[int, int]] = []
    seen: set[int] = set()
    for target in targets:
        va, rva = metadata.normalize_va_or_rva(parse_int_literal(str(target)))
        if va in seen:
            continue
        seen.add(va)
        normalized.append((va, rva))
    return normalized


def _selected_sections(metadata: PEMetadata, section_names: list[str] | None) -> list[PESection]:
    requested_sections = {name.lower() for name in section_names or []}
    return [
        section
        for section in metadata.sections
        if section.raw_size > 0 and (not requested_sections or section.name.lower() in requested_sections)
    ]


def _record_hit(
    hits_by_target: dict[int, list[dict[str, object]]],
    hit_counts_by_target: dict[int, int],
    target_va: int,
    hit: dict[str, object],
    *,
    max_hits_per_target: int,
) -> None:
    hit_counts_by_target[target_va] += 1
    if len(hits_by_target[target_va]) < max_hits_per_target:
        hits_by_target[target_va].append(hit)


def _scan_qword_refs(
    data: bytes,
    metadata: PEMetadata,
    sections: list[PESection],
    target_by_va: dict[int, int],
    hits_by_target: dict[int, list[dict[str, object]]],
    hit_counts_by_target: dict[int, int],
    *,
    max_hits_per_target: int,
) -> int:
    scanned_qword_count = 0
    for section in sections:
        if section.is_executable:
            continue
        raw_start = section.raw_pointer
        raw_end = min(len(data), section.raw_pointer + section.raw_size)
        raw_cursor = raw_start
        while raw_cursor + 8 <= raw_end:
            scanned_qword_count += 1
            value = struct.unpack_from("<Q", data, raw_cursor)[0]
            if value in target_by_va:
                reference_rva = section.virtual_address + (raw_cursor - raw_start)
                reference_va = metadata.image_base + reference_rva
                _record_hit(
                    hits_by_target,
                    hit_counts_by_target,
                    value,
                    {
                        "kind": "absolute-qword",
                        "reference_va": _hex(reference_va),
                        "reference_rva": _hex(reference_rva),
                        "target_va": _hex(value),
                        "target_rva": _hex(target_by_va[value]),
                        "section": section.name,
                        "raw_offset": _hex(raw_cursor),
                    },
                    max_hits_per_target=max_hits_per_target,
                )
            raw_cursor += 8
    return scanned_qword_count


def _rip_relative_ref_at(
    data: bytes,
    metadata: PEMetadata,
    section: PESection,
    raw_start: int,
    cursor: int,
) -> dict[str, object] | None:
    if cursor + 6 > len(data):
        return None

    prefix_len = 0
    rex_prefix = None
    first = data[cursor]
    if 0x40 <= first <= 0x4F:
        prefix_len = 1
        rex_prefix = first
    elif cursor > raw_start and 0x40 <= data[cursor - 1] <= 0x4F:
        return None

    opcode_offset = cursor + prefix_len
    if opcode_offset + 6 > len(data):
        return None

    opcode = data[opcode_offset]
    opcode_name = _RIP_RELATIVE_OPCODES.get(opcode)
    if opcode_name is None:
        return None

    modrm = data[opcode_offset + 1]
    if modrm & 0xC7 != 0x05:
        return None

    displacement = struct.unpack_from("<i", data, opcode_offset + 2)[0]
    instruction_length = prefix_len + 6
    reference_rva = section.virtual_address + (cursor - raw_start)
    reference_va = metadata.image_base + reference_rva
    target_va = reference_va + instruction_length + displacement
    result: dict[str, object] = {
        "kind": f"rip-relative-{opcode_name}",
        "reference_va": _hex(reference_va),
        "reference_rva": _hex(reference_rva),
        "target_va": _hex(target_va),
        "target_rva": _hex(target_va - metadata.image_base),
        "section": section.name,
        "raw_offset": _hex(cursor),
        "instruction_length": instruction_length,
        "displacement": displacement,
        "opcode": _hex(opcode),
        "modrm": _hex(modrm),
        "raw_bytes": data[cursor : cursor + instruction_length].hex(),
    }
    if rex_prefix is not None:
        result["rex_prefix"] = _hex(rex_prefix)
    return result


def _movabs_ref_at(data: bytes, metadata: PEMetadata, section: PESection, raw_start: int, cursor: int) -> dict[str, object] | None:
    if cursor + 10 > len(data) or not (0x48 <= data[cursor] <= 0x4F) or not (0xB8 <= data[cursor + 1] <= 0xBF):
        return None
    value = struct.unpack_from("<Q", data, cursor + 2)[0]
    reference_rva = section.virtual_address + (cursor - raw_start)
    reference_va = metadata.image_base + reference_rva
    return {
        "kind": "movabs-imm64",
        "reference_va": _hex(reference_va),
        "reference_rva": _hex(reference_rva),
        "target_va": _hex(value),
        "target_rva": _hex(value - metadata.image_base),
        "section": section.name,
        "raw_offset": _hex(cursor),
        "instruction_length": 10,
        "opcode": _hex(data[cursor + 1]),
        "raw_bytes": data[cursor : cursor + 10].hex(),
    }


def _scan_code_refs(
    data: bytes,
    metadata: PEMetadata,
    sections: list[PESection],
    target_by_va: dict[int, int],
    hits_by_target: dict[int, list[dict[str, object]]],
    hit_counts_by_target: dict[int, int],
    *,
    max_hits_per_target: int,
) -> int:
    scanned_byte_count = 0
    for section in sections:
        if not section.is_executable:
            continue
        raw_start = section.raw_pointer
        raw_end = min(len(data), raw_start + section.scan_size)
        scanned_byte_count += max(0, raw_end - raw_start)
        cursor = raw_start
        while cursor < raw_end:
            hit = _rip_relative_ref_at(data, metadata, section, raw_start, cursor)
            if hit is None:
                hit = _movabs_ref_at(data, metadata, section, raw_start, cursor)
            if hit is not None:
                target_va = parse_int_literal(str(hit["target_va"]))
                if target_va in target_by_va:
                    hit["target_rva"] = _hex(target_by_va[target_va])
                    _record_hit(
                        hits_by_target,
                        hit_counts_by_target,
                        target_va,
                        hit,
                        max_hits_per_target=max_hits_per_target,
                    )
                cursor += int(hit["instruction_length"])
                continue
            cursor += 1
    return scanned_byte_count


def find_pe_address_refs(
    path: str | Path,
    targets: list[str | int],
    *,
    max_hits_per_target: int = 32,
    section_names: list[str] | None = None,
) -> dict[str, object]:
    if max_hits_per_target <= 0:
        raise ValueError("Max hits per target must be greater than zero.")

    target_path = Path(path)
    data = target_path.read_bytes()
    metadata = read_pe_metadata(data)
    normalized_targets = _normalize_targets(targets, metadata)
    target_by_va = {va: rva for va, rva in normalized_targets}
    hits_by_target: dict[int, list[dict[str, object]]] = {va: [] for va, _ in normalized_targets}
    hit_counts_by_target: dict[int, int] = {va: 0 for va, _ in normalized_targets}
    sections = _selected_sections(metadata, section_names)

    scanned_qword_count = _scan_qword_refs(
        data,
        metadata,
        sections,
        target_by_va,
        hits_by_target,
        hit_counts_by_target,
        max_hits_per_target=max_hits_per_target,
    )
    scanned_code_byte_count = _scan_code_refs(
        data,
        metadata,
        sections,
        target_by_va,
        hits_by_target,
        hit_counts_by_target,
        max_hits_per_target=max_hits_per_target,
    )

    requested_sections = {name.lower() for name in section_names or []}
    return {
        "type": "pe-address-refs",
        "target": str(target_path),
        "image_base": _hex(metadata.image_base),
        "scan": {
            "section_filter": sorted(requested_sections),
            "sections_scanned": [
                {
                    "name": section.name,
                    "virtual_address": _hex(section.virtual_address),
                    "virtual_size": _hex(section.virtual_size),
                    "raw_pointer": _hex(section.raw_pointer),
                    "raw_size": _hex(section.raw_size),
                    "is_executable": section.is_executable,
                }
                for section in sections
            ],
            "target_count": len(normalized_targets),
            "scanned_qword_count": scanned_qword_count,
            "scanned_code_byte_count": scanned_code_byte_count,
            "max_hits_per_target": max_hits_per_target,
        },
        "results": [
            {
                "target_va": _hex(va),
                "target_rva": _hex(rva),
                "hit_count": hit_counts_by_target[va],
                "returned_hit_count": len(hits_by_target[va]),
                "truncated_hit_count": max(0, hit_counts_by_target[va] - len(hits_by_target[va])),
                "hits": hits_by_target[va],
            }
            for va, rva in normalized_targets
        ],
    }
