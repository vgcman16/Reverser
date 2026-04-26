from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

from reverser.analysis.pe_direct_calls import PEMetadata, PESection, parse_int_literal, read_pe_metadata
from reverser.analysis.pe_function_calls import _parse_function_spec
from reverser.analysis.pe_instructions import _decode_instruction_at
from reverser.analysis.pe_runtime_functions import (
    RuntimeFunction,
    function_for_rva,
    read_pe_runtime_functions,
    runtime_function_to_dict,
)


def _hex(value: int) -> str:
    return f"0x{value:x}"


_SHORT_JCC_NAMES = {
    0x70: "JO",
    0x71: "JNO",
    0x72: "JB",
    0x73: "JAE",
    0x74: "JZ",
    0x75: "JNZ",
    0x76: "JBE",
    0x77: "JA",
    0x78: "JS",
    0x79: "JNS",
    0x7A: "JP",
    0x7B: "JNP",
    0x7C: "JL",
    0x7D: "JGE",
    0x7E: "JLE",
    0x7F: "JG",
}

_NEAR_JCC_NAMES = {
    0x80: "JO",
    0x81: "JNO",
    0x82: "JB",
    0x83: "JAE",
    0x84: "JZ",
    0x85: "JNZ",
    0x86: "JBE",
    0x87: "JA",
    0x88: "JS",
    0x89: "JNS",
    0x8A: "JP",
    0x8B: "JNP",
    0x8C: "JL",
    0x8D: "JGE",
    0x8E: "JLE",
    0x8F: "JG",
}


@dataclass(frozen=True)
class _ScanRange:
    request: str
    section: PESection
    start_va: int
    end_va: int
    start_offset: int
    end_offset: int


def _section_scan_ranges(metadata: PEMetadata, data: bytes) -> list[_ScanRange]:
    ranges: list[_ScanRange] = []
    for section in metadata.sections:
        if not section.is_executable or section.raw_size <= 0:
            continue
        raw_start = section.raw_pointer
        raw_end = min(len(data), raw_start + section.scan_size)
        ranges.append(
            _ScanRange(
                request=section.name,
                section=section,
                start_va=metadata.image_base + section.virtual_address,
                end_va=metadata.image_base + section.virtual_address + section.scan_size,
                start_offset=raw_start,
                end_offset=raw_end,
            )
        )
    return ranges


def _function_scan_ranges(
    metadata: PEMetadata,
    runtime_functions: list[RuntimeFunction],
    requests: list[str] | tuple[str, ...],
) -> list[_ScanRange]:
    ranges: list[_ScanRange] = []
    for request in requests:
        start_va, end_va = _parse_function_spec(str(request), metadata, runtime_functions)
        section = metadata.section_for_va(start_va)
        end_section = metadata.section_for_va(end_va - 1)
        if section is None:
            raise ValueError(f"Function window {request!r} starts outside mapped PE sections.")
        if end_section is None or end_section.name != section.name:
            raise ValueError(f"Function window {request!r} must stay within one mapped PE section.")
        ranges.append(
            _ScanRange(
                request=str(request),
                section=section,
                start_va=start_va,
                end_va=end_va,
                start_offset=metadata.rva_to_offset(start_va - metadata.image_base),
                end_offset=metadata.rva_to_offset(end_va - metadata.image_base - 1) + 1,
            )
        )
    return ranges


def _scan_range_payload(metadata: PEMetadata, scan_range: _ScanRange) -> dict[str, object]:
    return {
        "request": scan_range.request,
        "section": scan_range.section.name,
        "start_va": _hex(scan_range.start_va),
        "start_rva": _hex(scan_range.start_va - metadata.image_base),
        "end_va": _hex(scan_range.end_va),
        "end_rva": _hex(scan_range.end_va - metadata.image_base),
        "raw_start": _hex(scan_range.start_offset),
        "raw_end": _hex(scan_range.end_offset),
    }


def _section_payload(section: PESection) -> dict[str, object]:
    return {
        "name": section.name,
        "virtual_address": _hex(section.virtual_address),
        "virtual_size": _hex(section.virtual_size),
        "raw_pointer": _hex(section.raw_pointer),
        "raw_size": _hex(section.raw_size),
    }


def _raw_branch_candidate_at(
    data: bytes,
    metadata: PEMetadata,
    section: PESection,
    raw_start: int,
    cursor: int,
    raw_end: int,
) -> dict[str, object] | None:
    opcode = data[cursor]
    branchsite_va = metadata.image_base + section.virtual_address + (cursor - raw_start)

    if opcode == 0xEB and cursor + 2 <= raw_end:
        rel = struct.unpack_from("<b", data, cursor + 1)[0]
        target_va = branchsite_va + 2 + rel
        return {
            "length": 2,
            "mnemonic": "JMP",
            "branch_kind": "unconditional",
            "relative_offset": rel,
            "target_va": target_va,
        }

    if 0x70 <= opcode <= 0x7F and cursor + 2 <= raw_end:
        rel = struct.unpack_from("<b", data, cursor + 1)[0]
        target_va = branchsite_va + 2 + rel
        return {
            "length": 2,
            "mnemonic": _SHORT_JCC_NAMES[opcode],
            "branch_kind": "conditional",
            "relative_offset": rel,
            "target_va": target_va,
        }

    if opcode == 0xE9 and cursor + 5 <= raw_end:
        rel = struct.unpack_from("<i", data, cursor + 1)[0]
        target_va = branchsite_va + 5 + rel
        return {
            "length": 5,
            "mnemonic": "JMP",
            "branch_kind": "unconditional",
            "relative_offset": rel,
            "target_va": target_va,
        }

    if opcode == 0x0F and cursor + 6 <= raw_end and data[cursor + 1] in _NEAR_JCC_NAMES:
        opcode2 = data[cursor + 1]
        rel = struct.unpack_from("<i", data, cursor + 2)[0]
        target_va = branchsite_va + 6 + rel
        return {
            "length": 6,
            "mnemonic": _NEAR_JCC_NAMES[opcode2],
            "branch_kind": "conditional",
            "relative_offset": rel,
            "target_va": target_va,
        }

    return None


def _raw_branch_instruction(candidate: dict[str, object], target_va: int) -> str:
    return f"{candidate['mnemonic']} {_hex(target_va)}"


def find_pe_branch_targets(
    path: str | Path,
    targets: list[str | int],
    *,
    functions: list[str] | tuple[str, ...] = (),
    strategy: str = "decoded",
) -> dict[str, object]:
    target_path = Path(path)
    data = target_path.read_bytes()
    metadata = read_pe_metadata(data)
    runtime_functions = read_pe_runtime_functions(data, metadata)
    normalized_targets = [metadata.normalize_va_or_rva(parse_int_literal(str(target))) for target in targets]
    target_by_va = {va: rva for va, rva in normalized_targets}
    branches_by_target: dict[int, list[dict[str, object]]] = {va: [] for va, _ in normalized_targets}
    executable_sections = [section for section in metadata.sections if section.is_executable and section.raw_size > 0]
    scan_ranges = (
        _function_scan_ranges(metadata, runtime_functions, functions)
        if functions
        else _section_scan_ranges(metadata, data)
    )
    decoded_instruction_count = 0
    branch_instruction_count = 0
    scanned_byte_count = 0

    if strategy not in {"decoded", "raw"}:
        raise ValueError("strategy must be 'decoded' or 'raw'.")

    for scan_range in scan_ranges:
        section = scan_range.section
        cursor = scan_range.start_offset
        raw_end = min(scan_range.end_offset, len(data))
        if strategy == "raw":
            while cursor < raw_end:
                scanned_byte_count += 1
                candidate = _raw_branch_candidate_at(data, metadata, section, section.raw_pointer, cursor, raw_end)
                if candidate is not None:
                    branch_instruction_count += 1
                    target_va = int(candidate["target_va"])
                    if target_va in target_by_va:
                        branchsite_rva = section.virtual_address + (cursor - section.raw_pointer)
                        branch: dict[str, object] = {
                            "branchsite_va": _hex(metadata.image_base + branchsite_rva),
                            "branchsite_rva": _hex(branchsite_rva),
                            "target_va": _hex(target_va),
                            "target_rva": _hex(target_by_va[target_va]),
                            "relative_offset": candidate["relative_offset"],
                            "branch_kind": candidate["branch_kind"],
                            "mnemonic": candidate["mnemonic"],
                            "section": section.name,
                            "raw_offset": _hex(cursor),
                            "raw_bytes": data[cursor : cursor + int(candidate["length"])].hex(),
                            "instruction": _raw_branch_instruction(candidate, target_va),
                            "strategy": "raw",
                        }
                        containing = function_for_rva(runtime_functions, branchsite_rva)
                        if containing is not None:
                            branch["function"] = runtime_function_to_dict(containing, metadata)
                        target_function = function_for_rva(runtime_functions, target_by_va[target_va])
                        if target_function is not None:
                            branch["target_function"] = runtime_function_to_dict(target_function, metadata)
                        branches_by_target[target_va].append(branch)
                cursor += 1
            continue

        target_hexes = {_hex(va) for va in target_by_va}
        while cursor < raw_end:
            instruction = _decode_instruction_at(
                data,
                metadata,
                runtime_functions,
                section,
                section.raw_pointer,
                cursor,
                raw_end,
            )
            length = max(1, int(instruction["length"]))
            decoded_instruction_count += 1

            if instruction.get("kind") == "branch":
                branch_instruction_count += 1
            if instruction.get("kind") == "branch" and instruction.get("target_va") in target_hexes:
                target_va = int(str(instruction["target_va"]), 0)
                branch: dict[str, object] = {
                    "branchsite_va": instruction["address_va"],
                    "branchsite_rva": instruction["address_rva"],
                    "target_va": instruction["target_va"],
                    "target_rva": instruction["target_rva"],
                    "relative_offset": instruction.get("relative_offset"),
                    "branch_kind": instruction.get("branch_kind"),
                    "mnemonic": instruction["mnemonic"],
                    "section": instruction["section"],
                    "raw_offset": instruction["raw_offset"],
                    "raw_bytes": instruction["raw_bytes"],
                    "instruction": instruction["instruction"],
                }
                containing = function_for_rva(runtime_functions, int(str(instruction["address_rva"]), 0))
                if containing is not None:
                    branch["function"] = runtime_function_to_dict(containing, metadata)
                if "target_function" in instruction:
                    branch["target_function"] = instruction["target_function"]
                branches_by_target[target_va].append(branch)

            cursor += length

    return {
        "type": "pe-branch-targets",
        "target": str(target_path),
        "image_base": _hex(metadata.image_base),
        "scan": {
            "strategy": strategy,
            "target_count": len(normalized_targets),
            "executable_section_count": len(executable_sections),
            "scanned_byte_count": scanned_byte_count,
            "decoded_instruction_count": decoded_instruction_count,
            "branch_instruction_count": branch_instruction_count,
            "branch_hit_count": sum(len(branches) for branches in branches_by_target.values()),
            "runtime_function_count": len(runtime_functions),
            "function_filters": list(functions),
            "scan_range_count": len(scan_ranges),
            "scan_ranges": [_scan_range_payload(metadata, scan_range) for scan_range in scan_ranges],
            "executable_sections": [_section_payload(section) for section in executable_sections],
        },
        "results": [
            {
                "target_va": _hex(va),
                "target_rva": _hex(rva),
                "hit_count": len(branches_by_target[va]),
                "branches": branches_by_target[va],
            }
            for va, rva in normalized_targets
        ],
    }
