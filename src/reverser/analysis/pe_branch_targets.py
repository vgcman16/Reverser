from __future__ import annotations

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


def find_pe_branch_targets(
    path: str | Path,
    targets: list[str | int],
    *,
    functions: list[str] | tuple[str, ...] = (),
) -> dict[str, object]:
    target_path = Path(path)
    data = target_path.read_bytes()
    metadata = read_pe_metadata(data)
    runtime_functions = read_pe_runtime_functions(data, metadata)
    normalized_targets = [metadata.normalize_va_or_rva(parse_int_literal(str(target))) for target in targets]
    target_by_va = {va: rva for va, rva in normalized_targets}
    target_hexes = {_hex(va) for va in target_by_va}
    branches_by_target: dict[int, list[dict[str, object]]] = {va: [] for va, _ in normalized_targets}
    executable_sections = [section for section in metadata.sections if section.is_executable and section.raw_size > 0]
    scan_ranges = (
        _function_scan_ranges(metadata, runtime_functions, functions)
        if functions
        else _section_scan_ranges(metadata, data)
    )
    decoded_instruction_count = 0
    branch_instruction_count = 0

    for scan_range in scan_ranges:
        section = scan_range.section
        cursor = scan_range.start_offset
        raw_end = min(scan_range.end_offset, len(data))
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
            "target_count": len(normalized_targets),
            "executable_section_count": len(executable_sections),
            "decoded_instruction_count": decoded_instruction_count,
            "branch_instruction_count": branch_instruction_count,
            "branch_hit_count": sum(len(branches) for branches in branches_by_target.values()),
            "runtime_function_count": len(runtime_functions),
            "function_filters": list(functions),
            "scan_range_count": len(scan_ranges),
            "scan_ranges": [
                {
                    "request": scan_range.request,
                    "section": scan_range.section.name,
                    "start_va": _hex(scan_range.start_va),
                    "start_rva": _hex(scan_range.start_va - metadata.image_base),
                    "end_va": _hex(scan_range.end_va),
                    "end_rva": _hex(scan_range.end_va - metadata.image_base),
                    "raw_start": _hex(scan_range.start_offset),
                    "raw_end": _hex(scan_range.end_offset),
                }
                for scan_range in scan_ranges
            ],
            "executable_sections": [
                {
                    "name": section.name,
                    "virtual_address": _hex(section.virtual_address),
                    "virtual_size": _hex(section.virtual_size),
                    "raw_pointer": _hex(section.raw_pointer),
                    "raw_size": _hex(section.raw_size),
                }
                for section in executable_sections
            ],
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
