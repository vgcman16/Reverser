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
    if value < 0:
        return f"-0x{abs(value):x}"
    return f"0x{value:x}"


@dataclass(frozen=True)
class _ScanRange:
    request: str
    section: PESection
    start_va: int
    end_va: int
    start_offset: int
    end_offset: int


def _normalize_immediates(values: list[str | int]) -> list[int]:
    normalized: list[int] = []
    seen: set[int] = set()
    for value in values:
        parsed = parse_int_literal(str(value))
        if parsed in seen:
            continue
        seen.add(parsed)
        normalized.append(parsed)
    return normalized


def _normalize_mnemonics(mnemonics: list[str] | tuple[str, ...] | None) -> set[str]:
    return {mnemonic.upper() for mnemonic in mnemonics or []}


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


def find_pe_immediates(
    path: str | Path,
    immediates: list[str | int],
    *,
    mnemonics: list[str] | tuple[str, ...] = (),
    functions: list[str] | tuple[str, ...] = (),
    max_hits_per_immediate: int = 128,
) -> dict[str, object]:
    target_path = Path(path)
    data = target_path.read_bytes()
    metadata = read_pe_metadata(data)
    runtime_functions = read_pe_runtime_functions(data, metadata)
    normalized_immediates = _normalize_immediates(immediates)
    mnemonic_filter = _normalize_mnemonics(mnemonics)
    hits_by_immediate: dict[int, list[dict[str, object]]] = {value: [] for value in normalized_immediates}
    hit_counts: dict[int, int] = {value: 0 for value in normalized_immediates}
    executable_sections = [section for section in metadata.sections if section.is_executable and section.raw_size > 0]
    scan_ranges = (
        _function_scan_ranges(metadata, runtime_functions, functions)
        if functions
        else _section_scan_ranges(metadata, data)
    )
    decoded_instruction_count = 0
    immediate_instruction_count = 0

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

            immediate = instruction.get("immediate")
            if isinstance(immediate, int):
                immediate_instruction_count += 1
                mnemonic = str(instruction["mnemonic"]).upper()
                if immediate in hit_counts and (not mnemonic_filter or mnemonic in mnemonic_filter):
                    hit_counts[immediate] += 1
                    if len(hits_by_immediate[immediate]) < max_hits_per_immediate:
                        hit: dict[str, object] = {
                            "reference_va": instruction["address_va"],
                            "reference_rva": instruction["address_rva"],
                            "section": instruction["section"],
                            "raw_offset": instruction["raw_offset"],
                            "raw_bytes": instruction["raw_bytes"],
                            "length": instruction["length"],
                            "mnemonic": instruction["mnemonic"],
                            "operands": instruction.get("operands", ""),
                            "instruction": instruction["instruction"],
                            "immediate": immediate,
                            "immediate_hex": _hex(immediate),
                        }
                        for key in (
                            "kind",
                            "register",
                            "memory_target_va",
                            "memory_target_rva",
                            "target_va",
                            "target_rva",
                            "branch_kind",
                            "call_kind",
                        ):
                            if key in instruction:
                                hit[key] = instruction[key]
                        containing = function_for_rva(runtime_functions, int(str(instruction["address_rva"]), 0))
                        if containing is not None:
                            hit["function"] = runtime_function_to_dict(containing, metadata)
                        hits_by_immediate[immediate].append(hit)

            cursor += length

    return {
        "type": "pe-immediates",
        "target": str(target_path),
        "image_base": _hex(metadata.image_base),
        "scan": {
            "immediate_count": len(normalized_immediates),
            "mnemonic_filter": sorted(mnemonic_filter),
            "function_filters": list(functions),
            "executable_section_count": len(executable_sections),
            "decoded_instruction_count": decoded_instruction_count,
            "immediate_instruction_count": immediate_instruction_count,
            "immediate_hit_count": sum(hit_counts.values()),
            "runtime_function_count": len(runtime_functions),
            "max_hits_per_immediate": max_hits_per_immediate,
            "scan_range_count": len(scan_ranges),
            "scan_ranges": [_scan_range_payload(metadata, scan_range) for scan_range in scan_ranges],
            "executable_sections": [_section_payload(section) for section in executable_sections],
        },
        "results": [
            {
                "immediate": _hex(immediate),
                "value": immediate,
                "hit_count": hit_counts[immediate],
                "returned_hit_count": len(hits_by_immediate[immediate]),
                "truncated_hit_count": max(0, hit_counts[immediate] - len(hits_by_immediate[immediate])),
                "hits": hits_by_immediate[immediate],
            }
            for immediate in normalized_immediates
        ],
        "warnings": [],
    }
