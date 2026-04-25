from __future__ import annotations

from pathlib import Path

from reverser.analysis.pe_direct_calls import parse_int_literal, read_pe_metadata
from reverser.analysis.pe_instructions import _decode_instruction_at
from reverser.analysis.pe_runtime_functions import (
    function_for_rva,
    read_pe_runtime_functions,
    runtime_function_to_dict,
)


def _hex(value: int) -> str:
    return f"0x{value:x}"


def find_pe_branch_targets(path: str | Path, targets: list[str | int]) -> dict[str, object]:
    target_path = Path(path)
    data = target_path.read_bytes()
    metadata = read_pe_metadata(data)
    runtime_functions = read_pe_runtime_functions(data, metadata)
    normalized_targets = [metadata.normalize_va_or_rva(parse_int_literal(str(target))) for target in targets]
    target_by_va = {va: rva for va, rva in normalized_targets}
    target_hexes = {_hex(va) for va in target_by_va}
    branches_by_target: dict[int, list[dict[str, object]]] = {va: [] for va, _ in normalized_targets}
    executable_sections = [section for section in metadata.sections if section.is_executable and section.raw_size > 0]
    decoded_instruction_count = 0
    branch_instruction_count = 0

    for section in executable_sections:
        raw_start = section.raw_pointer
        raw_end = min(len(data), raw_start + section.scan_size)
        cursor = raw_start
        while cursor < raw_end:
            instruction = _decode_instruction_at(data, metadata, runtime_functions, section, raw_start, cursor, raw_end)
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
