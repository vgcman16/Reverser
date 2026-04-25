from __future__ import annotations

import struct
from pathlib import Path

from reverser.analysis.pe_direct_calls import PEMetadata, parse_int_literal, read_pe_metadata
from reverser.analysis.pe_instructions import find_pe_instructions
from reverser.analysis.pe_qwords import target_string_preview
from reverser.analysis.pe_runtime_functions import (
    function_for_rva,
    read_pe_runtime_functions,
    runtime_function_to_dict,
)


def _hex(value: int) -> str:
    return f"0x{value:x}"


def _canonical_register(register: str) -> str:
    return {
        "ECX": "RCX",
        "CX": "RCX",
        "CL": "RCX",
        "EDX": "RDX",
        "DX": "RDX",
        "DL": "RDX",
        "R8D": "R8",
        "R8W": "R8",
        "R8B": "R8",
        "R9D": "R9",
        "R9W": "R9",
        "R9B": "R9",
    }.get(register, register)


def _normalize_va(metadata: PEMetadata, value: str | int) -> int:
    va, _ = metadata.normalize_va_or_rva(parse_int_literal(str(value)))
    return va


def _scan_direct_transfers(
    data: bytes,
    metadata: PEMetadata,
    resolver_va: int,
) -> tuple[list[dict[str, object]], dict[str, object]]:
    transfers: list[dict[str, object]] = []
    executable_sections = [section for section in metadata.sections if section.is_executable and section.raw_size > 0]
    call_opcode_count = 0
    jmp_opcode_count = 0

    for section in executable_sections:
        raw_start = section.raw_pointer
        raw_end = min(len(data), raw_start + section.scan_size)
        cursor = raw_start
        while cursor + 5 <= raw_end:
            opcode = data[cursor]
            if opcode not in (0xE8, 0xE9):
                cursor += 1
                continue

            if opcode == 0xE8:
                call_opcode_count += 1
                kind = "call"
                mnemonic = "CALL"
            else:
                jmp_opcode_count += 1
                kind = "tail-jump"
                mnemonic = "JMP"

            rel32 = struct.unpack_from("<i", data, cursor + 1)[0]
            transfer_rva = section.virtual_address + (cursor - raw_start)
            transfer_va = metadata.image_base + transfer_rva
            target_va = transfer_va + 5 + rel32
            if target_va == resolver_va:
                transfers.append(
                    {
                        "kind": kind,
                        "callsite_va": _hex(transfer_va),
                        "callsite_rva": _hex(transfer_rva),
                        "target_va": _hex(target_va),
                        "target_rva": _hex(target_va - metadata.image_base),
                        "rel32": rel32,
                        "section": section.name,
                        "raw_offset": _hex(cursor),
                        "instruction": f"{mnemonic} {_hex(target_va)}",
                    }
                )
            cursor += 1

    return transfers, {
        "executable_section_count": len(executable_sections),
        "direct_call_opcode_count": call_opcode_count,
        "direct_jmp_opcode_count": jmp_opcode_count,
    }


def _instruction_va(instruction: dict[str, object]) -> int:
    return int(str(instruction["address_va"]), 0)


def _record_register_setup(instructions: list[dict[str, object]]) -> dict[str, dict[str, object]]:
    registers: dict[str, dict[str, object]] = {}
    for instruction in instructions:
        operands = str(instruction.get("operands", ""))
        parts = [part.strip() for part in operands.split(",", 1)]
        if not parts or not parts[0]:
            continue

        destination = _canonical_register(parts[0])
        mnemonic = str(instruction.get("mnemonic", ""))
        if mnemonic == "LEA" and "memory_target_va" in instruction:
            registers[destination] = {
                "kind": "address",
                "value": str(instruction["memory_target_va"]),
                "source_va": str(instruction["address_va"]),
                "instruction": str(instruction["instruction"]),
            }
            continue

        if mnemonic == "MOV" and "immediate" in instruction:
            immediate = int(instruction["immediate"])
            registers[destination] = {
                "kind": "immediate",
                "value": immediate,
                "value_hex": _hex(immediate & 0xFFFFFFFFFFFFFFFF),
                "source_va": str(instruction["address_va"]),
                "instruction": str(instruction["instruction"]),
            }
            continue

        if mnemonic == "XOR" and len(parts) == 2 and _canonical_register(parts[1]) == destination:
            registers[destination] = {
                "kind": "immediate",
                "value": 0,
                "value_hex": "0x0",
                "source_va": str(instruction["address_va"]),
                "instruction": str(instruction["instruction"]),
            }
    return registers


def _read_u32_array(
    data: bytes,
    metadata: PEMetadata,
    start_va: int,
    end_va: int,
    *,
    max_entries: int,
) -> tuple[list[int], bool, str | None]:
    if end_va < start_va:
        return [], False, f"End address {_hex(end_va)} is before start address {_hex(start_va)}."
    byte_count = end_va - start_va
    if byte_count % 4:
        return [], False, f"Range {_hex(start_va)}..{_hex(end_va)} is not dword-aligned."

    entry_count = byte_count // 4
    truncated = entry_count > max_entries
    entry_count = min(entry_count, max_entries)
    try:
        start_offset = metadata.rva_to_offset(start_va - metadata.image_base)
    except ValueError as exc:
        return [], False, str(exc)

    values: list[int] = []
    for index in range(entry_count):
        offset = start_offset + index * 4
        if offset + 4 > len(data):
            return values, truncated, f"Range {_hex(start_va)}..{_hex(end_va)} exceeds file data."
        values.append(struct.unpack_from("<I", data, offset)[0])
    return values, truncated, None


def _module_name_for_index(
    data: bytes,
    metadata: PEMetadata,
    module_table_va: int | None,
    index: int,
) -> dict[str, object] | None:
    if module_table_va is None:
        return None
    entry_va = module_table_va + index * 8
    try:
        entry_offset = metadata.rva_to_offset(entry_va - metadata.image_base)
    except ValueError:
        return None
    if entry_offset + 8 > len(data):
        return None

    pointer_va = struct.unpack_from("<Q", data, entry_offset)[0]
    payload: dict[str, object] = {
        "module_table_entry_va": _hex(entry_va),
        "module_name_va": _hex(pointer_va),
    }
    preview = target_string_preview(data, metadata, pointer_va)
    if preview is not None:
        payload.update(preview)
        payload["module_name"] = preview["target_string"]
    return payload


def find_pe_resolver_invocations(
    path: str | Path,
    resolver: str | int,
    *,
    module_table: str | int | None = None,
    max_backtrack_instructions: int = 12,
    max_module_indices: int = 64,
) -> dict[str, object]:
    target_path = Path(path)
    data = target_path.read_bytes()
    metadata = read_pe_metadata(data)
    runtime_functions = read_pe_runtime_functions(data, metadata)
    resolver_va = _normalize_va(metadata, resolver)
    module_table_va = _normalize_va(metadata, module_table) if module_table is not None else None

    transfers, scan = _scan_direct_transfers(data, metadata, resolver_va)
    invocations: list[dict[str, object]] = []
    warnings: list[str] = []

    for transfer in sorted(transfers, key=lambda item: int(str(item["callsite_va"]), 0)):
        callsite_va = int(str(transfer["callsite_va"]), 0)
        callsite_rva = callsite_va - metadata.image_base
        containing = function_for_rva(runtime_functions, callsite_rva)
        if containing is None:
            warnings.append(f"{transfer['callsite_va']}: no containing runtime function; skipping.")
            continue

        function_payload = runtime_function_to_dict(containing, metadata)
        window = f"{function_payload['start_va']}..{_hex(callsite_va + 5)}"
        instructions_payload = find_pe_instructions(target_path, [window])
        instructions = instructions_payload["windows"][0]["instructions"]
        prior = [instruction for instruction in instructions if _instruction_va(instruction) < callsite_va]
        setup_instructions = prior[-max_backtrack_instructions:]
        registers = _record_register_setup(setup_instructions)

        invocation: dict[str, object] = {
            **transfer,
            "function": function_payload,
            "register_setup": registers,
        }

        selector = registers.get("RCX")
        if selector is not None and selector.get("kind") == "immediate":
            selector_value = int(selector["value"])
            invocation["selector"] = selector_value
            invocation["selector_hex"] = _hex(selector_value)

        api_name = registers.get("RDX")
        if api_name is not None and api_name.get("kind") == "address":
            api_name_va = int(str(api_name["value"]), 0)
            invocation["api_name_va"] = _hex(api_name_va)
            preview = target_string_preview(data, metadata, api_name_va)
            if preview is not None:
                invocation["api_name"] = preview["target_string"]
                invocation["api_name_kind"] = preview["target_string_kind"]

        start = registers.get("R8")
        end = registers.get("R9")
        if (
            start is not None
            and end is not None
            and start.get("kind") == "address"
            and end.get("kind") == "address"
        ):
            start_va = int(str(start["value"]), 0)
            end_va = int(str(end["value"]), 0)
            indices, truncated, error = _read_u32_array(
                data,
                metadata,
                start_va,
                end_va,
                max_entries=max_module_indices,
            )
            invocation["module_index_start_va"] = _hex(start_va)
            invocation["module_index_end_va"] = _hex(end_va)
            invocation["module_index_count"] = len(indices)
            if truncated:
                invocation["module_index_truncated"] = True
            if error is not None:
                invocation["module_index_error"] = error
            invocation["module_indices"] = [
                {
                    "ordinal": ordinal,
                    "index": index,
                    **(_module_name_for_index(data, metadata, module_table_va, index) or {}),
                }
                for ordinal, index in enumerate(indices)
            ]

        invocations.append(invocation)

    return {
        "type": "pe-resolver-invocations",
        "target": str(target_path),
        "image_base": _hex(metadata.image_base),
        "resolver_va": _hex(resolver_va),
        "resolver_rva": _hex(resolver_va - metadata.image_base),
        "module_table_va": _hex(module_table_va) if module_table_va is not None else None,
        "scan": {
            **scan,
            "runtime_function_count": len(runtime_functions),
            "transfer_hit_count": len(transfers),
            "invocation_count": len(invocations),
            "max_backtrack_instructions": max_backtrack_instructions,
            "max_module_indices": max_module_indices,
        },
        "invocations": invocations,
        "warnings": warnings,
    }
