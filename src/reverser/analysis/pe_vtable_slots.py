from __future__ import annotations

import struct
from pathlib import Path

from reverser.analysis.pe_direct_calls import parse_int_literal, read_pe_metadata
from reverser.analysis.pe_qwords import _annotate_qword
from reverser.analysis.pe_runtime_functions import (
    function_for_rva,
    read_pe_runtime_functions,
    runtime_function_to_dict,
)


def _hex(value: int) -> str:
    return f"0x{value:x}"


def _parse_vtable_spec(value: str, *, default_count: int) -> tuple[int, int]:
    raw_value = str(value)
    if ":" in raw_value:
        address_part, count_part = raw_value.split(":", 1)
        count = parse_int_literal(count_part)
    else:
        address_part = raw_value
        count = default_count

    if count <= 0:
        raise ValueError("Vtable slot count must be greater than zero.")
    return parse_int_literal(address_part), count


def read_pe_vtable_slots(path: str | Path, requests: list[str], *, default_count: int = 16) -> dict[str, object]:
    target_path = Path(path)
    data = target_path.read_bytes()
    metadata = read_pe_metadata(data)
    runtime_functions = read_pe_runtime_functions(data, metadata)
    warnings: list[str] = []
    tables: list[dict[str, object]] = []

    for request in requests:
        requested_value, requested_count = _parse_vtable_spec(request, default_count=default_count)
        va, rva = metadata.normalize_va_or_rva(requested_value)
        section = metadata.section_for_rva(rva)
        table: dict[str, object] = {
            "request": str(request),
            "address": _hex(va),
            "rva": _hex(rva),
            "section": section.name if section is not None else None,
            "count_requested": requested_count,
            "count_returned": 0,
            "slots": [],
        }

        if section is None:
            message = f"{request}: address {_hex(va)} is not mapped by a PE section"
            table["error"] = message
            warnings.append(message)
            tables.append(table)
            continue

        try:
            raw_offset = metadata.rva_to_offset(rva)
        except ValueError as exc:
            message = f"{request}: {exc}"
            table["error"] = message
            warnings.append(message)
            tables.append(table)
            continue

        section_raw_end = section.raw_pointer + section.raw_size
        raw_end = min(len(data), section_raw_end)
        available_count = max(0, (raw_end - raw_offset) // 8)
        returned_count = min(requested_count, available_count)
        if returned_count < requested_count:
            warnings.append(
                f"{request}: requested {requested_count} slots but only {returned_count} fit in mapped file data"
            )

        slots: list[dict[str, object]] = []
        for index in range(returned_count):
            entry_offset = raw_offset + index * 8
            entry_rva = rva + index * 8
            entry_va = metadata.image_base + entry_rva
            raw = data[entry_offset : entry_offset + 8]
            value = struct.unpack_from("<Q", raw)[0]
            slot: dict[str, object] = {
                "slot": index,
                "slot_offset": _hex(index * 8),
                "address": _hex(entry_va),
                "rva": _hex(entry_rva),
                "raw_offset": _hex(entry_offset),
                "raw_bytes": raw.hex(),
            }
            slot.update(_annotate_qword(value, raw, metadata, data))

            target_section = metadata.section_for_va(value)
            target_rva = value - metadata.image_base if target_section is not None else None
            if target_section is not None and target_section.is_executable and target_rva is not None:
                containing_function = function_for_rva(runtime_functions, target_rva)
                slot["target_function"] = (
                    runtime_function_to_dict(containing_function, metadata)
                    if containing_function is not None
                    else None
                )
                slot["target_is_function_start"] = (
                    containing_function is not None and containing_function.begin_rva == target_rva
                )
            slots.append(slot)

        table["raw_offset"] = _hex(raw_offset)
        table["count_returned"] = returned_count
        table["slots"] = slots
        tables.append(table)

    return {
        "type": "pe-vtable-slots",
        "target": str(target_path),
        "image_base": _hex(metadata.image_base),
        "scan": {
            "table_count": len(tables),
            "default_count": default_count,
            "runtime_function_count": len(runtime_functions),
        },
        "tables": tables,
        "warnings": warnings,
    }
