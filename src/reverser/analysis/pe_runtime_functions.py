from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

from reverser.analysis.pe_direct_calls import PEMetadata, parse_int_literal, read_pe_metadata


def _hex(value: int) -> str:
    return f"0x{value:x}"


@dataclass(frozen=True)
class RuntimeFunction:
    begin_rva: int
    end_rva: int
    unwind_info_rva: int
    raw_offset: int


def read_pe_runtime_functions(data: bytes, metadata: PEMetadata) -> list[RuntimeFunction]:
    functions: list[RuntimeFunction] = []
    pdata_sections = [section for section in metadata.sections if section.name.lower() == ".pdata" and section.raw_size > 0]
    for section in pdata_sections:
        raw_start = section.raw_pointer
        raw_end = min(len(data), section.raw_pointer + section.raw_size)
        cursor = raw_start
        while cursor + 12 <= raw_end:
            begin_rva, end_rva, unwind_info_rva = struct.unpack_from("<III", data, cursor)
            if begin_rva == 0 and end_rva == 0 and unwind_info_rva == 0:
                cursor += 12
                continue
            if begin_rva < end_rva and metadata.section_for_rva(begin_rva) is not None:
                functions.append(
                    RuntimeFunction(
                        begin_rva=begin_rva,
                        end_rva=end_rva,
                        unwind_info_rva=unwind_info_rva,
                        raw_offset=cursor,
                    )
                )
            cursor += 12
    return sorted(functions, key=lambda function: function.begin_rva)


def function_for_rva(functions: list[RuntimeFunction], rva: int) -> RuntimeFunction | None:
    for function in functions:
        if function.begin_rva <= rva < function.end_rva:
            return function
        if function.begin_rva > rva:
            break
    return None


def runtime_function_to_dict(function: RuntimeFunction, metadata: PEMetadata) -> dict[str, object]:
    return {
        "start_va": _hex(metadata.image_base + function.begin_rva),
        "start_rva": _hex(function.begin_rva),
        "end_va": _hex(metadata.image_base + function.end_rva),
        "end_rva": _hex(function.end_rva),
        "unwind_info_va": _hex(metadata.image_base + function.unwind_info_rva),
        "unwind_info_rva": _hex(function.unwind_info_rva),
        "pdata_raw_offset": _hex(function.raw_offset),
    }


def _runtime_function_index(functions: list[RuntimeFunction], rva: int) -> int | None:
    for index, function in enumerate(functions):
        if function.begin_rva <= rva < function.end_rva:
            return index
        if function.begin_rva > rva:
            break
    return None


def _insertion_index(functions: list[RuntimeFunction], rva: int) -> int:
    for index, function in enumerate(functions):
        if function.begin_rva > rva:
            return index
    return len(functions)


def _neighbor_payloads(
    functions: list[RuntimeFunction],
    metadata: PEMetadata,
    *,
    center_index: int | None,
    insertion_index: int,
    neighbor_count: int,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    if center_index is None:
        previous_end = insertion_index
        next_start = insertion_index
    else:
        previous_end = center_index
        next_start = center_index + 1
    previous_start = max(0, previous_end - neighbor_count)
    next_end = min(len(functions), next_start + neighbor_count)
    previous = [runtime_function_to_dict(function, metadata) for function in functions[previous_start:previous_end]]
    next_functions = [runtime_function_to_dict(function, metadata) for function in functions[next_start:next_end]]
    return previous, next_functions


def find_pe_runtime_functions(
    path: str | Path,
    addresses: list[str | int],
    *,
    neighbors: int = 1,
) -> dict[str, object]:
    if neighbors < 0:
        raise ValueError("Neighbor count must not be negative.")

    target_path = Path(path)
    data = target_path.read_bytes()
    metadata = read_pe_metadata(data)
    functions = read_pe_runtime_functions(data, metadata)
    pdata_section_count = len([section for section in metadata.sections if section.name.lower() == ".pdata"])
    queries: list[dict[str, object]] = []

    for address in addresses:
        address_va, address_rva = metadata.normalize_va_or_rva(parse_int_literal(str(address)))
        section = metadata.section_for_rva(address_rva)
        center_index = _runtime_function_index(functions, address_rva)
        insertion_index = _insertion_index(functions, address_rva)
        containing = functions[center_index] if center_index is not None else None
        previous, next_functions = _neighbor_payloads(
            functions,
            metadata,
            center_index=center_index,
            insertion_index=insertion_index,
            neighbor_count=neighbors,
        )
        query: dict[str, object] = {
            "request": str(address),
            "address_va": _hex(address_va),
            "address_rva": _hex(address_rva),
            "section": section.name if section is not None else None,
            "containing_function": runtime_function_to_dict(containing, metadata) if containing is not None else None,
            "containing_function_index": center_index,
            "is_function_start": containing is not None and containing.begin_rva == address_rva,
            "previous_functions": previous,
            "next_functions": next_functions,
        }
        queries.append(query)

    return {
        "type": "pe-runtime-functions",
        "target": str(target_path),
        "image_base": _hex(metadata.image_base),
        "scan": {
            "runtime_function_count": len(functions),
            "pdata_section_count": pdata_section_count,
            "query_count": len(queries),
            "neighbors": neighbors,
        },
        "queries": queries,
    }
