from __future__ import annotations

import struct
from pathlib import Path

from reverser.analysis.pe_direct_calls import PEMetadata, PESection, parse_int_literal, read_pe_metadata
from reverser.analysis.pe_runtime_functions import (
    RuntimeFunction,
    function_for_rva,
    read_pe_runtime_functions,
)


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


def _parse_function_spec(
    value: str,
    metadata: PEMetadata,
    runtime_functions: list[RuntimeFunction] | None = None,
) -> tuple[int, int]:
    raw_value = str(value)
    separator = ".." if ".." in raw_value else ":"
    if separator not in raw_value:
        if runtime_functions is None:
            raise ValueError(f"Function range must be START:END or START..END, got {value!r}.")
        _, address_rva = metadata.normalize_va_or_rva(parse_int_literal(raw_value))
        function = function_for_rva(runtime_functions, address_rva)
        if function is None:
            raise ValueError(
                f"Function address {value!r} does not resolve to a .pdata runtime function; "
                "pass START:END or START..END instead."
            )
        return metadata.image_base + function.begin_rva, metadata.image_base + function.end_rva
    start_raw, end_raw = raw_value.split(separator, 1)
    start_va, _ = metadata.normalize_va_or_rva(parse_int_literal(start_raw))
    end_va, _ = metadata.normalize_va_or_rva(parse_int_literal(end_raw))
    if end_va <= start_va:
        raise ValueError(f"Function range end must be greater than start: {value!r}.")
    return start_va, end_va


def _read_bytes(data: bytes, metadata: PEMetadata, va: int, count: int) -> bytes | None:
    section = metadata.section_for_va(va)
    if section is None:
        return None
    try:
        raw_offset = metadata.rva_to_offset(va - metadata.image_base)
    except ValueError:
        return None
    if raw_offset + count > len(data):
        return None
    return data[raw_offset : raw_offset + count]


def _read_ascii_cstring(
    data: bytes,
    metadata: PEMetadata,
    va: int,
    *,
    max_bytes: int,
    min_length: int,
) -> dict[str, object] | None:
    raw = _read_bytes(data, metadata, va, max_bytes)
    if raw is None:
        return None
    value = raw.split(b"\x00", 1)[0]
    if len(value) < min_length:
        return None
    if not all(32 <= byte <= 126 or byte in (9,) for byte in value):
        return None
    return {
        "kind": "ascii-cstring",
        "value": value.decode("ascii", errors="replace"),
        "length": len(value),
    }


def _read_utf16le_string(
    data: bytes,
    metadata: PEMetadata,
    va: int,
    *,
    max_bytes: int,
    min_length: int,
) -> dict[str, object] | None:
    raw = _read_bytes(data, metadata, va, max_bytes)
    if raw is None:
        return None
    chars: list[int] = []
    for index in range(0, len(raw) - 1, 2):
        codepoint = struct.unpack_from("<H", raw, index)[0]
        if codepoint == 0:
            break
        if codepoint < 32 or codepoint > 126:
            return None
        chars.append(codepoint)
    if len(chars) < min_length:
        return None
    return {
        "kind": "utf16le-string",
        "value": "".join(chr(codepoint) for codepoint in chars),
        "length": len(chars),
    }


def _decode_rip_relative_reference(data: bytes, metadata: PEMetadata, section: PESection, raw_start: int, cursor: int) -> dict[str, object] | None:
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
    payload: dict[str, object] = {
        "reference_kind": f"rip-relative-{opcode_name}",
        "reference_va": _hex(reference_va),
        "reference_rva": _hex(reference_rva),
        "target_va": _hex(target_va),
        "target_rva": _hex(target_va - metadata.image_base),
        "instruction_length": instruction_length,
        "raw_bytes": data[cursor : cursor + instruction_length].hex(),
    }
    if rex_prefix is not None:
        payload["rex_prefix"] = _hex(rex_prefix)
    return payload


def _decode_movabs_reference(data: bytes, metadata: PEMetadata, section: PESection, raw_start: int, cursor: int) -> dict[str, object] | None:
    if cursor + 10 > len(data) or not (0x48 <= data[cursor] <= 0x4F) or not (0xB8 <= data[cursor + 1] <= 0xBF):
        return None
    value = struct.unpack_from("<Q", data, cursor + 2)[0]
    reference_rva = section.virtual_address + (cursor - raw_start)
    reference_va = metadata.image_base + reference_rva
    return {
        "reference_kind": "movabs-imm64",
        "reference_va": _hex(reference_va),
        "reference_rva": _hex(reference_rva),
        "target_va": _hex(value),
        "target_rva": _hex(value - metadata.image_base),
        "instruction_length": 10,
        "raw_bytes": data[cursor : cursor + 10].hex(),
    }


def _string_literal_for_reference(
    data: bytes,
    metadata: PEMetadata,
    reference: dict[str, object],
    *,
    max_string_bytes: int,
    min_string_length: int,
) -> dict[str, object] | None:
    target_va = parse_int_literal(str(reference["target_va"]))
    target_section = metadata.section_for_va(target_va)
    if target_section is None or target_section.is_executable:
        return None

    literal = _read_ascii_cstring(
        data,
        metadata,
        target_va,
        max_bytes=max_string_bytes,
        min_length=min_string_length,
    )
    if literal is None:
        literal = _read_utf16le_string(
            data,
            metadata,
            target_va,
            max_bytes=max_string_bytes,
            min_length=min_string_length,
        )
    if literal is None:
        return None

    literal.update(reference)
    literal["target_section"] = target_section.name
    return literal


def _scan_function_literals(
    data: bytes,
    metadata: PEMetadata,
    *,
    start_va: int,
    end_va: int,
    max_literals: int,
    max_string_bytes: int,
    min_string_length: int,
) -> tuple[list[dict[str, object]], int, int]:
    section = metadata.section_for_va(start_va)
    end_section = metadata.section_for_va(end_va - 1)
    if section is None or end_section is None or section.name != end_section.name:
        return [], 0, 0

    start_offset = metadata.rva_to_offset(start_va - metadata.image_base)
    end_offset = metadata.rva_to_offset(end_va - metadata.image_base - 1) + 1
    raw_start = section.raw_pointer
    cursor = start_offset
    literals: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    literal_hit_count = 0
    scanned_byte_count = max(0, end_offset - start_offset)

    while cursor < end_offset:
        reference = _decode_rip_relative_reference(data, metadata, section, raw_start, cursor)
        if reference is None:
            reference = _decode_movabs_reference(data, metadata, section, raw_start, cursor)
        if reference is not None:
            literal = _string_literal_for_reference(
                data,
                metadata,
                reference,
                max_string_bytes=max_string_bytes,
                min_string_length=min_string_length,
            )
            if literal is not None:
                literal_hit_count += 1
                key = (str(literal["target_va"]), str(literal["value"]))
                if key not in seen and len(literals) < max_literals:
                    seen.add(key)
                    literals.append(literal)
            cursor += int(reference["instruction_length"])
            continue
        cursor += 1

    return literals, literal_hit_count, scanned_byte_count


def find_pe_function_literals(
    path: str | Path,
    functions: list[str],
    *,
    max_literals_per_function: int = 16,
    max_string_bytes: int = 256,
    min_string_length: int = 4,
) -> dict[str, object]:
    if max_literals_per_function <= 0:
        raise ValueError("Max literals per function must be greater than zero.")
    if max_string_bytes <= 0:
        raise ValueError("Max string bytes must be greater than zero.")
    if min_string_length <= 0:
        raise ValueError("Min string length must be greater than zero.")

    target_path = Path(path)
    data = target_path.read_bytes()
    metadata = read_pe_metadata(data)
    runtime_functions = read_pe_runtime_functions(data, metadata)
    warnings: list[str] = []
    function_payloads: list[dict[str, object]] = []
    scanned_byte_count = 0

    for function_spec in functions:
        try:
            start_va, end_va = _parse_function_spec(str(function_spec), metadata, runtime_functions)
        except ValueError as exc:
            warnings.append(str(exc))
            continue

        literals, literal_hit_count, scanned_count = _scan_function_literals(
            data,
            metadata,
            start_va=start_va,
            end_va=end_va,
            max_literals=max_literals_per_function,
            max_string_bytes=max_string_bytes,
            min_string_length=min_string_length,
        )
        scanned_byte_count += scanned_count
        function_payloads.append(
            {
                "request": str(function_spec),
                "start_va": _hex(start_va),
                "start_rva": _hex(start_va - metadata.image_base),
                "end_va": _hex(end_va),
                "end_rva": _hex(end_va - metadata.image_base),
                "literal_hit_count": literal_hit_count,
                "literal_count": len(literals),
                "truncated_literal_count": max(0, literal_hit_count - len(literals)),
                "literals": literals,
            }
        )

    return {
        "type": "pe-function-literals",
        "target": str(target_path),
        "image_base": _hex(metadata.image_base),
        "scan": {
            "function_count": len(function_payloads),
            "max_literals_per_function": max_literals_per_function,
            "max_string_bytes": max_string_bytes,
            "min_string_length": min_string_length,
            "runtime_function_count": len(runtime_functions),
            "scanned_byte_count": scanned_byte_count,
        },
        "functions": function_payloads,
        "warnings": warnings,
    }
