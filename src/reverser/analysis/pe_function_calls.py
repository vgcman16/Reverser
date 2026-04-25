from __future__ import annotations

import struct
from pathlib import Path

from reverser.analysis.pe_direct_calls import PEMetadata, PESection, parse_int_literal, read_pe_metadata
from reverser.analysis.pe_imports import import_lookup_by_iat_va
from reverser.analysis.pe_runtime_functions import (
    RuntimeFunction,
    function_for_rva,
    read_pe_runtime_functions,
    runtime_function_to_dict,
)


def _hex(value: int) -> str:
    return f"0x{value:x}"


_REG64 = (
    "RAX",
    "RCX",
    "RDX",
    "RBX",
    "RSP",
    "RBP",
    "RSI",
    "RDI",
    "R8",
    "R9",
    "R10",
    "R11",
    "R12",
    "R13",
    "R14",
    "R15",
)


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


def _read_qword(data: bytes, metadata: PEMetadata, va: int) -> int | None:
    section = metadata.section_for_va(va)
    if section is None:
        return None
    try:
        raw_offset = metadata.rva_to_offset(va - metadata.image_base)
    except ValueError:
        return None
    if raw_offset + 8 > len(data):
        return None
    return struct.unpack_from("<Q", data, raw_offset)[0]


def _section_name_for_va(metadata: PEMetadata, va: int) -> str | None:
    section = metadata.section_for_va(va)
    return section.name if section is not None else None


def _runtime_payload_for_va(
    metadata: PEMetadata,
    runtime_functions: list[RuntimeFunction],
    va: int,
) -> dict[str, object] | None:
    if va < metadata.image_base:
        return None
    function = function_for_rva(runtime_functions, va - metadata.image_base)
    if function is None:
        return None
    return runtime_function_to_dict(function, metadata)


def _target_payload(
    metadata: PEMetadata,
    runtime_functions: list[RuntimeFunction],
    target_va: int,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "target_va": _hex(target_va),
        "target_rva": _hex(target_va - metadata.image_base) if target_va >= metadata.image_base else None,
        "target_section": _section_name_for_va(metadata, target_va),
    }
    function = _runtime_payload_for_va(metadata, runtime_functions, target_va)
    if function is not None:
        payload["target_function"] = function
    return payload


def _memory_pointer_payload(
    data: bytes,
    metadata: PEMetadata,
    runtime_functions: list[RuntimeFunction],
    memory_va: int,
    import_lookup: dict[int, dict[str, object]] | None = None,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "memory_va": _hex(memory_va),
        "memory_rva": _hex(memory_va - metadata.image_base) if memory_va >= metadata.image_base else None,
        "memory_section": _section_name_for_va(metadata, memory_va),
    }
    imported = import_lookup.get(memory_va) if import_lookup is not None else None
    if imported is not None:
        payload["import"] = imported
    resolved = _read_qword(data, metadata, memory_va)
    if resolved is None:
        return payload

    payload["resolved_pointer_va"] = _hex(resolved)
    payload["resolved_pointer_rva"] = _hex(resolved - metadata.image_base) if resolved >= metadata.image_base else None
    payload["resolved_pointer_section"] = _section_name_for_va(metadata, resolved)
    function = _runtime_payload_for_va(metadata, runtime_functions, resolved)
    if function is not None:
        payload["resolved_pointer_function"] = function
    return payload


def _base_register_name(register_code: int) -> str:
    return _REG64[register_code]


def _signed_hex(value: int) -> str:
    if value < 0:
        return f"-0x{-value:x}"
    return f"0x{value:x}"


def _format_base_displacement(base_register: str | None, displacement: int) -> str:
    if base_register is None:
        return _signed_hex(displacement)
    if displacement == 0:
        return base_register
    sign = "+" if displacement > 0 else "-"
    return f"{base_register}{sign}0x{abs(displacement):x}"


def _decode_ff_call(
    data: bytes,
    metadata: PEMetadata,
    runtime_functions: list[RuntimeFunction],
    section: PESection,
    raw_start: int,
    cursor: int,
    import_lookup: dict[int, dict[str, object]] | None = None,
) -> dict[str, object] | None:
    prefix_len = 0
    rex_prefix = None
    if 0x40 <= data[cursor] <= 0x4F:
        prefix_len = 1
        rex_prefix = data[cursor]

    opcode_offset = cursor + prefix_len
    if opcode_offset + 2 > len(data) or data[opcode_offset] != 0xFF:
        return None

    modrm = data[opcode_offset + 1]
    if rex_prefix is not None and rex_prefix & 0x4:
        return None
    if ((modrm >> 3) & 0x7) != 0x2:
        return None

    mod = (modrm >> 6) & 0x3
    rm = modrm & 0x7
    rex_b = 0x8 if rex_prefix is not None and rex_prefix & 0x1 else 0
    call_rva = section.virtual_address + (cursor - raw_start)
    call_va = metadata.image_base + call_rva

    base: dict[str, object] = {
        "callsite_va": _hex(call_va),
        "callsite_rva": _hex(call_rva),
        "section": section.name,
        "raw_offset": _hex(cursor),
        "opcode": "0xff",
        "modrm": _hex(modrm),
    }
    if rex_prefix is not None:
        base["rex_prefix"] = _hex(rex_prefix)

    if mod == 0x3:
        register = _base_register_name(rm + rex_b)
        instruction_length = prefix_len + 2
        base.update(
            {
                "kind": "indirect-register",
                "instruction": f"CALL {register}",
                "instruction_length": instruction_length,
                "raw_bytes": data[cursor : cursor + instruction_length].hex(),
                "register": register,
            }
        )
        return base

    displacement_offset = opcode_offset + 2
    base_register: str | None = None
    displacement = 0
    has_sib = rm == 0x4
    if has_sib:
        if displacement_offset >= len(data):
            return None
        sib = data[displacement_offset]
        displacement_offset += 1
        base["sib"] = _hex(sib)
        sib_base = sib & 0x7
        if not (mod == 0 and sib_base == 0x5):
            base_register = _base_register_name(sib_base + rex_b)
    elif not (mod == 0 and rm == 0x5):
        base_register = _base_register_name(rm + rex_b)

    if mod == 0 and not has_sib and rm == 0x5:
        if displacement_offset + 4 > len(data):
            return None
        displacement = struct.unpack_from("<i", data, displacement_offset)[0]
        instruction_length = prefix_len + 6
        memory_va = call_va + instruction_length + displacement
        base.update(
            {
                "kind": "indirect-rip-memory",
                "instruction": f"CALL qword ptr [{_hex(memory_va)}]",
                "instruction_length": instruction_length,
                "raw_bytes": data[cursor : cursor + instruction_length].hex(),
                "displacement": displacement,
            }
        )
        base.update(_memory_pointer_payload(data, metadata, runtime_functions, memory_va, import_lookup))
        return base

    if mod == 0 and has_sib and base_register is None:
        if displacement_offset + 4 > len(data):
            return None
        displacement = struct.unpack_from("<i", data, displacement_offset)[0]
        instruction_length = prefix_len + 3 + 4
    elif mod == 0:
        instruction_length = prefix_len + 2 + (1 if has_sib else 0)
    elif mod == 1:
        if displacement_offset + 1 > len(data):
            return None
        displacement = struct.unpack_from("<b", data, displacement_offset)[0]
        instruction_length = prefix_len + 3 + (1 if has_sib else 0)
    elif mod == 2:
        if displacement_offset + 4 > len(data):
            return None
        displacement = struct.unpack_from("<i", data, displacement_offset)[0]
        instruction_length = prefix_len + 6 + (1 if has_sib else 0)
    else:
        return None

    operand = _format_base_displacement(base_register, displacement)
    base.update(
        {
            "kind": "indirect-memory",
            "instruction": f"CALL qword ptr [{operand}]",
            "instruction_length": instruction_length,
            "raw_bytes": data[cursor : cursor + instruction_length].hex(),
            "base_register": base_register,
            "displacement": displacement,
        }
    )
    return base


def _call_at(
    data: bytes,
    metadata: PEMetadata,
    runtime_functions: list[RuntimeFunction],
    section: PESection,
    raw_start: int,
    cursor: int,
    import_lookup: dict[int, dict[str, object]] | None = None,
) -> dict[str, object] | None:
    call_rva = section.virtual_address + (cursor - raw_start)
    call_va = metadata.image_base + call_rva

    if cursor + 5 <= len(data) and data[cursor] == 0xE8:
        rel32 = struct.unpack_from("<i", data, cursor + 1)[0]
        target_va = call_va + 5 + rel32
        target_section = metadata.section_for_va(target_va)
        if target_section is None or not target_section.is_executable:
            return None
        payload: dict[str, object] = {
            "kind": "direct-rel32",
            "callsite_va": _hex(call_va),
            "callsite_rva": _hex(call_rva),
            "section": section.name,
            "raw_offset": _hex(cursor),
            "instruction": f"CALL {_hex(target_va)}",
            "instruction_length": 5,
            "raw_bytes": data[cursor : cursor + 5].hex(),
            "rel32": rel32,
        }
        payload.update(_target_payload(metadata, runtime_functions, target_va))
        return payload

    if cursor + 2 <= len(data) and (data[cursor] == 0xFF or (0x40 <= data[cursor] <= 0x4F and cursor + 1 < len(data) and data[cursor + 1] == 0xFF)):
        return _decode_ff_call(data, metadata, runtime_functions, section, raw_start, cursor, import_lookup)

    return None


def _scan_function_calls(
    data: bytes,
    metadata: PEMetadata,
    runtime_functions: list[RuntimeFunction],
    import_lookup: dict[int, dict[str, object]],
    *,
    start_va: int,
    end_va: int,
    max_calls: int,
) -> tuple[list[dict[str, object]], int, int]:
    section = metadata.section_for_va(start_va)
    end_section = metadata.section_for_va(end_va - 1)
    if section is None or end_section is None or section.name != end_section.name:
        return [], 0, 0

    start_offset = metadata.rva_to_offset(start_va - metadata.image_base)
    end_offset = metadata.rva_to_offset(end_va - metadata.image_base - 1) + 1
    raw_start = section.raw_pointer
    cursor = start_offset
    calls: list[dict[str, object]] = []
    call_hit_count = 0
    scanned_byte_count = max(0, end_offset - start_offset)
    from reverser.analysis.pe_instructions import _decode_instruction_at

    while cursor < end_offset:
        call = _call_at(data, metadata, runtime_functions, section, raw_start, cursor, import_lookup)
        if call is not None:
            call_hit_count += 1
            if len(calls) < max_calls:
                calls.append(call)
            cursor += max(1, int(call["instruction_length"]))
            continue
        decoded = _decode_instruction_at(
            data,
            metadata,
            runtime_functions,
            section,
            raw_start,
            cursor,
            end_offset,
        )
        if decoded.get("kind") != "unknown":
            cursor += max(1, int(decoded.get("length", 1)))
            continue
        cursor += 1

    return calls, call_hit_count, scanned_byte_count


def find_pe_function_calls(
    path: str | Path,
    functions: list[str],
    *,
    max_calls_per_function: int = 128,
) -> dict[str, object]:
    if max_calls_per_function <= 0:
        raise ValueError("Max calls per function must be greater than zero.")

    target_path = Path(path)
    data = target_path.read_bytes()
    metadata = read_pe_metadata(data)
    runtime_functions = read_pe_runtime_functions(data, metadata)
    import_lookup, import_warnings = import_lookup_by_iat_va(data, metadata)
    results: list[dict[str, object]] = []
    warnings: list[str] = list(import_warnings)
    scanned_byte_count = 0

    for function_spec in functions:
        start_va, end_va = _parse_function_spec(function_spec, metadata, runtime_functions)
        calls, hit_count, scanned = _scan_function_calls(
            data,
            metadata,
            runtime_functions,
            import_lookup,
            start_va=start_va,
            end_va=end_va,
            max_calls=max_calls_per_function,
        )
        scanned_byte_count += scanned
        if scanned == 0:
            warnings.append(f"Function range {function_spec!r} does not map to one PE section.")
        results.append(
            {
                "request": str(function_spec),
                "start_va": _hex(start_va),
                "start_rva": _hex(start_va - metadata.image_base),
                "end_va": _hex(end_va),
                "end_rva": _hex(end_va - metadata.image_base),
                "call_hit_count": hit_count,
                "call_count": len(calls),
                "truncated_call_count": max(0, hit_count - len(calls)),
                "calls": calls,
            }
        )

    return {
        "type": "pe-function-calls",
        "target": str(target_path),
        "image_base": _hex(metadata.image_base),
        "scan": {
            "function_count": len(functions),
            "max_calls_per_function": max_calls_per_function,
            "runtime_function_count": len(runtime_functions),
            "import_lookup_count": len(import_lookup),
            "scanned_byte_count": scanned_byte_count,
        },
        "functions": results,
        "warnings": warnings,
    }
