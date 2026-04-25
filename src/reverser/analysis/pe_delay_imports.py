from __future__ import annotations

import struct
from pathlib import Path

from reverser.analysis.pe_direct_calls import PEMetadata, parse_int_literal, read_pe_metadata

_DELAY_ATTR_RVA_BASED = 0x1
_ORDINAL_FLAG64 = 0x8000000000000000


def _hex(value: int) -> str:
    return f"0x{value:x}"


def _read_c_string(data: bytes, metadata: PEMetadata, rva: int, *, max_bytes: int = 256) -> str | None:
    section = metadata.section_for_rva(rva)
    if section is None:
        return None
    try:
        raw_offset = metadata.rva_to_offset(rva)
    except ValueError:
        return None

    section_raw_end = min(len(data), section.raw_pointer + section.raw_size)
    raw = data[raw_offset : min(section_raw_end, raw_offset + max_bytes)]
    raw = raw.split(b"\x00", 1)[0]
    if not raw:
        return None
    return raw.decode("ascii", errors="replace")


def _normalize_delay_address(value: int, attributes: int, metadata: PEMetadata) -> dict[str, object] | None:
    if value == 0:
        return None
    if attributes & _DELAY_ATTR_RVA_BASED:
        va = metadata.image_base + value
        rva = value
        section = metadata.section_for_rva(rva)
    else:
        va = value
        rva = value - metadata.image_base
        section = metadata.section_for_va(va)
    return {
        "value": _hex(value),
        "va": _hex(va),
        "rva": _hex(rva),
        "section": section.name if section is not None else None,
    }


def _delay_value_to_rva(value: int, attributes: int, metadata: PEMetadata) -> int:
    if attributes & _DELAY_ATTR_RVA_BASED:
        return value
    return value - metadata.image_base


def _delay_value_to_va(value: int, attributes: int, metadata: PEMetadata) -> int:
    if attributes & _DELAY_ATTR_RVA_BASED:
        return metadata.image_base + value
    return value


def _read_qword_va(data: bytes, metadata: PEMetadata, va: int) -> int | None:
    section = metadata.section_for_va(va)
    if section is None:
        return None
    try:
        raw_offset = metadata.rva_to_offset(va - metadata.image_base)
    except ValueError:
        return None
    if raw_offset + 8 > min(len(data), section.raw_pointer + section.raw_size):
        return None
    return struct.unpack_from("<Q", data, raw_offset)[0]


def _read_import_by_name(
    data: bytes,
    metadata: PEMetadata,
    value: int,
    attributes: int,
) -> dict[str, object] | None:
    if value == 0:
        return None
    if value & _ORDINAL_FLAG64:
        return {
            "kind": "ordinal",
            "ordinal": value & 0xFFFF,
        }

    if attributes & _DELAY_ATTR_RVA_BASED:
        name_rva = value
    else:
        name_rva = value - metadata.image_base
    section = metadata.section_for_rva(name_rva)
    if section is None:
        return {
            "kind": "name",
            "import_name_value": _hex(value),
            "import_name_rva": _hex(name_rva),
            "error": "import name is not mapped by a PE section",
        }
    try:
        raw_offset = metadata.rva_to_offset(name_rva)
    except ValueError as exc:
        return {
            "kind": "name",
            "import_name_value": _hex(value),
            "import_name_rva": _hex(name_rva),
            "error": str(exc),
        }
    if raw_offset + 2 > min(len(data), section.raw_pointer + section.raw_size):
        return {
            "kind": "name",
            "import_name_value": _hex(value),
            "import_name_rva": _hex(name_rva),
            "error": "import name hint does not fit in mapped file data",
        }

    hint = struct.unpack_from("<H", data, raw_offset)[0]
    name = _read_c_string(data, metadata, name_rva + 2)
    return {
        "kind": "name",
        "import_name_value": _hex(value),
        "import_name_va": _hex(metadata.image_base + name_rva),
        "import_name_rva": _hex(name_rva),
        "hint": hint,
        "name": name,
    }


def _iat_slot_payload(
    *,
    data: bytes,
    metadata: PEMetadata,
    iat_va: int,
    int_va: int,
    index: int,
    attributes: int,
) -> dict[str, object] | None:
    iat_entry_va = iat_va + index * 8
    int_entry_va = int_va + index * 8
    iat_value = _read_qword_va(data, metadata, iat_entry_va)
    int_value = _read_qword_va(data, metadata, int_entry_va)
    if iat_value is None and int_value is None:
        return None
    if iat_value == 0 and int_value == 0:
        return None

    target_section = None if iat_value is None else metadata.section_for_va(iat_value)
    payload: dict[str, object] = {
        "index": index,
        "iat_entry_va": _hex(iat_entry_va),
        "iat_entry_rva": _hex(iat_entry_va - metadata.image_base),
        "int_entry_va": _hex(int_entry_va),
        "int_entry_rva": _hex(int_entry_va - metadata.image_base),
        "iat_value": None if iat_value is None else _hex(iat_value),
        "int_value": None if int_value is None else _hex(int_value),
    }
    if iat_value is not None and target_section is not None:
        payload["iat_target_rva"] = _hex(iat_value - metadata.image_base)
        payload["iat_target_section"] = target_section.name
        payload["iat_target_is_executable"] = target_section.is_executable
    if int_value is not None:
        import_payload = _read_import_by_name(data, metadata, int_value, attributes)
        if import_payload is not None:
            payload["import"] = import_payload
    return payload


def read_pe_delay_imports(
    path: str | Path,
    descriptors: list[str],
    *,
    max_slots: int = 64,
) -> dict[str, object]:
    target_path = Path(path)
    data = target_path.read_bytes()
    metadata = read_pe_metadata(data)
    warnings: list[str] = []
    descriptor_payloads: list[dict[str, object]] = []

    for descriptor in descriptors:
        requested_value = parse_int_literal(descriptor)
        va, rva = metadata.normalize_va_or_rva(requested_value)
        section = metadata.section_for_rva(rva)
        payload: dict[str, object] = {
            "request": str(descriptor),
            "address": _hex(va),
            "rva": _hex(rva),
            "section": section.name if section is not None else None,
        }
        if section is None:
            message = f"{descriptor}: descriptor address {_hex(va)} is not mapped by a PE section"
            payload["error"] = message
            warnings.append(message)
            descriptor_payloads.append(payload)
            continue

        try:
            raw_offset = metadata.rva_to_offset(rva)
        except ValueError as exc:
            message = f"{descriptor}: {exc}"
            payload["error"] = message
            warnings.append(message)
            descriptor_payloads.append(payload)
            continue
        raw_end = min(len(data), section.raw_pointer + section.raw_size)
        if raw_offset + 32 > raw_end:
            message = f"{descriptor}: delay import descriptor does not fit in mapped file data"
            payload["error"] = message
            warnings.append(message)
            descriptor_payloads.append(payload)
            continue

        (
            attributes,
            dll_name_value,
            module_handle_value,
            iat_value,
            int_value,
            bound_iat_value,
            unload_iat_value,
            timestamp,
        ) = struct.unpack_from("<IIIIIIII", data, raw_offset)
        name_addr = _normalize_delay_address(dll_name_value, attributes, metadata)
        iat_addr = _normalize_delay_address(iat_value, attributes, metadata)
        int_addr = _normalize_delay_address(int_value, attributes, metadata)
        dll_name = None
        if dll_name_value:
            dll_name = _read_c_string(data, metadata, _delay_value_to_rva(dll_name_value, attributes, metadata))

        slots: list[dict[str, object]] = []
        if iat_addr is not None and int_addr is not None:
            iat_va = _delay_value_to_va(iat_value, attributes, metadata)
            int_va = _delay_value_to_va(int_value, attributes, metadata)
            for index in range(max_slots):
                slot = _iat_slot_payload(
                    data=data,
                    metadata=metadata,
                    iat_va=iat_va,
                    int_va=int_va,
                    index=index,
                    attributes=attributes,
                )
                if slot is None:
                    break
                slots.append(slot)

        payload.update(
            {
                "raw_offset": _hex(raw_offset),
                "attributes": _hex(attributes),
                "rva_based": bool(attributes & _DELAY_ATTR_RVA_BASED),
                "dll_name": dll_name,
                "dll_name_address": name_addr,
                "module_handle_cache": _normalize_delay_address(module_handle_value, attributes, metadata),
                "iat": iat_addr,
                "int": int_addr,
                "bound_iat": _normalize_delay_address(bound_iat_value, attributes, metadata),
                "unload_iat": _normalize_delay_address(unload_iat_value, attributes, metadata),
                "timestamp": timestamp,
                "slot_count": len(slots),
                "slots": slots,
            }
        )
        descriptor_payloads.append(payload)

    return {
        "type": "pe-delay-imports",
        "target": str(target_path),
        "image_base": _hex(metadata.image_base),
        "scan": {
            "descriptor_count": len(descriptors),
            "max_slots": max_slots,
        },
        "descriptors": descriptor_payloads,
        "warnings": warnings,
    }
