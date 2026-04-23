from __future__ import annotations

import struct
from pathlib import Path

from reverser.analysis.pe_direct_calls import PEMetadata, parse_int_literal, read_pe_metadata


def _hex(value: int) -> str:
    return f"0x{value:x}"


def _read_cstring(data: bytes, metadata: PEMetadata, va: int, *, max_bytes: int) -> tuple[str, int, int]:
    if va < metadata.image_base:
        raise ValueError(f"VA {_hex(va)} is below image base {_hex(metadata.image_base)}.")
    raw_offset = metadata.rva_to_offset(va - metadata.image_base)
    raw_end = min(len(data), raw_offset + max_bytes)
    terminator = data.find(b"\x00", raw_offset, raw_end)
    if terminator == -1:
        terminator = raw_end
    raw = data[raw_offset:terminator]
    return raw.decode("ascii", errors="replace"), raw_offset, len(raw)


def _annotate_pointer(value: int, metadata: PEMetadata) -> dict[str, object]:
    section = metadata.section_for_va(value)
    payload: dict[str, object] = {"value": _hex(value)}
    if section is not None:
        payload["target_rva"] = _hex(value - metadata.image_base)
        payload["target_section"] = section.name
        payload["target_is_executable"] = section.is_executable
    return payload


def _parse_msvc_type_name(decorated_name: str) -> dict[str, object]:
    prefixes = (
        (".?AV", "class"),
        (".?AU", "struct"),
        (".?AW4", "enum"),
    )
    for prefix, kind in prefixes:
        if decorated_name.startswith(prefix):
            body = decorated_name[len(prefix) :]
            suffix_index = body.find("@@")
            if suffix_index != -1:
                body = body[:suffix_index]
            return {
                "format": "msvc-rtti-type-descriptor",
                "kind": kind,
                "name": body.replace("@", "::"),
            }
    return {
        "format": "unknown",
        "kind": None,
        "name": None,
    }


def read_pe_rtti_type_descriptors(
    path: str | Path,
    addresses: list[str | int],
    *,
    max_name_bytes: int = 256,
) -> dict[str, object]:
    target_path = Path(path)
    data = target_path.read_bytes()
    metadata = read_pe_metadata(data)
    warnings: list[str] = []
    descriptors: list[dict[str, object]] = []

    for address in addresses:
        requested_value = parse_int_literal(str(address))
        va, rva = metadata.normalize_va_or_rva(requested_value)
        section = metadata.section_for_rva(rva)
        descriptor: dict[str, object] = {
            "request": str(address),
            "address": _hex(va),
            "rva": _hex(rva),
            "section": section.name if section is not None else None,
        }

        if section is None:
            message = f"{address}: address {_hex(va)} is not mapped by a PE section"
            descriptor["error"] = message
            warnings.append(message)
            descriptors.append(descriptor)
            continue

        try:
            raw_offset = metadata.rva_to_offset(rva)
        except ValueError as exc:
            message = f"{address}: {exc}"
            descriptor["error"] = message
            warnings.append(message)
            descriptors.append(descriptor)
            continue

        if raw_offset + 16 > len(data):
            message = f"{address}: not enough file data for a 16-byte RTTI TypeDescriptor header"
            descriptor["error"] = message
            warnings.append(message)
            descriptors.append(descriptor)
            continue

        vfptr = struct.unpack_from("<Q", data, raw_offset)[0]
        spare = struct.unpack_from("<Q", data, raw_offset + 8)[0]
        name_va = va + 16
        try:
            decorated_name, name_raw_offset, name_length = _read_cstring(
                data,
                metadata,
                name_va,
                max_bytes=max_name_bytes,
            )
        except ValueError as exc:
            message = f"{address}: {exc}"
            descriptor["error"] = message
            warnings.append(message)
            descriptors.append(descriptor)
            continue

        descriptor.update(
            {
                "raw_offset": _hex(raw_offset),
                "vfptr": _annotate_pointer(vfptr, metadata),
                "spare": _hex(spare),
                "name_address": _hex(name_va),
                "name_rva": _hex(name_va - metadata.image_base),
                "name_raw_offset": _hex(name_raw_offset),
                "decorated_name": decorated_name,
                "name_length": name_length,
                "parsed_name": _parse_msvc_type_name(decorated_name),
                "looks_like_msvc_type_descriptor": decorated_name.startswith(".?A"),
            }
        )
        descriptors.append(descriptor)

    return {
        "type": "pe-rtti-type-descriptors",
        "target": str(target_path),
        "image_base": _hex(metadata.image_base),
        "descriptors": descriptors,
        "warnings": warnings,
    }
