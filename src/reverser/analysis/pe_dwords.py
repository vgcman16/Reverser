from __future__ import annotations

import struct
from pathlib import Path

from reverser.analysis.pe_direct_calls import PEMetadata, parse_int_literal, read_pe_metadata
from reverser.analysis.pe_qwords import _target_preview_for_rva


def _hex(value: int) -> str:
    return f"0x{value:x}"


def _parse_read_spec(value: str, *, default_count: int) -> tuple[int, int]:
    raw_value = str(value)
    if ":" in raw_value:
        address_part, count_part = raw_value.split(":", 1)
        count = parse_int_literal(count_part)
    else:
        address_part = raw_value
        count = default_count

    if count <= 0:
        raise ValueError("Dword read count must be greater than zero.")
    return parse_int_literal(address_part), count


def _annotate_dword(value: int, raw: bytes, metadata: PEMetadata, data: bytes) -> dict[str, object]:
    target_section = metadata.section_for_va(value)
    rva_target_section = None if target_section is not None else metadata.section_for_rva(value)
    if value == 0:
        annotation = "zero"
    elif target_section is not None:
        annotation = "executable-target" if target_section.is_executable else "image-target"
    elif rva_target_section is not None:
        annotation = "executable-rva-target" if rva_target_section.is_executable else "rva-target"
    else:
        annotation = "non-image-value"

    payload: dict[str, object] = {
        "value": _hex(value),
        "signed_value": struct.unpack_from("<i", raw)[0],
        "annotation": annotation,
    }
    if target_section is not None:
        payload["target_rva"] = _hex(value - metadata.image_base)
        payload["target_section"] = target_section.name
        payload["target_is_executable"] = target_section.is_executable
    elif rva_target_section is not None:
        payload["target_va"] = _hex(metadata.image_base + value)
        payload["target_rva"] = _hex(value)
        payload["target_section"] = rva_target_section.name
        payload["target_is_executable"] = rva_target_section.is_executable
        target_preview = _target_preview_for_rva(data, metadata, value)
        if target_preview is not None:
            payload.update(target_preview)
            if target_preview.get("target_string_kind") == "import-name":
                payload["annotation"] = "import-name-rva"
    return payload


def read_pe_dwords(path: str | Path, requests: list[str], *, default_count: int = 16) -> dict[str, object]:
    target_path = Path(path)
    data = target_path.read_bytes()
    metadata = read_pe_metadata(data)
    warnings: list[str] = []
    reads: list[dict[str, object]] = []

    for request in requests:
        requested_value, requested_count = _parse_read_spec(request, default_count=default_count)
        va, rva = metadata.normalize_va_or_rva(requested_value)
        section = metadata.section_for_rva(rva)
        read_payload: dict[str, object] = {
            "request": str(request),
            "address": _hex(va),
            "rva": _hex(rva),
            "section": section.name if section is not None else None,
            "count_requested": requested_count,
            "count_returned": 0,
            "dwords": [],
        }

        if section is None:
            message = f"{request}: address {_hex(va)} is not mapped by a PE section"
            read_payload["error"] = message
            warnings.append(message)
            reads.append(read_payload)
            continue

        try:
            raw_offset = metadata.rva_to_offset(rva)
        except ValueError as exc:
            message = f"{request}: {exc}"
            read_payload["error"] = message
            warnings.append(message)
            reads.append(read_payload)
            continue

        section_raw_end = section.raw_pointer + section.raw_size
        raw_end = min(len(data), section_raw_end)
        available_count = max(0, (raw_end - raw_offset) // 4)
        returned_count = min(requested_count, available_count)
        if returned_count < requested_count:
            warnings.append(
                f"{request}: requested {requested_count} dwords but only {returned_count} fit in mapped file data"
            )

        dwords: list[dict[str, object]] = []
        for index in range(returned_count):
            entry_offset = raw_offset + index * 4
            entry_rva = rva + index * 4
            entry_va = metadata.image_base + entry_rva
            raw = data[entry_offset : entry_offset + 4]
            value = struct.unpack_from("<I", raw)[0]
            entry = {
                "index": index,
                "address": _hex(entry_va),
                "rva": _hex(entry_rva),
                "raw_offset": _hex(entry_offset),
                "raw_bytes": raw.hex(),
            }
            entry.update(_annotate_dword(value, raw, metadata, data))
            dwords.append(entry)

        read_payload["raw_offset"] = _hex(raw_offset)
        read_payload["count_returned"] = returned_count
        read_payload["dwords"] = dwords
        reads.append(read_payload)

    return {
        "type": "pe-dwords",
        "target": str(target_path),
        "image_base": _hex(metadata.image_base),
        "reads": reads,
        "warnings": warnings,
    }
