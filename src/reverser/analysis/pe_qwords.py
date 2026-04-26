from __future__ import annotations

import math
import string
import struct
from pathlib import Path

from reverser.analysis.pe_direct_calls import PEMetadata, parse_int_literal, read_pe_metadata


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
        raise ValueError("Qword read count must be greater than zero.")
    return parse_int_literal(address_part), count


def _ascii_preview(raw: bytes) -> str | None:
    stripped = raw.split(b"\x00", 1)[0]
    if len(stripped) < 4:
        return None
    printable = set(bytes(string.printable, "ascii")) - {0x0B, 0x0C}
    if all(byte in printable for byte in stripped):
        return stripped.decode("ascii", errors="replace")
    return None


def _utf16le_preview(raw: bytes) -> str | None:
    chars: list[str] = []
    for offset in range(0, len(raw) - 1, 2):
        codepoint = struct.unpack_from("<H", raw, offset)[0]
        if codepoint == 0:
            break
        chars.append(chr(codepoint))

    if len(chars) < 4:
        return None
    text = "".join(chars)
    if all(char in string.printable for char in text):
        return text
    return None


def _string_preview_from_raw(raw: bytes) -> dict[str, object] | None:
    utf16 = _utf16le_preview(raw)
    if utf16 is not None:
        return {
            "target_string_kind": "utf16le",
            "target_string": utf16,
            "target_string_length": len(utf16),
        }

    ascii_text = _ascii_preview(raw)
    if ascii_text is not None:
        return {
            "target_string_kind": "ascii",
            "target_string": ascii_text,
            "target_string_length": len(ascii_text),
        }
    return None


def _import_name_preview(raw: bytes) -> dict[str, object] | None:
    if len(raw) < 6:
        return None
    printable = set(bytes(string.printable, "ascii")) - {0x0B, 0x0C}
    if raw[0] in printable and raw[1] in printable:
        return None
    name = _ascii_preview(raw[2:])
    if name is None:
        return None
    return {
        "target_string_kind": "import-name",
        "target_string": name,
        "target_string_length": len(name),
        "target_import_hint": struct.unpack_from("<H", raw, 0)[0],
    }


def _target_preview_for_rva(data: bytes, metadata: PEMetadata, rva: int) -> dict[str, object] | None:
    section = metadata.section_for_rva(rva)
    if section is None or section.is_executable:
        return None

    try:
        raw_offset = metadata.rva_to_offset(rva)
    except ValueError:
        return None

    section_raw_end = min(len(data), section.raw_pointer + section.raw_size)
    raw = data[raw_offset : min(section_raw_end, raw_offset + 256)]
    import_preview = _import_name_preview(raw)
    if import_preview is not None:
        return import_preview
    return _string_preview_from_raw(raw)


def target_string_preview(data: bytes, metadata: PEMetadata, value: int) -> dict[str, object] | None:
    section = metadata.section_for_va(value)
    if section is None or section.is_executable:
        return None
    return _target_preview_for_rva(data, metadata, value - metadata.image_base)


def _annotate_qword(value: int, raw: bytes, metadata: PEMetadata, data: bytes) -> dict[str, object]:
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
        "annotation": annotation,
    }
    if target_section is not None:
        payload["target_rva"] = _hex(value - metadata.image_base)
        payload["target_section"] = target_section.name
        payload["target_is_executable"] = target_section.is_executable
        target_preview = target_string_preview(data, metadata, value)
        if target_preview is not None:
            payload.update(target_preview)
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

    ascii_preview = _ascii_preview(raw)
    if ascii_preview is not None:
        payload["ascii_preview"] = ascii_preview
        if annotation == "non-image-value":
            payload["annotation"] = "ascii-inline"
    elif annotation == "non-image-value":
        float64 = struct.unpack_from("<d", raw)[0]
        if math.isfinite(float64):
            payload["float64"] = float64
    return payload


def read_pe_qwords(path: str | Path, requests: list[str], *, default_count: int = 8) -> dict[str, object]:
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
            "qwords": [],
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
        available_count = max(0, (raw_end - raw_offset) // 8)
        returned_count = min(requested_count, available_count)
        if returned_count < requested_count:
            warnings.append(
                f"{request}: requested {requested_count} qwords but only {returned_count} fit in mapped file data"
            )

        qwords: list[dict[str, object]] = []
        for index in range(returned_count):
            entry_offset = raw_offset + index * 8
            entry_rva = rva + index * 8
            entry_va = metadata.image_base + entry_rva
            raw = data[entry_offset : entry_offset + 8]
            value = struct.unpack_from("<Q", raw)[0]
            entry = {
                "index": index,
                "address": _hex(entry_va),
                "rva": _hex(entry_rva),
                "raw_offset": _hex(entry_offset),
                "raw_bytes": raw.hex(),
            }
            entry.update(_annotate_qword(value, raw, metadata, data))
            qwords.append(entry)

        read_payload["raw_offset"] = _hex(raw_offset)
        read_payload["count_returned"] = returned_count
        read_payload["qwords"] = qwords
        reads.append(read_payload)

    return {
        "type": "pe-qwords",
        "target": str(target_path),
        "image_base": _hex(metadata.image_base),
        "reads": reads,
        "warnings": warnings,
    }
