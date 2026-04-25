from __future__ import annotations

import string
import struct
from pathlib import Path

from reverser.analysis.pe_direct_calls import parse_int_literal, read_pe_metadata


def _hex(value: int) -> str:
    return f"0x{value:x}"


def _parse_read_spec(value: str, *, default_max_bytes: int) -> tuple[int, int]:
    raw_value = str(value)
    if ":" in raw_value:
        address_part, count_part = raw_value.split(":", 1)
        max_bytes = parse_int_literal(count_part)
    else:
        address_part = raw_value
        max_bytes = default_max_bytes

    if max_bytes <= 0:
        raise ValueError("String read byte count must be greater than zero.")
    return parse_int_literal(address_part), max_bytes


def _read_ascii_cstring(raw: bytes, *, min_length: int) -> dict[str, object] | None:
    terminator_index = raw.find(b"\x00")
    if terminator_index >= 0:
        value = raw[:terminator_index]
        terminator_found = True
    else:
        value = raw
        terminator_found = False

    if len(value) < min_length:
        return None

    printable = set(bytes(string.printable, "ascii")) - {0x0B, 0x0C}
    if not all(byte in printable for byte in value):
        return None

    return {
        "kind": "ascii-cstring",
        "value": value.decode("ascii", errors="replace"),
        "length": len(value),
        "terminator_found": terminator_found,
    }


def _read_utf16le_cstring(raw: bytes, *, min_length: int) -> dict[str, object] | None:
    chars: list[str] = []
    terminator_found = False
    for offset in range(0, len(raw) - 1, 2):
        codepoint = struct.unpack_from("<H", raw, offset)[0]
        if codepoint == 0:
            terminator_found = True
            break
        char = chr(codepoint)
        if char not in string.printable:
            return None
        chars.append(char)

    if len(chars) < min_length:
        return None

    return {
        "kind": "utf16le-cstring",
        "value": "".join(chars),
        "length": len(chars),
        "terminator_found": terminator_found,
    }


def read_pe_strings(
    path: str | Path,
    requests: list[str],
    *,
    default_max_bytes: int = 256,
    min_length: int = 1,
) -> dict[str, object]:
    target_path = Path(path)
    data = target_path.read_bytes()
    metadata = read_pe_metadata(data)
    warnings: list[str] = []
    reads: list[dict[str, object]] = []

    for request in requests:
        requested_value, requested_max_bytes = _parse_read_spec(request, default_max_bytes=default_max_bytes)
        va, rva = metadata.normalize_va_or_rva(requested_value)
        section = metadata.section_for_rva(rva)
        read_payload: dict[str, object] = {
            "request": str(request),
            "address": _hex(va),
            "rva": _hex(rva),
            "section": section.name if section is not None else None,
            "max_bytes_requested": requested_max_bytes,
            "max_bytes_returned": 0,
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

        section_raw_end = min(len(data), section.raw_pointer + section.raw_size)
        max_raw_end = min(section_raw_end, raw_offset + requested_max_bytes)
        raw = data[raw_offset:max_raw_end]
        if len(raw) < requested_max_bytes:
            warnings.append(
                f"{request}: requested {requested_max_bytes} bytes but only {len(raw)} fit in mapped file data"
            )

        ascii_string = _read_ascii_cstring(raw, min_length=min_length)
        utf16le_string = _read_utf16le_cstring(raw, min_length=min_length)

        read_payload.update(
            {
                "raw_offset": _hex(raw_offset),
                "max_bytes_returned": len(raw),
                "raw_bytes": raw.hex(),
                "ascii": ascii_string,
                "utf16le": utf16le_string,
            }
        )
        if ascii_string is None and utf16le_string is None:
            read_payload["decoded"] = False
        else:
            read_payload["decoded"] = True
        reads.append(read_payload)

    return {
        "type": "pe-strings",
        "target": str(target_path),
        "image_base": _hex(metadata.image_base),
        "scan": {
            "request_count": len(requests),
            "default_max_bytes": default_max_bytes,
            "min_length": min_length,
        },
        "reads": reads,
        "warnings": warnings,
    }
