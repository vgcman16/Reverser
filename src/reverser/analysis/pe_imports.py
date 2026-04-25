from __future__ import annotations

import struct
from pathlib import Path

from reverser.analysis.pe_direct_calls import PEMetadata, read_pe_metadata


def _hex(value: int) -> str:
    return f"0x{value:x}"


def _read_c_string(data: bytes, offset: int | None) -> str:
    if offset is None or offset >= len(data):
        return "<invalid>"
    end = data.find(b"\x00", offset)
    if end == -1:
        end = len(data)
    return data[offset:end].decode("ascii", errors="replace")


def _rva_to_offset(metadata: PEMetadata, rva: int) -> int | None:
    try:
        return metadata.rva_to_offset(rva)
    except ValueError:
        return None


def _pe_optional_context(data: bytes) -> tuple[int, bool, int]:
    if len(data) < 0x100 or data[:2] != b"MZ":
        raise ValueError("Target is not a PE file.")
    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 4 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        raise ValueError("Target begins with MZ but has no valid PE signature.")

    coff_offset = pe_offset + 4
    optional_header_size = struct.unpack_from("<H", data, coff_offset + 16)[0]
    optional_offset = coff_offset + 20
    if optional_offset + optional_header_size > len(data):
        raise ValueError("PE optional header extends beyond the file.")

    magic = struct.unpack_from("<H", data, optional_offset)[0]
    is_pe32_plus = magic == 0x20B
    if magic not in (0x10B, 0x20B):
        raise ValueError(f"Unsupported PE optional-header magic {_hex(magic)}.")
    number_of_rva_and_sizes = struct.unpack_from("<I", data, optional_offset + (108 if is_pe32_plus else 92))[0]
    data_directory_offset = optional_offset + (112 if is_pe32_plus else 96)
    return data_directory_offset, is_pe32_plus, number_of_rva_and_sizes


def _read_data_directory(data: bytes, index: int, directory_offset: int, directory_count: int) -> tuple[int, int]:
    if index >= directory_count:
        return 0, 0
    offset = directory_offset + index * 8
    if offset + 8 > len(data):
        return 0, 0
    return struct.unpack_from("<II", data, offset)


def _import_function_payload(
    *,
    metadata: PEMetadata,
    dll_name: str,
    index: int,
    step: int,
    ordinal_flag: int,
    lookup_rva: int,
    lookup_offset: int | None,
    first_thunk: int,
    iat_offset: int | None,
    value: int,
    data: bytes,
) -> dict[str, object]:
    iat_entry_rva = first_thunk + index * step
    iat_entry_va = metadata.image_base + iat_entry_rva
    lookup_entry_rva = lookup_rva + index * step
    payload: dict[str, object] = {
        "index": index,
        "dll": dll_name,
        "iat_entry_va": _hex(iat_entry_va),
        "iat_entry_rva": _hex(iat_entry_rva),
        "lookup_entry_va": _hex(metadata.image_base + lookup_entry_rva),
        "lookup_entry_rva": _hex(lookup_entry_rva),
        "lookup_value": _hex(value),
    }
    if iat_offset is not None:
        payload["iat_entry_raw_offset"] = _hex(iat_offset + index * step)
    if lookup_offset is not None:
        payload["lookup_entry_raw_offset"] = _hex(lookup_offset + index * step)

    if value & ordinal_flag:
        ordinal = value & 0xFFFF
        payload.update(
            {
                "import_by": "ordinal",
                "ordinal": ordinal,
                "display_name": f"{dll_name}!ordinal:{ordinal}",
            }
        )
        return payload

    hint_name_rva = int(value)
    hint_name_offset = _rva_to_offset(metadata, hint_name_rva)
    payload.update(
        {
            "import_by": "name",
            "hint_name_va": _hex(metadata.image_base + hint_name_rva),
            "hint_name_rva": _hex(hint_name_rva),
        }
    )
    if hint_name_offset is None or hint_name_offset + 2 > len(data):
        payload["name"] = "<invalid>"
        payload["display_name"] = f"{dll_name}!<invalid>"
        return payload

    hint = struct.unpack_from("<H", data, hint_name_offset)[0]
    name = _read_c_string(data, hint_name_offset + 2)
    payload.update(
        {
            "hint": hint,
            "name": name,
            "display_name": f"{dll_name}!{name}",
        }
    )
    return payload


def read_pe_import_entries(data: bytes, metadata: PEMetadata | None = None) -> tuple[list[dict[str, object]], list[str]]:
    metadata = metadata or read_pe_metadata(data)
    directory_offset, is_pe32_plus, directory_count = _pe_optional_context(data)
    import_rva, import_size = _read_data_directory(data, 1, directory_offset, directory_count)
    warnings: list[str] = []
    if import_rva == 0:
        return [], warnings

    descriptor_offset = _rva_to_offset(metadata, import_rva)
    if descriptor_offset is None:
        warnings.append(f"Import directory RVA {_hex(import_rva)} is not file-backed.")
        return [], warnings

    step = 8 if is_pe32_plus else 4
    ordinal_flag = 1 << (63 if is_pe32_plus else 31)
    entries: list[dict[str, object]] = []
    cursor = descriptor_offset
    descriptor_index = 0
    max_descriptor_end = descriptor_offset + import_size if import_size else len(data)

    while cursor + 20 <= len(data) and cursor < max_descriptor_end:
        original_first_thunk, _, _, name_rva, first_thunk = struct.unpack_from("<IIIII", data, cursor)
        if not any((original_first_thunk, name_rva, first_thunk)):
            break

        name_offset = _rva_to_offset(metadata, name_rva)
        dll_name = _read_c_string(data, name_offset)
        lookup_rva = original_first_thunk or first_thunk
        lookup_offset = _rva_to_offset(metadata, lookup_rva)
        iat_offset = _rva_to_offset(metadata, first_thunk)

        if lookup_offset is None:
            warnings.append(f"Import lookup table for {dll_name} at RVA {_hex(lookup_rva)} is not file-backed.")
            cursor += 20
            descriptor_index += 1
            continue

        for index in range(4096):
            item_offset = lookup_offset + index * step
            if item_offset + step > len(data):
                warnings.append(f"Import lookup table for {dll_name} reached end of file before a null thunk.")
                break
            value = struct.unpack_from("<Q" if is_pe32_plus else "<I", data, item_offset)[0]
            if value == 0:
                break
            entry = _import_function_payload(
                metadata=metadata,
                dll_name=dll_name,
                index=index,
                step=step,
                ordinal_flag=ordinal_flag,
                lookup_rva=lookup_rva,
                lookup_offset=lookup_offset,
                first_thunk=first_thunk,
                iat_offset=iat_offset,
                value=value,
                data=data,
            )
            entry["descriptor_index"] = descriptor_index
            entry["descriptor_rva"] = _hex(import_rva + descriptor_index * 20)
            entry["descriptor_va"] = _hex(metadata.image_base + import_rva + descriptor_index * 20)
            entries.append(entry)

        cursor += 20
        descriptor_index += 1

    return entries, warnings


def import_lookup_by_iat_va(data: bytes, metadata: PEMetadata | None = None) -> tuple[dict[int, dict[str, object]], list[str]]:
    entries, warnings = read_pe_import_entries(data, metadata)
    lookup: dict[int, dict[str, object]] = {}
    for entry in entries:
        iat_entry_va = int(str(entry["iat_entry_va"]), 0)
        lookup[iat_entry_va] = {
            key: value
            for key, value in entry.items()
            if key
            in {
                "dll",
                "import_by",
                "name",
                "ordinal",
                "hint",
                "display_name",
                "iat_entry_va",
                "iat_entry_rva",
                "hint_name_va",
                "hint_name_rva",
            }
        }
    return lookup, warnings


def read_pe_imports(path: str | Path) -> dict[str, object]:
    target_path = Path(path)
    data = target_path.read_bytes()
    metadata = read_pe_metadata(data)
    entries, warnings = read_pe_import_entries(data, metadata)

    imports_by_dll: dict[str, list[dict[str, object]]] = {}
    for entry in entries:
        imports_by_dll.setdefault(str(entry["dll"]), []).append(entry)

    imports = [
        {
            "dll": dll_name,
            "function_count": len(functions),
            "functions": functions,
        }
        for dll_name, functions in sorted(imports_by_dll.items(), key=lambda item: item[0].lower())
    ]

    return {
        "type": "pe-imports",
        "target": str(target_path),
        "image_base": _hex(metadata.image_base),
        "scan": {
            "descriptor_count": len(imports),
            "imported_function_count": len(entries),
        },
        "imports": imports,
        "warnings": warnings,
    }
