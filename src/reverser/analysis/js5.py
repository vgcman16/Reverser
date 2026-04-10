from __future__ import annotations

import bz2
import hashlib
import json
import lzma
import re
import sqlite3
import zlib
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path

from reverser import __version__


JCACHE_NAME_PATTERN = re.compile(r"^(?P<core>core-)?js5-(?P<archive_id>\d+)\.jcache$", re.IGNORECASE)
COMPRESSION_LABELS = {
    0: "none",
    1: "bzip2",
    2: "gzip",
    3: "lzma",
}
DEFAULT_MAX_CONTAINER_BYTES = 1_000_000
DEFAULT_MAX_DECODED_BYTES = 1_000_000
CP1252_CODEC = "cp1252"
SCRIPT_VAR_TYPE_NAMES = {
    0: "INT",
    26: "ENUM",
    30: "LOC",
    31: "MODEL",
    32: "NPC",
    33: "OBJ",
    36: "STRING",
    73: "STRUCT",
    97: "INTERFACE",
    110: "LONG",
}


@dataclass(slots=True)
class JS5ContainerRecord:
    raw_bytes: int
    compression_type: str
    compression_code: int | None = None
    compressed_bytes: int | None = None
    uncompressed_bytes: int | None = None
    header_bytes: int = 0
    payload_magic: str = ""
    trailing_bytes: int = 0
    trailing_revision_candidate: int | None = None
    decoded_bytes: int | None = None
    decoded_matches_header: bool | None = None
    decoded_prefix_hex: str | None = None
    parse_error: str | None = None
    decompression_error: str | None = None
    decoded_skipped_reason: str | None = None
    compressed_payload: bytes = b""
    decoded_payload: bytes | None = None

    def to_dict(self) -> dict[str, object]:
        payload: dict[str, object] = {
            "raw_bytes": self.raw_bytes,
            "compression_type": self.compression_type,
            "trailing_bytes": self.trailing_bytes,
        }

        optional_fields = {
            "compression_code": self.compression_code,
            "compressed_bytes": self.compressed_bytes,
            "uncompressed_bytes": self.uncompressed_bytes,
            "header_bytes": self.header_bytes,
            "payload_magic": self.payload_magic or None,
            "trailing_revision_candidate": self.trailing_revision_candidate,
            "decoded_bytes": self.decoded_bytes,
            "decoded_matches_header": self.decoded_matches_header,
            "decoded_prefix_hex": self.decoded_prefix_hex,
            "parse_error": self.parse_error,
            "decompression_error": self.decompression_error,
            "decoded_skipped_reason": self.decoded_skipped_reason,
        }
        for key, value in optional_fields.items():
            if value is not None:
                payload[key] = value
        return payload


def quote_identifier(name: str) -> str:
    escaped = name.replace('"', '""')
    return f'"{escaped}"'


def _read_u8(data: bytes, offset: int) -> tuple[int, int]:
    return data[offset], offset + 1


def _read_u16be(data: bytes, offset: int) -> tuple[int, int]:
    return int.from_bytes(data[offset : offset + 2], "big"), offset + 2


def _read_i32be(data: bytes, offset: int) -> tuple[int, int]:
    return int.from_bytes(data[offset : offset + 4], "big", signed=True), offset + 4


def _read_u24be(data: bytes, offset: int) -> tuple[int, int]:
    return int.from_bytes(data[offset : offset + 3], "big"), offset + 3


def _read_u32be(data: bytes, offset: int) -> tuple[int, int]:
    return int.from_bytes(data[offset : offset + 4], "big"), offset + 4


def _read_c_string(data: bytes, offset: int) -> tuple[str, int]:
    terminator = data.find(b"\x00", offset)
    if terminator == -1:
        raise ValueError("unterminated cp1252 string")
    return data[offset:terminator].decode(CP1252_CODEC), terminator + 1


def _read_small_smart_int(data: bytes, offset: int) -> tuple[int, int]:
    peek = data[offset]
    if peek < 128:
        return peek, offset + 1
    value = int.from_bytes(data[offset : offset + 2], "big") - 0x8000
    return value, offset + 2


def _read_smart_int(data: bytes, offset: int) -> tuple[int, int]:
    if data[offset] & 0x80:
        value = int.from_bytes(data[offset : offset + 4], "big") & 0x7FFFFFFF
        return value, offset + 4
    value = int.from_bytes(data[offset : offset + 2], "big")
    return value, offset + 2


def _script_var_type_name(type_id: int | None = None, type_char: str | None = None) -> str | None:
    if type_id is not None:
        return SCRIPT_VAR_TYPE_NAMES.get(type_id)
    if type_char is not None:
        for known_id, name in SCRIPT_VAR_TYPE_NAMES.items():
            if len(type_char) == 1 and name:
                if type_char == "i" and known_id == 0:
                    return name
                if type_char == "s" and known_id == 36:
                    return name
    return None


def match_jcache_name(path: Path) -> re.Match[str] | None:
    return JCACHE_NAME_PATTERN.match(path.name)


@lru_cache(maxsize=128)
def load_index_names(anchor: str) -> tuple[dict[int, str], str | None, int | None]:
    target = Path(anchor)
    candidate_paths: list[Path] = []

    for ancestor in [target.parent, *target.parents]:
        prot_dir = ancestor / "prot"
        if not prot_dir.is_dir():
            continue
        candidate_paths.extend(prot_dir.glob("*/generated/shared/js5-archive-resolution.json"))

    def sort_key(path: Path) -> tuple[int, str]:
        try:
            return (int(path.parts[-4]), str(path))
        except (ValueError, IndexError):
            return (-1, str(path))

    for candidate in sorted(candidate_paths, key=sort_key, reverse=True):
        try:
            payload = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue

        index_names = payload.get("indexNames", {})
        if not isinstance(index_names, dict):
            continue

        normalized: dict[int, str] = {}
        for key, value in index_names.items():
            try:
                normalized[int(key)] = str(value)
            except (TypeError, ValueError):
                continue

        if not normalized:
            continue

        build = payload.get("build")
        try:
            normalized_build = int(build) if build is not None else None
        except (TypeError, ValueError):
            normalized_build = None
        return normalized, str(candidate), normalized_build

    return {}, None, None


def decompress_rs_bzip2(compressed_payload: bytes) -> bytes:
    return bz2.decompress(b"BZh1" + compressed_payload)


def decompress_rs_lzma(compressed_payload: bytes, expected_size: int | None = None) -> bytes:
    if len(compressed_payload) < 5:
        raise ValueError(f"LZMA payload too short: {len(compressed_payload)} bytes")

    props = compressed_payload[:5]
    body = compressed_payload[5:]
    property_byte = props[0]
    pb = property_byte // (9 * 5)
    remainder = property_byte % (9 * 5)
    lp = remainder // 9
    lc = remainder % 9
    dictionary_size = int.from_bytes(props[1:5], "little")
    filters = [
        {
            "id": lzma.FILTER_LZMA1,
            "dict_size": dictionary_size,
            "lc": lc,
            "lp": lp,
            "pb": pb,
        }
    ]
    if expected_size is not None:
        decoder = lzma.LZMADecompressor(format=lzma.FORMAT_RAW, filters=filters)
        return decoder.decompress(body, max_length=expected_size)

    return lzma.decompress(body, format=lzma.FORMAT_RAW, filters=filters)


def _decompress_payload(
    compression_code: int,
    compressed_payload: bytes,
    expected_size: int | None = None,
) -> bytes:
    if compression_code == 0:
        return compressed_payload
    if compression_code == 1:
        return decompress_rs_bzip2(compressed_payload)
    if compression_code == 2:
        return zlib.decompress(compressed_payload, zlib.MAX_WBITS | 16)
    if compression_code == 3:
        return decompress_rs_lzma(compressed_payload, expected_size=expected_size)
    raise ValueError(f"Unsupported container compression type: {compression_code}")


def parse_js5_container_record(
    raw: bytes,
    *,
    max_compressed_bytes: int | None = DEFAULT_MAX_CONTAINER_BYTES,
    max_decoded_bytes: int | None = DEFAULT_MAX_DECODED_BYTES,
    include_decoded_payload: bool = False,
) -> JS5ContainerRecord:
    if len(raw) < 5:
        return JS5ContainerRecord(
            raw_bytes=len(raw),
            compression_type="truncated",
            parse_error="container shorter than 5-byte header",
        )

    compression_code = raw[0]
    compression_type = COMPRESSION_LABELS.get(compression_code, f"unknown:{compression_code}")
    compressed_bytes = int.from_bytes(raw[1:5], "big")
    header_bytes = 5
    uncompressed_bytes: int | None = None

    if compression_code != 0:
        if len(raw) < 9:
            return JS5ContainerRecord(
                raw_bytes=len(raw),
                compression_type=compression_type,
                compression_code=compression_code,
                compressed_bytes=compressed_bytes,
                parse_error="compressed record header truncated",
            )
        uncompressed_bytes = int.from_bytes(raw[5:9], "big")
        header_bytes = 9

    end = header_bytes + compressed_bytes
    if len(raw) < end:
        return JS5ContainerRecord(
            raw_bytes=len(raw),
            compression_type=compression_type,
            compression_code=compression_code,
            compressed_bytes=compressed_bytes,
            uncompressed_bytes=uncompressed_bytes,
            header_bytes=header_bytes,
            parse_error=(
                f"container declared {compressed_bytes} compressed bytes but only "
                f"{max(0, len(raw) - header_bytes)} remain"
            ),
        )

    compressed_payload = raw[header_bytes:end]
    trailing_bytes = max(0, len(raw) - end)
    trailing_revision_candidate = int.from_bytes(raw[end : end + 2], "big") if trailing_bytes >= 2 else None
    record = JS5ContainerRecord(
        raw_bytes=len(raw),
        compression_type=compression_type,
        compression_code=compression_code,
        compressed_bytes=compressed_bytes,
        uncompressed_bytes=uncompressed_bytes,
        header_bytes=header_bytes,
        payload_magic=compressed_payload[:6].hex(),
        trailing_bytes=trailing_bytes,
        trailing_revision_candidate=trailing_revision_candidate,
        compressed_payload=compressed_payload,
    )

    if not compressed_payload:
        return record

    if max_compressed_bytes is not None and compressed_bytes > max_compressed_bytes:
        record.decoded_skipped_reason = (
            f"compressed payload exceeds decode limit: {compressed_bytes} > {max_compressed_bytes}"
        )
        return record

    expected_decoded_bytes = compressed_bytes if compression_code == 0 else uncompressed_bytes
    if max_decoded_bytes is not None and expected_decoded_bytes is not None and expected_decoded_bytes > max_decoded_bytes:
        record.decoded_skipped_reason = (
            f"declared decoded size exceeds limit: {expected_decoded_bytes} > {max_decoded_bytes}"
        )
        return record

    try:
        decoded_payload = _decompress_payload(
            compression_code,
            compressed_payload,
            expected_size=uncompressed_bytes,
        )
    except (EOFError, OSError, ValueError, lzma.LZMAError, zlib.error) as exc:
        record.decompression_error = str(exc)
        return record

    record.decoded_bytes = len(decoded_payload)
    record.decoded_matches_header = uncompressed_bytes is None or len(decoded_payload) == uncompressed_bytes
    record.decoded_prefix_hex = decoded_payload[:16].hex()
    if include_decoded_payload:
        record.decoded_payload = decoded_payload
    return record


def parse_reference_table_payload(payload: bytes) -> dict[str, object]:
    if not payload:
        raise ValueError("reference table payload is empty")

    offset = 0
    format_version, offset = _read_u8(payload, offset)
    if format_version not in {5, 6, 7}:
        raise ValueError(f"unsupported reference table format: {format_version}")

    table_version = 0
    if format_version >= 6:
        table_version, offset = _read_u32be(payload, offset)
    mask, offset = _read_u8(payload, offset)

    has_names = bool(mask & 0x1)
    has_whirlpools = bool(mask & 0x2)
    has_sizes = bool(mask & 0x4)
    has_hashes = bool(mask & 0x8)

    archive_count, offset = _read_smart_int(payload, offset) if format_version >= 7 else _read_u16be(payload, offset)
    archive_ids: list[int] = []
    last_archive_id = 0
    for _ in range(archive_count):
        delta, offset = _read_smart_int(payload, offset) if format_version >= 7 else _read_u16be(payload, offset)
        last_archive_id += delta
        archive_ids.append(last_archive_id)

    archives = [{"archive_id": archive_id} for archive_id in archive_ids]

    if has_names:
        for archive in archives:
            archive["name_hash"], offset = _read_u32be(payload, offset)

    for archive in archives:
        archive["crc"], offset = _read_u32be(payload, offset)

    if has_hashes:
        for archive in archives:
            archive["content_hash"], offset = _read_u32be(payload, offset)

    if has_whirlpools:
        for archive in archives:
            archive["whirlpool"] = payload[offset : offset + 64].hex()
            offset += 64

    if has_sizes:
        for archive in archives:
            archive["compressed_size"], offset = _read_u32be(payload, offset)
            archive["uncompressed_size"], offset = _read_u32be(payload, offset)

    for archive in archives:
        archive["version"], offset = _read_u32be(payload, offset)

    file_counts: list[int] = []
    for _ in archives:
        count, offset = _read_smart_int(payload, offset) if format_version >= 7 else _read_u16be(payload, offset)
        file_counts.append(count)

    for archive, file_count in zip(archives, file_counts, strict=True):
        last_file_id = 0
        file_ids: list[int] = []
        for _ in range(file_count):
            delta, offset = _read_smart_int(payload, offset) if format_version >= 7 else _read_u16be(payload, offset)
            last_file_id += delta
            file_ids.append(last_file_id)
        archive["file_ids"] = file_ids
        archive["file_count"] = len(file_ids)

    if has_names:
        for archive in archives:
            archive["file_name_hashes"] = []
            for _ in archive["file_ids"]:
                file_name_hash, offset = _read_u32be(payload, offset)
                archive["file_name_hashes"].append(file_name_hash)

    return {
        "format": format_version,
        "table_version": table_version,
        "mask": mask,
        "archive_count": archive_count,
        "has_names": has_names,
        "has_whirlpools": has_whirlpools,
        "has_sizes": has_sizes,
        "has_hashes": has_hashes,
        "archives": archives,
        "archives_by_id": {int(archive["archive_id"]): archive for archive in archives},
    }


def split_archive_payload(payload: bytes, file_ids: list[int]) -> list[dict[str, object]]:
    if not file_ids:
        return []
    if len(file_ids) == 1:
        return [{"file_id": int(file_ids[0]), "data": payload}]
    if not payload:
        raise ValueError("archive payload is empty")

    file_count = len(file_ids)
    chunk_count = payload[-1]
    footer_bytes = 1 + chunk_count * file_count * 4
    footer_offset = len(payload) - footer_bytes
    if footer_offset < 0:
        raise ValueError("archive footer exceeds payload length")

    footer_position = footer_offset
    chunk_sizes: list[list[int]] = []
    sizes = [0] * file_count
    for _ in range(chunk_count):
        running_chunk_size = 0
        file_chunk_sizes: list[int] = []
        for file_index in range(file_count):
            delta, footer_position = _read_i32be(payload, footer_position)
            running_chunk_size += delta
            if running_chunk_size < 0:
                raise ValueError("archive chunk size became negative")
            file_chunk_sizes.append(running_chunk_size)
            sizes[file_index] += running_chunk_size
        chunk_sizes.append(file_chunk_sizes)

    data_blobs = [bytearray(size) for size in sizes]
    positions = [0] * file_count
    data_offset = 0
    for chunk in chunk_sizes:
        for file_index, chunk_size in enumerate(chunk):
            chunk_end = data_offset + chunk_size
            if chunk_end > footer_offset:
                raise ValueError("archive chunk overruns payload data section")
            data_blobs[file_index][positions[file_index] : positions[file_index] + chunk_size] = payload[data_offset:chunk_end]
            positions[file_index] += chunk_size
            data_offset = chunk_end

    return [
        {
            "file_id": int(file_id),
            "data": bytes(blob),
        }
        for file_id, blob in zip(file_ids, data_blobs, strict=True)
    ]


def _guess_definition_id(index_name: str | None, archive_key: int, file_id: int) -> int | None:
    if index_name == "CONFIG_ENUM":
        return (archive_key << 8) | file_id
    if index_name == "CONFIG_STRUCT":
        return (archive_key << 5) | file_id
    if index_name == "CONFIG" and archive_key == 11:
        return file_id
    return None


def _decode_enum_definition(data: bytes) -> dict[str, object]:
    offset = 0
    payload: dict[str, object] = {
        "kind": "config-enum",
        "parser_status": "parsed",
        "entry_count": 0,
    }
    entries: list[dict[str, object]] = []

    try:
        while offset < len(data):
            opcode, offset = _read_u8(data, offset)
            if opcode == 0:
                break
            if opcode == 1:
                type_code, offset = _read_u8(data, offset)
                type_char = bytes([type_code]).decode(CP1252_CODEC)
                payload["key_type_char"] = type_char
                payload["key_type_name"] = _script_var_type_name(type_char=type_char)
            elif opcode == 2:
                type_code, offset = _read_u8(data, offset)
                type_char = bytes([type_code]).decode(CP1252_CODEC)
                payload["value_type_char"] = type_char
                payload["value_type_name"] = _script_var_type_name(type_char=type_char)
            elif opcode == 3:
                default_string, offset = _read_c_string(data, offset)
                payload["default_string"] = default_string
            elif opcode == 4:
                default_int, offset = _read_i32be(data, offset)
                payload["default_int"] = default_int
            elif opcode in {5, 6, 7, 8}:
                string_values = opcode in {5, 7}
                if opcode in {7, 8}:
                    _, offset = _read_u16be(data, offset)
                size, offset = _read_u16be(data, offset)
                payload["entry_count"] = int(payload["entry_count"]) + size
                for _ in range(size):
                    if opcode in {5, 6}:
                        key, offset = _read_i32be(data, offset)
                    else:
                        key, offset = _read_u16be(data, offset)
                    if string_values:
                        value, offset = _read_c_string(data, offset)
                    else:
                        value, offset = _read_i32be(data, offset)
                    if len(entries) < 10:
                        entries.append({"key": key, "value": value})
            elif opcode == 101:
                type_id, offset = _read_small_smart_int(data, offset)
                payload["key_type_id"] = type_id
                payload["key_type_name"] = _script_var_type_name(type_id=type_id)
            elif opcode == 102:
                type_id, offset = _read_small_smart_int(data, offset)
                payload["value_type_id"] = type_id
                payload["value_type_name"] = _script_var_type_name(type_id=type_id)
            else:
                raise ValueError(f"invalid enum opcode {opcode}")
    except Exception as exc:
        payload["parser_status"] = "error"
        payload["error"] = str(exc)

    if entries:
        payload["entry_samples"] = entries
    return payload


def _decode_struct_definition(data: bytes) -> dict[str, object]:
    offset = 0
    payload: dict[str, object] = {
        "kind": "config-struct",
        "parser_status": "parsed",
        "entry_count": 0,
    }
    entries: list[dict[str, object]] = []

    try:
        while offset < len(data):
            opcode, offset = _read_u8(data, offset)
            if opcode == 0:
                break
            if opcode != 249:
                raise ValueError(f"invalid struct opcode {opcode}")
            size, offset = _read_u8(data, offset)
            payload["entry_count"] = size
            for _ in range(size):
                is_string, offset = _read_u8(data, offset)
                key, offset = _read_u24be(data, offset)
                if is_string == 1:
                    value, offset = _read_c_string(data, offset)
                else:
                    value, offset = _read_i32be(data, offset)
                if len(entries) < 10:
                    entries.append({"key": key, "value": value})
    except Exception as exc:
        payload["parser_status"] = "error"
        payload["error"] = str(exc)

    if entries:
        payload["entry_samples"] = entries
    return payload


def _decode_param_definition(data: bytes) -> dict[str, object]:
    offset = 0
    payload: dict[str, object] = {
        "kind": "config-param",
        "parser_status": "parsed",
    }
    try:
        while offset < len(data):
            opcode, offset = _read_u8(data, offset)
            if opcode == 0:
                break
            if opcode == 1:
                type_code, offset = _read_u8(data, offset)
                type_char = bytes([type_code]).decode(CP1252_CODEC)
                payload["type_char"] = type_char
                payload["type_name"] = _script_var_type_name(type_char=type_char)
            elif opcode == 2:
                default_int, offset = _read_i32be(data, offset)
                payload["default_int"] = default_int
            elif opcode == 4:
                payload["members_only"] = True
            elif opcode == 5:
                default_string, offset = _read_c_string(data, offset)
                payload["default_string"] = default_string
            elif opcode == 101:
                type_id, offset = _read_small_smart_int(data, offset)
                payload["type_id"] = type_id
                payload["type_name"] = _script_var_type_name(type_id=type_id)
            else:
                raise ValueError(f"invalid param opcode {opcode}")
    except Exception as exc:
        payload["parser_status"] = "error"
        payload["error"] = str(exc)
    return payload


def _decode_varbit_definition(data: bytes) -> dict[str, object]:
    offset = 0
    payload: dict[str, object] = {
        "kind": "config-varbit",
        "parser_status": "parsed",
    }
    try:
        while offset < len(data):
            opcode, offset = _read_u8(data, offset)
            if opcode == 0:
                break
            if opcode == 1:
                base_var, offset = _read_u16be(data, offset)
                least_significant_bit, offset = _read_u8(data, offset)
                most_significant_bit, offset = _read_u8(data, offset)
                payload["base_var"] = base_var
                payload["least_significant_bit"] = least_significant_bit
                payload["most_significant_bit"] = most_significant_bit
            else:
                raise ValueError(f"invalid varbit opcode {opcode}")
    except Exception as exc:
        payload["parser_status"] = "error"
        payload["error"] = str(exc)
    return payload


def _decode_var_definition(data: bytes) -> dict[str, object]:
    offset = 0
    payload: dict[str, object] = {
        "kind": "config-var-definition",
        "parser_status": "parsed",
        "force_default": True,
        "lifetime": 0,
    }
    try:
        while offset < len(data):
            opcode, offset = _read_u8(data, offset)
            if opcode == 0:
                break
            if opcode == 1:
                type_code, offset = _read_u8(data, offset)
                type_char = bytes([type_code]).decode(CP1252_CODEC)
                payload["type_char"] = type_char
                payload["type_name"] = _script_var_type_name(type_char=type_char)
            elif opcode == 2:
                lifetime, offset = _read_u8(data, offset)
                payload["lifetime"] = lifetime
            elif opcode == 4:
                payload["force_default"] = False
            elif opcode == 101:
                type_id, offset = _read_small_smart_int(data, offset)
                payload["type_id"] = type_id
                payload["type_name"] = _script_var_type_name(type_id=type_id)
            else:
                raise ValueError(f"invalid var-definition opcode {opcode}")
    except Exception as exc:
        payload["parser_status"] = "error"
        payload["error"] = str(exc)
    return payload


def profile_archive_file(
    data: bytes,
    *,
    index_name: str | None,
    archive_key: int,
    file_id: int,
) -> dict[str, object] | None:
    if index_name == "CONFIG_ENUM":
        profile = _decode_enum_definition(data)
    elif index_name == "CONFIG_STRUCT":
        profile = _decode_struct_definition(data)
        if profile.get("parser_status") == "error":
            varbit_profile = _decode_varbit_definition(data)
            if varbit_profile.get("parser_status") == "parsed":
                profile = varbit_profile
    elif index_name == "CONFIG" and archive_key == 11:
        profile = _decode_param_definition(data)
    elif index_name == "CONFIG":
        profile = _decode_var_definition(data)
    else:
        profile = _decode_varbit_definition(data)
        if profile.get("parser_status") == "error":
            return None

    if profile.get("parser_status") == "error":
        return None

    definition_id = _guess_definition_id(index_name, archive_key, file_id)
    if definition_id is not None:
        profile["definition_id"] = definition_id
    if "definition_id" not in profile and index_name == "CONFIG":
        profile["definition_id"] = file_id
    profile["archive_key"] = archive_key
    profile["file_id"] = file_id
    return profile


def export_js5_cache(
    source: str | Path,
    output_dir: str | Path,
    *,
    tables: list[str] | None = None,
    keys: list[int] | None = None,
    limit: int | None = None,
    include_container: bool = False,
    max_decoded_bytes: int | None = 64 * 1024 * 1024,
) -> dict[str, object]:
    target = Path(source)
    destination = Path(output_dir)
    if not target.is_file():
        raise FileNotFoundError(str(target))
    match = match_jcache_name(target)
    if match is None:
        raise ValueError(f"{target} is not a supported JS5 cache filename")

    archive_id = int(match.group("archive_id"))
    store_kind = "core-js5" if match.group("core") else "js5"
    index_names, mapping_source, mapping_build = load_index_names(str(target))
    index_name = index_names.get(archive_id)
    requested_tables = tables or ["cache", "cache_index"]
    normalized_keys = sorted(set(int(key) for key in keys or []))
    normalized_limit = max(0, int(limit)) if limit is not None else None

    destination.mkdir(parents=True, exist_ok=True)
    manifest_path = destination / "manifest.json"

    warnings: list[str] = []
    table_payloads: dict[str, dict[str, object]] = {}
    decoded_record_count = 0
    failed_decode_count = 0
    skipped_decode_count = 0
    exported_record_count = 0
    split_file_count = 0
    semantic_profile_count = 0
    semantic_kind_counts: dict[str, int] = {}
    reference_table_summary: dict[str, object] | None = None
    reference_table_archives_by_id: dict[int, dict[str, object]] = {}

    with sqlite3.connect(str(target)) as connection:
        cursor = connection.cursor()
        tables_present = [
            str(name)
            for name, in cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ).fetchall()
        ]
        if "cache_index" in tables_present:
            reference_row = cursor.execute(
                'SELECT "DATA" FROM "cache_index" WHERE "KEY" = 1'
            ).fetchone()
            if reference_row is not None:
                try:
                    reference_container = parse_js5_container_record(
                        bytes(reference_row[0]),
                        max_compressed_bytes=None,
                        max_decoded_bytes=max_decoded_bytes,
                        include_decoded_payload=True,
                    )
                    if reference_container.decoded_payload is not None:
                        reference_table_summary = parse_reference_table_payload(reference_container.decoded_payload)
                        reference_table_archives_by_id = {
                            int(key): value
                            for key, value in reference_table_summary.get("archives_by_id", {}).items()
                        }
                except Exception as exc:
                    warnings.append(f"reference table decode failed: {exc}")

        selected_tables = [table for table in requested_tables if table in tables_present]
        missing_tables = sorted(set(requested_tables) - set(selected_tables))
        for table_name in missing_tables:
            warnings.append(f"table not present: {table_name}")

        for table_name in selected_tables:
            table_dir = destination / table_name
            table_dir.mkdir(parents=True, exist_ok=True)
            quoted_name = quote_identifier(table_name)
            query = f'SELECT "KEY", "DATA", "VERSION", "CRC" FROM {quoted_name} WHERE "DATA" IS NOT NULL'
            params: list[object] = []
            if normalized_keys:
                placeholders = ", ".join("?" for _ in normalized_keys)
                query += f' AND "KEY" IN ({placeholders})'
                params.extend(normalized_keys)
            query += ' ORDER BY "KEY"'
            if normalized_limit is not None:
                query += f" LIMIT {normalized_limit}"

            rows = cursor.execute(query, params).fetchall()
            records: list[dict[str, object]] = []
            for key, data, version, crc in rows:
                exported_record_count += 1
                raw_bytes = bytes(data)
                container = parse_js5_container_record(
                    raw_bytes,
                    max_compressed_bytes=None,
                    max_decoded_bytes=max_decoded_bytes,
                    include_decoded_payload=True,
                )
                stem = f"key-{int(key)}"
                payload_path: Path | None = None
                payload_sha256: str | None = None
                container_path: Path | None = None
                archive_files: list[dict[str, object]] = []

                if include_container:
                    container_path = table_dir / f"{stem}.container.bin"
                    container_path.write_bytes(raw_bytes)

                if container.decoded_payload is not None:
                    payload_path = table_dir / f"{stem}.payload.bin"
                    payload_path.write_bytes(container.decoded_payload)
                    payload_sha256 = hashlib.sha256(container.decoded_payload).hexdigest()
                    decoded_record_count += 1
                elif container.decoded_skipped_reason:
                    skipped_decode_count += 1
                else:
                    failed_decode_count += 1

                if (
                    table_name == "cache"
                    and container.decoded_payload is not None
                    and int(key) in reference_table_archives_by_id
                ):
                    archive_meta = reference_table_archives_by_id[int(key)]
                    try:
                        split_files = split_archive_payload(
                            container.decoded_payload,
                            [int(file_id) for file_id in archive_meta.get("file_ids", [])],
                        )
                    except Exception as exc:
                        warnings.append(f"archive split failed for {table_name}:{key}: {exc}")
                    else:
                        archive_dir = table_dir / stem
                        archive_dir.mkdir(parents=True, exist_ok=True)
                        for archive_file in split_files:
                            file_id = int(archive_file["file_id"])
                            file_data = bytes(archive_file["data"])
                            file_path = archive_dir / f"file-{file_id}.bin"
                            file_path.write_bytes(file_data)
                            split_file_count += 1
                            semantic_profile = profile_archive_file(
                                file_data,
                                index_name=index_name,
                                archive_key=int(key),
                                file_id=file_id,
                            )
                            if semantic_profile is not None and semantic_profile.get("parser_status") in {"parsed", "profiled"}:
                                semantic_profile_count += 1
                                semantic_kind = semantic_profile.get("kind")
                                if isinstance(semantic_kind, str) and semantic_kind:
                                    semantic_kind_counts[semantic_kind] = semantic_kind_counts.get(semantic_kind, 0) + 1
                            archive_files.append(
                                {
                                    "file_id": file_id,
                                    "size_bytes": len(file_data),
                                    "sha256": hashlib.sha256(file_data).hexdigest(),
                                    "path": str(file_path),
                                    "semantic_profile": semantic_profile,
                                }
                            )

                records.append(
                    {
                        "key": int(key),
                        "version": int(version) if version is not None else None,
                        "crc": int(crc) if crc is not None else None,
                        **container.to_dict(),
                        "payload_path": str(payload_path) if payload_path else None,
                        "payload_sha256": payload_sha256,
                        "container_path": str(container_path) if container_path else None,
                        "archive_file_count": len(archive_files),
                        "archive_files": archive_files,
                    }
                )

            table_payloads[table_name] = {
                "record_count": len(records),
                "records": records,
            }

    manifest = {
        "report_version": "1.0",
        "tool": {
            "name": "reverser-workbench",
            "version": __version__,
        },
        "generated_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "source_path": str(target),
        "export_root": str(destination),
        "manifest_path": str(manifest_path),
        "store_kind": store_kind,
        "archive_id": archive_id,
        "index_name": index_name,
        "mapping_source": mapping_source,
        "mapping_build": mapping_build,
        "tables_present": tables_present,
        "settings": {
            "requested_tables": requested_tables,
            "selected_tables": list(table_payloads),
            "keys": normalized_keys,
            "limit": normalized_limit,
            "include_container": include_container,
            "max_decoded_bytes": max_decoded_bytes,
        },
        "summary": {
            "table_count": len(table_payloads),
            "exported_record_count": exported_record_count,
            "decoded_record_count": decoded_record_count,
            "failed_decode_count": failed_decode_count,
            "skipped_decode_count": skipped_decode_count,
            "split_file_count": split_file_count,
            "semantic_profile_count": semantic_profile_count,
            "semantic_kind_counts": semantic_kind_counts,
        },
        "warnings": warnings,
        "tables": table_payloads,
    }
    if reference_table_summary is not None:
        manifest["reference_table"] = {
            "format": reference_table_summary["format"],
            "table_version": reference_table_summary["table_version"],
            "mask": reference_table_summary["mask"],
            "archive_count": reference_table_summary["archive_count"],
            "archives_sample": reference_table_summary["archives"][:25],
        }
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest
