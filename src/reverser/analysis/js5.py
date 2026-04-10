from __future__ import annotations

import bz2
import hashlib
import json
import lzma
import re
import sqlite3
import zlib
from collections import deque
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
DEFAULT_MAX_RT7_OBJ_VERTICES = 200_000
DEFAULT_MAX_RT7_OBJ_INDICES = 1_500_000
MAPSQUARE_WORLD_STRIDE = 128
CP1252_CODEC = "cp1252"
CLIENTSCRIPT_IMMEDIATE_TYPES = ("short", "byte", "int", "tribyte", "switch")
DEFAULT_CLIENTSCRIPT_CALIBRATION_SAMPLE = 512
DEFAULT_CLIENTSCRIPT_MAX_SOLUTIONS = 32
DEFAULT_CLIENTSCRIPT_MAX_STATES = 20_000
DEFAULT_CLIENTSCRIPT_TRACE_INSTRUCTIONS = 256
CLIENTSCRIPT_SEMANTICS_FILENAME = "clientscript-opcode-semantics.json"
CLIENTSCRIPT_VAR_SOURCE_NAMES = {
    0: "player",
    1: "npc",
    2: "client",
    3: "world",
    4: "region",
    5: "object",
    6: "clan",
    7: "clansettings",
    9: "playergroup",
}
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
MAPSQUARE_FILE_NAMES = {
    0: "locations",
    3: "tiles",
    5: "tiles-nxt",
    6: "environment",
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


@dataclass(slots=True)
class ClientscriptLayout:
    byte0: int
    opcode_data: bytes
    instruction_count: int
    local_int_count: int
    local_string_count: int
    local_long_count: int
    int_argument_count: int
    string_argument_count: int
    long_argument_count: int
    switch_table_count: int
    switch_case_count: int
    switch_tables: list[dict[str, object]]
    switch_tables_sample: list[dict[str, object]]
    switch_payload_bytes: int
    footer_bytes: int


def quote_identifier(name: str) -> str:
    escaped = name.replace('"', '""')
    return f'"{escaped}"'


def _require_remaining(data: bytes, offset: int, size: int) -> None:
    if offset + size > len(data):
        raise ValueError(f"truncated field at offset {offset}: need {size} bytes, have {len(data) - offset}")


def _read_u8(data: bytes, offset: int) -> tuple[int, int]:
    _require_remaining(data, offset, 1)
    return data[offset], offset + 1


def _read_u16be(data: bytes, offset: int) -> tuple[int, int]:
    _require_remaining(data, offset, 2)
    return int.from_bytes(data[offset : offset + 2], "big"), offset + 2


def _read_u16le(data: bytes, offset: int) -> tuple[int, int]:
    _require_remaining(data, offset, 2)
    return int.from_bytes(data[offset : offset + 2], "little"), offset + 2


def _read_i8(data: bytes, offset: int) -> tuple[int, int]:
    _require_remaining(data, offset, 1)
    value = data[offset]
    return (value - 256 if value > 127 else value), offset + 1


def _read_i16be(data: bytes, offset: int) -> tuple[int, int]:
    _require_remaining(data, offset, 2)
    value = int.from_bytes(data[offset : offset + 2], "big")
    if value > 0x7FFF:
        value -= 0x10000
    return value, offset + 2


def _read_i16le(data: bytes, offset: int) -> tuple[int, int]:
    _require_remaining(data, offset, 2)
    return int.from_bytes(data[offset : offset + 2], "little", signed=True), offset + 2


def _read_i32be(data: bytes, offset: int) -> tuple[int, int]:
    _require_remaining(data, offset, 4)
    return int.from_bytes(data[offset : offset + 4], "big", signed=True), offset + 4


def _read_u24be(data: bytes, offset: int) -> tuple[int, int]:
    _require_remaining(data, offset, 3)
    return int.from_bytes(data[offset : offset + 3], "big"), offset + 3


def _read_u32be(data: bytes, offset: int) -> tuple[int, int]:
    _require_remaining(data, offset, 4)
    return int.from_bytes(data[offset : offset + 4], "big"), offset + 4


def _read_u32le(data: bytes, offset: int) -> tuple[int, int]:
    _require_remaining(data, offset, 4)
    return int.from_bytes(data[offset : offset + 4], "little"), offset + 4


def _read_u64be(data: bytes, offset: int) -> tuple[int, int]:
    _require_remaining(data, offset, 8)
    return int.from_bytes(data[offset : offset + 8], "big"), offset + 8


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


def _parse_clientscript_opcode_key(value: object) -> int | None:
    if isinstance(value, int):
        return value
    if not isinstance(value, str):
        return None
    text = value.strip().lower()
    if not text:
        return None
    try:
        if text.startswith("0x"):
            return int(text, 16)
        return int(text, 10)
    except ValueError:
        return None


@lru_cache(maxsize=128)
def load_clientscript_semantic_overrides(anchor: str) -> tuple[dict[int, dict[str, object]], str | None, int | None]:
    target = Path(anchor)
    candidate_paths: list[Path] = []

    for ancestor in [target.parent, *target.parents]:
        candidate_paths.append(ancestor / CLIENTSCRIPT_SEMANTICS_FILENAME)
        prot_dir = ancestor / "prot"
        if prot_dir.is_dir():
            candidate_paths.extend(prot_dir.glob(f"*/generated/shared/{CLIENTSCRIPT_SEMANTICS_FILENAME}"))
        data_prot_dir = ancestor / "data" / "prot"
        if data_prot_dir.is_dir():
            candidate_paths.extend(data_prot_dir.glob(f"*/generated/shared/{CLIENTSCRIPT_SEMANTICS_FILENAME}"))

    def sort_key(path: Path) -> tuple[int, str]:
        try:
            return (int(path.parts[-4]), str(path))
        except (ValueError, IndexError):
            return (-1, str(path))

    seen: set[Path] = set()
    for candidate in sorted(candidate_paths, key=sort_key, reverse=True):
        if candidate in seen or not candidate.is_file():
            continue
        seen.add(candidate)
        try:
            payload = json.loads(candidate.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue

        entries = payload.get("opcodes", payload) if isinstance(payload, dict) else None
        if not isinstance(entries, dict):
            continue

        normalized: dict[int, dict[str, object]] = {}
        for raw_key, entry in entries.items():
            raw_opcode = _parse_clientscript_opcode_key(raw_key)
            if raw_opcode is None or not isinstance(entry, dict):
                continue
            normalized_entry: dict[str, object] = {}
            for field in ("mnemonic", "family", "notes", "status", "control_flow_kind", "jump_base"):
                field_value = entry.get(field)
                if isinstance(field_value, str) and field_value:
                    normalized_entry[field] = field_value
            canonical_id = entry.get("canonical_id")
            if isinstance(canonical_id, int):
                normalized_entry["canonical_id"] = canonical_id
            jump_scale = entry.get("jump_scale")
            if isinstance(jump_scale, int):
                normalized_entry["jump_scale"] = jump_scale
            confidence = entry.get("confidence")
            if isinstance(confidence, (int, float)):
                normalized_entry["confidence"] = float(confidence)
            aliases = entry.get("aliases")
            if isinstance(aliases, list):
                normalized_aliases = [str(alias) for alias in aliases if str(alias)]
                if normalized_aliases:
                    normalized_entry["aliases"] = normalized_aliases
            immediate_kind = entry.get("immediate_kind", entry.get("expected_immediate_kind"))
            if isinstance(immediate_kind, str) and immediate_kind in CLIENTSCRIPT_IMMEDIATE_TYPES:
                normalized_entry["immediate_kind"] = immediate_kind
            if normalized_entry:
                normalized[raw_opcode] = normalized_entry

        if not normalized:
            continue

        build = payload.get("build") if isinstance(payload, dict) else None
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
    if index_name in {"CONFIG_ITEM", "CONFIG_NPC", "CONFIG_OBJECT"}:
        return (archive_key << 8) | file_id
    if index_name == "CONFIG" and archive_key == 11:
        return file_id
    return None


def _read_param_entries(data: bytes, offset: int) -> tuple[list[dict[str, object]], int]:
    size, offset = _read_u8(data, offset)
    entries: list[dict[str, object]] = []
    for _ in range(size):
        is_string, offset = _read_u8(data, offset)
        key, offset = _read_u24be(data, offset)
        if is_string == 1:
            value, offset = _read_c_string(data, offset)
        else:
            value, offset = _read_i32be(data, offset)
        entries.append({"key": key, "value": value})
    return entries, offset


def _finalize_partial_profile(
    payload: dict[str, object],
    *,
    data: bytes,
    offset: int,
    stopped_opcode: int | None,
    opaque_flags: list[int],
    opaque_values: dict[int, object],
    min_field_count: int,
) -> dict[str, object]:
    payload["data_bytes"] = len(data)
    payload["consumed_bytes"] = offset
    if opaque_flags:
        payload["opaque_flags"] = [int(opcode) for opcode in sorted(set(opaque_flags))]
    if opaque_values:
        payload["opaque_values"] = {str(opcode): value for opcode, value in sorted(opaque_values.items())}
    if stopped_opcode is not None:
        payload["parser_status"] = "profiled"
        payload["stopped_opcode"] = int(stopped_opcode)
    field_count = sum(
        1
        for key, value in payload.items()
        if key
        not in {
            "kind",
            "parser_status",
            "data_bytes",
            "consumed_bytes",
            "opaque_flags",
            "opaque_values",
            "stopped_opcode",
        }
        and value not in (None, [], {}, False)
    )
    if payload.get("parser_status") == "profiled" and field_count < min_field_count:
        payload["parser_status"] = "error"
        payload["error"] = f"insufficient field coverage before opcode {stopped_opcode}"
    return payload


def _png_chunk(chunk_type: bytes, payload: bytes) -> bytes:
    return (
        len(payload).to_bytes(4, "big")
        + chunk_type
        + payload
        + zlib.crc32(chunk_type + payload).to_bytes(4, "big")
    )


def _encode_png_rgba(width: int, height: int, rgba: bytes) -> bytes:
    if width <= 0 or height <= 0:
        raise ValueError("PNG dimensions must be positive")
    if len(rgba) != width * height * 4:
        raise ValueError("RGBA payload length does not match PNG dimensions")

    scanlines = bytearray()
    stride = width * 4
    for row in range(height):
        scanlines.append(0)
        start = row * stride
        scanlines.extend(rgba[start : start + stride])

    ihdr = (
        width.to_bytes(4, "big")
        + height.to_bytes(4, "big")
        + bytes([8, 6, 0, 0, 0])
    )
    idat = zlib.compress(bytes(scanlines), level=9)
    return (
        b"\x89PNG\r\n\x1a\n"
        + _png_chunk(b"IHDR", ihdr)
        + _png_chunk(b"IDAT", idat)
        + _png_chunk(b"IEND", b"")
    )


def _decode_sprite_archive(data: bytes) -> dict[str, object]:
    if len(data) < 10:
        raise ValueError("sprite archive too short")

    sprite_count = int.from_bytes(data[-2:], "big")
    if sprite_count <= 0:
        raise ValueError("sprite archive declares zero sprites")

    footer_offset = len(data) - 7 - sprite_count * 8
    if footer_offset < 0:
        raise ValueError("sprite archive footer exceeds payload length")

    canvas_width = int.from_bytes(data[footer_offset : footer_offset + 2], "big")
    canvas_height = int.from_bytes(data[footer_offset + 2 : footer_offset + 4], "big")
    palette_size = data[footer_offset + 4] + 1
    if palette_size <= 0:
        raise ValueError("sprite archive palette size is invalid")

    palette_offset = footer_offset - (palette_size - 1) * 3
    if palette_offset < 0:
        raise ValueError("sprite archive palette exceeds payload length")

    cursor = footer_offset + 5
    x_offsets: list[int] = []
    y_offsets: list[int] = []
    widths: list[int] = []
    heights: list[int] = []
    for target in (x_offsets, y_offsets, widths, heights):
        for _ in range(sprite_count):
            value = int.from_bytes(data[cursor : cursor + 2], "big")
            cursor += 2
            target.append(value)

    palette = [0]
    for index in range(1, palette_size):
        rgb = int.from_bytes(
            data[palette_offset + (index - 1) * 3 : palette_offset + (index - 1) * 3 + 3],
            "big",
        )
        palette.append(rgb if rgb != 0 else 1)

    frames: list[dict[str, object]] = []
    pixel_offset = 0
    total_pixels = 0
    alpha_sprite_count = 0
    max_frame_width = 0
    max_frame_height = 0

    for sprite_id in range(sprite_count):
        width = widths[sprite_id]
        height = heights[sprite_id]
        if width <= 0 or height <= 0:
            raise ValueError(f"sprite {sprite_id} has invalid dimensions {width}x{height}")

        flags = data[pixel_offset]
        pixel_offset += 1
        size = width * height
        total_pixels += size
        max_frame_width = max(max_frame_width, width)
        max_frame_height = max(max_frame_height, height)
        has_alpha = bool(flags & 0x2)
        column_major = bool(flags & 0x1)
        if has_alpha:
            alpha_sprite_count += 1

        indices = [0] * size
        if column_major:
            for x in range(width):
                for y in range(height):
                    indices[y * width + x] = data[pixel_offset]
                    pixel_offset += 1
        else:
            indices = list(data[pixel_offset : pixel_offset + size])
            pixel_offset += size

        alphas = [255] * size
        if has_alpha:
            if column_major:
                for x in range(width):
                    for y in range(height):
                        alphas[y * width + x] = data[pixel_offset]
                        pixel_offset += 1
            else:
                alphas = list(data[pixel_offset : pixel_offset + size])
                pixel_offset += size

        rgba = bytearray(size * 4)
        nontransparent_pixels = 0
        for pixel_index, palette_index in enumerate(indices):
            rgb = palette[palette_index] if 0 <= palette_index < len(palette) else 0
            alpha = alphas[pixel_index] if palette_index != 0 else 0
            if alpha:
                nontransparent_pixels += 1
            base = pixel_index * 4
            rgba[base] = (rgb >> 16) & 0xFF
            rgba[base + 1] = (rgb >> 8) & 0xFF
            rgba[base + 2] = rgb & 0xFF
            rgba[base + 3] = alpha

        frames.append(
            {
                "sprite_id": sprite_id,
                "offset_x": x_offsets[sprite_id],
                "offset_y": y_offsets[sprite_id],
                "width": width,
                "height": height,
                "flags": flags,
                "column_major": column_major,
                "has_alpha": has_alpha,
                "nontransparent_pixels": nontransparent_pixels,
                "rgba": bytes(rgba),
            }
        )

    if pixel_offset != palette_offset:
        raise ValueError(
            f"sprite archive data section length mismatch: decoded {pixel_offset} bytes before palette, expected {palette_offset}"
        )

    max_preview_frames = min(len(frames), 16)
    preview_png: bytes | None = None
    preview_kind = "contact-sheet" if sprite_count > 1 else "single"
    preview_width = 0
    preview_height = 0
    preview_skip_reason: str | None = None
    if total_pixels > 4_000_000:
        preview_skip_reason = f"sprite preview skipped: total pixels {total_pixels} exceed 4000000"
    elif max_preview_frames == 0:
        preview_skip_reason = "sprite preview skipped: no frames"
    else:
        preview_subset = frames[:max_preview_frames]
        if len(preview_subset) == 1:
            frame = preview_subset[0]
            preview_width = int(frame["width"])
            preview_height = int(frame["height"])
            preview_png = _encode_png_rgba(preview_width, preview_height, bytes(frame["rgba"]))
        else:
            columns = 1
            while columns * columns < max_preview_frames:
                columns += 1
            rows = (max_preview_frames + columns - 1) // columns
            cell_width = max(int(frame["width"]) for frame in preview_subset)
            cell_height = max(int(frame["height"]) for frame in preview_subset)
            preview_width = columns * cell_width
            preview_height = rows * cell_height
            sheet = bytearray(preview_width * preview_height * 4)
            for frame_index, frame in enumerate(preview_subset):
                origin_x = (frame_index % columns) * cell_width
                origin_y = (frame_index // columns) * cell_height
                width = int(frame["width"])
                height = int(frame["height"])
                rgba = bytes(frame["rgba"])
                for y in range(height):
                    dest_row = ((origin_y + y) * preview_width + origin_x) * 4
                    src_row = y * width * 4
                    row_bytes = width * 4
                    sheet[dest_row : dest_row + row_bytes] = rgba[src_row : src_row + row_bytes]
            preview_png = _encode_png_rgba(preview_width, preview_height, bytes(sheet))

    payload: dict[str, object] = {
        "kind": "sprite-sheet",
        "parser_status": "parsed",
        "sprite_count": sprite_count,
        "canvas_width": canvas_width,
        "canvas_height": canvas_height,
        "palette_size": palette_size,
        "alpha_sprite_count": alpha_sprite_count,
        "total_pixels": total_pixels,
        "max_frame_width": max_frame_width,
        "max_frame_height": max_frame_height,
        "preview_kind": preview_kind,
        "preview_width": preview_width,
        "preview_height": preview_height,
        "palette_sample": [f"#{color:06x}" for color in palette[1:11]],
        "frames_sample": [
            {
                key: value
                for key, value in frame.items()
                if key != "rgba"
            }
            for frame in frames[:10]
        ],
    }
    if preview_skip_reason is not None:
        payload["preview_skip_reason"] = preview_skip_reason
    if preview_png is not None:
        payload["_preview_png_bytes"] = preview_png
    return payload


def _parse_clientscript_layout(data: bytes) -> ClientscriptLayout:
    if len(data) < 19:
        raise ValueError("clientscript payload too short")

    switch_payload_bytes = int.from_bytes(data[-2:], "big")
    fixed_footer_start = len(data) - 2 - switch_payload_bytes - 16
    if fixed_footer_start < 1:
        raise ValueError("clientscript footer exceeds payload length")

    offset = fixed_footer_start
    instruction_count, offset = _read_u32be(data, offset)
    local_int_count, offset = _read_u16be(data, offset)
    local_string_count, offset = _read_u16be(data, offset)
    local_long_count, offset = _read_u16be(data, offset)
    int_argument_count, offset = _read_u16be(data, offset)
    string_argument_count, offset = _read_u16be(data, offset)
    long_argument_count, offset = _read_u16be(data, offset)

    switch_table_start = offset
    if switch_table_start != len(data) - 2 - switch_payload_bytes:
        raise ValueError("clientscript footer alignment mismatch")

    switch_count, offset = _read_u8(data, offset)
    switch_tables: list[dict[str, object]] = []
    total_switch_cases = 0
    for table_index in range(switch_count):
        case_count, offset = _read_u16be(data, offset)
        total_switch_cases += case_count
        cases: list[dict[str, int]] = []
        case_samples: list[dict[str, int]] = []
        for case_index in range(case_count):
            case_value, offset = _read_i32be(data, offset)
            jump_offset, offset = _read_i32be(data, offset)
            case_payload = {"value": case_value, "jump_offset": jump_offset}
            cases.append(case_payload)
            if case_index < 8:
                case_samples.append(case_payload)
        switch_tables.append(
            {
                "table_index": table_index,
                "case_count": case_count,
                "cases": cases,
                "case_samples": case_samples,
            }
        )

    if offset != len(data) - 2:
        raise ValueError(f"clientscript trailer parsing ended at {offset}, expected {len(data) - 2}")

    return ClientscriptLayout(
        byte0=data[0],
        opcode_data=data[1:fixed_footer_start],
        instruction_count=instruction_count,
        local_int_count=local_int_count,
        local_string_count=local_string_count,
        local_long_count=local_long_count,
        int_argument_count=int_argument_count,
        string_argument_count=string_argument_count,
        long_argument_count=long_argument_count,
        switch_table_count=switch_count,
        switch_case_count=total_switch_cases,
        switch_tables=switch_tables,
        switch_tables_sample=switch_tables[:6],
        switch_payload_bytes=switch_payload_bytes,
        footer_bytes=len(data) - fixed_footer_start,
    )


def _clientscript_profile_from_layout(layout: ClientscriptLayout) -> dict[str, object]:
    return {
        "kind": "clientscript-metadata",
        "parser_status": "parsed",
        "body_bytes": 1 + len(layout.opcode_data),
        "opcode_data_bytes": len(layout.opcode_data),
        "footer_bytes": layout.footer_bytes,
        "trailer_length": layout.switch_payload_bytes,
        "switch_payload_bytes": layout.switch_payload_bytes,
        "instruction_count": layout.instruction_count,
        "local_int_count": layout.local_int_count,
        "local_string_count": layout.local_string_count,
        "local_long_count": layout.local_long_count,
        "int_argument_count": layout.int_argument_count,
        "string_argument_count": layout.string_argument_count,
        "long_argument_count": layout.long_argument_count,
        "switch_table_count": layout.switch_table_count,
        "switch_case_count": layout.switch_case_count,
        "switch_tables_sample": layout.switch_tables_sample,
        "byte0": layout.byte0,
        "script_name": None,
    }


def _read_clientscript_immediate(opcode_data: bytes, offset: int, immediate_kind: str) -> dict[str, object] | None:
    try:
        if immediate_kind == "short":
            value, end_offset = _read_i16be(opcode_data, offset)
            return {"immediate_kind": immediate_kind, "immediate_value": value, "end_offset": end_offset}
        if immediate_kind == "byte":
            value, end_offset = _read_u8(opcode_data, offset)
            return {"immediate_kind": immediate_kind, "immediate_value": value, "end_offset": end_offset}
        if immediate_kind == "int":
            value, end_offset = _read_i32be(opcode_data, offset)
            return {"immediate_kind": immediate_kind, "immediate_value": value, "end_offset": end_offset}
        if immediate_kind == "tribyte":
            value, end_offset = _read_u24be(opcode_data, offset)
            return {"immediate_kind": immediate_kind, "immediate_value": value, "end_offset": end_offset}
        if immediate_kind == "switch":
            subtype, end_offset = _read_u8(opcode_data, offset)
            payload: dict[str, object] = {
                "immediate_kind": immediate_kind,
                "switch_subtype": subtype,
            }
            if subtype == 0:
                value, end_offset = _read_i32be(opcode_data, end_offset)
                payload["immediate_value"] = value
            elif subtype == 1:
                high, end_offset = _read_u32be(opcode_data, end_offset)
                low, end_offset = _read_u32be(opcode_data, end_offset)
                payload["immediate_value"] = {
                    "high": high,
                    "low": low,
                    "hex": f"0x{high:08X}{low:08X}",
                }
            elif subtype == 2:
                value, end_offset = _read_c_string(opcode_data, end_offset)
                payload["immediate_value"] = value
            else:
                return None
            payload["end_offset"] = end_offset
            return payload
    except ValueError:
        return None
    return None


def _unpack_clientscript_chain(chain: object | None) -> list[dict[str, object]]:
    steps: list[dict[str, object]] = []
    current = chain
    while current is not None:
        current, step = current
        steps.append(step)
    steps.reverse()
    return steps


def _clientscript_solution_sort_key(solution: tuple[dict[int, str], object | None]) -> tuple[int, int, int, tuple[int, ...]]:
    mapping, chain = solution
    steps = _unpack_clientscript_chain(chain)
    switch_count = sum(1 for step in steps if step["immediate_kind"] == "switch")
    tribyte_count = sum(1 for step in steps if step["immediate_kind"] == "tribyte")
    return (
        switch_count,
        tribyte_count,
        len(mapping),
        tuple(int(step["raw_opcode"]) for step in steps[:16]),
    )


def _solve_clientscript_disassembly(
    opcode_data: bytes,
    instruction_count: int,
    *,
    possible_types: dict[int, set[str]] | None = None,
    max_states: int = DEFAULT_CLIENTSCRIPT_MAX_STATES,
    max_solutions: int = DEFAULT_CLIENTSCRIPT_MAX_SOLUTIONS,
) -> dict[str, object]:
    queue = deque([(0, instruction_count, {}, None)])
    visited: set[tuple[int, int, tuple[tuple[int, str], ...]]] = set()
    states_explored = 0
    solutions: list[tuple[dict[int, str], object | None]] = []

    while queue and states_explored < max_states and len(solutions) < max_solutions:
        offset, ops_left, mapping, chain = queue.popleft()
        states_explored += 1

        if ops_left == 0:
            if offset == len(opcode_data):
                solutions.append((mapping, chain))
            continue

        if offset + 2 > len(opcode_data):
            continue
        if len(opcode_data) - offset < ops_left * 3:
            continue

        raw_opcode = int.from_bytes(opcode_data[offset : offset + 2], "big")
        if raw_opcode in mapping:
            candidate_types = [mapping[raw_opcode]]
        else:
            allowed_types = possible_types.get(raw_opcode) if possible_types is not None else None
            candidate_types = [
                immediate_kind
                for immediate_kind in CLIENTSCRIPT_IMMEDIATE_TYPES
                if allowed_types is None or immediate_kind in allowed_types
            ]

        for immediate_kind in candidate_types:
            immediate = _read_clientscript_immediate(opcode_data, offset + 2, immediate_kind)
            if immediate is None:
                continue
            end_offset = int(immediate["end_offset"])
            if len(opcode_data) - end_offset < (ops_left - 1) * 3:
                continue

            new_mapping = mapping if raw_opcode in mapping else {**mapping, raw_opcode: immediate_kind}
            mapping_key = tuple(sorted((int(opcode), kind) for opcode, kind in new_mapping.items()))
            state_key = (end_offset, ops_left - 1, mapping_key)
            if state_key in visited:
                continue
            visited.add(state_key)

            step = {
                "offset": offset,
                "raw_opcode": raw_opcode,
                "raw_opcode_hex": f"0x{raw_opcode:04X}",
                "immediate_kind": immediate_kind,
                "immediate_value": immediate.get("immediate_value"),
                "switch_subtype": immediate.get("switch_subtype"),
            }
            queue.append((end_offset, ops_left - 1, new_mapping, (chain, step)))

    observed_types: dict[int, set[str]] = {}
    for mapping, _chain in solutions:
        for raw_opcode, immediate_kind in mapping.items():
            observed_types.setdefault(raw_opcode, set()).add(immediate_kind)

    selected_mapping: dict[int, str] | None = None
    selected_steps: list[dict[str, object]] | None = None
    if solutions:
        selected_mapping, selected_chain = min(solutions, key=_clientscript_solution_sort_key)
        selected_steps = _unpack_clientscript_chain(selected_chain)

    return {
        "states_explored": states_explored,
        "solution_count": len(solutions),
        "bailed": bool(queue),
        "selected_mapping": selected_mapping,
        "selected_steps": selected_steps,
        "observed_types": observed_types,
    }


def _format_clientscript_immediate_value(value: object) -> str:
    if value is None:
        return "null"
    if isinstance(value, str):
        return json.dumps(value)
    if isinstance(value, dict):
        if "hex" in value:
            return str(value["hex"])
        return json.dumps(value, sort_keys=True)
    return str(value)


def _render_clientscript_disassembly_text(
    layout: ClientscriptLayout,
    steps: list[dict[str, object]],
    *,
    mode: str,
    solution_count: int,
    bailed: bool,
) -> str:
    lines = [
        "# Reverser Workbench Clientscript Trace",
        f"byte0: {layout.byte0}",
        f"instruction_count: {layout.instruction_count}",
        f"opcode_data_bytes: {len(layout.opcode_data)}",
        f"mode: {mode}",
        f"solution_count: {solution_count}",
        f"bailed: {str(bailed).lower()}",
        "",
    ]
    for step in steps[:DEFAULT_CLIENTSCRIPT_TRACE_INSTRUCTIONS]:
        rendered_value = _format_clientscript_immediate_value(step.get("immediate_value"))
        subtype = step.get("switch_subtype")
        subtype_suffix = f" subtype={subtype}" if subtype is not None else ""
        semantic_label = step.get("semantic_label")
        semantic_suffix = f" semantic={semantic_label}" if isinstance(semantic_label, str) and semantic_label else ""
        expression_suffix_parts: list[str] = []
        branch_condition = step.get("branch_condition_expression")
        if isinstance(branch_condition, dict):
            expression_suffix_parts.append(f" cond={_format_clientscript_expression(branch_condition)}")
        switch_selector = step.get("switch_selector_expression")
        if isinstance(switch_selector, dict):
            expression_suffix_parts.append(f" selector={_format_clientscript_expression(switch_selector)}")
        produced_int = step.get("produced_int_expressions")
        if isinstance(produced_int, list) and produced_int:
            expression_suffix_parts.append(
                " push_int="
                + ",".join(_format_clientscript_expression(expression) for expression in produced_int[:2] if isinstance(expression, dict))
            )
        consumed_int = step.get("consumed_int_expressions")
        if isinstance(consumed_int, list) and consumed_int:
            expression_suffix_parts.append(
                " pop_int="
                + ",".join(_format_clientscript_expression(expression) for expression in consumed_int[:2] if isinstance(expression, dict))
            )
        expression_suffix = "".join(expression_suffix_parts)
        lines.append(
            f"{int(step['offset']):04d}: raw_op={step['raw_opcode_hex']} imm={step['immediate_kind']}{subtype_suffix} value={rendered_value}{semantic_suffix}{expression_suffix}"
        )
    if len(steps) > DEFAULT_CLIENTSCRIPT_TRACE_INSTRUCTIONS:
        lines.append("")
        lines.append(
            f"... truncated after {DEFAULT_CLIENTSCRIPT_TRACE_INSTRUCTIONS} instructions"
        )
    return "\n".join(lines) + "\n"


def _clientscript_constant_kind(switch_subtype: object) -> str | None:
    if switch_subtype == 0:
        return "int"
    if switch_subtype == 1:
        return "long"
    if switch_subtype == 2:
        return "string"
    return None


def _apply_clientscript_semantic_hints(
    step: dict[str, object],
    opcode_catalog: dict[int, dict[str, object]] | None,
) -> dict[str, object]:
    annotated = dict(step)
    raw_opcode = int(step["raw_opcode"])
    immediate_kind = str(step["immediate_kind"])

    if immediate_kind == "switch":
        constant_kind = _clientscript_constant_kind(step.get("switch_subtype"))
        if constant_kind is not None:
            annotated["constant_kind"] = constant_kind
            annotated["semantic_label"] = f"PUSH_CONST_{constant_kind.upper()}"
            annotated["semantic_family"] = "stack-constant"
            annotated["semantic_confidence"] = 0.98
    elif immediate_kind == "tribyte" and isinstance(step.get("immediate_value"), int):
        packed_value = int(step["immediate_value"])
        source_id = (packed_value >> 16) & 0xFF
        reference_id = packed_value & 0xFFFF
        annotated["reference_source_id"] = source_id
        annotated["reference_source_name"] = CLIENTSCRIPT_VAR_SOURCE_NAMES.get(source_id)
        annotated["reference_id"] = reference_id
        annotated["semantic_label"] = "VAR_REFERENCE_CANDIDATE"
        annotated["semantic_family"] = "state-reference"
        annotated["semantic_confidence"] = 0.7

    catalog_entry = opcode_catalog.get(raw_opcode) if opcode_catalog is not None else None
    if isinstance(catalog_entry, dict):
        mnemonic = catalog_entry.get("mnemonic")
        if isinstance(mnemonic, str) and mnemonic:
            annotated["semantic_label"] = mnemonic
        family = catalog_entry.get("family")
        if isinstance(family, str) and family:
            annotated["semantic_family"] = family
        confidence = catalog_entry.get("confidence")
        if isinstance(confidence, (int, float)):
            annotated["semantic_confidence"] = float(confidence)
        notes = catalog_entry.get("notes")
        if isinstance(notes, str) and notes:
            annotated["semantic_notes"] = notes
        control_flow_kind = catalog_entry.get("control_flow_kind")
        if isinstance(control_flow_kind, str) and control_flow_kind:
            annotated["control_flow_kind"] = control_flow_kind
        jump_base = catalog_entry.get("jump_base")
        if isinstance(jump_base, str) and jump_base:
            annotated["jump_base"] = jump_base
        jump_scale = catalog_entry.get("jump_scale")
        if isinstance(jump_scale, int):
            annotated["jump_scale"] = jump_scale
        candidate = catalog_entry.get("candidate_mnemonic")
        if isinstance(candidate, str) and candidate and "semantic_label" not in annotated:
            annotated["semantic_label"] = candidate
        if candidate == "TERMINATOR_CANDIDATE" and "control_flow_kind" not in annotated:
            annotated["control_flow_kind"] = "return-candidate"
        if "candidate_confidence" in catalog_entry and "semantic_confidence" not in annotated:
            candidate_confidence = catalog_entry.get("candidate_confidence")
            if isinstance(candidate_confidence, (int, float)):
                annotated["semantic_confidence"] = float(candidate_confidence)
    return annotated


def _make_clientscript_stack_effect(
    *,
    int_pops: int = 0,
    int_pushes: int = 0,
    string_pops: int = 0,
    string_pushes: int = 0,
    long_pops: int = 0,
    long_pushes: int = 0,
    confidence: float,
    notes: str,
) -> dict[str, object]:
    payload: dict[str, object] = {
        "confidence": round(float(confidence), 2),
        "notes": notes,
    }
    if int_pops:
        payload["int_pops"] = int(int_pops)
    if int_pushes:
        payload["int_pushes"] = int(int_pushes)
    if string_pops:
        payload["string_pops"] = int(string_pops)
    if string_pushes:
        payload["string_pushes"] = int(string_pushes)
    if long_pops:
        payload["long_pops"] = int(long_pops)
    if long_pushes:
        payload["long_pushes"] = int(long_pushes)
    return payload


def _classify_clientscript_expression_role(expression: object) -> str:
    if not isinstance(expression, dict):
        return "unknown"

    kind = str(expression.get("kind", "expression"))
    if kind == "widget-reference":
        return "widget"
    if kind == "state-reference":
        return "state-int"
    if kind == "int-literal":
        return "literal-int"
    if kind == "slot-reference":
        return "slot-int"
    if kind == "string-literal":
        return "string"
    if kind.endswith("-input"):
        return "string-input" if str(expression.get("stack_name", "")) == "string" else "symbolic-int"
    if kind.startswith("string-"):
        return "string"
    if kind.startswith("int-") or kind.endswith("-result"):
        return "symbolic-int"
    return "symbolic-int"


def _classify_clientscript_operand_signature(
    int_expressions: list[dict[str, object]],
    string_expressions: list[dict[str, object]],
) -> str:
    int_roles = [_classify_clientscript_expression_role(expression) for expression in int_expressions]
    string_roles = [_classify_clientscript_expression_role(expression) for expression in string_expressions]
    widget_count = sum(1 for role in int_roles if role == "widget")
    non_widget_roles = [role for role in int_roles if role != "widget"]

    if string_roles:
        if widget_count > 0 and non_widget_roles:
            return "widget+int+string"
        if widget_count > 0:
            return "widget+string"
        if int_roles:
            return "int+string"
        return "string-only"

    if widget_count >= 2 and not non_widget_roles:
        return "widget+widget"
    if widget_count == 1 and len(int_roles) == 1:
        return "widget-only"
    if widget_count == 1 and len(non_widget_roles) == 1:
        secondary_role = non_widget_roles[0]
        if secondary_role in {"state-int", "literal-int", "slot-int", "symbolic-int"}:
            return f"widget+{secondary_role}"
        return "widget+int"
    if widget_count > 0:
        return "widget+int"
    if int_roles:
        return "int-only"
    return "empty"


def _infer_clientscript_widget_operand_signature(entry: dict[str, object]) -> dict[str, object] | None:
    semantic_label = str(
        entry.get("candidate_mnemonic")
        or entry.get("semantic_label")
        or entry.get("mnemonic")
        or ""
    )
    if semantic_label != "WIDGET_MUTATOR_CANDIDATE":
        return None

    consumed_signature_counts: dict[str, int] = {}
    consumed_signature_sample = entry.get("consumed_operand_signature_sample")
    if isinstance(consumed_signature_sample, list):
        for sample in consumed_signature_sample:
            if not isinstance(sample, dict):
                continue
            signature = str(sample.get("signature", ""))
            if not signature:
                continue
            consumed_signature_counts[signature] = int(sample.get("count", 0))
    prefix_signature_counts: dict[str, int] = {}
    signature_sample = entry.get("prefix_operand_signature_sample")
    if isinstance(signature_sample, list):
        for sample in signature_sample:
            if not isinstance(sample, dict):
                continue
            signature = str(sample.get("signature", ""))
            if not signature:
                continue
            prefix_signature_counts[signature] = int(sample.get("count", 0))
    signature_counts: dict[str, int] = dict(prefix_signature_counts)
    for signature, count in consumed_signature_counts.items():
        signature_counts[signature] = int(signature_counts.get(signature, 0)) + int(count)

    widget_support = (
        int(entry.get("prefix_widget_literal_count", 0))
        + int(entry.get("previous_widget_literal_count", 0))
        + int(entry.get("prefix_widget_stack_script_count", 0))
    )
    if widget_support <= 0 and not signature_counts:
        return None

    dominant_signature = None
    if consumed_signature_counts:
        dominant_signature = max(consumed_signature_counts.items(), key=lambda item: (int(item[1]), str(item[0])))[0]
    elif signature_counts:
        dominant_signature = max(signature_counts.items(), key=lambda item: (int(item[1]), str(item[0])))[0]

    string_support = int(entry.get("prefix_string_operand_script_count", 0)) > 0 or any(
        signature in signature_counts for signature in {"widget+string", "widget+int+string"}
    )
    int_support = int(entry.get("prefix_secondary_int_script_count", 0)) > 0 or any(
        signature in signature_counts
        for signature in {
            "widget+int",
            "widget+widget",
            "widget+state-int",
            "widget+literal-int",
            "widget+slot-int",
            "widget+symbolic-int",
            "widget+int+string",
        }
    )

    min_int_inputs = 1 if widget_support > 0 or dominant_signature else 0
    if int_support:
        min_int_inputs += 1
    min_string_inputs = 1 if string_support else 0

    confidence = 0.58
    if dominant_signature in {"widget+int", "widget+widget", "widget+state-int", "widget+literal-int", "widget+slot-int", "widget+symbolic-int"}:
        confidence = 0.66
    elif dominant_signature == "widget+string":
        confidence = 0.69
    elif dominant_signature == "widget+int+string":
        confidence = 0.72
    elif dominant_signature == "widget-only":
        confidence = 0.6
    if consumed_signature_sample and dominant_signature in {
        "widget+widget",
        "widget+state-int",
        "widget+literal-int",
        "widget+slot-int",
        "widget+symbolic-int",
    }:
        confidence = max(confidence, 0.72)

    notes = "Widget-targeted payload likely consumes one packed widget id."
    if dominant_signature == "widget+int":
        notes = "Widget-targeted payload likely consumes a packed widget id plus one additional integer-like argument."
    elif dominant_signature == "widget+widget":
        notes = "Widget-targeted payload likely consumes a packed widget id plus a second widget-like handle or index argument."
    elif dominant_signature == "widget+state-int":
        notes = "Widget-targeted payload likely consumes a packed widget id plus one state-derived integer argument."
    elif dominant_signature == "widget+literal-int":
        notes = "Widget-targeted payload likely consumes a packed widget id plus one literal integer argument."
    elif dominant_signature == "widget+slot-int":
        notes = "Widget-targeted payload likely consumes a packed widget id plus one slot/local integer argument."
    elif dominant_signature == "widget+symbolic-int":
        notes = "Widget-targeted payload likely consumes a packed widget id plus one computed integer argument."
    elif dominant_signature == "widget+string":
        notes = "Widget-targeted payload likely consumes a packed widget id plus one string argument."
    elif dominant_signature == "widget+int+string":
        notes = "Widget-targeted payload likely consumes a packed widget id plus both integer-like and string arguments."
    elif int_support:
        notes = "Widget-targeted payload likely consumes a packed widget id plus one additional integer-like argument."
    elif string_support:
        notes = "Widget-targeted payload likely consumes a packed widget id plus one string argument."

    return {
        "target_kind": "widget",
        "signature": dominant_signature or "widget-only",
        "secondary_operand_kind": (
            dominant_signature.split("+", 1)[1]
            if isinstance(dominant_signature, str) and dominant_signature.startswith("widget+")
            else None
        ),
        "min_int_inputs": min_int_inputs,
        "min_string_inputs": min_string_inputs,
        "confidence": round(confidence, 2),
        "notes": notes,
    }


def _infer_clientscript_stack_effect(entry: dict[str, object]) -> dict[str, object] | None:
    semantic_label = str(
        entry.get("semantic_label")
        or entry.get("mnemonic")
        or entry.get("candidate_mnemonic")
        or ""
    )
    control_flow_kind = str(entry.get("control_flow_kind", ""))

    if semantic_label in {"PUSH_INT_CANDIDATE", "PUSH_INT_LITERAL"} or semantic_label.startswith("PUSH_CONST_INT"):
        return _make_clientscript_stack_effect(
            int_pushes=1,
            confidence=0.9 if semantic_label != "PUSH_INT_CANDIDATE" else 0.62,
            notes="Opcode appears to materialize an integer literal onto the integer stack.",
        )
    if semantic_label == "PUSH_SLOT_REFERENCE_CANDIDATE":
        return _make_clientscript_stack_effect(
            int_pushes=1,
            confidence=0.6,
            notes="Byte-sized slot operand looks like a local/argument load that pushes one integer value.",
        )
    if semantic_label.startswith("PUSH_CONST_STRING"):
        return _make_clientscript_stack_effect(
            string_pushes=1,
            confidence=0.95,
            notes="Opcode pushes one string constant onto the string stack.",
        )
    if semantic_label.startswith("PUSH_CONST_LONG"):
        return _make_clientscript_stack_effect(
            long_pushes=1,
            confidence=0.95,
            notes="Opcode pushes one long constant onto the long stack.",
        )
    if semantic_label == "VAR_REFERENCE_CANDIDATE":
        return _make_clientscript_stack_effect(
            int_pushes=1,
            confidence=0.52,
            notes="State-reference opcode likely materializes one integer-like value or handle on the stack.",
        )
    if semantic_label == "INT_STATE_GETTER_CANDIDATE":
        return _make_clientscript_stack_effect(
            int_pushes=1,
            confidence=0.58,
            notes="Contextual frontier behaves like an integer-producing state getter in switch or branch-heavy prefixes.",
        )
    if semantic_label == "WIDGET_MUTATOR_CANDIDATE":
        operand_signature = _infer_clientscript_widget_operand_signature(entry)
        if isinstance(operand_signature, dict):
            return _make_clientscript_stack_effect(
                int_pops=int(operand_signature.get("min_int_inputs", 0)),
                string_pops=int(operand_signature.get("min_string_inputs", 0)),
                confidence=float(operand_signature.get("confidence", 0.56)),
                notes=str(operand_signature.get("notes", "Widget-mutator candidate likely consumes a packed widget id.")),
            )
        return _make_clientscript_stack_effect(
            confidence=0.48,
            notes="Widget-mutator candidate appears side-effecting, but its exact stack arity still needs more solved prefixes.",
        )
    if semantic_label == "SWITCH_CASE_ACTION_CANDIDATE":
        previous_labels = entry.get("previous_semantic_label_sample")
        previous_push_int_count = int(entry.get("previous_push_int_count", 0))
        if isinstance(previous_labels, list):
            previous_label_names = {
                str(sample.get("label", ""))
                for sample in previous_labels
                if isinstance(sample, dict) and isinstance(sample.get("label"), str)
            }
        else:
            previous_label_names = set()
        if previous_push_int_count > 0 or previous_label_names & {
            "INT_STATE_GETTER_CANDIDATE",
            "PUSH_INT_CANDIDATE",
            "PUSH_INT_LITERAL",
        }:
            return _make_clientscript_stack_effect(
                int_pops=1,
                confidence=0.48,
                notes="Switch-case payload opcode likely consumes at least one prepared integer value or selector before applying its side effect.",
            )
        return _make_clientscript_stack_effect(
            confidence=0.42,
            notes="Switch-case payload opcode looks side-effecting, but its exact stack arity is still unresolved.",
        )
    if semantic_label == "SWITCH_DISPATCH_FRONTIER_CANDIDATE":
        return _make_clientscript_stack_effect(
            int_pops=1,
            confidence=0.66,
            notes="Switch dispatch typically consumes one selector from the integer stack.",
        )
    if semantic_label == "JUMP_OFFSET_FRONTIER_CANDIDATE" and control_flow_kind in {"branch", "branch-candidate"}:
        return _make_clientscript_stack_effect(
            int_pops=1,
            confidence=0.57,
            notes="Branch-like jump candidate likely consumes one integer condition from the stack.",
        )
    if semantic_label in {"RETURN", "TERMINATOR_CANDIDATE"} or control_flow_kind in {"return", "return-candidate", "throw"}:
        return _make_clientscript_stack_effect(
            confidence=0.9,
            notes="Terminal control-flow opcode does not require an additional stack delta estimate here.",
        )
    return None


def _make_clientscript_expression(kind: str, **payload: object) -> dict[str, object]:
    expression: dict[str, object] = {"kind": kind}
    for field, value in payload.items():
        if value is None:
            continue
        if isinstance(value, list) and not value:
            continue
        expression[field] = value
    return expression


def _decode_clientscript_widget_id(value: object) -> dict[str, int] | None:
    if not isinstance(value, int) or value <= 0xFFFF:
        return None
    if value < 0:
        return None

    interface_id = (int(value) >> 16) & 0xFFFF
    component_id = int(value) & 0xFFFF
    if interface_id <= 0 or interface_id > 2048:
        return None

    return {
        "packed_value": int(value),
        "interface_id": interface_id,
        "component_id": component_id,
    }


def _is_clientscript_widget_literal_step(step: dict[str, object]) -> bool:
    semantic_label = str(step.get("semantic_label", ""))
    if semantic_label not in {"PUSH_INT_CANDIDATE", "PUSH_INT_LITERAL"} and not semantic_label.startswith("PUSH_CONST_INT"):
        return False
    return _decode_clientscript_widget_id(step.get("immediate_value")) is not None


def _sample_clientscript_expression(expression: dict[str, object]) -> dict[str, object]:
    sampled: dict[str, object] = {"kind": str(expression.get("kind", "expression"))}
    for field in (
        "value",
        "packed_value",
        "interface_id",
        "component_id",
        "ordinal",
        "slot",
        "source_name",
        "reference_id",
        "raw_opcode_hex",
        "semantic_label",
        "stack_name",
    ):
        value = expression.get(field)
        if value is not None:
            sampled[field] = value
    inputs = expression.get("inputs")
    if isinstance(inputs, list) and inputs:
        sampled["inputs"] = [
            _sample_clientscript_expression(item)
            for item in inputs[:2]
            if isinstance(item, dict)
        ]
    return sampled


def _format_clientscript_expression(expression: object) -> str:
    if not isinstance(expression, dict):
        return str(expression)
    kind = str(expression.get("kind", "expression"))
    if kind == "int-literal":
        return str(expression.get("value"))
    if kind == "string-literal":
        return json.dumps(expression.get("value"))
    if kind == "long-literal":
        value = expression.get("value")
        if isinstance(value, dict) and "hex" in value:
            return str(value["hex"])
        return json.dumps(value, sort_keys=True)
    if kind == "widget-reference":
        return f"widget[{expression.get('interface_id')}:{expression.get('component_id')}]"
    if kind == "slot-reference":
        return f"slot[{expression.get('slot')}]"
    if kind == "state-reference":
        source_name = expression.get("source_name") or "state"
        reference_id = expression.get("reference_id")
        return f"{source_name}[{reference_id}]"
    if kind.endswith("-input"):
        stack_name = str(expression.get("stack_name", "stack"))
        return f"{stack_name}_input#{expression.get('ordinal')}"
    label = expression.get("semantic_label") or expression.get("raw_opcode_hex") or kind
    inputs = expression.get("inputs")
    if isinstance(inputs, list) and inputs:
        rendered_inputs = ", ".join(_format_clientscript_expression(item) for item in inputs[:3])
        return f"{label}({rendered_inputs})"
    return str(label)


def _infer_clientscript_produced_expression(
    step: dict[str, object],
    *,
    stack_name: str,
    consumed_expressions: list[dict[str, object]],
    produce_index: int,
) -> dict[str, object]:
    semantic_label = str(step.get("semantic_label", ""))
    raw_opcode_hex = str(step.get("raw_opcode_hex", "0x0000"))
    immediate_value = step.get("immediate_value")
    sampled_inputs = [
        _sample_clientscript_expression(expression)
        for expression in consumed_expressions[:3]
        if isinstance(expression, dict)
    ]

    if stack_name == "int":
        if semantic_label in {"PUSH_INT_LITERAL", "PUSH_INT_CANDIDATE"} and isinstance(immediate_value, int):
            widget_id = _decode_clientscript_widget_id(immediate_value)
            if widget_id is not None:
                return _make_clientscript_expression(
                    "widget-reference",
                    packed_value=widget_id["packed_value"],
                    interface_id=widget_id["interface_id"],
                    component_id=widget_id["component_id"],
                    raw_opcode_hex=raw_opcode_hex,
                    semantic_label=semantic_label or None,
                )
            return _make_clientscript_expression(
                "int-literal",
                value=int(immediate_value),
                raw_opcode_hex=raw_opcode_hex,
                semantic_label=semantic_label or None,
            )
        if semantic_label == "INT_STATE_GETTER_CANDIDATE" and isinstance(immediate_value, int):
            return _make_clientscript_expression(
                "state-reference",
                source_name="state",
                reference_id=int(immediate_value),
                raw_opcode_hex=raw_opcode_hex,
                semantic_label=semantic_label,
            )
        if semantic_label.startswith("PUSH_CONST_INT") and isinstance(immediate_value, int):
            widget_id = _decode_clientscript_widget_id(immediate_value)
            if widget_id is not None:
                return _make_clientscript_expression(
                    "widget-reference",
                    packed_value=widget_id["packed_value"],
                    interface_id=widget_id["interface_id"],
                    component_id=widget_id["component_id"],
                    raw_opcode_hex=raw_opcode_hex,
                    semantic_label=semantic_label,
                )
            return _make_clientscript_expression(
                "int-literal",
                value=int(immediate_value),
                raw_opcode_hex=raw_opcode_hex,
                semantic_label=semantic_label,
            )
        if semantic_label == "PUSH_SLOT_REFERENCE_CANDIDATE" and isinstance(immediate_value, int):
            return _make_clientscript_expression(
                "slot-reference",
                slot=int(immediate_value),
                raw_opcode_hex=raw_opcode_hex,
                semantic_label=semantic_label,
            )
        if semantic_label == "VAR_REFERENCE_CANDIDATE":
            return _make_clientscript_expression(
                "state-reference",
                source_name=step.get("reference_source_name"),
                reference_id=step.get("reference_id"),
                raw_opcode_hex=raw_opcode_hex,
                semantic_label=semantic_label,
            )
    if stack_name == "string" and isinstance(immediate_value, str):
        return _make_clientscript_expression(
            "string-literal",
            value=immediate_value,
            raw_opcode_hex=raw_opcode_hex,
            semantic_label=semantic_label or None,
        )
    if stack_name == "long" and immediate_value is not None:
        return _make_clientscript_expression(
            "long-literal",
            value=immediate_value,
            raw_opcode_hex=raw_opcode_hex,
            semantic_label=semantic_label or None,
        )
    return _make_clientscript_expression(
        f"{stack_name}-result",
        raw_opcode_hex=raw_opcode_hex,
        semantic_label=semantic_label or None,
        immediate_value=immediate_value if immediate_value is not None else None,
        result_index=produce_index if produce_index else None,
        inputs=sampled_inputs,
    )


def _annotate_clientscript_stack_effects(
    steps: list[dict[str, object]],
) -> tuple[list[dict[str, object]], dict[str, object]]:
    annotated_steps: list[dict[str, object]] = []
    depths = {"int": 0, "string": 0, "long": 0}
    required_inputs = {"int": 0, "string": 0, "long": 0}
    expression_stacks: dict[str, list[dict[str, object]]] = {"int": [], "string": [], "long": []}
    known_effect_instruction_count = 0
    unknown_effect_instruction_count = 0

    for step in steps:
        annotated = dict(step)
        stack_effect = _infer_clientscript_stack_effect(annotated)
        if stack_effect is None:
            unknown_effect_instruction_count += 1
            annotated_steps.append(annotated)
            continue

        known_effect_instruction_count += 1
        annotated["stack_effect_candidate"] = dict(stack_effect)
        for stack_name in ("int", "string", "long"):
            pops = int(stack_effect.get(f"{stack_name}_pops", 0))
            pushes = int(stack_effect.get(f"{stack_name}_pushes", 0))
            before_depth = int(depths[stack_name])
            consumed_expressions: list[dict[str, object]] = []
            for _ in range(pops):
                if expression_stacks[stack_name]:
                    consumed_expressions.append(expression_stacks[stack_name].pop())
                else:
                    required_inputs[stack_name] += 1
                    consumed_expressions.append(
                        _make_clientscript_expression(
                            f"{stack_name}-input",
                            ordinal=int(required_inputs[stack_name]),
                            stack_name=stack_name,
                        )
                    )
            if before_depth < pops:
                before_depth = pops
            after_depth = before_depth - pops + pushes
            annotated[f"{stack_name}_stack_depth_before"] = before_depth
            annotated[f"{stack_name}_stack_depth_after"] = after_depth
            if consumed_expressions:
                annotated[f"consumed_{stack_name}_expressions"] = consumed_expressions
            depths[stack_name] = after_depth
            produced_expressions: list[dict[str, object]] = []
            for produce_index in range(pushes):
                produced_expression = _infer_clientscript_produced_expression(
                    annotated,
                    stack_name=stack_name,
                    consumed_expressions=consumed_expressions,
                    produce_index=produce_index,
                )
                expression_stacks[stack_name].append(produced_expression)
                produced_expressions.append(produced_expression)
            if produced_expressions:
                annotated[f"produced_{stack_name}_expressions"] = produced_expressions
        if annotated.get("consumed_int_expressions"):
            semantic_label = str(annotated.get("semantic_label", ""))
            control_flow_kind = str(annotated.get("control_flow_kind", ""))
            if semantic_label == "SWITCH_DISPATCH_FRONTIER_CANDIDATE":
                annotated["switch_selector_expression"] = annotated["consumed_int_expressions"][0]
            elif control_flow_kind in {"branch", "branch-candidate", "jump", "jump-candidate"}:
                annotated["branch_condition_expression"] = annotated["consumed_int_expressions"][0]
        annotated_steps.append(annotated)

    summary = {
        "known_effect_instruction_count": known_effect_instruction_count,
        "unknown_effect_instruction_count": unknown_effect_instruction_count,
        "minimum_required_inputs": {
            f"{stack_name}_stack": int(count)
            for stack_name, count in required_inputs.items()
            if int(count) > 0
        },
        "final_depths": {
            f"{stack_name}_stack": int(depth)
            for stack_name, depth in depths.items()
        },
        "final_expression_stacks": {
            f"{stack_name}_stack": [
                _sample_clientscript_expression(expression)
                for expression in expression_stacks[stack_name][-4:]
            ]
            for stack_name in ("int", "string", "long")
            if expression_stacks[stack_name]
        },
    }
    return annotated_steps, summary


def _summarize_clientscript_prefix_stack_state(
    instruction_steps: list[dict[str, object]],
) -> dict[str, object]:
    if not instruction_steps:
        return {}

    _annotated_steps, stack_tracking = _annotate_clientscript_stack_effects([dict(step) for step in instruction_steps])
    final_expression_stacks = stack_tracking.get("final_expression_stacks")
    if not isinstance(final_expression_stacks, dict):
        return {}

    int_stack = final_expression_stacks.get("int_stack")
    string_stack = final_expression_stacks.get("string_stack")
    if not isinstance(int_stack, list):
        int_stack = []
    if not isinstance(string_stack, list):
        string_stack = []

    int_kind_counts: dict[str, int] = {}
    for expression in int_stack:
        if not isinstance(expression, dict):
            continue
        kind = str(expression.get("kind", "expression"))
        int_kind_counts[kind] = int(int_kind_counts.get(kind, 0)) + 1

    widget_count = int(int_kind_counts.get("widget-reference", 0))
    state_count = int(int_kind_counts.get("state-reference", 0))
    int_literal_count = int(int_kind_counts.get("int-literal", 0))
    symbolic_int_count = max(len(int_stack) - widget_count - state_count - int_literal_count, 0)
    string_count = len(string_stack)

    if widget_count > 0 and string_count > 0 and (state_count > 0 or int_literal_count > 0 or symbolic_int_count > 0 or widget_count > 1):
        operand_signature = "widget+int+string"
    elif widget_count > 0 and string_count > 0:
        operand_signature = "widget+string"
    elif widget_count > 1 and state_count == 0 and int_literal_count == 0 and symbolic_int_count == 0:
        operand_signature = "widget+widget"
    elif widget_count > 0 and (state_count > 0 or int_literal_count > 0 or symbolic_int_count > 0 or widget_count > 1):
        operand_signature = "widget+int"
    elif widget_count > 0:
        operand_signature = "widget-only"
    elif string_count > 0:
        operand_signature = "string-only"
    elif int_stack:
        operand_signature = "int-only"
    else:
        operand_signature = "empty"

    return {
        "prefix_int_stack_expression_count": len(int_stack),
        "prefix_string_stack_count": string_count,
        "prefix_widget_stack_count": widget_count,
        "prefix_state_stack_count": state_count,
        "prefix_int_literal_stack_count": int_literal_count,
        "prefix_symbolic_int_stack_count": symbolic_int_count,
        "prefix_operand_signature": operand_signature,
        "prefix_int_stack_sample": int_stack[-4:],
        "prefix_string_stack_sample": string_stack[-4:],
    }


def _summarize_clientscript_consumed_operand_window(entry: dict[str, object]) -> dict[str, object]:
    stack_effect = entry.get("stack_effect_candidate")
    script_samples = entry.get("script_samples")
    if not isinstance(stack_effect, dict) or not isinstance(script_samples, list):
        return {}

    int_pops = int(stack_effect.get("int_pops", 0))
    string_pops = int(stack_effect.get("string_pops", 0))
    if int_pops <= 0 and string_pops <= 0:
        return {}

    signature_counts: dict[str, int] = {}
    secondary_kind_counts: dict[str, int] = {}
    secondary_literal_counts: dict[int, int] = {}
    operand_samples: list[dict[str, object]] = []

    for sample in script_samples:
        if not isinstance(sample, dict):
            continue
        int_stack_sample = sample.get("prefix_int_stack_sample")
        string_stack_sample = sample.get("prefix_string_stack_sample")
        if not isinstance(int_stack_sample, list):
            int_stack_sample = []
        if not isinstance(string_stack_sample, list):
            string_stack_sample = []

        consumed_int = int_stack_sample[-int_pops:] if int_pops > 0 else []
        consumed_string = string_stack_sample[-string_pops:] if string_pops > 0 else []
        if int_pops > 0 and not consumed_int:
            continue
        if string_pops > 0 and not consumed_string:
            continue

        signature = _classify_clientscript_operand_signature(
            [expression for expression in consumed_int if isinstance(expression, dict)],
            [expression for expression in consumed_string if isinstance(expression, dict)],
        )
        signature_counts[signature] = int(signature_counts.get(signature, 0)) + 1

        int_roles = [_classify_clientscript_expression_role(expression) for expression in consumed_int if isinstance(expression, dict)]
        if int_pops >= 2 and int_roles:
            non_widget_roles = [role for role in int_roles if role != "widget"]
            secondary_kind = non_widget_roles[-1] if non_widget_roles else ("widget" if int_roles.count("widget") >= 2 else int_roles[-1])
            secondary_kind_counts[secondary_kind] = int(secondary_kind_counts.get(secondary_kind, 0)) + 1
            if secondary_kind == "literal-int":
                for expression in reversed(consumed_int):
                    if not isinstance(expression, dict):
                        continue
                    if _classify_clientscript_expression_role(expression) != "literal-int":
                        continue
                    literal_value = expression.get("value")
                    if isinstance(literal_value, int):
                        secondary_literal_counts[literal_value] = int(secondary_literal_counts.get(literal_value, 0)) + 1
                    break

        if len(operand_samples) < 6:
            operand_samples.append(
                {
                    "key": sample.get("key"),
                    "signature": signature,
                    "int_operands": [expression for expression in consumed_int if isinstance(expression, dict)],
                    "string_operands": [expression for expression in consumed_string if isinstance(expression, dict)],
                }
            )

    payload: dict[str, object] = {}
    if signature_counts:
        payload["consumed_operand_signature_sample"] = [
            {
                "signature": signature,
                "count": count,
            }
            for signature, count in sorted(
                signature_counts.items(),
                key=lambda item: (-int(item[1]), str(item[0])),
            )[:6]
        ]
    if secondary_kind_counts:
        payload["consumed_secondary_int_kind_sample"] = [
            {
                "kind": kind,
                "count": count,
            }
            for kind, count in sorted(
                secondary_kind_counts.items(),
                key=lambda item: (-int(item[1]), str(item[0])),
            )[:6]
        ]
    if secondary_literal_counts:
        payload["consumed_secondary_int_literal_sample"] = [
            {
                "value": value,
                "count": count,
            }
            for value, count in sorted(
                secondary_literal_counts.items(),
                key=lambda item: (-int(item[1]), int(item[0])),
            )[:8]
        ]
        boolean_like_count = sum(
            count for value, count in secondary_literal_counts.items() if int(value) in {0, 1}
        )
        total_literal_count = sum(int(count) for count in secondary_literal_counts.values())
        if total_literal_count > 0:
            payload["consumed_secondary_literal_boolean_ratio"] = round(boolean_like_count / total_literal_count, 2)
    if operand_samples:
        payload["consumed_operand_samples"] = operand_samples
    return payload


def _escape_dot_label(text: str) -> str:
    return text.replace("\\", "\\\\").replace('"', '\\"')


def _render_clientscript_cfg_dot(graph: dict[str, object]) -> str:
    lines = [
        "digraph clientscript_cfg {",
        '  rankdir="TB";',
        '  node [shape=box, fontname="Consolas", fontsize=10];',
        '  edge [fontname="Consolas", fontsize=9];',
    ]
    for block in graph["blocks"]:
        block_id = str(block["block_id"])
        label = _escape_dot_label(str(block["label"]))
        entry_suffix = ", penwidth=2" if block.get("is_entry") else ""
        terminal_suffix = ', style="rounded,filled", fillcolor="#1f1f1f"' if block.get("is_terminal") else ""
        lines.append(f'  "{block_id}" [label="{label}"{entry_suffix}{terminal_suffix}];')
    for edge in graph["edges"]:
        edge_label = _escape_dot_label(str(edge["kind"]))
        lines.append(
            f'  "{edge["source"]}" -> "{edge["target"]}" [label="{edge_label}"];'
        )
    lines.append("}")
    return "\n".join(lines) + "\n"


def _render_clientscript_cfg_json(graph: dict[str, object]) -> str:
    return json.dumps(graph, indent=2) + "\n"


def _trace_clientscript_locked_prefix(
    layout: ClientscriptLayout,
    raw_opcode_types: dict[int, str],
    *,
    raw_opcode_catalog: dict[int, dict[str, object]] | None = None,
) -> dict[str, object] | None:
    if not raw_opcode_types:
        return None

    steps: list[dict[str, object]] = []
    offset = 0
    decoded_instruction_count = 0

    while decoded_instruction_count < layout.instruction_count:
        if offset + 2 > len(layout.opcode_data):
            return {
                "status": "frontier",
                "frontier_reason": "truncated-opcode-data",
                "frontier_offset": offset,
                "frontier_instruction_index": decoded_instruction_count,
                "decoded_instruction_count": decoded_instruction_count,
                "remaining_opcode_bytes": max(len(layout.opcode_data) - offset, 0),
                "instruction_offsets": [int(step["offset"]) for step in steps],
                "instruction_steps": steps,
                "last_instruction": steps[-1] if steps else None,
                "instruction_sample": steps[:32],
            }

        raw_opcode = int.from_bytes(layout.opcode_data[offset : offset + 2], "big")
        immediate_kind = raw_opcode_types.get(raw_opcode)
        if immediate_kind is None and raw_opcode_catalog is not None:
            catalog_entry = raw_opcode_catalog.get(raw_opcode)
            if isinstance(catalog_entry, dict):
                catalog_immediate_kind = catalog_entry.get("immediate_kind", catalog_entry.get("expected_immediate_kind"))
                if isinstance(catalog_immediate_kind, str) and catalog_immediate_kind in CLIENTSCRIPT_IMMEDIATE_TYPES:
                    immediate_kind = catalog_immediate_kind
        previous_step = steps[-1] if steps else None

        if immediate_kind is None:
            return {
                "status": "frontier",
                "frontier_reason": "unknown-locked-opcode",
                "frontier_offset": offset,
                "frontier_instruction_index": decoded_instruction_count,
                "frontier_raw_opcode": raw_opcode,
                "frontier_raw_opcode_hex": f"0x{raw_opcode:04X}",
                "decoded_instruction_count": decoded_instruction_count,
                "remaining_opcode_bytes": len(layout.opcode_data) - offset,
                "instruction_offsets": [int(step["offset"]) for step in steps],
                "instruction_steps": steps,
                "last_instruction": steps[-1] if steps else None,
                "instruction_sample": steps[:32],
                **(
                    {
                        "previous_raw_opcode": int(previous_step["raw_opcode"]),
                        "previous_raw_opcode_hex": str(previous_step["raw_opcode_hex"]),
                        "previous_immediate_kind": str(previous_step["immediate_kind"]),
                    }
                    if previous_step is not None
                    else {}
                ),
            }

        immediate = _read_clientscript_immediate(layout.opcode_data, offset + 2, immediate_kind)
        if immediate is None:
            return {
                "status": "frontier",
                "frontier_reason": "invalid-locked-immediate",
                "frontier_offset": offset,
                "frontier_instruction_index": decoded_instruction_count,
                "frontier_raw_opcode": raw_opcode,
                "frontier_raw_opcode_hex": f"0x{raw_opcode:04X}",
                "frontier_immediate_kind": immediate_kind,
                "decoded_instruction_count": decoded_instruction_count,
                "remaining_opcode_bytes": len(layout.opcode_data) - offset,
                "instruction_offsets": [int(step["offset"]) for step in steps],
                "instruction_steps": steps,
                "last_instruction": steps[-1] if steps else None,
                "instruction_sample": steps[:32],
                **(
                    {
                        "previous_raw_opcode": int(previous_step["raw_opcode"]),
                        "previous_raw_opcode_hex": str(previous_step["raw_opcode_hex"]),
                        "previous_immediate_kind": str(previous_step["immediate_kind"]),
                    }
                    if previous_step is not None
                    else {}
                ),
            }

        step = {
            "offset": offset,
            "raw_opcode": raw_opcode,
            "raw_opcode_hex": f"0x{raw_opcode:04X}",
            "immediate_kind": immediate_kind,
            "immediate_value": immediate.get("immediate_value"),
            "switch_subtype": immediate.get("switch_subtype"),
            "end_offset": int(immediate["end_offset"]),
        }
        steps.append(_apply_clientscript_semantic_hints(step, raw_opcode_catalog))
        offset = int(immediate["end_offset"])
        decoded_instruction_count += 1

    status = "complete" if offset == len(layout.opcode_data) else "extra-bytes"
    return {
        "status": status,
        "decoded_instruction_count": decoded_instruction_count,
        "remaining_opcode_bytes": max(len(layout.opcode_data) - offset, 0),
        "instruction_offsets": [int(step["offset"]) for step in steps],
        "instruction_steps": steps,
        "last_instruction": steps[-1] if steps else None,
        "instruction_sample": steps[:32],
    }


def _build_clientscript_switch_skeleton_cfg(layout: ClientscriptLayout) -> dict[str, object] | None:
    if not layout.switch_tables:
        return None

    dispatch_block_id = "block_dispatch"
    blocks: list[dict[str, object]] = [
        {
            "block_id": dispatch_block_id,
            "start_instruction_index": 0,
            "end_instruction_index": 0,
            "instruction_index_span": [0, 0],
            "label": f"dispatch\\ninstructions=0..?\\nswitch_tables={layout.switch_table_count}",
            "is_entry": True,
            "is_terminal": False,
            "is_reachable": True,
        }
    ]
    edges: list[dict[str, object]] = []
    seen_targets: set[int] = set()
    unresolved_targets: list[dict[str, object]] = []

    for table in layout.switch_tables:
        table_index = int(table["table_index"])
        case_entries = list(table.get("cases", []))
        valid_targets = sorted(
            {
                int(case["jump_offset"])
                for case in case_entries
                if isinstance(case.get("jump_offset"), int)
                and 0 <= int(case["jump_offset"]) < layout.instruction_count
            }
        )
        for case in case_entries:
            jump_offset = case.get("jump_offset")
            if not isinstance(jump_offset, int) or not (0 <= jump_offset < layout.instruction_count):
                unresolved_targets.append(
                    {
                        "table_index": table_index,
                        "case_value": case.get("value"),
                        "target_instruction_index": jump_offset,
                    }
                )

        for target_index, target_instruction_index in enumerate(valid_targets):
            if target_instruction_index in seen_targets:
                continue
            seen_targets.add(target_instruction_index)
            next_target = (
                valid_targets[target_index + 1]
                if target_index + 1 < len(valid_targets)
                else layout.instruction_count
            )
            block_id = f"block_i{target_instruction_index:04d}"
            blocks.append(
                {
                    "block_id": block_id,
                    "start_instruction_index": target_instruction_index,
                    "end_instruction_index": max(target_instruction_index, next_target - 1),
                    "instruction_index_span": [target_instruction_index, max(target_instruction_index, next_target - 1)],
                    "label": (
                        f"instr {target_instruction_index}"
                        if next_target == target_instruction_index + 1
                        else f"instr {target_instruction_index}..{max(target_instruction_index, next_target - 1)}"
                    ),
                    "is_entry": False,
                    "is_terminal": True,
                    "is_reachable": True,
                }
            )

        for case in case_entries:
            jump_offset = case.get("jump_offset")
            if not isinstance(jump_offset, int) or jump_offset not in seen_targets:
                continue
            edges.append(
                {
                    "source": dispatch_block_id,
                    "target": f"block_i{jump_offset:04d}",
                    "kind": f"switch[{table_index}]={case.get('value')}",
                }
            )

    if len(blocks) == 1:
        return None

    return {
        "kind": "clientscript-switch-skeleton-cfg",
        "entry_block": dispatch_block_id,
        "instruction_count": layout.instruction_count,
        "switch_table_count": layout.switch_table_count,
        "switch_case_count": layout.switch_case_count,
        "block_count": len(blocks),
        "edge_count": len(edges),
        "terminal_block_count": sum(1 for block in blocks if block["is_terminal"]),
        "unresolved_target_count": len(unresolved_targets),
        "blocks": blocks,
        "edges": edges,
        "unresolved_targets": unresolved_targets[:32],
    }


def _resolve_clientscript_jump_target(
    step: dict[str, object],
    *,
    next_offset: int | None,
) -> int | None:
    immediate_value = step.get("immediate_value")
    if not isinstance(immediate_value, int):
        return None
    jump_scale = int(step.get("jump_scale", 1))
    jump_base = step.get("jump_base", "next_offset")
    if jump_base == "current_offset":
        return int(step["offset"]) + immediate_value * jump_scale
    if jump_base == "absolute":
        return immediate_value * jump_scale
    if next_offset is not None:
        return next_offset + immediate_value * jump_scale
    return None


def _build_clientscript_cfg(
    layout: ClientscriptLayout,
    steps: list[dict[str, object]],
) -> dict[str, object] | None:
    if not steps:
        return None

    instruction_offsets = [int(step["offset"]) for step in steps]
    instruction_offset_set = set(instruction_offsets)
    instruction_by_offset = {int(step["offset"]): step for step in steps}
    instruction_edges: list[dict[str, object]] = []
    leaders = {instruction_offsets[0]}
    unresolved_targets: list[dict[str, object]] = []

    for index, step in enumerate(steps):
        current_offset = int(step["offset"])
        next_offset = instruction_offsets[index + 1] if index + 1 < len(steps) else None
        control_flow_kind = str(step.get("control_flow_kind", "fallthrough"))
        if control_flow_kind == "jump-candidate":
            control_flow_kind = "branch"
        elif control_flow_kind == "branch-candidate":
            control_flow_kind = "branch"
        is_terminal = control_flow_kind in {"return", "return-candidate", "throw"}

        if next_offset is not None and (is_terminal or control_flow_kind == "jump"):
            leaders.add(next_offset)

        if control_flow_kind == "jump":
            target_offset = _resolve_clientscript_jump_target(step, next_offset=next_offset)
            if target_offset is not None and target_offset in instruction_offset_set:
                leaders.add(target_offset)
                instruction_edges.append(
                    {
                        "source_offset": current_offset,
                        "target_offset": target_offset,
                        "kind": "jump",
                    }
                )
            elif target_offset is not None:
                unresolved_targets.append(
                    {
                        "source_offset": current_offset,
                        "target_offset": target_offset,
                        "kind": "jump",
                    }
                )
        elif control_flow_kind == "branch":
            target_offset = _resolve_clientscript_jump_target(step, next_offset=next_offset)
            if next_offset is not None:
                leaders.add(next_offset)
                instruction_edges.append(
                    {
                        "source_offset": current_offset,
                        "target_offset": next_offset,
                        "kind": "fallthrough",
                    }
                )
            if target_offset is not None and target_offset in instruction_offset_set:
                leaders.add(target_offset)
                instruction_edges.append(
                    {
                        "source_offset": current_offset,
                        "target_offset": target_offset,
                        "kind": "branch",
                    }
                )
            elif target_offset is not None:
                unresolved_targets.append(
                    {
                        "source_offset": current_offset,
                        "target_offset": target_offset,
                        "kind": "branch",
                    }
                )
        elif not is_terminal and next_offset is not None:
            instruction_edges.append(
                {
                    "source_offset": current_offset,
                    "target_offset": next_offset,
                    "kind": "fallthrough",
                }
            )

    sorted_leaders = sorted(leaders)
    blocks: list[dict[str, object]] = []
    instruction_block_ids: dict[int, str] = {}
    for leader_index, leader in enumerate(sorted_leaders):
        end_offset = (
            sorted_leaders[leader_index + 1]
            if leader_index + 1 < len(sorted_leaders)
            else len(layout.opcode_data)
        )
        block_steps = [
            instruction_by_offset[offset]
            for offset in instruction_offsets
            if leader <= offset < end_offset
        ]
        if not block_steps:
            continue
        block_id = f"block_{leader:04d}"
        for step in block_steps:
            instruction_block_ids[int(step["offset"])] = block_id

        label_lines = []
        for step in block_steps:
            rendered_value = _format_clientscript_immediate_value(step.get("immediate_value"))
            semantic_label = step.get("semantic_label")
            semantic_suffix = f" [{semantic_label}]" if isinstance(semantic_label, str) and semantic_label else ""
            label_lines.append(
                f"{int(step['offset']):04d}: {step['raw_opcode_hex']} {step['immediate_kind']} {rendered_value}{semantic_suffix}"
            )
        blocks.append(
            {
                "block_id": block_id,
                "start_offset": leader,
                "end_offset": int(block_steps[-1]["offset"]),
                "instruction_offsets": [int(step["offset"]) for step in block_steps],
                "label": "\\n".join(label_lines),
                "is_entry": leader == instruction_offsets[0],
            }
        )

    block_edges: list[dict[str, object]] = []
    seen_edges: set[tuple[str, str, str]] = set()
    for edge in instruction_edges:
        source_block_id = instruction_block_ids.get(int(edge["source_offset"]))
        target_block_id = instruction_block_ids.get(int(edge["target_offset"]))
        if source_block_id is None or target_block_id is None:
            continue
        if source_block_id == target_block_id and str(edge["kind"]) == "fallthrough":
            continue
        edge_key = (source_block_id, target_block_id, str(edge["kind"]))
        if edge_key in seen_edges:
            continue
        seen_edges.add(edge_key)
        block_edges.append(
            {
                "source": source_block_id,
                "target": target_block_id,
                "kind": edge["kind"],
            }
        )

    target_block_ids = {str(edge["target"]) for edge in block_edges}
    for block in blocks:
        outgoing = [edge for edge in block_edges if edge["source"] == block["block_id"]]
        block["is_terminal"] = not outgoing
        block["is_reachable"] = block["is_entry"] or block["block_id"] in target_block_ids

    return {
        "kind": "clientscript-control-flow-graph",
        "entry_block": blocks[0]["block_id"] if blocks else None,
        "instruction_count": len(steps),
        "block_count": len(blocks),
        "edge_count": len(block_edges),
        "terminal_block_count": sum(1 for block in blocks if block["is_terminal"]),
        "unresolved_target_count": len(unresolved_targets),
        "blocks": blocks,
        "edges": block_edges,
        "unresolved_targets": unresolved_targets[:16],
    }


def _decode_clientscript_metadata(
    data: bytes,
    *,
    raw_opcode_types: dict[int, str] | None = None,
    raw_opcode_catalog: dict[int, dict[str, object]] | None = None,
) -> dict[str, object]:
    layout = _parse_clientscript_layout(data)
    profile = _clientscript_profile_from_layout(layout)
    possible_types: dict[int, set[str]] = {}
    if raw_opcode_types:
        possible_types.update(
            {
                int(raw_opcode): {str(immediate_kind)}
                for raw_opcode, immediate_kind in raw_opcode_types.items()
            }
        )
    if raw_opcode_catalog:
        for raw_opcode, entry in raw_opcode_catalog.items():
            if not isinstance(entry, dict):
                continue
            immediate_kind = entry.get("immediate_kind", entry.get("expected_immediate_kind"))
            if (
                isinstance(immediate_kind, str)
                and immediate_kind in CLIENTSCRIPT_IMMEDIATE_TYPES
                and int(raw_opcode) not in possible_types
            ):
                possible_types[int(raw_opcode)] = {immediate_kind}
    disassembly = _solve_clientscript_disassembly(
        layout.opcode_data,
        layout.instruction_count,
        possible_types=possible_types or None,
    )
    mode = "cache-calibrated" if raw_opcode_types else "local-heuristic"
    profile["disassembly_mode"] = mode
    profile["disassembly_solution_count"] = disassembly["solution_count"]
    profile["disassembly_state_count"] = disassembly["states_explored"]
    profile["disassembly_bailed"] = disassembly["bailed"]
    if raw_opcode_types:
        profile["locked_raw_opcode_type_count"] = len(raw_opcode_types)

    selected_steps = disassembly.get("selected_steps")
    selected_mapping = disassembly.get("selected_mapping")
    if selected_steps and selected_mapping:
        annotated_steps = [
            _apply_clientscript_semantic_hints(step, raw_opcode_catalog)
            for step in selected_steps
        ]
        annotated_steps, stack_tracking = _annotate_clientscript_stack_effects(annotated_steps)
        immediate_kind_counts: dict[str, int] = {}
        for step in annotated_steps:
            immediate_kind = str(step["immediate_kind"])
            immediate_kind_counts[immediate_kind] = immediate_kind_counts.get(immediate_kind, 0) + 1

        profile["kind"] = "clientscript-disassembly"
        profile["parser_status"] = (
            "parsed"
            if disassembly["solution_count"] == 1 and not disassembly["bailed"]
            else "profiled"
        )
        profile["distinct_raw_opcode_count"] = len(selected_mapping)
        profile["immediate_kind_counts"] = immediate_kind_counts
        profile["raw_opcode_types_sample"] = [
            {
                "raw_opcode": raw_opcode,
                "raw_opcode_hex": f"0x{raw_opcode:04X}",
                "immediate_kind": immediate_kind,
                **(
                    {
                        "semantic_label": raw_opcode_catalog[raw_opcode].get("mnemonic")
                        or raw_opcode_catalog[raw_opcode].get("candidate_mnemonic"),
                        "semantic_family": raw_opcode_catalog[raw_opcode].get("family"),
                        "stack_effect_candidate": raw_opcode_catalog[raw_opcode].get("stack_effect_candidate"),
                    }
                    if raw_opcode_catalog is not None and raw_opcode in raw_opcode_catalog
                    else {}
                ),
            }
            for raw_opcode, immediate_kind in sorted(selected_mapping.items())[:24]
        ]
        profile["semantic_instruction_count"] = sum(
            1 for step in annotated_steps if isinstance(step.get("semantic_label"), str)
        )
        profile["stack_tracking"] = stack_tracking
        profile["instruction_sample"] = annotated_steps[:32]
        profile["_disassembly_text"] = _render_clientscript_disassembly_text(
            layout,
            annotated_steps,
            mode=mode,
            solution_count=int(disassembly["solution_count"]),
            bailed=bool(disassembly["bailed"]),
        )
        cfg = _build_clientscript_cfg(layout, annotated_steps)
        if cfg is not None:
            profile["cfg_mode"] = "override-aware"
            profile["cfg_block_count"] = cfg["block_count"]
            profile["cfg_edge_count"] = cfg["edge_count"]
            profile["cfg_terminal_block_count"] = cfg["terminal_block_count"]
            profile["cfg_unresolved_target_count"] = cfg["unresolved_target_count"]
            profile["cfg_entry_block"] = cfg["entry_block"]
            profile["cfg_blocks_sample"] = cfg["blocks"][:8]
            profile["cfg_edges_sample"] = cfg["edges"][:12]
            profile["_cfg_dot_text"] = _render_clientscript_cfg_dot(cfg)
            profile["_cfg_json_text"] = _render_clientscript_cfg_json(cfg)
    if not (selected_steps and selected_mapping) and raw_opcode_types:
        prefix_trace = _trace_clientscript_locked_prefix(
            layout,
            raw_opcode_types,
            raw_opcode_catalog=raw_opcode_catalog,
        )
        if prefix_trace is not None and prefix_trace.get("status") == "frontier":
            profile["frontier_mode"] = "locked-prefix"
            profile["frontier_reason"] = prefix_trace["frontier_reason"]
            profile["frontier_offset"] = prefix_trace["frontier_offset"]
            profile["frontier_instruction_index"] = prefix_trace["frontier_instruction_index"]
            profile["frontier_prefix_instruction_count"] = prefix_trace["decoded_instruction_count"]
            profile["frontier_remaining_opcode_bytes"] = prefix_trace["remaining_opcode_bytes"]
            frontier_opcode = prefix_trace.get("frontier_raw_opcode")
            if isinstance(frontier_opcode, int):
                profile["frontier_raw_opcode"] = frontier_opcode
                profile["frontier_raw_opcode_hex"] = prefix_trace["frontier_raw_opcode_hex"]
            frontier_immediate_kind = prefix_trace.get("frontier_immediate_kind")
            if isinstance(frontier_immediate_kind, str):
                profile["frontier_immediate_kind"] = frontier_immediate_kind
            previous_raw_opcode = prefix_trace.get("previous_raw_opcode")
            if isinstance(previous_raw_opcode, int):
                profile["frontier_previous_raw_opcode"] = previous_raw_opcode
                profile["frontier_previous_raw_opcode_hex"] = prefix_trace["previous_raw_opcode_hex"]
                profile["frontier_previous_immediate_kind"] = prefix_trace["previous_immediate_kind"]
            frontier_entry = (
                raw_opcode_catalog.get(frontier_opcode)
                if isinstance(frontier_opcode, int) and raw_opcode_catalog is not None
                else None
            )
            if isinstance(frontier_entry, dict):
                frontier_label = frontier_entry.get("mnemonic") or frontier_entry.get("candidate_mnemonic")
                if isinstance(frontier_label, str) and frontier_label:
                    profile["frontier_candidate_label"] = frontier_label
                frontier_family = frontier_entry.get("family")
                if isinstance(frontier_family, str) and frontier_family:
                    profile["frontier_candidate_family"] = frontier_family
                frontier_confidence = frontier_entry.get("confidence", frontier_entry.get("candidate_confidence"))
                if isinstance(frontier_confidence, (int, float)):
                    profile["frontier_candidate_confidence"] = float(frontier_confidence)
                frontier_stack_effect = frontier_entry.get("stack_effect_candidate")
                if isinstance(frontier_stack_effect, dict) and frontier_stack_effect:
                    profile["frontier_candidate_stack_effect"] = dict(frontier_stack_effect)
                frontier_operand_signature = frontier_entry.get("operand_signature_candidate")
                if isinstance(frontier_operand_signature, dict) and frontier_operand_signature:
                    profile["frontier_candidate_operand_signature"] = dict(frontier_operand_signature)
        profile["frontier_instruction_sample"] = prefix_trace["instruction_sample"][:16]
    if not (selected_steps and selected_mapping) and layout.switch_table_count:
        switch_cfg = _build_clientscript_switch_skeleton_cfg(layout)
        if switch_cfg is not None:
            profile["cfg_mode"] = "switch-skeleton"
            profile["cfg_block_count"] = switch_cfg["block_count"]
            profile["cfg_edge_count"] = switch_cfg["edge_count"]
            profile["cfg_terminal_block_count"] = switch_cfg["terminal_block_count"]
            profile["cfg_unresolved_target_count"] = switch_cfg["unresolved_target_count"]
            profile["cfg_entry_block"] = switch_cfg["entry_block"]
            profile["cfg_blocks_sample"] = switch_cfg["blocks"][:8]
            profile["cfg_edges_sample"] = switch_cfg["edges"][:16]
            profile["switch_dispatch_candidate_count"] = layout.switch_table_count
            profile["_cfg_dot_text"] = _render_clientscript_cfg_dot(switch_cfg)
            profile["_cfg_json_text"] = _render_clientscript_cfg_json(switch_cfg)
    return profile


def _mapsquare_coordinates(archive_key: int) -> tuple[int, int]:
    return archive_key % MAPSQUARE_WORLD_STRIDE, archive_key // MAPSQUARE_WORLD_STRIDE


def _append_int_sample(sample: list[int], value: int, *, limit: int = 12) -> None:
    if value not in sample and len(sample) < limit:
        sample.append(value)


def _decode_mapsquare_locations(data: bytes, *, archive_key: int) -> dict[str, object]:
    offset = 0
    loc_id = -1
    mapsquare_x, mapsquare_z = _mapsquare_coordinates(archive_key)
    placement_count = 0
    location_group_count = 0
    unique_loc_id_sample: list[int] = []
    type_counts = [0] * 32
    plane_counts = [0] * 4
    translated_placement_count = 0
    scaled_placement_count = 0
    rotation_override_count = 0
    extra_placement_count = 0
    placement_samples: list[dict[str, object]] = []

    while offset < len(data):
        delta, offset = _read_small_smart_int(data, offset)
        if delta == 0:
            break
        loc_id += delta
        location_group_count += 1
        _append_int_sample(unique_loc_id_sample, loc_id)

        packed_location = 0
        while offset < len(data):
            use_delta, offset = _read_small_smart_int(data, offset)
            if use_delta == 0:
                break
            packed_location += use_delta - 1
            local_y = packed_location & 0x3F
            local_x = (packed_location >> 6) & 0x3F
            plane = (packed_location >> 12) & 0x3
            packed_data, offset = _read_u8(data, offset)
            rotation = packed_data & 0x3
            type_id = (packed_data >> 2) & 0x1F
            extra: dict[str, object] | None = None

            plane_counts[plane] += 1
            type_counts[type_id] += 1
            placement_count += 1

            if packed_data & 0x80:
                extra_flags, offset = _read_u8(data, offset)
                extra_placement_count += 1
                extra = {"flags": extra_flags}
                if extra_flags & 0x01:
                    extra["rotation_override"] = [
                        _read_i16be(data, offset + i * 2)[0] for i in range(4)
                    ]
                    offset += 8
                    rotation_override_count += 1
                if extra_flags & 0x02:
                    translate_x, offset = _read_i16be(data, offset)
                    extra["translate_x"] = translate_x
                if extra_flags & 0x04:
                    translate_y, offset = _read_i16be(data, offset)
                    extra["translate_y"] = translate_y
                if extra_flags & 0x08:
                    translate_z, offset = _read_i16be(data, offset)
                    extra["translate_z"] = translate_z
                if extra_flags & 0x0E:
                    translated_placement_count += 1
                if extra_flags & 0x10:
                    scale, offset = _read_u16be(data, offset)
                    extra["scale"] = scale
                if extra_flags & 0x20:
                    scale_x, offset = _read_u16be(data, offset)
                    extra["scale_x"] = scale_x
                if extra_flags & 0x40:
                    scale_y, offset = _read_u16be(data, offset)
                    extra["scale_y"] = scale_y
                if extra_flags & 0x80:
                    scale_z, offset = _read_u16be(data, offset)
                    extra["scale_z"] = scale_z
                if extra_flags & 0xF0:
                    scaled_placement_count += 1

            if len(placement_samples) < 12:
                sample: dict[str, object] = {
                    "loc_id": loc_id,
                    "plane": plane,
                    "x": local_x,
                    "y": local_y,
                    "type": type_id,
                    "rotation": rotation,
                }
                if extra is not None:
                    sample["extra"] = extra
                placement_samples.append(sample)

    trailing_bytes = len(data) - offset
    if trailing_bytes and not any(byte != 0 for byte in data[offset:]):
        trailing_bytes = 0

    type_count_samples = [
        {"type": type_id, "count": count}
        for type_id, count in sorted(enumerate(type_counts), key=lambda item: (-item[1], item[0]))
        if count
    ][:10]

    payload: dict[str, object] = {
        "kind": "mapsquare-locations",
        "parser_status": "parsed",
        "mapsquare_x": mapsquare_x,
        "mapsquare_z": mapsquare_z,
        "mapsquare_file_kind": "locations",
        "location_group_count": location_group_count,
        "placement_count": placement_count,
        "unique_loc_id_count": location_group_count,
        "loc_id_sample": unique_loc_id_sample,
        "plane_counts": plane_counts,
        "type_count_samples": type_count_samples,
        "extra_placement_count": extra_placement_count,
        "translated_placement_count": translated_placement_count,
        "scaled_placement_count": scaled_placement_count,
        "rotation_override_count": rotation_override_count,
        "placement_samples": placement_samples,
    }
    if trailing_bytes:
        payload["trailing_bytes"] = trailing_bytes
    return payload


def _decode_mapsquare_tiles(
    data: bytes,
    *,
    archive_key: int,
    file_id: int,
) -> dict[str, object]:
    offset = 0
    file_kind = MAPSQUARE_FILE_NAMES.get(file_id, f"file-{file_id}")
    mapsquare_x, mapsquare_z = _mapsquare_coordinates(archive_key)
    format_magic: str | None = None
    format_version: int | None = None

    if len(data) >= 5 and data[:4] == b"jagx":
        format_magic = "jagx"
        offset = 4
        format_version, offset = _read_u8(data, offset)

    tile_count = 64 * 64 * 4
    nonempty_tile_count = 0
    overlay_tile_count = 0
    underlay_tile_count = 0
    settings_tile_count = 0
    height_tile_count = 0
    shape_tile_count = 0
    plane_nonempty_counts = [0] * 4
    plane_overlay_counts = [0] * 4
    plane_underlay_counts = [0] * 4
    plane_height_counts = [0] * 4
    overlay_id_sample: list[int] = []
    underlay_id_sample: list[int] = []
    settings_value_sample: list[int] = []
    shape_counts: dict[str, int] = {}
    tile_samples: list[dict[str, object]] = []
    min_height: int | None = None
    max_height: int | None = None

    for tile_index in range(tile_count):
        flags, offset = _read_u8(data, offset)
        plane = tile_index // 4096
        local_index = tile_index % 4096
        tile_x = local_index // 64
        tile_y = local_index % 64
        tile_sample: dict[str, object] | None = None

        if flags != 0:
            nonempty_tile_count += 1
            plane_nonempty_counts[plane] += 1
            if len(tile_samples) < 12:
                tile_sample = {
                    "plane": plane,
                    "x": tile_x,
                    "y": tile_y,
                    "flags": flags,
                }

        if flags & 0x01:
            shape, offset = _read_u8(data, offset)
            overlay_id, offset = _read_small_smart_int(data, offset)
            shape_tile_count += 1
            overlay_tile_count += 1
            plane_overlay_counts[plane] += 1
            _append_int_sample(overlay_id_sample, overlay_id)
            shape_key = str(shape)
            shape_counts[shape_key] = shape_counts.get(shape_key, 0) + 1
            if tile_sample is not None:
                tile_sample["shape"] = shape
                tile_sample["overlay_id"] = overlay_id
        if flags & 0x02:
            settings, offset = _read_u8(data, offset)
            settings_tile_count += 1
            _append_int_sample(settings_value_sample, settings)
            if tile_sample is not None:
                tile_sample["settings"] = settings
        if flags & 0x04:
            underlay_id, offset = _read_small_smart_int(data, offset)
            underlay_tile_count += 1
            plane_underlay_counts[plane] += 1
            _append_int_sample(underlay_id_sample, underlay_id)
            if tile_sample is not None:
                tile_sample["underlay_id"] = underlay_id
        if flags & 0x08:
            height, offset = _read_u16be(data, offset)
            height_tile_count += 1
            plane_height_counts[plane] += 1
            min_height = height if min_height is None else min(min_height, height)
            max_height = height if max_height is None else max(max_height, height)
            if tile_sample is not None:
                tile_sample["height"] = height
        if tile_sample is not None:
            tile_samples.append(tile_sample)

    nonmember_area_mask: str | None = None
    nonmember_subarea_count: int | None = None
    if len(data) - offset >= 8:
        nonmember = data[offset : offset + 8]
        nonmember_area_mask = nonmember.hex()
        nonmember_subarea_count = sum(bin(byte).count("1") for byte in nonmember)
        offset += 8

    extra_opcode_counts: dict[str, int] = {}
    environment_id_sample: list[int] = []

    while offset < len(data):
        opcode, offset = _read_u8(data, offset)
        extra_opcode_counts[str(opcode)] = extra_opcode_counts.get(str(opcode), 0) + 1
        if opcode == 0x00:
            flags, offset = _read_u8(data, offset)
            if flags & 0x01:
                _require_remaining(data, offset, 4)
                offset += 4
            if flags & 0x02:
                _require_remaining(data, offset, 2)
                offset += 2
            if flags & 0x04:
                _require_remaining(data, offset, 2)
                offset += 2
            if flags & 0x08:
                _require_remaining(data, offset, 2)
                offset += 2
            if flags & 0x10:
                _require_remaining(data, offset, 6)
                offset += 6
            if flags & 0x20:
                _require_remaining(data, offset, 4)
                offset += 4
            if flags & 0x40:
                _require_remaining(data, offset, 2)
                offset += 2
            if flags & 0x80:
                _require_remaining(data, offset, 2)
                offset += 2
        elif opcode == 0x01:
            count, offset = _read_u8(data, offset)
            for _ in range(count):
                _require_remaining(data, offset, 7)
                offset += 7
                array_count, offset = _read_u8(data, offset)
                _require_remaining(data, offset, array_count * 4 + 5)
                offset += array_count * 4 + 5
                extra_flags = data[offset - 1]
                _require_remaining(data, offset, 2)
                offset += 2
                if extra_flags & 0x1F:
                    _require_remaining(data, offset, 2)
                    offset += 2
        elif opcode == 0x02:
            _require_remaining(data, offset, 12)
            offset += 12
        elif opcode == 0x03:
            _require_remaining(data, offset, 6)
            offset += 6
        elif opcode == 0x80:
            environment_id, offset = _read_u16be(data, offset)
            _append_int_sample(environment_id_sample, environment_id)
            _require_remaining(data, offset, 8)
            offset += 8
        elif opcode == 0x81:
            for _ in range(4):
                flags, offset = _read_u8(data, offset)
                if flags & 0x01:
                    _require_remaining(data, offset, 256)
                    offset += 256
        elif opcode == 0x82:
            continue
        else:
            extra_opcode_counts[f"unknown_{opcode}"] = extra_opcode_counts.pop(str(opcode))
            break

    payload: dict[str, object] = {
        "kind": "mapsquare-tiles-nxt" if file_id == 5 else "mapsquare-tiles",
        "parser_status": "parsed",
        "mapsquare_x": mapsquare_x,
        "mapsquare_z": mapsquare_z,
        "mapsquare_file_kind": file_kind,
        "tile_count": tile_count,
        "format_magic": format_magic,
        "format_version": format_version,
        "nonempty_tile_count": nonempty_tile_count,
        "overlay_tile_count": overlay_tile_count,
        "underlay_tile_count": underlay_tile_count,
        "settings_tile_count": settings_tile_count,
        "height_tile_count": height_tile_count,
        "shape_tile_count": shape_tile_count,
        "plane_nonempty_counts": plane_nonempty_counts,
        "plane_overlay_counts": plane_overlay_counts,
        "plane_underlay_counts": plane_underlay_counts,
        "plane_height_counts": plane_height_counts,
        "overlay_id_sample": overlay_id_sample,
        "underlay_id_sample": underlay_id_sample,
        "settings_value_sample": settings_value_sample,
        "shape_counts": shape_counts,
        "tile_samples": tile_samples,
        "extra_opcode_counts": extra_opcode_counts,
        "environment_id_sample": environment_id_sample,
    }
    if min_height is not None and max_height is not None:
        payload["height_range"] = {"min": min_height, "max": max_height}
    if nonmember_area_mask is not None:
        payload["nonmember_area_mask"] = nonmember_area_mask
        payload["nonmember_subarea_count"] = nonmember_subarea_count
    if offset != len(data):
        payload["unparsed_trailing_bytes"] = len(data) - offset
    return payload


def _decode_mapsquare_tiles_nxt(data: bytes, *, archive_key: int) -> dict[str, object]:
    offset = 0
    mapsquare_x, mapsquare_z = _mapsquare_coordinates(archive_key)
    format_magic: str | None = None
    format_version: int | None = None

    if len(data) >= 5 and data[:4] == b"jagx":
        format_magic = "jagx"
        offset = 4
        format_version, offset = _read_u8(data, offset)

    level_presence = [0] * 4
    level_visible_counts = [0] * 4
    tile_count = 0
    nonempty_tile_count = 0
    blocking_tile_count = 0
    bridge_tile_count = 0
    roofed_tile_count = 0
    water_tile_count = 0
    forcedraw_tile_count = 0
    roofoverhang_tile_count = 0
    overlay_tile_count = 0
    underlay_tile_count = 0
    overlay_under_tile_count = 0
    underlay_under_tile_count = 0
    height_tile_count = 0
    water_height_tile_count = 0
    overlay_id_sample: list[int] = []
    underlay_id_sample: list[int] = []
    overlay_under_id_sample: list[int] = []
    underlay_under_id_sample: list[int] = []
    shape_counts: dict[str, int] = {}
    tile_samples: list[dict[str, object]] = []
    min_height: int | None = None
    max_height: int | None = None
    min_water_height: int | None = None
    max_water_height: int | None = None

    while offset < len(data):
        level_opcode, offset = _read_u8(data, offset)
        if level_opcode not in {0, 1, 2, 3}:
            raise ValueError(f"unsupported mapsquare-nxt level opcode {level_opcode}")
        level_presence[level_opcode] = 1

        for cell_index in range(66 * 66):
            flags, offset = _read_u8(data, offset)
            height, offset = _read_u16be(data, offset)
            tile_count += 1
            height_tile_count += 1
            min_height = height if min_height is None else min(min_height, height)
            max_height = height if max_height is None else max(max_height, height)

            if flags:
                nonempty_tile_count += 1
            if flags & 0x01:
                level_visible_counts[level_opcode] += 1
            if flags & 0x02:
                blocking_tile_count += 1
            if flags & 0x04:
                bridge_tile_count += 1
            if flags & 0x08:
                roofed_tile_count += 1
            if flags & 0x10:
                water_tile_count += 1
            if flags & 0x20:
                forcedraw_tile_count += 1
            if flags & 0x40:
                roofoverhang_tile_count += 1

            grid_x = cell_index // 66
            grid_y = cell_index % 66
            tile_sample: dict[str, object] | None = None
            if len(tile_samples) < 12 and (flags != 0 or (0 < grid_x < 65 and 0 < grid_y < 65)):
                tile_sample = {
                    "level": level_opcode,
                    "grid_x": grid_x,
                    "grid_y": grid_y,
                    "inner_tile": 0 < grid_x < 65 and 0 < grid_y < 65,
                    "flags": flags,
                    "height": height,
                }

            if flags & 0x01:
                if flags & 0x10:
                    water_height, offset = _read_u16be(data, offset)
                    water_height_tile_count += 1
                    min_water_height = water_height if min_water_height is None else min(min_water_height, water_height)
                    max_water_height = water_height if max_water_height is None else max(max_water_height, water_height)
                    if tile_sample is not None:
                        tile_sample["water_height"] = water_height

                underlay_id, offset = _read_small_smart_int(data, offset)
                if underlay_id != 0:
                    underlay_tile_count += 1
                    _append_int_sample(underlay_id_sample, underlay_id)
                    underlay_color, offset = _read_u16be(data, offset)
                    if tile_sample is not None:
                        tile_sample["underlay_id"] = underlay_id
                        tile_sample["underlay_color"] = underlay_color

                overlay_id, offset = _read_small_smart_int(data, offset)
                if overlay_id != 0:
                    overlay_tile_count += 1
                    _append_int_sample(overlay_id_sample, overlay_id)
                    if tile_sample is not None:
                        tile_sample["overlay_id"] = overlay_id

                if flags & 0x10:
                    overlay_under_id, offset = _read_small_smart_int(data, offset)
                    if overlay_under_id != 0:
                        overlay_under_tile_count += 1
                        _append_int_sample(overlay_under_id_sample, overlay_under_id)
                        if tile_sample is not None:
                            tile_sample["overlay_under_id"] = overlay_under_id

                if overlay_id != 0:
                    shape, offset = _read_u8(data, offset)
                    shape_key = str(shape)
                    shape_counts[shape_key] = shape_counts.get(shape_key, 0) + 1
                    if tile_sample is not None:
                        tile_sample["shape"] = shape

                if overlay_id != 0 and flags & 0x10:
                    underlay_under_id, offset = _read_small_smart_int(data, offset)
                    if underlay_under_id != 0:
                        underlay_under_tile_count += 1
                        _append_int_sample(underlay_under_id_sample, underlay_under_id)
                        if tile_sample is not None:
                            tile_sample["underlay_under_id"] = underlay_under_id

            if tile_sample is not None:
                tile_samples.append(tile_sample)

    payload: dict[str, object] = {
        "kind": "mapsquare-tiles-nxt",
        "parser_status": "parsed",
        "mapsquare_x": mapsquare_x,
        "mapsquare_z": mapsquare_z,
        "mapsquare_file_kind": "tiles-nxt",
        "grid_width": 66,
        "grid_height": 66,
        "tile_count": tile_count,
        "format_magic": format_magic,
        "format_version": format_version,
        "level_presence": level_presence,
        "level_visible_counts": level_visible_counts,
        "nonempty_tile_count": nonempty_tile_count,
        "blocking_tile_count": blocking_tile_count,
        "bridge_tile_count": bridge_tile_count,
        "roofed_tile_count": roofed_tile_count,
        "water_tile_count": water_tile_count,
        "forcedraw_tile_count": forcedraw_tile_count,
        "roofoverhang_tile_count": roofoverhang_tile_count,
        "overlay_tile_count": overlay_tile_count,
        "underlay_tile_count": underlay_tile_count,
        "overlay_under_tile_count": overlay_under_tile_count,
        "underlay_under_tile_count": underlay_under_tile_count,
        "height_tile_count": height_tile_count,
        "water_height_tile_count": water_height_tile_count,
        "overlay_id_sample": overlay_id_sample,
        "underlay_id_sample": underlay_id_sample,
        "overlay_under_id_sample": overlay_under_id_sample,
        "underlay_under_id_sample": underlay_under_id_sample,
        "shape_counts": shape_counts,
        "tile_samples": tile_samples,
    }
    if min_height is not None and max_height is not None:
        payload["height_range"] = {"min": min_height, "max": max_height}
    if min_water_height is not None and max_water_height is not None:
        payload["water_height_range"] = {"min": min_water_height, "max": max_water_height}
    return payload


def _profile_mapsquare_file(
    data: bytes,
    *,
    archive_key: int,
    file_id: int,
) -> dict[str, object] | None:
    if file_id == 0:
        return _decode_mapsquare_locations(data, archive_key=archive_key)
    if file_id == 3:
        return _decode_mapsquare_tiles(data, archive_key=archive_key, file_id=file_id)
    if file_id == 5:
        return _decode_mapsquare_tiles_nxt(data, archive_key=archive_key)
    if file_id == 6:
        mapsquare_x, mapsquare_z = _mapsquare_coordinates(archive_key)
        return {
            "kind": "mapsquare-environment",
            "parser_status": "profiled",
            "mapsquare_x": mapsquare_x,
            "mapsquare_z": mapsquare_z,
            "mapsquare_file_kind": "environment",
            "size_bytes": len(data),
            "header_hex": data[:24].hex(),
        }
    return None


def _find_related_jcache(source: str | Path, archive_id: int) -> Path | None:
    target = Path(source)
    for candidate in (
        target.with_name(f"js5-{archive_id}.jcache"),
        target.with_name(f"core-js5-{archive_id}.jcache"),
    ):
        if candidate.is_file():
            return candidate
    return None


@lru_cache(maxsize=64)
def _load_jcache_context(cache_path: str) -> dict[str, object] | None:
    target = Path(cache_path)
    if not target.is_file():
        return None

    match = match_jcache_name(target)
    if match is None:
        return None

    archive_id = int(match.group("archive_id"))
    index_names, _, _ = load_index_names(str(target))
    archive_index_name = index_names.get(archive_id)
    archives_by_id: dict[int, dict[str, object]] = {}

    try:
        with sqlite3.connect(str(target)) as connection:
            cursor = connection.cursor()
            tables_present = {
                str(name)
                for name, in cursor.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            if "cache_index" not in tables_present:
                return {
                    "path": str(target),
                    "archive_id": archive_id,
                    "index_name": archive_index_name,
                    "archives_by_id": archives_by_id,
                }

            reference_row = cursor.execute(
                'SELECT "DATA" FROM "cache_index" WHERE "KEY" = 1'
            ).fetchone()
            if reference_row is not None:
                container = parse_js5_container_record(
                    bytes(reference_row[0]),
                    max_compressed_bytes=None,
                    max_decoded_bytes=64 * 1024 * 1024,
                    include_decoded_payload=True,
                )
                if container.decoded_payload is not None:
                    reference_table = parse_reference_table_payload(container.decoded_payload)
                    archives_by_id = {
                        int(key): value
                        for key, value in reference_table.get("archives_by_id", {}).items()
                    }
    except (OSError, ValueError, sqlite3.Error):
        return None

    return {
        "path": str(target),
        "archive_id": archive_id,
        "index_name": archive_index_name,
        "archives_by_id": archives_by_id,
    }


@lru_cache(maxsize=4096)
def _load_jcache_semantic_profile(
    cache_path: str,
    archive_key: int,
    file_id: int,
) -> dict[str, object] | None:
    context = _load_jcache_context(cache_path)
    if context is None:
        return None

    archive_meta = context["archives_by_id"].get(int(archive_key))
    if not isinstance(archive_meta, dict):
        return None

    file_ids = archive_meta.get("file_ids", [])
    if int(file_id) not in file_ids:
        return None

    try:
        with sqlite3.connect(str(cache_path)) as connection:
            row = connection.execute(
                'SELECT "DATA" FROM "cache" WHERE "KEY" = ?',
                (int(archive_key),),
            ).fetchone()
    except sqlite3.Error:
        return None

    if row is None:
        return None

    try:
        container = parse_js5_container_record(
            bytes(row[0]),
            max_compressed_bytes=None,
            max_decoded_bytes=64 * 1024 * 1024,
            include_decoded_payload=True,
        )
        if container.decoded_payload is None:
            return None
        archive_files = split_archive_payload(
            container.decoded_payload,
            [int(value) for value in file_ids],
        )
    except (ValueError, sqlite3.Error):
        return None

    target_file = next((entry for entry in archive_files if int(entry["file_id"]) == int(file_id)), None)
    if target_file is None:
        return None

    index_name = context.get("index_name")
    if index_name is not None and not isinstance(index_name, str):
        index_name = None
    return profile_archive_file(
        bytes(target_file["data"]),
        index_name=index_name,
        archive_key=int(archive_key),
        file_id=int(file_id),
    )


def _collect_mapsquare_loc_ids(profile: dict[str, object], *, limit: int = 12) -> list[int]:
    collected: list[int] = []
    sources: list[object] = [profile.get("loc_id_sample"), profile.get("placement_samples")]
    for source in sources:
        if len(collected) >= limit:
            break
        if isinstance(source, list):
            for item in source:
                if isinstance(item, dict):
                    raw_value = item.get("loc_id")
                else:
                    raw_value = item
                try:
                    loc_id = int(raw_value)
                except (TypeError, ValueError):
                    continue
                if loc_id < 0 or loc_id in collected:
                    continue
                collected.append(loc_id)
                if len(collected) >= limit:
                    break
    return collected


def _summarize_object_definition(profile: dict[str, object]) -> dict[str, object]:
    definition_id = profile.get("definition_id")
    try:
        normalized_definition_id = int(definition_id) if definition_id is not None else None
    except (TypeError, ValueError):
        normalized_definition_id = None

    name = profile.get("name")
    summary: dict[str, object] = {
        "kind": "config-object-summary",
        "parser_status": str(profile.get("parser_status", "parsed")),
        "label": str(name) if isinstance(name, str) and name else (
            f"object-{normalized_definition_id}" if normalized_definition_id is not None else "object"
        ),
    }
    if normalized_definition_id is not None:
        summary["definition_id"] = normalized_definition_id
    if isinstance(name, str) and name:
        summary["name"] = name

    actions = [
        str(action)
        for action in profile.get("actions", [])
        if isinstance(action, str) and action
    ]
    if actions:
        summary["actions"] = actions[:5]
        summary["primary_action"] = actions[0]

    member_actions = [
        str(action)
        for action in profile.get("member_actions", [])
        if isinstance(action, str) and action
    ]
    if member_actions:
        summary["member_actions"] = member_actions[:5]

    model_entries = profile.get("model_entries")
    if isinstance(model_entries, list) and model_entries:
        summary["model_count"] = len(model_entries)
    else:
        model_ids = profile.get("model_ids")
        if isinstance(model_ids, list) and model_ids:
            summary["model_count"] = len(model_ids)

    for key in (
        "size_x",
        "size_y",
        "animation_id",
        "mapscene_id",
        "map_icon_id",
        "resize_x",
        "resize_y",
        "resize_z",
        "ambient",
        "contrast",
    ):
        value = profile.get(key)
        if value is not None:
            summary[key] = value

    for key in ("interactive", "clickable", "members_only", "is_rotated"):
        if key in profile:
            summary[key] = bool(profile[key])

    if "clip_type" in profile:
        summary["clip_type"] = profile["clip_type"]
    if "raise_object" in profile:
        summary["raise_object"] = bool(profile["raise_object"])
    if "morphs" in profile:
        summary["has_morphs"] = True
    if "param_count" in profile:
        summary["param_count"] = int(profile["param_count"])
    return summary


def _lookup_object_definition_summary(source: str | Path, definition_id: int) -> dict[str, object] | None:
    cache_path = _find_related_jcache(source, 16)
    if cache_path is None:
        return None

    archive_key = int(definition_id) >> 8
    file_id = int(definition_id) & 0xFF
    profile = _load_jcache_semantic_profile(str(cache_path), archive_key, file_id)
    if profile is None or profile.get("kind") != "config-object":
        return None
    return _summarize_object_definition(profile)


def _combine_unique_int_samples(*samples: object, limit: int = 12) -> list[int]:
    combined: list[int] = []
    for sample in samples:
        if len(combined) >= limit:
            break
        if not isinstance(sample, list):
            continue
        for value in sample:
            try:
                normalized = int(value)
            except (TypeError, ValueError):
                continue
            if normalized in combined:
                continue
            combined.append(normalized)
            if len(combined) >= limit:
                break
    return combined


def _merge_height_ranges(*profiles: dict[str, object]) -> dict[str, int] | None:
    min_height: int | None = None
    max_height: int | None = None
    for profile in profiles:
        height_range = profile.get("height_range")
        if not isinstance(height_range, dict):
            continue
        try:
            low = int(height_range["min"])
            high = int(height_range["max"])
        except (KeyError, TypeError, ValueError):
            continue
        min_height = low if min_height is None else min(min_height, low)
        max_height = high if max_height is None else max(max_height, high)
    if min_height is None or max_height is None:
        return None
    return {"min": min_height, "max": max_height}


def _enrich_mapsquare_locations_profile(
    profile: dict[str, object],
    *,
    source_path: str | Path,
) -> None:
    if profile.get("kind") != "mapsquare-locations":
        return

    loc_ids = _collect_mapsquare_loc_ids(profile)
    if not loc_ids:
        return

    summary_by_id: dict[int, dict[str, object]] = {}
    unresolved_loc_ids: list[int] = []
    for loc_id in loc_ids:
        summary = _lookup_object_definition_summary(source_path, loc_id)
        if summary is None:
            unresolved_loc_ids.append(loc_id)
            continue
        summary_by_id[loc_id] = summary

    profile["loc_definition_lookup_count"] = len(loc_ids)
    profile["loc_definition_resolved_count"] = len(summary_by_id)
    if summary_by_id:
        profile["loc_definition_sample"] = [
            summary_by_id[loc_id]
            for loc_id in loc_ids
            if loc_id in summary_by_id
        ]
    if unresolved_loc_ids:
        profile["unresolved_loc_id_sample"] = unresolved_loc_ids

    placement_samples = profile.get("placement_samples")
    if isinstance(placement_samples, list):
        for sample in placement_samples:
            if not isinstance(sample, dict):
                continue
            try:
                loc_id = int(sample.get("loc_id"))
            except (TypeError, ValueError):
                continue
            loc_summary = summary_by_id.get(loc_id)
            if loc_summary is not None:
                sample["loc_summary"] = loc_summary


def _summarize_mapsquare_archive(
    *,
    archive_key: int,
    archive_files: list[dict[str, object]],
) -> dict[str, object] | None:
    semantic_profiles = [
        entry["semantic_profile"]
        for entry in archive_files
        if isinstance(entry, dict) and isinstance(entry.get("semantic_profile"), dict)
    ]
    if not semantic_profiles:
        return None

    mapsquare_profiles = [
        profile
        for profile in semantic_profiles
        if isinstance(profile.get("kind"), str) and str(profile["kind"]).startswith("mapsquare-")
    ]
    if not mapsquare_profiles:
        return None

    seed = mapsquare_profiles[0]
    summary: dict[str, object] = {
        "kind": "mapsquare-archive",
        "parser_status": "profiled",
        "archive_key": int(archive_key),
        "mapsquare_x": int(seed.get("mapsquare_x", 0)),
        "mapsquare_z": int(seed.get("mapsquare_z", 0)),
        "file_count": len(archive_files),
        "file_ids": [int(entry["file_id"]) for entry in archive_files if isinstance(entry, dict) and "file_id" in entry],
        "file_kinds_present": [],
    }

    file_kinds_present: list[str] = []
    tile_profiles: list[dict[str, object]] = []
    location_profile: dict[str, object] | None = None
    has_environment_profile = False

    for profile in mapsquare_profiles:
        file_kind = profile.get("mapsquare_file_kind")
        if isinstance(file_kind, str) and file_kind not in file_kinds_present:
            file_kinds_present.append(file_kind)
        kind = profile.get("kind")
        if kind == "mapsquare-locations":
            location_profile = profile
        elif kind in {"mapsquare-tiles", "mapsquare-tiles-nxt"}:
            tile_profiles.append(profile)
        elif kind == "mapsquare-environment":
            has_environment_profile = True

    summary["file_kinds_present"] = file_kinds_present
    summary["tile_profile_count"] = len(tile_profiles)
    if has_environment_profile:
        summary["has_environment_profile"] = True

    if location_profile is not None:
        for key in ("location_group_count", "placement_count", "unique_loc_id_count", "loc_definition_lookup_count", "loc_definition_resolved_count"):
            value = location_profile.get(key)
            if value is not None:
                summary[key] = value
        for key in ("loc_id_sample", "loc_definition_sample", "unresolved_loc_id_sample"):
            value = location_profile.get(key)
            if isinstance(value, list) and value:
                summary[key] = value

    environment_ids = _combine_unique_int_samples(
        *[profile.get("environment_id_sample") for profile in tile_profiles],
    )
    if environment_ids:
        summary["environment_id_sample"] = environment_ids

    overlay_ids = _combine_unique_int_samples(
        *[profile.get("overlay_id_sample") for profile in tile_profiles],
    )
    if overlay_ids:
        summary["overlay_id_sample"] = overlay_ids

    underlay_ids = _combine_unique_int_samples(
        *[profile.get("underlay_id_sample") for profile in tile_profiles],
    )
    if underlay_ids:
        summary["underlay_id_sample"] = underlay_ids

    height_range = _merge_height_ranges(*tile_profiles)
    if height_range is not None:
        summary["height_range"] = height_range

    return summary


def _encode_rt7_model_obj(
    vertices: list[tuple[int, int, int]],
    render_groups: list[dict[str, object]],
) -> str:
    lines = [
        "# Reverser Workbench RT7 model export",
        f"# vertex_count {len(vertices)}",
        f"# render_count {len(render_groups)}",
    ]
    for x, y, z in vertices:
        lines.append(f"v {x} {y} {z}")

    for render in render_groups:
        render_index = int(render["render_index"])
        material_argument = int(render["material_argument"])
        is_hidden = bool(render["is_hidden"])
        lines.append(f"g render_{render_index}_material_{material_argument}")
        if is_hidden:
            lines.append("# hidden_render true")
        indices = list(render["indices"])
        triangle_count = len(indices) // 3
        for triangle_index in range(triangle_count):
            base = triangle_index * 3
            a = int(indices[base]) + 1
            b = int(indices[base + 1]) + 1
            c = int(indices[base + 2]) + 1
            lines.append(f"f {a} {b} {c}")
    return "\n".join(lines) + "\n"


def _decode_rt7_model(data: bytes) -> dict[str, object]:
    if len(data) < 9:
        raise ValueError("rt7 model payload too short")

    offset = 0
    format_id, offset = _read_u8(data, offset)
    version, offset = _read_u8(data, offset)
    marker, offset = _read_u8(data, offset)
    mesh_count, offset = _read_u8(data, offset)
    unk_count0, offset = _read_u8(data, offset)
    unk_count1, offset = _read_u8(data, offset)
    unk_count2, offset = _read_u8(data, offset)
    unk_count3, offset = _read_u8(data, offset)
    unk_count4 = 0
    if version >= 5:
        unk_count4, offset = _read_u8(data, offset)

    def decode_flags(flag_value: int) -> dict[str, bool]:
        return {
            "has_vertices": bool(flag_value & 0x01),
            "has_vertex_alpha": bool(flag_value & 0x02),
            "has_face_bones": bool(flag_value & 0x04),
            "has_bone_ids": bool(flag_value & 0x08),
            "is_hidden": bool(flag_value & 0x10),
            "has_skin": bool(flag_value & 0x20),
        }

    def skip_rt7_skin_entries(data_bytes: bytes, cursor: int, vertex_count: int) -> tuple[int, int, int]:
        total_entries = 0
        max_influences = 0
        for _ in range(vertex_count):
            id_count, cursor = _read_u16le(data_bytes, cursor)
            total_entries += id_count
            max_influences = max(max_influences, id_count)
            _require_remaining(data_bytes, cursor, id_count * 2)
            cursor += id_count * 2
            weight_count, cursor = _read_u16le(data_bytes, cursor)
            total_entries += weight_count
            max_influences = max(max_influences, weight_count)
            _require_remaining(data_bytes, cursor, weight_count)
            cursor += weight_count
        return cursor, total_entries, max_influences

    bounds: dict[str, int] | None = None
    total_vertex_count = 0
    total_index_count = 0
    total_triangle_count = 0
    render_samples: list[dict[str, object]] = []
    material_arguments: list[int] = []
    skin_entry_count = 0
    max_skin_influences = 0
    visible_render_count = 0
    hidden_render_count = 0
    mesh_obj_text: str | None = None
    mesh_obj_skip_reason: str | None = None
    feature_flags: dict[str, bool] = {
        "has_vertices": False,
        "has_vertex_alpha": False,
        "has_face_bones": False,
        "has_bone_ids": False,
        "has_skin": False,
        "has_uv": False,
        "has_normals": False,
        "has_tangents": False,
    }

    if version > 3:
        group_flags, offset = _read_u8(data, offset)
        mesh_unkint, offset = _read_u8(data, offset)
        face_count, offset = _read_u16le(data, offset)
        vertex_count, offset = _read_u32le(data, offset)
        total_vertex_count = vertex_count

        decoded = decode_flags(group_flags)
        feature_flags["has_vertices"] = decoded["has_vertices"]
        feature_flags["has_vertex_alpha"] = decoded["has_vertex_alpha"]
        feature_flags["has_face_bones"] = decoded["has_face_bones"]
        feature_flags["has_bone_ids"] = decoded["has_bone_ids"]
        feature_flags["has_skin"] = decoded["has_skin"]
        obj_vertices: list[tuple[int, int, int]] | None = None
        obj_render_groups: list[dict[str, object]] | None = []

        if vertex_count > DEFAULT_MAX_RT7_OBJ_VERTICES:
            mesh_obj_skip_reason = (
                f"obj export skipped: vertex_count {vertex_count} exceeds {DEFAULT_MAX_RT7_OBJ_VERTICES}"
            )
            obj_render_groups = None

        if decoded["has_vertices"]:
            if obj_render_groups is not None:
                obj_vertices = []
            min_x = min_y = min_z = 2**31 - 1
            max_x = max_y = max_z = -(2**31)
            for _ in range(vertex_count):
                x, offset = _read_i16le(data, offset)
                y, offset = _read_i16le(data, offset)
                z, offset = _read_i16le(data, offset)
                if obj_vertices is not None:
                    obj_vertices.append((x, y, z))
                min_x = min(min_x, x)
                min_y = min(min_y, y)
                min_z = min(min_z, z)
                max_x = max(max_x, x)
                max_y = max(max_y, y)
                max_z = max(max_z, z)
            bounds = {
                "min_x": min_x,
                "max_x": max_x,
                "min_y": min_y,
                "max_y": max_y,
                "min_z": min_z,
                "max_z": max_z,
            }

            _require_remaining(data, offset, vertex_count * 3)
            offset += vertex_count * 3
            feature_flags["has_normals"] = True
            _require_remaining(data, offset, vertex_count * 4)
            offset += vertex_count * 4
            feature_flags["has_tangents"] = True
            _require_remaining(data, offset, vertex_count * 4)
            offset += vertex_count * 4
            feature_flags["has_uv"] = True

        if decoded["has_bone_ids"]:
            _require_remaining(data, offset, vertex_count * 2)
            offset += vertex_count * 2

        if decoded["has_skin"]:
            offset, skin_entry_count, max_skin_influences = skip_rt7_skin_entries(data, offset, vertex_count)

        if decoded["has_vertices"]:
            _require_remaining(data, offset, vertex_count * 2)
            offset += vertex_count * 2
            _require_remaining(data, offset, vertex_count)
            offset += vertex_count
        if decoded["has_face_bones"]:
            _require_remaining(data, offset, vertex_count * 2)
            offset += vertex_count * 2

        for render_index in range(mesh_count):
            render_flags, offset = _read_u8(data, offset)
            render_unkint, offset = _read_u32be(data, offset)
            material_argument, offset = _read_u16le(data, offset)
            render_unkbyte2, offset = _read_u8(data, offset)
            index_count, offset = _read_u16le(data, offset)
            wide_indices = vertex_count > 0xFFFF
            index_values: list[int] = []
            obj_indices: list[int] | None = None
            if obj_render_groups is not None:
                if total_index_count + index_count <= DEFAULT_MAX_RT7_OBJ_INDICES:
                    obj_indices = []
                else:
                    mesh_obj_skip_reason = (
                        f"obj export skipped: total_index_count exceeds {DEFAULT_MAX_RT7_OBJ_INDICES}"
                    )
                    obj_render_groups = None
            if wide_indices:
                for _ in range(index_count):
                    value, offset = _read_u32be(data, offset)
                    if len(index_values) < 12:
                        index_values.append(value)
                    if obj_indices is not None:
                        obj_indices.append(value)
            else:
                for _ in range(index_count):
                    value, offset = _read_u16le(data, offset)
                    if len(index_values) < 12:
                        index_values.append(value)
                    if obj_indices is not None:
                        obj_indices.append(value)

            total_index_count += index_count
            total_triangle_count += index_count // 3
            material_arguments.append(material_argument)
            render_decoded = decode_flags(render_flags)
            if render_decoded["is_hidden"]:
                hidden_render_count += 1
            else:
                visible_render_count += 1

            if len(render_samples) < 10:
                render_samples.append(
                    {
                        "render_index": render_index,
                        "flags": render_flags,
                        "index_count": index_count,
                        "triangle_count": index_count // 3,
                        "material_argument": material_argument,
                        "wide_indices": wide_indices,
                        "unkint": render_unkint,
                        "unkbyte2": render_unkbyte2,
                        "index_sample": index_values,
                        "is_hidden": render_decoded["is_hidden"],
                    }
                )
            if obj_render_groups is not None and obj_indices is not None:
                obj_render_groups.append(
                    {
                        "render_index": render_index,
                        "material_argument": material_argument,
                        "is_hidden": render_decoded["is_hidden"],
                        "indices": obj_indices,
                    }
                )

        _require_remaining(data, offset, unk_count1 * 39)
        offset += unk_count1 * 39
        _require_remaining(data, offset, unk_count2 * 50)
        offset += unk_count2 * 50
        _require_remaining(data, offset, unk_count3 * 18)
        offset += unk_count3 * 18
        if obj_vertices and obj_render_groups and total_triangle_count > 0:
            mesh_obj_text = _encode_rt7_model_obj(obj_vertices, obj_render_groups)
        elif mesh_obj_skip_reason is None and decoded["has_vertices"] and total_triangle_count == 0:
            mesh_obj_skip_reason = "obj export skipped: model contains no triangles"
    else:
        face_count = 0
        mesh_unkint = 0
        mesh_obj_skip_reason = "obj export currently supports only RT7 models with version > 3"
        for mesh_index in range(mesh_count):
            group_flags, offset = _read_u8(data, offset)
            mesh_unkint, offset = _read_u32be(data, offset)
            material_argument, offset = _read_u16le(data, offset)
            mesh_face_count, offset = _read_u16le(data, offset)
            face_count += mesh_face_count
            decoded = decode_flags(group_flags)
            material_arguments.append(material_argument)
            for key in ("has_vertices", "has_vertex_alpha", "has_face_bones", "has_bone_ids", "has_skin"):
                feature_flags[key] = feature_flags[key] or decoded[key]
            if decoded["has_vertices"]:
                _require_remaining(data, offset, mesh_face_count * 2)
                offset += mesh_face_count * 2
            if decoded["has_vertex_alpha"]:
                _require_remaining(data, offset, mesh_face_count)
                offset += mesh_face_count
            if decoded["has_face_bones"]:
                _require_remaining(data, offset, mesh_face_count * 2)
                offset += mesh_face_count * 2

            lod_count, offset = _read_u8(data, offset)
            lod_samples: list[int] = []
            for _ in range(lod_count):
                index_count, offset = _read_u16le(data, offset)
                total_index_count += index_count
                total_triangle_count += index_count // 3
                if len(lod_samples) < 4:
                    lod_samples.append(index_count)
                _require_remaining(data, offset, index_count * 2)
                offset += index_count * 2

            vertex_count, offset = _read_u16le(data, offset) if decoded["has_vertices"] else (0, offset)
            total_vertex_count += vertex_count
            if decoded["has_vertices"]:
                min_x = min_y = min_z = 2**31 - 1
                max_x = max_y = max_z = -(2**31)
                for _ in range(vertex_count):
                    x, offset = _read_i16le(data, offset)
                    y, offset = _read_i16le(data, offset)
                    z, offset = _read_i16le(data, offset)
                    min_x = min(min_x, x)
                    min_y = min(min_y, y)
                    min_z = min(min_z, z)
                    max_x = max(max_x, x)
                    max_y = max(max_y, y)
                    max_z = max(max_z, z)
                if bounds is None:
                    bounds = {
                        "min_x": min_x,
                        "max_x": max_x,
                        "min_y": min_y,
                        "max_y": max_y,
                        "min_z": min_z,
                        "max_z": max_z,
                    }
                else:
                    bounds["min_x"] = min(bounds["min_x"], min_x)
                    bounds["max_x"] = max(bounds["max_x"], max_x)
                    bounds["min_y"] = min(bounds["min_y"], min_y)
                    bounds["max_y"] = max(bounds["max_y"], max_y)
                    bounds["min_z"] = min(bounds["min_z"], min_z)
                    bounds["max_z"] = max(bounds["max_z"], max_z)

                normal_bytes = vertex_count * 3
                _require_remaining(data, offset, normal_bytes)
                offset += normal_bytes
                feature_flags["has_normals"] = True
                if version >= 3:
                    _require_remaining(data, offset, vertex_count * 4)
                    offset += vertex_count * 4
                    feature_flags["has_tangents"] = True
                    _require_remaining(data, offset, vertex_count * 4)
                    offset += vertex_count * 4
                    feature_flags["has_uv"] = True
            if decoded["has_bone_ids"]:
                _require_remaining(data, offset, vertex_count * 2)
                offset += vertex_count * 2
            if decoded["has_skin"]:
                skin_weight_count, offset = _read_u32le(data, offset)
                skin_entry_count += skin_weight_count
                _require_remaining(data, offset, skin_weight_count * 2)
                offset += skin_weight_count * 2
                _require_remaining(data, offset, skin_weight_count)
                offset += skin_weight_count
            if decoded["is_hidden"]:
                hidden_render_count += 1
            else:
                visible_render_count += 1
            if len(render_samples) < 10:
                render_samples.append(
                    {
                        "render_index": mesh_index,
                        "flags": group_flags,
                        "lod_count": lod_count,
                        "lod_index_counts": lod_samples,
                        "material_argument": material_argument,
                        "face_count": mesh_face_count,
                        "unkint": mesh_unkint,
                        "is_hidden": decoded["is_hidden"],
                    }
                )

    if offset != len(data):
        raise ValueError(f"rt7 model parse ended at {offset}, expected {len(data)}")

    material_sample = material_arguments[:10]
    payload = {
        "kind": "rt7-model",
        "parser_status": "parsed",
        "format": format_id,
        "version": version,
        "marker": marker,
        "mesh_count": mesh_count,
        "feature_flags": feature_flags,
        "auxiliary_table_counts": {
            "unk_count0": unk_count0,
            "unk_count1": unk_count1,
            "unk_count2": unk_count2,
            "unk_count3": unk_count3,
            "unk_count4": unk_count4,
        },
        "face_count": face_count,
        "vertex_count": total_vertex_count,
        "render_count": visible_render_count + hidden_render_count,
        "visible_render_count": visible_render_count,
        "hidden_render_count": hidden_render_count,
        "total_index_count": total_index_count,
        "total_triangle_count": total_triangle_count,
        "material_argument_sample": material_sample,
        "render_samples": render_samples,
        "mesh_unkint": mesh_unkint,
        "skin_entry_count": skin_entry_count,
        "max_skin_influences": max_skin_influences,
        "bounds": bounds,
    }
    if mesh_obj_text is not None:
        payload["_mesh_obj_text"] = mesh_obj_text
    if mesh_obj_skip_reason is not None:
        payload["mesh_obj_skip_reason"] = mesh_obj_skip_reason
    return payload


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


def _decode_item_definition(data: bytes) -> dict[str, object]:
    offset = 0
    payload: dict[str, object] = {
        "kind": "config-item",
        "parser_status": "parsed",
    }
    ground_actions: list[str | None] = [None] * 5
    inventory_actions: list[str | None] = [None] * 5
    count_variants: list[dict[str, int]] = []
    opaque_flags: list[int] = []
    opaque_values: dict[int, object] = {}
    stopped_opcode: int | None = None

    try:
        while offset < len(data):
            opcode, offset = _read_u8(data, offset)
            if opcode == 0:
                break
            if opcode == 1:
                payload["model_id"], offset = _read_u16be(data, offset)
            elif opcode == 2:
                payload["name"], offset = _read_c_string(data, offset)
            elif opcode == 4:
                payload["zoom_2d"], offset = _read_u16be(data, offset)
            elif opcode == 5:
                payload["xan_2d"], offset = _read_u16be(data, offset)
            elif opcode == 6:
                payload["yan_2d"], offset = _read_u16be(data, offset)
            elif opcode == 7:
                payload["offset_x_2d"], offset = _read_i16be(data, offset)
            elif opcode == 8:
                payload["offset_y_2d"], offset = _read_i16be(data, offset)
            elif opcode == 11:
                payload["stackable"] = True
            elif opcode == 12:
                payload["cost"], offset = _read_i32be(data, offset)
            elif opcode == 13:
                payload["wear_pos"], offset = _read_u8(data, offset)
            elif opcode == 14:
                payload["wear_pos_2"], offset = _read_u8(data, offset)
            elif opcode == 15:
                opaque_flags.append(opcode)
            elif opcode == 16:
                payload["members_only"] = True
            elif opcode == 23:
                payload["male_model_0"], offset = _read_u16be(data, offset)
            elif opcode == 24:
                payload["male_model_1"], offset = _read_u16be(data, offset)
            elif opcode == 25:
                payload["female_model_0"], offset = _read_u16be(data, offset)
            elif opcode == 26:
                payload["female_model_1"], offset = _read_u16be(data, offset)
            elif opcode == 27:
                payload["wear_pos_3"], offset = _read_u8(data, offset)
            elif 30 <= opcode <= 34:
                action, offset = _read_c_string(data, offset)
                ground_actions[opcode - 30] = None if action.lower() == "hidden" else action
            elif 35 <= opcode <= 39:
                action, offset = _read_c_string(data, offset)
                inventory_actions[opcode - 35] = None if action.lower() == "hidden" else action
            elif opcode == 40:
                size, offset = _read_u8(data, offset)
                recolors: list[dict[str, int]] = []
                for _ in range(size):
                    source, offset = _read_u16be(data, offset)
                    target, offset = _read_u16be(data, offset)
                    recolors.append({"from": source, "to": target})
                payload["recolors"] = recolors
            elif opcode == 41:
                size, offset = _read_u8(data, offset)
                retextures: list[dict[str, int]] = []
                for _ in range(size):
                    source, offset = _read_u16be(data, offset)
                    target, offset = _read_u16be(data, offset)
                    retextures.append({"from": source, "to": target})
                payload["retextures"] = retextures
            elif opcode == 42:
                payload["shift_click_index"], offset = _read_u8(data, offset)
            elif opcode == 65:
                payload["tradable"] = True
            elif opcode == 69:
                opaque_values[opcode], offset = _read_i32be(data, offset)
            elif opcode == 78:
                payload["male_model_2"], offset = _read_u16be(data, offset)
            elif opcode == 79:
                payload["female_model_2"], offset = _read_u16be(data, offset)
            elif opcode == 90:
                payload["male_head_model_0"], offset = _read_u16be(data, offset)
            elif opcode == 91:
                payload["female_head_model_0"], offset = _read_u16be(data, offset)
            elif opcode == 92:
                payload["male_head_model_1"], offset = _read_u16be(data, offset)
            elif opcode == 93:
                payload["female_head_model_1"], offset = _read_u16be(data, offset)
            elif opcode == 94:
                payload["category_id"], offset = _read_u16be(data, offset)
            elif opcode == 95:
                payload["zan_2d"], offset = _read_u16be(data, offset)
            elif opcode == 97:
                payload["note_link_id"], offset = _read_u16be(data, offset)
            elif opcode == 98:
                payload["note_template_id"], offset = _read_u16be(data, offset)
            elif 100 <= opcode <= 109:
                item_id, offset = _read_u16be(data, offset)
                count, offset = _read_u16be(data, offset)
                count_variants.append({"threshold": count, "item_id": item_id})
            elif opcode == 110:
                payload["resize_x"], offset = _read_u16be(data, offset)
            elif opcode == 111:
                payload["resize_y"], offset = _read_u16be(data, offset)
            elif opcode == 112:
                payload["resize_z"], offset = _read_u16be(data, offset)
            elif opcode == 113:
                payload["ambient"], offset = _read_i8(data, offset)
            elif opcode == 114:
                payload["contrast"], offset = _read_i8(data, offset)
            elif opcode == 115:
                payload["team"], offset = _read_u8(data, offset)
            elif opcode == 139:
                payload["unnoted_id"], offset = _read_u16be(data, offset)
            elif opcode == 140:
                payload["noted_id"], offset = _read_u16be(data, offset)
            elif opcode == 144:
                opaque_values[opcode], offset = _read_u16be(data, offset)
            elif opcode == 148:
                payload["placeholder_id"], offset = _read_u16be(data, offset)
            elif opcode == 149:
                payload["placeholder_template_id"], offset = _read_u16be(data, offset)
            elif opcode == 178:
                opaque_flags.append(opcode)
            elif opcode == 181:
                opaque_values[opcode], offset = _read_u64be(data, offset)
            elif opcode == 249:
                params, offset = _read_param_entries(data, offset)
                payload["param_count"] = len(params)
                payload["param_samples"] = params[:10]
            else:
                stopped_opcode = opcode
                break
    except Exception as exc:
        payload["parser_status"] = "error"
        payload["error"] = str(exc)
        return payload

    if any(action is not None for action in ground_actions):
        payload["ground_actions"] = ground_actions
    if any(action is not None for action in inventory_actions):
        payload["inventory_actions"] = inventory_actions
    if count_variants:
        payload["count_variants"] = count_variants
    return _finalize_partial_profile(
        payload,
        data=data,
        offset=offset,
        stopped_opcode=stopped_opcode,
        opaque_flags=opaque_flags,
        opaque_values=opaque_values,
        min_field_count=3,
    )


def _decode_npc_definition(data: bytes) -> dict[str, object]:
    offset = 0
    payload: dict[str, object] = {
        "kind": "config-npc",
        "parser_status": "parsed",
    }
    actions: list[str | None] = [None] * 5
    opaque_flags: list[int] = []
    opaque_values: dict[int, object] = {}
    stopped_opcode: int | None = None

    try:
        while offset < len(data):
            opcode, offset = _read_u8(data, offset)
            if opcode == 0:
                break
            if opcode == 1:
                size, offset = _read_u8(data, offset)
                model_ids: list[int] = []
                for _ in range(size):
                    model_id, offset = _read_u16be(data, offset)
                    model_ids.append(model_id)
                payload["model_ids"] = model_ids
            elif opcode == 2:
                payload["name"], offset = _read_c_string(data, offset)
            elif opcode == 12:
                payload["size"], offset = _read_u8(data, offset)
            elif 30 <= opcode <= 34:
                action, offset = _read_c_string(data, offset)
                actions[opcode - 30] = None if action.lower() == "hidden" else action
            elif opcode == 40:
                size, offset = _read_u8(data, offset)
                recolors: list[dict[str, int]] = []
                for _ in range(size):
                    source, offset = _read_u16be(data, offset)
                    target, offset = _read_u16be(data, offset)
                    recolors.append({"from": source, "to": target})
                payload["recolors"] = recolors
            elif opcode == 41:
                size, offset = _read_u8(data, offset)
                retextures: list[dict[str, int]] = []
                for _ in range(size):
                    source, offset = _read_u16be(data, offset)
                    target, offset = _read_u16be(data, offset)
                    retextures.append({"from": source, "to": target})
                payload["retextures"] = retextures
            elif opcode == 60:
                size, offset = _read_u8(data, offset)
                head_model_ids: list[int] = []
                for _ in range(size):
                    model_id, offset = _read_u16be(data, offset)
                    head_model_ids.append(model_id)
                payload["head_model_ids"] = head_model_ids
            elif opcode == 93:
                payload["draw_map_dot"] = False
            elif opcode == 95:
                payload["combat_level"], offset = _read_u16be(data, offset)
            elif opcode == 97:
                payload["width_scale"], offset = _read_u16be(data, offset)
            elif opcode == 98:
                payload["height_scale"], offset = _read_u16be(data, offset)
            elif opcode == 99:
                payload["render_priority"] = True
            elif opcode == 100:
                payload["ambient"], offset = _read_i8(data, offset)
            elif opcode == 101:
                payload["contrast"], offset = _read_i8(data, offset)
            elif opcode == 102:
                mask, offset = _read_u8(data, offset)
                head_icons: list[dict[str, int]] = []
                bit = 0
                while mask:
                    if mask & 1:
                        icon_id, offset = _read_u16be(data, offset)
                        value, offset = _read_i16be(data, offset)
                        head_icons.append({"slot": bit, "icon_id": icon_id, "value": value})
                    mask >>= 1
                    bit += 1
                payload["head_icons"] = head_icons
            elif opcode == 103:
                payload["rotation_speed"], offset = _read_u16be(data, offset)
            elif opcode in {106, 118}:
                varbit_id, offset = _read_u16be(data, offset)
                varp_id, offset = _read_u16be(data, offset)
                transform_default: int | None = None
                if opcode == 118:
                    transform_default, offset = _read_u16be(data, offset)
                count, offset = _read_u8(data, offset)
                transforms: list[int] = []
                for _ in range(count + 2):
                    transform_id, offset = _read_u16be(data, offset)
                    transforms.append(transform_id)
                payload["morphs"] = {
                    "varbit_id": varbit_id,
                    "varp_id": varp_id,
                    "default_id": transform_default,
                    "transform_ids": transforms,
                }
            elif opcode == 107:
                payload["interactable"] = False
            elif opcode == 109:
                payload["clickable"] = False
            elif opcode == 111:
                payload["follower"] = True
            elif opcode == 119:
                opaque_values[opcode], offset = _read_u8(data, offset)
            elif opcode == 121:
                size, offset = _read_u8(data, offset)
                translations: list[dict[str, int]] = []
                for _ in range(size):
                    model_index, offset = _read_u8(data, offset)
                    x, offset = _read_i8(data, offset)
                    y, offset = _read_i8(data, offset)
                    z, offset = _read_i8(data, offset)
                    translations.append(
                        {"model_index": model_index, "x": x, "y": y, "z": z}
                    )
                payload["translations"] = translations
            elif opcode == 123:
                opaque_values[opcode], offset = _read_u8(data, offset)
            elif opcode == 127:
                opaque_values[opcode], offset = _read_u16be(data, offset)
            elif opcode == 137:
                opaque_values[opcode], offset = _read_u16be(data, offset)
            elif opcode == 249:
                params, offset = _read_param_entries(data, offset)
                payload["param_count"] = len(params)
                payload["param_samples"] = params[:10]
            else:
                stopped_opcode = opcode
                break
    except Exception as exc:
        payload["parser_status"] = "error"
        payload["error"] = str(exc)
        return payload

    if any(action is not None for action in actions):
        payload["actions"] = actions
    return _finalize_partial_profile(
        payload,
        data=data,
        offset=offset,
        stopped_opcode=stopped_opcode,
        opaque_flags=opaque_flags,
        opaque_values=opaque_values,
        min_field_count=3,
    )


def _decode_object_definition(data: bytes) -> dict[str, object]:
    offset = 0
    payload: dict[str, object] = {
        "kind": "config-object",
        "parser_status": "parsed",
    }
    actions: list[str | None] = [None] * 5
    member_actions: list[str | None] = [None] * 5
    opaque_flags: list[int] = []
    opaque_values: dict[int, object] = {}
    stopped_opcode: int | None = None

    try:
        while offset < len(data):
            opcode, offset = _read_u8(data, offset)
            if opcode == 0:
                break
            if opcode == 1:
                size, offset = _read_u8(data, offset)
                model_entries: list[dict[str, int]] = []
                for _ in range(size):
                    model_id, offset = _read_u16be(data, offset)
                    model_type, offset = _read_u8(data, offset)
                    model_entries.append({"model_id": model_id, "model_type": model_type})
                payload["model_entries"] = model_entries
            elif opcode == 2:
                payload["name"], offset = _read_c_string(data, offset)
            elif opcode == 5:
                size, offset = _read_u8(data, offset)
                model_ids: list[int] = []
                for _ in range(size):
                    model_id, offset = _read_u16be(data, offset)
                    model_ids.append(model_id)
                payload["model_ids"] = model_ids
            elif opcode == 14:
                payload["size_x"], offset = _read_u8(data, offset)
            elif opcode == 15:
                payload["size_y"], offset = _read_u8(data, offset)
            elif opcode == 17:
                payload["interactive"] = False
            elif opcode == 18:
                payload["solid"] = False
            elif opcode == 19:
                payload["interaction_type"], offset = _read_u8(data, offset)
            elif opcode == 21:
                payload["contoured_ground"] = True
            elif opcode == 22:
                payload["merge_normals"] = True
            elif opcode == 24:
                payload["animation_id"], offset = _read_u16be(data, offset)
            elif opcode == 28:
                payload["decor_displacement"], offset = _read_u8(data, offset)
            elif opcode == 29:
                payload["ambient"], offset = _read_i8(data, offset)
            elif 30 <= opcode <= 34:
                action, offset = _read_c_string(data, offset)
                actions[opcode - 30] = None if action.lower() == "hidden" else action
            elif opcode == 39:
                payload["contrast"], offset = _read_i8(data, offset)
            elif opcode == 40:
                size, offset = _read_u8(data, offset)
                recolors: list[dict[str, int]] = []
                for _ in range(size):
                    source, offset = _read_u16be(data, offset)
                    target, offset = _read_u16be(data, offset)
                    recolors.append({"from": source, "to": target})
                payload["recolors"] = recolors
            elif opcode == 41:
                size, offset = _read_u8(data, offset)
                retextures: list[dict[str, int]] = []
                for _ in range(size):
                    source, offset = _read_u16be(data, offset)
                    target, offset = _read_u16be(data, offset)
                    retextures.append({"from": source, "to": target})
                payload["retextures"] = retextures
            elif opcode == 42:
                opaque_flags.append(opcode)
            elif opcode == 62:
                payload["rotated"] = True
            elif opcode == 64:
                payload["casts_shadow"] = False
            elif opcode == 65:
                payload["resize_x"], offset = _read_u16be(data, offset)
            elif opcode == 66:
                payload["resize_y"], offset = _read_u16be(data, offset)
            elif opcode == 67:
                payload["resize_z"], offset = _read_u16be(data, offset)
            elif opcode == 68:
                payload["mapscene_id"], offset = _read_u16be(data, offset)
            elif opcode == 69:
                payload["blocking_mask"], offset = _read_u8(data, offset)
            elif opcode == 70:
                payload["offset_x"], offset = _read_i16be(data, offset)
            elif opcode == 71:
                payload["offset_y"], offset = _read_i16be(data, offset)
            elif opcode == 72:
                payload["offset_z"], offset = _read_i16be(data, offset)
            elif opcode == 73:
                payload["obstructs_ground"] = True
            elif opcode == 74:
                payload["hollow"] = True
            elif opcode == 75:
                payload["support_items"], offset = _read_u8(data, offset)
            elif opcode in {77, 92}:
                varbit_id, offset = _read_u16be(data, offset)
                varp_id, offset = _read_u16be(data, offset)
                default_id: int | None = None
                if opcode == 92:
                    default_id, offset = _read_u16be(data, offset)
                count, offset = _read_u8(data, offset)
                transforms: list[int] = []
                for _ in range(count + 2):
                    transform_id, offset = _read_u16be(data, offset)
                    transforms.append(transform_id)
                payload["morphs"] = {
                    "varbit_id": varbit_id,
                    "varp_id": varp_id,
                    "default_id": default_id,
                    "transform_ids": transforms,
                }
            elif opcode == 78:
                sound_id, offset = _read_u16be(data, offset)
                range_value, offset = _read_u8(data, offset)
                opaque_values[opcode] = {"sound_id": sound_id, "range": range_value}
            elif opcode == 79:
                min_delay, offset = _read_u16be(data, offset)
                max_delay, offset = _read_u16be(data, offset)
                range_value, offset = _read_u8(data, offset)
                volume, offset = _read_u8(data, offset)
                opaque_values[opcode] = {
                    "min_delay": min_delay,
                    "max_delay": max_delay,
                    "range": range_value,
                    "volume": volume,
                }
            elif opcode == 81:
                opaque_values[opcode], offset = _read_u16be(data, offset)
            elif opcode == 82:
                payload["map_icon_id"], offset = _read_u8(data, offset)
            elif opcode == 89:
                opaque_flags.append(opcode)
            elif opcode == 103:
                opaque_flags.append(opcode)
            elif opcode in {90, 91, 92, 93, 95, 99, 100, 101, 102, 104, 105, 106, 107, 160, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 177, 178, 190, 191, 196, 197}:
                opaque_values[opcode], offset = _read_u16be(data, offset)
            elif 150 <= opcode <= 154:
                action, offset = _read_c_string(data, offset)
                member_actions[opcode - 150] = None if action.lower() == "hidden" else action
            elif opcode == 249:
                params, offset = _read_param_entries(data, offset)
                payload["param_count"] = len(params)
                payload["param_samples"] = params[:10]
            else:
                stopped_opcode = opcode
                break
    except Exception as exc:
        payload["parser_status"] = "error"
        payload["error"] = str(exc)
        return payload

    if any(action is not None for action in actions):
        payload["actions"] = actions
    if any(action is not None for action in member_actions):
        payload["member_actions"] = member_actions
    return _finalize_partial_profile(
        payload,
        data=data,
        offset=offset,
        stopped_opcode=stopped_opcode,
        opaque_flags=opaque_flags,
        opaque_values=opaque_values,
        min_field_count=2,
    )


def _collect_clientscript_calibration_candidates(
    connection: sqlite3.Connection,
    *,
    include_keys: list[int],
    max_decoded_bytes: int | None,
    sample_limit: int = DEFAULT_CLIENTSCRIPT_CALIBRATION_SAMPLE,
) -> list[tuple[int, ClientscriptLayout]]:
    rows = connection.execute(
        'SELECT "KEY", "DATA" FROM "cache" WHERE "DATA" IS NOT NULL ORDER BY LENGTH("DATA") ASC, "KEY" ASC LIMIT ?',
        (sample_limit,),
    ).fetchall()

    extra_rows: list[tuple[int, bytes]] = []
    if include_keys:
        placeholders = ", ".join("?" for _ in include_keys)
        extra_rows = connection.execute(
            f'SELECT "KEY", "DATA" FROM "cache" WHERE "DATA" IS NOT NULL AND "KEY" IN ({placeholders}) ORDER BY "KEY" ASC',
            include_keys,
        ).fetchall()

    candidates: list[tuple[int, ClientscriptLayout]] = []
    seen_keys: set[int] = set()
    for key, data in [*rows, *extra_rows]:
        key_int = int(key)
        if key_int in seen_keys:
            continue
        seen_keys.add(key_int)
        container = parse_js5_container_record(
            bytes(data),
            max_compressed_bytes=None,
            max_decoded_bytes=max_decoded_bytes,
            include_decoded_payload=True,
        )
        if container.decoded_payload is None:
            continue
        try:
            layout = _parse_clientscript_layout(container.decoded_payload)
        except Exception:
            continue
        candidates.append((key_int, layout))
    candidates.sort(key=lambda item: (item[1].instruction_count, len(item[1].opcode_data), item[0]))
    return candidates


def _sample_clientscript_immediate_value(value: object) -> object:
    if isinstance(value, dict):
        if "hex" in value:
            return value["hex"]
        return value
    return value


def _infer_clientscript_opcode_candidate(stats: dict[str, object]) -> dict[str, object]:
    immediate_kind = str(stats["immediate_kind"])
    script_count = max(int(stats["script_count"]), 1)
    first_ratio = int(stats["first_count"]) / script_count
    last_ratio = int(stats["last_count"]) / script_count
    zero_ratio = int(stats["zero_count"]) / max(int(stats["occurrence_count"]), 1)
    entry: dict[str, object] = {}
    reasons: list[str] = []

    if immediate_kind == "switch":
        subtype_counts = stats.get("switch_subtype_counts", {})
        dominant_subtype = None
        if isinstance(subtype_counts, dict) and subtype_counts:
            dominant_subtype = max(subtype_counts.items(), key=lambda item: int(item[1]))[0]
        constant_kind = _clientscript_constant_kind(dominant_subtype)
        entry["candidate_mnemonic"] = (
            f"PUSH_CONST_{constant_kind.upper()}" if constant_kind is not None else "PUSH_CONST"
        )
        entry["family"] = "stack-constant"
        entry["candidate_confidence"] = 0.98
        reasons.append("Modern CS2 switch-immediate form is used for constant pushes.")
    elif immediate_kind == "tribyte":
        entry["candidate_mnemonic"] = "VAR_REFERENCE_CANDIDATE"
        entry["family"] = "state-reference"
        entry["candidate_confidence"] = 0.7
        source_counts = stats.get("reference_source_counts", {})
        if isinstance(source_counts, dict) and source_counts:
            dominant_source, _count = max(source_counts.items(), key=lambda item: int(item[1]))
            source_name = CLIENTSCRIPT_VAR_SOURCE_NAMES.get(int(dominant_source))
            if source_name:
                entry["reference_source_name"] = source_name
                reasons.append(f"Dominant tribyte source id maps to `{source_name}` state.")
        reasons.append("Tribyte immediates commonly encode domain/id state references in CS2.")
    elif immediate_kind == "byte" and last_ratio >= 0.95 and zero_ratio >= 0.95:
        entry["candidate_mnemonic"] = "TERMINATOR_CANDIDATE"
        entry["family"] = "control-flow"
        entry["candidate_confidence"] = 0.6 if first_ratio >= 0.25 else 0.75
        reasons.append("Opcode ends nearly every sampled script it appears in.")
        reasons.append("Immediate byte is almost always zero.")
        if first_ratio >= 0.25:
            reasons.append("Also appears in script prologues, so exact naming is still tentative.")
    elif immediate_kind == "byte" and int(stats.get("slot_fit_count", 0)) >= max(2, int(stats["script_count"]) * 0.75):
        entry["candidate_mnemonic"] = "PUSH_SLOT_REFERENCE_CANDIDATE"
        entry["family"] = "stack-local"
        entry["candidate_confidence"] = 0.6
        reasons.append("Byte immediate usually fits within local/argument slot counts across solved scripts.")
        reasons.append("This pattern is consistent with a small-slot load that pushes one integer value.")
    elif immediate_kind == "int" and last_ratio <= 0.25:
        entry["candidate_mnemonic"] = "PUSH_INT_CANDIDATE"
        entry["family"] = "stack"
        entry["candidate_confidence"] = round(min(0.65, 0.45 + min(script_count, 6) * 0.03), 2)
        reasons.append("Fixed-width 32-bit immediate commonly behaves like a literal or encoded integer/id push.")
        if first_ratio >= 0.5:
            reasons.append("Frequent prologue placement suggests the value may seed later control or widget logic.")

    if reasons:
        entry["candidate_reasons"] = reasons
    return entry


def _infer_clientscript_frontier_candidate(stats: dict[str, object]) -> dict[str, object]:
    script_count = max(int(stats["script_count"]), 1)
    switch_script_count = int(stats["switch_script_count"])
    switch_ratio = switch_script_count / script_count
    switch_case_count = int(stats["switch_case_count"])
    frontier_offsets = stats.get("frontier_offsets", [])
    frontier_instruction_indices = stats.get("frontier_instruction_indices", [])
    is_entry_frontier = bool(frontier_offsets) and bool(frontier_instruction_indices) and all(
        int(offset) == 0 for offset in frontier_offsets
    ) and all(int(index) == 0 for index in frontier_instruction_indices)
    entry: dict[str, object] = {}
    reasons: list[str] = []

    if switch_script_count and switch_ratio >= 0.75 and is_entry_frontier:
        entry["candidate_mnemonic"] = "SWITCH_DISPATCH_FRONTIER_CANDIDATE"
        entry["family"] = "control-flow"
        entry["candidate_confidence"] = round(min(0.85, 0.35 + switch_ratio * 0.2 + min(script_count, 4) * 0.05), 2)
        reasons.append("First unresolved opcode clusters in scripts that carry footer switch tables.")
        if switch_case_count:
            reasons.append(f"Supporting scripts expose {switch_case_count} total switch cases in their footers.")
    elif script_count >= 2:
        entry["candidate_mnemonic"] = "CONTROL_FLOW_FRONTIER_CANDIDATE"
        entry["family"] = "control-flow"
        entry["candidate_confidence"] = round(min(0.55, 0.2 + min(script_count, 4) * 0.08), 2)
        reasons.append("Raw opcode repeatedly appears as the first unresolved frontier across calibrated scripts.")

    if reasons:
        entry["candidate_reasons"] = reasons
    return entry


def _classify_clientscript_control_flow_consumer(step: dict[str, object]) -> str | None:
    semantic_label = str(step.get("semantic_label", ""))
    control_flow_kind = str(step.get("control_flow_kind", ""))
    if semantic_label == "SWITCH_DISPATCH_FRONTIER_CANDIDATE":
        return "switch"
    if control_flow_kind in {"branch", "branch-candidate"}:
        return "branch"
    if control_flow_kind in {"jump", "jump-candidate"}:
        return "jump"
    return None


def _infer_clientscript_producer_candidate(stats: dict[str, object]) -> dict[str, object]:
    immediate_kind = str(stats["immediate_kind"])
    occurrence_count = max(int(stats.get("occurrence_count", 0)), 1)
    control_flow_successor_count = int(stats.get("control_flow_successor_count", 0))
    if control_flow_successor_count < 2:
        return {}

    branch_successor_count = int(stats.get("branch_successor_count", 0))
    switch_successor_count = int(stats.get("switch_successor_count", 0))
    slot_fit_count = int(stats.get("slot_fit_count", 0))
    control_flow_successor_ratio = control_flow_successor_count / occurrence_count
    script_count = max(int(stats.get("script_count", 0)), 1)
    entry: dict[str, object] = {}
    reasons: list[str] = []

    if immediate_kind == "tribyte" and control_flow_successor_ratio >= 0.35:
        entry["candidate_mnemonic"] = "VAR_REFERENCE_CANDIDATE"
        entry["family"] = "state-reference"
        entry["candidate_confidence"] = round(
            min(0.82, 0.42 + min(control_flow_successor_count, 6) * 0.04 + control_flow_successor_ratio * 0.14),
            2,
        )
        reasons.append("Tribyte opcode repeatedly feeds branch or switch consumers in traced prefixes.")
        reasons.append("This shape fits CS2 state reads more closely than plain arithmetic or control flow.")
    elif (
        immediate_kind == "byte"
        and slot_fit_count >= max(2, int(control_flow_successor_count * 0.6))
        and control_flow_successor_ratio >= 0.35
    ):
        entry["candidate_mnemonic"] = "PUSH_SLOT_REFERENCE_CANDIDATE"
        entry["family"] = "stack-local"
        entry["candidate_confidence"] = round(
            min(0.78, 0.4 + min(control_flow_successor_count, 6) * 0.04 + control_flow_successor_ratio * 0.12),
            2,
        )
        reasons.append("Byte immediate usually fits local or argument slot ranges in traced producer positions.")
        reasons.append("Opcode frequently sits directly before branch or switch consumers, which fits a slot load.")
    elif immediate_kind == "int" and control_flow_successor_ratio >= 0.35:
        entry["candidate_mnemonic"] = "PUSH_INT_CANDIDATE"
        entry["family"] = "stack"
        entry["candidate_confidence"] = round(
            min(0.76, 0.38 + min(control_flow_successor_count, 8) * 0.03 + control_flow_successor_ratio * 0.12),
            2,
        )
        reasons.append("Fixed-width integer opcode repeatedly feeds branch or switch consumers in traced prefixes.")
        reasons.append("This pattern is consistent with a literal or encoded id push that seeds later control flow.")

    if not entry:
        return {}

    if branch_successor_count:
        reasons.append(f"Observed {branch_successor_count} branch-successor edges across {script_count} scripts.")
    if switch_successor_count:
        reasons.append(f"Observed {switch_successor_count} switch-successor edges across traced scripts.")
    entry["control_flow_successor_count"] = control_flow_successor_count
    entry["branch_successor_count"] = branch_successor_count
    entry["switch_successor_count"] = switch_successor_count
    entry["control_flow_successor_ratio"] = round(control_flow_successor_ratio, 2)
    if reasons:
        entry["candidate_reasons"] = reasons
    return entry


def _clientscript_frontier_kind_rank(entry: dict[str, object]) -> tuple[int, int, int, int, int, int]:
    return (
        int(entry.get("complete_trace_count", 0)),
        int(entry.get("improved_script_count", 0)),
        int(entry.get("switch_improved_script_count", 0)),
        int(entry.get("total_progress_instruction_count", 0)),
        int(entry.get("next_frontier_trace_count", 0)),
        int(entry.get("valid_trace_count", 0)),
        -int(entry.get("invalid_immediate_count", 0)),
    )


def _clientscript_frontier_kind_sort_key(entry: dict[str, object]) -> tuple[int, int, int, int, int, int, int]:
    priority = {
        "short": 4,
        "byte": 3,
        "int": 2,
        "tribyte": 1,
        "switch": 0,
    }
    return (
        *_clientscript_frontier_kind_rank(entry),
        priority.get(str(entry.get("immediate_kind", "")), -1),
    )


def _summarize_clientscript_relative_target(
    layout: ClientscriptLayout,
    trace: dict[str, object],
    *,
    step_index: int | None = None,
) -> dict[str, object] | None:
    step: dict[str, object] | None = None
    if isinstance(step_index, int):
        instruction_steps = trace.get("instruction_steps")
        if isinstance(instruction_steps, list) and 0 <= step_index < len(instruction_steps):
            candidate_step = instruction_steps[step_index]
            if isinstance(candidate_step, dict):
                step = candidate_step
    if step is None:
        candidate_step = trace.get("last_instruction")
        if isinstance(candidate_step, dict):
            step = candidate_step
    if step is None:
        return None
    if str(step.get("immediate_kind")) not in {"short", "int"}:
        return None

    next_offset = step.get("end_offset")
    if not isinstance(next_offset, int):
        return None

    target_offset = _resolve_clientscript_jump_target(step, next_offset=next_offset)
    if target_offset is None:
        return None

    instruction_offsets = {
        int(offset)
        for offset in trace.get("instruction_offsets", [])
        if isinstance(offset, int)
    }
    opcode_data_size = len(layout.opcode_data)
    direction = "forward" if target_offset > int(step["offset"]) else "backward"
    if target_offset == int(step["offset"]):
        direction = "self"
    relation = "out-of-bounds"
    if 0 <= target_offset < opcode_data_size:
        relation = "instruction-boundary" if target_offset in instruction_offsets else "in-bounds"
    elif target_offset == opcode_data_size:
        relation = "end-of-script"

    return {
        "relative_target_offset": target_offset,
        "relative_target_delta": target_offset - next_offset,
        "relative_target_direction": direction,
        "relative_target_relation": relation,
        "relative_target_in_bounds": 0 <= target_offset < opcode_data_size,
        "relative_target_hits_end": target_offset == opcode_data_size,
        "relative_target_aligns_to_instruction": target_offset in instruction_offsets,
    }


def _score_clientscript_frontier_immediate_kinds(
    layout: ClientscriptLayout,
    locked_opcode_types: dict[int, str],
    *,
    frontier_opcode: int,
    base_prefix_trace: dict[str, object],
    raw_opcode_catalog: dict[int, dict[str, object]] | None = None,
) -> dict[str, dict[str, object]]:
    base_decoded_instruction_count = int(base_prefix_trace.get("decoded_instruction_count", 0))
    scores: dict[str, dict[str, object]] = {}

    for immediate_kind in CLIENTSCRIPT_IMMEDIATE_TYPES:
        probe_types = dict(locked_opcode_types)
        probe_types[frontier_opcode] = immediate_kind
        trace = _trace_clientscript_locked_prefix(
            layout,
            probe_types,
            raw_opcode_catalog=raw_opcode_catalog,
        )
        if trace is None:
            continue

        decoded_instruction_count = int(trace.get("decoded_instruction_count", 0))
        progress_instruction_count = max(decoded_instruction_count - base_decoded_instruction_count, 0)
        frontier_reason = str(trace.get("frontier_reason", ""))
        valid_trace = not (
            trace.get("status") == "frontier"
            and frontier_reason == "invalid-locked-immediate"
        )

        entry: dict[str, object] = {
            "immediate_kind": immediate_kind,
            "trace_status": trace.get("status"),
            "frontier_reason": frontier_reason or None,
            "decoded_instruction_count": decoded_instruction_count,
            "progress_instruction_count": progress_instruction_count,
            "remaining_opcode_bytes": int(trace.get("remaining_opcode_bytes", 0)),
            "valid_trace": valid_trace,
        }
        next_frontier_opcode = trace.get("frontier_raw_opcode")
        if isinstance(next_frontier_opcode, int):
            entry["next_frontier_raw_opcode"] = next_frontier_opcode
            entry["next_frontier_raw_opcode_hex"] = trace.get("frontier_raw_opcode_hex")
        relative_target = _summarize_clientscript_relative_target(
            layout,
            trace,
            step_index=base_decoded_instruction_count,
        )
        if relative_target is not None:
            entry.update(relative_target)
        if trace.get("status") == "complete":
            terminal_instruction = trace.get("last_instruction")
            if isinstance(terminal_instruction, dict):
                terminal_raw_opcode = terminal_instruction.get("raw_opcode")
                if isinstance(terminal_raw_opcode, int):
                    entry["terminal_raw_opcode"] = terminal_raw_opcode
                    entry["terminal_raw_opcode_hex"] = f"0x{terminal_raw_opcode:04X}"
                terminal_semantic_label = terminal_instruction.get("semantic_label")
                if isinstance(terminal_semantic_label, str) and terminal_semantic_label:
                    entry["terminal_semantic_label"] = terminal_semantic_label
                terminal_semantic_family = terminal_instruction.get("semantic_family")
                if isinstance(terminal_semantic_family, str) and terminal_semantic_family:
                    entry["terminal_semantic_family"] = terminal_semantic_family
        scores[immediate_kind] = entry

    return scores


def _build_clientscript_semantic_suggestions(
    control_flow_candidates: dict[int, dict[str, object]],
    contextual_frontier_candidates: dict[int, dict[str, object]] | None = None,
) -> dict[str, dict[str, object]]:
    suggestions: dict[str, dict[str, object]] = {}

    for raw_opcode, entry in sorted(control_flow_candidates.items()):
        suggested_override = entry.get("suggested_override")
        mnemonic = entry.get("candidate_mnemonic")
        immediate_kind = entry.get("suggested_immediate_kind")
        family = entry.get("family")
        if int(entry.get("switch_script_count", 0)) <= 0 and str(mnemonic) not in {
            "JUMP_OFFSET_FRONTIER_CANDIDATE",
            "INT_STATE_GETTER_CANDIDATE",
        }:
            continue
        if not isinstance(mnemonic, str) or not mnemonic:
            continue
        if not isinstance(immediate_kind, str) or immediate_kind not in CLIENTSCRIPT_IMMEDIATE_TYPES:
            continue

        suggestion: dict[str, object] = {
            "mnemonic": mnemonic,
            "immediate_kind": immediate_kind,
        }
        if isinstance(family, str) and family:
            suggestion["family"] = family
        confidence = entry.get("suggested_immediate_kind_confidence", entry.get("candidate_confidence"))
        if isinstance(confidence, (int, float)):
            suggestion["confidence"] = float(confidence)
        reasons = entry.get("candidate_reasons")
        if isinstance(reasons, list):
            normalized_reasons = [str(reason) for reason in reasons if str(reason)]
            if normalized_reasons:
                suggestion["notes"] = " ".join(normalized_reasons)
        if isinstance(suggested_override, dict):
            for field in ("control_flow_kind", "jump_base"):
                field_value = suggested_override.get(field)
                if isinstance(field_value, str) and field_value:
                    suggestion[field] = field_value
            jump_scale = suggested_override.get("jump_scale")
            if isinstance(jump_scale, int):
                suggestion["jump_scale"] = jump_scale
        suggestions[f"0x{int(raw_opcode):04X}"] = suggestion

    if contextual_frontier_candidates:
        for raw_opcode, entry in sorted(contextual_frontier_candidates.items()):
            mnemonic = entry.get("candidate_mnemonic")
            immediate_kind = entry.get("suggested_immediate_kind")
            family = entry.get("family")
            if str(mnemonic) != "INT_STATE_GETTER_CANDIDATE":
                continue
            if not isinstance(immediate_kind, str) or immediate_kind not in CLIENTSCRIPT_IMMEDIATE_TYPES:
                continue

            suggestion: dict[str, object] = {
                "mnemonic": str(mnemonic),
                "immediate_kind": immediate_kind,
            }
            if isinstance(family, str) and family:
                suggestion["family"] = family
            confidence = entry.get("suggested_immediate_kind_confidence", entry.get("candidate_confidence"))
            if isinstance(confidence, (int, float)):
                suggestion["confidence"] = float(confidence)
            reasons = entry.get("candidate_reasons")
            if isinstance(reasons, list):
                normalized_reasons = [str(reason) for reason in reasons if str(reason)]
                if normalized_reasons:
                    suggestion["notes"] = " ".join(normalized_reasons)
            suggestions[f"0x{int(raw_opcode):04X}"] = suggestion

    return suggestions


def _augment_clientscript_locked_opcode_types(
    locked_opcode_types: dict[int, str],
    raw_opcode_catalog: dict[int, dict[str, object]],
) -> dict[int, str]:
    augmented = dict(locked_opcode_types)
    for raw_opcode, entry in raw_opcode_catalog.items():
        if not isinstance(entry, dict):
            continue
        immediate_kind = entry.get("immediate_kind", entry.get("suggested_immediate_kind"))
        if isinstance(immediate_kind, str) and immediate_kind in CLIENTSCRIPT_IMMEDIATE_TYPES:
            augmented[int(raw_opcode)] = immediate_kind
    return augmented


def _select_clientscript_contextual_state_probe(
    immediate_kind_candidates: list[dict[str, object]],
) -> tuple[dict[str, object] | None, str | None]:
    if not immediate_kind_candidates:
        return None, None

    top_candidate = immediate_kind_candidates[0]
    top_immediate_kind = str(top_candidate.get("immediate_kind", ""))
    if top_immediate_kind == "int":
        return top_candidate, None

    int_candidate = next(
        (
            candidate
            for candidate in immediate_kind_candidates
            if isinstance(candidate, dict) and str(candidate.get("immediate_kind", "")) == "int"
        ),
        None,
    )
    if int_candidate is None:
        return top_candidate, None

    top_relative_target_count = int(top_candidate.get("relative_target_count", 0))
    top_boundary_count = int(top_candidate.get("relative_target_instruction_boundary_count", 0))
    if top_relative_target_count > 0:
        if top_boundary_count > 0:
            return top_candidate, None
        if top_immediate_kind == "short":
            top_in_bounds_count = int(top_candidate.get("relative_target_in_bounds_count", 0))
            int_next_frontier_count = int(int_candidate.get("next_frontier_trace_count", 0))
            int_progress = int(int_candidate.get("total_progress_instruction_count", 0))
            if top_in_bounds_count > 0 and int_progress > 0 and int_next_frontier_count > 0:
                return int_candidate, (
                    "Selected the integer probe over a short in-bounds probe because the short target never lands on an instruction boundary while the integer probe continues into a real downstream frontier."
                )
            return top_candidate, None

    top_trace_statuses = {
        str(sample.get("trace_status"))
        for sample in top_candidate.get("trace_samples", [])
        if isinstance(sample, dict) and isinstance(sample.get("trace_status"), str)
    }
    top_is_overshoot_probe = bool(top_trace_statuses) and top_trace_statuses <= {"extra-bytes"}
    int_next_frontier_count = int(int_candidate.get("next_frontier_trace_count", 0))
    int_progress = int(int_candidate.get("total_progress_instruction_count", 0))
    top_next_frontier_count = int(top_candidate.get("next_frontier_trace_count", 0))
    top_progress = int(top_candidate.get("total_progress_instruction_count", 0))
    if top_is_overshoot_probe and int_progress > 0 and (
        int_next_frontier_count > 0 or top_next_frontier_count == 0 or top_progress >= int_progress
    ):
        return int_candidate, (
            "Selected the integer probe over a higher-ranked overshoot probe because it continues into a real downstream frontier."
        )

    return top_candidate, None


def _infer_clientscript_contextual_frontier_candidate(entry: dict[str, object]) -> dict[str, object]:
    immediate_kind_candidates = entry.get("immediate_kind_candidates")
    if not isinstance(immediate_kind_candidates, list) or not immediate_kind_candidates:
        return {}

    selected_candidate, selected_probe_reason = _select_clientscript_contextual_state_probe(immediate_kind_candidates)
    if not isinstance(selected_candidate, dict):
        return {}
    selected_immediate_kind = str(selected_candidate.get("immediate_kind", ""))
    if selected_immediate_kind != "int":
        return {}

    script_count = max(int(entry.get("script_count", 0)), 1)
    switch_prefix_count = int(entry.get("prefix_switch_dispatch_count", 0))
    prefix_push_int_count = int(entry.get("prefix_push_int_count", 0))
    previous_push_int_count = int(entry.get("previous_push_int_count", 0))
    if switch_prefix_count <= 0 or (prefix_push_int_count <= 0 and previous_push_int_count <= 0):
        return {}

    complete_trace_count = int(selected_candidate.get("complete_trace_count", 0))
    improved_script_count = int(selected_candidate.get("improved_script_count", 0))
    if improved_script_count <= 0:
        return {}

    switch_prefix_ratio = switch_prefix_count / script_count
    prefix_push_ratio = max(prefix_push_int_count, previous_push_int_count) / script_count
    confidence = round(
        min(
            0.74,
            0.38
            + switch_prefix_ratio * 0.14
            + prefix_push_ratio * 0.12
            + min(improved_script_count, 6) * 0.03
            + min(complete_trace_count, 4) * 0.02,
        ),
        2,
    )

    reasons = [
        "Downstream frontier repeatedly appears after a known switch dispatch and integer setup sequence.",
        "Best immediate-kind probe is a 32-bit integer, which fits a state or widget lookup operand.",
        "This pattern is consistent with an integer-producing state getter rather than terminal control flow.",
    ]
    if previous_push_int_count:
        reasons.append("Immediate predecessor is often a known integer push, which suggests the frontier consumes or refines integer state.")
    if selected_probe_reason is not None:
        reasons.append(selected_probe_reason)

    return {
        "candidate_mnemonic": "INT_STATE_GETTER_CANDIDATE",
        "family": "state-reader",
        "candidate_confidence": confidence,
        "candidate_reasons": reasons,
        "suggested_immediate_kind": selected_immediate_kind,
        "suggested_immediate_kind_confidence": confidence,
        "suggested_override": {
            "mnemonic": "INT_STATE_GETTER_CANDIDATE",
            "family": "state-reader",
            "immediate_kind": selected_immediate_kind,
        },
    }


def _refine_clientscript_frontier_candidate(entry: dict[str, object]) -> None:
    immediate_kind_candidates = entry.get("immediate_kind_candidates")
    if not isinstance(immediate_kind_candidates, list) or not immediate_kind_candidates:
        return
    if int(entry.get("switch_script_count", 0)) > 0:
        return

    top_candidate = immediate_kind_candidates[0]
    if str(top_candidate.get("immediate_kind")) != "short":
        return

    relative_target_count = int(top_candidate.get("relative_target_count", 0))
    in_bounds_count = int(top_candidate.get("relative_target_in_bounds_count", 0))
    boundary_count = int(top_candidate.get("relative_target_instruction_boundary_count", 0))
    improved_script_count = int(top_candidate.get("improved_script_count", 0))
    if relative_target_count <= 0 or improved_script_count <= 0 or boundary_count <= 0:
        return

    boundary_ratio = boundary_count / relative_target_count
    in_bounds_ratio = in_bounds_count / relative_target_count
    if boundary_ratio < 0.75 or in_bounds_ratio < 0.75:
        return

    reasons = [
        "Signed 16-bit immediate repeatedly advances the trace on the first unresolved opcode.",
        "Resolved targets stay inside the bytecode body and usually land on decoded instruction boundaries.",
        "This pattern fits a relative jump/branch offset more closely than a plain data operand.",
    ]
    backward_count = int(top_candidate.get("relative_target_backward_count", 0))
    forward_count = int(top_candidate.get("relative_target_forward_count", 0))
    if backward_count and forward_count:
        reasons.append("Observed both forward and backward targets, which is consistent with mixed branches and loops.")
    elif backward_count:
        reasons.append("Observed backward targets, which is consistent with loop or retry control flow.")
    elif forward_count:
        reasons.append("Observed forward targets, which is consistent with branch/goto style control flow.")

    entry["candidate_mnemonic"] = "JUMP_OFFSET_FRONTIER_CANDIDATE"
    entry["family"] = "control-flow"
    entry["candidate_confidence"] = round(
        min(
            0.82,
            0.34
            + boundary_ratio * 0.18
            + in_bounds_ratio * 0.12
            + min(improved_script_count, 4) * 0.04,
        ),
        2,
    )
    entry["candidate_reasons"] = reasons
    entry["suggested_immediate_kind"] = "short"
    entry["suggested_immediate_kind_confidence"] = entry["candidate_confidence"]
    entry["control_flow_kind"] = "branch-candidate"
    entry["jump_base"] = "next_offset"
    entry["jump_scale"] = 1
    entry["suggested_override"] = {
        "mnemonic": entry["candidate_mnemonic"],
        "family": entry["family"],
        "immediate_kind": "short",
        "control_flow_kind": "branch-candidate",
        "jump_base": "next_offset",
        "jump_scale": 1,
    }


def _refine_clientscript_switch_case_payload_candidate(entry: dict[str, object]) -> None:
    immediate_kind_candidates = entry.get("immediate_kind_candidates")
    if not isinstance(immediate_kind_candidates, list) or not immediate_kind_candidates:
        return
    if int(entry.get("switch_script_count", 0)) <= 0:
        return

    frontier_offsets_sample = entry.get("frontier_offsets_sample")
    frontier_instruction_index_sample = entry.get("frontier_instruction_index_sample")
    if not (
        isinstance(frontier_offsets_sample, list)
        and frontier_offsets_sample
        and any(int(offset) > 0 for offset in frontier_offsets_sample)
    ):
        return
    if not (
        isinstance(frontier_instruction_index_sample, list)
        and frontier_instruction_index_sample
        and any(int(index) > 0 for index in frontier_instruction_index_sample)
    ):
        return
    if int(entry.get("prefix_switch_dispatch_count", 0)) <= 0:
        return

    top_candidate = immediate_kind_candidates[0]
    if not isinstance(top_candidate, dict):
        return
    if int(top_candidate.get("improved_script_count", 0)) <= 0:
        return

    top_immediate_kind = str(top_candidate.get("immediate_kind", ""))
    if top_immediate_kind not in CLIENTSCRIPT_IMMEDIATE_TYPES or top_immediate_kind == "switch":
        return

    boundary_count = int(top_candidate.get("relative_target_instruction_boundary_count", 0))
    relative_target_count = int(top_candidate.get("relative_target_count", 0))
    if boundary_count > 0 and boundary_count >= max(1, relative_target_count // 2):
        return

    script_count = max(int(entry.get("script_count", 0)), 1)
    switch_ratio = int(entry.get("switch_script_count", 0)) / script_count
    prefix_push_int_count = int(entry.get("prefix_push_int_count", 0))
    previous_push_int_count = int(entry.get("previous_push_int_count", 0))
    next_frontier_trace_count = int(top_candidate.get("next_frontier_trace_count", 0))
    complete_trace_count = int(top_candidate.get("complete_trace_count", 0))
    max_decoded_instruction_count = int(top_candidate.get("max_decoded_instruction_count", 0))

    confidence = round(
        min(
            0.72,
            0.36
            + switch_ratio * 0.14
            + min(next_frontier_trace_count, 3) * 0.05
            + min(prefix_push_int_count + previous_push_int_count, 3) * 0.04
            + (0.04 if max_decoded_instruction_count >= 4 else 0.0)
            + (0.02 if complete_trace_count else 0.0),
        ),
        2,
    )

    reasons = [
        "Unresolved opcode appears after a recognized switch dispatch, deeper inside the case body rather than at script entry.",
        "Probe choices keep the trace moving but do not behave like another branch target or dispatcher, which fits a case payload/action opcode.",
        "This shape is more consistent with a widget-side effect, invoke, or mutator than with control-flow setup.",
    ]
    if prefix_push_int_count or previous_push_int_count:
        reasons.append("The surrounding prefix has already prepared integer state, which suggests the case-body opcode consumes or applies that state.")
    if next_frontier_trace_count:
        reasons.append("The best operand probe continues into a later frontier, so this opcode is carrying execution through the switch payload.")

    entry["candidate_mnemonic"] = "SWITCH_CASE_ACTION_CANDIDATE"
    entry["family"] = "payload-action"
    entry["candidate_confidence"] = confidence
    entry["candidate_reasons"] = reasons
    entry["suggested_immediate_kind"] = top_immediate_kind
    entry["suggested_immediate_kind_confidence"] = max(confidence, 0.58)
    entry["suggested_override"] = {
        "mnemonic": "SWITCH_CASE_ACTION_CANDIDATE",
        "family": "payload-action",
        "immediate_kind": top_immediate_kind,
    }


def _refine_clientscript_widget_mutator_candidate(entry: dict[str, object]) -> None:
    if str(entry.get("candidate_mnemonic", "")) != "SWITCH_CASE_ACTION_CANDIDATE":
        return

    prefix_widget_literal_count = int(entry.get("prefix_widget_literal_count", 0))
    previous_widget_literal_count = int(entry.get("previous_widget_literal_count", 0))
    total_widget_literal_support = prefix_widget_literal_count + previous_widget_literal_count
    if total_widget_literal_support <= 0:
        return

    confidence = round(
        min(
            0.8,
            max(float(entry.get("candidate_confidence", 0.0)), 0.58)
            + min(total_widget_literal_support, 3) * 0.05,
        ),
        2,
    )

    reasons = [
        str(reason)
        for reason in entry.get("candidate_reasons", [])
        if str(reason)
    ]
    reasons.append(
        "Prefix includes packed widget-id literals, which makes this payload opcode look more like a widget mutator or widget-targeted action than a generic case payload."
    )
    if previous_widget_literal_count:
        reasons.append("Immediate predecessor context also contains a widget-id literal, which strengthens the mutator interpretation.")

    suggested_immediate_kind = entry.get("suggested_immediate_kind")
    entry["candidate_mnemonic"] = "WIDGET_MUTATOR_CANDIDATE"
    entry["family"] = "widget-action"
    entry["candidate_confidence"] = confidence
    entry["candidate_reasons"] = reasons
    if isinstance(suggested_immediate_kind, str) and suggested_immediate_kind in CLIENTSCRIPT_IMMEDIATE_TYPES:
        entry["suggested_override"] = {
            "mnemonic": "WIDGET_MUTATOR_CANDIDATE",
            "family": "widget-action",
            "immediate_kind": suggested_immediate_kind,
        }


def _refine_clientscript_consumed_operand_payload_candidate(entry: dict[str, object]) -> None:
    if str(entry.get("candidate_mnemonic", "")) != "WIDGET_MUTATOR_CANDIDATE":
        return

    consumed_signature_sample = entry.get("consumed_operand_signature_sample")
    if not isinstance(consumed_signature_sample, list) or not consumed_signature_sample:
        return

    first_signature = consumed_signature_sample[0]
    if not isinstance(first_signature, dict):
        return
    signature = str(first_signature.get("signature", ""))
    if not signature or signature.startswith("widget"):
        return

    reasons = [
        str(reason)
        for reason in entry.get("candidate_reasons", [])
        if str(reason)
    ]
    reasons.append(
        "The precise consumed-operand window does not actually include a widget operand, so this opcode is being kept as a generic switch-case payload until stronger widget evidence appears."
    )
    entry["candidate_mnemonic"] = "SWITCH_CASE_ACTION_CANDIDATE"
    entry["family"] = "payload-action"
    entry["candidate_confidence"] = round(min(float(entry.get("candidate_confidence", 0.58)), 0.62), 2)
    entry["candidate_reasons"] = reasons
    suggested_immediate_kind = entry.get("suggested_immediate_kind")
    if isinstance(suggested_immediate_kind, str) and suggested_immediate_kind in CLIENTSCRIPT_IMMEDIATE_TYPES:
        entry["suggested_override"] = {
            "mnemonic": "SWITCH_CASE_ACTION_CANDIDATE",
            "family": "payload-action",
            "immediate_kind": suggested_immediate_kind,
        }


def _refine_clientscript_frontier_state_reader_candidate(entry: dict[str, object]) -> None:
    immediate_kind_candidates = entry.get("immediate_kind_candidates")
    if not isinstance(immediate_kind_candidates, list) or not immediate_kind_candidates:
        return
    if int(entry.get("switch_script_count", 0)) > 0:
        return

    int_candidate = next(
        (
            candidate
            for candidate in immediate_kind_candidates
            if isinstance(candidate, dict) and str(candidate.get("immediate_kind", "")) == "int"
        ),
        None,
    )
    if not isinstance(int_candidate, dict):
        return

    script_count = max(int(entry.get("script_count", 0)), 1)
    complete_trace_count = int(int_candidate.get("complete_trace_count", 0))
    max_decoded_instruction_count = int(int_candidate.get("max_decoded_instruction_count", 0))
    if script_count < 32 or complete_trace_count < max(16, script_count // 3) or max_decoded_instruction_count > 3:
        return

    frontier_offsets_sample = entry.get("frontier_offsets_sample")
    frontier_instruction_index_sample = entry.get("frontier_instruction_index_sample")
    if not (
        isinstance(frontier_offsets_sample, list)
        and frontier_offsets_sample
        and all(int(offset) == 0 for offset in frontier_offsets_sample)
    ):
        return
    if not (
        isinstance(frontier_instruction_index_sample, list)
        and frontier_instruction_index_sample
        and all(int(index) == 0 for index in frontier_instruction_index_sample)
    ):
        return

    known_terminal_semantic_count = int(int_candidate.get("known_terminal_semantic_count", 0))
    known_terminal_semantic_ratio = known_terminal_semantic_count / max(complete_trace_count, 1)
    if known_terminal_semantic_ratio < 0.55:
        return

    control_flow_terminal_count = 0
    for sample in int_candidate.get("terminal_semantic_label_sample", []):
        if not isinstance(sample, dict):
            continue
        label = str(sample.get("label", ""))
        count = int(sample.get("count", 0))
        if label in {
            "TERMINATOR_CANDIDATE",
            "JUMP_OFFSET_FRONTIER_CANDIDATE",
            "SWITCH_DISPATCH_FRONTIER_CANDIDATE",
            "CONTROL_FLOW_FRONTIER_CANDIDATE",
        }:
            control_flow_terminal_count += count
    if control_flow_terminal_count < max(8, complete_trace_count // 3):
        return

    byte_candidate = next(
        (
            candidate
            for candidate in immediate_kind_candidates
            if isinstance(candidate, dict) and str(candidate.get("immediate_kind", "")) == "byte"
        ),
        None,
    )
    byte_known_terminal_semantic_count = (
        int(byte_candidate.get("known_terminal_semantic_count", 0))
        if isinstance(byte_candidate, dict)
        else 0
    )
    if byte_known_terminal_semantic_count >= known_terminal_semantic_count:
        return

    confidence = round(
        min(
            0.84,
            0.44
            + min(script_count, 256) / 1024
            + known_terminal_semantic_ratio * 0.16
            + min(control_flow_terminal_count, 128) / 512,
        ),
        2,
    )
    entry["candidate_mnemonic"] = "INT_STATE_GETTER_CANDIDATE"
    entry["family"] = "state-reader"
    entry["candidate_confidence"] = confidence
    entry["candidate_reasons"] = [
        "32-bit probe repeatedly decodes into tiny complete scripts whose terminal opcode is already recognized as control flow or a terminator.",
        "Opcode appears at script entry across many wrapper-like scripts, which fits a getter feeding an immediate branch, switch, or return.",
        "Byte interpretation also parses structurally, but it loses downstream semantic consistency compared with the 32-bit interpretation.",
    ]
    entry["suggested_immediate_kind"] = "int"
    entry["suggested_immediate_kind_confidence"] = confidence
    entry["suggested_override"] = {
        "mnemonic": "INT_STATE_GETTER_CANDIDATE",
        "family": "state-reader",
        "immediate_kind": "int",
    }


def _promote_clientscript_control_flow_candidates(
    control_flow_candidates: dict[int, dict[str, object]],
) -> dict[int, dict[str, object]]:
    promoted: dict[int, dict[str, object]] = {}

    for raw_opcode, entry in sorted(control_flow_candidates.items()):
        mnemonic = entry.get("candidate_mnemonic")
        is_switch_candidate = int(entry.get("switch_script_count", 0)) > 0
        is_jump_candidate = (
            mnemonic == "JUMP_OFFSET_FRONTIER_CANDIDATE"
            and int(entry.get("script_count", 0)) >= 2
            and isinstance(entry.get("candidate_confidence"), (int, float))
            and float(entry["candidate_confidence"]) >= 0.7
        )
        is_widget_mutator_candidate = (
            mnemonic == "WIDGET_MUTATOR_CANDIDATE"
            and int(entry.get("switch_script_count", 0)) > 0
            and isinstance(entry.get("candidate_confidence"), (int, float))
            and float(entry["candidate_confidence"]) >= 0.62
        )
        if not is_switch_candidate and not is_jump_candidate and not is_widget_mutator_candidate:
            continue
        immediate_kind = entry.get("suggested_immediate_kind")
        family = entry.get("family")
        if not isinstance(immediate_kind, str) or immediate_kind not in CLIENTSCRIPT_IMMEDIATE_TYPES:
            continue
        if not isinstance(mnemonic, str) or not mnemonic:
            continue

        promoted_entry: dict[str, object] = {
            "mnemonic": mnemonic,
            "immediate_kind": immediate_kind,
            "status": "promoted-candidate",
            "promotion_source": "control-flow-frontier",
        }
        if isinstance(family, str) and family:
            promoted_entry["family"] = family
        confidence = entry.get("suggested_immediate_kind_confidence", entry.get("candidate_confidence"))
        if isinstance(confidence, (int, float)):
            promoted_entry["confidence"] = float(confidence)
        control_flow_kind = entry.get("control_flow_kind")
        if isinstance(control_flow_kind, str) and control_flow_kind:
            promoted_entry["control_flow_kind"] = control_flow_kind
        operand_signature_candidate = entry.get("operand_signature_candidate")
        if isinstance(operand_signature_candidate, dict) and operand_signature_candidate:
            promoted_entry["operand_signature_candidate"] = dict(operand_signature_candidate)
        stack_effect_candidate = entry.get("stack_effect_candidate")
        if isinstance(stack_effect_candidate, dict) and stack_effect_candidate:
            promoted_entry["stack_effect_candidate"] = dict(stack_effect_candidate)
        jump_base = entry.get("jump_base")
        if isinstance(jump_base, str) and jump_base:
            promoted_entry["jump_base"] = jump_base
        jump_scale = entry.get("jump_scale")
        if isinstance(jump_scale, int):
            promoted_entry["jump_scale"] = jump_scale
        promoted[int(raw_opcode)] = promoted_entry

    return promoted


def _merge_clientscript_control_flow_candidate_stage(
    combined: dict[int, dict[str, object]],
    candidates: dict[int, dict[str, object]],
    *,
    stage_name: str,
) -> None:
    stage_flag = f"{stage_name.replace('-', '_')}_observed"

    for raw_opcode, entry in candidates.items():
        if not isinstance(entry, dict):
            continue
        normalized_opcode = int(raw_opcode)
        if normalized_opcode in combined:
            combined[normalized_opcode][stage_flag] = True
            continue

        merged_entry = dict(entry)
        merged_entry["analysis_stage"] = stage_name
        combined[normalized_opcode] = merged_entry


def _combine_clientscript_control_flow_candidates(
    initial_candidates: dict[int, dict[str, object]],
    post_contextual_candidates: dict[int, dict[str, object]],
    recursive_candidates: dict[int, dict[str, object]] | None = None,
) -> dict[int, dict[str, object]]:
    combined: dict[int, dict[str, object]] = {}

    _merge_clientscript_control_flow_candidate_stage(combined, initial_candidates, stage_name="initial")
    _merge_clientscript_control_flow_candidate_stage(
        combined,
        post_contextual_candidates,
        stage_name="post-contextual",
    )
    if recursive_candidates:
        _merge_clientscript_control_flow_candidate_stage(
            combined,
            recursive_candidates,
            stage_name="recursive",
        )

    return combined


def _promote_clientscript_contextual_frontier_candidates(
    contextual_frontier_candidates: dict[int, dict[str, object]],
) -> dict[int, dict[str, object]]:
    promoted: dict[int, dict[str, object]] = {}

    for raw_opcode, entry in sorted(contextual_frontier_candidates.items()):
        mnemonic = entry.get("candidate_mnemonic")
        if mnemonic != "INT_STATE_GETTER_CANDIDATE":
            continue
        confidence = entry.get("suggested_immediate_kind_confidence", entry.get("candidate_confidence"))
        immediate_kind = entry.get("suggested_immediate_kind")
        family = entry.get("family")
        if not isinstance(confidence, (int, float)) or float(confidence) < 0.58:
            continue
        if not isinstance(immediate_kind, str) or immediate_kind not in CLIENTSCRIPT_IMMEDIATE_TYPES:
            continue
        promoted_entry: dict[str, object] = {
            "mnemonic": str(mnemonic),
            "immediate_kind": immediate_kind,
            "status": "promoted-candidate",
            "promotion_source": "contextual-frontier",
            "confidence": float(confidence),
        }
        if isinstance(family, str) and family:
            promoted_entry["family"] = family
        promoted[int(raw_opcode)] = promoted_entry

    return promoted


def _merge_clientscript_catalog_entry(
    catalog: dict[int, dict[str, object]],
    raw_opcode: int,
    entry: dict[str, object],
) -> None:
    existing_entry = catalog.get(raw_opcode)
    if existing_entry is None:
        catalog[raw_opcode] = dict(entry)
        return
    merged_entry = dict(entry)
    merged_entry.update(existing_entry)
    catalog[raw_opcode] = merged_entry


def _resolve_clientscript_contextual_frontier_passes(
    connection: sqlite3.Connection,
    *,
    locked_opcode_types: dict[int, str],
    raw_opcode_catalog: dict[int, dict[str, object]],
    include_keys: list[int],
    max_decoded_bytes: int | None,
    sample_limit: int = DEFAULT_CLIENTSCRIPT_CALIBRATION_SAMPLE,
    max_passes: int = 3,
) -> tuple[
    dict[int, dict[str, object]],
    dict[str, object],
    dict[int, dict[str, object]],
    dict[int, str],
    dict[int, dict[str, object]],
]:
    merged_candidates: dict[int, dict[str, object]] = {}
    merged_promoted: dict[int, dict[str, object]] = {}
    effective_locked_opcode_types = dict(locked_opcode_types)
    effective_opcode_catalog = {
        int(raw_opcode): dict(entry)
        for raw_opcode, entry in raw_opcode_catalog.items()
        if isinstance(entry, dict)
    }
    pass_summaries: list[dict[str, object]] = []

    for pass_index in range(1, max_passes + 1):
        candidates, summary = _build_clientscript_contextual_frontier_candidates(
            connection,
            locked_opcode_types=effective_locked_opcode_types,
            raw_opcode_catalog=effective_opcode_catalog,
            include_keys=include_keys,
            max_decoded_bytes=max_decoded_bytes,
            sample_limit=sample_limit,
        )
        promoted = _promote_clientscript_contextual_frontier_candidates(candidates)

        new_candidate_count = 0
        for raw_opcode, entry in candidates.items():
            if raw_opcode not in merged_candidates:
                new_candidate_count += 1
            merged_candidates[raw_opcode] = dict(entry)
            _merge_clientscript_catalog_entry(effective_opcode_catalog, raw_opcode, entry)

        new_promotion_count = 0
        for raw_opcode, promoted_entry in promoted.items():
            if raw_opcode not in merged_promoted:
                new_promotion_count += 1
            merged_promoted[raw_opcode] = dict(promoted_entry)
            _merge_clientscript_catalog_entry(effective_opcode_catalog, raw_opcode, promoted_entry)

        effective_locked_opcode_types = _augment_clientscript_locked_opcode_types(
            effective_locked_opcode_types,
            effective_opcode_catalog,
        )

        pass_summary = dict(summary)
        pass_summary["pass_index"] = pass_index
        pass_summary["new_candidate_count"] = new_candidate_count
        pass_summary["new_promotion_count"] = new_promotion_count
        pass_summary["promoted_opcode_sample"] = [
            f"0x{raw_opcode:04X}"
            for raw_opcode in sorted(promoted)[:12]
        ]
        pass_summaries.append(pass_summary)

        if new_candidate_count <= 0 and new_promotion_count <= 0:
            break

    summary = {
        "frontier_opcode_count": len(merged_candidates),
        "promoted_opcode_count": len(merged_promoted),
        "pass_count": len(pass_summaries),
        "pass_summaries": pass_summaries,
        "catalog_sample": sorted(
            merged_candidates.values(),
            key=lambda entry: (
                -int(entry.get("prefix_switch_dispatch_count", 0)),
                -int(entry.get("script_count", 0)),
                int(entry["raw_opcode"]),
            ),
        )[:24],
    }
    if pass_summaries:
        summary["frontier_script_count"] = max(
            int(pass_summary.get("frontier_script_count", 0))
            for pass_summary in pass_summaries
        )
    else:
        summary["frontier_script_count"] = 0

    return (
        merged_candidates,
        summary,
        merged_promoted,
        effective_locked_opcode_types,
        effective_opcode_catalog,
    )


def _build_clientscript_control_flow_candidates(
    connection: sqlite3.Connection,
    *,
    locked_opcode_types: dict[int, str],
    semantic_overrides: dict[int, dict[str, object]],
    raw_opcode_catalog: dict[int, dict[str, object]] | None = None,
    include_keys: list[int],
    max_decoded_bytes: int | None,
    sample_limit: int = DEFAULT_CLIENTSCRIPT_CALIBRATION_SAMPLE,
) -> tuple[dict[int, dict[str, object]], dict[str, object]]:
    candidates = _collect_clientscript_calibration_candidates(
        connection,
        include_keys=include_keys,
        max_decoded_bytes=max_decoded_bytes,
        sample_limit=sample_limit,
    )
    if not candidates or not locked_opcode_types:
        return {}, {
            "frontier_opcode_count": 0,
            "frontier_script_count": 0,
            "switch_frontier_script_count": 0,
            "catalog_sample": [],
        }

    frontier_stats_by_opcode: dict[int, dict[str, object]] = {}
    frontier_script_count = 0
    switch_frontier_script_count = 0

    for key, layout in candidates:
        prefix_trace = _trace_clientscript_locked_prefix(
            layout,
            locked_opcode_types,
            raw_opcode_catalog=raw_opcode_catalog,
        )
        if prefix_trace is None or prefix_trace.get("status") != "frontier":
            continue
        raw_opcode = prefix_trace.get("frontier_raw_opcode")
        if not isinstance(raw_opcode, int):
            continue

        instruction_steps = prefix_trace.get("instruction_steps")
        if not isinstance(instruction_steps, list):
            instruction_steps = []
        prefix_stack_summary = _summarize_clientscript_prefix_stack_state(instruction_steps)
        prefix_switch_dispatch_count = sum(
            1
            for step in instruction_steps
            if isinstance(step, dict) and str(step.get("semantic_label", "")) == "SWITCH_DISPATCH_FRONTIER_CANDIDATE"
        )
        prefix_push_int_count = sum(
            1
            for step in instruction_steps
            if isinstance(step, dict) and str(step.get("semantic_label", "")) in {"PUSH_INT_CANDIDATE", "PUSH_INT_LITERAL"}
        )
        prefix_widget_literal_count = sum(
            1
            for step in instruction_steps
            if isinstance(step, dict) and _is_clientscript_widget_literal_step(step)
        )
        last_step = instruction_steps[-1] if instruction_steps else None
        previous_label = (
            str(last_step.get("semantic_label"))
            if isinstance(last_step, dict) and isinstance(last_step.get("semantic_label"), str)
            else None
        )
        previous_widget_literal = 1 if isinstance(last_step, dict) and _is_clientscript_widget_literal_step(last_step) else 0

        frontier_script_count += 1
        if layout.switch_table_count:
            switch_frontier_script_count += 1

        stats = frontier_stats_by_opcode.setdefault(
            raw_opcode,
            {
                "script_count": 0,
                "switch_script_count": 0,
                "switch_case_count": 0,
                "reason_counts": {},
                "frontier_offsets": [],
                "frontier_instruction_indices": [],
                "previous_raw_opcode_counts": {},
                "previous_semantic_label_counts": {},
                "key_samples": [],
                "script_samples": [],
                "immediate_kind_scores": {},
                "prefix_switch_dispatch_count": 0,
                "prefix_push_int_count": 0,
                "prefix_widget_literal_count": 0,
                "previous_push_int_count": 0,
                "previous_widget_literal_count": 0,
                "prefix_widget_stack_script_count": 0,
                "prefix_state_stack_script_count": 0,
                "prefix_secondary_int_script_count": 0,
                "prefix_string_operand_script_count": 0,
                "prefix_operand_signature_counts": {},
            },
        )
        stats["script_count"] = int(stats["script_count"]) + 1
        if layout.switch_table_count:
            stats["switch_script_count"] = int(stats["switch_script_count"]) + 1
            stats["switch_case_count"] = int(stats["switch_case_count"]) + layout.switch_case_count
        if prefix_switch_dispatch_count:
            stats["prefix_switch_dispatch_count"] = int(stats["prefix_switch_dispatch_count"]) + 1
        if prefix_push_int_count:
            stats["prefix_push_int_count"] = int(stats["prefix_push_int_count"]) + 1
        if prefix_widget_literal_count:
            stats["prefix_widget_literal_count"] = int(stats["prefix_widget_literal_count"]) + 1
        if previous_label in {"PUSH_INT_CANDIDATE", "PUSH_INT_LITERAL", "INT_STATE_GETTER_CANDIDATE"}:
            stats["previous_push_int_count"] = int(stats["previous_push_int_count"]) + 1
        if previous_widget_literal:
            stats["previous_widget_literal_count"] = int(stats["previous_widget_literal_count"]) + 1
        if int(prefix_stack_summary.get("prefix_widget_stack_count", 0)) > 0:
            stats["prefix_widget_stack_script_count"] = int(stats["prefix_widget_stack_script_count"]) + 1
        if int(prefix_stack_summary.get("prefix_state_stack_count", 0)) > 0:
            stats["prefix_state_stack_script_count"] = int(stats["prefix_state_stack_script_count"]) + 1
        if (
            int(prefix_stack_summary.get("prefix_state_stack_count", 0)) > 0
            or int(prefix_stack_summary.get("prefix_int_literal_stack_count", 0)) > 0
            or int(prefix_stack_summary.get("prefix_symbolic_int_stack_count", 0)) > 0
            or int(prefix_stack_summary.get("prefix_widget_stack_count", 0)) > 1
        ):
            stats["prefix_secondary_int_script_count"] = int(stats["prefix_secondary_int_script_count"]) + 1
        if int(prefix_stack_summary.get("prefix_string_stack_count", 0)) > 0:
            stats["prefix_string_operand_script_count"] = int(stats["prefix_string_operand_script_count"]) + 1
        operand_signature = prefix_stack_summary.get("prefix_operand_signature")
        if isinstance(operand_signature, str) and operand_signature:
            signature_counts = stats["prefix_operand_signature_counts"]
            signature_counts[operand_signature] = int(signature_counts.get(operand_signature, 0)) + 1

        reason = str(prefix_trace["frontier_reason"])
        reason_counts = stats["reason_counts"]
        reason_counts[reason] = int(reason_counts.get(reason, 0)) + 1

        frontier_offset = int(prefix_trace["frontier_offset"])
        frontier_instruction_index = int(prefix_trace["frontier_instruction_index"])
        if frontier_offset not in stats["frontier_offsets"] and len(stats["frontier_offsets"]) < 8:
            stats["frontier_offsets"].append(frontier_offset)
        if (
            frontier_instruction_index not in stats["frontier_instruction_indices"]
            and len(stats["frontier_instruction_indices"]) < 8
        ):
            stats["frontier_instruction_indices"].append(frontier_instruction_index)

        previous_raw_opcode = prefix_trace.get("previous_raw_opcode")
        if isinstance(previous_raw_opcode, int):
            previous_counts = stats["previous_raw_opcode_counts"]
            previous_counts[previous_raw_opcode] = int(previous_counts.get(previous_raw_opcode, 0)) + 1
        if previous_label:
            previous_label_counts = stats["previous_semantic_label_counts"]
            previous_label_counts[previous_label] = int(previous_label_counts.get(previous_label, 0)) + 1

        if len(stats["key_samples"]) < 8:
            stats["key_samples"].append(int(key))
        if len(stats["script_samples"]) < 8:
            stats["script_samples"].append(
                {
                    "key": int(key),
                    "instruction_count": layout.instruction_count,
                    "switch_table_count": layout.switch_table_count,
                    "switch_case_count": layout.switch_case_count,
                    "frontier_reason": reason,
                    "frontier_offset": frontier_offset,
                    "frontier_instruction_index": frontier_instruction_index,
                    "decoded_prefix_instruction_count": int(prefix_trace["decoded_instruction_count"]),
                    "previous_raw_opcode_hex": prefix_trace.get("previous_raw_opcode_hex"),
                    "previous_semantic_label": previous_label,
                    "prefix_switch_dispatch_count": prefix_switch_dispatch_count,
                    "prefix_push_int_count": prefix_push_int_count,
                    "prefix_widget_literal_count": prefix_widget_literal_count,
                    "previous_widget_literal": bool(previous_widget_literal),
                    "prefix_operand_signature": prefix_stack_summary.get("prefix_operand_signature"),
                    "prefix_int_stack_sample": prefix_stack_summary.get("prefix_int_stack_sample"),
                    "prefix_string_stack_sample": prefix_stack_summary.get("prefix_string_stack_sample"),
                    "prefix_trace_sample": [
                        {
                            "raw_opcode_hex": str(step.get("raw_opcode_hex")),
                            "semantic_label": step.get("semantic_label"),
                            "immediate_kind": step.get("immediate_kind"),
                        }
                        for step in instruction_steps[-6:]
                        if isinstance(step, dict)
                    ],
                }
            )

        kind_scores = _score_clientscript_frontier_immediate_kinds(
            layout,
            locked_opcode_types,
            frontier_opcode=raw_opcode,
            base_prefix_trace=prefix_trace,
            raw_opcode_catalog=raw_opcode_catalog,
        )
        for immediate_kind, kind_score in kind_scores.items():
            kind_stats = stats["immediate_kind_scores"].setdefault(
                immediate_kind,
                {
                    "script_count": 0,
                    "switch_script_count": 0,
                    "valid_trace_count": 0,
                    "invalid_immediate_count": 0,
                    "complete_trace_count": 0,
                    "improved_script_count": 0,
                    "switch_improved_script_count": 0,
                    "total_decoded_instruction_count": 0,
                    "total_progress_instruction_count": 0,
                    "max_decoded_instruction_count": 0,
                    "next_frontier_trace_count": 0,
                    "next_frontier_counts": {},
                    "relative_target_count": 0,
                    "relative_target_in_bounds_count": 0,
                    "relative_target_instruction_boundary_count": 0,
                    "relative_target_terminal_count": 0,
                    "relative_target_forward_count": 0,
                    "relative_target_backward_count": 0,
                    "relative_target_self_count": 0,
                    "known_terminal_semantic_count": 0,
                    "terminal_raw_opcode_counts": {},
                    "terminal_semantic_label_counts": {},
                    "relative_target_samples": [],
                    "trace_samples": [],
                },
            )
            kind_stats["script_count"] = int(kind_stats["script_count"]) + 1
            if layout.switch_table_count:
                kind_stats["switch_script_count"] = int(kind_stats["switch_script_count"]) + 1
            if bool(kind_score["valid_trace"]):
                kind_stats["valid_trace_count"] = int(kind_stats["valid_trace_count"]) + 1
            else:
                kind_stats["invalid_immediate_count"] = int(kind_stats["invalid_immediate_count"]) + 1
            if kind_score.get("trace_status") == "complete":
                kind_stats["complete_trace_count"] = int(kind_stats["complete_trace_count"]) + 1
                terminal_raw_opcode = kind_score.get("terminal_raw_opcode")
                if isinstance(terminal_raw_opcode, int):
                    terminal_raw_opcode_counts = kind_stats["terminal_raw_opcode_counts"]
                    terminal_raw_opcode_counts[terminal_raw_opcode] = int(
                        terminal_raw_opcode_counts.get(terminal_raw_opcode, 0)
                    ) + 1
                terminal_semantic_label = kind_score.get("terminal_semantic_label")
                if isinstance(terminal_semantic_label, str) and terminal_semantic_label:
                    kind_stats["known_terminal_semantic_count"] = (
                        int(kind_stats["known_terminal_semantic_count"]) + 1
                    )
                    terminal_semantic_label_counts = kind_stats["terminal_semantic_label_counts"]
                    terminal_semantic_label_counts[terminal_semantic_label] = int(
                        terminal_semantic_label_counts.get(terminal_semantic_label, 0)
                    ) + 1

            progress_instruction_count = int(kind_score["progress_instruction_count"])
            if progress_instruction_count > 0:
                kind_stats["improved_script_count"] = int(kind_stats["improved_script_count"]) + 1
                if layout.switch_table_count:
                    kind_stats["switch_improved_script_count"] = int(kind_stats["switch_improved_script_count"]) + 1
            kind_stats["total_decoded_instruction_count"] = (
                int(kind_stats["total_decoded_instruction_count"])
                + int(kind_score["decoded_instruction_count"])
            )
            kind_stats["total_progress_instruction_count"] = (
                int(kind_stats["total_progress_instruction_count"]) + progress_instruction_count
            )
            kind_stats["max_decoded_instruction_count"] = max(
                int(kind_stats["max_decoded_instruction_count"]),
                int(kind_score["decoded_instruction_count"]),
            )
            next_frontier_raw_opcode = kind_score.get("next_frontier_raw_opcode")
            if isinstance(next_frontier_raw_opcode, int):
                kind_stats["next_frontier_trace_count"] = int(kind_stats["next_frontier_trace_count"]) + 1
                next_frontier_counts = kind_stats["next_frontier_counts"]
                next_frontier_counts[next_frontier_raw_opcode] = int(
                    next_frontier_counts.get(next_frontier_raw_opcode, 0)
                ) + 1
            relative_target_offset = kind_score.get("relative_target_offset")
            if isinstance(relative_target_offset, int):
                kind_stats["relative_target_count"] = int(kind_stats["relative_target_count"]) + 1
                if bool(kind_score.get("relative_target_in_bounds")):
                    kind_stats["relative_target_in_bounds_count"] = (
                        int(kind_stats["relative_target_in_bounds_count"]) + 1
                    )
                if bool(kind_score.get("relative_target_aligns_to_instruction")):
                    kind_stats["relative_target_instruction_boundary_count"] = (
                        int(kind_stats["relative_target_instruction_boundary_count"]) + 1
                    )
                if bool(kind_score.get("relative_target_hits_end")):
                    kind_stats["relative_target_terminal_count"] = (
                        int(kind_stats["relative_target_terminal_count"]) + 1
                    )
                direction = str(kind_score.get("relative_target_direction", ""))
                if direction == "forward":
                    kind_stats["relative_target_forward_count"] = int(kind_stats["relative_target_forward_count"]) + 1
                elif direction == "backward":
                    kind_stats["relative_target_backward_count"] = int(kind_stats["relative_target_backward_count"]) + 1
                elif direction == "self":
                    kind_stats["relative_target_self_count"] = int(kind_stats["relative_target_self_count"]) + 1
                if len(kind_stats["relative_target_samples"]) < 6:
                    kind_stats["relative_target_samples"].append(
                        {
                            "key": int(key),
                            "target_offset": relative_target_offset,
                            "target_delta": int(kind_score.get("relative_target_delta", 0)),
                            "target_relation": kind_score.get("relative_target_relation"),
                            "target_direction": kind_score.get("relative_target_direction"),
                        }
                    )
            if len(kind_stats["trace_samples"]) < 6:
                kind_stats["trace_samples"].append(
                    {
                        "key": int(key),
                        "trace_status": kind_score.get("trace_status"),
                        "frontier_reason": kind_score.get("frontier_reason"),
                        "decoded_instruction_count": int(kind_score["decoded_instruction_count"]),
                        "progress_instruction_count": progress_instruction_count,
                        "next_frontier_raw_opcode_hex": kind_score.get("next_frontier_raw_opcode_hex"),
                    }
                )

    catalog: dict[int, dict[str, object]] = {}
    for raw_opcode, stats in frontier_stats_by_opcode.items():
        entry: dict[str, object] = {
            "raw_opcode": raw_opcode,
            "raw_opcode_hex": f"0x{raw_opcode:04X}",
            "script_count": stats["script_count"],
            "switch_script_count": stats["switch_script_count"],
            "switch_script_ratio": round(
                int(stats["switch_script_count"]) / max(int(stats["script_count"]), 1),
                4,
            ),
            "switch_case_count": stats["switch_case_count"],
            "frontier_offsets_sample": stats["frontier_offsets"],
            "frontier_instruction_index_sample": stats["frontier_instruction_indices"],
            "reason_counts": stats["reason_counts"],
            "key_sample": stats["key_samples"],
            "script_samples": stats["script_samples"],
        }
        immediate_kind_candidates = [
            {
                "immediate_kind": immediate_kind,
                "script_count": kind_stats["script_count"],
                "switch_script_count": kind_stats["switch_script_count"],
                "valid_trace_count": kind_stats["valid_trace_count"],
                "invalid_immediate_count": kind_stats["invalid_immediate_count"],
                "complete_trace_count": kind_stats["complete_trace_count"],
                "improved_script_count": kind_stats["improved_script_count"],
                "switch_improved_script_count": kind_stats["switch_improved_script_count"],
                "total_decoded_instruction_count": kind_stats["total_decoded_instruction_count"],
                "total_progress_instruction_count": kind_stats["total_progress_instruction_count"],
                "max_decoded_instruction_count": kind_stats["max_decoded_instruction_count"],
                "next_frontier_trace_count": kind_stats["next_frontier_trace_count"],
                "relative_target_count": kind_stats["relative_target_count"],
                "relative_target_in_bounds_count": kind_stats["relative_target_in_bounds_count"],
                "relative_target_instruction_boundary_count": kind_stats["relative_target_instruction_boundary_count"],
                "relative_target_terminal_count": kind_stats["relative_target_terminal_count"],
                "relative_target_forward_count": kind_stats["relative_target_forward_count"],
                "relative_target_backward_count": kind_stats["relative_target_backward_count"],
                "relative_target_self_count": kind_stats["relative_target_self_count"],
                "known_terminal_semantic_count": kind_stats["known_terminal_semantic_count"],
                "next_frontier_sample": [
                    {
                        "raw_opcode": next_frontier_opcode,
                        "raw_opcode_hex": f"0x{next_frontier_opcode:04X}",
                        "count": count,
                    }
                    for next_frontier_opcode, count in sorted(
                        kind_stats["next_frontier_counts"].items(),
                        key=lambda item: (-int(item[1]), int(item[0])),
                    )[:6]
                ],
                "terminal_raw_opcode_sample": [
                    {
                        "raw_opcode": terminal_raw_opcode,
                        "raw_opcode_hex": f"0x{terminal_raw_opcode:04X}",
                        "count": count,
                    }
                    for terminal_raw_opcode, count in sorted(
                        kind_stats["terminal_raw_opcode_counts"].items(),
                        key=lambda item: (-int(item[1]), int(item[0])),
                    )[:6]
                ],
                "terminal_semantic_label_sample": [
                    {
                        "label": label,
                        "count": count,
                    }
                    for label, count in sorted(
                        kind_stats["terminal_semantic_label_counts"].items(),
                        key=lambda item: (-int(item[1]), str(item[0])),
                    )[:6]
                ],
                "relative_target_sample": kind_stats["relative_target_samples"],
                "trace_samples": kind_stats["trace_samples"],
            }
            for immediate_kind, kind_stats in stats["immediate_kind_scores"].items()
        ]
        immediate_kind_candidates.sort(key=_clientscript_frontier_kind_sort_key, reverse=True)
        if immediate_kind_candidates:
            entry["immediate_kind_candidates"] = immediate_kind_candidates
        previous_counts = stats["previous_raw_opcode_counts"]
        if previous_counts:
            entry["previous_raw_opcode_sample"] = [
                {
                    "raw_opcode": previous_raw_opcode,
                    "raw_opcode_hex": f"0x{previous_raw_opcode:04X}",
                    "count": count,
                }
                for previous_raw_opcode, count in sorted(
                    previous_counts.items(),
                    key=lambda item: (-int(item[1]), int(item[0])),
                )[:6]
            ]
        previous_label_counts = stats["previous_semantic_label_counts"]
        if previous_label_counts:
            entry["previous_semantic_label_sample"] = [
                {
                    "label": label,
                    "count": count,
                }
                for label, count in sorted(
                    previous_label_counts.items(),
                    key=lambda item: (-int(item[1]), str(item[0])),
                )[:8]
            ]
        if int(stats["prefix_switch_dispatch_count"]):
            entry["prefix_switch_dispatch_count"] = int(stats["prefix_switch_dispatch_count"])
        if int(stats["prefix_push_int_count"]):
            entry["prefix_push_int_count"] = int(stats["prefix_push_int_count"])
        if int(stats["prefix_widget_literal_count"]):
            entry["prefix_widget_literal_count"] = int(stats["prefix_widget_literal_count"])
        if int(stats["previous_push_int_count"]):
            entry["previous_push_int_count"] = int(stats["previous_push_int_count"])
        if int(stats["previous_widget_literal_count"]):
            entry["previous_widget_literal_count"] = int(stats["previous_widget_literal_count"])
        if int(stats["prefix_widget_stack_script_count"]):
            entry["prefix_widget_stack_script_count"] = int(stats["prefix_widget_stack_script_count"])
        if int(stats["prefix_state_stack_script_count"]):
            entry["prefix_state_stack_script_count"] = int(stats["prefix_state_stack_script_count"])
        if int(stats["prefix_secondary_int_script_count"]):
            entry["prefix_secondary_int_script_count"] = int(stats["prefix_secondary_int_script_count"])
        if int(stats["prefix_string_operand_script_count"]):
            entry["prefix_string_operand_script_count"] = int(stats["prefix_string_operand_script_count"])
        prefix_operand_signature_counts = stats["prefix_operand_signature_counts"]
        if prefix_operand_signature_counts:
            entry["prefix_operand_signature_sample"] = [
                {
                    "signature": signature,
                    "count": count,
                }
                for signature, count in sorted(
                    prefix_operand_signature_counts.items(),
                    key=lambda item: (-int(item[1]), str(item[0])),
                )[:6]
            ]

        entry.update(_infer_clientscript_frontier_candidate(stats))
        if immediate_kind_candidates:
            top_candidate = immediate_kind_candidates[0]
            second_candidate = immediate_kind_candidates[1] if len(immediate_kind_candidates) > 1 else None
            top_key = _clientscript_frontier_kind_rank(top_candidate)
            second_key = _clientscript_frontier_kind_rank(second_candidate) if second_candidate else None
            if (
                int(top_candidate["improved_script_count"]) > 0
                and (second_key is None or top_key > second_key)
            ):
                entry["suggested_immediate_kind"] = top_candidate["immediate_kind"]
                confidence = min(
                    0.9,
                    0.35
                    + min(int(top_candidate["improved_script_count"]), 4) * 0.08
                    + min(int(top_candidate["total_progress_instruction_count"]), 16) * 0.02,
                )
                if isinstance(entry.get("candidate_confidence"), (int, float)):
                    confidence = min(0.9, confidence + float(entry["candidate_confidence"]) * 0.2)
                entry["suggested_immediate_kind_confidence"] = round(confidence, 2)
                entry["suggested_override"] = {
                    **(
                        {"mnemonic": entry["candidate_mnemonic"]}
                        if isinstance(entry.get("candidate_mnemonic"), str)
                        else {}
                    ),
                    **({"family": entry["family"]} if isinstance(entry.get("family"), str) else {}),
                    "immediate_kind": top_candidate["immediate_kind"],
                }
        _refine_clientscript_frontier_candidate(entry)
        _refine_clientscript_switch_case_payload_candidate(entry)
        _refine_clientscript_widget_mutator_candidate(entry)
        _refine_clientscript_frontier_state_reader_candidate(entry)
        override = semantic_overrides.get(raw_opcode)
        if override:
            entry.update(override)
            entry["override"] = True
        operand_signature_candidate = _infer_clientscript_widget_operand_signature(entry)
        if operand_signature_candidate is not None:
            entry["operand_signature_candidate"] = operand_signature_candidate
        stack_effect_candidate = _infer_clientscript_stack_effect(entry)
        if stack_effect_candidate is not None:
            entry["stack_effect_candidate"] = stack_effect_candidate
        consumed_operand_summary = _summarize_clientscript_consumed_operand_window(entry)
        if consumed_operand_summary:
            entry.update(consumed_operand_summary)
            _refine_clientscript_consumed_operand_payload_candidate(entry)
            operand_signature_candidate = _infer_clientscript_widget_operand_signature(entry)
            if operand_signature_candidate is not None:
                entry["operand_signature_candidate"] = operand_signature_candidate
            else:
                entry.pop("operand_signature_candidate", None)
            stack_effect_candidate = _infer_clientscript_stack_effect(entry)
            if stack_effect_candidate is not None:
                entry["stack_effect_candidate"] = stack_effect_candidate
            else:
                entry.pop("stack_effect_candidate", None)
        catalog[raw_opcode] = entry

    ranked_sample = sorted(
        catalog.values(),
        key=lambda entry: (
            -int(entry["switch_script_count"]),
            -int(entry["script_count"]),
            int(entry["raw_opcode"]),
        ),
    )[:24]
    summary = {
        "frontier_opcode_count": len(catalog),
        "frontier_script_count": frontier_script_count,
        "switch_frontier_script_count": switch_frontier_script_count,
        "catalog_sample": ranked_sample,
    }
    return catalog, summary


def _build_clientscript_opcode_catalog(
    connection: sqlite3.Connection,
    *,
    locked_opcode_types: dict[int, str],
    semantic_overrides: dict[int, dict[str, object]],
    include_keys: list[int],
    max_decoded_bytes: int | None,
    sample_limit: int = DEFAULT_CLIENTSCRIPT_CALIBRATION_SAMPLE,
) -> tuple[dict[int, dict[str, object]], dict[str, object]]:
    candidates = _collect_clientscript_calibration_candidates(
        connection,
        include_keys=include_keys,
        max_decoded_bytes=max_decoded_bytes,
        sample_limit=sample_limit,
    )
    possible_types = {
        raw_opcode: {immediate_kind}
        for raw_opcode, immediate_kind in locked_opcode_types.items()
    }
    stats_by_opcode: dict[int, dict[str, object]] = {}
    parsed_script_count = 0

    for _key, layout in candidates:
        solution = _solve_clientscript_disassembly(
            layout.opcode_data,
            layout.instruction_count,
            possible_types=possible_types,
        )
        steps = solution.get("selected_steps")
        if not steps or solution["bailed"] or solution["solution_count"] != 1:
            continue
        parsed_script_count += 1
        seen_in_script: set[int] = set()
        max_slot = max(
            layout.local_int_count,
            layout.local_string_count,
            layout.local_long_count,
            layout.int_argument_count,
            layout.string_argument_count,
            layout.long_argument_count,
        )
        for index, step in enumerate(steps):
            raw_opcode = int(step["raw_opcode"])
            if raw_opcode not in locked_opcode_types:
                continue
            stats = stats_by_opcode.setdefault(
                raw_opcode,
                {
                    "immediate_kind": str(step["immediate_kind"]),
                    "occurrence_count": 0,
                    "script_count": 0,
                    "first_count": 0,
                    "last_count": 0,
                    "zero_count": 0,
                    "slot_fit_count": 0,
                    "sample_values": [],
                    "switch_subtype_counts": {},
                    "reference_source_counts": {},
                },
            )
            stats["occurrence_count"] = int(stats["occurrence_count"]) + 1
            if index == 0:
                stats["first_count"] = int(stats["first_count"]) + 1
            if index == len(steps) - 1:
                stats["last_count"] = int(stats["last_count"]) + 1

            immediate_value = step.get("immediate_value")
            if immediate_value == 0:
                stats["zero_count"] = int(stats["zero_count"]) + 1
            if (
                str(step["immediate_kind"]) == "byte"
                and isinstance(immediate_value, int)
                and immediate_value < max_slot
            ):
                stats["slot_fit_count"] = int(stats["slot_fit_count"]) + 1

            sample_values = stats["sample_values"]
            sampled_value = _sample_clientscript_immediate_value(immediate_value)
            if sampled_value not in sample_values and len(sample_values) < 8:
                sample_values.append(sampled_value)

            if str(step["immediate_kind"]) == "switch":
                subtype_counts = stats["switch_subtype_counts"]
                subtype = int(step.get("switch_subtype", -1))
                subtype_counts[subtype] = int(subtype_counts.get(subtype, 0)) + 1
            if str(step["immediate_kind"]) == "tribyte" and isinstance(immediate_value, int):
                source_id = (immediate_value >> 16) & 0xFF
                source_counts = stats["reference_source_counts"]
                source_counts[source_id] = int(source_counts.get(source_id, 0)) + 1

            seen_in_script.add(raw_opcode)

        for raw_opcode in seen_in_script:
            stats_by_opcode[raw_opcode]["script_count"] = int(stats_by_opcode[raw_opcode]["script_count"]) + 1

    catalog: dict[int, dict[str, object]] = {}
    for raw_opcode, stats in stats_by_opcode.items():
        entry: dict[str, object] = {
            "raw_opcode": raw_opcode,
            "raw_opcode_hex": f"0x{raw_opcode:04X}",
            "immediate_kind": stats["immediate_kind"],
            "occurrence_count": stats["occurrence_count"],
            "script_count": stats["script_count"],
            "first_count": stats["first_count"],
            "last_count": stats["last_count"],
            "sample_values": stats["sample_values"],
        }
        if stats["switch_subtype_counts"]:
            entry["switch_subtype_counts"] = stats["switch_subtype_counts"]
        if stats["reference_source_counts"]:
            entry["reference_source_counts"] = {
                int(source_id): {
                    "count": count,
                    "source_name": CLIENTSCRIPT_VAR_SOURCE_NAMES.get(int(source_id)),
                }
                for source_id, count in sorted(stats["reference_source_counts"].items())
            }
        if int(stats["slot_fit_count"]):
            entry["slot_fit_count"] = stats["slot_fit_count"]

        entry.update(_infer_clientscript_opcode_candidate(stats))
        stack_effect_candidate = _infer_clientscript_stack_effect(entry)
        if stack_effect_candidate is not None:
            entry["stack_effect_candidate"] = stack_effect_candidate
        override = semantic_overrides.get(raw_opcode)
        if override:
            entry.update(override)
            entry["override"] = True
            stack_effect_candidate = _infer_clientscript_stack_effect(entry)
            if stack_effect_candidate is not None:
                entry["stack_effect_candidate"] = stack_effect_candidate
        catalog[raw_opcode] = entry

    summary = {
        "catalog_opcode_count": len(catalog),
        "catalog_script_count": parsed_script_count,
        "override_count": sum(1 for entry in catalog.values() if entry.get("override")),
        "catalog_sample": [
            catalog[raw_opcode]
            for raw_opcode in sorted(catalog)[:24]
        ],
    }
    return catalog, summary


def _build_clientscript_producer_candidates(
    connection: sqlite3.Connection,
    *,
    locked_opcode_types: dict[int, str],
    raw_opcode_catalog: dict[int, dict[str, object]],
    include_keys: list[int],
    max_decoded_bytes: int | None,
    sample_limit: int = DEFAULT_CLIENTSCRIPT_CALIBRATION_SAMPLE,
) -> tuple[dict[int, dict[str, object]], dict[str, object]]:
    candidates = _collect_clientscript_calibration_candidates(
        connection,
        include_keys=include_keys,
        max_decoded_bytes=max_decoded_bytes,
        sample_limit=sample_limit,
    )
    if not candidates or not locked_opcode_types or not raw_opcode_catalog:
        return {}, {
            "producer_opcode_count": 0,
            "traced_script_count": 0,
            "producer_script_count": 0,
            "catalog_sample": [],
        }

    stats_by_opcode: dict[int, dict[str, object]] = {}
    traced_script_count = 0
    producer_script_keys: set[int] = set()

    for key, layout in candidates:
        prefix_trace = _trace_clientscript_locked_prefix(
            layout,
            locked_opcode_types,
            raw_opcode_catalog=raw_opcode_catalog,
        )
        steps = prefix_trace.get("instruction_steps") if isinstance(prefix_trace, dict) else None
        if not isinstance(steps, list) or len(steps) < 2:
            continue
        traced_script_count += 1
        max_slot = max(
            layout.local_int_count,
            layout.local_string_count,
            layout.local_long_count,
            layout.int_argument_count,
            layout.string_argument_count,
            layout.long_argument_count,
        )
        seen_in_script: set[int] = set()
        for index in range(1, len(steps)):
            consumer_step = steps[index]
            consumer_kind = _classify_clientscript_control_flow_consumer(consumer_step)
            if consumer_kind not in {"branch", "switch"}:
                continue

            producer_step = steps[index - 1]
            producer_raw_opcode = int(producer_step["raw_opcode"])
            producer_catalog_entry = raw_opcode_catalog.get(producer_raw_opcode)
            if isinstance(producer_catalog_entry, dict):
                producer_control_flow_kind = str(producer_catalog_entry.get("control_flow_kind", ""))
                producer_family = str(producer_catalog_entry.get("family", ""))
                if producer_control_flow_kind or producer_family == "control-flow":
                    continue

            immediate_kind = str(producer_step["immediate_kind"])
            if immediate_kind not in CLIENTSCRIPT_IMMEDIATE_TYPES:
                continue

            stats = stats_by_opcode.setdefault(
                producer_raw_opcode,
                {
                    "immediate_kind": immediate_kind,
                    "occurrence_count": 0,
                    "script_count": 0,
                    "control_flow_successor_count": 0,
                    "branch_successor_count": 0,
                    "switch_successor_count": 0,
                    "slot_fit_count": 0,
                    "sample_values": [],
                    "consumer_raw_opcode_counts": {},
                    "consumer_label_counts": {},
                    "key_samples": [],
                    "trace_samples": [],
                },
            )
            stats["occurrence_count"] = int(stats["occurrence_count"]) + 1
            stats["control_flow_successor_count"] = int(stats["control_flow_successor_count"]) + 1
            if consumer_kind == "branch":
                stats["branch_successor_count"] = int(stats["branch_successor_count"]) + 1
            elif consumer_kind == "switch":
                stats["switch_successor_count"] = int(stats["switch_successor_count"]) + 1

            immediate_value = producer_step.get("immediate_value")
            if immediate_kind == "byte" and isinstance(immediate_value, int) and 0 <= immediate_value < max_slot:
                stats["slot_fit_count"] = int(stats["slot_fit_count"]) + 1
            sampled_value = _sample_clientscript_immediate_value(immediate_value)
            if sampled_value not in stats["sample_values"] and len(stats["sample_values"]) < 8:
                stats["sample_values"].append(sampled_value)

            consumer_raw_opcode = int(consumer_step["raw_opcode"])
            consumer_raw_counts = stats["consumer_raw_opcode_counts"]
            consumer_raw_counts[consumer_raw_opcode] = int(consumer_raw_counts.get(consumer_raw_opcode, 0)) + 1
            consumer_label = str(
                consumer_step.get("semantic_label")
                or consumer_step.get("control_flow_kind")
                or consumer_step["raw_opcode_hex"]
            )
            consumer_label_counts = stats["consumer_label_counts"]
            consumer_label_counts[consumer_label] = int(consumer_label_counts.get(consumer_label, 0)) + 1

            if len(stats["key_samples"]) < 8 and int(key) not in stats["key_samples"]:
                stats["key_samples"].append(int(key))
            if len(stats["trace_samples"]) < 8:
                stats["trace_samples"].append(
                    {
                        "key": int(key),
                        "producer_offset": int(producer_step["offset"]),
                        "producer_raw_opcode_hex": str(producer_step["raw_opcode_hex"]),
                        "producer_immediate_kind": immediate_kind,
                        "producer_immediate_value": sampled_value,
                        "consumer_offset": int(consumer_step["offset"]),
                        "consumer_raw_opcode_hex": str(consumer_step["raw_opcode_hex"]),
                        "consumer_kind": consumer_kind,
                        "consumer_label": consumer_label,
                    }
                )

            seen_in_script.add(producer_raw_opcode)

        for producer_raw_opcode in seen_in_script:
            stats_by_opcode[producer_raw_opcode]["script_count"] = (
                int(stats_by_opcode[producer_raw_opcode]["script_count"]) + 1
            )
        if seen_in_script:
            producer_script_keys.add(int(key))

    catalog: dict[int, dict[str, object]] = {}
    for raw_opcode, stats in stats_by_opcode.items():
        entry: dict[str, object] = {
            "raw_opcode": raw_opcode,
            "raw_opcode_hex": f"0x{raw_opcode:04X}",
            "immediate_kind": stats["immediate_kind"],
            "occurrence_count": int(stats["occurrence_count"]),
            "script_count": int(stats["script_count"]),
            "control_flow_successor_count": int(stats["control_flow_successor_count"]),
            "branch_successor_count": int(stats["branch_successor_count"]),
            "switch_successor_count": int(stats["switch_successor_count"]),
            "sample_values": list(stats["sample_values"]),
            "key_sample": list(stats["key_samples"]),
            "trace_samples": list(stats["trace_samples"]),
            "consumer_raw_opcode_sample": [
                {
                    "raw_opcode": consumer_raw_opcode,
                    "raw_opcode_hex": f"0x{consumer_raw_opcode:04X}",
                    "count": count,
                }
                for consumer_raw_opcode, count in sorted(
                    stats["consumer_raw_opcode_counts"].items(),
                    key=lambda item: (-int(item[1]), int(item[0])),
                )[:8]
            ],
            "consumer_label_sample": [
                {
                    "label": label,
                    "count": count,
                }
                for label, count in sorted(
                    stats["consumer_label_counts"].items(),
                    key=lambda item: (-int(item[1]), str(item[0])),
                )[:8]
            ],
        }
        if int(stats["slot_fit_count"]):
            entry["slot_fit_count"] = int(stats["slot_fit_count"])
        entry.update(_infer_clientscript_producer_candidate(entry))
        stack_effect_candidate = _infer_clientscript_stack_effect(entry)
        if stack_effect_candidate is not None:
            entry["stack_effect_candidate"] = stack_effect_candidate
        catalog[raw_opcode] = entry

    summary = {
        "producer_opcode_count": len(catalog),
        "traced_script_count": traced_script_count,
        "producer_script_count": len(producer_script_keys),
        "catalog_sample": sorted(
            catalog.values(),
            key=lambda entry: (
                -int(entry.get("control_flow_successor_count", 0)),
                -int(entry.get("script_count", 0)),
                int(entry["raw_opcode"]),
            ),
        )[:24],
    }
    return catalog, summary


def _build_clientscript_contextual_frontier_candidates(
    connection: sqlite3.Connection,
    *,
    locked_opcode_types: dict[int, str],
    raw_opcode_catalog: dict[int, dict[str, object]],
    include_keys: list[int],
    max_decoded_bytes: int | None,
    sample_limit: int = DEFAULT_CLIENTSCRIPT_CALIBRATION_SAMPLE,
) -> tuple[dict[int, dict[str, object]], dict[str, object]]:
    candidates = _collect_clientscript_calibration_candidates(
        connection,
        include_keys=include_keys,
        max_decoded_bytes=max_decoded_bytes,
        sample_limit=sample_limit,
    )
    if not candidates or not locked_opcode_types or not raw_opcode_catalog:
        return {}, {
            "frontier_opcode_count": 0,
            "frontier_script_count": 0,
            "catalog_sample": [],
        }

    frontier_stats_by_opcode: dict[int, dict[str, object]] = {}
    frontier_script_count = 0

    for key, layout in candidates:
        prefix_trace = _trace_clientscript_locked_prefix(
            layout,
            locked_opcode_types,
            raw_opcode_catalog=raw_opcode_catalog,
        )
        if prefix_trace is None or prefix_trace.get("status") != "frontier":
            continue
        raw_opcode = prefix_trace.get("frontier_raw_opcode")
        if not isinstance(raw_opcode, int):
            continue

        frontier_script_count += 1
        instruction_steps = prefix_trace.get("instruction_steps")
        if not isinstance(instruction_steps, list):
            instruction_steps = []
        prefix_switch_dispatch_count = sum(
            1
            for step in instruction_steps
            if isinstance(step, dict) and str(step.get("semantic_label", "")) == "SWITCH_DISPATCH_FRONTIER_CANDIDATE"
        )
        prefix_push_int_count = sum(
            1
            for step in instruction_steps
            if isinstance(step, dict) and str(step.get("semantic_label", "")) in {"PUSH_INT_CANDIDATE", "PUSH_INT_LITERAL"}
        )
        last_step = instruction_steps[-1] if instruction_steps else None
        previous_label = (
            str(last_step.get("semantic_label"))
            if isinstance(last_step, dict) and isinstance(last_step.get("semantic_label"), str)
            else None
        )

        stats = frontier_stats_by_opcode.setdefault(
            raw_opcode,
            {
                "script_count": 0,
                "switch_script_count": 0,
                "switch_case_count": 0,
                "reason_counts": {},
                "frontier_offsets": [],
                "frontier_instruction_indices": [],
                "previous_raw_opcode_counts": {},
                "previous_semantic_label_counts": {},
                "key_samples": [],
                "script_samples": [],
                "immediate_kind_scores": {},
                "prefix_switch_dispatch_count": 0,
                "prefix_push_int_count": 0,
                "previous_push_int_count": 0,
            },
        )
        stats["script_count"] = int(stats["script_count"]) + 1
        if layout.switch_table_count:
            stats["switch_script_count"] = int(stats["switch_script_count"]) + 1
            stats["switch_case_count"] = int(stats["switch_case_count"]) + layout.switch_case_count
        if prefix_switch_dispatch_count:
            stats["prefix_switch_dispatch_count"] = int(stats["prefix_switch_dispatch_count"]) + 1
        if prefix_push_int_count:
            stats["prefix_push_int_count"] = int(stats["prefix_push_int_count"]) + 1
        if previous_label in {"PUSH_INT_CANDIDATE", "PUSH_INT_LITERAL"}:
            stats["previous_push_int_count"] = int(stats["previous_push_int_count"]) + 1

        reason = str(prefix_trace["frontier_reason"])
        reason_counts = stats["reason_counts"]
        reason_counts[reason] = int(reason_counts.get(reason, 0)) + 1

        frontier_offset = int(prefix_trace["frontier_offset"])
        frontier_instruction_index = int(prefix_trace["frontier_instruction_index"])
        if frontier_offset not in stats["frontier_offsets"] and len(stats["frontier_offsets"]) < 8:
            stats["frontier_offsets"].append(frontier_offset)
        if (
            frontier_instruction_index not in stats["frontier_instruction_indices"]
            and len(stats["frontier_instruction_indices"]) < 8
        ):
            stats["frontier_instruction_indices"].append(frontier_instruction_index)

        previous_raw_opcode = prefix_trace.get("previous_raw_opcode")
        if isinstance(previous_raw_opcode, int):
            previous_counts = stats["previous_raw_opcode_counts"]
            previous_counts[previous_raw_opcode] = int(previous_counts.get(previous_raw_opcode, 0)) + 1
        if previous_label:
            previous_label_counts = stats["previous_semantic_label_counts"]
            previous_label_counts[previous_label] = int(previous_label_counts.get(previous_label, 0)) + 1

        if len(stats["key_samples"]) < 8:
            stats["key_samples"].append(int(key))
        if len(stats["script_samples"]) < 8:
            stats["script_samples"].append(
                {
                    "key": int(key),
                    "instruction_count": layout.instruction_count,
                    "switch_table_count": layout.switch_table_count,
                    "switch_case_count": layout.switch_case_count,
                    "frontier_reason": reason,
                    "frontier_offset": frontier_offset,
                    "frontier_instruction_index": frontier_instruction_index,
                    "decoded_prefix_instruction_count": int(prefix_trace["decoded_instruction_count"]),
                    "previous_raw_opcode_hex": prefix_trace.get("previous_raw_opcode_hex"),
                    "previous_semantic_label": previous_label,
                    "prefix_switch_dispatch_count": prefix_switch_dispatch_count,
                    "prefix_push_int_count": prefix_push_int_count,
                    "prefix_trace_sample": [
                        {
                            "raw_opcode_hex": str(step.get("raw_opcode_hex")),
                            "semantic_label": step.get("semantic_label"),
                            "immediate_kind": step.get("immediate_kind"),
                        }
                        for step in instruction_steps[-6:]
                        if isinstance(step, dict)
                    ],
                }
            )

        kind_scores = _score_clientscript_frontier_immediate_kinds(
            layout,
            locked_opcode_types,
            frontier_opcode=raw_opcode,
            base_prefix_trace=prefix_trace,
            raw_opcode_catalog=raw_opcode_catalog,
        )
        for immediate_kind, kind_score in kind_scores.items():
            kind_stats = stats["immediate_kind_scores"].setdefault(
                immediate_kind,
                {
                    "script_count": 0,
                    "switch_script_count": 0,
                    "valid_trace_count": 0,
                    "invalid_immediate_count": 0,
                    "complete_trace_count": 0,
                    "improved_script_count": 0,
                    "switch_improved_script_count": 0,
                    "total_decoded_instruction_count": 0,
                    "total_progress_instruction_count": 0,
                    "max_decoded_instruction_count": 0,
                    "next_frontier_trace_count": 0,
                    "next_frontier_counts": {},
                    "relative_target_count": 0,
                    "relative_target_in_bounds_count": 0,
                    "relative_target_instruction_boundary_count": 0,
                    "relative_target_terminal_count": 0,
                    "relative_target_forward_count": 0,
                    "relative_target_backward_count": 0,
                    "relative_target_self_count": 0,
                    "relative_target_samples": [],
                    "trace_samples": [],
                },
            )
            kind_stats["script_count"] = int(kind_stats["script_count"]) + 1
            if layout.switch_table_count:
                kind_stats["switch_script_count"] = int(kind_stats["switch_script_count"]) + 1
            if bool(kind_score["valid_trace"]):
                kind_stats["valid_trace_count"] = int(kind_stats["valid_trace_count"]) + 1
            else:
                kind_stats["invalid_immediate_count"] = int(kind_stats["invalid_immediate_count"]) + 1
            if kind_score.get("trace_status") == "complete":
                kind_stats["complete_trace_count"] = int(kind_stats["complete_trace_count"]) + 1

            progress_instruction_count = int(kind_score["progress_instruction_count"])
            if progress_instruction_count > 0:
                kind_stats["improved_script_count"] = int(kind_stats["improved_script_count"]) + 1
                if layout.switch_table_count:
                    kind_stats["switch_improved_script_count"] = int(kind_stats["switch_improved_script_count"]) + 1
            kind_stats["total_decoded_instruction_count"] = (
                int(kind_stats["total_decoded_instruction_count"]) + int(kind_score["decoded_instruction_count"])
            )
            kind_stats["total_progress_instruction_count"] = (
                int(kind_stats["total_progress_instruction_count"]) + progress_instruction_count
            )
            kind_stats["max_decoded_instruction_count"] = max(
                int(kind_stats["max_decoded_instruction_count"]),
                int(kind_score["decoded_instruction_count"]),
            )
            next_frontier_raw_opcode = kind_score.get("next_frontier_raw_opcode")
            if isinstance(next_frontier_raw_opcode, int):
                kind_stats["next_frontier_trace_count"] = int(kind_stats["next_frontier_trace_count"]) + 1
                next_frontier_counts = kind_stats["next_frontier_counts"]
                next_frontier_counts[next_frontier_raw_opcode] = int(
                    next_frontier_counts.get(next_frontier_raw_opcode, 0)
                ) + 1
            relative_target_offset = kind_score.get("relative_target_offset")
            if isinstance(relative_target_offset, int):
                kind_stats["relative_target_count"] = int(kind_stats["relative_target_count"]) + 1
                if bool(kind_score.get("relative_target_in_bounds")):
                    kind_stats["relative_target_in_bounds_count"] = (
                        int(kind_stats["relative_target_in_bounds_count"]) + 1
                    )
                if bool(kind_score.get("relative_target_aligns_to_instruction")):
                    kind_stats["relative_target_instruction_boundary_count"] = (
                        int(kind_stats["relative_target_instruction_boundary_count"]) + 1
                    )
                if bool(kind_score.get("relative_target_hits_end")):
                    kind_stats["relative_target_terminal_count"] = (
                        int(kind_stats["relative_target_terminal_count"]) + 1
                    )
                direction = str(kind_score.get("relative_target_direction", ""))
                if direction == "forward":
                    kind_stats["relative_target_forward_count"] = int(kind_stats["relative_target_forward_count"]) + 1
                elif direction == "backward":
                    kind_stats["relative_target_backward_count"] = int(kind_stats["relative_target_backward_count"]) + 1
                elif direction == "self":
                    kind_stats["relative_target_self_count"] = int(kind_stats["relative_target_self_count"]) + 1
                if len(kind_stats["relative_target_samples"]) < 6:
                    kind_stats["relative_target_samples"].append(
                        {
                            "key": int(key),
                            "target_offset": relative_target_offset,
                            "target_delta": int(kind_score.get("relative_target_delta", 0)),
                            "target_relation": kind_score.get("relative_target_relation"),
                            "target_direction": kind_score.get("relative_target_direction"),
                        }
                    )
            if len(kind_stats["trace_samples"]) < 6:
                kind_stats["trace_samples"].append(
                    {
                        "key": int(key),
                        "trace_status": kind_score.get("trace_status"),
                        "frontier_reason": kind_score.get("frontier_reason"),
                        "decoded_instruction_count": int(kind_score["decoded_instruction_count"]),
                        "progress_instruction_count": progress_instruction_count,
                        "next_frontier_raw_opcode_hex": kind_score.get("next_frontier_raw_opcode_hex"),
                    }
                )

    catalog: dict[int, dict[str, object]] = {}
    for raw_opcode, stats in frontier_stats_by_opcode.items():
        immediate_kind_candidates: list[dict[str, object]] = []
        for immediate_kind, kind_stats in stats["immediate_kind_scores"].items():
            immediate_kind_candidates.append(
                {
                    "immediate_kind": immediate_kind,
                    "script_count": kind_stats["script_count"],
                    "switch_script_count": kind_stats["switch_script_count"],
                    "valid_trace_count": kind_stats["valid_trace_count"],
                    "invalid_immediate_count": kind_stats["invalid_immediate_count"],
                    "complete_trace_count": kind_stats["complete_trace_count"],
                    "improved_script_count": kind_stats["improved_script_count"],
                    "switch_improved_script_count": kind_stats["switch_improved_script_count"],
                    "total_decoded_instruction_count": kind_stats["total_decoded_instruction_count"],
                    "total_progress_instruction_count": kind_stats["total_progress_instruction_count"],
                    "max_decoded_instruction_count": kind_stats["max_decoded_instruction_count"],
                    "next_frontier_trace_count": kind_stats["next_frontier_trace_count"],
                    "next_frontier_sample": [
                        {
                            "raw_opcode": next_frontier_opcode,
                            "raw_opcode_hex": f"0x{next_frontier_opcode:04X}",
                            "count": count,
                        }
                        for next_frontier_opcode, count in sorted(
                            kind_stats["next_frontier_counts"].items(),
                            key=lambda item: (-int(item[1]), int(item[0])),
                        )[:6]
                    ],
                    "relative_target_count": kind_stats["relative_target_count"],
                    "relative_target_in_bounds_count": kind_stats["relative_target_in_bounds_count"],
                    "relative_target_instruction_boundary_count": kind_stats["relative_target_instruction_boundary_count"],
                    "relative_target_terminal_count": kind_stats["relative_target_terminal_count"],
                    "relative_target_forward_count": kind_stats["relative_target_forward_count"],
                    "relative_target_backward_count": kind_stats["relative_target_backward_count"],
                    "relative_target_self_count": kind_stats["relative_target_self_count"],
                    "relative_target_sample": kind_stats["relative_target_samples"],
                    "trace_samples": kind_stats["trace_samples"],
                }
            )
        immediate_kind_candidates.sort(key=_clientscript_frontier_kind_sort_key, reverse=True)

        entry: dict[str, object] = {
            "raw_opcode": raw_opcode,
            "raw_opcode_hex": f"0x{raw_opcode:04X}",
            "script_count": stats["script_count"],
            "switch_script_count": stats["switch_script_count"],
            "switch_script_ratio": round(int(stats["switch_script_count"]) / max(int(stats["script_count"]), 1), 2),
            "switch_case_count": stats["switch_case_count"],
            "frontier_offsets_sample": stats["frontier_offsets"],
            "frontier_instruction_index_sample": stats["frontier_instruction_indices"],
            "reason_counts": stats["reason_counts"],
            "key_sample": stats["key_samples"],
            "script_samples": stats["script_samples"],
            "previous_raw_opcode_sample": [
                {
                    "raw_opcode": previous_raw_opcode,
                    "raw_opcode_hex": f"0x{previous_raw_opcode:04X}",
                    "count": count,
                }
                for previous_raw_opcode, count in sorted(
                    stats["previous_raw_opcode_counts"].items(),
                    key=lambda item: (-int(item[1]), int(item[0])),
                )[:8]
            ],
            "previous_semantic_label_sample": [
                {
                    "label": label,
                    "count": count,
                }
                for label, count in sorted(
                    stats["previous_semantic_label_counts"].items(),
                    key=lambda item: (-int(item[1]), str(item[0])),
                )[:8]
            ],
            "prefix_switch_dispatch_count": stats["prefix_switch_dispatch_count"],
            "prefix_push_int_count": stats["prefix_push_int_count"],
            "previous_push_int_count": stats["previous_push_int_count"],
            "immediate_kind_candidates": immediate_kind_candidates,
        }
        entry.update(_infer_clientscript_contextual_frontier_candidate(entry))
        stack_effect_candidate = _infer_clientscript_stack_effect(entry)
        if stack_effect_candidate is not None:
            entry["stack_effect_candidate"] = stack_effect_candidate
        catalog[raw_opcode] = entry

    summary = {
        "frontier_opcode_count": len(catalog),
        "frontier_script_count": frontier_script_count,
        "catalog_sample": sorted(
            catalog.values(),
            key=lambda entry: (
                -int(entry.get("prefix_switch_dispatch_count", 0)),
                -int(entry.get("script_count", 0)),
                int(entry["raw_opcode"]),
            ),
        )[:24],
    }
    return catalog, summary


def _calibrate_clientscript_opcode_types(
    connection: sqlite3.Connection,
    *,
    include_keys: list[int],
    max_decoded_bytes: int | None,
    sample_limit: int = DEFAULT_CLIENTSCRIPT_CALIBRATION_SAMPLE,
) -> tuple[dict[int, str], dict[str, object]]:
    candidates = _collect_clientscript_calibration_candidates(
        connection,
        include_keys=include_keys,
        max_decoded_bytes=max_decoded_bytes,
        sample_limit=sample_limit,
    )
    if not candidates:
        return {}, {
            "sampled_script_count": 0,
            "solved_script_count": 0,
            "locked_opcode_type_count": 0,
            "candidate_opcode_type_count": 0,
            "pass_count": 0,
            "locked_opcode_types_sample": [],
        }

    possible_types: dict[int, set[str]] = {}
    solved_script_count = 0
    pass_count = 0
    for _ in range(4):
        pass_count += 1
        changed = False
        pass_solved = 0
        for _key, layout in candidates:
            solution = _solve_clientscript_disassembly(
                layout.opcode_data,
                layout.instruction_count,
                possible_types=possible_types or None,
            )
            if solution["solution_count"] and not solution["bailed"]:
                pass_solved += 1
                for raw_opcode, observed_types in solution["observed_types"].items():
                    previous = possible_types.get(raw_opcode, set(CLIENTSCRIPT_IMMEDIATE_TYPES))
                    narrowed = previous & observed_types
                    if narrowed != previous:
                        possible_types[raw_opcode] = narrowed
                        changed = True
        solved_script_count = max(solved_script_count, pass_solved)
        if not changed:
            break

    locked_opcode_types = {
        raw_opcode: next(iter(observed_types))
        for raw_opcode, observed_types in possible_types.items()
        if len(observed_types) == 1
    }
    summary = {
        "sampled_script_count": len(candidates),
        "solved_script_count": solved_script_count,
        "locked_opcode_type_count": len(locked_opcode_types),
        "candidate_opcode_type_count": len(possible_types),
        "pass_count": pass_count,
        "locked_opcode_types_sample": [
            {
                "raw_opcode": raw_opcode,
                "raw_opcode_hex": f"0x{raw_opcode:04X}",
                "immediate_kind": immediate_kind,
            }
            for raw_opcode, immediate_kind in sorted(locked_opcode_types.items())[:32]
        ],
    }
    return locked_opcode_types, summary


def profile_archive_file(
    data: bytes,
    *,
    index_name: str | None,
    archive_key: int,
    file_id: int,
    clientscript_opcode_types: dict[int, str] | None = None,
    clientscript_opcode_catalog: dict[int, dict[str, object]] | None = None,
) -> dict[str, object] | None:
    if index_name == "CONFIG_ENUM":
        profile = _decode_enum_definition(data)
    elif index_name == "MAPS":
        try:
            profile = _profile_mapsquare_file(data, archive_key=archive_key, file_id=file_id)
        except Exception:
            return None
    elif index_name == "MODELS_RT7":
        try:
            profile = _decode_rt7_model(data)
        except Exception:
            return None
    elif index_name in {"SPRITES", "LOADINGSPRITES"}:
        try:
            profile = _decode_sprite_archive(data)
        except Exception:
            return None
    elif index_name == "CLIENTSCRIPTS":
        try:
            profile = _decode_clientscript_metadata(
                data,
                raw_opcode_types=clientscript_opcode_types,
                raw_opcode_catalog=clientscript_opcode_catalog,
            )
        except Exception:
            return None
    elif index_name == "CONFIG_ITEM":
        profile = _decode_item_definition(data)
    elif index_name == "CONFIG_NPC":
        profile = _decode_npc_definition(data)
    elif index_name == "CONFIG_OBJECT":
        profile = _decode_object_definition(data)
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
        return None

    if profile is None:
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
    archive_summary_count = 0
    archive_summary_kind_counts: dict[str, int] = {}
    cfg_graph_count = 0
    reference_table_summary: dict[str, object] | None = None
    reference_table_archives_by_id: dict[int, dict[str, object]] = {}
    clientscript_opcode_types: dict[int, str] = {}
    effective_clientscript_opcode_types: dict[int, str] = {}
    clientscript_calibration_summary: dict[str, object] | None = None
    clientscript_opcode_catalog: dict[int, dict[str, object]] = {}
    clientscript_opcode_catalog_summary: dict[str, object] | None = None
    clientscript_control_flow_candidates: dict[int, dict[str, object]] = {}
    clientscript_control_flow_summary: dict[str, object] | None = None
    clientscript_post_context_control_flow_candidates: dict[int, dict[str, object]] = {}
    clientscript_post_context_control_flow_summary: dict[str, object] | None = None
    clientscript_recursive_control_flow_candidates: dict[int, dict[str, object]] = {}
    clientscript_recursive_control_flow_summary: dict[str, object] | None = None
    clientscript_producer_candidates: dict[int, dict[str, object]] = {}
    clientscript_producer_summary: dict[str, object] | None = None
    clientscript_contextual_frontier_candidates: dict[int, dict[str, object]] = {}
    clientscript_contextual_frontier_summary: dict[str, object] | None = None
    clientscript_promoted_contextual_frontiers: dict[int, dict[str, object]] = {}
    clientscript_promoted_candidates: dict[int, dict[str, object]] = {}
    clientscript_semantic_overrides: dict[int, dict[str, object]] = {}
    clientscript_semantic_source: str | None = None
    clientscript_semantic_build: int | None = None
    clientscript_opcode_catalog_path: Path | None = None
    clientscript_control_flow_candidates_path: Path | None = None
    clientscript_producer_candidates_path: Path | None = None
    clientscript_contextual_frontier_candidates_path: Path | None = None
    clientscript_semantic_suggestions_path: Path | None = None

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

        if index_name == "CLIENTSCRIPTS" and "cache" in tables_present:
            try:
                clientscript_semantic_overrides, clientscript_semantic_source, clientscript_semantic_build = (
                    load_clientscript_semantic_overrides(str(target))
                )
                clientscript_opcode_types, clientscript_calibration_summary = _calibrate_clientscript_opcode_types(
                    connection,
                    include_keys=normalized_keys,
                    max_decoded_bytes=max_decoded_bytes,
                )
                clientscript_opcode_catalog, clientscript_opcode_catalog_summary = _build_clientscript_opcode_catalog(
                    connection,
                    locked_opcode_types=clientscript_opcode_types,
                    semantic_overrides=clientscript_semantic_overrides,
                    include_keys=normalized_keys,
                    max_decoded_bytes=max_decoded_bytes,
                )
                clientscript_control_flow_candidates, clientscript_control_flow_summary = (
                    _build_clientscript_control_flow_candidates(
                        connection,
                        locked_opcode_types=clientscript_opcode_types,
                        semantic_overrides=clientscript_semantic_overrides,
                        raw_opcode_catalog=clientscript_opcode_catalog,
                        include_keys=normalized_keys,
                        max_decoded_bytes=max_decoded_bytes,
                    )
                )
                clientscript_promoted_candidates = _promote_clientscript_control_flow_candidates(
                    clientscript_control_flow_candidates
                )
                for raw_opcode, promoted_entry in clientscript_promoted_candidates.items():
                    _merge_clientscript_catalog_entry(clientscript_opcode_catalog, raw_opcode, promoted_entry)
                effective_clientscript_opcode_types = _augment_clientscript_locked_opcode_types(
                    clientscript_opcode_types,
                    clientscript_opcode_catalog,
                )
                for raw_opcode, candidate_entry in clientscript_control_flow_candidates.items():
                    _merge_clientscript_catalog_entry(clientscript_opcode_catalog, raw_opcode, candidate_entry)
                clientscript_producer_candidates, clientscript_producer_summary = (
                    _build_clientscript_producer_candidates(
                        connection,
                        locked_opcode_types=effective_clientscript_opcode_types,
                        raw_opcode_catalog=clientscript_opcode_catalog,
                        include_keys=normalized_keys,
                        max_decoded_bytes=max_decoded_bytes,
                    )
                )
                for raw_opcode, producer_entry in clientscript_producer_candidates.items():
                    _merge_clientscript_catalog_entry(clientscript_opcode_catalog, raw_opcode, producer_entry)
                (
                    clientscript_contextual_frontier_candidates,
                    clientscript_contextual_frontier_summary,
                    clientscript_promoted_contextual_frontiers,
                    effective_clientscript_opcode_types,
                    clientscript_opcode_catalog,
                ) = _resolve_clientscript_contextual_frontier_passes(
                    connection,
                    locked_opcode_types=effective_clientscript_opcode_types,
                    raw_opcode_catalog=clientscript_opcode_catalog,
                    include_keys=normalized_keys,
                    max_decoded_bytes=max_decoded_bytes,
                )
                clientscript_post_context_control_flow_candidates, clientscript_post_context_control_flow_summary = (
                    _build_clientscript_control_flow_candidates(
                        connection,
                        locked_opcode_types=effective_clientscript_opcode_types,
                        semantic_overrides=clientscript_semantic_overrides,
                        raw_opcode_catalog=clientscript_opcode_catalog,
                        include_keys=normalized_keys,
                        max_decoded_bytes=max_decoded_bytes,
                    )
                )
                post_context_promoted_candidates = _promote_clientscript_control_flow_candidates(
                    clientscript_post_context_control_flow_candidates
                )
                for raw_opcode, promoted_entry in post_context_promoted_candidates.items():
                    _merge_clientscript_catalog_entry(clientscript_opcode_catalog, raw_opcode, promoted_entry)
                for raw_opcode, candidate_entry in clientscript_post_context_control_flow_candidates.items():
                    _merge_clientscript_catalog_entry(clientscript_opcode_catalog, raw_opcode, candidate_entry)
                effective_clientscript_opcode_types = _augment_clientscript_locked_opcode_types(
                    effective_clientscript_opcode_types,
                    clientscript_opcode_catalog,
                )
                clientscript_recursive_control_flow_candidates, clientscript_recursive_control_flow_summary = (
                    _build_clientscript_control_flow_candidates(
                        connection,
                        locked_opcode_types=effective_clientscript_opcode_types,
                        semantic_overrides=clientscript_semantic_overrides,
                        raw_opcode_catalog=clientscript_opcode_catalog,
                        include_keys=normalized_keys,
                        max_decoded_bytes=max_decoded_bytes,
                    )
                )
                recursive_promoted_candidates = _promote_clientscript_control_flow_candidates(
                    clientscript_recursive_control_flow_candidates
                )
                for raw_opcode, promoted_entry in recursive_promoted_candidates.items():
                    _merge_clientscript_catalog_entry(clientscript_opcode_catalog, raw_opcode, promoted_entry)
                for raw_opcode, candidate_entry in clientscript_recursive_control_flow_candidates.items():
                    _merge_clientscript_catalog_entry(clientscript_opcode_catalog, raw_opcode, candidate_entry)
                clientscript_control_flow_candidates = _combine_clientscript_control_flow_candidates(
                    clientscript_control_flow_candidates,
                    clientscript_post_context_control_flow_candidates,
                    clientscript_recursive_control_flow_candidates,
                )
                if clientscript_control_flow_summary is not None:
                    clientscript_control_flow_summary["combined_frontier_opcode_count"] = (
                        len(clientscript_control_flow_candidates)
                    )
                    if clientscript_post_context_control_flow_summary is not None:
                        clientscript_control_flow_summary["post_contextual_frontier_opcode_count"] = int(
                            clientscript_post_context_control_flow_summary.get("frontier_opcode_count", 0)
                        )
                        clientscript_control_flow_summary["post_contextual_catalog_sample"] = (
                            clientscript_post_context_control_flow_summary.get("catalog_sample", [])[:24]
                        )
                    if clientscript_recursive_control_flow_summary is not None:
                        clientscript_control_flow_summary["recursive_frontier_opcode_count"] = int(
                            clientscript_recursive_control_flow_summary.get("frontier_opcode_count", 0)
                        )
                        clientscript_control_flow_summary["recursive_catalog_sample"] = (
                            clientscript_recursive_control_flow_summary.get("catalog_sample", [])[:24]
                        )
                for entry in clientscript_opcode_catalog.values():
                    stack_effect_candidate = _infer_clientscript_stack_effect(entry)
                    if stack_effect_candidate is not None:
                        entry["stack_effect_candidate"] = stack_effect_candidate
            except Exception as exc:
                warnings.append(f"clientscript calibration failed: {exc}")

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
                                clientscript_opcode_types=effective_clientscript_opcode_types or None,
                                clientscript_opcode_catalog=clientscript_opcode_catalog or None,
                            )
                            if semantic_profile is not None and index_name == "MAPS":
                                _enrich_mapsquare_locations_profile(
                                    semantic_profile,
                                    source_path=target,
                                )
                            preview_png_path: Path | None = None
                            mesh_obj_path: Path | None = None
                            disassembly_text_path: Path | None = None
                            cfg_dot_path: Path | None = None
                            cfg_json_path: Path | None = None
                            if semantic_profile is not None:
                                preview_png_bytes = semantic_profile.pop("_preview_png_bytes", None)
                                if isinstance(preview_png_bytes, bytes):
                                    preview_png_path = archive_dir / f"file-{file_id}.preview.png"
                                    preview_png_path.write_bytes(preview_png_bytes)
                                    semantic_profile["preview_png_path"] = str(preview_png_path)
                                mesh_obj_text = semantic_profile.pop("_mesh_obj_text", None)
                                if isinstance(mesh_obj_text, str):
                                    mesh_obj_path = archive_dir / f"file-{file_id}.mesh.obj"
                                    mesh_obj_path.write_text(mesh_obj_text, encoding="utf-8")
                                    semantic_profile["mesh_obj_path"] = str(mesh_obj_path)
                                disassembly_text = semantic_profile.pop("_disassembly_text", None)
                                if isinstance(disassembly_text, str):
                                    disassembly_text_path = archive_dir / f"file-{file_id}.disasm.txt"
                                    disassembly_text_path.write_text(disassembly_text, encoding="utf-8")
                                    semantic_profile["disassembly_text_path"] = str(disassembly_text_path)
                                cfg_dot_text = semantic_profile.pop("_cfg_dot_text", None)
                                if isinstance(cfg_dot_text, str):
                                    cfg_dot_path = archive_dir / f"file-{file_id}.cfg.dot"
                                    cfg_dot_path.write_text(cfg_dot_text, encoding="utf-8")
                                    semantic_profile["cfg_dot_path"] = str(cfg_dot_path)
                                cfg_json_text = semantic_profile.pop("_cfg_json_text", None)
                                if isinstance(cfg_json_text, str):
                                    cfg_json_path = archive_dir / f"file-{file_id}.cfg.json"
                                    cfg_json_path.write_text(cfg_json_text, encoding="utf-8")
                                    semantic_profile["cfg_json_path"] = str(cfg_json_path)
                                if cfg_dot_path is not None:
                                    cfg_graph_count += 1
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

                archive_summary: dict[str, object] | None = None
                if table_name == "cache" and index_name == "MAPS" and archive_files:
                    archive_summary = _summarize_mapsquare_archive(
                        archive_key=int(key),
                        archive_files=archive_files,
                    )
                    if archive_summary is not None:
                        archive_summary_count += 1
                        archive_summary_kind = archive_summary.get("kind")
                        if isinstance(archive_summary_kind, str) and archive_summary_kind:
                            archive_summary_kind_counts[archive_summary_kind] = (
                                archive_summary_kind_counts.get(archive_summary_kind, 0) + 1
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
                        "archive_summary": archive_summary,
                    }
                )

            table_payloads[table_name] = {
                "record_count": len(records),
                "records": records,
            }

    if clientscript_opcode_catalog:
        clientscript_opcode_catalog_path = destination / "clientscript-opcode-catalog.json"
        clientscript_opcode_catalog_path.write_text(
            json.dumps(
                {
                    "tool": {
                        "name": "reverser-workbench",
                        "version": __version__,
                    },
                    "source_path": str(target),
                    "catalog_opcode_count": len(clientscript_opcode_catalog),
                    "semantic_override_source": clientscript_semantic_source,
                    "semantic_override_build": clientscript_semantic_build,
                    "opcodes": [
                        clientscript_opcode_catalog[raw_opcode]
                        for raw_opcode in sorted(clientscript_opcode_catalog)
                    ],
                },
                indent=2,
            ),
            encoding="utf-8",
        )
    if clientscript_control_flow_candidates:
        clientscript_control_flow_candidates_path = destination / "clientscript-control-flow-candidates.json"
        control_flow_payload: dict[str, object] = {
            "tool": {
                "name": "reverser-workbench",
                "version": __version__,
            },
            "source_path": str(target),
            "frontier_opcode_count": len(clientscript_control_flow_candidates),
            "semantic_override_source": clientscript_semantic_source,
            "semantic_override_build": clientscript_semantic_build,
            "opcodes": sorted(
                clientscript_control_flow_candidates.values(),
                key=lambda entry: (
                    -int(entry["switch_script_count"]),
                    -int(entry["script_count"]),
                    int(entry["raw_opcode"]),
                ),
            ),
        }
        if clientscript_control_flow_summary is not None:
            control_flow_payload["initial_frontier_opcode_count"] = int(
                clientscript_control_flow_summary.get("frontier_opcode_count", len(clientscript_control_flow_candidates))
            )
        if clientscript_post_context_control_flow_summary is not None:
            control_flow_payload["post_contextual_frontier_opcode_count"] = int(
                clientscript_post_context_control_flow_summary.get("frontier_opcode_count", 0)
            )
        if clientscript_recursive_control_flow_summary is not None:
            control_flow_payload["recursive_frontier_opcode_count"] = int(
                clientscript_recursive_control_flow_summary.get("frontier_opcode_count", 0)
            )
        clientscript_control_flow_candidates_path.write_text(
            json.dumps(control_flow_payload, indent=2),
            encoding="utf-8",
        )
        semantic_suggestions = _build_clientscript_semantic_suggestions(
            clientscript_control_flow_candidates,
            clientscript_contextual_frontier_candidates,
        )
        if semantic_suggestions:
            clientscript_semantic_suggestions_path = destination / CLIENTSCRIPT_SEMANTICS_FILENAME
            clientscript_semantic_suggestions_path.write_text(
                json.dumps(
                    {
                        "tool": {
                            "name": "reverser-workbench",
                            "version": __version__,
                        },
                        "build": clientscript_semantic_build,
                        "source_path": str(target),
                        "opcodes": semantic_suggestions,
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )

    if clientscript_producer_candidates:
        clientscript_producer_candidates_path = destination / "clientscript-producer-candidates.json"
        clientscript_producer_candidates_path.write_text(
            json.dumps(
                {
                    "tool": {
                        "name": "reverser-workbench",
                        "version": __version__,
                    },
                    "source_path": str(target),
                    "producer_opcode_count": len(clientscript_producer_candidates),
                    "semantic_override_source": clientscript_semantic_source,
                    "semantic_override_build": clientscript_semantic_build,
                    "opcodes": sorted(
                        clientscript_producer_candidates.values(),
                        key=lambda entry: (
                            -int(entry.get("control_flow_successor_count", 0)),
                            -int(entry.get("script_count", 0)),
                            int(entry["raw_opcode"]),
                        ),
                    ),
                },
                indent=2,
            ),
            encoding="utf-8",
        )

    if clientscript_contextual_frontier_candidates:
        clientscript_contextual_frontier_candidates_path = destination / "clientscript-contextual-frontier-candidates.json"
        clientscript_contextual_frontier_candidates_path.write_text(
            json.dumps(
                {
                    "tool": {
                        "name": "reverser-workbench",
                        "version": __version__,
                    },
                    "source_path": str(target),
                    "frontier_opcode_count": len(clientscript_contextual_frontier_candidates),
                    "semantic_override_source": clientscript_semantic_source,
                    "semantic_override_build": clientscript_semantic_build,
                    "opcodes": sorted(
                        clientscript_contextual_frontier_candidates.values(),
                        key=lambda entry: (
                            -int(entry.get("prefix_switch_dispatch_count", 0)),
                            -int(entry.get("script_count", 0)),
                            int(entry["raw_opcode"]),
                        ),
                    ),
                },
                indent=2,
            ),
            encoding="utf-8",
        )

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
        "clientscript_opcode_catalog_path": (
            str(clientscript_opcode_catalog_path) if clientscript_opcode_catalog_path is not None else None
        ),
        "clientscript_control_flow_candidates_path": (
            str(clientscript_control_flow_candidates_path)
            if clientscript_control_flow_candidates_path is not None
            else None
        ),
        "clientscript_producer_candidates_path": (
            str(clientscript_producer_candidates_path)
            if clientscript_producer_candidates_path is not None
            else None
        ),
        "clientscript_contextual_frontier_candidates_path": (
            str(clientscript_contextual_frontier_candidates_path)
            if clientscript_contextual_frontier_candidates_path is not None
            else None
        ),
        "clientscript_semantic_suggestions_path": (
            str(clientscript_semantic_suggestions_path)
            if clientscript_semantic_suggestions_path is not None
            else None
        ),
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
            "cfg_graph_count": cfg_graph_count,
            "archive_summary_count": archive_summary_count,
            "archive_summary_kind_counts": archive_summary_kind_counts,
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
    if clientscript_calibration_summary is not None:
        if clientscript_opcode_catalog_summary is not None:
            clientscript_calibration_summary["opcode_catalog"] = clientscript_opcode_catalog_summary
        if clientscript_control_flow_summary is not None:
            clientscript_calibration_summary["control_flow_candidates"] = clientscript_control_flow_summary
        if clientscript_producer_summary is not None:
            clientscript_calibration_summary["producer_candidates"] = clientscript_producer_summary
        if clientscript_contextual_frontier_summary is not None:
            clientscript_calibration_summary["contextual_frontier_candidates"] = clientscript_contextual_frontier_summary
        if clientscript_semantic_source is not None:
            clientscript_calibration_summary["semantic_override_source"] = clientscript_semantic_source
        if clientscript_semantic_build is not None:
            clientscript_calibration_summary["semantic_override_build"] = clientscript_semantic_build
        manifest["clientscript_calibration"] = clientscript_calibration_summary
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest
