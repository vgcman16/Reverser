from __future__ import annotations

import copy
import bz2
import hashlib
import json
import lzma
import os
import re
import sqlite3
import tempfile
import zlib
from collections import Counter, deque
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
CLIENTSCRIPT_SUPPORTED_IMMEDIATE_TYPES = CLIENTSCRIPT_IMMEDIATE_TYPES + ("string", "none", "bytes")
CLIENTSCRIPT_TAIL_CONTINUATION_MAX_INSTRUCTIONS = 12
CLIENTSCRIPT_BUDGET_RELAXED_MAX_GAP = 12
CLIENTSCRIPT_BUILTIN_OPCODE_HINTS: dict[int, dict[str, object]] = {
    0x0195: {
        "mnemonic": "UI_LINK_RECORD_CANDIDATE",
        "family": "widget-bridge",
        "immediate_kind": "int",
        "confidence": 0.86,
        "notes": (
            "Repeated low-entropy UI scripts encode 0x0195 as a 32-bit scalar bridge between "
            "0x0511 style setters and either another flat setter or the 0x0495 terminator."
        ),
        "status": "builtin-hint",
    },
    0x0200: {
        "mnemonic": "COMPACT_STATE_PREFIX_CANDIDATE",
        "family": "control-prefix",
        "immediate_kind": "byte",
        "confidence": 0.8,
        "notes": (
            "Across the UI corpus 0x0200 repeatedly behaves as a one-byte compact prefix that "
            "hands straight into 0x1100, 0x1700, 0x0005, 0x5E00, or neighboring flat setters."
        ),
        "status": "builtin-hint",
    },
    0x0105: {
        "mnemonic": "COMPACT_STATE_PREFIX_CANDIDATE",
        "family": "control-prefix",
        "immediate_kind": "byte",
        "confidence": 0.77,
        "notes": (
            "Repeated low-entropy UI tails encode 0x0105 as a one-byte compact prefix that hands "
            "straight into 0x0511 style setters and neighboring flat widget bridge opcodes like "
            "0x0195 instead of opening a nested shell dispatch."
        ),
        "status": "builtin-hint",
    },
    0x025A: {
        "mnemonic": "SCALAR_SELECTOR_CANDIDATE",
        "family": "scalar-bridge",
        "immediate_kind": "int",
        "confidence": 0.78,
        "notes": (
            "String-rich widget lanes repeatedly encode 0x025A as a flat 32-bit scalar selector "
            "immediately before 0x0511 text/style setters and follow-up flat setters like 0x0267."
        ),
        "status": "builtin-hint",
    },
    0x0267: {
        "mnemonic": "SEQUENCE_SCALAR_BRIDGE_CANDIDATE",
        "family": "scalar-bridge",
        "immediate_kind": "int",
        "confidence": 0.84,
        "notes": (
            "Across string-rich widget lanes 0x0267 overwhelmingly carries a flat 32-bit scalar and "
            "then hands off to 0x0717, 0x0713, 0x035E, or the 0x0495 terminator."
        ),
        "status": "builtin-hint",
    },
    0x0269: {
        "mnemonic": "COMPACT_STATE_PREFIX_CANDIDATE",
        "family": "control-prefix",
        "immediate_kind": "byte",
        "confidence": 0.81,
        "notes": (
            "Subtype-0 widget bridge families repeatedly hand control back to the flat UI setter "
            "stream through 0x0269 as a one-byte compact prefix before short 0x0511 text/style "
            "arms and the structured 0x035E terminal footer resume."
        ),
        "status": "builtin-hint",
    },
    0x025F: {
        "mnemonic": "COMPACT_PREFIX_MARKER_CANDIDATE",
        "family": "control-prefix",
        "immediate_kind": "byte",
        "confidence": 0.81,
        "notes": (
            "Repeated text-heavy widget tails encode 0x025F as a one-byte compact marker and then "
            "resume immediately into flat setters like 0x0511, 0x0195, 0x035E, or the 0x0495 terminator."
        ),
        "status": "builtin-hint",
    },
    0x0412: {
        "mnemonic": "STATIC_SCALAR_RECORD_CANDIDATE",
        "family": "widget-structure-record",
        "immediate_kind": "int",
        "confidence": 0.82,
        "notes": (
            "Repeated widget construction tails encode 0x0412 as a flat 32-bit scalar record and "
            "then hand off directly into the 0x0713 layout setter cadence."
        ),
        "status": "builtin-hint",
    },
    0x0464: {
        "mnemonic": "COMPACT_LAYOUT_PREFIX_CANDIDATE",
        "family": "layout-prefix",
        "immediate_kind": "byte",
        "confidence": 0.77,
        "notes": (
            "Compact UI tails repeatedly encode 0x0464 as a one-byte prefix that resumes "
            "immediately into 0x0495, 0x0511, 0x0713, 0x0895, or neighboring 0x035E records."
        ),
        "status": "builtin-hint",
    },
    0x0592: {
        "mnemonic": "STATEFUL_SCALAR_BRIDGE_CANDIDATE",
        "family": "scalar-bridge",
        "immediate_kind": "int",
        "confidence": 0.87,
        "notes": (
            "Across the live UI corpus 0x0592 overwhelmingly carries a flat 32-bit scalar and then "
            "hands off directly into compact markers, 0x035E bridge records, 0x0511 setters, or "
            "0x0713 layout arms instead of a nested short-width shell."
        ),
        "status": "builtin-hint",
    },
    0x03C8: {
        "mnemonic": "COMPACT_LAYOUT_MARKER_CANDIDATE",
        "family": "layout-prefix",
        "immediate_kind": "byte",
        "confidence": 0.82,
        "notes": (
            "Low-entropy widget tails repeatedly encode 0x03C8 as a one-byte layout marker before "
            "handing control to 0x0511, 0x0713, 0x0495, or adjacent 0x035E bridge records."
        ),
        "status": "builtin-hint",
    },
    0x056B: {
        "mnemonic": "COMPACT_LAYOUT_RESUME_CANDIDATE",
        "family": "layout-prefix",
        "immediate_kind": "byte",
        "confidence": 0.8,
        "notes": (
            "Representative tail blocks encode 0x056B as a one-byte compact resume marker that "
            "immediately hands back into 0x0495, 0x0511, 0x0713, 0x0895, or nearby 0x035E records."
        ),
        "status": "builtin-hint",
    },
    0x062C: {
        "mnemonic": "COMPACT_BRANCH_PREFIX_CANDIDATE",
        "family": "control-prefix",
        "immediate_kind": "byte",
        "confidence": 0.79,
        "notes": (
            "Representative UI tails encode 0x062C as a one-byte compact prefix and then hand "
            "straight back to 0x0495, 0x0511, 0x0713, 0x0895, or adjacent 0x035E bridge records."
        ),
        "status": "builtin-hint",
    },
    0x0862: {
        "mnemonic": "COMPACT_SCALAR_PREFIX_CANDIDATE",
        "family": "control-prefix",
        "immediate_kind": "byte",
        "confidence": 0.68,
        "notes": (
            "Rare but repeated text-rich widget tails encode 0x0862 as a one-byte compact prefix "
            "before resuming directly into the 0x0592 scalar bridge cadence."
        ),
        "status": "builtin-hint",
    },
    0x0713: {
        "mnemonic": "STATIC_LAYOUT_SETTER_CANDIDATE",
        "family": "widget-layout",
        "immediate_kind": "int",
        "confidence": 0.83,
        "notes": (
            "Repeated widget-layout tails encode 0x0713 as a flat 32-bit scalar setter that hands "
            "off directly into 0x0511 style arms, 0x035E bridge records, or the 0x0495 terminator."
        ),
        "status": "builtin-hint",
    },
    0x08B9: {
        "mnemonic": "WIDGET_STYLE_SCALAR_BRIDGE_CANDIDATE",
        "family": "widget-style",
        "immediate_kind": "int",
        "confidence": 0.8,
        "notes": (
            "Repeated widget-style tails encode 0x08B9 as a flat 32-bit scalar bridge and then "
            "resume through 0x0511, 0x025A, 0x0195, 0x035E, or 0x0495 without re-entering a shell dispatch."
        ),
        "status": "builtin-hint",
    },
    0x9502: {
        "mnemonic": "STATEFUL_WIDGET_SOURCE_ID_CANDIDATE",
        "family": "widget-source-id",
        "immediate_kind": "tribyte",
        "confidence": 0.8,
        "notes": (
            "Representative UI tails encode 0x9502 as a flat 24-bit source-id bridge and then "
            "resume directly through 0x0895 context binders or the 0x0495 terminator instead of "
            "re-entering a nested shell dispatch."
        ),
        "status": "builtin-hint",
    },
    0xCA02: {
        "mnemonic": "STATEFUL_SCALAR_BRIDGE_CANDIDATE",
        "family": "scalar-bridge",
        "immediate_kind": "int",
        "confidence": 0.79,
        "notes": (
            "Representative widget-state lanes encode 0xCA02 as a flat 32-bit scalar and then "
            "resume through the 0x1100 getter cadence instead of a nested shell dispatch."
        ),
        "status": "builtin-hint",
    },
    0xCA00: {
        "mnemonic": "STATEFUL_SCALAR_BRIDGE_CANDIDATE",
        "family": "scalar-bridge",
        "immediate_kind": "int",
        "confidence": 0.77,
        "notes": (
            "Sibling CA00 lanes mirror the CA02 rhythm: a flat 32-bit scalar prefix that hands "
            "execution back into getter and layout cadences instead of a compact dispatcher."
        ),
        "status": "builtin-hint",
    },
    0x03F2: {
        "mnemonic": "STATIC_LAYOUT_SCALAR_CANDIDATE",
        "family": "widget-layout",
        "immediate_kind": "int",
        "confidence": 0.8,
        "notes": (
            "Repeated widget-layout tails encode 0x03F2 as a 32-bit scalar setter that hands off "
            "into the 0x0713 cadence or adjacent flat widget-state setters."
        ),
        "status": "builtin-hint",
    },
}
CLIENTSCRIPT_FRONTIER_ONLY_SCOPE = "frontier-only"
CLIENTSCRIPT_STACK_NAMES = ("int", "string", "long")
DEFAULT_CLIENTSCRIPT_CALIBRATION_SAMPLE = 512
DEFAULT_CLIENTSCRIPT_MAX_SOLUTIONS = 32
DEFAULT_CLIENTSCRIPT_MAX_STATES = 20_000
DEFAULT_CLIENTSCRIPT_TRACE_INSTRUCTIONS = 256
DEFAULT_CLIENTSCRIPT_BRANCH_PROBE_SOFT_LIMIT = 12
DEFAULT_CLIENTSCRIPT_BRANCH_PROBE_HARD_LIMIT = 24
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


def _write_text_artifact(path: Path, text: str, *, encoding: str = "utf-8") -> None:
    """Write text via a same-directory temp file to avoid sync-provider placeholder corruption."""

    path.parent.mkdir(parents=True, exist_ok=True)
    temp_name: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding=encoding,
            dir=path.parent,
            prefix=f"{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temp_name = handle.name
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temp_name, path)
    except Exception:
        if temp_name is not None:
            Path(temp_name).unlink(missing_ok=True)
        raise


def _write_json_artifact(path: Path, payload: object) -> None:
    _write_text_artifact(path, json.dumps(payload, indent=2), encoding="utf-8")


def _looks_plausible_clientscript_string(value: str) -> bool:
    if value == "":
        return True
    if len(value) > 256:
        return False

    printable_count = 0
    for character in value:
        codepoint = ord(character)
        if character in {"\t", "\n", "\r"} or 32 <= codepoint <= 126 or 160 <= codepoint <= 255:
            printable_count += 1

    return printable_count >= max(1, int(len(value) * 0.8))


def _extract_clientscript_string_operand_values(entry: dict[str, object]) -> list[str]:
    operand_samples = entry.get("consumed_operand_samples")
    if not isinstance(operand_samples, list):
        return []

    values: list[str] = []
    for sample in operand_samples:
        if not isinstance(sample, dict):
            continue
        string_operands = sample.get("string_operands")
        if not isinstance(string_operands, list):
            continue
        for operand in string_operands:
            if not isinstance(operand, dict):
                continue
            value = operand.get("value")
            if isinstance(value, str):
                values.append(value)
    return values


def _looks_like_clientscript_url_string(value: str) -> bool:
    stripped = value.strip()
    if len(stripped) < 8 or not _looks_plausible_clientscript_string(stripped):
        return False
    return bool(re.search(r"(?i)\b(?:https?://|www\.)", stripped))


def _looks_like_clientscript_message_string(value: str) -> bool:
    stripped = value.strip()
    if len(stripped) < 12 or not _looks_plausible_clientscript_string(stripped):
        return False
    if _looks_like_clientscript_url_string(stripped):
        return False
    if any(ord(character) < 32 and character not in {"\t", "\n", "\r"} for character in stripped):
        return False

    word_tokens = re.findall(r"[A-Za-z][A-Za-z'/-]*", stripped)
    if len(word_tokens) < 2:
        return False

    letter_count = sum(1 for character in stripped if character.isalpha())
    space_count = stripped.count(" ")
    punctuation_count = sum(1 for character in stripped if character in ".,!?:;'\"()-/[]")
    readable_count = letter_count + space_count + punctuation_count
    return (
        space_count >= 1
        and letter_count >= max(6, len(stripped) // 3)
        and readable_count >= max(1, int(len(stripped) * 0.7))
    )


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


def _normalize_artifact_path(value: str | Path) -> str:
    text = str(value).strip()
    text = text.replace("\\", "/")
    text = re.sub(r"^/+\?/+", "", text)
    if text.upper().startswith("UNC/"):
        text = "//" + text[4:]
    if re.match(r"^/[A-Za-z]:/", text):
        text = text[1:]
    return text.casefold()


def _load_json_object(path: Path) -> dict[str, object] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return None
    return payload if isinstance(payload, dict) else None


def _load_clientscript_cached_opcode_entries(path: Path) -> tuple[dict[int, dict[str, object]], dict[str, object] | None]:
    payload = _load_json_object(path)
    if payload is None:
        return {}, None

    opcode_entries = payload.get("opcodes")
    if not isinstance(opcode_entries, list):
        return {}, payload

    normalized: dict[int, dict[str, object]] = {}
    for entry in opcode_entries:
        if not isinstance(entry, dict):
            continue
        raw_opcode = _parse_clientscript_opcode_key(entry.get("raw_opcode"))
        if raw_opcode is None:
            raw_opcode = _parse_clientscript_opcode_key(entry.get("raw_opcode_hex"))
        if raw_opcode is None:
            continue
        normalized[raw_opcode] = entry

    return normalized, payload


def _lookup_clientscript_builtin_opcode_hint(raw_opcode: int) -> dict[str, object] | None:
    entry = CLIENTSCRIPT_BUILTIN_OPCODE_HINTS.get(int(raw_opcode))
    return dict(entry) if isinstance(entry, dict) else None


def _merge_clientscript_catalog_entry_with_builtin_hint(
    raw_opcode: int,
    entry: dict[str, object] | None,
) -> dict[str, object] | None:
    builtin_entry = _lookup_clientscript_builtin_opcode_hint(raw_opcode)
    normalized_entry = dict(entry) if isinstance(entry, dict) else None
    if builtin_entry is None:
        return normalized_entry
    if normalized_entry is None:
        return builtin_entry

    catalog_label = str(
        normalized_entry.get("mnemonic")
        or normalized_entry.get("semantic_label")
        or normalized_entry.get("candidate_mnemonic")
        or ""
    )
    catalog_immediate_kind = normalized_entry.get(
        "immediate_kind",
        normalized_entry.get("expected_immediate_kind"),
    )
    builtin_immediate_kind = builtin_entry.get(
        "immediate_kind",
        builtin_entry.get("expected_immediate_kind"),
    )
    if (
        _is_clientscript_frontier_semantic_label(catalog_label)
        or (
            isinstance(catalog_immediate_kind, str)
            and isinstance(builtin_immediate_kind, str)
            and catalog_immediate_kind in CLIENTSCRIPT_SUPPORTED_IMMEDIATE_TYPES
            and builtin_immediate_kind in CLIENTSCRIPT_SUPPORTED_IMMEDIATE_TYPES
            and catalog_immediate_kind != builtin_immediate_kind
        )
    ):
        merged = dict(normalized_entry)
        merged.update(builtin_entry)
        return merged
    return normalized_entry


def _resolve_clientscript_cache_artifact_path(
    cache_root: Path,
    manifest_payload: dict[str, object],
    *,
    manifest_key: str,
    default_name: str,
) -> Path | None:
    artifact_path = manifest_payload.get(manifest_key)
    if isinstance(artifact_path, str):
        candidate = Path(artifact_path)
        if candidate.is_file():
            return candidate
    fallback = cache_root / default_name
    if fallback.is_file():
        return fallback
    return None


def _summarize_cached_clientscript_catalog_payload(
    payload: dict[str, object] | None,
    *,
    fallback_count: int,
) -> dict[str, object] | None:
    if payload is None:
        return None
    return {
        "catalog_opcode_count": int(payload.get("catalog_opcode_count", fallback_count)),
        "semantic_override_source": payload.get("semantic_override_source"),
        "semantic_override_build": payload.get("semantic_override_build"),
    }


def _summarize_cached_clientscript_candidate_payload(
    payload: dict[str, object] | None,
    *,
    fallback_count: int,
    count_keys: tuple[str, ...] = ("frontier_opcode_count",),
) -> dict[str, object] | None:
    if payload is None:
        return None
    summary: dict[str, object] = {}
    for key in count_keys:
        if key in payload:
            try:
                summary[key] = int(payload.get(key, 0))
            except (TypeError, ValueError):
                continue
    if not summary and fallback_count > 0:
        summary[count_keys[0]] = fallback_count
    return summary or None


def _make_clientscript_override_stack_effect_from_stack_pops(
    stack_pops: Sequence[object],
) -> dict[str, object] | None:
    normalized_pops = [str(token).strip() for token in stack_pops if str(token).strip()]
    if not normalized_pops:
        return None

    int_like_tokens = {"widget", "int", "state-int", "literal-int", "slot-int", "symbolic-int"}
    int_pops = sum(1 for token in normalized_pops if token in int_like_tokens)
    string_pops = sum(1 for token in normalized_pops if token in {"string", "string-only", "string-input"})
    long_pops = sum(1 for token in normalized_pops if token == "long")
    if int_pops <= 0 and string_pops <= 0 and long_pops <= 0:
        return None
    return _make_clientscript_stack_effect(
        int_pops=int_pops,
        string_pops=string_pops,
        long_pops=long_pops,
        confidence=0.78,
        notes="Subtype override supplied an explicit consumed operand window.",
    )


def _allows_clientscript_resolution_scope(
    catalog_entry: dict[str, object] | None,
    *,
    resolution_scope: str,
) -> bool:
    if not isinstance(catalog_entry, dict):
        return False
    entry_scope = str(catalog_entry.get("resolution_scope", "") or "")
    if entry_scope == CLIENTSCRIPT_FRONTIER_ONLY_SCOPE and resolution_scope != "frontier":
        return False
    return True


def _classify_clientscript_subtype_override_resolution_scope(
    *,
    confidence: str,
    observation_count: int,
) -> str | None:
    normalized_confidence = str(confidence or "").lower()
    if normalized_confidence == "high" and observation_count >= 3:
        return None
    if normalized_confidence in {"high", "medium"} and observation_count >= 3:
        return CLIENTSCRIPT_FRONTIER_ONLY_SCOPE
    if normalized_confidence == "high" and observation_count > 0:
        return CLIENTSCRIPT_FRONTIER_ONLY_SCOPE
    return "skip"


def _should_force_clientscript_frontier_only_subtype_opcode(
    raw_opcode: int,
) -> bool:
    return int(raw_opcode) in {
        0x9500,
    }


def _normalize_clientscript_semantic_override_entry(
    entry: dict[str, object],
    *,
    allow_subtypes: bool,
) -> dict[str, object]:
    normalized_entry: dict[str, object] = {}
    mnemonic = entry.get("mnemonic", entry.get("candidate_mnemonic", entry.get("name")))
    if isinstance(mnemonic, str) and mnemonic:
        normalized_entry["mnemonic"] = mnemonic
    for field in (
        "family",
        "notes",
        "status",
        "control_flow_kind",
        "jump_base",
        "promotion_source",
    ):
        field_value = entry.get(field)
        if isinstance(field_value, str) and field_value:
            normalized_entry[field] = field_value
    dispatch_mode = entry.get("subtype_dispatch_mode")
    if isinstance(dispatch_mode, str) and dispatch_mode:
        normalized_entry["subtype_dispatch_mode"] = dispatch_mode
    resolution_scope = entry.get("resolution_scope")
    if isinstance(resolution_scope, str) and resolution_scope:
        normalized_entry["resolution_scope"] = resolution_scope
    strict_subtype_dispatch = entry.get("strict_subtype_dispatch")
    if isinstance(strict_subtype_dispatch, bool):
        normalized_entry["strict_subtype_dispatch"] = strict_subtype_dispatch
    canonical_id = entry.get("canonical_id")
    if isinstance(canonical_id, int):
        normalized_entry["canonical_id"] = canonical_id
    jump_scale = entry.get("jump_scale")
    if isinstance(jump_scale, int):
        normalized_entry["jump_scale"] = jump_scale
    immediate_width = entry.get("immediate_width")
    if isinstance(immediate_width, int) and immediate_width >= 0:
        normalized_entry["immediate_width"] = int(immediate_width)
    confidence = entry.get("confidence")
    if isinstance(confidence, (int, float)):
        normalized_entry["confidence"] = float(confidence)
    aliases = entry.get("aliases")
    if isinstance(aliases, list):
        normalized_aliases = [str(alias) for alias in aliases if str(alias)]
        if normalized_aliases:
            normalized_entry["aliases"] = normalized_aliases

    immediate_kind = entry.get("immediate_kind", entry.get("expected_immediate_kind"))
    if not (
        isinstance(immediate_kind, str)
        and immediate_kind in CLIENTSCRIPT_SUPPORTED_IMMEDIATE_TYPES
    ):
        width_to_kind = {0: "none", 1: "byte", 2: "short", 3: "tribyte", 4: "int"}
        if isinstance(immediate_width, int):
            immediate_kind = width_to_kind.get(int(immediate_width))
    if isinstance(immediate_kind, str) and immediate_kind in CLIENTSCRIPT_SUPPORTED_IMMEDIATE_TYPES:
        normalized_entry["immediate_kind"] = immediate_kind

    operand_signature_candidate = entry.get("operand_signature_candidate")
    if isinstance(operand_signature_candidate, dict) and operand_signature_candidate:
        normalized_entry["operand_signature_candidate"] = dict(operand_signature_candidate)
    stack_effect_candidate = entry.get("stack_effect_candidate")
    if isinstance(stack_effect_candidate, dict) and stack_effect_candidate:
        normalized_entry["stack_effect_candidate"] = dict(stack_effect_candidate)

    stack_pops = entry.get("stack_pops")
    if isinstance(stack_pops, list) and stack_pops:
        normalized_stack_pops = [str(token).strip() for token in stack_pops if str(token).strip()]
        if normalized_stack_pops:
            normalized_entry["stack_pops"] = normalized_stack_pops
            if "operand_signature_candidate" not in normalized_entry:
                normalized_entry["operand_signature_candidate"] = {
                    "signature": "+".join(normalized_stack_pops),
                    "confidence": float(normalized_entry.get("confidence", 0.78)),
                    "notes": "Subtype override supplied an explicit operand signature.",
                }
            if "stack_effect_candidate" not in normalized_entry:
                inferred_stack_effect = _make_clientscript_override_stack_effect_from_stack_pops(
                    normalized_stack_pops
                )
                if inferred_stack_effect is not None:
                    normalized_entry["stack_effect_candidate"] = inferred_stack_effect

    contextual_stack_hints = entry.get("contextual_stack_hints")
    if isinstance(contextual_stack_hints, list):
        normalized_contextual_hints: list[dict[str, object]] = []
        for hint_entry in contextual_stack_hints:
            if not isinstance(hint_entry, dict):
                continue
            match_prefix_operand_signature = hint_entry.get("match_prefix_operand_signature")
            normalized_match_prefixes: list[str] = []
            if isinstance(match_prefix_operand_signature, str) and match_prefix_operand_signature.strip():
                normalized_match_prefixes = [match_prefix_operand_signature.strip()]
            elif isinstance(match_prefix_operand_signature, list):
                normalized_match_prefixes = [
                    str(signature).strip()
                    for signature in match_prefix_operand_signature
                    if str(signature).strip()
                ]
            if not normalized_match_prefixes:
                continue

            normalized_hint = _normalize_clientscript_semantic_override_entry(
                {
                    field: value
                    for field, value in hint_entry.items()
                    if field not in {"contextual_stack_hints", "match_prefix_operand_signature"}
                },
                allow_subtypes=False,
            )
            if not normalized_hint:
                normalized_hint = {}
            if len(normalized_match_prefixes) == 1:
                normalized_hint["match_prefix_operand_signature"] = normalized_match_prefixes[0]
            else:
                normalized_hint["match_prefix_operand_signature"] = normalized_match_prefixes
            normalized_contextual_hints.append(normalized_hint)
        if normalized_contextual_hints:
            normalized_entry["contextual_stack_hints"] = normalized_contextual_hints

    if allow_subtypes:
        subtype_entries = entry.get("subtypes")
        normalized_subtypes: dict[int, dict[str, object]] = {}
        if isinstance(subtype_entries, dict):
            subtype_items = subtype_entries.items()
        elif isinstance(subtype_entries, list):
            subtype_items = []
            for subtype_entry in subtype_entries:
                if not isinstance(subtype_entry, dict):
                    continue
                subtype_key = subtype_entry.get("sub_opcode", subtype_entry.get("sub_opcode_hex"))
                subtype_items.append((subtype_key, subtype_entry))
        else:
            subtype_items = []

        for subtype_key, subtype_entry in subtype_items:
            sub_opcode = _parse_clientscript_opcode_key(subtype_key)
            if sub_opcode is None or not isinstance(subtype_entry, dict):
                continue
            normalized_sub_entry = _normalize_clientscript_semantic_override_entry(
                subtype_entry,
                allow_subtypes=False,
            )
            if normalized_sub_entry:
                normalized_sub_entry["sub_opcode"] = int(sub_opcode)
                normalized_sub_entry["sub_opcode_hex"] = f"0x{int(sub_opcode):02X}"
                normalized_subtypes[int(sub_opcode)] = normalized_sub_entry
        if normalized_subtypes:
            normalized_entry["subtypes"] = normalized_subtypes

    return normalized_entry


def _normalize_clientscript_semantic_override_payload(
    payload: dict[str, object] | None,
) -> tuple[dict[int, dict[str, object]], int | None]:
    if not isinstance(payload, dict):
        return {}, None

    entries = payload.get("opcodes", payload)
    if not isinstance(entries, dict):
        return {}, None

    normalized: dict[int, dict[str, object]] = {}
    for raw_key, entry in entries.items():
        raw_opcode = _parse_clientscript_opcode_key(raw_key)
        if raw_opcode is None or not isinstance(entry, dict):
            continue
        normalized_entry = _normalize_clientscript_semantic_override_entry(
            entry,
            allow_subtypes=True,
        )
        if normalized_entry:
            normalized[raw_opcode] = normalized_entry

    build = payload.get("build")
    try:
        normalized_build = int(build) if build is not None else None
    except (TypeError, ValueError):
        normalized_build = None

    return normalized, normalized_build


def _load_clientscript_semantic_override_file(path: Path) -> tuple[dict[int, dict[str, object]], int | None] | None:
    try:
        payload = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return None

    normalized, build = _normalize_clientscript_semantic_override_payload(payload)
    if not normalized:
        return None
    return normalized, build


def _load_clientscript_subtype_override_artifacts(
    cache_root: Path,
) -> dict[int, dict[str, object]]:
    normalized: dict[int, dict[str, object]] = {}
    for artifact_path in sorted(cache_root.glob("clientscript-opcode-subtypes-*.json")):
        payload = _load_json_object(artifact_path)
        if payload is None:
            continue
        raw_opcode = _parse_clientscript_opcode_key(
            payload.get("raw_opcode_hex", payload.get("raw_opcode"))
        )
        if raw_opcode is None:
            continue
        candidates = payload.get("blocked_frontier_subtype_candidates")
        if not isinstance(candidates, list):
            continue

        subtype_entries: dict[str, dict[str, object]] = {}
        subtype_scopes: list[str | None] = []
        for candidate in candidates:
            if not isinstance(candidate, dict):
                continue
            confidence = str(candidate.get("confidence", "") or "").lower()
            try:
                observation_count = int(candidate.get("observation_count", 0))
            except (TypeError, ValueError):
                observation_count = 0
            resolution_scope = _classify_clientscript_subtype_override_resolution_scope(
                confidence=confidence,
                observation_count=observation_count,
            )
            if resolution_scope == "skip":
                continue
            if _should_force_clientscript_frontier_only_subtype_opcode(int(raw_opcode)):
                resolution_scope = CLIENTSCRIPT_FRONTIER_ONLY_SCOPE
            suggested_override = candidate.get("suggested_override")
            if not isinstance(suggested_override, dict):
                continue
            sub_opcode = _parse_clientscript_opcode_key(
                suggested_override.get("sub_opcode", candidate.get("sub_opcode_hex"))
            )
            if sub_opcode is None:
                continue
            override_notes = suggested_override.get("notes")
            if not isinstance(override_notes, str) or not override_notes.strip():
                override_notes = None
            override_stack_pops = suggested_override.get(
                "stack_pops",
                candidate.get("dominant_stack_pops"),
            )
            match_prefix_operand_signature = suggested_override.get("match_prefix_operand_signature")
            normalized_match_prefixes: list[str] = []
            if (
                isinstance(match_prefix_operand_signature, str)
                and match_prefix_operand_signature.strip()
            ):
                normalized_match_prefixes = [match_prefix_operand_signature.strip()]
            elif isinstance(match_prefix_operand_signature, list):
                normalized_match_prefixes = [
                    str(signature).strip()
                    for signature in match_prefix_operand_signature
                    if str(signature).strip()
                ]
            base_notes = (
                f"High-confidence subtype override loaded from {artifact_path.name}; "
                f"dominant landing opcode {candidate.get('recommended_landing_opcode_hex')}."
            )
            if override_notes:
                base_notes = f"{base_notes} {override_notes.strip()}"
            subtype_entry: dict[str, object] = {
                "mnemonic": suggested_override.get("name"),
                "family": "widget-extension-dispatch",
                "status": "promoted-candidate",
                "promotion_source": "opcode-subtype-probe",
                "confidence": 0.9 if confidence == "high" else 0.78,
                "immediate_width": suggested_override.get(
                    "immediate_width",
                    candidate.get("recommended_immediate_width"),
                ),
                "immediate_kind": suggested_override.get(
                    "immediate_kind",
                    candidate.get("recommended_immediate_kind"),
                ),
                "notes": base_notes,
            }
            if isinstance(override_stack_pops, list):
                if normalized_match_prefixes:
                    contextual_hint: dict[str, object] = {
                        "mnemonic": suggested_override.get("name"),
                        "family": "widget-extension-dispatch",
                        "confidence": 0.9 if confidence == "high" else 0.78,
                        "resolution_scope": CLIENTSCRIPT_FRONTIER_ONLY_SCOPE,
                        "stack_pops": list(override_stack_pops),
                        "notes": (
                            "Subtype override supplied a prefix-gated consumed operand window."
                        ),
                    }
                    if len(normalized_match_prefixes) == 1:
                        contextual_hint["match_prefix_operand_signature"] = normalized_match_prefixes[0]
                    else:
                        contextual_hint["match_prefix_operand_signature"] = list(normalized_match_prefixes)
                    if override_notes:
                        contextual_hint["notes"] = (
                            f"{contextual_hint['notes']} {override_notes.strip()}"
                        )
                    subtype_entry["contextual_stack_hints"] = [contextual_hint]
                else:
                    subtype_entry["stack_pops"] = list(override_stack_pops)
            if resolution_scope == CLIENTSCRIPT_FRONTIER_ONLY_SCOPE:
                subtype_entry["resolution_scope"] = CLIENTSCRIPT_FRONTIER_ONLY_SCOPE
                subtype_entry["notes"] = (
                    f"Frontier-only subtype override loaded from {artifact_path.name}; "
                    f"dominant landing opcode {candidate.get('recommended_landing_opcode_hex')}."
                )
                if override_notes:
                    subtype_entry["notes"] = (
                        f"{subtype_entry['notes']} {override_notes.strip()}"
                    )
            normalized_subtype_entry = _normalize_clientscript_semantic_override_entry(
                subtype_entry,
                allow_subtypes=False,
            )
            if normalized_subtype_entry:
                subtype_entries[f"0x{int(sub_opcode):02X}"] = normalized_subtype_entry
                subtype_scopes.append(resolution_scope)

        if subtype_entries:
            raw_entry_payload: dict[str, object] = {
                "mnemonic": "EXTENSION_DISPATCH_CANDIDATE",
                "family": "extension-dispatch",
                "status": "promoted-candidate",
                "promotion_source": "opcode-subtype-probe",
                "subtype_dispatch_mode": "prefer-known-subtypes",
                "subtypes": subtype_entries,
            }
            if subtype_scopes and all(scope == CLIENTSCRIPT_FRONTIER_ONLY_SCOPE for scope in subtype_scopes):
                raw_entry_payload["resolution_scope"] = CLIENTSCRIPT_FRONTIER_ONLY_SCOPE
            raw_entry = _normalize_clientscript_semantic_override_entry(
                raw_entry_payload,
                allow_subtypes=True,
            )
            if raw_entry:
                normalized[int(raw_opcode)] = raw_entry

    return normalized


def _load_clientscript_semantic_overrides_from_cache_dir(
    cache_dir: str | Path,
    *,
    source_path: str | Path,
) -> tuple[dict[int, dict[str, object]], str | None, int | None]:
    cache_root = Path(cache_dir)
    candidate = cache_root / CLIENTSCRIPT_SEMANTICS_FILENAME
    subtype_overrides = _load_clientscript_subtype_override_artifacts(cache_root)
    if not candidate.is_file():
        if subtype_overrides:
            return subtype_overrides, None, None
        return {}, None, None

    try:
        payload = json.loads(candidate.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        if subtype_overrides:
            return subtype_overrides, None, None
        return {}, None, None

    cached_source_path = payload.get("source_path") if isinstance(payload, dict) else None
    if isinstance(cached_source_path, str) and _normalize_artifact_path(cached_source_path) != _normalize_artifact_path(
        source_path
    ):
        if subtype_overrides:
            return subtype_overrides, None, None
        return {}, None, None

    normalized, build = _normalize_clientscript_semantic_override_payload(payload)
    if subtype_overrides:
        merged_overrides = {
            int(raw_opcode): dict(entry)
            for raw_opcode, entry in normalized.items()
        }
        for raw_opcode, override_entry in subtype_overrides.items():
            _merge_clientscript_catalog_entry(merged_overrides, int(raw_opcode), override_entry)
        normalized = merged_overrides
    if not normalized:
        return {}, None, None
    return normalized, str(candidate), build


def _load_cached_clientscript_analysis(
    cache_dir: str | Path,
    *,
    source_path: str | Path,
) -> tuple[dict[str, object] | None, str | None]:
    cache_root = Path(cache_dir)
    if not cache_root.is_dir():
        return None, f"clientscript cache dir not found: {cache_root}"

    manifest_path = cache_root / "manifest.json"
    manifest_payload = _load_json_object(manifest_path)
    if manifest_payload is None:
        return None, f"clientscript cache manifest missing or invalid: {manifest_path}"

    if str(manifest_payload.get("index_name", "")) != "CLIENTSCRIPTS":
        return None, f"clientscript cache manifest is not for CLIENTSCRIPTS: {manifest_path}"

    cached_source_path = manifest_payload.get("source_path")
    if not isinstance(cached_source_path, str) or _normalize_artifact_path(cached_source_path) != _normalize_artifact_path(
        source_path
    ):
        return None, f"clientscript cache source mismatch: {cache_root}"

    settings_payload = manifest_payload.get("settings")
    if isinstance(settings_payload, dict):
        cached_keys = settings_payload.get("keys")
        cached_limit = settings_payload.get("limit")
        if (isinstance(cached_keys, list) and len(cached_keys) > 0) or cached_limit is not None:
            return None, None

    opcode_catalog_path = _resolve_clientscript_cache_artifact_path(
        cache_root,
        manifest_payload,
        manifest_key="clientscript_opcode_catalog_path",
        default_name="clientscript-opcode-catalog.json",
    )
    if opcode_catalog_path is None:
        return None, f"clientscript cache is missing an opcode catalog: {cache_root}"

    opcode_catalog, opcode_catalog_payload = _load_clientscript_cached_opcode_entries(opcode_catalog_path)
    if not opcode_catalog:
        return None, f"clientscript cache opcode catalog is empty or invalid: {opcode_catalog_path}"

    control_flow_candidates: dict[int, dict[str, object]] = {}
    control_flow_payload: dict[str, object] | None = None
    control_flow_path = _resolve_clientscript_cache_artifact_path(
        cache_root,
        manifest_payload,
        manifest_key="clientscript_control_flow_candidates_path",
        default_name="clientscript-control-flow-candidates.json",
    )
    if control_flow_path is not None:
        control_flow_candidates, control_flow_payload = _load_clientscript_cached_opcode_entries(control_flow_path)

    producer_candidates: dict[int, dict[str, object]] = {}
    producer_payload: dict[str, object] | None = None
    producer_path = _resolve_clientscript_cache_artifact_path(
        cache_root,
        manifest_payload,
        manifest_key="clientscript_producer_candidates_path",
        default_name="clientscript-producer-candidates.json",
    )
    if producer_path is not None:
        producer_candidates, producer_payload = _load_clientscript_cached_opcode_entries(producer_path)

    contextual_candidates: dict[int, dict[str, object]] = {}
    contextual_payload: dict[str, object] | None = None
    contextual_path = _resolve_clientscript_cache_artifact_path(
        cache_root,
        manifest_payload,
        manifest_key="clientscript_contextual_frontier_candidates_path",
        default_name="clientscript-contextual-frontier-candidates.json",
    )
    if contextual_path is not None:
        contextual_candidates, contextual_payload = _load_clientscript_cached_opcode_entries(contextual_path)

    string_candidates: dict[int, dict[str, object]] = {}
    string_payload: dict[str, object] | None = None
    string_path = _resolve_clientscript_cache_artifact_path(
        cache_root,
        manifest_payload,
        manifest_key="clientscript_string_frontier_candidates_path",
        default_name="clientscript-string-frontier-candidates.json",
    )
    if string_path is not None:
        string_candidates, string_payload = _load_clientscript_cached_opcode_entries(string_path)

    semantic_overrides: dict[int, dict[str, object]] = {}
    semantic_override_source = manifest_payload.get("clientscript_semantic_suggestions_path")
    semantic_override_build: int | None = None
    semantic_override_path = _resolve_clientscript_cache_artifact_path(
        cache_root,
        manifest_payload,
        manifest_key="clientscript_semantic_suggestions_path",
        default_name=CLIENTSCRIPT_SEMANTICS_FILENAME,
    )
    if semantic_override_path is not None:
        semantic_override_payload = _load_clientscript_semantic_override_file(semantic_override_path)
        if semantic_override_payload is not None:
            semantic_overrides, semantic_override_build = semantic_override_payload
            semantic_override_source = str(semantic_override_path)

    calibration_summary = manifest_payload.get("clientscript_calibration")
    if not isinstance(calibration_summary, dict):
        calibration_summary = {"locked_opcode_type_count": 0}
    calibration_summary = copy.deepcopy(calibration_summary)
    calibration_summary["cache_mode"] = "reused"
    calibration_summary["cache_source"] = str(cache_root)

    return {
        "cache_root": str(cache_root),
        "manifest": manifest_payload,
        "opcode_catalog": opcode_catalog,
        "opcode_catalog_summary": _summarize_cached_clientscript_catalog_payload(
            opcode_catalog_payload,
            fallback_count=len(opcode_catalog),
        ),
        "control_flow_candidates": control_flow_candidates,
        "control_flow_summary": _summarize_cached_clientscript_candidate_payload(
            control_flow_payload,
            fallback_count=len(control_flow_candidates),
            count_keys=(
                "frontier_opcode_count",
                "initial_frontier_opcode_count",
                "post_contextual_frontier_opcode_count",
                "recursive_frontier_opcode_count",
                "post_string_frontier_opcode_count",
            ),
        ),
        "producer_candidates": producer_candidates,
        "producer_summary": _summarize_cached_clientscript_candidate_payload(
            producer_payload,
            fallback_count=len(producer_candidates),
            count_keys=("producer_opcode_count",),
        ),
        "contextual_frontier_candidates": contextual_candidates,
        "contextual_frontier_summary": _summarize_cached_clientscript_candidate_payload(
            contextual_payload,
            fallback_count=len(contextual_candidates),
        ),
        "string_frontier_candidates": string_candidates,
        "string_frontier_summary": _summarize_cached_clientscript_candidate_payload(
            string_payload,
            fallback_count=len(string_candidates),
        ),
        "semantic_overrides": semantic_overrides,
        "calibration_summary": calibration_summary,
        "semantic_override_source": semantic_override_source
        if isinstance(semantic_override_source, str)
        else (
            opcode_catalog_payload.get("semantic_override_source")
            if isinstance(opcode_catalog_payload, dict)
            else None
        ),
        "semantic_override_build": semantic_override_build
        if semantic_override_build is not None
        else (
            opcode_catalog_payload.get("semantic_override_build")
            if isinstance(opcode_catalog_payload, dict)
            else None
        ),
    }, None


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
        loaded = _load_clientscript_semantic_override_file(candidate)
        if loaded is None:
            continue
        normalized, normalized_build = loaded
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


def _default_clientscript_immediate_width(immediate_kind: str | None) -> int | None:
    width_by_kind = {
        "none": 0,
        "byte": 1,
        "short": 2,
        "tribyte": 3,
        "int": 4,
    }
    if not isinstance(immediate_kind, str):
        return None
    return width_by_kind.get(immediate_kind)


def _peek_clientscript_u32be(opcode_data: bytes, offset: int) -> int | None:
    if offset < 0 or offset + 4 > len(opcode_data):
        return None
    return int.from_bytes(opcode_data[offset : offset + 4], "big")


def _peek_clientscript_u16be(opcode_data: bytes, offset: int) -> int | None:
    if offset < 0 or offset + 2 > len(opcode_data):
        return None
    return int.from_bytes(opcode_data[offset : offset + 2], "big")


def _peek_clientscript_raw_opcode(opcode_data: bytes, offset: int) -> int | None:
    if offset < 0 or offset + 2 > len(opcode_data):
        return None
    return int.from_bytes(opcode_data[offset : offset + 2], "big")


def _is_known_clientscript_opcode_boundary(
    raw_opcode: int | None,
    *,
    raw_opcode_types: dict[int, str] | None = None,
    raw_opcode_catalog: dict[int, dict[str, object]] | None = None,
) -> bool:
    if not isinstance(raw_opcode, int):
        return False
    if isinstance(raw_opcode_types, dict):
        immediate_kind = raw_opcode_types.get(raw_opcode)
        if isinstance(immediate_kind, str) and immediate_kind in CLIENTSCRIPT_SUPPORTED_IMMEDIATE_TYPES:
            return True
    if isinstance(raw_opcode_catalog, dict):
        catalog_entry = raw_opcode_catalog.get(raw_opcode)
        if isinstance(catalog_entry, dict):
            immediate_kind = catalog_entry.get("immediate_kind", catalog_entry.get("expected_immediate_kind"))
            if isinstance(immediate_kind, str) and immediate_kind in CLIENTSCRIPT_SUPPORTED_IMMEDIATE_TYPES:
                return True
            mnemonic = catalog_entry.get("mnemonic")
            if isinstance(mnemonic, str) and mnemonic:
                return True
    return False


def _make_clientscript_opcode_only_layout(opcode_data: bytes) -> ClientscriptLayout:
    return ClientscriptLayout(
        byte0=0,
        opcode_data=opcode_data,
        instruction_count=0,
        local_int_count=0,
        local_string_count=0,
        local_long_count=0,
        int_argument_count=0,
        string_argument_count=0,
        long_argument_count=0,
        switch_table_count=0,
        switch_case_count=0,
        switch_tables=[],
        switch_tables_sample=[],
        switch_payload_bytes=0,
        footer_bytes=0,
    )


def _score_clientscript_signature_gated_path_trace(
    trace: dict[str, object],
    *,
    candidate_width: int,
    raw_opcode_types: dict[int, str] | None = None,
    raw_opcode_catalog: dict[int, dict[str, object]] | None = None,
) -> tuple[int, int, int, int]:
    status_rank = {
        "terminal": 6,
        "instruction-budget": 5,
        "next-control-flow": 4,
        "frontier": 3,
        "loop": 2,
        "out-of-bounds": 1,
        "invalid-immediate": 0,
    }
    status = str(trace.get("status", "") or "")
    instruction_count = int(trace.get("instruction_count", 0) or 0)
    if status == "out-of-bounds" and instruction_count > 0:
        status_rank = dict(status_rank)
        status_rank["out-of-bounds"] = 4
    next_instruction = trace.get("next_instruction")
    next_raw_opcode = (
        next_instruction.get("raw_opcode")
        if isinstance(next_instruction, dict)
        else None
    )
    next_known = (
        1
        if isinstance(next_raw_opcode, int)
        and _is_known_clientscript_opcode_boundary(
            next_raw_opcode,
            raw_opcode_types=raw_opcode_types,
            raw_opcode_catalog=raw_opcode_catalog,
        )
        else 0
    )
    return (
        int(status_rank.get(status, -1)),
        instruction_count,
        next_known,
        -int(candidate_width),
    )


def _resolve_clientscript_signature_gated_bytes_width_by_bounded_path(
    opcode_data: bytes,
    *,
    payload_offset: int,
    candidate_widths: list[int] | tuple[int, ...],
    raw_opcode_types: dict[int, str] | None = None,
    raw_opcode_catalog: dict[int, dict[str, object]] | None = None,
) -> int | None:
    if not candidate_widths:
        return None

    probe_layout = _make_clientscript_opcode_only_layout(opcode_data)
    best_width: int | None = None
    best_score: tuple[int, int, int, int] | None = None

    for candidate_width in candidate_widths:
        if not isinstance(candidate_width, int) or candidate_width <= 0:
            continue
        start_offset = payload_offset + candidate_width
        if start_offset > len(opcode_data):
            continue
        trace = _trace_clientscript_bounded_stack_path(
            probe_layout,
            start_offset=start_offset,
            initial_state=_make_clientscript_stack_state(),
            raw_opcode_types=raw_opcode_types,
            raw_opcode_catalog=raw_opcode_catalog,
            soft_instruction_limit=12,
            hard_instruction_limit=24,
        )
        score = _score_clientscript_signature_gated_path_trace(
            trace,
            candidate_width=candidate_width,
            raw_opcode_types=raw_opcode_types,
            raw_opcode_catalog=raw_opcode_catalog,
        )
        if best_score is None or score > best_score:
            best_width = int(candidate_width)
            best_score = score

    if best_width is None or best_score is None:
        return None

    if best_score[0] < 3:
        return None
    if best_score[0] < 5 and best_score[1] <= 0:
        return None
    return best_width


def _resolve_clientscript_signature_gated_bytes_width(
    step: dict[str, object] | None,
    *,
    immediate_kind: str | None = None,
    opcode_data: bytes | None = None,
    offset: int | None = None,
    raw_opcode_types: dict[int, str] | None = None,
    raw_opcode_catalog: dict[int, dict[str, object]] | None = None,
) -> tuple[bool, int | None]:
    if not isinstance(step, dict) or immediate_kind != "bytes" or not isinstance(opcode_data, bytes):
        return False, None

    raw_opcode = step.get("raw_opcode")
    if raw_opcode not in {0x035E, 0x0511}:
        return False, None

    step_offset = offset if isinstance(offset, int) else step.get("offset")
    if not isinstance(step_offset, int):
        return False, None

    if raw_opcode == 0x0511:
        payload_offset = step_offset + 2
        if payload_offset >= len(opcode_data) or opcode_data[payload_offset] != 0x02:
            return False, None
        try:
            text_value, text_end_offset = _read_c_string(opcode_data, payload_offset + 1)
        except ValueError:
            return False, None
        if not _looks_plausible_clientscript_string(text_value):
            return False, None
        candidate_width = text_end_offset - payload_offset
        if candidate_width == 5:
            return False, None
        inferred_width = _resolve_clientscript_signature_gated_bytes_width_by_bounded_path(
            opcode_data,
            payload_offset=payload_offset,
            candidate_widths=(5, candidate_width),
            raw_opcode_types=raw_opcode_types,
            raw_opcode_catalog=raw_opcode_catalog,
        )
        if inferred_width == candidate_width:
            return True, candidate_width
        next_opcode = _peek_clientscript_raw_opcode(opcode_data, text_end_offset)
        if _is_known_clientscript_opcode_boundary(
            next_opcode,
            raw_opcode_types=raw_opcode_types,
            raw_opcode_catalog=raw_opcode_catalog,
        ):
            return True, candidate_width
        return False, None

    payload_offset = step_offset + 2
    subtype_id = _peek_clientscript_u32be(opcode_data, payload_offset)
    remaining_payload_bytes = len(opcode_data) - payload_offset
    compact_marker_end_offset = payload_offset + 15
    compact_marker_opcode = _peek_clientscript_raw_opcode(opcode_data, compact_marker_end_offset)
    compact_marker_followup_opcode = _peek_clientscript_raw_opcode(opcode_data, compact_marker_end_offset + 2)
    compact_tail_opcode = _peek_clientscript_raw_opcode(opcode_data, payload_offset + 4)
    compact_tail_followup_opcode = _peek_clientscript_raw_opcode(opcode_data, payload_offset + 10)
    compact_tail_terminator = (
        opcode_data[payload_offset + 12]
        if payload_offset + 12 < len(opcode_data)
        else None
    )
    compact_marker_like_opcodes = {
        0x0000,
        0x0001,
        0x0002,
        0x0003,
        0x0004,
        0x0005,
        0x0006,
        0x0007,
        0x0008,
        0x001D,
        0x0200,
    }
    compact_high_signal_opcodes = {
        0x00E4,
        0x025A,
        0x02AA,
        0x035E,
        0x0389,
        0x03F2,
        0x0511,
        0x0592,
        0x0713,
        0x0895,
    }

    # Some structured widget records compact down by a single byte and hand
    # control back to the flat layout stream via a zero-width 0x0001 marker
    # before 0x0713 / 0x0511 / 0x035E / 0x0495 setters resume.
    if subtype_id in {0x00000000, 0x00000002} and compact_marker_opcode == 0x0001 and compact_marker_followup_opcode in {
        0x035E,
        0x0495,
        0x0511,
        0x0713,
    }:
        return True, 15

    # A later compact terminal family runs out the opcode stream with only ten
    # payload bytes remaining. In the live corpus this shows up across multiple
    # subtype ids as the final structured record in the script, so consuming the
    # remaining ten bytes is the structurally honest choice.
    if remaining_payload_bytes == 10:
        return True, 10

    # Subtype 0 also has a sibling compact tail that carries the same 10-byte
    # record payload and then hands off to a final 0x0495 byte terminator.
    if (
        subtype_id == 0x00000000
        and remaining_payload_bytes == 13
        and compact_tail_opcode != 0x0895
        and compact_tail_followup_opcode == 0x0495
    ):
        return True, 10

    # A smaller subtype-0 terminal variant leaves a final flat 0x0495 marker
    # after only nine payload bytes. Treat it as a dedicated EOF compact tail
    # instead of forcing the legacy 16-byte default.
    if subtype_id == 0x00000000 and remaining_payload_bytes == 12:
        inferred_width = _resolve_clientscript_signature_gated_bytes_width_by_bounded_path(
            opcode_data,
            payload_offset=payload_offset,
            candidate_widths=(4, 9, 10),
            raw_opcode_types=raw_opcode_types,
            raw_opcode_catalog=raw_opcode_catalog,
        )
        if inferred_width is not None:
            return True, inferred_width

    # Several subtype families also terminate through a compact flat footer:
    # 0x035E + u32(subtype) followed immediately by 0x0895 int and 0x0495 byte 0.
    # This shows up on both the original low-numbered widget records and a later
    # family of higher subtype ids, so keep the gate exact to the flat footer
    # shape rather than pinning it to a hard-coded subtype list.
    if (
        compact_tail_opcode == 0x0895
        and compact_tail_followup_opcode == 0x0495
        and compact_tail_terminator == 0
    ):
        return True, 4

    if subtype_id == 0x00000000:
        embedded_text_opcode = _peek_clientscript_raw_opcode(opcode_data, payload_offset + 4)
        embedded_text_marker = (
            opcode_data[payload_offset + 6]
            if payload_offset + 6 < len(opcode_data)
            else None
        )
        if embedded_text_opcode == 0x0511 and embedded_text_marker == 0x02:
            try:
                text_value, text_end_offset = _read_c_string(opcode_data, payload_offset + 7)
            except ValueError:
                text_value = None
                text_end_offset = None
            if isinstance(text_value, str) and isinstance(text_end_offset, int) and _looks_plausible_clientscript_string(text_value):
                return True, text_end_offset - payload_offset

        embedded_selector_opcode = _peek_clientscript_u16be(opcode_data, payload_offset + 4)
        embedded_selector_flag = (
            opcode_data[payload_offset + 6]
            if payload_offset + 6 < len(opcode_data)
            else None
        )
        embedded_opcode = _peek_clientscript_raw_opcode(opcode_data, payload_offset + 7)
        if (
            isinstance(embedded_selector_opcode, int)
            and embedded_selector_opcode > 0
            and embedded_selector_flag == 0
            and embedded_opcode == 0x0511
        ):
            embedded_payload_offset = payload_offset + 9
            if (
                embedded_payload_offset < len(opcode_data)
                and opcode_data[embedded_payload_offset] == 0x02
            ):
                try:
                    text_value, text_end_offset = _read_c_string(opcode_data, embedded_payload_offset + 1)
                except ValueError:
                    text_value = None
                    text_end_offset = None
                if isinstance(text_value, str) and isinstance(text_end_offset, int) and _looks_plausible_clientscript_string(text_value):
                    return True, text_end_offset - payload_offset
            return True, 14

        embedded_prefixed_text_opcode = _peek_clientscript_raw_opcode(opcode_data, payload_offset + 7)
        embedded_prefixed_text_marker = (
            opcode_data[payload_offset + 9]
            if payload_offset + 9 < len(opcode_data)
            else None
        )
        if (
            opcode_data[payload_offset + 4 : payload_offset + 7] == b"\x01\x13\x00"
            and embedded_prefixed_text_opcode == 0x0511
            and embedded_prefixed_text_marker == 0x02
        ):
            try:
                text_value, text_end_offset = _read_c_string(opcode_data, payload_offset + 10)
            except ValueError:
                text_value = None
                text_end_offset = None
            if isinstance(text_value, str) and isinstance(text_end_offset, int) and _looks_plausible_clientscript_string(text_value):
                candidate_width = text_end_offset - payload_offset
                inferred_width = _resolve_clientscript_signature_gated_bytes_width_by_bounded_path(
                    opcode_data,
                    payload_offset=payload_offset,
                    candidate_widths=(4, 9, 10, 14, 15, candidate_width),
                    raw_opcode_types=raw_opcode_types,
                    raw_opcode_catalog=raw_opcode_catalog,
                )
                if inferred_width == candidate_width:
                    return True, candidate_width
                next_opcode = _peek_clientscript_raw_opcode(opcode_data, text_end_offset)
                if _is_known_clientscript_opcode_boundary(
                    next_opcode,
                    raw_opcode_types=raw_opcode_types,
                    raw_opcode_catalog=raw_opcode_catalog,
                ):
                    return True, candidate_width

        inferred_width = _resolve_clientscript_signature_gated_bytes_width_by_bounded_path(
            opcode_data,
            payload_offset=payload_offset,
            candidate_widths=(4, 9, 10, 14, 15),
            raw_opcode_types=raw_opcode_types,
            raw_opcode_catalog=raw_opcode_catalog,
        )
        if inferred_width is not None:
            return True, inferred_width

    if subtype_id == 0x00000001:
        embedded_text_opcode = _peek_clientscript_raw_opcode(opcode_data, payload_offset + 7)
        embedded_text_marker = (
            opcode_data[payload_offset + 9]
            if payload_offset + 9 < len(opcode_data)
            else None
        )
        trailing_opcode = _peek_clientscript_raw_opcode(opcode_data, payload_offset + 17)
        if (
            opcode_data[payload_offset + 4 : payload_offset + 7] == b"\x06\x7C\x00"
            and embedded_text_opcode == 0x0511
            and embedded_text_marker == 0x02
            and trailing_opcode == 0x0267
        ):
            try:
                text_value, text_end_offset = _read_c_string(opcode_data, payload_offset + 9)
            except ValueError:
                text_value = None
                text_end_offset = None
            if isinstance(text_value, str) and isinstance(text_end_offset, int) and _looks_plausible_clientscript_string(text_value):
                candidate_width = text_end_offset - payload_offset + 6
                inferred_width = _resolve_clientscript_signature_gated_bytes_width_by_bounded_path(
                    opcode_data,
                    payload_offset=payload_offset,
                    candidate_widths=(10, 11, candidate_width),
                    raw_opcode_types=raw_opcode_types,
                    raw_opcode_catalog=raw_opcode_catalog,
                )
                if inferred_width == candidate_width:
                    return True, candidate_width
                next_opcode = _peek_clientscript_raw_opcode(opcode_data, payload_offset + candidate_width)
                if _is_known_clientscript_opcode_boundary(
                    next_opcode,
                    raw_opcode_types=raw_opcode_types,
                    raw_opcode_catalog=raw_opcode_catalog,
                ):
                    return True, candidate_width

        inferred_width = _resolve_clientscript_signature_gated_bytes_width_by_bounded_path(
            opcode_data,
            payload_offset=payload_offset,
            candidate_widths=(10, 11),
            raw_opcode_types=raw_opcode_types,
            raw_opcode_catalog=raw_opcode_catalog,
        )
        if inferred_width is not None:
            return True, inferred_width
        return True, 10

    if subtype_id == 0x00000002:
        inferred_width = _resolve_clientscript_signature_gated_bytes_width_by_bounded_path(
            opcode_data,
            payload_offset=payload_offset,
            candidate_widths=(16, 17),
            raw_opcode_types=raw_opcode_types,
            raw_opcode_catalog=raw_opcode_catalog,
        )
        if inferred_width is not None:
            return True, inferred_width
        if remaining_payload_bytes >= 16:
            return True, 16
        # The live widget lane terminates with a compact subtype-2 footer:
        # 0x035E + u32(2) followed immediately by flat opcodes 0x0895/0x0495.
        # Preserve the normal 16-byte bridge everywhere else and only collapse
        # this exact 15-byte EOF tail back to a 4-byte payload.
        if remaining_payload_bytes == 13:
            return True, 4
        return True, None

    if subtype_id == 0x00000004:
        base_end_offset = payload_offset + 16
        extended_end_offset = payload_offset + 20
        base_opcode = _peek_clientscript_raw_opcode(opcode_data, base_end_offset)
        extended_opcode = _peek_clientscript_raw_opcode(opcode_data, extended_end_offset)

        base_known = _is_known_clientscript_opcode_boundary(
            base_opcode,
            raw_opcode_types=raw_opcode_types,
            raw_opcode_catalog=raw_opcode_catalog,
        )
        extended_known = _is_known_clientscript_opcode_boundary(
            extended_opcode,
            raw_opcode_types=raw_opcode_types,
            raw_opcode_catalog=raw_opcode_catalog,
        )

        # Subtype 4 extends the structured widget lane with an extra trailing
        # scalar. When we stop at 16 bytes the shorter read can fall into a
        # perfectly valid 0x0000 PUSH_INT sinkhole, so prefer the full 20-byte
        # record whenever the extended handoff reaches a real opcode boundary.
        if base_opcode in compact_high_signal_opcodes and extended_opcode in compact_marker_like_opcodes:
            return True, 16
        if extended_known and (not base_known or base_opcode == 0x0000 or extended_opcode == 0x1100):
            return True, 20
        if base_known and not extended_known:
            return True, 16

        inferred_width = _resolve_clientscript_signature_gated_bytes_width_by_bounded_path(
            opcode_data,
            payload_offset=payload_offset,
            candidate_widths=(4, 10, 14, 16, 20),
            raw_opcode_types=raw_opcode_types,
            raw_opcode_catalog=raw_opcode_catalog,
        )
        if inferred_width is not None:
            return True, inferred_width
        return True, None

    if subtype_id == 0x00000005:
        compact_end_offset = payload_offset + 10
        extended_end_offset = payload_offset + 14
        compact_opcode = _peek_clientscript_raw_opcode(opcode_data, compact_end_offset)
        extended_opcode = _peek_clientscript_raw_opcode(opcode_data, extended_end_offset)

        compact_known = _is_known_clientscript_opcode_boundary(
            compact_opcode,
            raw_opcode_types=raw_opcode_types,
            raw_opcode_catalog=raw_opcode_catalog,
        )
        extended_known = _is_known_clientscript_opcode_boundary(
            extended_opcode,
            raw_opcode_types=raw_opcode_types,
            raw_opcode_catalog=raw_opcode_catalog,
        )

        # Subtype 5 acts as a polymorphic bridge record in the live widget lane:
        # the compact form lands on 0x0096-style neutral setters, while the
        # extended form carries an extra scalar before handing off to a real
        # opcode boundary such as 0x0592/0x03F2/0x0895.
        if compact_opcode in compact_high_signal_opcodes and extended_opcode in compact_marker_like_opcodes:
            return True, 10
        if compact_opcode == 0x0000 and extended_known and extended_opcode != 0x0000:
            return True, 14
        if extended_opcode == 0x0000 and compact_known and compact_opcode != 0x0000:
            return True, 10
        if compact_known and not extended_known:
            return True, 10
        if extended_known and not compact_known:
            return True, 14

        inferred_width = _resolve_clientscript_signature_gated_bytes_width_by_bounded_path(
            opcode_data,
            payload_offset=payload_offset,
            candidate_widths=(4, 10, 14, 16, 20),
            raw_opcode_types=raw_opcode_types,
            raw_opcode_catalog=raw_opcode_catalog,
        )
        if inferred_width is not None:
            return True, inferred_width

        return True, None

    widget_id = _peek_clientscript_u32be(opcode_data, payload_offset + 4)
    if subtype_id != 0x00000006 or widget_id != 0x00560000:
        return False, None

    base_end_offset = payload_offset + 16
    extended_end_offset = payload_offset + 20
    base_opcode = _peek_clientscript_raw_opcode(opcode_data, base_end_offset)
    extended_opcode = _peek_clientscript_raw_opcode(opcode_data, extended_end_offset)

    if base_opcode == 0x035E:
        return True, 16

    extended_known = _is_known_clientscript_opcode_boundary(
        extended_opcode,
        raw_opcode_types=raw_opcode_types,
        raw_opcode_catalog=raw_opcode_catalog,
    )
    if extended_known:
        return True, 20

    base_known = _is_known_clientscript_opcode_boundary(
        base_opcode,
        raw_opcode_types=raw_opcode_types,
        raw_opcode_catalog=raw_opcode_catalog,
    )
    if base_known:
        return True, 16

    return True, None


def _resolve_clientscript_step_immediate_width(
    step: dict[str, object] | None,
    *,
    immediate_kind: str | None = None,
    opcode_data: bytes | None = None,
    offset: int | None = None,
    raw_opcode_types: dict[int, str] | None = None,
    raw_opcode_catalog: dict[int, dict[str, object]] | None = None,
) -> int | None:
    matched_signature, signature_width = _resolve_clientscript_signature_gated_bytes_width(
        step,
        immediate_kind=immediate_kind,
        opcode_data=opcode_data,
        offset=offset,
        raw_opcode_types=raw_opcode_types,
        raw_opcode_catalog=raw_opcode_catalog,
    )
    if matched_signature:
        return signature_width

    if isinstance(step, dict):
        immediate_width = step.get("immediate_width")
        if isinstance(immediate_width, int) and immediate_width >= 0:
            return int(immediate_width)
        catalog_entry = step.get("catalog_entry_override")
        if isinstance(catalog_entry, dict):
            immediate_width = catalog_entry.get("immediate_width")
            if isinstance(immediate_width, int) and immediate_width >= 0:
                return int(immediate_width)
    return _default_clientscript_immediate_width(immediate_kind)


def _resolve_clientscript_signature_gated_immediate_kind(
    step: dict[str, object] | None,
    *,
    immediate_kind: str | None = None,
    opcode_data: bytes | None = None,
    offset: int | None = None,
    raw_opcode_types: dict[int, str] | None = None,
    raw_opcode_catalog: dict[int, dict[str, object]] | None = None,
) -> str | None:
    if not isinstance(step, dict) or not isinstance(opcode_data, bytes):
        return None
    if immediate_kind != "int":
        return None

    raw_opcode = step.get("raw_opcode")
    step_offset = offset if isinstance(offset, int) else step.get("offset")
    if not isinstance(raw_opcode, int) or not isinstance(step_offset, int):
        return None

    if raw_opcode == 0x0000:
        payload_offset = step_offset + 2
        if payload_offset + 4 > len(opcode_data):
            return None
        byte_opcode = _peek_clientscript_raw_opcode(opcode_data, payload_offset + 1)
        short_opcode = _peek_clientscript_raw_opcode(opcode_data, payload_offset + 2)
        int_opcode = _peek_clientscript_raw_opcode(opcode_data, payload_offset + 4)
        high_signal_opcodes = {
            0x025A,
            0x0267,
            0x035E,
            0x03F2,
            0x0412,
            0x0495,
            0x0511,
            0x0592,
            0x0713,
            0x0717,
            0x0895,
            0x1100,
        }
        compact_marker_like_opcodes = {
            0x0000,
            0x0001,
            0x0002,
            0x0003,
            0x0004,
            0x0005,
            0x0006,
            0x0007,
            0x0008,
            0x001D,
            0x0200,
        }
        byte_known = _is_known_clientscript_opcode_boundary(
            byte_opcode,
            raw_opcode_types=raw_opcode_types,
            raw_opcode_catalog=raw_opcode_catalog,
        )
        short_known = _is_known_clientscript_opcode_boundary(
            short_opcode,
            raw_opcode_types=raw_opcode_types,
            raw_opcode_catalog=raw_opcode_catalog,
        )
        int_known = _is_known_clientscript_opcode_boundary(
            int_opcode,
            raw_opcode_types=raw_opcode_types,
            raw_opcode_catalog=raw_opcode_catalog,
        )

        if (
            isinstance(byte_opcode, int)
            and byte_opcode in high_signal_opcodes
            and (
                short_opcode not in high_signal_opcodes
                or short_opcode in compact_marker_like_opcodes
            )
            and (
                int_opcode not in high_signal_opcodes
                or int_opcode in compact_marker_like_opcodes
            )
        ):
            inferred_width = _resolve_clientscript_signature_gated_bytes_width_by_bounded_path(
                opcode_data,
                payload_offset=payload_offset,
                candidate_widths=(1, 2, 4),
                raw_opcode_types=raw_opcode_types,
                raw_opcode_catalog=raw_opcode_catalog,
            )
            if inferred_width == 1:
                return "byte"

        if opcode_data[payload_offset : payload_offset + 2] != b"\x00\x00":
            return None

        if short_opcode in high_signal_opcodes and int_opcode in compact_marker_like_opcodes:
            return "short"
        if short_opcode in high_signal_opcodes and not int_known:
            return "short"
        if short_known and int_opcode == 0x0000:
            return "short"
    return None


def _read_clientscript_immediate(
    opcode_data: bytes,
    offset: int,
    immediate_kind: str,
    *,
    immediate_width: int | None = None,
) -> dict[str, object] | None:
    try:
        if immediate_kind == "none":
            return {"immediate_kind": immediate_kind, "immediate_value": None, "end_offset": offset}
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
        if immediate_kind == "string":
            value, end_offset = _read_c_string(opcode_data, offset)
            if not _looks_plausible_clientscript_string(value):
                return None
            return {"immediate_kind": immediate_kind, "immediate_value": value, "end_offset": end_offset}
        if immediate_kind == "bytes":
            if not isinstance(immediate_width, int) or immediate_width <= 0:
                return None
            end_offset = offset + immediate_width
            if end_offset > len(opcode_data):
                return None
            payload = opcode_data[offset:end_offset]
            return {
                "immediate_kind": immediate_kind,
                "immediate_value": {
                    "hex": payload.hex(" ").upper(),
                    "byte_count": int(immediate_width),
                },
                "end_offset": end_offset,
            }
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
        if len(opcode_data) - offset < ops_left * 2:
            continue

        raw_opcode = int.from_bytes(opcode_data[offset : offset + 2], "big")
        if raw_opcode in mapping:
            candidate_types = [mapping[raw_opcode]]
        else:
            allowed_types = possible_types.get(raw_opcode) if possible_types is not None else None
            available_types = (
                CLIENTSCRIPT_IMMEDIATE_TYPES
                if allowed_types is None
                else [kind for kind in CLIENTSCRIPT_SUPPORTED_IMMEDIATE_TYPES if kind in allowed_types]
            )
            candidate_types = list(available_types)

        for immediate_kind in candidate_types:
            immediate = _read_clientscript_immediate(opcode_data, offset + 2, immediate_kind)
            if immediate is None:
                continue
            end_offset = int(immediate["end_offset"])
            if len(opcode_data) - end_offset < (ops_left - 1) * 2:
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


def _clientscript_expression_result_name(expression: object) -> str | None:
    if not isinstance(expression, dict):
        return None
    origin_offset = expression.get("origin_offset")
    origin_stack_name = expression.get("origin_stack_name")
    if not isinstance(origin_offset, int) or not isinstance(origin_stack_name, str) or not origin_stack_name:
        return None
    result_index = expression.get("result_index", 0)
    if not isinstance(result_index, int):
        result_index = 0
    suffix = "" if result_index <= 0 else f"_{result_index}"
    return f"{origin_stack_name}_{origin_offset:04d}{suffix}"


def _coerce_clientscript_widget_expression(expression: object) -> dict[str, object] | None:
    if not isinstance(expression, dict):
        return None
    if str(expression.get("kind", "")) == "widget-reference":
        return expression
    if str(expression.get("kind", "")) != "int-literal":
        return None
    value = expression.get("value")
    if not isinstance(value, int) or value < 0:
        return None
    return {
        "kind": "widget-reference",
        "packed_value": value,
        "interface_id": value >> 16,
        "component_id": value & 0xFFFF,
    }


def _format_clientscript_pseudocode_expression(
    expression: object,
    *,
    prefer_result_name: bool = True,
) -> str:
    if not isinstance(expression, dict):
        return str(expression)

    if prefer_result_name:
        result_name = _clientscript_expression_result_name(expression)
        if result_name is not None and str(expression.get("kind", "")).endswith("-result"):
            return result_name

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

    inputs = expression.get("inputs")
    safe_inputs = inputs[:3] if isinstance(inputs, list) else []
    rendered_inputs = [
        _format_clientscript_pseudocode_expression(item)
        for item in safe_inputs
        if isinstance(item, dict)
    ]
    semantic_label = str(expression.get("semantic_label") or expression.get("raw_opcode_hex") or kind)
    input_kinds = [
        str(item.get("kind", ""))
        for item in safe_inputs
        if isinstance(item, dict)
    ]

    if semantic_label == "STRING_FORMATTER_CANDIDATE":
        if len(rendered_inputs) >= 2:
            string_inputs = [
                _format_clientscript_pseudocode_expression(item)
                for item in safe_inputs
                if isinstance(item, dict)
                and str(item.get("kind", "")).startswith("string")
            ]
            int_inputs = [
                _format_clientscript_pseudocode_expression(item)
                for item in safe_inputs
                if isinstance(item, dict)
                and str(item.get("kind", "")) in {"int-literal", "state-reference", "slot-reference", "int-result", "int-input"}
            ]
            if len(string_inputs) >= 2:
                return f"concat_strings({', '.join(string_inputs[:2])})"
            if string_inputs and int_inputs:
                return f"append_int({string_inputs[0]}, {int_inputs[0]})"
        return f"format_string({', '.join(rendered_inputs)})"

    if semantic_label == "WIDGET_TEXT_MUTATOR_CANDIDATE":
        if len(rendered_inputs) >= 2:
            return f"set_widget_text({', '.join(rendered_inputs[:2])})"

    label = semantic_label
    if input_kinds:
        return f"{label}({', '.join(rendered_inputs)})"
    return label


def _render_clientscript_pseudocode_statement(
    step: dict[str, object],
    *,
    next_offset: int | None,
) -> str:
    semantic_label = str(step.get("semantic_label", ""))
    control_flow_kind = str(step.get("control_flow_kind", ""))
    operand_signature = step.get("operand_signature_candidate")
    signature = (
        str(operand_signature.get("signature", ""))
        if isinstance(operand_signature, dict)
        else ""
    )
    produced_int = [
        expression
        for expression in step.get("produced_int_expressions", [])
        if isinstance(expression, dict)
    ]
    produced_string = [
        expression
        for expression in step.get("produced_string_expressions", [])
        if isinstance(expression, dict)
    ]
    consumed_int = [
        expression
        for expression in step.get("consumed_int_expressions", [])
        if isinstance(expression, dict)
    ]
    consumed_string = [
        expression
        for expression in step.get("consumed_string_expressions", [])
        if isinstance(expression, dict)
    ]

    def _select_widget_operand() -> tuple[dict[str, object] | None, int | None]:
        for index, expression in enumerate(consumed_int):
            if str(expression.get("kind", "")) == "widget-reference":
                return expression, index
        for reverse_index, expression in reversed(list(enumerate(consumed_int))):
            coerced = _coerce_clientscript_widget_expression(expression)
            if coerced is not None:
                return coerced, reverse_index
        return None, None

    if semantic_label == "RETURN" or control_flow_kind in {"return", "return-candidate"}:
        return "return;"

    if control_flow_kind == "jump":
        target_offset = _resolve_clientscript_jump_target(step, next_offset=next_offset)
        if isinstance(target_offset, int):
            return f"goto L_{target_offset:04d};"
        return "goto <unresolved>;"

    if control_flow_kind in {"branch", "branch-candidate", "jump-candidate"}:
        branch_condition = step.get("branch_condition_expression")
        rendered_condition = _format_clientscript_pseudocode_expression(branch_condition)
        target_offset = _resolve_clientscript_jump_target(step, next_offset=next_offset)
        if isinstance(target_offset, int):
            return f"if ({rendered_condition}) goto L_{target_offset:04d};"
        return f"if ({rendered_condition}) goto <unresolved>;"

    if semantic_label == "SWITCH_DISPATCH_FRONTIER_CANDIDATE":
        selector = step.get("switch_selector_expression")
        rendered_selector = _format_clientscript_pseudocode_expression(selector)
        return f"switch ({rendered_selector}) {{ /* unresolved dispatch */ }}"

    if semantic_label == "WIDGET_TEXT_MUTATOR_CANDIDATE":
        widget_expression, widget_index = _select_widget_operand()
        if widget_expression is None and consumed_int:
            widget_expression = consumed_int[0]
            widget_index = 0
        string_expression = consumed_string[0] if consumed_string else None
        widget_value = _format_clientscript_pseudocode_expression(widget_expression)
        string_value = _format_clientscript_pseudocode_expression(string_expression)
        if widget_expression is not None and string_expression is not None:
            return f"set_widget_text({widget_value}, {string_value});"

    if semantic_label == "WIDGET_EVENT_BINDER_CANDIDATE" or signature == "widget+int+string":
        widget_expression, widget_index = _select_widget_operand()
        int_expression = next(
            (
                expression
                for index, expression in enumerate(consumed_int)
                if index != widget_index and str(expression.get("kind", "")) != "widget-reference"
            ),
            None,
        )
        string_expression = consumed_string[0] if consumed_string else None
        widget_value = _format_clientscript_pseudocode_expression(widget_expression)
        int_value = _format_clientscript_pseudocode_expression(int_expression)
        string_value = _format_clientscript_pseudocode_expression(string_expression)
        if widget_expression is not None and string_expression is not None and int_expression is not None:
            return f"bind_widget_event({widget_value}, {string_value}, {int_value});"
        if widget_expression is not None and int_expression is not None:
            return f"bind_widget_event({widget_value}, {int_value});"
        if widget_expression is not None and string_expression is not None:
            return f"bind_widget_event({widget_value}, {string_value});"

    if semantic_label == "STRING_FORMATTER_CANDIDATE":
        if produced_string:
            target_name = _clientscript_expression_result_name(produced_string[0]) or "string_result"
        else:
            target_name = "string_result"
        if signature == "int+string" and consumed_string and consumed_int:
            string_value = _format_clientscript_pseudocode_expression(consumed_string[0])
            int_value = _format_clientscript_pseudocode_expression(consumed_int[0])
            return f"{target_name} = append_int({string_value}, {int_value});"
        if signature == "string+string" and len(consumed_string) >= 2:
            left_value = _format_clientscript_pseudocode_expression(consumed_string[0])
            right_value = _format_clientscript_pseudocode_expression(consumed_string[1])
            return f"{target_name} = concat_strings({left_value}, {right_value});"
        if produced_string:
            rhs = _format_clientscript_pseudocode_expression(produced_string[0], prefer_result_name=False)
            return f"{target_name} = {rhs};"

    if semantic_label.startswith("PUSH_CONST_STRING") and produced_string:
        target_name = _clientscript_expression_result_name(produced_string[0]) or "string_result"
        rhs = _format_clientscript_pseudocode_expression(produced_string[0], prefer_result_name=False)
        return f"{target_name} = {rhs};"

    if semantic_label in {"PUSH_INT_LITERAL", "PUSH_INT_CANDIDATE", "INT_STATE_GETTER_CANDIDATE", "VAR_REFERENCE_CANDIDATE"} and produced_int:
        target_name = _clientscript_expression_result_name(produced_int[0]) or "int_result"
        rhs = _format_clientscript_pseudocode_expression(produced_int[0], prefer_result_name=False)
        return f"{target_name} = {rhs};"

    if signature == "widget+string" and consumed_int and consumed_string:
        widget_value = _format_clientscript_pseudocode_expression(consumed_int[0])
        string_value = _format_clientscript_pseudocode_expression(consumed_string[0])
        return f"set_widget_text({widget_value}, {string_value});"

    if produced_string:
        target_name = _clientscript_expression_result_name(produced_string[0]) or "string_result"
        rhs = _format_clientscript_pseudocode_expression(produced_string[0], prefer_result_name=False)
        return f"{target_name} = {rhs};"
    if produced_int:
        target_name = _clientscript_expression_result_name(produced_int[0]) or "int_result"
        rhs = _format_clientscript_pseudocode_expression(produced_int[0], prefer_result_name=False)
        return f"{target_name} = {rhs};"

    rendered_value = _format_clientscript_immediate_value(step.get("immediate_value"))
    raw_opcode_hex = str(step.get("raw_opcode_hex", "0x0000"))
    label = semantic_label or raw_opcode_hex
    return f"/* {label} {rendered_value} */"


def _render_clientscript_pseudocode_text(
    layout: ClientscriptLayout,
    steps: list[dict[str, object]],
    *,
    mode: str,
    solution_count: int,
    bailed: bool,
) -> str:
    lines = [
        "// Reverser Workbench Clientscript Pseudocode",
        f"// byte0: {layout.byte0}",
        f"// instruction_count: {layout.instruction_count}",
        f"// opcode_data_bytes: {len(layout.opcode_data)}",
        f"// mode: {mode}",
        f"// solution_count: {solution_count}",
        f"// bailed: {str(bailed).lower()}",
        "",
    ]

    for index, step in enumerate(steps[:DEFAULT_CLIENTSCRIPT_TRACE_INSTRUCTIONS]):
        next_offset = (
            int(steps[index + 1]["offset"])
            if index + 1 < len(steps[:DEFAULT_CLIENTSCRIPT_TRACE_INSTRUCTIONS])
            else None
        )
        statement = _render_clientscript_pseudocode_statement(step, next_offset=next_offset)
        lines.append(f"L_{int(step['offset']):04d}: {statement}")

    if len(steps) > DEFAULT_CLIENTSCRIPT_TRACE_INSTRUCTIONS:
        lines.append("")
        lines.append(f"// ... truncated after {DEFAULT_CLIENTSCRIPT_TRACE_INSTRUCTIONS} instructions")
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
    *,
    resolution_scope: str = "global",
) -> dict[str, object]:
    annotated = dict(step)
    annotated["semantic_resolution_scope"] = resolution_scope
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

    catalog_entry = annotated.get("catalog_entry_override")
    if not isinstance(catalog_entry, dict):
        catalog_entry = opcode_catalog.get(raw_opcode) if opcode_catalog is not None else None
    if isinstance(catalog_entry, dict) and not _allows_clientscript_resolution_scope(
        catalog_entry,
        resolution_scope=resolution_scope,
    ):
        catalog_entry = None
    if isinstance(catalog_entry, dict):
        mnemonic = catalog_entry.get("mnemonic")
        if isinstance(mnemonic, str) and mnemonic:
            annotated["semantic_label"] = mnemonic
        family = catalog_entry.get("family")
        if isinstance(family, str) and family:
            annotated["family"] = family
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
        stack_effect_candidate = catalog_entry.get("stack_effect_candidate")
        if isinstance(stack_effect_candidate, dict) and stack_effect_candidate:
            annotated["stack_effect_candidate"] = dict(stack_effect_candidate)
        operand_signature_candidate = catalog_entry.get("operand_signature_candidate")
        if isinstance(operand_signature_candidate, dict) and operand_signature_candidate:
            annotated["operand_signature_candidate"] = dict(operand_signature_candidate)
        contextual_stack_hints = catalog_entry.get("contextual_stack_hints")
        if isinstance(contextual_stack_hints, list) and contextual_stack_hints:
            annotated["contextual_stack_hints"] = [
                dict(hint_entry)
                for hint_entry in contextual_stack_hints
                if isinstance(hint_entry, dict)
            ]
        candidate = catalog_entry.get("candidate_mnemonic")
        if _should_promote_clientscript_arity_candidate(annotated.get("semantic_label"), candidate):
            annotated["semantic_label"] = str(candidate)
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
        if len(string_roles) >= 2:
            return "string+string"
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
    family = str(entry.get("family") or entry.get("semantic_family") or "")
    if semantic_label != "WIDGET_MUTATOR_CANDIDATE" and not family.startswith("widget"):
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


def _infer_clientscript_string_operand_signature(entry: dict[str, object]) -> dict[str, object] | None:
    semantic_label = str(
        entry.get("candidate_mnemonic")
        or entry.get("semantic_label")
        or entry.get("mnemonic")
        or ""
    )
    family = str(entry.get("family") or entry.get("semantic_family") or "")
    if semantic_label == "WIDGET_MUTATOR_CANDIDATE" or family.startswith("widget"):
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

    relevant_signatures = {"int+string", "string+string", "string-only"}
    dominant_signature = None
    if consumed_signature_counts:
        candidates = {key: value for key, value in consumed_signature_counts.items() if key in relevant_signatures}
        if candidates:
            dominant_signature = max(candidates.items(), key=lambda item: (int(item[1]), str(item[0])))[0]
    if dominant_signature is None and signature_counts:
        candidates = {key: value for key, value in signature_counts.items() if key in relevant_signatures}
        if candidates:
            dominant_signature = max(candidates.items(), key=lambda item: (int(item[1]), str(item[0])))[0]

    string_support = int(entry.get("prefix_string_operand_script_count", 0)) > 0 or dominant_signature is not None
    if not string_support:
        return None

    min_string_inputs = 1
    min_int_inputs = 1 if dominant_signature == "int+string" else 0
    confidence = 0.6
    notes = "String-context payload likely consumes one string value."
    if dominant_signature == "int+string":
        confidence = 0.69
        notes = "String-context payload likely consumes one string plus one integer-like value, which fits a formatter or parameterized string transform."
    elif dominant_signature == "string+string":
        min_string_inputs = 2
        confidence = 0.71
        notes = "String-context payload likely consumes two string values, which fits a concatenation or string merge transform."
    elif dominant_signature == "string-only":
        confidence = 0.64
        notes = "String-context payload likely consumes one string value before applying a transformation or side effect."
    elif int(entry.get("prefix_string_operand_script_count", 0)) > 0:
        notes = "Prefix stack already carries string data, so this payload likely consumes at least one string operand."

    return {
        "target_kind": "string",
        "signature": dominant_signature or "string-only",
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
    family = str(entry.get("family") or entry.get("semantic_family") or "")
    explicit_stack_effect = entry.get("stack_effect_candidate")
    if isinstance(explicit_stack_effect, dict) and any(
        field in explicit_stack_effect
        for field in (
            "int_pops",
            "int_pushes",
            "string_pops",
            "string_pushes",
            "long_pops",
            "long_pushes",
            "confidence",
        )
    ):
        return dict(explicit_stack_effect)

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
    if semantic_label == "WIDGET_MUTATOR_CANDIDATE" or family.startswith("widget"):
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
    if semantic_label == "STATE_VALUE_ACTION_CANDIDATE":
        return _make_clientscript_stack_effect(
            int_pops=2,
            confidence=0.66,
            notes="State-fed payload action likely consumes one state-derived integer plus one additional integer argument before applying a side effect.",
        )
    if semantic_label in {"STRING_ACTION_CANDIDATE", "STRING_FORMATTER_CANDIDATE"} or family.startswith("string"):
        operand_signature = _infer_clientscript_string_operand_signature(entry)
        if isinstance(operand_signature, dict):
            return _make_clientscript_stack_effect(
                int_pops=int(operand_signature.get("min_int_inputs", 0)),
                string_pops=int(operand_signature.get("min_string_inputs", 0)),
                string_pushes=1 if semantic_label == "STRING_FORMATTER_CANDIDATE" or family == "string-transform-action" else 0,
                confidence=float(operand_signature.get("confidence", 0.6)),
                notes=str(operand_signature.get("notes", "String-context payload likely consumes at least one string operand.")),
            )
    if semantic_label == "SWITCH_CASE_ACTION_CANDIDATE":
        string_operand_signature = _infer_clientscript_string_operand_signature(entry)
        if isinstance(string_operand_signature, dict):
            return _make_clientscript_stack_effect(
                int_pops=int(string_operand_signature.get("min_int_inputs", 0)),
                string_pops=int(string_operand_signature.get("min_string_inputs", 0)),
                confidence=float(string_operand_signature.get("confidence", 0.6)),
                notes=str(string_operand_signature.get("notes", "Switch-case payload likely consumes string-context operands.")),
            )
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
    if semantic_label == "BRANCH_FRONTIER_CANDIDATE":
        return _make_clientscript_stack_effect(
            int_pops=1,
            confidence=0.57,
            notes="Branch-like frontier candidate likely consumes one integer condition from the stack.",
        )
    if semantic_label == "JUMP_OFFSET_FRONTIER_CANDIDATE" and control_flow_kind in {
        "branch",
        "branch-candidate",
    }:
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


def _sample_clientscript_instruction_step(step: dict[str, object]) -> dict[str, object]:
    sampled: dict[str, object] = {}
    for field in (
        "offset",
        "raw_opcode",
        "raw_opcode_hex",
        "sub_opcode",
        "sub_opcode_hex",
        "immediate_kind",
        "immediate_width",
        "end_offset",
    ):
        value = step.get(field)
        if value is not None:
            sampled[field] = value
    immediate_value = step.get("immediate_value")
    if isinstance(immediate_value, (int, float, str, bool)):
        sampled["immediate_value"] = immediate_value
    elif isinstance(immediate_value, dict):
        sampled_immediate: dict[str, object] = {}
        hex_value = immediate_value.get("hex")
        if isinstance(hex_value, str) and hex_value:
            sampled_immediate["hex"] = hex_value
        if sampled_immediate:
            sampled["immediate_value"] = sampled_immediate
    for field in ("semantic_label", "semantic_family", "control_flow_kind"):
        value = step.get(field)
        if isinstance(value, str) and value:
            sampled[field] = value
    return sampled


def _hydrate_clientscript_step_end_offsets(
    layout: ClientscriptLayout,
    steps: list[dict[str, object]],
) -> list[dict[str, object]]:
    hydrated_steps: list[dict[str, object]] = []
    for index, step in enumerate(steps):
        if not isinstance(step, dict):
            continue
        hydrated = dict(step)
        end_offset = hydrated.get("end_offset")
        if not isinstance(end_offset, int):
            next_step = steps[index + 1] if index + 1 < len(steps) else None
            next_offset = next_step.get("offset") if isinstance(next_step, dict) else None
            if isinstance(next_offset, int):
                hydrated["end_offset"] = int(next_offset)
            else:
                offset = hydrated.get("offset")
                immediate_kind = hydrated.get("immediate_kind")
                if isinstance(offset, int) and isinstance(immediate_kind, str):
                    immediate = _read_clientscript_immediate(
                        layout.opcode_data,
                        offset + 2,
                        immediate_kind,
                        immediate_width=_resolve_clientscript_step_immediate_width(
                            hydrated,
                            immediate_kind=immediate_kind,
                            opcode_data=layout.opcode_data,
                            offset=offset,
                        ),
                    )
                    if immediate is not None:
                        hydrated["end_offset"] = int(immediate["end_offset"])
                if not isinstance(hydrated.get("end_offset"), int) and isinstance(offset, int):
                    hydrated["end_offset"] = min(len(layout.opcode_data), int(offset) + 2)
        hydrated_steps.append(hydrated)
    return hydrated_steps


def _build_clientscript_late_instruction_sample(
    instruction_steps: list[dict[str, object]],
    *,
    max_steps: int = 16,
) -> list[dict[str, object]]:
    if max_steps <= 0:
        return []
    return [
        _sample_clientscript_instruction_step(step)
        for step in instruction_steps[-max_steps:]
        if isinstance(step, dict)
    ]


def _sample_clientscript_hex_context(
    opcode_data: bytes,
    *,
    focus_offset: int,
    focus_end_offset: int | None = None,
    bytes_before: int = 16,
    bytes_after: int = 24,
) -> dict[str, object] | None:
    if focus_offset < 0 or focus_offset >= len(opcode_data):
        return None

    resolved_focus_end_offset = focus_end_offset if isinstance(focus_end_offset, int) else focus_offset + 2
    resolved_focus_end_offset = max(focus_offset, min(resolved_focus_end_offset, len(opcode_data)))
    start_offset = max(focus_offset - max(bytes_before, 0), 0)
    end_offset = min(resolved_focus_end_offset + max(bytes_after, 0), len(opcode_data))
    if start_offset >= end_offset:
        return None

    chunk = opcode_data[start_offset:end_offset]
    ascii_sample = "".join(chr(byte) if 32 <= byte <= 126 else "." for byte in chunk)
    return {
        "start_offset": start_offset,
        "focus_offset": focus_offset,
        "focus_end_offset": resolved_focus_end_offset,
        "end_offset": end_offset,
        "hex": " ".join(f"{byte:02X}" for byte in chunk),
        "ascii": ascii_sample,
    }


def _is_clientscript_frontier_semantic_label(label: object) -> bool:
    return isinstance(label, str) and bool(label) and label.endswith("_FRONTIER_CANDIDATE")


def _find_clientscript_tail_hint_instruction(
    instruction_sample: list[dict[str, object]],
) -> dict[str, object] | None:
    for step in reversed(instruction_sample):
        if not isinstance(step, dict):
            continue
        if _is_clientscript_frontier_semantic_label(step.get("semantic_label")):
            return step
    return None


def _resolve_clientscript_catalog_dispatch(
    opcode_data: bytes,
    offset: int,
    *,
    raw_opcode: int,
    raw_opcode_types: dict[int, str] | None = None,
    raw_opcode_catalog: dict[int, dict[str, object]] | None = None,
    resolution_scope: str = "global",
) -> tuple[str | None, dict[str, object] | None, dict[str, object]]:
    step_fields: dict[str, object] = {}
    catalog_entry = raw_opcode_catalog.get(raw_opcode) if raw_opcode_catalog is not None else None
    base_catalog_entry = _merge_clientscript_catalog_entry_with_builtin_hint(raw_opcode, catalog_entry)
    if isinstance(base_catalog_entry, dict) and not _allows_clientscript_resolution_scope(
        base_catalog_entry,
        resolution_scope=resolution_scope,
    ):
        base_catalog_entry = None
    resolved_immediate_kind: str | None = None

    if isinstance(base_catalog_entry, dict):
        catalog_immediate_kind = base_catalog_entry.get(
            "immediate_kind",
            base_catalog_entry.get("expected_immediate_kind"),
        )
        if (
            isinstance(catalog_immediate_kind, str)
            and catalog_immediate_kind in CLIENTSCRIPT_SUPPORTED_IMMEDIATE_TYPES
        ):
            resolved_immediate_kind = catalog_immediate_kind
    if raw_opcode_types is not None:
        mapped_immediate_kind = raw_opcode_types.get(raw_opcode)
        if (
            isinstance(mapped_immediate_kind, str)
            and mapped_immediate_kind in CLIENTSCRIPT_SUPPORTED_IMMEDIATE_TYPES
        ):
            resolved_immediate_kind = mapped_immediate_kind

    if isinstance(base_catalog_entry, dict):
        subtype_entries = base_catalog_entry.get("subtypes")
        if isinstance(subtype_entries, dict) and offset + 2 < len(opcode_data):
            sub_opcode = int(opcode_data[offset + 2])
            step_fields["sub_opcode"] = sub_opcode
            step_fields["sub_opcode_hex"] = f"0x{sub_opcode:02X}"
            subtype_entry = subtype_entries.get(sub_opcode)
            if subtype_entry is None:
                subtype_entry = subtype_entries.get(f"0x{sub_opcode:02X}")
            if not isinstance(subtype_entry, dict):
                subtype_entry = None
            if isinstance(subtype_entry, dict) and not _allows_clientscript_resolution_scope(
                subtype_entry,
                resolution_scope=resolution_scope,
            ):
                subtype_entry = None
            dispatch_mode = str(
                base_catalog_entry.get(
                    "subtype_dispatch_mode",
                    "strict" if base_catalog_entry.get("strict_subtype_dispatch") else "prefer-known-subtypes",
                )
                or "prefer-known-subtypes"
            )
            if isinstance(subtype_entry, dict):
                merged_catalog_entry = {
                    field: value
                    for field, value in base_catalog_entry.items()
                    if field != "subtypes"
                }
                merged_catalog_entry.update(dict(subtype_entry))
                merged_catalog_entry["sub_opcode"] = sub_opcode
                merged_catalog_entry["sub_opcode_hex"] = f"0x{sub_opcode:02X}"
                resolved_immediate_kind = str(
                    merged_catalog_entry.get(
                        "immediate_kind",
                        merged_catalog_entry.get("expected_immediate_kind", "byte"),
                    )
                    or "byte"
                )
                if resolved_immediate_kind not in CLIENTSCRIPT_SUPPORTED_IMMEDIATE_TYPES:
                    resolved_immediate_kind = "byte"
                return resolved_immediate_kind, merged_catalog_entry, step_fields
            if dispatch_mode == "strict":
                return None, None, step_fields

    contextual_immediate_kind = _resolve_clientscript_signature_gated_immediate_kind(
        {
            "offset": int(offset),
            "raw_opcode": int(raw_opcode),
        },
        immediate_kind=resolved_immediate_kind,
        opcode_data=opcode_data,
        offset=offset,
        raw_opcode_types=raw_opcode_types,
        raw_opcode_catalog=raw_opcode_catalog,
    )
    if isinstance(contextual_immediate_kind, str) and contextual_immediate_kind in CLIENTSCRIPT_SUPPORTED_IMMEDIATE_TYPES:
        resolved_immediate_kind = contextual_immediate_kind

    return resolved_immediate_kind, base_catalog_entry, step_fields


def _validate_clientscript_selected_steps_against_subtypes(
    layout: ClientscriptLayout,
    steps: list[dict[str, object]],
    *,
    raw_opcode_catalog: dict[int, dict[str, object]] | None,
    resolution_scope: str = "global",
) -> bool:
    if not raw_opcode_catalog:
        return True

    for step in steps:
        if not isinstance(step, dict):
            continue
        raw_opcode = step.get("raw_opcode")
        offset = step.get("offset")
        if not isinstance(raw_opcode, int) or not isinstance(offset, int):
            continue
        catalog_entry = raw_opcode_catalog.get(raw_opcode)
        if not isinstance(catalog_entry, dict):
            continue
        if not _allows_clientscript_resolution_scope(
            catalog_entry,
            resolution_scope=resolution_scope,
        ):
            continue
        subtype_entries = catalog_entry.get("subtypes")
        if not isinstance(subtype_entries, dict) or offset + 2 >= len(layout.opcode_data):
            continue
        sub_opcode = int(layout.opcode_data[offset + 2])
        subtype_entry = subtype_entries.get(sub_opcode)
        if subtype_entry is None:
            subtype_entry = subtype_entries.get(f"0x{sub_opcode:02X}")
        if isinstance(subtype_entry, dict) and not _allows_clientscript_resolution_scope(
            subtype_entry,
            resolution_scope=resolution_scope,
        ):
            subtype_entry = None
        dispatch_mode = str(
            catalog_entry.get(
                "subtype_dispatch_mode",
                "strict" if catalog_entry.get("strict_subtype_dispatch") else "prefer-known-subtypes",
            )
            or "prefer-known-subtypes"
        )
        if not isinstance(subtype_entry, dict):
            if dispatch_mode == "strict":
                return False
            continue

        expected_kind = subtype_entry.get("immediate_kind", subtype_entry.get("expected_immediate_kind"))
        if not (
            isinstance(expected_kind, str)
            and expected_kind in CLIENTSCRIPT_SUPPORTED_IMMEDIATE_TYPES
        ):
            expected_width = subtype_entry.get("immediate_width")
            width_to_kind = {0: "none", 1: "byte", 2: "short", 3: "tribyte", 4: "int"}
            expected_kind = width_to_kind.get(expected_width)
        actual_kind = step.get("immediate_kind")
        if isinstance(expected_kind, str) and actual_kind != expected_kind:
            return False
    return True


def _peek_clientscript_next_opcode_instruction(
    layout: ClientscriptLayout,
    offset: int,
    *,
    raw_opcode_types: dict[int, str] | None = None,
    raw_opcode_catalog: dict[int, dict[str, object]] | None = None,
) -> dict[str, object] | None:
    if offset < 0 or offset + 2 > len(layout.opcode_data):
        return None

    raw_opcode = int.from_bytes(layout.opcode_data[offset : offset + 2], "big")
    step: dict[str, object] = {
        "offset": int(offset),
        "raw_opcode": int(raw_opcode),
        "raw_opcode_hex": f"0x{raw_opcode:04X}",
    }
    immediate_kind, resolved_catalog_entry, step_fields = _resolve_clientscript_catalog_dispatch(
        layout.opcode_data,
        offset,
        raw_opcode=raw_opcode,
        raw_opcode_types=raw_opcode_types,
        raw_opcode_catalog=raw_opcode_catalog,
        resolution_scope="frontier",
    )
    step.update(step_fields)
    if isinstance(resolved_catalog_entry, dict):
        step["catalog_entry_override"] = resolved_catalog_entry
        immediate_width = resolved_catalog_entry.get("immediate_width")
        if isinstance(immediate_width, int) and immediate_width >= 0:
            step["immediate_width"] = int(immediate_width)
    if isinstance(immediate_kind, str) and immediate_kind in CLIENTSCRIPT_SUPPORTED_IMMEDIATE_TYPES:
        step["immediate_kind"] = immediate_kind
    if "immediate_kind" not in step:
        step.pop("catalog_entry_override", None)
        return step
    annotated = _apply_clientscript_semantic_hints(
        step,
        raw_opcode_catalog,
        resolution_scope="frontier",
    )
    annotated.pop("catalog_entry_override", None)
    return annotated


def _decode_clientscript_instruction_at_offset(
    layout: ClientscriptLayout,
    offset: int,
    *,
    raw_opcode_types: dict[int, str] | None = None,
    raw_opcode_catalog: dict[int, dict[str, object]] | None = None,
) -> dict[str, object]:
    preview_step = _peek_clientscript_next_opcode_instruction(
        layout,
        offset,
        raw_opcode_types=raw_opcode_types,
        raw_opcode_catalog=raw_opcode_catalog,
    )
    if not isinstance(preview_step, dict):
        return {"status": "out-of-bounds", "offset": int(offset)}

    immediate_kind = preview_step.get("immediate_kind")
    if not isinstance(immediate_kind, str) or immediate_kind not in CLIENTSCRIPT_SUPPORTED_IMMEDIATE_TYPES:
        return {
            "status": "frontier",
            "offset": int(offset),
            "next_instruction": _sample_clientscript_instruction_step(preview_step),
        }

    immediate = _read_clientscript_immediate(
        layout.opcode_data,
        offset + 2,
        immediate_kind,
        immediate_width=_resolve_clientscript_step_immediate_width(
            preview_step,
            immediate_kind=immediate_kind,
            opcode_data=layout.opcode_data,
            offset=offset,
            raw_opcode_types=raw_opcode_types,
            raw_opcode_catalog=raw_opcode_catalog,
        ),
    )
    if immediate is None:
        return {
            "status": "invalid-immediate",
            "offset": int(offset),
            "next_instruction": _sample_clientscript_instruction_step(preview_step),
            "immediate_kind": immediate_kind,
        }

    decoded_step = dict(preview_step)
    decoded_step["immediate_kind"] = immediate_kind
    immediate_width = _resolve_clientscript_step_immediate_width(
        preview_step,
        immediate_kind=immediate_kind,
        opcode_data=layout.opcode_data,
        offset=offset,
        raw_opcode_types=raw_opcode_types,
        raw_opcode_catalog=raw_opcode_catalog,
    )
    if isinstance(immediate_width, int) and immediate_width >= 0:
        decoded_step["immediate_width"] = int(immediate_width)
    decoded_step["immediate_value"] = immediate.get("immediate_value")
    decoded_step["switch_subtype"] = immediate.get("switch_subtype")
    decoded_step["end_offset"] = int(immediate["end_offset"])
    return {
        "status": "decoded",
        "offset": int(offset),
        "step": decoded_step,
    }


def _trace_clientscript_bounded_stack_path(
    layout: ClientscriptLayout,
    *,
    start_offset: int,
    initial_state: dict[str, object],
    raw_opcode_types: dict[int, str] | None = None,
    raw_opcode_catalog: dict[int, dict[str, object]] | None = None,
    soft_instruction_limit: int = DEFAULT_CLIENTSCRIPT_BRANCH_PROBE_SOFT_LIMIT,
    hard_instruction_limit: int = DEFAULT_CLIENTSCRIPT_BRANCH_PROBE_HARD_LIMIT,
) -> dict[str, object]:
    state = _clone_clientscript_stack_state(initial_state)
    initial_state_snapshot = _clone_clientscript_stack_state(initial_state)
    steps: list[dict[str, object]] = []
    visited: set[tuple[int, str]] = set()
    current_offset = int(start_offset)

    def _finish(
        status: str,
        *,
        next_instruction: dict[str, object] | None = None,
        end_offset: int | None = None,
    ) -> dict[str, object]:
        final_stack_tracking = _summarize_clientscript_stack_state(state)
        final_stack_compact = _summarize_clientscript_stack_state_compact(state)
        result = {
            "status": status,
            "start_offset": int(start_offset),
            "end_offset": int(current_offset if end_offset is None else end_offset),
            "instruction_count": len(steps),
            "instruction_sample": [
                _sample_clientscript_instruction_step(step)
                for step in steps[:12]
                if isinstance(step, dict)
            ],
            "final_stack_tracking": final_stack_tracking,
            "final_stack_compact": final_stack_compact,
            "required_input_delta": _diff_clientscript_required_inputs(initial_state_snapshot, state),
        }
        if isinstance(next_instruction, dict) and next_instruction:
            result["next_instruction"] = dict(next_instruction)
        return result

    while len(steps) < max(hard_instruction_limit, 1):
        if current_offset < 0 or current_offset >= len(layout.opcode_data):
            return _finish("out-of-bounds")

        loop_key = (int(current_offset), _coarsen_clientscript_stack_state_signature(state))
        if loop_key in visited:
            return _finish("loop")
        visited.add(loop_key)

        decoded = _decode_clientscript_instruction_at_offset(
            layout,
            current_offset,
            raw_opcode_types=raw_opcode_types,
            raw_opcode_catalog=raw_opcode_catalog,
        )
        decoded_status = str(decoded.get("status", ""))
        if decoded_status != "decoded":
            next_instruction = decoded.get("next_instruction")
            return _finish(
                decoded_status or "frontier",
                next_instruction=dict(next_instruction) if isinstance(next_instruction, dict) else None,
            )

        step = decoded.get("step")
        if not isinstance(step, dict):
            return _finish("frontier")

        normalized_control_flow_kind = _normalize_clientscript_control_flow_kind(step.get("control_flow_kind"))
        if normalized_control_flow_kind in {"branch", "jump", "switch"}:
            return _finish(
                "next-control-flow",
                next_instruction=_sample_clientscript_instruction_step(step),
                end_offset=int(step.get("offset", current_offset)),
            )

        annotated_step = _apply_clientscript_step_to_stack_state(step, state)
        steps.append(annotated_step)
        current_offset = int(annotated_step.get("end_offset", current_offset))

        if _is_clientscript_terminal_step(annotated_step):
            return _finish("terminal")
        if len(steps) >= max(soft_instruction_limit, 1):
            return _finish("instruction-budget")

    return _finish("instruction-budget-hard")


def _find_clientscript_branch_probe_step_index(
    instruction_steps: list[dict[str, object]],
) -> int | None:
    for index in range(len(instruction_steps) - 1, -1, -1):
        step = instruction_steps[index]
        if not isinstance(step, dict):
            continue
        normalized_control_flow_kind = _normalize_clientscript_control_flow_kind(step.get("control_flow_kind"))
        semantic_label = str(step.get("semantic_label", "") or "")
        if normalized_control_flow_kind not in {"branch", "jump"} and semantic_label not in {
            "BRANCH_FRONTIER_CANDIDATE",
            "JUMP_OFFSET_FRONTIER_CANDIDATE",
        }:
            continue
        if str(step.get("immediate_kind", "")) not in {"short", "int"}:
            continue
        if not isinstance(step.get("end_offset"), int):
            continue
        return index
    return None


def _probe_clientscript_branch_state(
    layout: ClientscriptLayout,
    instruction_steps: list[dict[str, object]],
    *,
    branch_step_index: int,
    raw_opcode_types: dict[int, str] | None = None,
    raw_opcode_catalog: dict[int, dict[str, object]] | None = None,
    soft_instruction_limit: int = DEFAULT_CLIENTSCRIPT_BRANCH_PROBE_SOFT_LIMIT,
    hard_instruction_limit: int = DEFAULT_CLIENTSCRIPT_BRANCH_PROBE_HARD_LIMIT,
) -> dict[str, object] | None:
    if not (0 <= branch_step_index < len(instruction_steps)):
        return None

    prefix_steps = [
        step
        for step in instruction_steps[:branch_step_index]
        if isinstance(step, dict)
    ]
    _annotated_prefix_steps, state_before_branch = _replay_clientscript_stack_state(prefix_steps)
    branch_state = _clone_clientscript_stack_state(state_before_branch)
    branch_step = instruction_steps[branch_step_index]
    if not isinstance(branch_step, dict):
        return None

    annotated_branch_step = _apply_clientscript_step_to_stack_state(branch_step, branch_state)
    if not isinstance(annotated_branch_step.get("stack_effect_candidate"), dict):
        return None

    fallthrough_offset = annotated_branch_step.get("end_offset")
    if not isinstance(fallthrough_offset, int):
        return None
    branch_target_offset = _resolve_clientscript_jump_target(
        annotated_branch_step,
        next_offset=fallthrough_offset,
    )

    probe = {
        "branch_step_index": int(branch_step_index),
        "branch_instruction": _sample_clientscript_instruction_step(annotated_branch_step),
        "branch_control_flow_kind": _normalize_clientscript_control_flow_kind(
            annotated_branch_step.get("control_flow_kind")
        ),
        "branch_state_before": _summarize_clientscript_stack_state(state_before_branch),
        "branch_state_before_compact": _summarize_clientscript_stack_state_compact(state_before_branch),
        "branch_state_after": _summarize_clientscript_stack_state(branch_state),
        "branch_state_after_compact": _summarize_clientscript_stack_state_compact(branch_state),
        "branch_required_input_delta": _diff_clientscript_required_inputs(state_before_branch, branch_state),
        "fallthrough_offset": int(fallthrough_offset),
        "fallthrough_path": _trace_clientscript_bounded_stack_path(
            layout,
            start_offset=fallthrough_offset,
            initial_state=branch_state,
            raw_opcode_types=raw_opcode_types,
            raw_opcode_catalog=raw_opcode_catalog,
            soft_instruction_limit=soft_instruction_limit,
            hard_instruction_limit=hard_instruction_limit,
        ),
    }

    if isinstance(branch_target_offset, int):
        probe["branch_target_offset"] = int(branch_target_offset)
        probe["taken_path"] = _trace_clientscript_bounded_stack_path(
            layout,
            start_offset=branch_target_offset,
            initial_state=branch_state,
            raw_opcode_types=raw_opcode_types,
            raw_opcode_catalog=raw_opcode_catalog,
            soft_instruction_limit=soft_instruction_limit,
            hard_instruction_limit=hard_instruction_limit,
        )
    probe["path_comparison"] = _compare_clientscript_branch_probe_paths(
        probe["fallthrough_path"],
        probe.get("taken_path") if isinstance(probe.get("taken_path"), dict) else None,
    )
    return probe


def _build_clientscript_branch_state_probe(
    layout: ClientscriptLayout,
    instruction_steps: list[dict[str, object]],
    *,
    raw_opcode_types: dict[int, str] | None = None,
    raw_opcode_catalog: dict[int, dict[str, object]] | None = None,
    soft_instruction_limit: int = DEFAULT_CLIENTSCRIPT_BRANCH_PROBE_SOFT_LIMIT,
    hard_instruction_limit: int = DEFAULT_CLIENTSCRIPT_BRANCH_PROBE_HARD_LIMIT,
) -> dict[str, object] | None:
    branch_step_index = _find_clientscript_branch_probe_step_index(instruction_steps)
    if branch_step_index is None:
        return None
    return _probe_clientscript_branch_state(
        layout,
        instruction_steps,
        branch_step_index=branch_step_index,
        raw_opcode_types=raw_opcode_types,
        raw_opcode_catalog=raw_opcode_catalog,
        soft_instruction_limit=soft_instruction_limit,
        hard_instruction_limit=hard_instruction_limit,
    )


def _trace_clientscript_tail_continuation(
    layout: ClientscriptLayout,
    offset: int,
    *,
    raw_opcode_types: dict[int, str] | None = None,
    raw_opcode_catalog: dict[int, dict[str, object]] | None = None,
    max_instructions: int = CLIENTSCRIPT_TAIL_CONTINUATION_MAX_INSTRUCTIONS,
) -> dict[str, object] | None:
    if offset < 0 or offset >= len(layout.opcode_data) or max_instructions <= 0:
        return None

    steps: list[dict[str, object]] = []
    current_offset = int(offset)

    while len(steps) < max_instructions and current_offset < len(layout.opcode_data):
        if current_offset + 2 > len(layout.opcode_data):
            break

        raw_opcode = int.from_bytes(layout.opcode_data[current_offset : current_offset + 2], "big")
        immediate_kind, resolved_catalog_entry, step_fields = _resolve_clientscript_catalog_dispatch(
            layout.opcode_data,
            current_offset,
            raw_opcode=raw_opcode,
            raw_opcode_types=raw_opcode_types,
            raw_opcode_catalog=raw_opcode_catalog,
            resolution_scope="frontier",
        )

        if not isinstance(immediate_kind, str):
            return {
                "status": "frontier",
                "offset": current_offset,
                "raw_opcode": raw_opcode,
                "raw_opcode_hex": f"0x{raw_opcode:04X}",
                **step_fields,
                "instruction_count": len(steps),
                "instruction_sample": [_sample_clientscript_instruction_step(step) for step in steps],
            }

        immediate = _read_clientscript_immediate(
            layout.opcode_data,
            current_offset + 2,
            immediate_kind,
            immediate_width=_resolve_clientscript_step_immediate_width(
                {
                    "offset": current_offset,
                    "raw_opcode": raw_opcode,
                    "immediate_kind": immediate_kind,
                    "catalog_entry_override": resolved_catalog_entry,
                    **step_fields,
                },
                immediate_kind=immediate_kind,
                opcode_data=layout.opcode_data,
                offset=current_offset,
                raw_opcode_types=raw_opcode_types,
                raw_opcode_catalog=raw_opcode_catalog,
            ),
        )
        if immediate is None:
            return {
                "status": "invalid-immediate",
                "offset": current_offset,
                "raw_opcode": raw_opcode,
                "raw_opcode_hex": f"0x{raw_opcode:04X}",
                "immediate_kind": immediate_kind,
                "instruction_count": len(steps),
                "instruction_sample": [_sample_clientscript_instruction_step(step) for step in steps],
            }

        resolved_immediate_width = _resolve_clientscript_step_immediate_width(
            {
                "offset": current_offset,
                "raw_opcode": raw_opcode,
                "immediate_kind": immediate_kind,
                "catalog_entry_override": resolved_catalog_entry,
                **step_fields,
            },
            immediate_kind=immediate_kind,
            opcode_data=layout.opcode_data,
            offset=current_offset,
            raw_opcode_types=raw_opcode_types,
            raw_opcode_catalog=raw_opcode_catalog,
        )
        step = _apply_clientscript_semantic_hints(
            {
                "offset": current_offset,
                "raw_opcode": raw_opcode,
                "raw_opcode_hex": f"0x{raw_opcode:04X}",
                **step_fields,
                "immediate_kind": immediate_kind,
                **({"immediate_width": resolved_immediate_width} if isinstance(resolved_immediate_width, int) else {}),
                "immediate_value": immediate.get("immediate_value"),
                "switch_subtype": immediate.get("switch_subtype"),
                "end_offset": int(immediate["end_offset"]),
                **(
                    {"catalog_entry_override": resolved_catalog_entry}
                    if isinstance(resolved_catalog_entry, dict)
                    else {}
                ),
            },
            raw_opcode_catalog,
            resolution_scope="frontier",
        )
        step.pop("catalog_entry_override", None)
        steps.append(step)
        current_offset = int(immediate["end_offset"])

    return {
        "status": "complete" if current_offset >= len(layout.opcode_data) else "partial",
        "offset": int(offset),
        "end_offset": current_offset,
        "instruction_count": len(steps),
        "instruction_steps": steps,
        "instruction_sample": [_sample_clientscript_instruction_step(step) for step in steps],
        "remaining_opcode_bytes": max(len(layout.opcode_data) - current_offset, 0),
    }


def _score_clientscript_instruction_budget_suspect(
    step: dict[str, object],
    *,
    distance_from_budget_stop: int,
    orphaned_instruction_count: int,
) -> tuple[int, list[str]]:
    immediate_kind = str(step.get("immediate_kind", "") or "")
    semantic_label = str(step.get("semantic_label", "") or "")
    semantic_family = str(step.get("semantic_family", "") or "")
    control_flow_kind = str(step.get("control_flow_kind", "") or "")

    score = 0
    reasons: list[str] = []

    if immediate_kind == "switch":
        score += 8
        reasons.append(
            "Switch payloads carry jump-table data, so under-consuming one can leak several fake instructions into the historical trace."
        )
    elif immediate_kind == "string":
        score += 6
        reasons.append(
            "Variable-length strings are a common source of historical under-consumption when the parser cuts the payload short."
        )

    if control_flow_kind in {"switch", "switch-candidate"} or "SWITCH" in semantic_label:
        score += 4
        reasons.append("Semantic hints already place this opcode in the switch pipeline.")

    if semantic_label in {"PUSH_CONST_STRING_CANDIDATE", "STRING_FORMATTER_CANDIDATE"} or semantic_family.startswith(
        "string"
    ):
        score += 3
        reasons.append("String-context opcode sits close to the point where the instruction budget drift becomes visible.")

    if _is_clientscript_frontier_semantic_label(semantic_label):
        score += 2
        reasons.append("This opcode is still only frontier-classified, so a wrong payload shape could still be inflating the trace.")

    if distance_from_budget_stop <= max(orphaned_instruction_count, 2):
        score += 2
        reasons.append("The parse budget breaks only a few decoded steps after this instruction.")

    return score, reasons[:3]


def _build_clientscript_instruction_budget_desync(
    layout: ClientscriptLayout,
    prefix_trace: dict[str, object],
    tail_continuation: dict[str, object],
) -> dict[str, object] | None:
    if str(prefix_trace.get("status", "")) != "extra-bytes":
        return None
    if not isinstance(tail_continuation, dict):
        return None

    decoded_prefix_instruction_count = int(prefix_trace.get("decoded_instruction_count", 0))
    orphaned_instruction_count = int(tail_continuation.get("instruction_count", 0))
    if (
        decoded_prefix_instruction_count <= 0
        or orphaned_instruction_count <= 0
        or decoded_prefix_instruction_count != int(layout.instruction_count)
    ):
        return None

    orphaned_start_offset = int(tail_continuation.get("offset", 0))
    orphaned_end_offset = int(tail_continuation.get("end_offset", orphaned_start_offset))
    orphaned_byte_count = max(orphaned_end_offset - orphaned_start_offset, 0)
    if orphaned_byte_count <= 0:
        orphaned_byte_count = int(prefix_trace.get("remaining_opcode_bytes", 0))

    instruction_steps = prefix_trace.get("instruction_steps")
    if not isinstance(instruction_steps, list) or not instruction_steps:
        return None

    window_size = min(max(orphaned_instruction_count * 3, 8), 16)
    historical_window = [
        step
        for step in instruction_steps[-window_size:]
        if isinstance(step, dict)
    ]
    if not historical_window:
        return None

    historical_window_start_instruction_index = max(decoded_prefix_instruction_count - len(historical_window), 0)
    sampled_window: list[dict[str, object]] = []
    suspect_instruction_sample: list[dict[str, object]] = []

    for instruction_index, step in enumerate(
        historical_window,
        start=historical_window_start_instruction_index,
    ):
        distance_from_budget_stop = max(decoded_prefix_instruction_count - instruction_index, 1)
        sampled_step = _sample_clientscript_instruction_step(step)
        sampled_step["instruction_index"] = instruction_index
        sampled_step["distance_from_budget_stop"] = distance_from_budget_stop
        sampled_window.append(sampled_step)

        risk_score, suspicion_reasons = _score_clientscript_instruction_budget_suspect(
            step,
            distance_from_budget_stop=distance_from_budget_stop,
            orphaned_instruction_count=orphaned_instruction_count,
        )
        if risk_score <= 0:
            continue

        suspect_step = dict(sampled_step)
        suspect_step["risk_score"] = risk_score
        if suspicion_reasons:
            suspect_step["suspicion_reasons"] = suspicion_reasons
        suspect_instruction_sample.append(suspect_step)

    suspect_instruction_sample.sort(
        key=lambda item: (
            -int(item.get("risk_score", 0)),
            int(item.get("distance_from_budget_stop", 0)),
            int(item.get("offset", 0)),
        )
    )
    suspect_instruction_sample = suspect_instruction_sample[:5]

    combined_instruction_count = decoded_prefix_instruction_count + orphaned_instruction_count
    instruction_budget_gap = max(combined_instruction_count - int(layout.instruction_count), 0)
    if instruction_budget_gap <= 0:
        return None

    top_suspect_instruction = copy.deepcopy(suspect_instruction_sample[0]) if suspect_instruction_sample else None
    top_suspect_hex_context = None
    if isinstance(top_suspect_instruction, dict):
        top_suspect_hex_context = _sample_clientscript_hex_context(
            layout.opcode_data,
            focus_offset=int(top_suspect_instruction.get("offset", 0)),
            focus_end_offset=(
                int(top_suspect_instruction["end_offset"])
                if isinstance(top_suspect_instruction.get("end_offset"), int)
                else None
            ),
        )

    orphaned_hex_context = _sample_clientscript_hex_context(
        layout.opcode_data,
        focus_offset=orphaned_start_offset,
        focus_end_offset=orphaned_end_offset,
        bytes_before=0,
        bytes_after=12,
    )

    return {
        "status": "budget-mismatch",
        "declared_instruction_count": int(layout.instruction_count),
        "decoded_prefix_instruction_count": decoded_prefix_instruction_count,
        "orphaned_instruction_count": orphaned_instruction_count,
        "combined_instruction_count": combined_instruction_count,
        "instruction_budget_gap": instruction_budget_gap,
        "orphaned_byte_count": orphaned_byte_count,
        "historical_window_start_instruction_index": historical_window_start_instruction_index,
        "historical_window_instruction_sample": sampled_window,
        "orphaned_instruction_sample": copy.deepcopy(tail_continuation.get("instruction_sample", [])[:8]),
        "orphaned_hex_context": orphaned_hex_context,
        "top_suspect_instruction": top_suspect_instruction,
        "top_suspect_hex_context": top_suspect_hex_context,
        "suspect_instruction_sample": suspect_instruction_sample,
        "notes": (
            f"The locked prefix exhausted the declared instruction budget {instruction_budget_gap} instructions early, "
            f"but the remaining {orphaned_byte_count} opcode bytes still parse into a valid continuation."
        ),
    }


def _is_clientscript_terminal_step(step: dict[str, object] | None) -> bool:
    if not isinstance(step, dict):
        return False
    semantic_label = str(step.get("semantic_label", "") or "")
    control_flow_kind = str(step.get("control_flow_kind", "") or "")
    if semantic_label == "RETURN" or control_flow_kind in {"return", "return-candidate", "throw"}:
        return True

    if int(step.get("raw_opcode", -1)) != 0x035E or str(step.get("immediate_kind", "") or "") != "bytes":
        return False
    immediate_value = step.get("immediate_value")
    if not isinstance(immediate_value, dict):
        return False
    hex_value = immediate_value.get("hex")
    byte_count = immediate_value.get("byte_count")
    if not isinstance(hex_value, str) or not isinstance(byte_count, int):
        return False
    normalized_hex = hex_value.replace(" ", "").upper()
    return byte_count == 10 and normalized_hex == "00000000063700049500"


def _recover_clientscript_budget_relaxed_trace(
    layout: ClientscriptLayout,
    prefix_trace: dict[str, object],
    tail_continuation: dict[str, object],
) -> dict[str, object] | None:
    if str(prefix_trace.get("status", "")) != "extra-bytes":
        return None
    if str(tail_continuation.get("status", "")) != "complete":
        return None

    prefix_steps = prefix_trace.get("instruction_steps")
    tail_steps = tail_continuation.get("instruction_steps")
    if not isinstance(prefix_steps, list) or not prefix_steps:
        return None
    if not isinstance(tail_steps, list) or not tail_steps:
        return None

    last_prefix_step = prefix_steps[-1]
    if not isinstance(last_prefix_step, dict):
        return None
    prefix_end_offset = last_prefix_step.get("end_offset")
    tail_offset = tail_continuation.get("offset")
    if not isinstance(prefix_end_offset, int) or not isinstance(tail_offset, int):
        return None
    if prefix_end_offset != tail_offset:
        return None

    tail_end_offset = tail_continuation.get("end_offset")
    if not isinstance(tail_end_offset, int) or tail_end_offset != len(layout.opcode_data):
        return None
    if not _is_clientscript_terminal_step(tail_steps[-1] if tail_steps else None):
        return None

    decoded_prefix_instruction_count = int(prefix_trace.get("decoded_instruction_count", 0))
    tail_instruction_count = int(tail_continuation.get("instruction_count", 0))
    if decoded_prefix_instruction_count != len(prefix_steps) or tail_instruction_count != len(tail_steps):
        return None

    recovered_instruction_count = decoded_prefix_instruction_count + tail_instruction_count
    instruction_budget_gap = recovered_instruction_count - int(layout.instruction_count)
    if instruction_budget_gap <= 0 or instruction_budget_gap > CLIENTSCRIPT_BUDGET_RELAXED_MAX_GAP:
        return None

    return {
        "status": "budget-relaxed",
        "declared_instruction_count": int(layout.instruction_count),
        "recovered_instruction_count": recovered_instruction_count,
        "instruction_budget_gap": instruction_budget_gap,
        "tail_offset": tail_offset,
        "tail_end_offset": tail_end_offset,
        "tail_instruction_count": tail_instruction_count,
        "recovery_source": "tail-continuation",
        "notes": (
            f"Recovered a complete linear trace by appending {tail_instruction_count} parseable tail instructions "
            f"after the declared budget was exhausted {instruction_budget_gap} instructions early."
        ),
        "instruction_steps": [copy.deepcopy(step) for step in prefix_steps + tail_steps],
    }


def _populate_clientscript_disassembly_profile(
    profile: dict[str, object],
    layout: ClientscriptLayout,
    annotated_steps: list[dict[str, object]],
    *,
    mode: str,
    solution_count: int,
    bailed: bool,
    parser_status: str,
    distinct_raw_opcode_count: int | None = None,
    tail_trace_status: str = "selected-solution",
    recovery: dict[str, object] | None = None,
    raw_opcode_types: dict[int, str] | None = None,
    raw_opcode_catalog: dict[int, dict[str, object]] | None = None,
) -> None:
    annotated_steps = _hydrate_clientscript_step_end_offsets(layout, annotated_steps)
    annotated_steps, stack_tracking = _annotate_clientscript_stack_effects(annotated_steps)
    immediate_kind_counts: dict[str, int] = {}
    for step in annotated_steps:
        immediate_kind = str(step["immediate_kind"])
        immediate_kind_counts[immediate_kind] = immediate_kind_counts.get(immediate_kind, 0) + 1

    profile["kind"] = "clientscript-disassembly"
    profile["parser_status"] = parser_status
    profile["distinct_raw_opcode_count"] = (
        distinct_raw_opcode_count
        if isinstance(distinct_raw_opcode_count, int)
        else len({int(step["raw_opcode"]) for step in annotated_steps})
    )
    profile["immediate_kind_counts"] = immediate_kind_counts
    profile["semantic_instruction_count"] = sum(
        1 for step in annotated_steps if isinstance(step.get("semantic_label"), str)
    )
    profile["stack_tracking"] = stack_tracking
    profile["tail_trace_status"] = tail_trace_status
    profile["tail_instruction_count"] = len(annotated_steps)
    profile["tail_remaining_opcode_bytes"] = 0
    if annotated_steps:
        profile["tail_last_instruction"] = _sample_clientscript_instruction_step(annotated_steps[-1])
        profile["tail_instruction_sample"] = _build_clientscript_late_instruction_sample(
            annotated_steps,
            max_steps=8,
        )
        profile["late_instruction_sample"] = _build_clientscript_late_instruction_sample(
            annotated_steps,
            max_steps=16,
        )
    profile["tail_stack_tracking"] = {
        field: copy.deepcopy(stack_tracking[field])
        for field in ("minimum_required_inputs", "final_depths", "final_expression_stacks")
        if field in stack_tracking
    }
    branch_state_probe = _build_clientscript_branch_state_probe(
        layout,
        annotated_steps,
        raw_opcode_types=raw_opcode_types,
        raw_opcode_catalog=raw_opcode_catalog,
    )
    if isinstance(branch_state_probe, dict) and branch_state_probe:
        profile["branch_state_probe"] = branch_state_probe
    profile["instruction_sample"] = annotated_steps[:32]
    profile["disassembly_mode"] = mode
    profile["disassembly_solution_count"] = int(solution_count)
    profile["disassembly_bailed"] = bool(bailed)
    if isinstance(recovery, dict) and recovery:
        profile["instruction_budget_relaxed"] = copy.deepcopy(recovery)

    profile["_disassembly_text"] = _render_clientscript_disassembly_text(
        layout,
        annotated_steps,
        mode=mode,
        solution_count=int(solution_count),
        bailed=bool(bailed),
    )
    profile["_pseudocode_text"] = _render_clientscript_pseudocode_text(
        layout,
        annotated_steps,
        mode=mode,
        solution_count=int(solution_count),
        bailed=bool(bailed),
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
    origin_offset = int(step.get("offset", 0))
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
                    origin_offset=origin_offset,
                    origin_stack_name=stack_name,
                    raw_opcode_hex=raw_opcode_hex,
                    semantic_label=semantic_label or None,
                )
            return _make_clientscript_expression(
                "int-literal",
                value=int(immediate_value),
                origin_offset=origin_offset,
                origin_stack_name=stack_name,
                raw_opcode_hex=raw_opcode_hex,
                semantic_label=semantic_label or None,
            )
        if semantic_label == "INT_STATE_GETTER_CANDIDATE" and isinstance(immediate_value, int):
            return _make_clientscript_expression(
                "state-reference",
                source_name="state",
                reference_id=int(immediate_value),
                origin_offset=origin_offset,
                origin_stack_name=stack_name,
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
                    origin_offset=origin_offset,
                    origin_stack_name=stack_name,
                    raw_opcode_hex=raw_opcode_hex,
                    semantic_label=semantic_label,
                )
            return _make_clientscript_expression(
                "int-literal",
                value=int(immediate_value),
                origin_offset=origin_offset,
                origin_stack_name=stack_name,
                raw_opcode_hex=raw_opcode_hex,
                semantic_label=semantic_label,
            )
        if semantic_label == "PUSH_SLOT_REFERENCE_CANDIDATE" and isinstance(immediate_value, int):
            return _make_clientscript_expression(
                "slot-reference",
                slot=int(immediate_value),
                origin_offset=origin_offset,
                origin_stack_name=stack_name,
                raw_opcode_hex=raw_opcode_hex,
                semantic_label=semantic_label,
            )
        if semantic_label == "VAR_REFERENCE_CANDIDATE":
            return _make_clientscript_expression(
                "state-reference",
                source_name=step.get("reference_source_name"),
                reference_id=step.get("reference_id"),
                origin_offset=origin_offset,
                origin_stack_name=stack_name,
                raw_opcode_hex=raw_opcode_hex,
                semantic_label=semantic_label,
            )
    if stack_name == "string" and isinstance(immediate_value, str):
        return _make_clientscript_expression(
            "string-literal",
            value=immediate_value,
            origin_offset=origin_offset,
            origin_stack_name=stack_name,
            raw_opcode_hex=raw_opcode_hex,
            semantic_label=semantic_label or None,
        )
    if stack_name == "long" and immediate_value is not None:
        return _make_clientscript_expression(
            "long-literal",
            value=immediate_value,
            origin_offset=origin_offset,
            origin_stack_name=stack_name,
            raw_opcode_hex=raw_opcode_hex,
            semantic_label=semantic_label or None,
        )
    return _make_clientscript_expression(
        f"{stack_name}-result",
        origin_offset=origin_offset,
        origin_stack_name=stack_name,
        raw_opcode_hex=raw_opcode_hex,
        semantic_label=semantic_label or None,
        immediate_value=immediate_value if immediate_value is not None else None,
        result_index=produce_index if produce_index else None,
        inputs=sampled_inputs,
    )


def _make_clientscript_stack_state() -> dict[str, object]:
    return {
        "depths": {stack_name: 0 for stack_name in CLIENTSCRIPT_STACK_NAMES},
        "required_inputs": {stack_name: 0 for stack_name in CLIENTSCRIPT_STACK_NAMES},
        "expression_stacks": {stack_name: [] for stack_name in CLIENTSCRIPT_STACK_NAMES},
        "known_effect_instruction_count": 0,
        "unknown_effect_instruction_count": 0,
    }


def _clone_clientscript_stack_state(state: dict[str, object]) -> dict[str, object]:
    cloned = _make_clientscript_stack_state()
    for field in ("depths", "required_inputs", "expression_stacks"):
        source = state.get(field)
        if isinstance(source, dict):
            cloned[field] = copy.deepcopy(source)
    for field in ("known_effect_instruction_count", "unknown_effect_instruction_count"):
        value = state.get(field)
        if isinstance(value, int):
            cloned[field] = int(value)
    return cloned


def _prepare_clientscript_step_for_stack_annotation(step: dict[str, object]) -> dict[str, object]:
    annotated = dict(step)
    for stack_name in CLIENTSCRIPT_STACK_NAMES:
        annotated.pop(f"{stack_name}_stack_depth_before", None)
        annotated.pop(f"{stack_name}_stack_depth_after", None)
        annotated.pop(f"consumed_{stack_name}_expressions", None)
        annotated.pop(f"produced_{stack_name}_expressions", None)
    annotated.pop("switch_selector_expression", None)
    annotated.pop("branch_condition_expression", None)
    return annotated


def _summarize_clientscript_stack_state(state: dict[str, object]) -> dict[str, object]:
    depths = state.get("depths")
    if not isinstance(depths, dict):
        depths = {}
    required_inputs = state.get("required_inputs")
    if not isinstance(required_inputs, dict):
        required_inputs = {}
    expression_stacks = state.get("expression_stacks")
    if not isinstance(expression_stacks, dict):
        expression_stacks = {}

    return {
        "known_effect_instruction_count": int(state.get("known_effect_instruction_count", 0)),
        "unknown_effect_instruction_count": int(state.get("unknown_effect_instruction_count", 0)),
        "minimum_required_inputs": {
            f"{stack_name}_stack": int(required_inputs.get(stack_name, 0))
            for stack_name in CLIENTSCRIPT_STACK_NAMES
            if int(required_inputs.get(stack_name, 0)) > 0
        },
        "final_depths": {
            f"{stack_name}_stack": int(depths.get(stack_name, 0))
            for stack_name in CLIENTSCRIPT_STACK_NAMES
        },
        "final_expression_stacks": {
            f"{stack_name}_stack": [
                _sample_clientscript_expression(expression)
                for expression in expression_stacks.get(stack_name, [])[-4:]
                if isinstance(expression, dict)
            ]
            for stack_name in CLIENTSCRIPT_STACK_NAMES
            if expression_stacks.get(stack_name)
        },
    }


def _coarsen_clientscript_stack_state_signature(state: dict[str, object]) -> str:
    expression_stacks = state.get("expression_stacks")
    if not isinstance(expression_stacks, dict):
        expression_stacks = {}

    signature_parts: list[str] = []
    for stack_name in CLIENTSCRIPT_STACK_NAMES:
        stack = expression_stacks.get(stack_name)
        if not isinstance(stack, list):
            stack = []
        top_kinds = [
            str(expression.get("kind", "expression"))
            for expression in stack[-3:]
            if isinstance(expression, dict)
        ]
        signature_parts.append(
            f"{stack_name}:{len(stack)}:{','.join(top_kinds) if top_kinds else '-'}"
        )
    return "|".join(signature_parts)


def _summarize_clientscript_stack_state_compact(state: dict[str, object]) -> dict[str, object]:
    expression_stacks = state.get("expression_stacks")
    if not isinstance(expression_stacks, dict):
        expression_stacks = {}

    int_stack = expression_stacks.get("int")
    if not isinstance(int_stack, list):
        int_stack = []
    string_stack = expression_stacks.get("string")
    if not isinstance(string_stack, list):
        string_stack = []
    long_stack = expression_stacks.get("long")
    if not isinstance(long_stack, list):
        long_stack = []

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
    operand_signature = _classify_clientscript_operand_signature(
        [expression for expression in int_stack if isinstance(expression, dict)],
        [expression for expression in string_stack if isinstance(expression, dict)],
    )

    return {
        "operand_signature": operand_signature,
        "int_stack_count": len(int_stack),
        "string_stack_count": len(string_stack),
        "long_stack_count": len(long_stack),
        "widget_stack_count": widget_count,
        "state_stack_count": state_count,
        "int_literal_stack_count": int_literal_count,
        "symbolic_int_stack_count": symbolic_int_count,
        "int_survivor_sample": [
            _format_clientscript_expression(expression)
            for expression in int_stack[-3:]
            if isinstance(expression, dict)
        ],
        "string_survivor_sample": [
            _format_clientscript_expression(expression)
            for expression in string_stack[-3:]
            if isinstance(expression, dict)
        ],
        "long_survivor_sample": [
            _format_clientscript_expression(expression)
            for expression in long_stack[-3:]
            if isinstance(expression, dict)
        ],
    }


def _resolve_clientscript_contextual_stack_hint(
    step: dict[str, object],
    state: dict[str, object],
) -> dict[str, object] | None:
    if str(step.get("semantic_resolution_scope", "") or "") != "frontier":
        return None

    contextual_stack_hints = step.get("contextual_stack_hints")
    if not isinstance(contextual_stack_hints, list) or not contextual_stack_hints:
        return None

    state_compact = _summarize_clientscript_stack_state_compact(state)
    prefix_operand_signature = str(state_compact.get("operand_signature", "") or "")
    if not prefix_operand_signature:
        return None
    normalized_prefix_operand_signature = _normalize_clientscript_operand_signature_for_matching(
        prefix_operand_signature
    )

    best_hint: dict[str, object] | None = None
    best_confidence = float("-inf")
    for hint_entry in contextual_stack_hints:
        if not isinstance(hint_entry, dict):
            continue
        if not _allows_clientscript_resolution_scope(hint_entry, resolution_scope="frontier"):
            continue

        match_prefix_operand_signature = hint_entry.get("match_prefix_operand_signature")
        normalized_matches: list[str] = []
        if isinstance(match_prefix_operand_signature, str) and match_prefix_operand_signature:
            normalized_matches = [match_prefix_operand_signature]
        elif isinstance(match_prefix_operand_signature, list):
            normalized_matches = [
                str(signature).strip()
                for signature in match_prefix_operand_signature
                if str(signature).strip()
            ]
        normalized_match_set = set(normalized_matches)
        normalized_match_set.update(
            _normalize_clientscript_operand_signature_for_matching(signature)
            for signature in normalized_matches
            if isinstance(signature, str) and signature
        )
        if (
            prefix_operand_signature not in normalized_match_set
            and normalized_prefix_operand_signature not in normalized_match_set
        ):
            continue

        confidence = hint_entry.get("confidence")
        try:
            confidence_value = float(confidence)
        except (TypeError, ValueError):
            confidence_value = 0.0
        if best_hint is None or confidence_value > best_confidence:
            best_hint = hint_entry
            best_confidence = confidence_value

    if not isinstance(best_hint, dict):
        return None

    contextual_override: dict[str, object] = {
        "contextual_stack_hint_applied": True,
        "contextual_stack_hint_match_prefix_operand_signature": prefix_operand_signature,
        "stack_effect_source": "contextual-hint",
    }
    mnemonic = best_hint.get("mnemonic")
    if isinstance(mnemonic, str) and mnemonic:
        contextual_override["semantic_label"] = mnemonic
    family = best_hint.get("family")
    if isinstance(family, str) and family:
        contextual_override["family"] = family
        contextual_override["semantic_family"] = family
    notes = best_hint.get("notes")
    if isinstance(notes, str) and notes:
        contextual_override["semantic_notes"] = notes
    confidence = best_hint.get("confidence")
    if isinstance(confidence, (int, float)):
        contextual_override["semantic_confidence"] = float(confidence)
    operand_signature_candidate = best_hint.get("operand_signature_candidate")
    if isinstance(operand_signature_candidate, dict) and operand_signature_candidate:
        contextual_override["operand_signature_candidate"] = dict(operand_signature_candidate)
    stack_pops = best_hint.get("stack_pops")
    if (
        "operand_signature_candidate" not in contextual_override
        and isinstance(stack_pops, list)
        and stack_pops
    ):
        normalized_stack_pops = [str(token).strip() for token in stack_pops if str(token).strip()]
        if normalized_stack_pops:
            contextual_override["operand_signature_candidate"] = {
                "signature": "+".join(normalized_stack_pops),
                "confidence": float(contextual_override.get("semantic_confidence", 0.78)),
                "notes": "Contextual stack hint supplied an explicit operand signature.",
            }
    stack_effect_candidate = best_hint.get("stack_effect_candidate")
    if isinstance(stack_effect_candidate, dict) and stack_effect_candidate:
        contextual_override["stack_effect_candidate"] = dict(stack_effect_candidate)
    elif isinstance(stack_pops, list) and stack_pops:
        inferred_stack_effect = _make_clientscript_override_stack_effect_from_stack_pops(stack_pops)
        if inferred_stack_effect is not None:
            contextual_override["stack_effect_candidate"] = inferred_stack_effect
    return contextual_override


def _diff_clientscript_required_inputs(
    before: dict[str, object],
    after: dict[str, object],
) -> dict[str, int]:
    before_required = before.get("required_inputs")
    if not isinstance(before_required, dict):
        before_required = {}
    after_required = after.get("required_inputs")
    if not isinstance(after_required, dict):
        after_required = {}

    delta: dict[str, int] = {}
    for stack_name in CLIENTSCRIPT_STACK_NAMES:
        before_count = int(before_required.get(stack_name, 0))
        after_count = int(after_required.get(stack_name, 0))
        if after_count > before_count:
            delta[f"{stack_name}_stack"] = after_count - before_count
    return delta


def _normalize_clientscript_control_flow_kind(control_flow_kind: object) -> str:
    normalized = str(control_flow_kind or "")
    if normalized == "branch-candidate":
        return "branch"
    if normalized == "jump-candidate":
        return "jump"
    if normalized == "switch-candidate":
        return "switch"
    return normalized


def _compare_clientscript_branch_probe_paths(
    fallthrough_path: dict[str, object],
    taken_path: dict[str, object] | None,
) -> dict[str, object]:
    fallthrough_status = str(fallthrough_path.get("status", ""))
    taken_status = str(taken_path.get("status", "")) if isinstance(taken_path, dict) else "missing"
    fallthrough_required_input_delta = fallthrough_path.get("required_input_delta")
    if not isinstance(fallthrough_required_input_delta, dict):
        fallthrough_required_input_delta = {}
    taken_required_input_delta = taken_path.get("required_input_delta") if isinstance(taken_path, dict) else {}
    if not isinstance(taken_required_input_delta, dict):
        taken_required_input_delta = {}

    fallthrough_compact = fallthrough_path.get("final_stack_compact")
    if not isinstance(fallthrough_compact, dict):
        fallthrough_compact = {}
    taken_compact = taken_path.get("final_stack_compact") if isinstance(taken_path, dict) else {}
    if not isinstance(taken_compact, dict):
        taken_compact = {}

    divergence_flags: list[str] = []
    if fallthrough_status != taken_status:
        divergence_flags.append("path-status-divergence")
    if fallthrough_required_input_delta != taken_required_input_delta:
        divergence_flags.append("phantom-input-mismatch")
    if str(fallthrough_compact.get("operand_signature", "")) != str(taken_compact.get("operand_signature", "")):
        divergence_flags.append("survivor-signature-mismatch")
    if (
        fallthrough_compact.get("int_survivor_sample") != taken_compact.get("int_survivor_sample")
        or fallthrough_compact.get("string_survivor_sample") != taken_compact.get("string_survivor_sample")
        or fallthrough_compact.get("long_survivor_sample") != taken_compact.get("long_survivor_sample")
    ):
        divergence_flags.append("survivor-sample-mismatch")

    phantom_input_side = "none"
    if fallthrough_required_input_delta and not taken_required_input_delta:
        phantom_input_side = "fallthrough-only"
    elif taken_required_input_delta and not fallthrough_required_input_delta:
        phantom_input_side = "taken-only"
    elif fallthrough_required_input_delta != taken_required_input_delta:
        phantom_input_side = "both-different"

    return {
        "fallthrough_status": fallthrough_status,
        "taken_status": taken_status,
        "fallthrough_operand_signature": str(fallthrough_compact.get("operand_signature", "")),
        "taken_operand_signature": str(taken_compact.get("operand_signature", "")),
        "phantom_input_side": phantom_input_side,
        "phantom_input_mismatch": fallthrough_required_input_delta != taken_required_input_delta,
        "operand_signature_mismatch": str(fallthrough_compact.get("operand_signature", "")) != str(
            taken_compact.get("operand_signature", "")
        ),
        "survivor_sample_mismatch": "survivor-sample-mismatch" in divergence_flags,
        "status_mismatch": fallthrough_status != taken_status,
        "divergence_flags": divergence_flags,
    }


def _apply_clientscript_step_to_stack_state(
    step: dict[str, object],
    state: dict[str, object],
) -> dict[str, object]:
    annotated = _prepare_clientscript_step_for_stack_annotation(step)
    contextual_stack_hint = _resolve_clientscript_contextual_stack_hint(annotated, state)
    if isinstance(contextual_stack_hint, dict):
        annotated.update(contextual_stack_hint)
    stack_effect = _infer_clientscript_stack_effect(annotated)
    if stack_effect is None:
        state["unknown_effect_instruction_count"] = int(state.get("unknown_effect_instruction_count", 0)) + 1
        return annotated

    state["known_effect_instruction_count"] = int(state.get("known_effect_instruction_count", 0)) + 1
    annotated["stack_effect_candidate"] = dict(stack_effect)

    depths = state.setdefault("depths", {stack_name: 0 for stack_name in CLIENTSCRIPT_STACK_NAMES})
    required_inputs = state.setdefault(
        "required_inputs",
        {stack_name: 0 for stack_name in CLIENTSCRIPT_STACK_NAMES},
    )
    expression_stacks = state.setdefault(
        "expression_stacks",
        {stack_name: [] for stack_name in CLIENTSCRIPT_STACK_NAMES},
    )

    for stack_name in CLIENTSCRIPT_STACK_NAMES:
        pops = int(stack_effect.get(f"{stack_name}_pops", 0))
        pushes = int(stack_effect.get(f"{stack_name}_pushes", 0))
        before_depth = int(depths.get(stack_name, 0))
        stack = expression_stacks.setdefault(stack_name, [])
        consumed_expressions: list[dict[str, object]] = []
        for _ in range(pops):
            if stack:
                consumed_expressions.append(stack.pop())
            else:
                required_inputs[stack_name] = int(required_inputs.get(stack_name, 0)) + 1
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
            stack.append(produced_expression)
            produced_expressions.append(produced_expression)
        if produced_expressions:
            annotated[f"produced_{stack_name}_expressions"] = produced_expressions

    if annotated.get("consumed_int_expressions"):
        semantic_label = str(annotated.get("semantic_label", ""))
        control_flow_kind = _normalize_clientscript_control_flow_kind(annotated.get("control_flow_kind"))
        if semantic_label == "SWITCH_DISPATCH_FRONTIER_CANDIDATE":
            annotated["switch_selector_expression"] = annotated["consumed_int_expressions"][0]
        elif control_flow_kind in {"branch", "jump"}:
            annotated["branch_condition_expression"] = annotated["consumed_int_expressions"][0]

    return annotated


def _replay_clientscript_stack_state(
    steps: list[dict[str, object]],
    *,
    initial_state: dict[str, object] | None = None,
) -> tuple[list[dict[str, object]], dict[str, object]]:
    state = (
        _clone_clientscript_stack_state(initial_state)
        if isinstance(initial_state, dict)
        else _make_clientscript_stack_state()
    )
    annotated_steps: list[dict[str, object]] = []
    for step in steps:
        if not isinstance(step, dict):
            continue
        annotated_steps.append(_apply_clientscript_step_to_stack_state(step, state))
    return annotated_steps, state


def _diff_clientscript_stack_compact_survivor_delta(
    before: dict[str, object],
    after: dict[str, object],
) -> dict[str, int]:
    delta: dict[str, int] = {}
    for field in (
        "int_stack_count",
        "string_stack_count",
        "long_stack_count",
        "widget_stack_count",
        "state_stack_count",
        "int_literal_stack_count",
        "symbolic_int_stack_count",
    ):
        before_count = int(before.get(field, 0) or 0)
        after_count = int(after.get(field, 0) or 0)
        if after_count != before_count:
            delta[field] = after_count - before_count
    return delta


def _compact_clientscript_stack_compact_survivor_delta(
    before: dict[str, object],
    after: dict[str, object],
) -> dict[str, int]:
    delta: dict[str, int] = {}
    for source_field, compact_field in (
        ("int_stack_count", "int"),
        ("string_stack_count", "string"),
        ("long_stack_count", "long"),
    ):
        before_count = int(before.get(source_field, 0) or 0)
        after_count = int(after.get(source_field, 0) or 0)
        if after_count != before_count:
            delta[compact_field] = after_count - before_count
    return delta


def _replay_clientscript_stack_state_with_snapshots(
    steps: list[dict[str, object]],
    *,
    initial_state: dict[str, object] | None = None,
) -> tuple[list[dict[str, object]], dict[str, object]]:
    state = (
        _clone_clientscript_stack_state(initial_state)
        if isinstance(initial_state, dict)
        else _make_clientscript_stack_state()
    )
    snapshots: list[dict[str, object]] = []
    for step in steps:
        if not isinstance(step, dict):
            continue
        before_state = _clone_clientscript_stack_state(state)
        annotated_step = _apply_clientscript_step_to_stack_state(copy.deepcopy(step), state)
        after_state = _clone_clientscript_stack_state(state)
        before_compact = _summarize_clientscript_stack_state_compact(before_state)
        after_compact = _summarize_clientscript_stack_state_compact(after_state)
        snapshots.append(
            {
                "step": annotated_step,
                "pre_stack_compact": before_compact,
                "post_stack_compact": after_compact,
                "required_input_delta": _diff_clientscript_required_inputs(before_state, after_state),
                "survivor_delta": _diff_clientscript_stack_compact_survivor_delta(
                    before_compact,
                    after_compact,
                ),
            }
        )
    return snapshots, state


def _annotate_clientscript_stack_effects(
    steps: list[dict[str, object]],
) -> tuple[list[dict[str, object]], dict[str, object]]:
    annotated_steps, stack_state = _replay_clientscript_stack_state(steps)
    return annotated_steps, _summarize_clientscript_stack_state(stack_state)


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
    string_result_count = sum(
        1
        for expression in string_stack
        if isinstance(expression, dict) and str(expression.get("kind", "")).startswith("string-")
        and str(expression.get("kind", "")) != "string-literal"
    )

    operand_signature = _classify_clientscript_operand_signature(
        [expression for expression in int_stack if isinstance(expression, dict)],
        [expression for expression in string_stack if isinstance(expression, dict)],
    )

    return {
        "prefix_int_stack_expression_count": len(int_stack),
        "prefix_string_stack_count": string_count,
        "prefix_string_result_stack_count": string_result_count,
        "prefix_widget_stack_count": widget_count,
        "prefix_state_stack_count": state_count,
        "prefix_int_literal_stack_count": int_literal_count,
        "prefix_symbolic_int_stack_count": symbolic_int_count,
        "prefix_operand_signature": operand_signature,
        "prefix_int_stack_sample": int_stack[-4:],
        "prefix_string_stack_sample": string_stack[-4:],
    }


def _build_clientscript_string_transform_frontier_candidates(
    opcode_catalog: dict[int, dict[str, object]],
) -> tuple[dict[int, dict[str, object]], dict[str, object]]:
    catalog: dict[int, dict[str, object]] = {}
    transform_frontier_script_count = 0
    result_carry_script_count = 0

    for raw_opcode, entry in sorted(opcode_catalog.items()):
        if not isinstance(entry, dict):
            continue
        mnemonic = str(entry.get("mnemonic") or entry.get("candidate_mnemonic") or entry.get("semantic_label") or "")
        family = str(entry.get("family") or entry.get("semantic_family") or "")
        if mnemonic in {
            "PUSH_CONST_STRING_CANDIDATE",
            "STRING_FORMATTER_CANDIDATE",
            "WIDGET_TEXT_MUTATOR_CANDIDATE",
        }:
            continue
        if family in {"stack-constant", "string-transform-action", "widget-text-action"}:
            continue

        signature_counts: dict[str, int] = {}
        signature_sample = entry.get("prefix_operand_signature_sample")
        if isinstance(signature_sample, list):
            for sample in signature_sample:
                if not isinstance(sample, dict):
                    continue
                signature = str(sample.get("signature", ""))
                if not signature:
                    continue
                signature_counts[signature] = int(sample.get("count", 0))
        if not signature_counts:
            continue

        dominant_signature = max(signature_counts.items(), key=lambda item: (int(item[1]), str(item[0])))[0]
        transform_signature = dominant_signature in {"int+string", "string+string"}
        widget_text_signature = dominant_signature in {"widget+string", "widget+int+string"}

        script_samples = entry.get("script_samples")
        if not isinstance(script_samples, list):
            script_samples = []
        string_result_script_count = 0
        string_result_samples: list[dict[str, object]] = []
        for sample in script_samples:
            if not isinstance(sample, dict):
                continue
            string_stack_sample = sample.get("prefix_string_stack_sample")
            if not isinstance(string_stack_sample, list):
                continue
            string_results = [
                expression
                for expression in string_stack_sample
                if isinstance(expression, dict)
                and str(expression.get("kind", "")).startswith("string-")
                and str(expression.get("kind", "")) != "string-literal"
            ]
            if not string_results:
                continue
            string_result_script_count += 1
            if len(string_result_samples) < 6:
                string_result_samples.append(
                    {
                        "key": sample.get("key"),
                        "prefix_operand_signature": sample.get("prefix_operand_signature"),
                        "string_results": string_results,
                    }
                )

        if not transform_signature and not widget_text_signature and string_result_script_count <= 0:
            continue

        script_count = int(entry.get("script_count", 0))
        confidence = 0.58
        reasons: list[str] = []
        candidate_mnemonic = "STRING_RESULT_CHAIN_CANDIDATE"
        candidate_family = "string-result-chain"
        if transform_signature:
            candidate_mnemonic = "STRING_FORMATTER_FRONTIER_CANDIDATE"
            candidate_family = "string-transform-frontier"
            confidence = 0.68
            reasons.append(
                "The unresolved opcode consistently appears with mixed integer/string or string/string operands already staged on the stack, which matches a formatter-style frontier."
            )
        elif widget_text_signature:
            candidate_mnemonic = "WIDGET_TEXT_MUTATOR_FRONTIER_CANDIDATE"
            candidate_family = "widget-text-frontier"
            confidence = 0.7
            reasons.append(
                "The unresolved opcode appears with a widget-bearing string payload already staged on the stack, which matches a text-bearing widget frontier."
            )
        else:
            reasons.append(
                "The unresolved opcode repeatedly appears after a produced string-result survives on the stack, which marks it as a likely downstream string-transform or text-delivery frontier."
            )

        if string_result_script_count > 0:
            confidence = min(0.84, confidence + 0.06)
            reasons.append(
                "Observed prefix stacks already contain produced string-result values, which is strong evidence that the formatter/text pipeline has advanced to this frontier."
            )
        if script_count >= 2:
            confidence = min(0.84, confidence + 0.03)
        if transform_signature:
            transform_frontier_script_count += script_count
        if string_result_script_count > 0:
            result_carry_script_count += string_result_script_count

        candidate_entry: dict[str, object] = {
            "raw_opcode": int(raw_opcode),
            "raw_opcode_hex": f"0x{int(raw_opcode):04X}",
            "script_count": script_count,
            "key_sample": entry.get("key_sample", []),
            "script_samples": script_samples[:8],
            "prefix_operand_signature_sample": [
                {"signature": signature, "count": count}
                for signature, count in sorted(
                    signature_counts.items(),
                    key=lambda item: (-int(item[1]), str(item[0])),
                )[:6]
            ],
            "string_result_script_count": string_result_script_count,
            "string_result_samples": string_result_samples,
            "candidate_mnemonic": candidate_mnemonic,
            "family": candidate_family,
            "candidate_confidence": round(confidence, 2),
            "candidate_reasons": reasons,
        }
        catalog[int(raw_opcode)] = candidate_entry

    summary = {
        "frontier_opcode_count": len(catalog),
        "transform_frontier_script_count": transform_frontier_script_count,
        "string_result_frontier_script_count": result_carry_script_count,
        "catalog_sample": sorted(
            catalog.values(),
            key=lambda entry: (
                -int(entry.get("string_result_script_count", 0)),
                -int(entry.get("script_count", 0)),
                int(entry["raw_opcode"]),
            ),
        )[:24],
    }
    return catalog, summary


def _build_clientscript_string_transform_arity_candidates(
    frontier_candidates: dict[int, dict[str, object]],
) -> tuple[dict[int, dict[str, object]], dict[str, object]]:
    profile_specs = (
        {
            "candidate_mnemonic": "STRING_FORMATTER_CANDIDATE",
            "family": "string-transform-action",
            "target_kind": "string",
            "signature": "int+string",
            "int_pops": 1,
            "string_pops": 1,
            "string_pushes": 1,
            "base_confidence": 0.5,
            "specificity_rank": 2,
            "notes": "Top-of-stack window repeatedly looks like one integer plus one string feeding a string-producing transform.",
        },
        {
            "candidate_mnemonic": "STRING_FORMATTER_CANDIDATE",
            "family": "string-transform-action",
            "target_kind": "string",
            "signature": "string+string",
            "int_pops": 0,
            "string_pops": 2,
            "string_pushes": 1,
            "base_confidence": 0.52,
            "specificity_rank": 3,
            "notes": "Top-of-stack window repeatedly looks like two strings being merged into a new string result.",
        },
        {
            "candidate_mnemonic": "WIDGET_TEXT_MUTATOR_CANDIDATE",
            "family": "widget-text-action",
            "target_kind": "widget",
            "signature": "widget+string",
            "int_pops": 1,
            "string_pops": 1,
            "string_pushes": 0,
            "base_confidence": 0.56,
            "specificity_rank": 4,
            "notes": "Top-of-stack window repeatedly looks like a widget handle plus a string payload, which fits a text-bearing widget mutator.",
        },
        {
            "candidate_mnemonic": "WIDGET_TEXT_MUTATOR_CANDIDATE",
            "family": "widget-text-action",
            "target_kind": "widget",
            "signature": "widget+int+string",
            "int_pops": 2,
            "string_pops": 1,
            "string_pushes": 0,
            "base_confidence": 0.58,
            "specificity_rank": 5,
            "notes": "Top-of-stack window repeatedly looks like a widget handle plus an integer and string payload, which fits a parameterized widget-text mutator.",
        },
        {
            "candidate_mnemonic": "STRING_ACTION_CANDIDATE",
            "family": "string-action",
            "target_kind": "string",
            "signature": "string-only",
            "int_pops": 0,
            "string_pops": 1,
            "string_pushes": 0,
            "base_confidence": 0.46,
            "specificity_rank": 1,
            "notes": "Top-of-stack window repeatedly looks like a single-string sink, which fits a message, URL, or other string-only action.",
        },
    )

    catalog: dict[int, dict[str, object]] = {}
    selected_profile_count = 0
    ambiguous_profile_count = 0
    formatter_profile_count = 0
    widget_text_profile_count = 0
    string_action_profile_count = 0

    for raw_opcode, entry in sorted(frontier_candidates.items()):
        if not isinstance(entry, dict):
            continue
        script_samples = entry.get("script_samples")
        if not isinstance(script_samples, list) or not script_samples:
            continue

        arity_profiles: list[dict[str, object]] = []
        string_result_script_count = int(entry.get("string_result_script_count", 0))
        for spec in profile_specs:
            window_summary = _summarize_clientscript_consumed_operand_window(
                {
                    "script_samples": script_samples,
                    "stack_effect_candidate": {
                        "int_pops": int(spec["int_pops"]),
                        "string_pops": int(spec["string_pops"]),
                    },
                }
            )
            consumed_signature_sample = window_summary.get("consumed_operand_signature_sample")
            if not isinstance(consumed_signature_sample, list) or not consumed_signature_sample:
                continue

            consumed_window_count = int(window_summary.get("consumed_operand_window_count", 0))
            if consumed_window_count <= 0:
                continue

            match_count = sum(
                int(sample.get("count", 0))
                for sample in consumed_signature_sample
                if isinstance(sample, dict) and str(sample.get("signature", "")) == str(spec["signature"])
            )
            if match_count <= 0:
                continue

            match_ratio = match_count / max(consumed_window_count, 1)
            confidence = float(spec["base_confidence"])
            confidence += min(match_ratio, 1.0) * 0.18
            confidence += min(match_count, 4) * 0.03
            if int(spec["string_pushes"]) > 0 and string_result_script_count > 0:
                confidence += 0.04
            confidence = round(min(confidence, 0.86), 2)

            operand_signature_candidate: dict[str, object] = {
                "target_kind": str(spec["target_kind"]),
                "signature": str(spec["signature"]),
                "min_int_inputs": int(spec["int_pops"]),
                "min_string_inputs": int(spec["string_pops"]),
                "confidence": confidence,
                "notes": str(spec["notes"]),
            }
            if str(spec["signature"]).startswith("widget+"):
                secondary_operand_kind = str(spec["signature"]).split("+", 1)[1]
                operand_signature_candidate["secondary_operand_kind"] = secondary_operand_kind

            stack_effect_candidate = _make_clientscript_stack_effect(
                int_pops=int(spec["int_pops"]),
                string_pops=int(spec["string_pops"]),
                string_pushes=int(spec["string_pushes"]),
                confidence=confidence,
                notes=str(spec["notes"]),
            )

            arity_profile: dict[str, object] = {
                "candidate_mnemonic": str(spec["candidate_mnemonic"]),
                "family": str(spec["family"]),
                "signature": str(spec["signature"]),
                "int_pops": int(spec["int_pops"]),
                "string_pops": int(spec["string_pops"]),
                "string_pushes": int(spec["string_pushes"]),
                "eligible_sample_count": consumed_window_count,
                "match_count": match_count,
                "match_ratio": round(match_ratio, 2),
                "confidence": confidence,
                "notes": str(spec["notes"]),
                "operand_signature_candidate": operand_signature_candidate,
                "stack_effect_candidate": stack_effect_candidate,
                "consumed_operand_signature_sample": consumed_signature_sample[:4],
                "consumed_operand_samples": window_summary.get("consumed_operand_samples", [])[:4],
                "_specificity_rank": int(spec["specificity_rank"]),
            }
            consumed_secondary_int_kind_sample = window_summary.get("consumed_secondary_int_kind_sample")
            if isinstance(consumed_secondary_int_kind_sample, list) and consumed_secondary_int_kind_sample:
                arity_profile["consumed_secondary_int_kind_sample"] = consumed_secondary_int_kind_sample[:4]
            consumed_secondary_int_literal_sample = window_summary.get("consumed_secondary_int_literal_sample")
            if isinstance(consumed_secondary_int_literal_sample, list) and consumed_secondary_int_literal_sample:
                arity_profile["consumed_secondary_int_literal_sample"] = (
                    consumed_secondary_int_literal_sample[:4]
                )
            consumed_secondary_literal_boolean_ratio = window_summary.get(
                "consumed_secondary_literal_boolean_ratio"
            )
            if isinstance(consumed_secondary_literal_boolean_ratio, (int, float)):
                arity_profile["consumed_secondary_literal_boolean_ratio"] = float(
                    consumed_secondary_literal_boolean_ratio
                )
            arity_profiles.append(arity_profile)

        if not arity_profiles:
            continue

        arity_profiles.sort(
            key=lambda profile: (
                -float(profile.get("confidence", 0.0)),
                -int(profile.get("match_count", 0)),
                -float(profile.get("match_ratio", 0.0)),
                -int(profile.get("_specificity_rank", 0)),
                str(profile.get("signature", "")),
            )
        )
        for profile in arity_profiles:
            profile.pop("_specificity_rank", None)

        best_profile = dict(arity_profiles[0])
        runner_up = arity_profiles[1] if len(arity_profiles) > 1 else None
        candidate_arity_profile: dict[str, object] | None = None
        if (
            float(best_profile.get("confidence", 0.0)) >= 0.72
            and int(best_profile.get("match_count", 0)) >= 2
            and (
                runner_up is None
                or float(best_profile.get("confidence", 0.0)) - float(runner_up.get("confidence", 0.0)) >= 0.04
            )
        ):
            candidate_arity_profile = dict(best_profile)
            selected_profile_count += 1
            selected_mnemonic = str(candidate_arity_profile.get("candidate_mnemonic", ""))
            if selected_mnemonic == "STRING_FORMATTER_CANDIDATE":
                formatter_profile_count += 1
            elif selected_mnemonic == "WIDGET_TEXT_MUTATOR_CANDIDATE":
                widget_text_profile_count += 1
            elif selected_mnemonic == "STRING_ACTION_CANDIDATE":
                string_action_profile_count += 1
        elif len(arity_profiles) > 1:
            ambiguous_profile_count += 1

        profile_entry: dict[str, object] = {
            "raw_opcode": int(raw_opcode),
            "raw_opcode_hex": f"0x{int(raw_opcode):04X}",
            "script_count": int(entry.get("script_count", 0)),
            "string_result_script_count": string_result_script_count,
            "frontier_candidate_mnemonic": str(entry.get("candidate_mnemonic") or ""),
            "frontier_family": str(entry.get("family") or ""),
            "key_sample": entry.get("key_sample", [])[:8],
            "arity_profile_sample": arity_profiles[:5],
        }
        if candidate_arity_profile is not None:
            profile_entry["candidate_arity_profile"] = candidate_arity_profile
        catalog[int(raw_opcode)] = profile_entry

    summary = {
        "profiled_opcode_count": len(catalog),
        "selected_profile_count": selected_profile_count,
        "ambiguous_profile_count": ambiguous_profile_count,
        "formatter_profile_count": formatter_profile_count,
        "widget_text_profile_count": widget_text_profile_count,
        "string_action_profile_count": string_action_profile_count,
        "catalog_sample": sorted(
            catalog.values(),
            key=lambda entry: (
                -int("candidate_arity_profile" in entry),
                -int(entry.get("string_result_script_count", 0)),
                -int(entry.get("script_count", 0)),
                int(entry["raw_opcode"]),
            ),
        )[:24],
    }
    return catalog, summary


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
        payload["consumed_operand_window_count"] = sum(int(count) for count in signature_counts.values())
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
            if offset == len(layout.opcode_data) and _is_clientscript_terminal_step(steps[-1] if steps else None):
                return {
                    "status": "complete",
                    "decoded_instruction_count": decoded_instruction_count,
                    "remaining_opcode_bytes": 0,
                    "instruction_offsets": [int(step["offset"]) for step in steps],
                    "instruction_steps": steps,
                    "last_instruction": steps[-1] if steps else None,
                    "instruction_sample": steps[:32],
                }
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
        immediate_kind, resolved_catalog_entry, step_fields = _resolve_clientscript_catalog_dispatch(
            layout.opcode_data,
            offset,
            raw_opcode=raw_opcode,
            raw_opcode_types=raw_opcode_types,
            raw_opcode_catalog=raw_opcode_catalog,
            resolution_scope="frontier",
        )
        previous_step = steps[-1] if steps else None

        if immediate_kind is None:
            return {
                "status": "frontier",
                "frontier_reason": "unknown-locked-opcode",
                "frontier_offset": offset,
                "frontier_instruction_index": decoded_instruction_count,
                "frontier_raw_opcode": raw_opcode,
                "frontier_raw_opcode_hex": f"0x{raw_opcode:04X}",
                **step_fields,
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

        immediate = _read_clientscript_immediate(
            layout.opcode_data,
            offset + 2,
            immediate_kind,
            immediate_width=_resolve_clientscript_step_immediate_width(
                {
                    "offset": offset,
                    "raw_opcode": raw_opcode,
                    "immediate_kind": immediate_kind,
                    "catalog_entry_override": resolved_catalog_entry,
                    **step_fields,
                },
                immediate_kind=immediate_kind,
                opcode_data=layout.opcode_data,
                offset=offset,
                raw_opcode_types=raw_opcode_types,
                raw_opcode_catalog=raw_opcode_catalog,
            ),
        )
        if immediate is None:
            return {
                "status": "frontier",
                "frontier_reason": "invalid-locked-immediate",
                "frontier_offset": offset,
                "frontier_instruction_index": decoded_instruction_count,
                "frontier_raw_opcode": raw_opcode,
                "frontier_raw_opcode_hex": f"0x{raw_opcode:04X}",
                **step_fields,
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
            **step_fields,
            "immediate_kind": immediate_kind,
            "immediate_value": immediate.get("immediate_value"),
            "switch_subtype": immediate.get("switch_subtype"),
            "end_offset": int(immediate["end_offset"]),
            **(
                {"catalog_entry_override": resolved_catalog_entry}
                if isinstance(resolved_catalog_entry, dict)
                else {}
            ),
        }
        annotated_step = _apply_clientscript_semantic_hints(
            step,
            raw_opcode_catalog,
            resolution_scope="frontier",
        )
        annotated_step.pop("catalog_entry_override", None)
        steps.append(annotated_step)
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
    effective_raw_opcode_catalog = {
        int(raw_opcode): _merge_clientscript_catalog_entry_with_builtin_hint(int(raw_opcode), entry)
        for raw_opcode, entry in (raw_opcode_catalog or {}).items()
        if isinstance(entry, dict)
    }
    for raw_opcode, entry in CLIENTSCRIPT_BUILTIN_OPCODE_HINTS.items():
        effective_raw_opcode_catalog.setdefault(int(raw_opcode), dict(entry))
    possible_types: dict[int, set[str]] = {}
    if raw_opcode_types:
        possible_types.update(
            {
                int(raw_opcode): {str(immediate_kind)}
                for raw_opcode, immediate_kind in raw_opcode_types.items()
            }
        )
    if effective_raw_opcode_catalog:
        for raw_opcode, entry in effective_raw_opcode_catalog.items():
            if not isinstance(entry, dict):
                continue
            immediate_kind = entry.get("immediate_kind", entry.get("expected_immediate_kind"))
            if (
                isinstance(immediate_kind, str)
                and immediate_kind in CLIENTSCRIPT_SUPPORTED_IMMEDIATE_TYPES
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
    if (
        isinstance(selected_steps, list)
        and isinstance(selected_mapping, dict)
        and not _validate_clientscript_selected_steps_against_subtypes(
            layout,
            selected_steps,
            raw_opcode_catalog=effective_raw_opcode_catalog,
            resolution_scope="global",
        )
    ):
        selected_steps = None
        selected_mapping = None
        profile["disassembly_rejection_reason"] = "subtype-dispatch-mismatch"
    if selected_steps and selected_mapping:
        selected_mapping_catalog = {
            raw_opcode: entry
            for raw_opcode, entry in effective_raw_opcode_catalog.items()
            if _allows_clientscript_resolution_scope(entry, resolution_scope="global")
        }
        annotated_steps = [
            _apply_clientscript_semantic_hints(
                step,
                effective_raw_opcode_catalog,
                resolution_scope="global",
            )
            for step in selected_steps
        ]
        _populate_clientscript_disassembly_profile(
            profile,
            layout,
            annotated_steps,
            mode=mode,
            solution_count=int(disassembly["solution_count"]),
            bailed=bool(disassembly["bailed"]),
            parser_status=(
                "parsed"
                if disassembly["solution_count"] == 1 and not disassembly["bailed"]
                else "profiled"
            ),
            distinct_raw_opcode_count=len(selected_mapping),
            raw_opcode_types=selected_mapping,
            raw_opcode_catalog=selected_mapping_catalog,
        )
        profile["raw_opcode_types_sample"] = [
            {
                "raw_opcode": raw_opcode,
                "raw_opcode_hex": f"0x{raw_opcode:04X}",
                "immediate_kind": immediate_kind,
                **(
                    {
                        "semantic_label": selected_mapping_catalog[raw_opcode].get("mnemonic")
                        or selected_mapping_catalog[raw_opcode].get("candidate_mnemonic"),
                        "semantic_family": selected_mapping_catalog[raw_opcode].get("family"),
                        "stack_effect_candidate": selected_mapping_catalog[raw_opcode].get("stack_effect_candidate"),
                    }
                    if raw_opcode in selected_mapping_catalog
                    else {}
                ),
            }
            for raw_opcode, immediate_kind in sorted(selected_mapping.items())[:24]
        ]
    if not (selected_steps and selected_mapping) and raw_opcode_types:
        prefix_trace = _trace_clientscript_locked_prefix(
            layout,
            raw_opcode_types,
            raw_opcode_catalog=effective_raw_opcode_catalog,
        )
        if prefix_trace is not None:
            trace_status = prefix_trace.get("status")
            if isinstance(trace_status, str) and trace_status:
                profile["tail_trace_status"] = trace_status
            profile["tail_instruction_count"] = int(prefix_trace.get("decoded_instruction_count", 0))
            profile["tail_remaining_opcode_bytes"] = int(prefix_trace.get("remaining_opcode_bytes", 0))
            consumed_offset = _measure_clientscript_trace_consumed_offset(layout, prefix_trace)
            tail_next_instruction = _peek_clientscript_next_opcode_instruction(
                layout,
                consumed_offset,
                raw_opcode_types=raw_opcode_types,
                raw_opcode_catalog=effective_raw_opcode_catalog,
            )
            if isinstance(tail_next_instruction, dict):
                profile["tail_next_instruction"] = _sample_clientscript_instruction_step(tail_next_instruction)
                tail_next_raw_opcode = tail_next_instruction.get("raw_opcode")
                if isinstance(tail_next_raw_opcode, int):
                    profile["tail_next_raw_opcode"] = tail_next_raw_opcode
                    profile["tail_next_raw_opcode_hex"] = str(
                        tail_next_instruction.get("raw_opcode_hex", f"0x{tail_next_raw_opcode:04X}")
                    )
            if trace_status == "extra-bytes":
                tail_continuation = _trace_clientscript_tail_continuation(
                    layout,
                    consumed_offset,
                    raw_opcode_types=raw_opcode_types,
                    raw_opcode_catalog=effective_raw_opcode_catalog,
                )
                if isinstance(tail_continuation, dict) and tail_continuation:
                    profile["tail_continuation"] = tail_continuation
                    instruction_budget_desync = _build_clientscript_instruction_budget_desync(
                        layout,
                        prefix_trace,
                        tail_continuation,
                    )
                    if isinstance(instruction_budget_desync, dict) and instruction_budget_desync:
                        profile["instruction_budget_desync"] = instruction_budget_desync
                    recovery = _recover_clientscript_budget_relaxed_trace(
                        layout,
                        prefix_trace,
                        tail_continuation,
                    )
                    if isinstance(recovery, dict) and recovery:
                        recovered_steps = recovery.get("instruction_steps")
                        if isinstance(recovered_steps, list) and recovered_steps:
                            _populate_clientscript_disassembly_profile(
                                profile,
                                layout,
                                [dict(step) for step in recovered_steps if isinstance(step, dict)],
                                mode=f"{mode}-budget-relaxed",
                                solution_count=int(disassembly["solution_count"]),
                                bailed=bool(disassembly["bailed"]),
                                parser_status="recovered",
                                tail_trace_status="budget-relaxed",
                                recovery={
                                    field: value
                                    for field, value in recovery.items()
                                    if field != "instruction_steps"
                                },
                                raw_opcode_types=raw_opcode_types,
                                raw_opcode_catalog=effective_raw_opcode_catalog,
                            )
            elif trace_status == "complete":
                instruction_steps = prefix_trace.get("instruction_steps")
                if isinstance(instruction_steps, list) and instruction_steps:
                    _populate_clientscript_disassembly_profile(
                        profile,
                        layout,
                        [dict(step) for step in instruction_steps if isinstance(step, dict)],
                        mode=f"{mode}-locked-prefix",
                        solution_count=int(disassembly["solution_count"]),
                        bailed=bool(disassembly["bailed"]),
                        parser_status="parsed",
                        tail_trace_status="complete",
                        raw_opcode_types=raw_opcode_types,
                        raw_opcode_catalog=effective_raw_opcode_catalog,
                    )
            if profile.get("kind") != "clientscript-disassembly":
                instruction_steps = prefix_trace.get("instruction_steps")
                if isinstance(instruction_steps, list) and instruction_steps:
                    profile["tail_last_instruction"] = _sample_clientscript_instruction_step(instruction_steps[-1])
                    profile["tail_instruction_sample"] = _build_clientscript_late_instruction_sample(
                        instruction_steps,
                        max_steps=8,
                    )
                    profile["late_instruction_sample"] = _build_clientscript_late_instruction_sample(
                        instruction_steps,
                        max_steps=16,
                    )
                    tail_stack_summary = _summarize_clientscript_prefix_stack_state(instruction_steps)
                    if tail_stack_summary:
                        profile["tail_stack_summary"] = tail_stack_summary
                    branch_state_probe = _build_clientscript_branch_state_probe(
                        layout,
                        instruction_steps,
                        raw_opcode_types=raw_opcode_types,
                        raw_opcode_catalog=effective_raw_opcode_catalog,
                    )
                    if isinstance(branch_state_probe, dict) and branch_state_probe:
                        profile["branch_state_probe"] = branch_state_probe
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
                effective_raw_opcode_catalog.get(frontier_opcode)
                if isinstance(frontier_opcode, int) and effective_raw_opcode_catalog is not None
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


def _build_clientscript_pseudocode_profile_status(
    semantic_profile: dict[str, object],
    *,
    archive_key: int,
    file_id: int,
) -> dict[str, object] | None:
    kind = str(semantic_profile.get("kind", ""))
    if not kind.startswith("clientscript"):
        return None

    entry: dict[str, object] = {
        "archive_key": int(archive_key),
        "file_id": int(file_id),
        "kind": kind,
        "parser_status": str(semantic_profile.get("parser_status", "")),
        "disassembly_mode": str(semantic_profile.get("disassembly_mode", "")),
        "disassembly_solution_count": int(semantic_profile.get("disassembly_solution_count", 0)),
        "disassembly_bailed": bool(semantic_profile.get("disassembly_bailed", False)),
    }

    pseudocode_text_path = semantic_profile.get("pseudocode_text_path")
    if isinstance(pseudocode_text_path, str) and pseudocode_text_path:
        entry["status"] = "ready"
        entry["pseudocode_text_path"] = pseudocode_text_path
    elif isinstance(semantic_profile.get("_pseudocode_text"), str) and str(semantic_profile.get("_pseudocode_text")):
        entry["status"] = "ready"
    else:
        entry["status"] = "blocked"
    frontier_reason = semantic_profile.get("frontier_reason")
    if isinstance(frontier_reason, str) and frontier_reason:
        entry["frontier_reason"] = frontier_reason
    frontier_offset = semantic_profile.get("frontier_offset")
    if isinstance(frontier_offset, int):
        entry["frontier_offset"] = frontier_offset
    frontier_instruction_index = semantic_profile.get("frontier_instruction_index")
    if isinstance(frontier_instruction_index, int):
        entry["frontier_instruction_index"] = frontier_instruction_index
    frontier_raw_opcode = semantic_profile.get("frontier_raw_opcode")
    if isinstance(frontier_raw_opcode, int):
        entry["frontier_raw_opcode"] = frontier_raw_opcode
        entry["frontier_raw_opcode_hex"] = str(
            semantic_profile.get("frontier_raw_opcode_hex", f"0x{frontier_raw_opcode:04X}")
        )
    frontier_candidate_label = semantic_profile.get("frontier_candidate_label")
    if isinstance(frontier_candidate_label, str) and frontier_candidate_label:
        entry["frontier_candidate_label"] = frontier_candidate_label
    frontier_candidate_family = semantic_profile.get("frontier_candidate_family")
    if isinstance(frontier_candidate_family, str) and frontier_candidate_family:
        entry["frontier_candidate_family"] = frontier_candidate_family
    frontier_candidate_confidence = semantic_profile.get("frontier_candidate_confidence")
    if isinstance(frontier_candidate_confidence, (int, float)):
        entry["frontier_candidate_confidence"] = float(frontier_candidate_confidence)
    frontier_candidate_operand_signature = semantic_profile.get("frontier_candidate_operand_signature")
    if isinstance(frontier_candidate_operand_signature, dict) and frontier_candidate_operand_signature:
        entry["frontier_candidate_operand_signature"] = dict(frontier_candidate_operand_signature)
    frontier_candidate_stack_effect = semantic_profile.get("frontier_candidate_stack_effect")
    if isinstance(frontier_candidate_stack_effect, dict) and frontier_candidate_stack_effect:
        entry["frontier_candidate_stack_effect"] = dict(frontier_candidate_stack_effect)
    frontier_previous_raw_opcode = semantic_profile.get("frontier_previous_raw_opcode")
    if isinstance(frontier_previous_raw_opcode, int):
        entry["frontier_previous_raw_opcode"] = frontier_previous_raw_opcode
        entry["frontier_previous_raw_opcode_hex"] = str(
            semantic_profile.get("frontier_previous_raw_opcode_hex", f"0x{frontier_previous_raw_opcode:04X}")
        )
    tail_trace_status = semantic_profile.get("tail_trace_status")
    if isinstance(tail_trace_status, str) and tail_trace_status:
        entry["tail_trace_status"] = tail_trace_status
    tail_instruction_count = semantic_profile.get("tail_instruction_count")
    if isinstance(tail_instruction_count, int):
        entry["tail_instruction_count"] = tail_instruction_count
    tail_remaining_opcode_bytes = semantic_profile.get("tail_remaining_opcode_bytes")
    if isinstance(tail_remaining_opcode_bytes, int):
        entry["tail_remaining_opcode_bytes"] = tail_remaining_opcode_bytes
    tail_last_instruction = semantic_profile.get("tail_last_instruction")
    if isinstance(tail_last_instruction, dict) and tail_last_instruction:
        entry["tail_last_instruction"] = dict(tail_last_instruction)
    tail_next_instruction = semantic_profile.get("tail_next_instruction")
    if isinstance(tail_next_instruction, dict) and tail_next_instruction:
        entry["tail_next_instruction"] = dict(tail_next_instruction)
        tail_next_raw_opcode = tail_next_instruction.get("raw_opcode")
        if isinstance(tail_next_raw_opcode, int):
            entry["tail_next_raw_opcode"] = tail_next_raw_opcode
            entry["tail_next_raw_opcode_hex"] = str(
                tail_next_instruction.get("raw_opcode_hex", f"0x{tail_next_raw_opcode:04X}")
            )
    tail_continuation = semantic_profile.get("tail_continuation")
    if isinstance(tail_continuation, dict) and tail_continuation:
        entry["tail_continuation"] = copy.deepcopy(tail_continuation)
    instruction_budget_relaxed = semantic_profile.get("instruction_budget_relaxed")
    if isinstance(instruction_budget_relaxed, dict) and instruction_budget_relaxed:
        entry["instruction_budget_relaxed"] = copy.deepcopy(instruction_budget_relaxed)
    instruction_budget_desync = semantic_profile.get("instruction_budget_desync")
    if isinstance(instruction_budget_desync, dict) and instruction_budget_desync:
        entry["instruction_budget_desync"] = copy.deepcopy(instruction_budget_desync)
        instruction_budget_gap = instruction_budget_desync.get("instruction_budget_gap")
        if isinstance(instruction_budget_gap, int):
            entry["instruction_budget_gap"] = instruction_budget_gap
        top_suspect_instruction = instruction_budget_desync.get("top_suspect_instruction")
        if isinstance(top_suspect_instruction, dict) and top_suspect_instruction:
            entry["instruction_budget_top_suspect_instruction"] = dict(top_suspect_instruction)
            top_suspect_raw_opcode = top_suspect_instruction.get("raw_opcode")
            if isinstance(top_suspect_raw_opcode, int):
                entry["instruction_budget_top_suspect_raw_opcode"] = top_suspect_raw_opcode
                entry["instruction_budget_top_suspect_raw_opcode_hex"] = str(
                    top_suspect_instruction.get("raw_opcode_hex", f"0x{top_suspect_raw_opcode:04X}")
                )
            top_suspect_semantic_label = top_suspect_instruction.get("semantic_label")
            if isinstance(top_suspect_semantic_label, str) and top_suspect_semantic_label:
                entry["instruction_budget_top_suspect_semantic_label"] = top_suspect_semantic_label
    late_instruction_sample = semantic_profile.get("late_instruction_sample")
    if isinstance(late_instruction_sample, list) and late_instruction_sample:
        normalized_late_instruction_sample = [
            dict(step)
            for step in late_instruction_sample[:16]
            if isinstance(step, dict)
        ]
        if normalized_late_instruction_sample:
            entry["late_instruction_sample"] = normalized_late_instruction_sample
    tail_instruction_sample = semantic_profile.get("tail_instruction_sample")
    if isinstance(tail_instruction_sample, list) and tail_instruction_sample:
        normalized_tail_instruction_sample = [
            dict(step)
            for step in tail_instruction_sample[:8]
            if isinstance(step, dict)
        ]
        if normalized_tail_instruction_sample:
            entry["tail_instruction_sample"] = normalized_tail_instruction_sample
            tail_hint_instruction = _find_clientscript_tail_hint_instruction(normalized_tail_instruction_sample)
            if isinstance(tail_hint_instruction, dict):
                entry["tail_hint_instruction"] = dict(tail_hint_instruction)
                tail_hint_raw_opcode = tail_hint_instruction.get("raw_opcode")
                if isinstance(tail_hint_raw_opcode, int):
                    entry["tail_hint_raw_opcode"] = tail_hint_raw_opcode
                    entry["tail_hint_raw_opcode_hex"] = str(
                        tail_hint_instruction.get("raw_opcode_hex", f"0x{tail_hint_raw_opcode:04X}")
                    )
                tail_hint_semantic_label = tail_hint_instruction.get("semantic_label")
                if isinstance(tail_hint_semantic_label, str) and tail_hint_semantic_label:
                    entry["tail_hint_semantic_label"] = tail_hint_semantic_label
    tail_stack_summary = semantic_profile.get("tail_stack_summary")
    if isinstance(tail_stack_summary, dict) and tail_stack_summary:
        entry["tail_stack_summary"] = dict(tail_stack_summary)
        tail_operand_signature = tail_stack_summary.get("prefix_operand_signature")
        if isinstance(tail_operand_signature, str) and tail_operand_signature:
            entry["tail_operand_signature"] = tail_operand_signature
    tail_stack_tracking = semantic_profile.get("tail_stack_tracking")
    if isinstance(tail_stack_tracking, dict) and tail_stack_tracking:
        entry["tail_stack_tracking"] = {
            field: copy.deepcopy(tail_stack_tracking[field])
            for field in ("minimum_required_inputs", "final_depths", "final_expression_stacks")
            if field in tail_stack_tracking
        }
    if entry["status"] == "ready":
        return entry
    entry["blocking_kind"] = (
        "opcode-frontier"
        if isinstance(frontier_raw_opcode, int)
        else "frontier-reason"
        if isinstance(frontier_reason, str) and frontier_reason
        else "tail-extra-bytes"
        if tail_trace_status == "extra-bytes"
        else "tail-complete"
        if tail_trace_status == "complete"
        else "incomplete-disassembly"
    )
    return entry


def _normalize_clientscript_step_match_value(value: object) -> object:
    if isinstance(value, (int, float, str, bool)):
        return value
    if isinstance(value, dict):
        hex_value = value.get("hex")
        if isinstance(hex_value, str) and hex_value:
            return hex_value
    return None


def _clientscript_step_match_signature(step: dict[str, object]) -> tuple[object, ...]:
    immediate_value = _normalize_clientscript_step_match_value(step.get("immediate_value"))
    return (
        str(step.get("raw_opcode_hex", "")),
        str(step.get("immediate_kind", "")),
        str(step.get("semantic_label", "")),
        immediate_value,
    )


def _collect_clientscript_late_trace(
    entry: dict[str, object],
    *,
    max_steps: int = 24,
) -> list[dict[str, object]]:
    late_trace: list[dict[str, object]] = []

    base_sample = entry.get("late_instruction_sample")
    if not isinstance(base_sample, list) or not base_sample:
        base_sample = entry.get("tail_instruction_sample")
    if isinstance(base_sample, list):
        late_trace.extend(dict(step) for step in base_sample if isinstance(step, dict))

    tail_continuation = entry.get("tail_continuation")
    if isinstance(tail_continuation, dict):
        continuation_sample = tail_continuation.get("instruction_sample")
        existing_offsets = {
            int(step["offset"])
            for step in late_trace
            if isinstance(step.get("offset"), int)
        }
        if isinstance(continuation_sample, list):
            for step in continuation_sample:
                if not isinstance(step, dict):
                    continue
                offset = step.get("offset")
                if isinstance(offset, int) and offset in existing_offsets:
                    continue
                late_trace.append(dict(step))
                if isinstance(offset, int):
                    existing_offsets.add(offset)

    if all(isinstance(step.get("offset"), int) for step in late_trace):
        late_trace.sort(key=lambda step: int(step["offset"]))
    if len(late_trace) > max_steps:
        late_trace = late_trace[-max_steps:]
    return late_trace


def _compare_clientscript_late_traces(
    blocked_trace: list[dict[str, object]],
    ready_trace: list[dict[str, object]],
) -> dict[str, object] | None:
    if not blocked_trace or not ready_trace:
        return None

    blocked_signatures = [_clientscript_step_match_signature(step) for step in blocked_trace]
    ready_signatures = [_clientscript_step_match_signature(step) for step in ready_trace]
    max_common_suffix = min(len(blocked_signatures), len(ready_signatures))
    common_suffix_instruction_count = 0
    while common_suffix_instruction_count < max_common_suffix:
        if (
            blocked_signatures[-(common_suffix_instruction_count + 1)]
            != ready_signatures[-(common_suffix_instruction_count + 1)]
        ):
            break
        common_suffix_instruction_count += 1

    if common_suffix_instruction_count < 4:
        return None

    blocked_extra_prefix = (
        blocked_trace[:-common_suffix_instruction_count]
        if common_suffix_instruction_count < len(blocked_trace)
        else []
    )
    ready_extra_prefix = (
        ready_trace[:-common_suffix_instruction_count]
        if common_suffix_instruction_count < len(ready_trace)
        else []
    )
    blocked_divergence_index = len(blocked_trace) - common_suffix_instruction_count - 1
    ready_divergence_index = len(ready_trace) - common_suffix_instruction_count - 1
    blocked_divergence_instruction = (
        copy.deepcopy(blocked_trace[blocked_divergence_index])
        if blocked_divergence_index >= 0
        else None
    )
    ready_divergence_instruction = (
        copy.deepcopy(ready_trace[ready_divergence_index])
        if ready_divergence_index >= 0
        else None
    )

    if blocked_divergence_instruction and ready_divergence_instruction:
        divergence_kind = "opcode-mismatch"
    elif blocked_divergence_instruction:
        divergence_kind = "blocked-extra-prefix"
    elif ready_divergence_instruction:
        divergence_kind = "control-extra-prefix"
    else:
        divergence_kind = "shared-tail-only"

    blocked_extra_prefix_count = max(len(blocked_trace) - common_suffix_instruction_count, 0)
    ready_extra_prefix_count = max(len(ready_trace) - common_suffix_instruction_count, 0)
    return {
        "common_suffix_instruction_count": common_suffix_instruction_count,
        "blocked_late_trace_count": len(blocked_trace),
        "control_late_trace_count": len(ready_trace),
        "blocked_extra_prefix_count": blocked_extra_prefix_count,
        "control_extra_prefix_count": ready_extra_prefix_count,
        "divergence_kind": divergence_kind,
        "blocked_divergence_instruction": blocked_divergence_instruction,
        "control_divergence_instruction": ready_divergence_instruction,
        "common_suffix_sample": copy.deepcopy(blocked_trace[-min(common_suffix_instruction_count, 8) :]),
        "blocked_extra_prefix_sample": copy.deepcopy(blocked_extra_prefix[-8:]),
        "control_extra_prefix_sample": copy.deepcopy(ready_extra_prefix[-8:]),
        "blocked_late_trace_sample": copy.deepcopy(blocked_trace[-12:]),
        "control_late_trace_sample": copy.deepcopy(ready_trace[-12:]),
    }


def _build_clientscript_control_group_diff(
    blocked_entry: dict[str, object],
    ready_entries: list[dict[str, object]],
) -> dict[str, object] | None:
    blocked_trace = _collect_clientscript_late_trace(blocked_entry)
    if not blocked_trace:
        return None

    blocked_operand_signature = str(blocked_entry.get("tail_operand_signature", "") or "")
    best_candidate: tuple[tuple[int, int, int], dict[str, object], dict[str, object]] | None = None

    for ready_entry in ready_entries:
        if not isinstance(ready_entry, dict):
            continue
        ready_trace = _collect_clientscript_late_trace(ready_entry)
        comparison = _compare_clientscript_late_traces(blocked_trace, ready_trace)
        if comparison is None:
            continue

        ready_operand_signature = str(ready_entry.get("tail_operand_signature", "") or "")
        score = (
            int(comparison["common_suffix_instruction_count"]),
            1 if blocked_operand_signature and blocked_operand_signature == ready_operand_signature else 0,
            -int(comparison["control_extra_prefix_count"]),
        )
        if best_candidate is None or score > best_candidate[0]:
            best_candidate = (score, ready_entry, comparison)

    if best_candidate is None:
        return None

    _, ready_entry, comparison = best_candidate
    control_archive_key = int(ready_entry.get("archive_key", 0))
    control_file_id = int(ready_entry.get("file_id", 0))
    blocked_extra_prefix_count = int(comparison["blocked_extra_prefix_count"])
    control_extra_prefix_count = int(comparison["control_extra_prefix_count"])
    shared_suffix_instruction_count = int(comparison["common_suffix_instruction_count"])
    blocked_extra_prefix = (
        blocked_trace[:-shared_suffix_instruction_count]
        if shared_suffix_instruction_count < len(blocked_trace)
        else []
    )
    blocked_shared_suffix = (
        blocked_trace[-shared_suffix_instruction_count:]
        if shared_suffix_instruction_count > 0
        else []
    )
    ready_shared_suffix = (
        _collect_clientscript_late_trace(ready_entry)[-shared_suffix_instruction_count:]
        if shared_suffix_instruction_count > 0
        else []
    )
    top_suspect_instruction = None
    instruction_budget_desync = blocked_entry.get("instruction_budget_desync")
    if isinstance(instruction_budget_desync, dict):
        candidate = instruction_budget_desync.get("top_suspect_instruction")
        if isinstance(candidate, dict):
            top_suspect_instruction = candidate
    top_suspect_signature = (
        _clientscript_step_match_signature(top_suspect_instruction)
        if isinstance(top_suspect_instruction, dict)
        else None
    )
    top_suspect_exonerated_by_control = bool(
        top_suspect_signature
        and any(
            _clientscript_step_match_signature(step) == top_suspect_signature
            for step in blocked_shared_suffix
        )
        and any(
            _clientscript_step_match_signature(step) == top_suspect_signature
            for step in ready_shared_suffix
        )
    )
    blocked_prefix_candidates: list[tuple[int, int, dict[str, object]]] = []
    blocked_prefix_total = len(blocked_extra_prefix)
    for index, step in enumerate(blocked_extra_prefix):
        if not isinstance(step, dict):
            continue
        semantic_label = str(step.get("semantic_label", "") or "")
        semantic_family = str(step.get("semantic_family", "") or "")
        immediate_kind = str(step.get("immediate_kind", "") or "")
        distance_from_shared_suffix = blocked_prefix_total - index
        candidate_score = 0
        if semantic_label.endswith("FRONTIER_CANDIDATE"):
            candidate_score += 8
        if semantic_family == "control-flow":
            candidate_score += 6
        if immediate_kind in {"string", "short", "switch", "tribyte"}:
            candidate_score += 3
        if not semantic_label:
            candidate_score += 2
        if semantic_family in {"string-transform-action", "stack-constant"}:
            candidate_score += 1
        candidate_score += max(0, 6 - distance_from_shared_suffix)
        blocked_prefix_candidates.append((candidate_score, -distance_from_shared_suffix, dict(step)))

    blocked_prefix_candidates.sort(key=lambda item: (item[0], item[1]), reverse=True)
    blocked_prefix_candidate_sample = [
        dict(step) for _, _, step in blocked_prefix_candidates[:5]
    ]
    blocked_leak_candidate = (
        copy.deepcopy(blocked_prefix_candidates[0][2]) if blocked_prefix_candidates else None
    )

    notes = (
        f"Matched solved control key {control_archive_key} with a shared {shared_suffix_instruction_count}-instruction tail."
    )
    if blocked_extra_prefix_count > control_extra_prefix_count:
        notes += (
            f" The blocked script carries {blocked_extra_prefix_count - control_extra_prefix_count} extra late-trace instructions before that shared suffix."
        )
    elif control_extra_prefix_count > blocked_extra_prefix_count:
        notes += (
            f" The solved control carries {control_extra_prefix_count - blocked_extra_prefix_count} additional prefix instructions before the shared tail."
        )
    if top_suspect_exonerated_by_control:
        notes += " The current top instruction-budget suspect also appears inside the shared solved suffix, so the real leak likely sits earlier in the blocked-only prefix."
    if isinstance(blocked_leak_candidate, dict):
        raw_opcode_hex = blocked_leak_candidate.get("raw_opcode_hex")
        if isinstance(raw_opcode_hex, str) and raw_opcode_hex:
            notes += f" Best blocked-only leak candidate: {raw_opcode_hex}."

    return {
        "control_archive_key": control_archive_key,
        "control_file_id": control_file_id,
        "control_pseudocode_text_path": ready_entry.get("pseudocode_text_path"),
        "blocked_operand_signature": blocked_operand_signature or None,
        "control_operand_signature": ready_entry.get("tail_operand_signature"),
        "top_suspect_exonerated_by_control": top_suspect_exonerated_by_control,
        "top_suspect_shared_suffix_instruction": copy.deepcopy(top_suspect_instruction)
        if top_suspect_exonerated_by_control
        else None,
        "blocked_leak_candidate": blocked_leak_candidate,
        "blocked_prefix_candidate_sample": blocked_prefix_candidate_sample,
        "notes": notes,
        **comparison,
    }


def _summarize_clientscript_pseudocode_blockers(
    profile_statuses: list[dict[str, object]],
) -> dict[str, object]:
    ready_entries = [
        entry
        for entry in profile_statuses
        if isinstance(entry, dict) and str(entry.get("status", "")) == "ready"
    ]
    ready_count = 0
    blocked_count = 0
    ready_key_sample: list[int] = []
    blocked_key_sample: list[int] = []
    control_group_diff_count = 0
    control_group_ready_key_sample: list[int] = []
    blocking_kind_counts: dict[str, int] = {}
    frontier_reason_counts: dict[str, int] = {}
    tail_status_counts: dict[str, int] = {}
    blocker_catalog: dict[int, dict[str, object]] = {}
    tail_last_opcode_catalog: dict[int, dict[str, object]] = {}
    tail_next_opcode_catalog: dict[int, dict[str, object]] = {}
    tail_hint_opcode_catalog: dict[int, dict[str, object]] = {}
    instruction_budget_top_suspect_catalog: dict[int, dict[str, object]] = {}
    control_group_leak_candidate_catalog: dict[int, dict[str, object]] = {}
    blocked_profile_sample: list[dict[str, object]] = []
    instruction_budget_desync_count = 0

    for entry in profile_statuses:
        if not isinstance(entry, dict):
            continue
        archive_key = int(entry.get("archive_key", 0))
        status = str(entry.get("status", ""))
        if status == "ready":
            ready_count += 1
            _append_int_sample(ready_key_sample, archive_key)
            continue

        blocked_count += 1
        _append_int_sample(blocked_key_sample, archive_key)
        blocking_kind = str(entry.get("blocking_kind", "") or "unspecified")
        blocking_kind_counts[blocking_kind] = int(blocking_kind_counts.get(blocking_kind, 0)) + 1
        tail_trace_status = str(entry.get("tail_trace_status", "") or "")
        if tail_trace_status:
            tail_status_counts[tail_trace_status] = int(tail_status_counts.get(tail_trace_status, 0)) + 1
        control_group_diff = _build_clientscript_control_group_diff(entry, ready_entries)
        if isinstance(control_group_diff, dict) and control_group_diff:
            control_group_diff_count += 1
            control_archive_key = control_group_diff.get("control_archive_key")
            if isinstance(control_archive_key, int):
                _append_int_sample(control_group_ready_key_sample, control_archive_key)
            blocked_leak_candidate = control_group_diff.get("blocked_leak_candidate")
            if isinstance(blocked_leak_candidate, dict):
                leak_raw_opcode = blocked_leak_candidate.get("raw_opcode")
                if isinstance(leak_raw_opcode, int):
                    leak_catalog_entry = control_group_leak_candidate_catalog.setdefault(
                        leak_raw_opcode,
                        {
                            "raw_opcode": int(leak_raw_opcode),
                            "raw_opcode_hex": str(
                                blocked_leak_candidate.get("raw_opcode_hex", f"0x{leak_raw_opcode:04X}")
                            ),
                            "blocked_profile_count": 0,
                            "key_sample": [],
                            "control_key_sample": [],
                            "tail_status_sample": [],
                        },
                    )
                    leak_catalog_entry["blocked_profile_count"] = int(
                        leak_catalog_entry.get("blocked_profile_count", 0)
                    ) + 1
                    _append_int_sample(leak_catalog_entry["key_sample"], archive_key)
                    if isinstance(control_archive_key, int):
                        _append_int_sample(leak_catalog_entry["control_key_sample"], control_archive_key)
                    tail_status_sample = leak_catalog_entry.get("tail_status_sample")
                    if (
                        isinstance(tail_status_sample, list)
                        and tail_trace_status
                        and tail_trace_status not in tail_status_sample
                        and len(tail_status_sample) < 4
                    ):
                        tail_status_sample.append(tail_trace_status)
                    for field in ("semantic_label", "semantic_family", "immediate_kind"):
                        value = blocked_leak_candidate.get(field)
                        if isinstance(value, str) and value and field not in leak_catalog_entry:
                            leak_catalog_entry[field] = value
        if len(blocked_profile_sample) < 16:
            sample_entry = {
                "archive_key": archive_key,
                "file_id": int(entry.get("file_id", 0)),
                "blocking_kind": blocking_kind,
            }
            for field in (
                "frontier_reason",
                "frontier_raw_opcode_hex",
                "frontier_candidate_label",
                "frontier_candidate_family",
                "tail_trace_status",
                "tail_operand_signature",
                "tail_next_raw_opcode_hex",
                "tail_hint_raw_opcode_hex",
                "tail_hint_semantic_label",
                "instruction_budget_top_suspect_raw_opcode_hex",
                "instruction_budget_top_suspect_semantic_label",
            ):
                value = entry.get(field)
                if isinstance(value, str) and value:
                    sample_entry[field] = value
            for field in (
                "frontier_offset",
                "tail_instruction_count",
                "tail_remaining_opcode_bytes",
                "instruction_budget_gap",
            ):
                value = entry.get(field)
                if isinstance(value, int):
                    sample_entry[field] = value
            tail_last_instruction = entry.get("tail_last_instruction")
            if isinstance(tail_last_instruction, dict) and tail_last_instruction:
                sample_entry["tail_last_instruction"] = dict(tail_last_instruction)
            tail_next_instruction = entry.get("tail_next_instruction")
            if isinstance(tail_next_instruction, dict) and tail_next_instruction:
                sample_entry["tail_next_instruction"] = dict(tail_next_instruction)
                if "tail_next_raw_opcode_hex" not in sample_entry:
                    tail_next_raw_opcode_hex = tail_next_instruction.get("raw_opcode_hex")
                    if isinstance(tail_next_raw_opcode_hex, str) and tail_next_raw_opcode_hex:
                        sample_entry["tail_next_raw_opcode_hex"] = tail_next_raw_opcode_hex
            tail_continuation = entry.get("tail_continuation")
            if isinstance(tail_continuation, dict) and tail_continuation:
                sample_entry["tail_continuation"] = copy.deepcopy(tail_continuation)
            instruction_budget_desync = entry.get("instruction_budget_desync")
            if isinstance(instruction_budget_desync, dict) and instruction_budget_desync:
                sample_entry["instruction_budget_desync"] = copy.deepcopy(instruction_budget_desync)
            if isinstance(control_group_diff, dict) and control_group_diff:
                sample_entry["control_group_diff"] = copy.deepcopy(control_group_diff)
            blocked_profile_sample.append(sample_entry)

        frontier_reason = str(entry.get("frontier_reason", "") or "unspecified")
        frontier_reason_counts[frontier_reason] = int(frontier_reason_counts.get(frontier_reason, 0)) + 1
        tail_last_instruction = entry.get("tail_last_instruction")
        if isinstance(tail_last_instruction, dict):
            tail_raw_opcode = tail_last_instruction.get("raw_opcode")
            if isinstance(tail_raw_opcode, int):
                tail_catalog_entry = tail_last_opcode_catalog.setdefault(
                    tail_raw_opcode,
                    {
                        "raw_opcode": int(tail_raw_opcode),
                        "raw_opcode_hex": str(
                            tail_last_instruction.get("raw_opcode_hex", f"0x{tail_raw_opcode:04X}")
                        ),
                        "blocked_profile_count": 0,
                        "key_sample": [],
                        "tail_status_sample": [],
                        "operand_signature_sample": [],
                    },
                )
                tail_catalog_entry["blocked_profile_count"] = int(tail_catalog_entry.get("blocked_profile_count", 0)) + 1
                _append_int_sample(tail_catalog_entry["key_sample"], archive_key)
                tail_status_sample = tail_catalog_entry.get("tail_status_sample")
                if (
                    isinstance(tail_status_sample, list)
                    and tail_trace_status
                    and tail_trace_status not in tail_status_sample
                    and len(tail_status_sample) < 4
                ):
                    tail_status_sample.append(tail_trace_status)
                tail_operand_signature = entry.get("tail_operand_signature")
                operand_signature_sample = tail_catalog_entry.get("operand_signature_sample")
                if (
                    isinstance(operand_signature_sample, list)
                    and isinstance(tail_operand_signature, str)
                    and tail_operand_signature
                    and tail_operand_signature not in operand_signature_sample
                    and len(operand_signature_sample) < 4
                ):
                    operand_signature_sample.append(tail_operand_signature)
                for field in ("semantic_label", "semantic_family", "immediate_kind"):
                    value = tail_last_instruction.get(field)
                    if isinstance(value, str) and value and field not in tail_catalog_entry:
                        tail_catalog_entry[field] = value
        tail_next_instruction = entry.get("tail_next_instruction")
        if isinstance(tail_next_instruction, dict):
            tail_next_raw_opcode = tail_next_instruction.get("raw_opcode")
            if isinstance(tail_next_raw_opcode, int):
                tail_next_catalog_entry = tail_next_opcode_catalog.setdefault(
                    tail_next_raw_opcode,
                    {
                        "raw_opcode": int(tail_next_raw_opcode),
                        "raw_opcode_hex": str(
                            tail_next_instruction.get("raw_opcode_hex", f"0x{tail_next_raw_opcode:04X}")
                        ),
                        "blocked_profile_count": 0,
                        "key_sample": [],
                        "tail_status_sample": [],
                        "operand_signature_sample": [],
                    },
                )
                tail_next_catalog_entry["blocked_profile_count"] = int(
                    tail_next_catalog_entry.get("blocked_profile_count", 0)
                ) + 1
                _append_int_sample(tail_next_catalog_entry["key_sample"], archive_key)
                tail_status_sample = tail_next_catalog_entry.get("tail_status_sample")
                if (
                    isinstance(tail_status_sample, list)
                    and tail_trace_status
                    and tail_trace_status not in tail_status_sample
                    and len(tail_status_sample) < 4
                ):
                    tail_status_sample.append(tail_trace_status)
                tail_operand_signature = entry.get("tail_operand_signature")
                operand_signature_sample = tail_next_catalog_entry.get("operand_signature_sample")
                if (
                    isinstance(operand_signature_sample, list)
                    and isinstance(tail_operand_signature, str)
                    and tail_operand_signature
                    and tail_operand_signature not in operand_signature_sample
                    and len(operand_signature_sample) < 4
                ):
                    operand_signature_sample.append(tail_operand_signature)
                for field in ("semantic_label", "semantic_family", "immediate_kind"):
                    value = tail_next_instruction.get(field)
                    if isinstance(value, str) and value and field not in tail_next_catalog_entry:
                        tail_next_catalog_entry[field] = value
        tail_hint_instruction = entry.get("tail_hint_instruction")
        if isinstance(tail_hint_instruction, dict):
            tail_hint_raw_opcode = tail_hint_instruction.get("raw_opcode")
            if isinstance(tail_hint_raw_opcode, int):
                tail_hint_catalog_entry = tail_hint_opcode_catalog.setdefault(
                    tail_hint_raw_opcode,
                    {
                        "raw_opcode": int(tail_hint_raw_opcode),
                        "raw_opcode_hex": str(
                            tail_hint_instruction.get("raw_opcode_hex", f"0x{tail_hint_raw_opcode:04X}")
                        ),
                        "blocked_profile_count": 0,
                        "key_sample": [],
                        "tail_status_sample": [],
                        "operand_signature_sample": [],
                    },
                )
                tail_hint_catalog_entry["blocked_profile_count"] = int(
                    tail_hint_catalog_entry.get("blocked_profile_count", 0)
                ) + 1
                _append_int_sample(tail_hint_catalog_entry["key_sample"], archive_key)
                tail_status_sample = tail_hint_catalog_entry.get("tail_status_sample")
                if (
                    isinstance(tail_status_sample, list)
                    and tail_trace_status
                    and tail_trace_status not in tail_status_sample
                    and len(tail_status_sample) < 4
                ):
                    tail_status_sample.append(tail_trace_status)
                tail_operand_signature = entry.get("tail_operand_signature")
                operand_signature_sample = tail_hint_catalog_entry.get("operand_signature_sample")
                if (
                    isinstance(operand_signature_sample, list)
                    and isinstance(tail_operand_signature, str)
                    and tail_operand_signature
                    and tail_operand_signature not in operand_signature_sample
                    and len(operand_signature_sample) < 4
                ):
                    operand_signature_sample.append(tail_operand_signature)
                for field in ("semantic_label", "semantic_family", "immediate_kind"):
                    value = tail_hint_instruction.get(field)
                    if isinstance(value, str) and value and field not in tail_hint_catalog_entry:
                        tail_hint_catalog_entry[field] = value
        instruction_budget_desync = entry.get("instruction_budget_desync")
        if isinstance(instruction_budget_desync, dict) and instruction_budget_desync:
            instruction_budget_desync_count += 1
            top_suspect_instruction = instruction_budget_desync.get("top_suspect_instruction")
            if isinstance(top_suspect_instruction, dict):
                top_suspect_raw_opcode = top_suspect_instruction.get("raw_opcode")
                if isinstance(top_suspect_raw_opcode, int):
                    top_suspect_catalog_entry = instruction_budget_top_suspect_catalog.setdefault(
                        top_suspect_raw_opcode,
                        {
                            "raw_opcode": int(top_suspect_raw_opcode),
                            "raw_opcode_hex": str(
                                top_suspect_instruction.get("raw_opcode_hex", f"0x{top_suspect_raw_opcode:04X}")
                            ),
                            "blocked_profile_count": 0,
                            "key_sample": [],
                            "tail_status_sample": [],
                        },
                    )
                    top_suspect_catalog_entry["blocked_profile_count"] = int(
                        top_suspect_catalog_entry.get("blocked_profile_count", 0)
                    ) + 1
                    _append_int_sample(top_suspect_catalog_entry["key_sample"], archive_key)
                    tail_status_sample = top_suspect_catalog_entry.get("tail_status_sample")
                    if (
                        isinstance(tail_status_sample, list)
                        and tail_trace_status
                        and tail_trace_status not in tail_status_sample
                        and len(tail_status_sample) < 4
                    ):
                        tail_status_sample.append(tail_trace_status)
                    for field in ("semantic_label", "semantic_family", "immediate_kind"):
                        value = top_suspect_instruction.get(field)
                        if isinstance(value, str) and value and field not in top_suspect_catalog_entry:
                            top_suspect_catalog_entry[field] = value

        raw_opcode = entry.get("frontier_raw_opcode")
        if not isinstance(raw_opcode, int):
            continue

        catalog_entry = blocker_catalog.setdefault(
            raw_opcode,
            {
                "raw_opcode": int(raw_opcode),
                "raw_opcode_hex": str(entry.get("frontier_raw_opcode_hex", f"0x{raw_opcode:04X}")),
                "blocked_profile_count": 0,
                "key_sample": [],
                "file_sample": [],
                "frontier_reason_sample": [],
            },
        )
        catalog_entry["blocked_profile_count"] = int(catalog_entry.get("blocked_profile_count", 0)) + 1
        _append_int_sample(catalog_entry["key_sample"], archive_key)
        file_sample = catalog_entry.get("file_sample")
        if isinstance(file_sample, list) and len(file_sample) < 8:
            file_entry = {
                "archive_key": archive_key,
                "file_id": int(entry.get("file_id", 0)),
            }
            frontier_offset = entry.get("frontier_offset")
            if isinstance(frontier_offset, int):
                file_entry["frontier_offset"] = frontier_offset
            frontier_instruction_index = entry.get("frontier_instruction_index")
            if isinstance(frontier_instruction_index, int):
                file_entry["frontier_instruction_index"] = frontier_instruction_index
            if file_entry not in file_sample:
                file_sample.append(file_entry)
        frontier_reason_sample = catalog_entry.get("frontier_reason_sample")
        if isinstance(frontier_reason_sample, list) and frontier_reason not in frontier_reason_sample and len(frontier_reason_sample) < 4:
            frontier_reason_sample.append(frontier_reason)
        for field in (
            "frontier_candidate_label",
            "frontier_candidate_family",
        ):
            value = entry.get(field)
            if isinstance(value, str) and value and field not in catalog_entry:
                catalog_entry[field] = value
        frontier_candidate_confidence = entry.get("frontier_candidate_confidence")
        if isinstance(frontier_candidate_confidence, (int, float)) and "frontier_candidate_confidence" not in catalog_entry:
            catalog_entry["frontier_candidate_confidence"] = float(frontier_candidate_confidence)
        for field in (
            "frontier_candidate_operand_signature",
            "frontier_candidate_stack_effect",
        ):
            value = entry.get(field)
            if isinstance(value, dict) and value and field not in catalog_entry:
                catalog_entry[field] = dict(value)

    return {
        "kind": "clientscript-pseudocode-blockers",
        "profile_count": len(profile_statuses),
        "ready_profile_count": ready_count,
        "blocked_profile_count": blocked_count,
        "ready_key_sample": ready_key_sample,
        "blocked_key_sample": blocked_key_sample,
        "control_group_diff_count": control_group_diff_count,
        "control_group_ready_key_sample": control_group_ready_key_sample,
        "blocking_kind_counts": dict(
            sorted(blocking_kind_counts.items(), key=lambda item: (-int(item[1]), str(item[0])))
        ),
        "blocker_opcode_count": len(blocker_catalog),
        "frontier_reason_counts": dict(sorted(frontier_reason_counts.items(), key=lambda item: (-int(item[1]), str(item[0])))),
        "tail_status_counts": dict(sorted(tail_status_counts.items(), key=lambda item: (-int(item[1]), str(item[0])))),
        "tail_last_opcode_count": len(tail_last_opcode_catalog),
        "tail_last_opcodes": sorted(
            tail_last_opcode_catalog.values(),
            key=lambda item: (-int(item.get("blocked_profile_count", 0)), int(item.get("raw_opcode", 0))),
        ),
        "tail_next_opcode_count": len(tail_next_opcode_catalog),
        "tail_next_opcodes": sorted(
            tail_next_opcode_catalog.values(),
            key=lambda item: (-int(item.get("blocked_profile_count", 0)), int(item.get("raw_opcode", 0))),
        ),
        "tail_hint_opcode_count": len(tail_hint_opcode_catalog),
        "tail_hint_opcodes": sorted(
            tail_hint_opcode_catalog.values(),
            key=lambda item: (-int(item.get("blocked_profile_count", 0)), int(item.get("raw_opcode", 0))),
        ),
        "instruction_budget_desync_count": instruction_budget_desync_count,
        "instruction_budget_top_suspect_opcode_count": len(instruction_budget_top_suspect_catalog),
        "instruction_budget_top_suspect_opcodes": sorted(
            instruction_budget_top_suspect_catalog.values(),
            key=lambda item: (-int(item.get("blocked_profile_count", 0)), int(item.get("raw_opcode", 0))),
        ),
        "control_group_leak_candidate_count": len(control_group_leak_candidate_catalog),
        "control_group_leak_candidates": sorted(
            control_group_leak_candidate_catalog.values(),
            key=lambda item: (-int(item.get("blocked_profile_count", 0)), int(item.get("raw_opcode", 0))),
        ),
        "opcodes": sorted(
            blocker_catalog.values(),
            key=lambda item: (-int(item.get("blocked_profile_count", 0)), int(item.get("raw_opcode", 0))),
        ),
        "blocked_profile_sample": blocked_profile_sample,
    }


def _infer_clientscript_tail_producer_candidate(stats: dict[str, object]) -> dict[str, object]:
    immediate_kind = str(stats.get("immediate_kind", ""))
    blocked_profile_count = max(int(stats.get("blocked_profile_count", 0)), 1)
    matched_tail_last_count = int(stats.get("matched_tail_last_count", 0))
    tail_last_immediate_value_count = int(stats.get("tail_last_immediate_value_count", 0))
    if immediate_kind != "int":
        return {}
    if matched_tail_last_count <= 0 or tail_last_immediate_value_count <= 0:
        return {}

    confidence = round(
        min(
            0.84,
            0.52
            + min(matched_tail_last_count, blocked_profile_count) * 0.08
            + min(tail_last_immediate_value_count, blocked_profile_count) * 0.05
            + (0.03 if int(stats.get("distinct_immediate_value_count", 0)) <= blocked_profile_count else 0.0),
        ),
        2,
    )

    reasons = [
        "Late-tail blockers repeatedly land on the same fixed-width integer opcode immediately after an already decoded instance of that opcode.",
        "The decoded tail instruction already exposes a concrete 32-bit immediate, which makes this shape fit a literal integer producer more closely than a late consumer or mutator.",
    ]
    sample_values = stats.get("sample_values")
    if isinstance(sample_values, list) and sample_values:
        reasons.append(f"Observed concrete integer payloads such as {sample_values[0]!r} in the final aligned tail window.")
    operand_signature_sample = stats.get("operand_signature_sample")
    if isinstance(operand_signature_sample, list) and operand_signature_sample:
        reasons.append(
            f"The surviving tail stack still carries signatures like {operand_signature_sample[0]!r}, so promoting this opcode keeps that produced integer available to the downstream consumer."
        )

    return {
        "candidate_mnemonic": "PUSH_INT_CANDIDATE",
        "family": "stack",
        "status": "candidate",
        "promotion_source": "tail-producer",
        "candidate_confidence": confidence,
        "candidate_reasons": reasons,
        "notes": " ".join(reasons),
        "suggested_immediate_kind": "int",
        "suggested_immediate_kind_confidence": confidence,
        "suggested_override": {
            "mnemonic": "PUSH_INT_CANDIDATE",
            "family": "stack",
            "immediate_kind": "int",
        },
    }


def _build_clientscript_tail_producer_candidates(
    profile_statuses: list[dict[str, object]],
    *,
    raw_opcode_catalog: dict[int, dict[str, object]] | None = None,
) -> tuple[dict[int, dict[str, object]], dict[str, object]]:
    if not profile_statuses:
        return {}, {
            "tail_producer_opcode_count": 0,
            "tail_extra_bytes_profile_count": 0,
            "catalog_sample": [],
        }

    stats_by_opcode: dict[int, dict[str, object]] = {}
    tail_extra_bytes_profile_count = 0

    for entry in profile_statuses:
        if not isinstance(entry, dict):
            continue
        if str(entry.get("status", "")) != "blocked":
            continue
        if str(entry.get("tail_trace_status", "")) != "extra-bytes":
            continue

        tail_next_instruction = entry.get("tail_next_instruction")
        if not isinstance(tail_next_instruction, dict):
            continue
        raw_opcode = tail_next_instruction.get("raw_opcode")
        if not isinstance(raw_opcode, int):
            continue

        immediate_kind = tail_next_instruction.get("immediate_kind")
        tail_last_instruction = entry.get("tail_last_instruction")
        if not isinstance(immediate_kind, str) and isinstance(tail_last_instruction, dict):
            candidate_immediate_kind = tail_last_instruction.get("immediate_kind")
            if isinstance(candidate_immediate_kind, str):
                immediate_kind = candidate_immediate_kind
        if not isinstance(immediate_kind, str) or immediate_kind not in CLIENTSCRIPT_SUPPORTED_IMMEDIATE_TYPES:
            continue

        existing_entry = raw_opcode_catalog.get(raw_opcode) if isinstance(raw_opcode_catalog, dict) else None
        existing_label = None
        if isinstance(existing_entry, dict):
            existing_label = existing_entry.get("mnemonic", existing_entry.get("candidate_mnemonic"))
            if existing_label in {"PUSH_INT_LITERAL", "PUSH_INT_CANDIDATE"}:
                continue

        tail_extra_bytes_profile_count += 1
        stats = stats_by_opcode.setdefault(
            raw_opcode,
            {
                "raw_opcode": int(raw_opcode),
                "raw_opcode_hex": str(tail_next_instruction.get("raw_opcode_hex", f"0x{raw_opcode:04X}")),
                "immediate_kind": immediate_kind,
                "blocked_profile_count": 0,
                "matched_tail_last_count": 0,
                "tail_last_immediate_value_count": 0,
                "sample_values": [],
                "key_sample": [],
                "tail_status_sample": [],
                "operand_signature_sample": [],
                "trace_samples": [],
            },
        )
        stats["blocked_profile_count"] = int(stats.get("blocked_profile_count", 0)) + 1
        archive_key = int(entry.get("archive_key", 0))
        _append_int_sample(stats["key_sample"], archive_key)

        tail_trace_status = str(entry.get("tail_trace_status", "") or "")
        tail_status_sample = stats.get("tail_status_sample")
        if (
            isinstance(tail_status_sample, list)
            and tail_trace_status
            and tail_trace_status not in tail_status_sample
            and len(tail_status_sample) < 4
        ):
            tail_status_sample.append(tail_trace_status)

        tail_operand_signature = entry.get("tail_operand_signature")
        operand_signature_sample = stats.get("operand_signature_sample")
        if (
            isinstance(operand_signature_sample, list)
            and isinstance(tail_operand_signature, str)
            and tail_operand_signature
            and tail_operand_signature not in operand_signature_sample
            and len(operand_signature_sample) < 4
        ):
            operand_signature_sample.append(tail_operand_signature)

        if isinstance(tail_last_instruction, dict) and tail_last_instruction.get("raw_opcode") == raw_opcode:
            stats["matched_tail_last_count"] = int(stats.get("matched_tail_last_count", 0)) + 1
            sampled_value = _sample_clientscript_immediate_value(tail_last_instruction.get("immediate_value"))
            if sampled_value is not None:
                stats["tail_last_immediate_value_count"] = int(stats.get("tail_last_immediate_value_count", 0)) + 1
                sample_values = stats.get("sample_values")
                if isinstance(sample_values, list) and sampled_value not in sample_values and len(sample_values) < 8:
                    sample_values.append(sampled_value)

        trace_samples = stats.get("trace_samples")
        if isinstance(trace_samples, list) and len(trace_samples) < 8:
            trace_entry = {
                "archive_key": archive_key,
                "file_id": int(entry.get("file_id", 0)),
                "tail_next_offset": int(tail_next_instruction.get("offset", 0)),
                "tail_next_raw_opcode_hex": str(tail_next_instruction.get("raw_opcode_hex", f"0x{raw_opcode:04X}")),
            }
            if isinstance(tail_last_instruction, dict):
                trace_entry["tail_last_offset"] = int(tail_last_instruction.get("offset", 0))
                tail_last_raw_opcode_hex = tail_last_instruction.get("raw_opcode_hex")
                if isinstance(tail_last_raw_opcode_hex, str) and tail_last_raw_opcode_hex:
                    trace_entry["tail_last_raw_opcode_hex"] = tail_last_raw_opcode_hex
                tail_last_immediate_value = _sample_clientscript_immediate_value(tail_last_instruction.get("immediate_value"))
                if tail_last_immediate_value is not None:
                    trace_entry["tail_last_immediate_value"] = tail_last_immediate_value
            if isinstance(tail_operand_signature, str) and tail_operand_signature:
                trace_entry["tail_operand_signature"] = tail_operand_signature
            trace_samples.append(trace_entry)

    catalog: dict[int, dict[str, object]] = {}
    for raw_opcode, stats in stats_by_opcode.items():
        sample_values = stats.get("sample_values")
        distinct_immediate_value_count = len(sample_values) if isinstance(sample_values, list) else 0
        entry: dict[str, object] = {
            "raw_opcode": int(raw_opcode),
            "raw_opcode_hex": str(stats["raw_opcode_hex"]),
            "immediate_kind": str(stats["immediate_kind"]),
            "blocked_profile_count": int(stats["blocked_profile_count"]),
            "matched_tail_last_count": int(stats["matched_tail_last_count"]),
            "tail_last_immediate_value_count": int(stats["tail_last_immediate_value_count"]),
            "distinct_immediate_value_count": distinct_immediate_value_count,
            "sample_values": list(sample_values) if isinstance(sample_values, list) else [],
            "key_sample": list(stats["key_sample"]),
            "tail_status_sample": list(stats["tail_status_sample"]),
            "operand_signature_sample": list(stats["operand_signature_sample"]),
            "trace_samples": list(stats["trace_samples"]),
        }
        entry.update(_infer_clientscript_tail_producer_candidate(entry))
        if "candidate_mnemonic" not in entry:
            continue
        stack_effect_candidate = _infer_clientscript_stack_effect(entry)
        if stack_effect_candidate is not None:
            entry["stack_effect_candidate"] = stack_effect_candidate
        catalog[int(raw_opcode)] = entry

    summary = {
        "tail_producer_opcode_count": len(catalog),
        "tail_extra_bytes_profile_count": tail_extra_bytes_profile_count,
        "catalog_sample": sorted(
            catalog.values(),
            key=lambda entry: (
                -int(entry.get("blocked_profile_count", 0)),
                -int(entry.get("matched_tail_last_count", 0)),
                int(entry["raw_opcode"]),
            ),
        )[:24],
    }
    return catalog, summary


def _infer_clientscript_tail_consumer_candidate(entry: dict[str, object]) -> dict[str, object]:
    immediate_kind_candidates = entry.get("immediate_kind_candidates")
    if not isinstance(immediate_kind_candidates, list) or not immediate_kind_candidates:
        return {}

    top_candidate = immediate_kind_candidates[0]
    immediate_kind = str(top_candidate.get("immediate_kind", ""))
    if immediate_kind not in CLIENTSCRIPT_SUPPORTED_IMMEDIATE_TYPES:
        return {}

    script_count = max(int(entry.get("script_count", 0)), 1)
    complete_trace_count = int(top_candidate.get("complete_trace_count", 0))
    resolves_extra_bytes_count = int(top_candidate.get("resolves_extra_bytes_count", 0))
    retains_base_consumed_offset_count = int(top_candidate.get("retains_base_consumed_offset_count", 0))
    if complete_trace_count <= 0 or resolves_extra_bytes_count <= 0 or retains_base_consumed_offset_count <= 0:
        return {}

    operand_signature_sample = entry.get("operand_signature_sample")
    dominant_signature = None
    if isinstance(operand_signature_sample, list) and operand_signature_sample:
        first_signature = operand_signature_sample[0]
        if isinstance(first_signature, dict):
            candidate_signature = first_signature.get("signature")
            if isinstance(candidate_signature, str) and candidate_signature:
                dominant_signature = candidate_signature
    if not isinstance(dominant_signature, str) or not dominant_signature.startswith("widget"):
        return {}

    mnemonic = "WIDGET_MUTATOR_CANDIDATE"
    family = "widget-action"
    notes = "Late-tail opcode likely drains a widget-targeted payload after the producer chain has fully populated the stack."
    if dominant_signature == "widget+int+string":
        mnemonic = "WIDGET_EVENT_BINDER_CANDIDATE"
        family = "widget-event-action"
        notes = (
            "Late-tail opcode likely binds or dispatches a widget-scoped action using a packed widget id,"
            " a string label, and an additional integer argument."
        )
    elif dominant_signature == "widget+string":
        mnemonic = "WIDGET_TEXT_MUTATOR_CANDIDATE"
        family = "widget-text-action"
        notes = "Late-tail opcode likely consumes a packed widget id plus one string payload."
    elif dominant_signature == "widget+widget":
        mnemonic = "WIDGET_LINK_MUTATOR_CANDIDATE"
        family = "widget-link-action"
        notes = "Late-tail opcode likely consumes two widget handles to link or re-parent interface state."
    elif dominant_signature in {
        "widget+int",
        "widget+state-int",
        "widget+literal-int",
        "widget+slot-int",
        "widget+symbolic-int",
    }:
        mnemonic = "WIDGET_STATE_MUTATOR_CANDIDATE"
        family = "widget-state-action"
        notes = "Late-tail opcode likely consumes a packed widget id plus one integer-like state argument."
    elif dominant_signature == "widget-only":
        mnemonic = "WIDGET_ATOMIC_ACTION_CANDIDATE"
        family = "widget-action"
        notes = "Late-tail opcode likely performs an atomic widget action using only the packed widget id."

    confidence = round(
        min(
            0.86,
            0.56
            + min(complete_trace_count, script_count) * 0.11
            + min(resolves_extra_bytes_count, script_count) * 0.06
            + min(retains_base_consumed_offset_count, script_count) * 0.04
            + (0.03 if immediate_kind == "switch" else 0.0),
        ),
        2,
    )

    reasons = [
        f"Treating this late-tail opcode as a {immediate_kind!r} immediate consumes the remaining bytes cleanly and restores a complete trace.",
        f"The surviving operand window is dominated by {dominant_signature!r}, so the opcode is behaving like a real widget-targeted consumer rather than another producer.",
    ]
    trace_samples = top_candidate.get("trace_samples")
    if isinstance(trace_samples, list) and trace_samples:
        first_trace = trace_samples[0]
        if isinstance(first_trace, dict):
            consumed_offset = first_trace.get("consumed_offset")
            if isinstance(consumed_offset, int):
                reasons.append(f"Observed aligned late-tail completion through byte offset {consumed_offset}.")

    inferred: dict[str, object] = {
        "mnemonic": mnemonic,
        "candidate_mnemonic": mnemonic,
        "family": family,
        "status": "candidate",
        "promotion_source": "tail-consumer",
        "candidate_confidence": confidence,
        "candidate_reasons": reasons,
        "notes": " ".join(reasons + [notes]),
        "immediate_kind": immediate_kind,
        "suggested_immediate_kind": immediate_kind,
        "suggested_immediate_kind_confidence": confidence,
        "suggested_override": {
            "mnemonic": mnemonic,
            "family": family,
            "immediate_kind": immediate_kind,
        },
    }
    signature_probe_entry = dict(entry | inferred)
    if "prefix_operand_signature_sample" not in signature_probe_entry:
        operand_signature_sample = entry.get("operand_signature_sample")
        if isinstance(operand_signature_sample, list) and operand_signature_sample:
            signature_probe_entry["prefix_operand_signature_sample"] = [
                dict(sample) for sample in operand_signature_sample if isinstance(sample, dict)
            ]

    operand_signature_candidate = _infer_clientscript_widget_operand_signature(signature_probe_entry)
    if operand_signature_candidate is not None:
        inferred["operand_signature_candidate"] = operand_signature_candidate
    stack_effect_candidate = _infer_clientscript_stack_effect(signature_probe_entry)
    if stack_effect_candidate is not None:
        inferred["stack_effect_candidate"] = stack_effect_candidate
    return inferred


def _build_clientscript_tail_consumer_candidates(
    tail_hint_candidates: dict[int, dict[str, object]],
) -> tuple[dict[int, dict[str, object]], dict[str, object]]:
    if not tail_hint_candidates:
        return {}, {
            "tail_consumer_opcode_count": 0,
            "complete_tail_opcode_count": 0,
            "catalog_sample": [],
        }

    catalog: dict[int, dict[str, object]] = {}
    complete_tail_opcode_count = 0
    for raw_opcode, entry in sorted(tail_hint_candidates.items()):
        if not isinstance(entry, dict):
            continue
        immediate_kind_candidates = entry.get("immediate_kind_candidates")
        if not isinstance(immediate_kind_candidates, list) or not immediate_kind_candidates:
            continue
        top_candidate = immediate_kind_candidates[0]
        if int(top_candidate.get("complete_trace_count", 0)) > 0:
            complete_tail_opcode_count += 1

        inferred = _infer_clientscript_tail_consumer_candidate(entry)
        if not inferred:
            continue

        merged_entry = dict(entry)
        merged_entry.update(inferred)
        catalog[int(raw_opcode)] = merged_entry

    summary = {
        "tail_consumer_opcode_count": len(catalog),
        "complete_tail_opcode_count": complete_tail_opcode_count,
        "catalog_sample": sorted(
            catalog.values(),
            key=lambda item: (
                -int(item.get("script_count", 0)),
                -int(item.get("candidate_confidence", 0) * 100),
                int(item.get("raw_opcode", 0)),
            ),
        )[:24],
    }
    return catalog, summary


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
    elif immediate_kind == "string":
        entry["candidate_mnemonic"] = "PUSH_CONST_STRING"
        entry["family"] = "stack-constant"
        entry["candidate_confidence"] = 0.94
        reasons.append("Null-terminated CP1252 immediate is consistent with a direct string constant push.")
        if first_ratio >= 0.5:
            reasons.append("Frequent prologue placement suggests this string seeds later UI or sub-script logic.")

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


def _select_clientscript_string_payload_immediate_kind(
    entry: dict[str, object],
) -> tuple[str | None, str | None]:
    immediate_kind_candidates = entry.get("immediate_kind_candidates")
    if not isinstance(immediate_kind_candidates, list) or not immediate_kind_candidates:
        return None, None

    candidates = [
        candidate
        for candidate in immediate_kind_candidates
        if isinstance(candidate, dict)
        and str(candidate.get("immediate_kind", "")) in CLIENTSCRIPT_IMMEDIATE_TYPES
        and str(candidate.get("immediate_kind", "")) != "switch"
        and int(candidate.get("improved_script_count", 0)) > 0
    ]
    if not candidates:
        return None, None

    def structural_rank(candidate: dict[str, object]) -> tuple[int, int, int, int, int, int]:
        return (
            int(candidate.get("complete_trace_count", 0)),
            int(candidate.get("improved_script_count", 0)),
            int(candidate.get("total_progress_instruction_count", 0)),
            int(candidate.get("next_frontier_trace_count", 0)),
            int(candidate.get("valid_trace_count", 0)),
            -int(candidate.get("invalid_immediate_count", 0)),
        )

    width_priority = {
        "byte": 0,
        "short": 1,
        "tribyte": 2,
        "int": 3,
        "string": 4,
    }

    best_rank = max(structural_rank(candidate) for candidate in candidates)
    tied_candidates = [candidate for candidate in candidates if structural_rank(candidate) == best_rank]
    selected = min(
        tied_candidates,
        key=lambda candidate: (
            int(candidate.get("relative_target_instruction_boundary_count", 0)),
            int(candidate.get("relative_target_count", 0)),
            width_priority.get(str(candidate.get("immediate_kind", "")), 99),
            str(candidate.get("immediate_kind", "")),
        ),
    )
    selected_kind = str(selected.get("immediate_kind", ""))
    if selected_kind not in CLIENTSCRIPT_SUPPORTED_IMMEDIATE_TYPES:
        return None, None
    if len(tied_candidates) <= 1:
        return selected_kind, None

    return (
        selected_kind,
        "Several immediate probes preserved the same downstream string-context progress, so the narrower non-control-flow-shaped operand was selected to avoid overfitting a formatter/message payload into a jump-like interpretation.",
    )


def _refine_clientscript_string_payload_frontier_candidate(entry: dict[str, object]) -> None:
    current_mnemonic = str(entry.get("candidate_mnemonic", ""))
    if current_mnemonic and current_mnemonic not in {
        "CONTROL_FLOW_FRONTIER_CANDIDATE",
        "STRING_RESULT_CHAIN_CANDIDATE",
        "STRING_FORMATTER_FRONTIER_CANDIDATE",
        "WIDGET_TEXT_MUTATOR_FRONTIER_CANDIDATE",
    }:
        return
    if int(entry.get("switch_script_count", 0)) <= 0:
        return

    signature_sample = entry.get("prefix_operand_signature_sample")
    if not isinstance(signature_sample, list) or not signature_sample:
        return

    signature_counts: dict[str, int] = {}
    for sample in signature_sample:
        if not isinstance(sample, dict):
            continue
        signature = str(sample.get("signature", ""))
        if not signature:
            continue
        signature_counts[signature] = int(sample.get("count", 0))
    if not signature_counts:
        return

    dominant_signature = max(signature_counts.items(), key=lambda item: (int(item[1]), str(item[0])))[0]
    signature_profiles: dict[str, tuple[str, str, float, str]] = {
        "int+string": (
            "STRING_FORMATTER_CANDIDATE",
            "string-transform-action",
            0.7,
            "Prefix stack already holds one integer-like value plus one string, which matches a formatter-style payload even though only a small number of scripts currently reach this frontier.",
        ),
        "string+string": (
            "STRING_FORMATTER_CANDIDATE",
            "string-transform-action",
            0.72,
            "Prefix stack already holds two string values, which matches a string-concatenation payload even though only a small number of scripts currently reach this frontier.",
        ),
        "string-only": (
            "STRING_ACTION_CANDIDATE",
            "string-action",
            0.66,
            "Prefix stack already holds a string-only payload, which matches a message, URL, or other string sink even though only a small number of scripts currently reach this frontier.",
        ),
        "widget+string": (
            "WIDGET_TEXT_MUTATOR_CANDIDATE",
            "widget-text-action",
            0.76,
            "Prefix stack already holds a widget target plus a string payload, which matches a text-bearing widget mutator even though only a small number of scripts currently reach this frontier.",
        ),
        "widget+int+string": (
            "WIDGET_EVENT_BINDER_CANDIDATE",
            "widget-event-action",
            0.78,
            "Prefix stack already holds a widget target, an integer-like parameter, and a string payload, which matches a widget event-binding payload more closely than a plain text mutator.",
        ),
    }
    signature_profile = signature_profiles.get(dominant_signature)
    if signature_profile is None:
        return

    resolved_immediate_kind = entry.get("suggested_immediate_kind")
    probe_reason: str | None = None
    if not (
        isinstance(resolved_immediate_kind, str)
        and resolved_immediate_kind in CLIENTSCRIPT_SUPPORTED_IMMEDIATE_TYPES
        and resolved_immediate_kind != "switch"
    ):
        resolved_immediate_kind, probe_reason = _select_clientscript_string_payload_immediate_kind(entry)
    if not (
        isinstance(resolved_immediate_kind, str)
        and resolved_immediate_kind in CLIENTSCRIPT_SUPPORTED_IMMEDIATE_TYPES
        and resolved_immediate_kind != "switch"
    ):
        return

    candidate_mnemonic, family, base_confidence, primary_reason = signature_profile
    confidence = max(float(entry.get("candidate_confidence", 0.0)), base_confidence)
    if any(
        isinstance(candidate, dict) and str(candidate.get("immediate_kind", "")) == resolved_immediate_kind
        and int(candidate.get("next_frontier_trace_count", 0)) > 0
        for candidate in entry.get("immediate_kind_candidates", [])
        if isinstance(entry.get("immediate_kind_candidates"), list)
    ):
        confidence = min(0.82, confidence + 0.03)
    confidence = round(confidence, 2)

    reasons = [
        str(reason)
        for reason in entry.get("candidate_reasons", [])
        if str(reason)
    ]
    reasons.append(primary_reason)
    if probe_reason is not None:
        reasons.append(probe_reason)

    entry["candidate_mnemonic"] = candidate_mnemonic
    entry["family"] = family
    entry["candidate_confidence"] = confidence
    entry["candidate_reasons"] = reasons
    entry["suggested_immediate_kind"] = resolved_immediate_kind
    entry["suggested_immediate_kind_confidence"] = max(
        confidence,
        float(entry.get("suggested_immediate_kind_confidence", 0.0)),
    )
    entry["suggested_override"] = {
        "mnemonic": candidate_mnemonic,
        "family": family,
        "immediate_kind": resolved_immediate_kind,
    }


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
    probe_immediate_kinds: tuple[str, ...] | None = None,
) -> dict[str, dict[str, object]]:
    base_decoded_instruction_count = int(base_prefix_trace.get("decoded_instruction_count", 0))
    scores: dict[str, dict[str, object]] = {}
    kinds_to_probe = probe_immediate_kinds or CLIENTSCRIPT_IMMEDIATE_TYPES
    for immediate_kind in kinds_to_probe:
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


def _measure_clientscript_trace_consumed_offset(
    layout: ClientscriptLayout,
    trace: dict[str, object],
) -> int:
    frontier_offset = trace.get("frontier_offset")
    if isinstance(frontier_offset, int):
        return max(0, min(frontier_offset, len(layout.opcode_data)))

    last_instruction = trace.get("last_instruction")
    if isinstance(last_instruction, dict):
        end_offset = last_instruction.get("end_offset")
        if isinstance(end_offset, int):
            return max(0, min(end_offset, len(layout.opcode_data)))

    remaining_opcode_bytes = trace.get("remaining_opcode_bytes")
    if isinstance(remaining_opcode_bytes, int):
        return max(0, min(len(layout.opcode_data) - remaining_opcode_bytes, len(layout.opcode_data)))

    return 0


def _build_clientscript_tail_hint_probe_catalog(
    raw_opcode_catalog: dict[int, dict[str, object]] | None,
    *,
    raw_opcode: int,
    immediate_kind: str,
) -> dict[int, dict[str, object]]:
    probe_catalog = {
        int(opcode): dict(entry)
        for opcode, entry in (raw_opcode_catalog or {}).items()
        if isinstance(entry, dict)
    }
    probe_entry = dict(probe_catalog.get(raw_opcode, {}))
    probe_entry["raw_opcode"] = int(raw_opcode)
    probe_entry["raw_opcode_hex"] = f"0x{int(raw_opcode):04X}"
    probe_entry["immediate_kind"] = immediate_kind
    if immediate_kind == "string":
        probe_entry["mnemonic"] = "PUSH_CONST_STRING_CANDIDATE"
        probe_entry["family"] = "stack-constant"
        probe_entry["confidence"] = max(float(probe_entry.get("confidence", 0.0)), 0.72)
        probe_entry.pop("control_flow_kind", None)
        probe_entry.pop("jump_base", None)
        probe_entry.pop("jump_scale", None)
    probe_catalog[int(raw_opcode)] = probe_entry
    return probe_catalog


def _find_clientscript_instruction_at_offset(
    instruction_steps: list[dict[str, object]],
    *,
    offset: int,
    raw_opcode: int | None = None,
) -> dict[str, object] | None:
    for step in instruction_steps:
        if not isinstance(step, dict):
            continue
        if int(step.get("offset", -1)) != offset:
            continue
        if raw_opcode is not None and int(step.get("raw_opcode", -1)) != raw_opcode:
            continue
        return step
    return None


def _score_clientscript_tail_hint_immediate_kinds(
    layout: ClientscriptLayout,
    locked_opcode_types: dict[int, str],
    *,
    tail_hint_instruction: dict[str, object],
    base_trace: dict[str, object],
    raw_opcode_catalog: dict[int, dict[str, object]] | None = None,
    probe_immediate_kinds: tuple[str, ...] | None = None,
) -> dict[str, dict[str, object]]:
    tail_hint_opcode = int(tail_hint_instruction["raw_opcode"])
    tail_hint_offset = int(tail_hint_instruction["offset"])
    base_trace_status = str(base_trace.get("status", ""))
    base_consumed_offset = _measure_clientscript_trace_consumed_offset(layout, base_trace)
    scores: dict[str, dict[str, object]] = {}
    kinds_to_probe = probe_immediate_kinds or CLIENTSCRIPT_SUPPORTED_IMMEDIATE_TYPES

    for immediate_kind in kinds_to_probe:
        probe_types = dict(locked_opcode_types)
        probe_types[tail_hint_opcode] = immediate_kind
        probe_catalog = _build_clientscript_tail_hint_probe_catalog(
            raw_opcode_catalog,
            raw_opcode=tail_hint_opcode,
            immediate_kind=immediate_kind,
        )
        trace = _trace_clientscript_locked_prefix(
            layout,
            probe_types,
            raw_opcode_catalog=probe_catalog,
        )
        if trace is None:
            continue

        trace_status = str(trace.get("status", ""))
        frontier_reason = str(trace.get("frontier_reason", ""))
        consumed_offset = _measure_clientscript_trace_consumed_offset(layout, trace)
        valid_trace = not (trace_status == "frontier" and frontier_reason == "invalid-locked-immediate")
        probe_step = _find_clientscript_instruction_at_offset(
            trace.get("instruction_steps", []),
            offset=tail_hint_offset,
            raw_opcode=tail_hint_opcode,
        )

        entry: dict[str, object] = {
            "immediate_kind": immediate_kind,
            "trace_status": trace_status,
            "frontier_reason": frontier_reason or None,
            "decoded_instruction_count": int(trace.get("decoded_instruction_count", 0)),
            "consumed_offset": consumed_offset,
            "consumed_offset_delta": consumed_offset - base_consumed_offset,
            "remaining_opcode_bytes": int(trace.get("remaining_opcode_bytes", 0)),
            "valid_trace": valid_trace,
            "hint_step_found": probe_step is not None,
            "retains_base_consumed_offset": consumed_offset >= base_consumed_offset,
            "resolves_extra_bytes": base_trace_status == "extra-bytes" and trace_status in {"frontier", "complete"},
        }

        if trace_status == "frontier":
            next_frontier_opcode = trace.get("frontier_raw_opcode")
            if isinstance(next_frontier_opcode, int):
                entry["next_frontier_raw_opcode"] = next_frontier_opcode
                entry["next_frontier_raw_opcode_hex"] = trace.get("frontier_raw_opcode_hex")

        if isinstance(probe_step, dict):
            probe_semantic_label = probe_step.get("semantic_label")
            if isinstance(probe_semantic_label, str) and probe_semantic_label:
                entry["probe_semantic_label"] = probe_semantic_label
            probe_semantic_family = probe_step.get("semantic_family")
            if isinstance(probe_semantic_family, str) and probe_semantic_family:
                entry["probe_semantic_family"] = probe_semantic_family
            probe_control_flow_kind = probe_step.get("control_flow_kind")
            if isinstance(probe_control_flow_kind, str) and probe_control_flow_kind:
                entry["probe_control_flow_kind"] = probe_control_flow_kind
            immediate_value = probe_step.get("immediate_value")
            if isinstance(immediate_value, str) and immediate_value:
                entry["string_immediate_value"] = immediate_value
            elif isinstance(immediate_value, (int, float, bool)):
                entry["probe_immediate_value"] = immediate_value

            instruction_steps = trace.get("instruction_steps")
            if isinstance(instruction_steps, list):
                step_index = next(
                    (
                        index
                        for index, candidate_step in enumerate(instruction_steps)
                        if isinstance(candidate_step, dict)
                        and int(candidate_step.get("offset", -1)) == tail_hint_offset
                        and int(candidate_step.get("raw_opcode", -1)) == tail_hint_opcode
                    ),
                    None,
                )
                if isinstance(step_index, int):
                    relative_target = _summarize_clientscript_relative_target(
                        layout,
                        trace,
                        step_index=step_index,
                    )
                    if isinstance(relative_target, dict) and relative_target:
                        entry.update(relative_target)

        scores[immediate_kind] = entry

    return scores


def _clientscript_tail_hint_kind_rank(candidate: dict[str, object] | None) -> tuple[int, int, int, int, int, int, int]:
    if not isinstance(candidate, dict):
        return (-1, -1, -1, -1, -1, -1, -1)

    trace_status = str(candidate.get("trace_status", ""))
    status_rank = {
        "complete": 3,
        "frontier": 2,
        "extra-bytes": 1,
    }.get(trace_status, 0)
    resolves_extra_bytes = int(
        candidate.get("resolves_extra_bytes_count", candidate.get("resolves_extra_bytes", 0)) or 0
    )
    retains_base_consumed_offset = int(
        candidate.get(
            "retains_base_consumed_offset_count",
            candidate.get("retains_base_consumed_offset", 0),
        )
        or 0
    )
    hint_step_found = int(candidate.get("hint_step_found_count", candidate.get("hint_step_found", 0)) or 0)
    string_immediate_count = int(candidate.get("string_immediate_count", 0) or 0)
    frontier_trace_count = int(candidate.get("frontier_trace_count", 0) or 0)
    consumed_offset = int(candidate.get("max_consumed_offset", candidate.get("consumed_offset", 0)) or 0)
    remaining_opcode_bytes = int(candidate.get("remaining_opcode_bytes", 0) or 0)
    return (
        resolves_extra_bytes,
        status_rank,
        retains_base_consumed_offset,
        hint_step_found,
        string_immediate_count,
        frontier_trace_count,
        consumed_offset - remaining_opcode_bytes,
    )


def _infer_clientscript_tail_hint_candidate(entry: dict[str, object]) -> dict[str, object]:
    immediate_kind_candidates = entry.get("immediate_kind_candidates")
    if not isinstance(immediate_kind_candidates, list) or not immediate_kind_candidates:
        return {}

    top_candidate = immediate_kind_candidates[0]
    if str(top_candidate.get("immediate_kind", "")) != "string":
        return _infer_clientscript_tail_hint_branch_candidate(entry)

    script_count = max(int(entry.get("script_count", 0)), 1)
    resolves_extra_bytes_count = int(top_candidate.get("resolves_extra_bytes_count", 0))
    retains_base_consumed_offset_count = int(top_candidate.get("retains_base_consumed_offset_count", 0))
    frontier_trace_count = int(top_candidate.get("frontier_trace_count", 0))
    string_immediate_count = int(top_candidate.get("string_immediate_count", 0))
    if (
        resolves_extra_bytes_count <= 0
        or retains_base_consumed_offset_count <= 0
        or frontier_trace_count <= 0
        or string_immediate_count <= 0
    ):
        return _infer_clientscript_tail_hint_branch_candidate(entry)

    confidence = round(
        min(
            0.88,
            0.56
            + min(resolves_extra_bytes_count, script_count) * 0.08
            + min(retains_base_consumed_offset_count, script_count) * 0.04
            + min(string_immediate_count, script_count) * 0.04
            + min(frontier_trace_count, script_count) * 0.03,
        ),
        2,
    )

    reasons = [
        "Late-tail replays stop desynchronizing when this opcode is treated as an inline CP1252 string literal.",
        "The string probe preserves the proven prefix and exposes a real downstream frontier instead of collapsing into tail extra-bytes.",
    ]
    string_immediate_samples = top_candidate.get("string_immediate_samples")
    if isinstance(string_immediate_samples, list) and string_immediate_samples:
        reasons.append(f"Observed plausible inline string payloads such as {json.dumps(str(string_immediate_samples[0]))}.")
    next_frontier_sample = top_candidate.get("next_frontier_sample")
    if isinstance(next_frontier_sample, list) and next_frontier_sample:
        next_frontier = next_frontier_sample[0]
        next_frontier_hex = next_frontier.get("raw_opcode_hex")
        if isinstance(next_frontier_hex, str) and next_frontier_hex:
            reasons.append(f"Promoting the tail hint reveals a downstream frontier at {next_frontier_hex}.")

    return {
        "candidate_mnemonic": "PUSH_CONST_STRING_CANDIDATE",
        "family": "stack-constant",
        "candidate_confidence": confidence,
        "candidate_reasons": reasons,
        "suggested_immediate_kind": "string",
        "suggested_immediate_kind_confidence": confidence,
        "suggested_override": {
            "mnemonic": "PUSH_CONST_STRING_CANDIDATE",
            "family": "stack-constant",
            "immediate_kind": "string",
        },
    }


def _infer_clientscript_tail_hint_branch_candidate(entry: dict[str, object]) -> dict[str, object]:
    immediate_kind_candidates = entry.get("immediate_kind_candidates")
    if not isinstance(immediate_kind_candidates, list) or not immediate_kind_candidates:
        return {}

    semantic_label = str(entry.get("semantic_label", "") or "")
    control_flow_kind = str(entry.get("control_flow_kind", "") or "")
    if semantic_label != "JUMP_OFFSET_FRONTIER_CANDIDATE" and control_flow_kind not in {
        "branch",
        "branch-candidate",
        "jump",
        "jump-candidate",
    }:
        return {}

    short_candidate = next(
        (
            candidate
            for candidate in immediate_kind_candidates
            if isinstance(candidate, dict) and str(candidate.get("immediate_kind", "")) == "short"
        ),
        None,
    )
    if not isinstance(short_candidate, dict):
        return {}

    script_count = max(int(entry.get("script_count", 0)), 1)
    retains_base_consumed_offset_count = int(short_candidate.get("retains_base_consumed_offset_count", 0))
    hint_step_found_count = int(short_candidate.get("hint_step_found_count", 0))
    relative_target_count = int(short_candidate.get("relative_target_count", 0))
    relative_target_in_bounds_count = int(short_candidate.get("relative_target_in_bounds_count", 0))
    relative_target_boundary_count = int(
        short_candidate.get("relative_target_instruction_boundary_count", 0)
    )
    if (
        retains_base_consumed_offset_count <= 0
        or hint_step_found_count <= 0
        or relative_target_count <= 0
        or relative_target_boundary_count <= 0
    ):
        return {}

    confidence = round(
        min(
            0.78,
            0.48
            + min(retains_base_consumed_offset_count, script_count) * 0.06
            + min(relative_target_boundary_count, script_count) * 0.08
            + min(relative_target_in_bounds_count, script_count) * 0.04,
        ),
        2,
    )

    reasons = [
        "Late-tail replay keeps the deepest proven prefix when this opcode remains a signed 16-bit control-flow operand.",
        "The short probe resolves to an in-bounds instruction-aligned jump target, which fits a real branch edge better than a stray scalar payload.",
    ]
    alternate_probe = next(
        (
            candidate
            for candidate in immediate_kind_candidates
            if isinstance(candidate, dict)
            and str(candidate.get("immediate_kind", "")) != "short"
            and int(candidate.get("resolves_extra_bytes_count", 0)) > 0
        ),
        None,
    )
    if isinstance(alternate_probe, dict):
        alternate_kind = str(alternate_probe.get("immediate_kind", "") or "")
        alternate_consumed_offset = int(alternate_probe.get("max_consumed_offset", 0) or 0)
        if alternate_kind:
            reasons.append(
                f"Alternative {alternate_kind!r} probe leaves the proven trace earlier at byte offset {alternate_consumed_offset}, so it is likely reinterpreting branch data as payload."
            )
    relative_target_sample = short_candidate.get("relative_target_sample")
    if isinstance(relative_target_sample, list) and relative_target_sample:
        first_target = relative_target_sample[0]
        if isinstance(first_target, dict):
            target_offset = first_target.get("target_offset")
            target_relation = first_target.get("target_relation")
            if isinstance(target_offset, int):
                reasons.append(
                    f"Observed branch target {target_offset} ({target_relation or 'unknown relation'}) from the short replay."
                )

    normalized_control_flow_kind = control_flow_kind or "branch-candidate"
    jump_base = entry.get("jump_base")
    if not isinstance(jump_base, str) or not jump_base:
        jump_base = "next_offset"
    jump_scale = entry.get("jump_scale")
    if not isinstance(jump_scale, int):
        jump_scale = 1

    return {
        "candidate_mnemonic": "JUMP_OFFSET_FRONTIER_CANDIDATE",
        "family": "control-flow",
        "candidate_confidence": confidence,
        "candidate_reasons": reasons,
        "suggested_immediate_kind": "short",
        "suggested_immediate_kind_confidence": confidence,
        "control_flow_kind": normalized_control_flow_kind,
        "jump_base": jump_base,
        "jump_scale": jump_scale,
        "suggested_override": {
            "mnemonic": "JUMP_OFFSET_FRONTIER_CANDIDATE",
            "family": "control-flow",
            "immediate_kind": "short",
            "control_flow_kind": normalized_control_flow_kind,
            "jump_base": jump_base,
            "jump_scale": jump_scale,
        },
    }


def _build_clientscript_tail_hint_candidates(
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
            "tail_hint_opcode_count": 0,
            "tail_extra_bytes_script_count": 0,
            "selected_candidate_count": 0,
            "catalog_sample": [],
        }

    stats_by_opcode: dict[int, dict[str, object]] = {}
    tail_extra_bytes_script_count = 0

    for key, layout in candidates:
        base_trace = _trace_clientscript_locked_prefix(
            layout,
            locked_opcode_types,
            raw_opcode_catalog=raw_opcode_catalog,
        )
        if base_trace is None or str(base_trace.get("status", "")) != "extra-bytes":
            continue

        instruction_steps = base_trace.get("instruction_steps")
        if not isinstance(instruction_steps, list) or not instruction_steps:
            continue
        tail_hint_instruction = _find_clientscript_tail_hint_instruction(instruction_steps)
        if not isinstance(tail_hint_instruction, dict):
            continue
        raw_opcode = tail_hint_instruction.get("raw_opcode")
        if not isinstance(raw_opcode, int):
            continue

        tail_extra_bytes_script_count += 1
        prefix_stack_summary = _summarize_clientscript_prefix_stack_state(instruction_steps)
        operand_signature = prefix_stack_summary.get("prefix_operand_signature")
        base_consumed_offset = _measure_clientscript_trace_consumed_offset(layout, base_trace)

        stats = stats_by_opcode.setdefault(
            raw_opcode,
            {
                "script_count": 0,
                "key_samples": [],
                "script_samples": [],
                "immediate_kind_scores": {},
                "base_trace_status_counts": {},
                "operand_signature_counts": {},
            },
        )
        stats["script_count"] = int(stats["script_count"]) + 1
        if len(stats["key_samples"]) < 8:
            stats["key_samples"].append(int(key))
        if isinstance(operand_signature, str) and operand_signature:
            operand_signature_counts = stats["operand_signature_counts"]
            operand_signature_counts[operand_signature] = int(operand_signature_counts.get(operand_signature, 0)) + 1
        base_trace_status = str(base_trace.get("status", ""))
        base_trace_status_counts = stats["base_trace_status_counts"]
        base_trace_status_counts[base_trace_status] = int(base_trace_status_counts.get(base_trace_status, 0)) + 1
        if len(stats["script_samples"]) < 8:
            stats["script_samples"].append(
                {
                    "key": int(key),
                    "tail_hint_offset": int(tail_hint_instruction["offset"]),
                    "tail_hint_raw_opcode_hex": str(tail_hint_instruction.get("raw_opcode_hex", f"0x{raw_opcode:04X}")),
                    "base_trace_status": base_trace_status,
                    "base_consumed_offset": base_consumed_offset,
                    "base_remaining_opcode_bytes": int(base_trace.get("remaining_opcode_bytes", 0)),
                    "operand_signature": operand_signature,
                }
            )
        for field in ("semantic_label", "semantic_family", "control_flow_kind", "jump_base"):
            value = tail_hint_instruction.get(field)
            if isinstance(value, str) and value and field not in stats:
                stats[field] = value
        jump_scale = tail_hint_instruction.get("jump_scale")
        if isinstance(jump_scale, int) and "jump_scale" not in stats:
            stats["jump_scale"] = jump_scale

        kind_scores = _score_clientscript_tail_hint_immediate_kinds(
            layout,
            locked_opcode_types,
            tail_hint_instruction=tail_hint_instruction,
            base_trace=base_trace,
            raw_opcode_catalog=raw_opcode_catalog,
        )
        for immediate_kind, kind_score in kind_scores.items():
            kind_stats = stats["immediate_kind_scores"].setdefault(
                immediate_kind,
                {
                    "script_count": 0,
                    "valid_trace_count": 0,
                    "frontier_trace_count": 0,
                    "complete_trace_count": 0,
                    "extra_bytes_trace_count": 0,
                    "resolves_extra_bytes_count": 0,
                    "retains_base_consumed_offset_count": 0,
                    "hint_step_found_count": 0,
                    "string_immediate_count": 0,
                    "string_immediate_samples": [],
                    "next_frontier_trace_count": 0,
                    "next_frontier_counts": {},
                    "probe_semantic_label_counts": {},
                    "probe_semantic_family_counts": {},
                    "probe_control_flow_kind_counts": {},
                    "relative_target_count": 0,
                    "relative_target_in_bounds_count": 0,
                    "relative_target_instruction_boundary_count": 0,
                    "relative_target_terminal_count": 0,
                    "relative_target_forward_count": 0,
                    "relative_target_backward_count": 0,
                    "relative_target_self_count": 0,
                    "relative_target_samples": [],
                    "total_consumed_offset": 0,
                    "max_consumed_offset": 0,
                    "trace_samples": [],
                },
            )
            kind_stats["script_count"] = int(kind_stats["script_count"]) + 1
            if bool(kind_score.get("valid_trace")):
                kind_stats["valid_trace_count"] = int(kind_stats["valid_trace_count"]) + 1
            trace_status = str(kind_score.get("trace_status", ""))
            if trace_status == "frontier":
                kind_stats["frontier_trace_count"] = int(kind_stats["frontier_trace_count"]) + 1
            elif trace_status == "complete":
                kind_stats["complete_trace_count"] = int(kind_stats["complete_trace_count"]) + 1
            elif trace_status == "extra-bytes":
                kind_stats["extra_bytes_trace_count"] = int(kind_stats["extra_bytes_trace_count"]) + 1
            if bool(kind_score.get("resolves_extra_bytes")):
                kind_stats["resolves_extra_bytes_count"] = int(kind_stats["resolves_extra_bytes_count"]) + 1
            if bool(kind_score.get("retains_base_consumed_offset")):
                kind_stats["retains_base_consumed_offset_count"] = (
                    int(kind_stats["retains_base_consumed_offset_count"]) + 1
                )
            if bool(kind_score.get("hint_step_found")):
                kind_stats["hint_step_found_count"] = int(kind_stats["hint_step_found_count"]) + 1
            kind_stats["total_consumed_offset"] = int(kind_stats["total_consumed_offset"]) + int(
                kind_score.get("consumed_offset", 0)
            )
            kind_stats["max_consumed_offset"] = max(
                int(kind_stats["max_consumed_offset"]),
                int(kind_score.get("consumed_offset", 0)),
            )
            string_immediate_value = kind_score.get("string_immediate_value")
            if isinstance(string_immediate_value, str) and string_immediate_value:
                kind_stats["string_immediate_count"] = int(kind_stats["string_immediate_count"]) + 1
                string_immediate_samples = kind_stats["string_immediate_samples"]
                if string_immediate_value not in string_immediate_samples and len(string_immediate_samples) < 6:
                    string_immediate_samples.append(string_immediate_value)
            next_frontier_raw_opcode = kind_score.get("next_frontier_raw_opcode")
            if isinstance(next_frontier_raw_opcode, int):
                kind_stats["next_frontier_trace_count"] = int(kind_stats["next_frontier_trace_count"]) + 1
                next_frontier_counts = kind_stats["next_frontier_counts"]
                next_frontier_counts[next_frontier_raw_opcode] = int(
                    next_frontier_counts.get(next_frontier_raw_opcode, 0)
                ) + 1
            for field, counts_key in (
                ("probe_semantic_label", "probe_semantic_label_counts"),
                ("probe_semantic_family", "probe_semantic_family_counts"),
                ("probe_control_flow_kind", "probe_control_flow_kind_counts"),
            ):
                value = kind_score.get(field)
                if isinstance(value, str) and value:
                    counts = kind_stats[counts_key]
                    counts[value] = int(counts.get(value, 0)) + 1
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
                    kind_stats["relative_target_forward_count"] = (
                        int(kind_stats["relative_target_forward_count"]) + 1
                    )
                elif direction == "backward":
                    kind_stats["relative_target_backward_count"] = (
                        int(kind_stats["relative_target_backward_count"]) + 1
                    )
                elif direction == "self":
                    kind_stats["relative_target_self_count"] = int(kind_stats["relative_target_self_count"]) + 1
                if len(kind_stats["relative_target_samples"]) < 6:
                    kind_stats["relative_target_samples"].append(
                        {
                            "key": int(key),
                            "target_offset": int(relative_target_offset),
                            "target_delta": int(kind_score.get("relative_target_delta", 0)),
                            "target_relation": kind_score.get("relative_target_relation"),
                            "target_direction": kind_score.get("relative_target_direction"),
                        }
                    )
            if len(kind_stats["trace_samples"]) < 6:
                kind_stats["trace_samples"].append(
                    {
                        "key": int(key),
                        "trace_status": trace_status,
                        "frontier_reason": kind_score.get("frontier_reason"),
                        "consumed_offset": int(kind_score.get("consumed_offset", 0)),
                        "remaining_opcode_bytes": int(kind_score.get("remaining_opcode_bytes", 0)),
                        "next_frontier_raw_opcode_hex": kind_score.get("next_frontier_raw_opcode_hex"),
                        "string_immediate_value": kind_score.get("string_immediate_value"),
                    }
                )

    catalog: dict[int, dict[str, object]] = {}
    selected_candidate_count = 0
    for raw_opcode, stats in stats_by_opcode.items():
        immediate_kind_candidates: list[dict[str, object]] = []
        for immediate_kind, kind_stats in stats["immediate_kind_scores"].items():
            candidate_entry: dict[str, object] = {
                "immediate_kind": immediate_kind,
                "script_count": int(kind_stats["script_count"]),
                "valid_trace_count": int(kind_stats["valid_trace_count"]),
                "frontier_trace_count": int(kind_stats["frontier_trace_count"]),
                "complete_trace_count": int(kind_stats["complete_trace_count"]),
                "extra_bytes_trace_count": int(kind_stats["extra_bytes_trace_count"]),
                "resolves_extra_bytes_count": int(kind_stats["resolves_extra_bytes_count"]),
                "retains_base_consumed_offset_count": int(kind_stats["retains_base_consumed_offset_count"]),
                "hint_step_found_count": int(kind_stats["hint_step_found_count"]),
                "string_immediate_count": int(kind_stats["string_immediate_count"]),
                "total_consumed_offset": int(kind_stats["total_consumed_offset"]),
                "max_consumed_offset": int(kind_stats["max_consumed_offset"]),
                "next_frontier_trace_count": int(kind_stats["next_frontier_trace_count"]),
                "relative_target_count": int(kind_stats["relative_target_count"]),
                "relative_target_in_bounds_count": int(kind_stats["relative_target_in_bounds_count"]),
                "relative_target_instruction_boundary_count": int(
                    kind_stats["relative_target_instruction_boundary_count"]
                ),
                "relative_target_terminal_count": int(kind_stats["relative_target_terminal_count"]),
                "relative_target_forward_count": int(kind_stats["relative_target_forward_count"]),
                "relative_target_backward_count": int(kind_stats["relative_target_backward_count"]),
                "relative_target_self_count": int(kind_stats["relative_target_self_count"]),
                "trace_samples": kind_stats["trace_samples"][:6],
            }
            string_immediate_samples = kind_stats.get("string_immediate_samples")
            if isinstance(string_immediate_samples, list) and string_immediate_samples:
                candidate_entry["string_immediate_samples"] = string_immediate_samples[:6]
            next_frontier_counts = kind_stats.get("next_frontier_counts")
            if isinstance(next_frontier_counts, dict) and next_frontier_counts:
                candidate_entry["next_frontier_sample"] = [
                    {
                        "raw_opcode": int(next_raw_opcode),
                        "raw_opcode_hex": f"0x{int(next_raw_opcode):04X}",
                        "count": int(count),
                    }
                    for next_raw_opcode, count in sorted(
                        next_frontier_counts.items(),
                        key=lambda item: (-int(item[1]), int(item[0])),
                    )[:6]
                ]
            for counts_key, output_key, value_label in (
                ("probe_semantic_label_counts", "probe_semantic_label_sample", "label"),
                ("probe_semantic_family_counts", "probe_semantic_family_sample", "family"),
                ("probe_control_flow_kind_counts", "probe_control_flow_kind_sample", "kind"),
            ):
                counts = kind_stats.get(counts_key)
                if isinstance(counts, dict) and counts:
                    candidate_entry[output_key] = [
                        {
                            value_label: str(value),
                            "count": int(count),
                        }
                        for value, count in sorted(
                            counts.items(),
                            key=lambda item: (-int(item[1]), str(item[0])),
                        )[:6]
                    ]
            relative_target_samples = kind_stats.get("relative_target_samples")
            if isinstance(relative_target_samples, list) and relative_target_samples:
                candidate_entry["relative_target_sample"] = relative_target_samples[:6]
            immediate_kind_candidates.append(candidate_entry)

        immediate_kind_candidates.sort(
            key=lambda candidate: (
                _clientscript_tail_hint_kind_rank(candidate),
                str(candidate.get("immediate_kind", "")),
            ),
            reverse=True,
        )

        entry: dict[str, object] = {
            "raw_opcode": int(raw_opcode),
            "raw_opcode_hex": f"0x{int(raw_opcode):04X}",
            "script_count": int(stats["script_count"]),
            "key_sample": stats["key_samples"][:8],
            "script_samples": stats["script_samples"][:8],
            "immediate_kind_candidates": immediate_kind_candidates,
        }
        for field in ("semantic_label", "semantic_family", "control_flow_kind", "jump_base"):
            value = stats.get(field)
            if isinstance(value, str) and value:
                entry[field] = value
        jump_scale = stats.get("jump_scale")
        if isinstance(jump_scale, int):
            entry["jump_scale"] = jump_scale
        operand_signature_counts = stats.get("operand_signature_counts")
        if isinstance(operand_signature_counts, dict) and operand_signature_counts:
            entry["operand_signature_sample"] = [
                {
                    "signature": signature,
                    "count": count,
                }
                for signature, count in sorted(
                    operand_signature_counts.items(),
                    key=lambda item: (-int(item[1]), str(item[0])),
                )[:6]
            ]
        base_trace_status_counts = stats.get("base_trace_status_counts")
        if isinstance(base_trace_status_counts, dict) and base_trace_status_counts:
            entry["base_trace_status_sample"] = [
                {
                    "status": status,
                    "count": count,
                }
                for status, count in sorted(
                    base_trace_status_counts.items(),
                    key=lambda item: (-int(item[1]), str(item[0])),
                )[:6]
            ]

        inferred = _infer_clientscript_tail_hint_candidate(entry)
        if not inferred:
            inferred = _infer_clientscript_tail_hint_branch_candidate(entry)
        if inferred:
            entry.update(inferred)
            selected_candidate_count += 1
        catalog[int(raw_opcode)] = entry

    summary = {
        "tail_hint_opcode_count": len(catalog),
        "tail_extra_bytes_script_count": tail_extra_bytes_script_count,
        "selected_candidate_count": selected_candidate_count,
        "catalog_sample": sorted(
            catalog.values(),
            key=lambda entry: (
                -int("candidate_mnemonic" in entry),
                -int(entry.get("script_count", 0)),
                int(entry["raw_opcode"]),
            ),
        )[:24],
    }
    return catalog, summary


def _promote_clientscript_tail_hint_candidates(
    tail_hint_candidates: dict[int, dict[str, object]],
) -> dict[int, dict[str, object]]:
    promoted: dict[int, dict[str, object]] = {}

    for raw_opcode, entry in sorted(tail_hint_candidates.items()):
        mnemonic = entry.get("candidate_mnemonic")
        immediate_kind = entry.get("suggested_immediate_kind")
        confidence = entry.get("suggested_immediate_kind_confidence", entry.get("candidate_confidence"))
        family = entry.get("family")
        if mnemonic not in {"PUSH_CONST_STRING_CANDIDATE", "JUMP_OFFSET_FRONTIER_CANDIDATE"}:
            continue
        if mnemonic == "PUSH_CONST_STRING_CANDIDATE" and immediate_kind != "string":
            continue
        if mnemonic == "JUMP_OFFSET_FRONTIER_CANDIDATE" and immediate_kind != "short":
            continue

        promoted_entry: dict[str, object] = {
            "mnemonic": str(mnemonic),
            "immediate_kind": str(immediate_kind),
            "status": "promoted-candidate",
            "promotion_source": "tail-hint",
        }
        if isinstance(family, str) and family:
            promoted_entry["family"] = family
        if isinstance(confidence, (int, float)):
            promoted_entry["confidence"] = float(confidence)
        if mnemonic == "JUMP_OFFSET_FRONTIER_CANDIDATE":
            for field in ("control_flow_kind", "jump_base"):
                value = entry.get(field)
                if isinstance(value, str) and value:
                    promoted_entry[field] = value
            jump_scale = entry.get("jump_scale")
            if isinstance(jump_scale, int):
                promoted_entry["jump_scale"] = jump_scale
        promoted[int(raw_opcode)] = promoted_entry

    return promoted


def _build_clientscript_semantic_suggestions(
    control_flow_candidates: dict[int, dict[str, object]],
    contextual_frontier_candidates: dict[int, dict[str, object]] | None = None,
    string_frontier_candidates: dict[int, dict[str, object]] | None = None,
    string_transform_arity_candidates: dict[int, dict[str, object]] | None = None,
    tail_hint_candidates: dict[int, dict[str, object]] | None = None,
) -> dict[str, dict[str, object]]:
    suggestions: dict[str, dict[str, object]] = {}

    def suggestion_key(raw_opcode: int) -> str:
        return f"0x{int(raw_opcode):04X}"

    def suggestion_confidence(suggestion: dict[str, object] | None) -> float:
        if not isinstance(suggestion, dict):
            return 0.0
        value = suggestion.get("confidence")
        if not isinstance(value, (int, float)):
            return 0.0
        return float(value)

    def merge_suggestion(raw_opcode: int, suggestion: dict[str, object], *, replace_margin: float = 0.0) -> None:
        key = suggestion_key(raw_opcode)
        existing = suggestions.get(key)
        if isinstance(existing, dict):
            existing_mnemonic = existing.get("mnemonic")
            incoming_mnemonic = suggestion.get("mnemonic")
            if _should_promote_clientscript_arity_candidate(existing_mnemonic, incoming_mnemonic):
                suggestions[key] = suggestion
                return
        if existing is not None and suggestion_confidence(existing) > suggestion_confidence(suggestion) + replace_margin:
            return
        suggestions[key] = suggestion

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
        if not isinstance(immediate_kind, str) or immediate_kind not in CLIENTSCRIPT_SUPPORTED_IMMEDIATE_TYPES:
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
        merge_suggestion(raw_opcode, suggestion)

    if contextual_frontier_candidates:
        for raw_opcode, entry in sorted(contextual_frontier_candidates.items()):
            mnemonic = entry.get("candidate_mnemonic")
            immediate_kind = entry.get("suggested_immediate_kind")
            family = entry.get("family")
            if str(mnemonic) != "INT_STATE_GETTER_CANDIDATE":
                continue
            if not isinstance(immediate_kind, str) or immediate_kind not in CLIENTSCRIPT_SUPPORTED_IMMEDIATE_TYPES:
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
            merge_suggestion(raw_opcode, suggestion)

    if string_frontier_candidates:
        for raw_opcode, entry in sorted(string_frontier_candidates.items()):
            mnemonic = entry.get("candidate_mnemonic")
            immediate_kind = entry.get("suggested_immediate_kind")
            family = entry.get("family")
            if str(mnemonic) != "PUSH_CONST_STRING_CANDIDATE":
                continue
            if not isinstance(immediate_kind, str) or immediate_kind not in CLIENTSCRIPT_SUPPORTED_IMMEDIATE_TYPES:
                continue
            confidence = entry.get("suggested_immediate_kind_confidence", entry.get("candidate_confidence"))
            if not isinstance(confidence, (int, float)) or float(confidence) < 0.72:
                continue
            if int(entry.get("script_count", 0)) < 2 and int(entry.get("complete_trace_count", 0)) <= 0:
                continue

            suggestion = {
                "mnemonic": str(mnemonic),
                "immediate_kind": immediate_kind,
            }
            if isinstance(family, str) and family:
                suggestion["family"] = family
            suggestion["confidence"] = float(confidence)
            reasons = entry.get("candidate_reasons")
            if isinstance(reasons, list):
                normalized_reasons = [str(reason) for reason in reasons if str(reason)]
                if normalized_reasons:
                    suggestion["notes"] = " ".join(normalized_reasons)
            merge_suggestion(raw_opcode, suggestion)

    if string_transform_arity_candidates:
        for raw_opcode, entry in sorted(string_transform_arity_candidates.items()):
            candidate_profile = entry.get("candidate_arity_profile")
            if not isinstance(candidate_profile, dict) or not candidate_profile:
                continue

            mnemonic = candidate_profile.get("candidate_mnemonic")
            immediate_kind = entry.get("immediate_kind", entry.get("suggested_immediate_kind"))
            family = candidate_profile.get("family", entry.get("family"))
            confidence = candidate_profile.get("confidence")
            match_count = candidate_profile.get("match_count", candidate_profile.get("eligible_sample_count", 0))
            if not isinstance(mnemonic, str) or not mnemonic:
                continue
            if not isinstance(immediate_kind, str) or immediate_kind not in CLIENTSCRIPT_SUPPORTED_IMMEDIATE_TYPES:
                continue
            if not isinstance(confidence, (int, float)) or float(confidence) < 0.78:
                continue
            if not isinstance(match_count, int) or match_count < 2:
                continue

            suggestion = {
                "mnemonic": mnemonic,
                "immediate_kind": immediate_kind,
                "confidence": float(confidence),
                "promotion_source": "string-transform-arity",
            }
            if isinstance(family, str) and family:
                suggestion["family"] = family
            notes_parts: list[str] = []
            notes = candidate_profile.get("notes")
            if isinstance(notes, str) and notes:
                notes_parts.append(notes)
            signature = candidate_profile.get("signature")
            if isinstance(signature, str) and signature:
                notes_parts.append(f"Operand signature: {signature}.")
            if notes_parts:
                suggestion["notes"] = " ".join(notes_parts)
            operand_signature_candidate = candidate_profile.get("operand_signature_candidate")
            if isinstance(operand_signature_candidate, dict) and operand_signature_candidate:
                suggestion["operand_signature_candidate"] = dict(operand_signature_candidate)
            stack_effect_candidate = candidate_profile.get("stack_effect_candidate")
            if isinstance(stack_effect_candidate, dict) and stack_effect_candidate:
                suggestion["stack_effect_candidate"] = dict(stack_effect_candidate)
            existing = suggestions.get(suggestion_key(raw_opcode))
            existing_mnemonic = existing.get("mnemonic") if isinstance(existing, dict) else None
            if existing_mnemonic == "CONTROL_FLOW_FRONTIER_CANDIDATE":
                suggestions[suggestion_key(raw_opcode)] = suggestion
                continue
            merge_suggestion(raw_opcode, suggestion, replace_margin=0.05)

    if tail_hint_candidates:
        for raw_opcode, entry in sorted(tail_hint_candidates.items()):
            mnemonic = entry.get("candidate_mnemonic")
            immediate_kind = entry.get("suggested_immediate_kind")
            family = entry.get("family")
            if str(mnemonic) not in {"PUSH_CONST_STRING_CANDIDATE", "JUMP_OFFSET_FRONTIER_CANDIDATE"}:
                continue
            if not isinstance(immediate_kind, str) or immediate_kind not in CLIENTSCRIPT_SUPPORTED_IMMEDIATE_TYPES:
                continue
            if str(mnemonic) == "PUSH_CONST_STRING_CANDIDATE" and immediate_kind != "string":
                continue
            if str(mnemonic) == "JUMP_OFFSET_FRONTIER_CANDIDATE" and immediate_kind != "short":
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
            if str(mnemonic) == "JUMP_OFFSET_FRONTIER_CANDIDATE":
                for field in ("control_flow_kind", "jump_base"):
                    value = entry.get(field)
                    if isinstance(value, str) and value:
                        suggestion[field] = value
                jump_scale = entry.get("jump_scale")
                if isinstance(jump_scale, int):
                    suggestion["jump_scale"] = jump_scale
            merge_suggestion(raw_opcode, suggestion)

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
        if isinstance(immediate_kind, str) and immediate_kind in CLIENTSCRIPT_SUPPORTED_IMMEDIATE_TYPES:
            augmented[int(raw_opcode)] = immediate_kind
    for raw_opcode, entry in CLIENTSCRIPT_BUILTIN_OPCODE_HINTS.items():
        immediate_kind = entry.get("immediate_kind", entry.get("suggested_immediate_kind"))
        if isinstance(immediate_kind, str) and immediate_kind in CLIENTSCRIPT_SUPPORTED_IMMEDIATE_TYPES:
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
    if isinstance(suggested_immediate_kind, str) and suggested_immediate_kind in CLIENTSCRIPT_SUPPORTED_IMMEDIATE_TYPES:
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
    if isinstance(suggested_immediate_kind, str) and suggested_immediate_kind in CLIENTSCRIPT_SUPPORTED_IMMEDIATE_TYPES:
        entry["suggested_override"] = {
            "mnemonic": "SWITCH_CASE_ACTION_CANDIDATE",
            "family": "payload-action",
            "immediate_kind": suggested_immediate_kind,
        }


def _refine_clientscript_consumed_operand_role_candidate(entry: dict[str, object]) -> None:
    consumed_signature_sample = entry.get("consumed_operand_signature_sample")
    if not isinstance(consumed_signature_sample, list) or not consumed_signature_sample:
        return

    first_signature = consumed_signature_sample[0]
    if not isinstance(first_signature, dict):
        return
    signature = str(first_signature.get("signature", ""))
    if not signature:
        return

    mnemonic = str(entry.get("candidate_mnemonic", ""))
    suggested_immediate_kind = entry.get("suggested_immediate_kind")
    reasons = [
        str(reason)
        for reason in entry.get("candidate_reasons", [])
        if str(reason)
    ]

    def _apply_role(candidate_mnemonic: str, family: str, confidence: float, reason: str) -> None:
        entry["candidate_mnemonic"] = candidate_mnemonic
        entry["family"] = family
        entry["candidate_confidence"] = round(max(float(entry.get("candidate_confidence", 0.0)), confidence), 2)
        entry["candidate_reasons"] = reasons + [reason]
        if isinstance(suggested_immediate_kind, str) and suggested_immediate_kind in CLIENTSCRIPT_SUPPORTED_IMMEDIATE_TYPES:
            entry["suggested_override"] = {
                "mnemonic": candidate_mnemonic,
                "family": family,
                "immediate_kind": suggested_immediate_kind,
            }

    def _infer_string_action_subtype() -> dict[str, object] | None:
        sample_values = _extract_clientscript_string_operand_values(entry)
        if not sample_values:
            return None

        url_like_values = [value for value in sample_values if _looks_like_clientscript_url_string(value)]
        if url_like_values and len(url_like_values) * 2 >= len(sample_values):
            return {
                "candidate_mnemonic": "STRING_URL_ACTION_CANDIDATE",
                "family": "string-url-action",
                "confidence": 0.75,
                "reason": "Consumed string samples look like URL payloads, which fits a global link-launch or URL-targeted string action more closely than a generic string sink.",
            }

        message_like_values = [value for value in sample_values if _looks_like_clientscript_message_string(value)]
        if message_like_values and len(message_like_values) * 2 >= len(sample_values):
            return {
                "candidate_mnemonic": "STRING_MESSAGE_ACTION_CANDIDATE",
                "family": "string-message-action",
                "confidence": 0.72,
                "reason": "Consumed string samples look like human-readable message text, which fits a global message-style string sink more closely than a generic string action.",
            }
        return None

    if mnemonic == "WIDGET_MUTATOR_CANDIDATE":
        if signature == "widget+widget":
            _apply_role(
                "WIDGET_LINK_MUTATOR_CANDIDATE",
                "widget-link-action",
                0.76,
                "Consumed operand window shows two widget references, which fits a widget-linking or hierarchy-style mutator more closely than a generic widget action.",
            )
            return
        if signature == "widget+state-int":
            _apply_role(
                "WIDGET_STATE_MUTATOR_CANDIDATE",
                "widget-state-action",
                0.76,
                "Consumed operand window shows a widget reference paired with a state-derived integer, which fits a widget configuration or state-application mutator.",
            )
            return
        if signature == "widget+int+string":
            _apply_role(
                "WIDGET_EVENT_BINDER_CANDIDATE",
                "widget-event-action",
                0.8,
                "Consumed operand window includes a widget reference, string data, and an extra integer-like argument, which fits an event-binding or action-routing widget opcode more closely than a plain text mutator.",
            )
            return
        if signature == "widget+string":
            _apply_role(
                "WIDGET_TEXT_MUTATOR_CANDIDATE",
                "widget-text-action",
                0.77,
                "Consumed operand window includes a widget reference plus string data, which fits a text-bearing widget mutator more closely than a generic widget action.",
            )
            return
        if signature == "widget-only":
            _apply_role(
                "WIDGET_ATOMIC_ACTION_CANDIDATE",
                "widget-atomic-action",
                0.72,
                "Consumed operand window shows only a widget target, which fits an atomic widget action that does not require an extra value argument.",
            )
            return

    if mnemonic in {"SWITCH_CASE_ACTION_CANDIDATE", "STRING_ACTION_CANDIDATE"}:
        secondary_kind_sample = entry.get("consumed_secondary_int_kind_sample")
        secondary_kind = None
        if isinstance(secondary_kind_sample, list) and secondary_kind_sample and isinstance(secondary_kind_sample[0], dict):
            secondary_kind = str(secondary_kind_sample[0].get("kind", ""))
        if signature == "int+string":
            _apply_role(
                "STRING_FORMATTER_CANDIDATE",
                "string-transform-action",
                0.71,
                "Consumed operand window shows one string plus one integer-like value, which fits a formatter or parameterized string transform better than a generic case payload.",
            )
            return
        if signature == "string+string":
            _apply_role(
                "STRING_FORMATTER_CANDIDATE",
                "string-transform-action",
                0.73,
                "Consumed operand window shows two string values, which fits a concatenation or string-merge transform better than a generic case payload.",
            )
            return
        if signature == "string-only":
            string_action_subtype = _infer_string_action_subtype()
            if string_action_subtype is not None:
                _apply_role(
                    str(string_action_subtype.get("candidate_mnemonic", "STRING_ACTION_CANDIDATE")),
                    str(string_action_subtype.get("family", "string-action")),
                    float(string_action_subtype.get("confidence", 0.67)),
                    str(string_action_subtype.get("reason", "")),
                )
                return
            if mnemonic == "STRING_ACTION_CANDIDATE":
                return
            _apply_role(
                "STRING_ACTION_CANDIDATE",
                "string-action",
                0.67,
                "Consumed operand window shows string-only input, which fits a string transform or string-targeted action better than a generic case payload.",
            )
            return
        if signature == "int-only" and secondary_kind == "state-int":
            _apply_role(
                "STATE_VALUE_ACTION_CANDIDATE",
                "state-action",
                0.66,
                "Consumed operand window shows a state-derived integer paired with another integer value, which fits a state-fed payload action better than a generic case body side effect.",
            )


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
            (
                mnemonic == "WIDGET_MUTATOR_CANDIDATE"
                or str(entry.get("family", "")).startswith("widget")
            )
            and int(entry.get("switch_script_count", 0)) > 0
            and isinstance(entry.get("candidate_confidence"), (int, float))
            and float(entry["candidate_confidence"]) >= 0.62
        )
        is_state_payload_candidate = (
            mnemonic == "STATE_VALUE_ACTION_CANDIDATE"
            and int(entry.get("switch_script_count", 0)) > 0
            and isinstance(entry.get("candidate_confidence"), (int, float))
            and float(entry["candidate_confidence"]) >= 0.62
        )
        is_string_payload_candidate = (
            str(entry.get("family", "")).startswith("string")
            and int(entry.get("switch_script_count", 0)) > 0
            and isinstance(entry.get("candidate_confidence"), (int, float))
            and float(entry["candidate_confidence"]) >= 0.62
        )
        if (
            not is_switch_candidate
            and not is_jump_candidate
            and not is_widget_mutator_candidate
            and not is_state_payload_candidate
            and not is_string_payload_candidate
        ):
            continue
        immediate_kind = entry.get("suggested_immediate_kind")
        family = entry.get("family")
        if not isinstance(immediate_kind, str) or immediate_kind not in CLIENTSCRIPT_SUPPORTED_IMMEDIATE_TYPES:
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
            incoming_entry = dict(entry)
            incoming_entry["analysis_stage"] = stage_name
            _merge_clientscript_catalog_entry(combined, normalized_opcode, incoming_entry)
            combined[normalized_opcode][stage_flag] = True
            continue

        merged_entry = dict(entry)
        merged_entry["analysis_stage"] = stage_name
        merged_entry[stage_flag] = True
        combined[normalized_opcode] = merged_entry


def _combine_clientscript_control_flow_candidates(
    initial_candidates: dict[int, dict[str, object]],
    post_contextual_candidates: dict[int, dict[str, object]],
    recursive_candidates: dict[int, dict[str, object]] | None = None,
    post_string_candidates: dict[int, dict[str, object]] | None = None,
    post_tail_hint_candidates: dict[int, dict[str, object]] | None = None,
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
    if post_string_candidates:
        _merge_clientscript_control_flow_candidate_stage(
            combined,
            post_string_candidates,
            stage_name="post-string",
        )
    if post_tail_hint_candidates:
        _merge_clientscript_control_flow_candidate_stage(
            combined,
            post_tail_hint_candidates,
            stage_name="post-tail-hint",
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
        if not isinstance(immediate_kind, str) or immediate_kind not in CLIENTSCRIPT_SUPPORTED_IMMEDIATE_TYPES:
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
    existing_label = existing_entry.get("mnemonic", existing_entry.get("candidate_mnemonic"))
    incoming_label = entry.get("mnemonic", entry.get("candidate_mnemonic"))
    prefer_incoming = _should_promote_clientscript_arity_candidate(existing_label, incoming_label)
    merged_entry = dict(existing_entry)
    if prefer_incoming:
        merged_entry.update(entry)
    else:
        for field, value in entry.items():
            if field not in merged_entry or merged_entry[field] in (None, "", {}, []):
                merged_entry[field] = value
    existing_subtypes = existing_entry.get("subtypes") if isinstance(existing_entry, dict) else None
    incoming_subtypes = entry.get("subtypes")
    if isinstance(existing_subtypes, dict) or isinstance(incoming_subtypes, dict):
        merged_subtypes: dict[int, dict[str, object]] = {}
        if isinstance(existing_subtypes, dict):
            for sub_opcode, sub_entry in existing_subtypes.items():
                parsed_sub_opcode = _parse_clientscript_opcode_key(sub_opcode)
                if parsed_sub_opcode is None or not isinstance(sub_entry, dict):
                    continue
                merged_subtypes[int(parsed_sub_opcode)] = dict(sub_entry)
        if isinstance(incoming_subtypes, dict):
            for sub_opcode, sub_entry in incoming_subtypes.items():
                parsed_sub_opcode = _parse_clientscript_opcode_key(sub_opcode)
                if parsed_sub_opcode is None or not isinstance(sub_entry, dict):
                    continue
                existing_sub_entry = merged_subtypes.get(int(parsed_sub_opcode))
                if existing_sub_entry is None:
                    merged_subtypes[int(parsed_sub_opcode)] = dict(sub_entry)
                    continue
                merged_sub_entry = dict(existing_sub_entry)
                merged_sub_entry.update(sub_entry)
                merged_subtypes[int(parsed_sub_opcode)] = merged_sub_entry
        if merged_subtypes:
            merged_entry["subtypes"] = merged_subtypes
    catalog[raw_opcode] = merged_entry


def _seed_clientscript_catalog_with_semantic_overrides(
    catalog: dict[int, dict[str, object]],
    semantic_overrides: dict[int, dict[str, object]],
) -> None:
    for raw_opcode, override_entry in semantic_overrides.items():
        if not isinstance(override_entry, dict):
            continue
        seeded_entry = {
            "raw_opcode": int(raw_opcode),
            "raw_opcode_hex": f"0x{int(raw_opcode):04X}",
            "override": True,
            **override_entry,
        }
        _merge_clientscript_catalog_entry(catalog, int(raw_opcode), seeded_entry)


def _should_promote_clientscript_arity_candidate(
    current_label: object,
    promoted_label: object,
) -> bool:
    if not isinstance(promoted_label, str) or not promoted_label:
        return False
    if current_label == promoted_label:
        return False
    if not isinstance(current_label, str) or not current_label:
        return True
    return current_label in {
        "CONTROL_FLOW_FRONTIER_CANDIDATE",
        "STRING_RESULT_CHAIN_CANDIDATE",
        "STRING_FORMATTER_FRONTIER_CANDIDATE",
        "WIDGET_TEXT_MUTATOR_FRONTIER_CANDIDATE",
    }


def _build_clientscript_effective_semantic_suggestions(
    semantic_suggestions: dict[str, dict[str, object]],
    *,
    semantic_overrides: dict[int, dict[str, object]] | None = None,
    raw_opcode_catalog: dict[int, dict[str, object]] | None = None,
) -> dict[str, dict[str, object]]:
    effective = {
        str(raw_key): dict(entry)
        for raw_key, entry in semantic_suggestions.items()
        if isinstance(entry, dict)
    }

    def add_entry(raw_opcode: int, entry: dict[str, object], *, prefer_existing: bool) -> None:
        mnemonic = entry.get("mnemonic", entry.get("candidate_mnemonic"))
        immediate_kind = entry.get("immediate_kind", entry.get("suggested_immediate_kind"))
        if not isinstance(mnemonic, str) or not mnemonic:
            return
        if not isinstance(immediate_kind, str) or immediate_kind not in CLIENTSCRIPT_SUPPORTED_IMMEDIATE_TYPES:
            return

        normalized_entry: dict[str, object] = {
            "mnemonic": mnemonic,
            "immediate_kind": immediate_kind,
        }
        for field in (
            "family",
            "notes",
            "status",
            "control_flow_kind",
            "jump_base",
            "promotion_source",
        ):
            field_value = entry.get(field)
            if isinstance(field_value, str) and field_value:
                normalized_entry[field] = field_value
        canonical_id = entry.get("canonical_id")
        if isinstance(canonical_id, int):
            normalized_entry["canonical_id"] = canonical_id
        jump_scale = entry.get("jump_scale")
        if isinstance(jump_scale, int):
            normalized_entry["jump_scale"] = jump_scale
        confidence = entry.get("confidence", entry.get("candidate_confidence"))
        if isinstance(confidence, (int, float)):
            normalized_entry["confidence"] = float(confidence)
        aliases = entry.get("aliases")
        if isinstance(aliases, list):
            normalized_aliases = [str(alias) for alias in aliases if str(alias)]
            if normalized_aliases:
                normalized_entry["aliases"] = normalized_aliases
        operand_signature_candidate = entry.get("operand_signature_candidate")
        if isinstance(operand_signature_candidate, dict) and operand_signature_candidate:
            normalized_entry["operand_signature_candidate"] = dict(operand_signature_candidate)
        stack_effect_candidate = entry.get("stack_effect_candidate")
        if isinstance(stack_effect_candidate, dict) and stack_effect_candidate:
            normalized_entry["stack_effect_candidate"] = dict(stack_effect_candidate)

        suggestion_key = f"0x{int(raw_opcode):04X}"
        existing_entry = effective.get(suggestion_key)
        existing_label = (
            existing_entry.get("mnemonic")
            if isinstance(existing_entry, dict)
            else None
        )
        if isinstance(existing_entry, dict):
            if prefer_existing:
                if not _should_promote_clientscript_arity_candidate(existing_label, mnemonic):
                    return
            elif _should_promote_clientscript_arity_candidate(mnemonic, existing_label):
                return
        effective[suggestion_key] = normalized_entry

    if raw_opcode_catalog:
        for raw_opcode, entry in raw_opcode_catalog.items():
            if isinstance(entry, dict):
                add_entry(int(raw_opcode), entry, prefer_existing=True)

    if semantic_overrides:
        for raw_opcode, entry in semantic_overrides.items():
            if isinstance(entry, dict):
                add_entry(int(raw_opcode), entry, prefer_existing=False)

    return effective


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
        _refine_clientscript_string_payload_frontier_candidate(entry)
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
            _refine_clientscript_consumed_operand_role_candidate(entry)
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
            if immediate_kind not in CLIENTSCRIPT_SUPPORTED_IMMEDIATE_TYPES:
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


def _build_clientscript_string_frontier_candidates(
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
    frontier_stats_by_opcode: dict[int, dict[str, object]] = {}
    string_rich_script_count = 0
    frontier_script_count = 0

    for key, layout in candidates:
        string_metadata_score = int(layout.local_string_count) + int(layout.string_argument_count)
        if string_metadata_score <= 0:
            continue
        string_rich_script_count += 1

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

        instruction_steps = prefix_trace.get("steps", [])
        if not isinstance(instruction_steps, list):
            instruction_steps = []
        previous_step = instruction_steps[-1] if instruction_steps else None
        previous_label = str(previous_step.get("semantic_label", "")) if isinstance(previous_step, dict) else ""
        prefix_stack_summary = _summarize_clientscript_prefix_stack_state(instruction_steps)

        stats = frontier_stats_by_opcode.setdefault(
            raw_opcode,
            {
                "script_count": 0,
                "string_argument_script_count": 0,
                "local_string_script_count": 0,
                "frontier_offsets": [],
                "frontier_instruction_indices": [],
                "reason_counts": {},
                "key_samples": [],
                "script_samples": [],
                "previous_semantic_label_counts": {},
                "prefix_string_operand_script_count": 0,
                "prefix_operand_signature_counts": {},
                "immediate_kind_scores": {},
            },
        )
        stats["script_count"] = int(stats["script_count"]) + 1
        if int(layout.string_argument_count) > 0:
            stats["string_argument_script_count"] = int(stats["string_argument_script_count"]) + 1
        if int(layout.local_string_count) > 0:
            stats["local_string_script_count"] = int(stats["local_string_script_count"]) + 1
        if int(prefix_stack_summary.get("prefix_string_stack_count", 0)) > 0:
            stats["prefix_string_operand_script_count"] = int(stats["prefix_string_operand_script_count"]) + 1

        operand_signature = prefix_stack_summary.get("prefix_operand_signature")
        if isinstance(operand_signature, str) and operand_signature:
            signature_counts = stats["prefix_operand_signature_counts"]
            signature_counts[operand_signature] = int(signature_counts.get(operand_signature, 0)) + 1

        reason = str(prefix_trace.get("frontier_reason", ""))
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
                    "local_string_count": layout.local_string_count,
                    "string_argument_count": layout.string_argument_count,
                    "frontier_reason": reason,
                    "frontier_offset": frontier_offset,
                    "frontier_instruction_index": frontier_instruction_index,
                    "decoded_prefix_instruction_count": int(prefix_trace["decoded_instruction_count"]),
                    "previous_semantic_label": previous_label or None,
                    "prefix_operand_signature": prefix_stack_summary.get("prefix_operand_signature"),
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
            probe_immediate_kinds=("string",),
        )
        string_score = kind_scores.get("string")
        if not isinstance(string_score, dict):
            continue
        kind_stats = stats["immediate_kind_scores"].setdefault(
            "string",
            {
                "script_count": 0,
                "valid_trace_count": 0,
                "invalid_immediate_count": 0,
                "complete_trace_count": 0,
                "improved_script_count": 0,
                "total_decoded_instruction_count": 0,
                "total_progress_instruction_count": 0,
                "max_decoded_instruction_count": 0,
                "next_frontier_trace_count": 0,
                "next_frontier_counts": {},
                "trace_samples": [],
            },
        )
        kind_stats["script_count"] = int(kind_stats["script_count"]) + 1
        if bool(string_score["valid_trace"]):
            kind_stats["valid_trace_count"] = int(kind_stats["valid_trace_count"]) + 1
        else:
            kind_stats["invalid_immediate_count"] = int(kind_stats["invalid_immediate_count"]) + 1
        if string_score.get("trace_status") == "complete":
            kind_stats["complete_trace_count"] = int(kind_stats["complete_trace_count"]) + 1

        progress_instruction_count = int(string_score["progress_instruction_count"])
        if progress_instruction_count > 0:
            kind_stats["improved_script_count"] = int(kind_stats["improved_script_count"]) + 1
        kind_stats["total_decoded_instruction_count"] = (
            int(kind_stats["total_decoded_instruction_count"]) + int(string_score["decoded_instruction_count"])
        )
        kind_stats["total_progress_instruction_count"] = (
            int(kind_stats["total_progress_instruction_count"]) + progress_instruction_count
        )
        kind_stats["max_decoded_instruction_count"] = max(
            int(kind_stats["max_decoded_instruction_count"]),
            int(string_score["decoded_instruction_count"]),
        )
        next_frontier_raw_opcode = string_score.get("next_frontier_raw_opcode")
        if isinstance(next_frontier_raw_opcode, int):
            kind_stats["next_frontier_trace_count"] = int(kind_stats["next_frontier_trace_count"]) + 1
            next_frontier_counts = kind_stats["next_frontier_counts"]
            next_frontier_counts[next_frontier_raw_opcode] = int(
                next_frontier_counts.get(next_frontier_raw_opcode, 0)
            ) + 1
        if len(kind_stats["trace_samples"]) < 6:
            kind_stats["trace_samples"].append(
                {
                    "key": int(key),
                    "trace_status": string_score.get("trace_status"),
                    "frontier_reason": string_score.get("frontier_reason"),
                    "decoded_instruction_count": int(string_score["decoded_instruction_count"]),
                    "progress_instruction_count": progress_instruction_count,
                    "next_frontier_raw_opcode_hex": string_score.get("next_frontier_raw_opcode_hex"),
                }
            )

    catalog: dict[int, dict[str, object]] = {}
    for raw_opcode, stats in frontier_stats_by_opcode.items():
        string_stats = stats["immediate_kind_scores"].get("string")
        if not isinstance(string_stats, dict):
            continue
        improved_script_count = int(string_stats.get("improved_script_count", 0))
        if improved_script_count <= 0:
            continue

        confidence = round(
            min(
                0.9,
                0.42
                + min(improved_script_count, 4) * 0.09
                + min(int(string_stats.get("total_progress_instruction_count", 0)), 16) * 0.02
                + (0.08 if int(string_stats.get("complete_trace_count", 0)) > 0 else 0.0)
                + (0.04 if int(stats.get("string_argument_script_count", 0)) > 0 else 0.0),
            ),
            2,
        )
        reasons = [
            "String-rich scripts can continue decoding only when this unresolved opcode is treated as a null-terminated CP1252 string immediate.",
            "The string probe is isolated to the frontier analysis pass, so it can surface text opcodes without widening the default opcode calibration search.",
        ]
        if int(stats.get("string_argument_script_count", 0)) > 0:
            reasons.append("Affected scripts already declare string arguments, which strengthens the case for an inline string-producing opcode.")
        if int(string_stats.get("complete_trace_count", 0)) > 0:
            reasons.append("At least one string probe reaches a complete trace, which is strong evidence for a direct string constant push.")

        entry: dict[str, object] = {
            "raw_opcode": raw_opcode,
            "raw_opcode_hex": f"0x{raw_opcode:04X}",
            "script_count": stats["script_count"],
            "string_argument_script_count": stats["string_argument_script_count"],
            "local_string_script_count": stats["local_string_script_count"],
            "frontier_offsets_sample": stats["frontier_offsets"],
            "frontier_instruction_index_sample": stats["frontier_instruction_indices"],
            "reason_counts": stats["reason_counts"],
            "key_sample": stats["key_samples"],
            "script_samples": stats["script_samples"],
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
            "prefix_string_operand_script_count": stats["prefix_string_operand_script_count"],
            "prefix_operand_signature_sample": [
                {
                    "signature": signature,
                    "count": count,
                }
                for signature, count in sorted(
                    stats["prefix_operand_signature_counts"].items(),
                    key=lambda item: (-int(item[1]), str(item[0])),
                )[:6]
            ],
            "immediate_kind_candidates": [
                {
                    "immediate_kind": "string",
                    "script_count": string_stats["script_count"],
                    "valid_trace_count": string_stats["valid_trace_count"],
                    "invalid_immediate_count": string_stats["invalid_immediate_count"],
                    "complete_trace_count": string_stats["complete_trace_count"],
                    "improved_script_count": string_stats["improved_script_count"],
                    "total_decoded_instruction_count": string_stats["total_decoded_instruction_count"],
                    "total_progress_instruction_count": string_stats["total_progress_instruction_count"],
                    "max_decoded_instruction_count": string_stats["max_decoded_instruction_count"],
                    "next_frontier_trace_count": string_stats["next_frontier_trace_count"],
                    "next_frontier_sample": [
                        {
                            "raw_opcode": next_frontier_opcode,
                            "raw_opcode_hex": f"0x{next_frontier_opcode:04X}",
                            "count": count,
                        }
                        for next_frontier_opcode, count in sorted(
                            string_stats["next_frontier_counts"].items(),
                            key=lambda item: (-int(item[1]), int(item[0])),
                        )[:6]
                    ],
                    "trace_samples": string_stats["trace_samples"],
                }
            ],
            "complete_trace_count": string_stats["complete_trace_count"],
            "improved_script_count": string_stats["improved_script_count"],
            "total_progress_instruction_count": string_stats["total_progress_instruction_count"],
            "next_frontier_trace_count": string_stats["next_frontier_trace_count"],
            "candidate_mnemonic": "PUSH_CONST_STRING_CANDIDATE",
            "family": "stack-constant",
            "candidate_confidence": confidence,
            "candidate_reasons": reasons,
            "suggested_immediate_kind": "string",
            "suggested_immediate_kind_confidence": max(confidence, 0.7),
            "suggested_override": {
                "mnemonic": "PUSH_CONST_STRING_CANDIDATE",
                "family": "stack-constant",
                "immediate_kind": "string",
            },
        }
        stack_effect_candidate = _infer_clientscript_stack_effect(entry)
        if stack_effect_candidate is not None:
            entry["stack_effect_candidate"] = stack_effect_candidate
        catalog[raw_opcode] = entry

    summary = {
        "string_rich_script_count": string_rich_script_count,
        "frontier_script_count": frontier_script_count,
        "frontier_opcode_count": len(catalog),
        "catalog_sample": sorted(
            catalog.values(),
            key=lambda entry: (
                -int(entry.get("string_argument_script_count", 0)),
                -int(entry.get("script_count", 0)),
                int(entry["raw_opcode"]),
            ),
        )[:24],
    }
    return catalog, summary


def _promote_clientscript_string_frontier_candidates(
    string_frontier_candidates: dict[int, dict[str, object]],
) -> dict[int, dict[str, object]]:
    promoted: dict[int, dict[str, object]] = {}

    for raw_opcode, entry in sorted(string_frontier_candidates.items()):
        mnemonic = entry.get("candidate_mnemonic")
        immediate_kind = entry.get("suggested_immediate_kind")
        confidence = entry.get("suggested_immediate_kind_confidence", entry.get("candidate_confidence"))
        family = entry.get("family")
        if mnemonic != "PUSH_CONST_STRING_CANDIDATE":
            continue
        if not isinstance(immediate_kind, str) or immediate_kind not in CLIENTSCRIPT_SUPPORTED_IMMEDIATE_TYPES:
            continue
        if not isinstance(confidence, (int, float)) or float(confidence) < 0.75:
            continue
        if int(entry.get("script_count", 0)) < 2 and int(entry.get("complete_trace_count", 0)) <= 0:
            continue

        promoted_entry: dict[str, object] = {
            "mnemonic": str(mnemonic),
            "immediate_kind": immediate_kind,
            "status": "promoted-candidate",
            "promotion_source": "string-frontier",
            "confidence": float(confidence),
        }
        if isinstance(family, str) and family:
            promoted_entry["family"] = family
        stack_effect_candidate = entry.get("stack_effect_candidate")
        if isinstance(stack_effect_candidate, dict) and stack_effect_candidate:
            promoted_entry["stack_effect_candidate"] = dict(stack_effect_candidate)
        promoted[int(raw_opcode)] = promoted_entry

    return promoted


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
    key_start: int | None = None,
    key_end: int | None = None,
    limit: int | None = None,
    include_container: bool = False,
    clientscript_cache_dir: str | Path | None = None,
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
    normalized_key_start = int(key_start) if key_start is not None else None
    normalized_key_end = int(key_end) if key_end is not None else None
    if (
        normalized_key_start is not None
        and normalized_key_end is not None
        and normalized_key_start > normalized_key_end
    ):
        raise ValueError("key_start cannot be greater than key_end")
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
    clientscript_initial_control_flow_candidates: dict[int, dict[str, object]] = {}
    clientscript_post_context_control_flow_candidates: dict[int, dict[str, object]] = {}
    clientscript_post_context_control_flow_summary: dict[str, object] | None = None
    clientscript_recursive_control_flow_candidates: dict[int, dict[str, object]] = {}
    clientscript_recursive_control_flow_summary: dict[str, object] | None = None
    clientscript_post_string_control_flow_candidates: dict[int, dict[str, object]] = {}
    clientscript_post_string_control_flow_summary: dict[str, object] | None = None
    clientscript_post_tail_hint_control_flow_candidates: dict[int, dict[str, object]] = {}
    clientscript_post_tail_hint_control_flow_summary: dict[str, object] | None = None
    clientscript_producer_candidates: dict[int, dict[str, object]] = {}
    clientscript_producer_summary: dict[str, object] | None = None
    clientscript_contextual_frontier_candidates: dict[int, dict[str, object]] = {}
    clientscript_contextual_frontier_summary: dict[str, object] | None = None
    clientscript_string_frontier_candidates: dict[int, dict[str, object]] = {}
    clientscript_string_frontier_summary: dict[str, object] | None = None
    clientscript_string_transform_frontier_candidates: dict[int, dict[str, object]] = {}
    clientscript_string_transform_frontier_summary: dict[str, object] | None = None
    clientscript_string_transform_arity_candidates: dict[int, dict[str, object]] = {}
    clientscript_string_transform_arity_summary: dict[str, object] | None = None
    clientscript_tail_hint_candidates: dict[int, dict[str, object]] = {}
    clientscript_tail_hint_summary: dict[str, object] | None = None
    clientscript_tail_consumer_candidates: dict[int, dict[str, object]] = {}
    clientscript_tail_consumer_summary: dict[str, object] | None = None
    clientscript_tail_producer_candidates: dict[int, dict[str, object]] = {}
    clientscript_tail_producer_summary: dict[str, object] | None = None
    clientscript_promoted_contextual_frontiers: dict[int, dict[str, object]] = {}
    clientscript_promoted_string_frontiers: dict[int, dict[str, object]] = {}
    clientscript_promoted_candidates: dict[int, dict[str, object]] = {}
    clientscript_semantic_overrides: dict[int, dict[str, object]] = {}
    clientscript_cached_semantic_overrides: dict[int, dict[str, object]] = {}
    cached_semantic_source: str | None = None
    cached_semantic_build: int | None = None
    clientscript_semantic_source: str | None = None
    clientscript_semantic_build: int | None = None
    clientscript_cache_mode: str | None = None
    clientscript_cache_source: str | None = None
    clientscript_opcode_catalog_path: Path | None = None
    clientscript_control_flow_candidates_path: Path | None = None
    clientscript_producer_candidates_path: Path | None = None
    clientscript_contextual_frontier_candidates_path: Path | None = None
    clientscript_string_frontier_candidates_path: Path | None = None
    clientscript_string_transform_frontier_candidates_path: Path | None = None
    clientscript_string_transform_arity_candidates_path: Path | None = None
    clientscript_tail_hint_candidates_path: Path | None = None
    clientscript_tail_consumer_candidates_path: Path | None = None
    clientscript_tail_producer_candidates_path: Path | None = None
    clientscript_semantic_suggestions_path: Path | None = None
    clientscript_pseudocode_profile_statuses: list[dict[str, object]] = []
    clientscript_pseudocode_blockers_path: Path | None = None
    clientscript_pseudocode_blocker_summary: dict[str, object] | None = None

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
            cache_loaded = False
            if clientscript_cache_dir is not None:
                (
                    clientscript_cached_semantic_overrides,
                    cached_semantic_source,
                    cached_semantic_build,
                ) = _load_clientscript_semantic_overrides_from_cache_dir(
                    clientscript_cache_dir,
                    source_path=target,
                )
                if clientscript_cached_semantic_overrides:
                    clientscript_semantic_source = cached_semantic_source
                    clientscript_semantic_build = cached_semantic_build
            if clientscript_cache_dir is not None:
                cached_clientscript_analysis, cache_warning = _load_cached_clientscript_analysis(
                    clientscript_cache_dir,
                    source_path=target,
                )
                if cached_clientscript_analysis is None:
                    if cache_warning:
                        warnings.append(cache_warning)
                else:
                    cache_loaded = True
                    clientscript_cache_mode = "reused"
                    clientscript_cache_source = str(cached_clientscript_analysis["cache_root"])
                    clientscript_opcode_catalog = dict(cached_clientscript_analysis["opcode_catalog"])
                    clientscript_opcode_catalog_summary = cached_clientscript_analysis["opcode_catalog_summary"]
                    clientscript_control_flow_candidates = dict(cached_clientscript_analysis["control_flow_candidates"])
                    clientscript_initial_control_flow_candidates = dict(clientscript_control_flow_candidates)
                    clientscript_control_flow_summary = cached_clientscript_analysis["control_flow_summary"]
                    clientscript_producer_candidates = dict(cached_clientscript_analysis["producer_candidates"])
                    clientscript_producer_summary = cached_clientscript_analysis["producer_summary"]
                    clientscript_contextual_frontier_candidates = dict(
                        cached_clientscript_analysis["contextual_frontier_candidates"]
                    )
                    clientscript_contextual_frontier_summary = cached_clientscript_analysis[
                        "contextual_frontier_summary"
                    ]
                    clientscript_string_frontier_candidates = dict(
                        cached_clientscript_analysis["string_frontier_candidates"]
                    )
                    clientscript_string_frontier_summary = cached_clientscript_analysis["string_frontier_summary"]
                    clientscript_semantic_source = cached_clientscript_analysis["semantic_override_source"]
                    clientscript_semantic_build = cached_clientscript_analysis["semantic_override_build"]
                    clientscript_semantic_overrides = dict(cached_clientscript_analysis["semantic_overrides"])
                    if clientscript_cached_semantic_overrides:
                        merged_semantic_overrides = dict(clientscript_semantic_overrides)
                        for raw_opcode, override_entry in clientscript_cached_semantic_overrides.items():
                            merged_semantic_overrides[int(raw_opcode)] = dict(override_entry)
                        clientscript_semantic_overrides = merged_semantic_overrides
                        if clientscript_semantic_source is None:
                            clientscript_semantic_source = cached_semantic_source or str(clientscript_cache_dir)
                        if clientscript_semantic_build is None:
                            clientscript_semantic_build = cached_semantic_build
                    clientscript_calibration_summary = dict(cached_clientscript_analysis["calibration_summary"])
                    for entry in clientscript_control_flow_candidates.values():
                        _refine_clientscript_frontier_state_reader_candidate(entry)
                        _refine_clientscript_consumed_operand_payload_candidate(entry)
                        _refine_clientscript_switch_case_payload_candidate(entry)
                        _refine_clientscript_widget_mutator_candidate(entry)
                        _refine_clientscript_consumed_operand_role_candidate(entry)
                    clientscript_promoted_candidates = _promote_clientscript_control_flow_candidates(
                        clientscript_control_flow_candidates
                    )
                    for raw_opcode, promoted_entry in clientscript_promoted_candidates.items():
                        _merge_clientscript_catalog_entry(clientscript_opcode_catalog, raw_opcode, promoted_entry)
                    for raw_opcode, candidate_entry in clientscript_control_flow_candidates.items():
                        _merge_clientscript_catalog_entry(clientscript_opcode_catalog, raw_opcode, candidate_entry)
                    for raw_opcode, producer_entry in clientscript_producer_candidates.items():
                        _merge_clientscript_catalog_entry(clientscript_opcode_catalog, raw_opcode, producer_entry)
                    clientscript_promoted_string_frontiers = _promote_clientscript_string_frontier_candidates(
                        clientscript_string_frontier_candidates
                    )
                    for raw_opcode, promoted_entry in clientscript_promoted_string_frontiers.items():
                        _merge_clientscript_catalog_entry(clientscript_opcode_catalog, raw_opcode, promoted_entry)
                    for raw_opcode, candidate_entry in clientscript_string_frontier_candidates.items():
                        _merge_clientscript_catalog_entry(clientscript_opcode_catalog, raw_opcode, candidate_entry)
                    _seed_clientscript_catalog_with_semantic_overrides(
                        clientscript_opcode_catalog,
                        clientscript_semantic_overrides,
                    )
                    effective_clientscript_opcode_types = _augment_clientscript_locked_opcode_types(
                        {},
                        clientscript_opcode_catalog,
                    )
                    clientscript_opcode_types = dict(effective_clientscript_opcode_types)
                    for entry in clientscript_opcode_catalog.values():
                        stack_effect_candidate = _infer_clientscript_stack_effect(entry)
                        if stack_effect_candidate is not None:
                            entry["stack_effect_candidate"] = stack_effect_candidate

            if not cache_loaded:
                try:
                    clientscript_cache_mode = "rebuilt"
                    clientscript_semantic_overrides, clientscript_semantic_source, clientscript_semantic_build = (
                        load_clientscript_semantic_overrides(str(target))
                    )
                    if clientscript_cached_semantic_overrides:
                        merged_semantic_overrides = dict(clientscript_semantic_overrides)
                        for raw_opcode, override_entry in clientscript_cached_semantic_overrides.items():
                            merged_semantic_overrides[int(raw_opcode)] = dict(override_entry)
                        clientscript_semantic_overrides = merged_semantic_overrides
                        if clientscript_semantic_source is None:
                            clientscript_semantic_source = cached_semantic_source or str(clientscript_cache_dir)
                        if clientscript_semantic_build is None:
                            clientscript_semantic_build = cached_semantic_build
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
                    _seed_clientscript_catalog_with_semantic_overrides(
                        clientscript_opcode_catalog,
                        clientscript_semantic_overrides,
                    )
                    clientscript_opcode_types = _augment_clientscript_locked_opcode_types(
                        clientscript_opcode_types,
                        clientscript_opcode_catalog,
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
                    clientscript_initial_control_flow_candidates = dict(clientscript_control_flow_candidates)
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
                        clientscript_initial_control_flow_candidates,
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
                    clientscript_string_frontier_candidates, clientscript_string_frontier_summary = (
                        _build_clientscript_string_frontier_candidates(
                            connection,
                            locked_opcode_types=effective_clientscript_opcode_types,
                            raw_opcode_catalog=clientscript_opcode_catalog,
                            include_keys=normalized_keys,
                            max_decoded_bytes=max_decoded_bytes,
                        )
                    )
                    clientscript_promoted_string_frontiers = _promote_clientscript_string_frontier_candidates(
                        clientscript_string_frontier_candidates
                    )
                    for raw_opcode, promoted_entry in clientscript_promoted_string_frontiers.items():
                        _merge_clientscript_catalog_entry(clientscript_opcode_catalog, raw_opcode, promoted_entry)
                    for raw_opcode, candidate_entry in clientscript_string_frontier_candidates.items():
                        _merge_clientscript_catalog_entry(clientscript_opcode_catalog, raw_opcode, candidate_entry)
                    effective_clientscript_opcode_types = _augment_clientscript_locked_opcode_types(
                        effective_clientscript_opcode_types,
                        clientscript_opcode_catalog,
                    )
                    clientscript_post_string_control_flow_candidates, clientscript_post_string_control_flow_summary = (
                        _build_clientscript_control_flow_candidates(
                            connection,
                            locked_opcode_types=effective_clientscript_opcode_types,
                            semantic_overrides=clientscript_semantic_overrides,
                            raw_opcode_catalog=clientscript_opcode_catalog,
                            include_keys=normalized_keys,
                            max_decoded_bytes=max_decoded_bytes,
                        )
                    )
                    post_string_promoted_candidates = _promote_clientscript_control_flow_candidates(
                        clientscript_post_string_control_flow_candidates
                    )
                    for raw_opcode, promoted_entry in post_string_promoted_candidates.items():
                        _merge_clientscript_catalog_entry(clientscript_opcode_catalog, raw_opcode, promoted_entry)
                    for raw_opcode, candidate_entry in clientscript_post_string_control_flow_candidates.items():
                        _merge_clientscript_catalog_entry(clientscript_opcode_catalog, raw_opcode, candidate_entry)
                    clientscript_control_flow_candidates = _combine_clientscript_control_flow_candidates(
                        clientscript_initial_control_flow_candidates,
                        clientscript_post_context_control_flow_candidates,
                        clientscript_recursive_control_flow_candidates,
                        clientscript_post_string_control_flow_candidates,
                    )
                    if (
                        clientscript_control_flow_summary is not None
                        and clientscript_post_string_control_flow_summary is not None
                    ):
                        clientscript_control_flow_summary["post_string_frontier_opcode_count"] = int(
                            clientscript_post_string_control_flow_summary.get("frontier_opcode_count", 0)
                        )
                        clientscript_control_flow_summary["post_string_catalog_sample"] = (
                            clientscript_post_string_control_flow_summary.get("catalog_sample", [])[:24]
                        )
                    for entry in clientscript_opcode_catalog.values():
                        stack_effect_candidate = _infer_clientscript_stack_effect(entry)
                        if stack_effect_candidate is not None:
                            entry["stack_effect_candidate"] = stack_effect_candidate
                except Exception as exc:
                    warnings.append(f"clientscript calibration failed: {exc}")

            if clientscript_opcode_catalog:
                (
                    clientscript_string_transform_frontier_candidates,
                    clientscript_string_transform_frontier_summary,
                ) = _build_clientscript_string_transform_frontier_candidates(clientscript_opcode_catalog)
                (
                    clientscript_string_transform_arity_candidates,
                    clientscript_string_transform_arity_summary,
                ) = _build_clientscript_string_transform_arity_candidates(
                    clientscript_string_transform_frontier_candidates
                )
                for raw_opcode, arity_entry in clientscript_string_transform_arity_candidates.items():
                    if not isinstance(arity_entry, dict):
                        continue
                    arity_profile_sample = arity_entry.get("arity_profile_sample")
                    candidate_arity_profile = arity_entry.get("candidate_arity_profile")

                    frontier_entry = clientscript_string_transform_frontier_candidates.get(raw_opcode)
                    resolved_immediate_kind: str | None = None
                    if isinstance(frontier_entry, dict):
                        frontier_immediate_kind = frontier_entry.get("immediate_kind", frontier_entry.get("suggested_immediate_kind"))
                        if (
                            isinstance(frontier_immediate_kind, str)
                            and frontier_immediate_kind in CLIENTSCRIPT_SUPPORTED_IMMEDIATE_TYPES
                        ):
                            resolved_immediate_kind = frontier_immediate_kind
                        if isinstance(arity_profile_sample, list) and arity_profile_sample:
                            frontier_entry["arity_profile_sample"] = [dict(profile) for profile in arity_profile_sample]
                        if isinstance(candidate_arity_profile, dict) and candidate_arity_profile:
                            frontier_entry["candidate_arity_profile"] = dict(candidate_arity_profile)
                            promoted_mnemonic = candidate_arity_profile.get("candidate_mnemonic")
                            if _should_promote_clientscript_arity_candidate(
                                frontier_entry.get("candidate_mnemonic"),
                                promoted_mnemonic,
                            ):
                                frontier_entry["candidate_mnemonic"] = str(promoted_mnemonic)
                                promoted_family = candidate_arity_profile.get("family")
                                if isinstance(promoted_family, str) and promoted_family:
                                    frontier_entry["family"] = promoted_family
                                promoted_confidence = candidate_arity_profile.get("confidence")
                                if isinstance(promoted_confidence, (int, float)):
                                    frontier_entry["candidate_confidence"] = float(promoted_confidence)
                            if "operand_signature_candidate" not in frontier_entry:
                                operand_signature_candidate = candidate_arity_profile.get(
                                    "operand_signature_candidate"
                                )
                                if isinstance(operand_signature_candidate, dict) and operand_signature_candidate:
                                    frontier_entry["operand_signature_candidate"] = dict(
                                        operand_signature_candidate
                                    )
                            if "stack_effect_candidate" not in frontier_entry:
                                stack_effect_candidate = candidate_arity_profile.get("stack_effect_candidate")
                                if isinstance(stack_effect_candidate, dict) and stack_effect_candidate:
                                    frontier_entry["stack_effect_candidate"] = dict(stack_effect_candidate)

                    opcode_entry = clientscript_opcode_catalog.get(raw_opcode)
                    if isinstance(opcode_entry, dict):
                        opcode_immediate_kind = opcode_entry.get("immediate_kind", opcode_entry.get("suggested_immediate_kind"))
                        if (
                            resolved_immediate_kind is None
                            and isinstance(opcode_immediate_kind, str)
                            and opcode_immediate_kind in CLIENTSCRIPT_SUPPORTED_IMMEDIATE_TYPES
                        ):
                            resolved_immediate_kind = opcode_immediate_kind
                        if isinstance(arity_profile_sample, list) and arity_profile_sample:
                            opcode_entry["arity_profile_sample"] = [dict(profile) for profile in arity_profile_sample]
                        if isinstance(candidate_arity_profile, dict) and candidate_arity_profile:
                            opcode_entry["arity_profile_candidate"] = dict(candidate_arity_profile)
                            promoted_mnemonic = candidate_arity_profile.get("candidate_mnemonic")
                            if _should_promote_clientscript_arity_candidate(
                                opcode_entry.get("mnemonic", opcode_entry.get("candidate_mnemonic")),
                                promoted_mnemonic,
                            ):
                                opcode_entry["candidate_mnemonic"] = str(promoted_mnemonic)
                                promoted_family = candidate_arity_profile.get("family")
                                if isinstance(promoted_family, str) and promoted_family:
                                    opcode_entry["family"] = promoted_family
                                promoted_confidence = candidate_arity_profile.get("confidence")
                                if isinstance(promoted_confidence, (int, float)):
                                    opcode_entry["candidate_confidence"] = float(promoted_confidence)
                            operand_signature_candidate = candidate_arity_profile.get(
                                "operand_signature_candidate"
                            )
                            if isinstance(operand_signature_candidate, dict) and operand_signature_candidate:
                                opcode_entry["operand_signature_candidate"] = dict(operand_signature_candidate)
                            stack_effect_candidate = candidate_arity_profile.get("stack_effect_candidate")
                            if isinstance(stack_effect_candidate, dict) and stack_effect_candidate:
                                opcode_entry["stack_effect_candidate"] = dict(stack_effect_candidate)
                    if resolved_immediate_kind is not None:
                        arity_entry["immediate_kind"] = resolved_immediate_kind

                feedback_locked_opcode_types = _augment_clientscript_locked_opcode_types(
                    effective_clientscript_opcode_types,
                    clientscript_opcode_catalog,
                )
                feedback_pass_summaries: list[dict[str, object]] = []
                for feedback_pass_index in range(1, 4):
                    if len(feedback_locked_opcode_types) <= len(effective_clientscript_opcode_types):
                        break
                    clientscript_feedback_control_flow_candidates, clientscript_feedback_control_flow_summary = (
                        _build_clientscript_control_flow_candidates(
                            connection,
                            locked_opcode_types=feedback_locked_opcode_types,
                            semantic_overrides=clientscript_semantic_overrides,
                            raw_opcode_catalog=clientscript_opcode_catalog,
                            include_keys=normalized_keys,
                            max_decoded_bytes=max_decoded_bytes,
                        )
                    )
                    feedback_promoted_candidates = _promote_clientscript_control_flow_candidates(
                        clientscript_feedback_control_flow_candidates
                    )
                    for raw_opcode, promoted_entry in feedback_promoted_candidates.items():
                        _merge_clientscript_catalog_entry(clientscript_opcode_catalog, raw_opcode, promoted_entry)
                    for raw_opcode, candidate_entry in clientscript_feedback_control_flow_candidates.items():
                        _merge_clientscript_catalog_entry(clientscript_opcode_catalog, raw_opcode, candidate_entry)
                    stage_name = "feedback" if feedback_pass_index == 1 else f"feedback-{feedback_pass_index}"
                    _merge_clientscript_control_flow_candidate_stage(
                        clientscript_control_flow_candidates,
                        clientscript_feedback_control_flow_candidates,
                        stage_name=stage_name,
                    )
                    if clientscript_feedback_control_flow_summary is not None:
                        feedback_pass_summaries.append(
                            {
                                "pass_index": feedback_pass_index,
                                "frontier_opcode_count": int(
                                    clientscript_feedback_control_flow_summary.get("frontier_opcode_count", 0)
                                ),
                                "catalog_sample": clientscript_feedback_control_flow_summary.get("catalog_sample", [])[:24],
                            }
                        )
                    effective_clientscript_opcode_types = _augment_clientscript_locked_opcode_types(
                        feedback_locked_opcode_types,
                        clientscript_opcode_catalog,
                    )
                    clientscript_opcode_types = dict(effective_clientscript_opcode_types)
                    feedback_locked_opcode_types = _augment_clientscript_locked_opcode_types(
                        effective_clientscript_opcode_types,
                        clientscript_opcode_catalog,
                    )
                if clientscript_control_flow_summary is not None and feedback_pass_summaries:
                    clientscript_control_flow_summary["feedback_pass_count"] = len(feedback_pass_summaries)
                    clientscript_control_flow_summary["feedback_frontier_opcode_count"] = int(
                        feedback_pass_summaries[-1].get("frontier_opcode_count", 0)
                    )
                    clientscript_control_flow_summary["feedback_catalog_sample"] = (
                        feedback_pass_summaries[-1].get("catalog_sample", [])
                    )
                    clientscript_control_flow_summary["feedback_pass_summaries"] = feedback_pass_summaries

                clientscript_tail_hint_candidates, clientscript_tail_hint_summary = (
                    _build_clientscript_tail_hint_candidates(
                        connection,
                        locked_opcode_types=effective_clientscript_opcode_types,
                        raw_opcode_catalog=clientscript_opcode_catalog,
                        include_keys=normalized_keys,
                        max_decoded_bytes=max_decoded_bytes,
                    )
                )
                clientscript_promoted_tail_hints = _promote_clientscript_tail_hint_candidates(
                    clientscript_tail_hint_candidates
                )
                tail_hint_locked_opcode_types = dict(effective_clientscript_opcode_types)
                for raw_opcode, promoted_entry in clientscript_promoted_tail_hints.items():
                    _merge_clientscript_catalog_entry(clientscript_opcode_catalog, raw_opcode, promoted_entry)
                for raw_opcode, candidate_entry in clientscript_tail_hint_candidates.items():
                    _merge_clientscript_catalog_entry(clientscript_opcode_catalog, raw_opcode, candidate_entry)
                (
                    clientscript_tail_consumer_candidates,
                    clientscript_tail_consumer_summary,
                ) = _build_clientscript_tail_consumer_candidates(
                    clientscript_tail_hint_candidates
                )
                for raw_opcode, candidate_entry in clientscript_tail_consumer_candidates.items():
                    _merge_clientscript_catalog_entry(clientscript_opcode_catalog, raw_opcode, candidate_entry)
                effective_clientscript_opcode_types = _augment_clientscript_locked_opcode_types(
                    effective_clientscript_opcode_types,
                    clientscript_opcode_catalog,
                )
                clientscript_opcode_types = dict(effective_clientscript_opcode_types)
                if effective_clientscript_opcode_types != tail_hint_locked_opcode_types:
                    (
                        clientscript_post_tail_hint_control_flow_candidates,
                        clientscript_post_tail_hint_control_flow_summary,
                    ) = _build_clientscript_control_flow_candidates(
                        connection,
                        locked_opcode_types=effective_clientscript_opcode_types,
                        semantic_overrides=clientscript_semantic_overrides,
                        raw_opcode_catalog=clientscript_opcode_catalog,
                        include_keys=normalized_keys,
                        max_decoded_bytes=max_decoded_bytes,
                    )
                    post_tail_hint_promoted_candidates = _promote_clientscript_control_flow_candidates(
                        clientscript_post_tail_hint_control_flow_candidates
                    )
                    for raw_opcode, promoted_entry in post_tail_hint_promoted_candidates.items():
                        _merge_clientscript_catalog_entry(clientscript_opcode_catalog, raw_opcode, promoted_entry)
                    for raw_opcode, candidate_entry in clientscript_post_tail_hint_control_flow_candidates.items():
                        _merge_clientscript_catalog_entry(clientscript_opcode_catalog, raw_opcode, candidate_entry)
                    clientscript_control_flow_candidates = _combine_clientscript_control_flow_candidates(
                        clientscript_initial_control_flow_candidates,
                        clientscript_post_context_control_flow_candidates,
                        clientscript_recursive_control_flow_candidates,
                        clientscript_post_string_control_flow_candidates,
                        clientscript_post_tail_hint_control_flow_candidates,
                    )
                    if (
                        clientscript_control_flow_summary is not None
                        and clientscript_post_tail_hint_control_flow_summary is not None
                    ):
                        clientscript_control_flow_summary["post_tail_hint_frontier_opcode_count"] = int(
                            clientscript_post_tail_hint_control_flow_summary.get("frontier_opcode_count", 0)
                        )
                        clientscript_control_flow_summary["post_tail_hint_catalog_sample"] = (
                            clientscript_post_tail_hint_control_flow_summary.get("catalog_sample", [])[:24]
                        )
                        clientscript_control_flow_summary["combined_frontier_opcode_count"] = int(
                            len(clientscript_control_flow_candidates)
                        )

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
            if normalized_key_start is not None:
                query += ' AND "KEY" >= ?'
                params.append(normalized_key_start)
            if normalized_key_end is not None:
                query += ' AND "KEY" <= ?'
                params.append(normalized_key_end)
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
                            pseudocode_text_path: Path | None = None
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
                                    _write_text_artifact(mesh_obj_path, mesh_obj_text, encoding="utf-8")
                                    semantic_profile["mesh_obj_path"] = str(mesh_obj_path)
                                disassembly_text = semantic_profile.pop("_disassembly_text", None)
                                if isinstance(disassembly_text, str):
                                    disassembly_text_path = archive_dir / f"file-{file_id}.disasm.txt"
                                    _write_text_artifact(disassembly_text_path, disassembly_text, encoding="utf-8")
                                    semantic_profile["disassembly_text_path"] = str(disassembly_text_path)
                                pseudocode_text = semantic_profile.pop("_pseudocode_text", None)
                                if isinstance(pseudocode_text, str):
                                    pseudocode_text_path = archive_dir / f"file-{file_id}.pseudo.txt"
                                    _write_text_artifact(pseudocode_text_path, pseudocode_text, encoding="utf-8")
                                    semantic_profile["pseudocode_text_path"] = str(pseudocode_text_path)
                                cfg_dot_text = semantic_profile.pop("_cfg_dot_text", None)
                                if isinstance(cfg_dot_text, str):
                                    cfg_dot_path = archive_dir / f"file-{file_id}.cfg.dot"
                                    _write_text_artifact(cfg_dot_path, cfg_dot_text, encoding="utf-8")
                                    semantic_profile["cfg_dot_path"] = str(cfg_dot_path)
                                cfg_json_text = semantic_profile.pop("_cfg_json_text", None)
                                if isinstance(cfg_json_text, str):
                                    cfg_json_path = archive_dir / f"file-{file_id}.cfg.json"
                                    _write_text_artifact(cfg_json_path, cfg_json_text, encoding="utf-8")
                                    semantic_profile["cfg_json_path"] = str(cfg_json_path)
                                if cfg_dot_path is not None:
                                    cfg_graph_count += 1
                                if index_name == "CLIENTSCRIPTS":
                                    pseudocode_status = _build_clientscript_pseudocode_profile_status(
                                        semantic_profile,
                                        archive_key=int(key),
                                        file_id=file_id,
                                    )
                                    if pseudocode_status is not None:
                                        clientscript_pseudocode_profile_statuses.append(pseudocode_status)
                                        semantic_profile["pseudocode_status"] = pseudocode_status["status"]
                                        if pseudocode_status["status"] == "blocked":
                                            semantic_profile["pseudocode_blocker"] = {
                                                field: value
                                                for field, value in pseudocode_status.items()
                                                if field
                                                not in {
                                                    "archive_key",
                                                    "file_id",
                                                    "kind",
                                                    "parser_status",
                                                    "disassembly_mode",
                                                    "disassembly_solution_count",
                                                    "disassembly_bailed",
                                                    "status",
                                                }
                                            }
                            if semantic_profile is not None and semantic_profile.get("parser_status") in {
                                "parsed",
                                "profiled",
                                "recovered",
                            }:
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
        _write_json_artifact(
            clientscript_opcode_catalog_path,
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
        if clientscript_post_string_control_flow_summary is not None:
            control_flow_payload["post_string_frontier_opcode_count"] = int(
                clientscript_post_string_control_flow_summary.get("frontier_opcode_count", 0)
            )
        if clientscript_post_tail_hint_control_flow_summary is not None:
            control_flow_payload["post_tail_hint_frontier_opcode_count"] = int(
                clientscript_post_tail_hint_control_flow_summary.get("frontier_opcode_count", 0)
            )
        _write_json_artifact(clientscript_control_flow_candidates_path, control_flow_payload)
    if clientscript_string_frontier_candidates:
        clientscript_string_frontier_candidates_path = destination / "clientscript-string-frontier-candidates.json"
        _write_json_artifact(
            clientscript_string_frontier_candidates_path,
            {
                "tool": {
                    "name": "reverser-workbench",
                    "version": __version__,
                },
                "source_path": str(target),
                "frontier_opcode_count": len(clientscript_string_frontier_candidates),
                "semantic_override_source": clientscript_semantic_source,
                "semantic_override_build": clientscript_semantic_build,
                "opcodes": sorted(
                    clientscript_string_frontier_candidates.values(),
                    key=lambda entry: (
                        -int(entry.get("string_argument_script_count", 0)),
                        -int(entry.get("script_count", 0)),
                        int(entry["raw_opcode"]),
                    ),
                ),
            },
        )

    if clientscript_pseudocode_profile_statuses and clientscript_opcode_catalog:
        clientscript_tail_producer_candidates, clientscript_tail_producer_summary = (
            _build_clientscript_tail_producer_candidates(
                clientscript_pseudocode_profile_statuses,
                raw_opcode_catalog=clientscript_opcode_catalog,
            )
        )
        for raw_opcode, candidate_entry in clientscript_tail_producer_candidates.items():
            _merge_clientscript_catalog_entry(clientscript_opcode_catalog, raw_opcode, candidate_entry)
        effective_clientscript_opcode_types = _augment_clientscript_locked_opcode_types(
            effective_clientscript_opcode_types,
            clientscript_opcode_catalog,
        )
        clientscript_opcode_types = dict(effective_clientscript_opcode_types)
        for entry in clientscript_opcode_catalog.values():
            stack_effect_candidate = _infer_clientscript_stack_effect(entry)
            if stack_effect_candidate is not None:
                entry["stack_effect_candidate"] = stack_effect_candidate

    semantic_suggestions = _build_clientscript_semantic_suggestions(
        clientscript_control_flow_candidates,
        clientscript_contextual_frontier_candidates,
        clientscript_string_frontier_candidates,
        clientscript_string_transform_arity_candidates,
        clientscript_tail_hint_candidates,
    )
    effective_semantic_suggestions = _build_clientscript_effective_semantic_suggestions(
        semantic_suggestions,
        semantic_overrides=clientscript_semantic_overrides,
        raw_opcode_catalog=clientscript_opcode_catalog,
    )
    if effective_semantic_suggestions:
        clientscript_semantic_suggestions_path = destination / CLIENTSCRIPT_SEMANTICS_FILENAME
        _write_json_artifact(
            clientscript_semantic_suggestions_path,
            {
                "tool": {
                    "name": "reverser-workbench",
                    "version": __version__,
                },
                "build": clientscript_semantic_build,
                "source_path": str(target),
                "opcodes": effective_semantic_suggestions,
            },
        )

    if clientscript_string_transform_frontier_candidates:
        clientscript_string_transform_frontier_candidates_path = (
            destination / "clientscript-string-transform-frontier-candidates.json"
        )
        _write_json_artifact(
            clientscript_string_transform_frontier_candidates_path,
            {
                "tool": {
                    "name": "reverser-workbench",
                    "version": __version__,
                },
                "source_path": str(target),
                "frontier_opcode_count": len(clientscript_string_transform_frontier_candidates),
                "semantic_override_source": clientscript_semantic_source,
                "semantic_override_build": clientscript_semantic_build,
                "opcodes": sorted(
                    clientscript_string_transform_frontier_candidates.values(),
                    key=lambda entry: (
                        -int(entry.get("string_result_script_count", 0)),
                        -int(entry.get("script_count", 0)),
                        int(entry["raw_opcode"]),
                    ),
                ),
            },
        )

    if clientscript_string_transform_arity_candidates:
        clientscript_string_transform_arity_candidates_path = (
            destination / "clientscript-string-transform-arity-candidates.json"
        )
        _write_json_artifact(
            clientscript_string_transform_arity_candidates_path,
            {
                "tool": {
                    "name": "reverser-workbench",
                    "version": __version__,
                },
                "source_path": str(target),
                "profiled_opcode_count": len(clientscript_string_transform_arity_candidates),
                "semantic_override_source": clientscript_semantic_source,
                "semantic_override_build": clientscript_semantic_build,
                "opcodes": sorted(
                    clientscript_string_transform_arity_candidates.values(),
                    key=lambda entry: (
                        -int("candidate_arity_profile" in entry),
                        -int(entry.get("string_result_script_count", 0)),
                        -int(entry.get("script_count", 0)),
                        int(entry["raw_opcode"]),
                    ),
                ),
            },
        )

    if clientscript_tail_hint_candidates:
        clientscript_tail_hint_candidates_path = destination / "clientscript-tail-hint-candidates.json"
        _write_json_artifact(
            clientscript_tail_hint_candidates_path,
            {
                "tool": {
                    "name": "reverser-workbench",
                    "version": __version__,
                },
                "source_path": str(target),
                "tail_hint_opcode_count": len(clientscript_tail_hint_candidates),
                "semantic_override_source": clientscript_semantic_source,
                "semantic_override_build": clientscript_semantic_build,
                "opcodes": sorted(
                    clientscript_tail_hint_candidates.values(),
                    key=lambda entry: (
                        -int("candidate_mnemonic" in entry),
                        -int(entry.get("script_count", 0)),
                        int(entry["raw_opcode"]),
                    ),
                ),
            },
        )

    if clientscript_tail_consumer_candidates:
        clientscript_tail_consumer_candidates_path = destination / "clientscript-tail-consumer-candidates.json"
        _write_json_artifact(
            clientscript_tail_consumer_candidates_path,
            {
                "tool": {
                    "name": "reverser-workbench",
                    "version": __version__,
                },
                "source_path": str(target),
                "tail_consumer_opcode_count": len(clientscript_tail_consumer_candidates),
                "semantic_override_source": clientscript_semantic_source,
                "semantic_override_build": clientscript_semantic_build,
                "opcodes": sorted(
                    clientscript_tail_consumer_candidates.values(),
                    key=lambda entry: (
                        -int(entry.get("script_count", 0)),
                        -int(entry.get("candidate_confidence", 0) * 100),
                        int(entry["raw_opcode"]),
                    ),
                ),
            },
        )

    if clientscript_producer_candidates:
        clientscript_producer_candidates_path = destination / "clientscript-producer-candidates.json"
        _write_json_artifact(
            clientscript_producer_candidates_path,
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
        )

    if clientscript_tail_producer_candidates:
        clientscript_tail_producer_candidates_path = destination / "clientscript-tail-producer-candidates.json"
        _write_json_artifact(
            clientscript_tail_producer_candidates_path,
            {
                "tool": {
                    "name": "reverser-workbench",
                    "version": __version__,
                },
                "source_path": str(target),
                "tail_producer_opcode_count": len(clientscript_tail_producer_candidates),
                "semantic_override_source": clientscript_semantic_source,
                "semantic_override_build": clientscript_semantic_build,
                "opcodes": sorted(
                    clientscript_tail_producer_candidates.values(),
                    key=lambda entry: (
                        -int(entry.get("blocked_profile_count", 0)),
                        -int(entry.get("matched_tail_last_count", 0)),
                        int(entry["raw_opcode"]),
                    ),
                ),
            },
        )

    if clientscript_contextual_frontier_candidates:
        clientscript_contextual_frontier_candidates_path = destination / "clientscript-contextual-frontier-candidates.json"
        _write_json_artifact(
            clientscript_contextual_frontier_candidates_path,
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
        )

    if clientscript_pseudocode_profile_statuses:
        clientscript_pseudocode_blocker_summary = _summarize_clientscript_pseudocode_blockers(
            clientscript_pseudocode_profile_statuses
        )
        clientscript_pseudocode_blockers_path = destination / "clientscript-pseudocode-blockers.json"
        _write_json_artifact(clientscript_pseudocode_blockers_path, clientscript_pseudocode_blocker_summary)

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
        "clientscript_string_frontier_candidates_path": (
            str(clientscript_string_frontier_candidates_path)
            if clientscript_string_frontier_candidates_path is not None
            else None
        ),
        "clientscript_string_transform_frontier_candidates_path": (
            str(clientscript_string_transform_frontier_candidates_path)
            if clientscript_string_transform_frontier_candidates_path is not None
            else None
        ),
        "clientscript_string_transform_arity_candidates_path": (
            str(clientscript_string_transform_arity_candidates_path)
            if clientscript_string_transform_arity_candidates_path is not None
            else None
        ),
        "clientscript_tail_hint_candidates_path": (
            str(clientscript_tail_hint_candidates_path)
            if clientscript_tail_hint_candidates_path is not None
            else None
        ),
        "clientscript_tail_consumer_candidates_path": (
            str(clientscript_tail_consumer_candidates_path)
            if clientscript_tail_consumer_candidates_path is not None
            else None
        ),
        "clientscript_tail_producer_candidates_path": (
            str(clientscript_tail_producer_candidates_path)
            if clientscript_tail_producer_candidates_path is not None
            else None
        ),
        "clientscript_semantic_suggestions_path": (
            str(clientscript_semantic_suggestions_path)
            if clientscript_semantic_suggestions_path is not None
            else None
        ),
        "clientscript_pseudocode_blockers_path": (
            str(clientscript_pseudocode_blockers_path)
            if clientscript_pseudocode_blockers_path is not None
            else None
        ),
        "settings": {
            "requested_tables": requested_tables,
            "selected_tables": list(table_payloads),
            "keys": normalized_keys,
            "key_start": normalized_key_start,
            "key_end": normalized_key_end,
            "limit": normalized_limit,
            "include_container": include_container,
            "clientscript_cache_dir": str(clientscript_cache_dir) if clientscript_cache_dir is not None else None,
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
        if clientscript_cache_mode is not None:
            clientscript_calibration_summary["cache_mode"] = clientscript_cache_mode
        if clientscript_cache_source is not None:
            clientscript_calibration_summary["cache_source"] = clientscript_cache_source
        if clientscript_opcode_catalog_summary is not None:
            clientscript_calibration_summary["opcode_catalog"] = clientscript_opcode_catalog_summary
        if clientscript_control_flow_summary is not None:
            clientscript_calibration_summary["control_flow_candidates"] = clientscript_control_flow_summary
        if clientscript_producer_summary is not None:
            clientscript_calibration_summary["producer_candidates"] = clientscript_producer_summary
        if clientscript_contextual_frontier_summary is not None:
            clientscript_calibration_summary["contextual_frontier_candidates"] = clientscript_contextual_frontier_summary
        if clientscript_string_frontier_summary is not None:
            clientscript_calibration_summary["string_frontier_candidates"] = clientscript_string_frontier_summary
        if clientscript_string_transform_frontier_summary is not None:
            clientscript_calibration_summary["string_transform_frontier_candidates"] = (
                clientscript_string_transform_frontier_summary
            )
        if clientscript_string_transform_arity_summary is not None:
            clientscript_calibration_summary["string_transform_arity_candidates"] = (
                clientscript_string_transform_arity_summary
            )
        if clientscript_tail_hint_summary is not None:
            clientscript_calibration_summary["tail_hint_candidates"] = clientscript_tail_hint_summary
        if clientscript_tail_consumer_summary is not None:
            clientscript_calibration_summary["tail_consumer_candidates"] = clientscript_tail_consumer_summary
        if clientscript_tail_producer_summary is not None:
            clientscript_calibration_summary["tail_producer_candidates"] = clientscript_tail_producer_summary
        if clientscript_semantic_source is not None:
            clientscript_calibration_summary["semantic_override_source"] = clientscript_semantic_source
        if clientscript_semantic_build is not None:
            clientscript_calibration_summary["semantic_override_build"] = clientscript_semantic_build
        manifest["clientscript_calibration"] = clientscript_calibration_summary
    if clientscript_pseudocode_blocker_summary is not None:
        manifest["clientscript_pseudocode"] = {
            "profile_count": int(clientscript_pseudocode_blocker_summary.get("profile_count", 0)),
            "ready_profile_count": int(clientscript_pseudocode_blocker_summary.get("ready_profile_count", 0)),
            "blocked_profile_count": int(clientscript_pseudocode_blocker_summary.get("blocked_profile_count", 0)),
            "blocker_opcode_count": int(clientscript_pseudocode_blocker_summary.get("blocker_opcode_count", 0)),
            "blocking_kind_counts": dict(
                clientscript_pseudocode_blocker_summary.get("blocking_kind_counts", {})
            ),
            "frontier_reason_counts": dict(
                clientscript_pseudocode_blocker_summary.get("frontier_reason_counts", {})
            ),
            "tail_status_counts": dict(
                clientscript_pseudocode_blocker_summary.get("tail_status_counts", {})
            ),
            "tail_last_opcode_count": int(
                clientscript_pseudocode_blocker_summary.get("tail_last_opcode_count", 0)
            ),
            "tail_hint_opcode_count": int(
                clientscript_pseudocode_blocker_summary.get("tail_hint_opcode_count", 0)
            ),
            "control_group_diff_count": int(
                clientscript_pseudocode_blocker_summary.get("control_group_diff_count", 0)
            ),
            "blocked_key_sample": list(
                clientscript_pseudocode_blocker_summary.get("blocked_key_sample", [])
            )[:12],
        }
    _write_json_artifact(manifest_path, manifest)
    return manifest


def _resolve_js5_export_manifest_path(source: str | Path) -> Path:
    path = Path(source)
    if path.is_dir():
        return path / "manifest.json"
    return path


def _sample_clientscript_opcode_probe_step(step: dict[str, object]) -> dict[str, object]:
    sampled = _sample_clientscript_instruction_step(step)
    for field in (
        "reference_source_name",
        "reference_id",
        "reference_source_id",
        "semantic_confidence",
        "semantic_resolution_scope",
        "int_stack_depth_before",
        "int_stack_depth_after",
        "string_stack_depth_before",
        "string_stack_depth_after",
        "long_stack_depth_before",
        "long_stack_depth_after",
        "contextual_stack_hint_applied",
        "contextual_stack_hint_match_prefix_operand_signature",
        "stack_effect_source",
    ):
        value = step.get(field)
        if value is not None:
            sampled[field] = value

    operand_signature = step.get("operand_signature_candidate")
    if isinstance(operand_signature, dict) and operand_signature:
        sampled["operand_signature_candidate"] = {
            key: value
            for key, value in operand_signature.items()
            if key in {"signature", "confidence", "notes"} and value is not None
        }

    stack_effect = step.get("stack_effect_candidate")
    if isinstance(stack_effect, dict) and stack_effect:
        sampled["stack_effect_candidate"] = {
            key: value
            for key, value in stack_effect.items()
            if value is not None
        }
        hint_applied_survivor_delta: dict[str, int] = {}
        for stack_name in CLIENTSCRIPT_STACK_NAMES:
            pushes = int(stack_effect.get(f"{stack_name}_pushes", 0))
            pops = int(stack_effect.get(f"{stack_name}_pops", 0))
            delta = pushes - pops
            if delta != 0:
                compact_stack_name = stack_name.removesuffix("_stack")
                hint_applied_survivor_delta[compact_stack_name] = delta
        if sampled.get("contextual_stack_hint_applied") and hint_applied_survivor_delta:
            sampled["hint_applied_survivor_delta"] = hint_applied_survivor_delta

    for field in (
        "consumed_int_expressions",
        "consumed_string_expressions",
        "produced_int_expressions",
        "produced_string_expressions",
    ):
        expressions = step.get(field)
        if isinstance(expressions, list) and expressions:
            sampled[field] = [
                _sample_clientscript_expression(expression)
                for expression in expressions[:3]
                if isinstance(expression, dict)
            ]
    return sampled


def _merge_clientscript_opcode_probe_hit(
    hit: dict[str, object],
    *,
    step: dict[str, object],
    sample_source: str,
    previous_step: dict[str, object] | None,
    next_step: dict[str, object] | None,
) -> None:
    sample_sources = hit.setdefault("sample_sources", [])
    if isinstance(sample_sources, list) and sample_source not in sample_sources:
        sample_sources.append(sample_source)

    sampled_step = _sample_clientscript_opcode_probe_step(step)
    existing_step = hit.get("step")
    if not isinstance(existing_step, dict) or len(sampled_step) > len(existing_step):
        hit["step"] = sampled_step
    else:
        for key, value in sampled_step.items():
            if key not in existing_step:
                existing_step[key] = value

    if previous_step is not None and "previous_step" not in hit:
        hit["previous_step"] = _sample_clientscript_opcode_probe_step(previous_step)
    if next_step is not None and "next_step" not in hit:
        hit["next_step"] = _sample_clientscript_opcode_probe_step(next_step)


def _annotate_clientscript_opcode_probe_steps(
    steps: list[object],
) -> tuple[list[dict[str, object] | None], dict[str, object]]:
    replay_state = _make_clientscript_stack_state()
    annotated_steps: list[dict[str, object] | None] = []
    for step in steps:
        if isinstance(step, dict):
            annotated_steps.append(
                _apply_clientscript_step_to_stack_state(
                    copy.deepcopy(step),
                    replay_state,
                )
            )
        else:
            annotated_steps.append(None)
    return annotated_steps, replay_state


def _build_clientscript_opcode_probe_frontier_step(
    semantic_profile: dict[str, object],
    blocker: dict[str, object],
) -> dict[str, object] | None:
    frontier_step = semantic_profile.get("tail_next_instruction")
    if not isinstance(frontier_step, dict):
        return None

    step = dict(frontier_step)
    tail_stack_summary = semantic_profile.get("tail_stack_summary")
    if isinstance(tail_stack_summary, dict):
        signature = tail_stack_summary.get("prefix_operand_signature")
        if isinstance(signature, str) and signature:
            step["operand_signature_candidate"] = {
                "signature": signature,
                "confidence": 0.68,
                "notes": "Recovered from the blocked prefix stack summary at the active frontier.",
            }
    frontier_candidate_label = blocker.get("frontier_candidate_label")
    if isinstance(frontier_candidate_label, str) and frontier_candidate_label and "semantic_label" not in step:
        step["semantic_label"] = frontier_candidate_label
    frontier_candidate_family = blocker.get("frontier_candidate_family")
    if isinstance(frontier_candidate_family, str) and frontier_candidate_family and "semantic_family" not in step:
        step["semantic_family"] = frontier_candidate_family
    frontier_candidate_confidence = blocker.get("frontier_candidate_confidence")
    if frontier_candidate_confidence is not None and "semantic_confidence" not in step:
        step["semantic_confidence"] = frontier_candidate_confidence
    return step


def _infer_clientscript_opcode_probe_behavior(step: dict[str, object]) -> str:
    operand_signature = step.get("operand_signature_candidate")
    if isinstance(operand_signature, dict):
        signature = operand_signature.get("signature")
        if isinstance(signature, str) and signature:
            return signature

    stack_effect = step.get("stack_effect_candidate")
    if isinstance(stack_effect, dict) and stack_effect:
        pop_count = 0
        push_count = 0
        for stack_name in CLIENTSCRIPT_STACK_NAMES:
            pop_count += int(stack_effect.get(f"{stack_name}_pops", 0))
            push_count += int(stack_effect.get(f"{stack_name}_pushes", 0))
        if push_count > 0 and pop_count <= 0:
            return "producer"
        if pop_count > 0 and push_count <= 0:
            return "consumer"
        if pop_count > 0 and push_count > 0:
            return "transform"

    consumed_int = step.get("consumed_int_expressions")
    consumed_string = step.get("consumed_string_expressions")
    produced_int = step.get("produced_int_expressions")
    produced_string = step.get("produced_string_expressions")

    consumed_count = (
        len(consumed_int) if isinstance(consumed_int, list) else 0
    ) + (
        len(consumed_string) if isinstance(consumed_string, list) else 0
    )
    produced_count = (
        len(produced_int) if isinstance(produced_int, list) else 0
    ) + (
        len(produced_string) if isinstance(produced_string, list) else 0
    )

    if produced_count > 0 and consumed_count <= 0:
        if isinstance(produced_string, list) and produced_string:
            return "produces-string"
        if isinstance(produced_int, list) and produced_int:
            return "produces-int"
        return "producer"
    if consumed_count > 0 and produced_count <= 0:
        return "consumer"
    if consumed_count > 0 and produced_count > 0:
        return "transform"
    return "opaque"


def _load_clientscript_opcode_artifact_entries(
    export_root: Path,
    *,
    raw_opcode: int,
) -> dict[str, dict[str, object]]:
    artifact_entries: dict[str, dict[str, object]] = {}
    for artifact_path in sorted(export_root.glob("clientscript-*.json")):
        if artifact_path.name == "manifest.json":
            continue
        try:
            payload = json.loads(artifact_path.read_text(encoding="utf-8-sig"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            continue

        opcodes = payload.get("opcodes")
        entry: dict[str, object] | None = None
        if isinstance(opcodes, list):
            entry = next(
                (
                    candidate
                    for candidate in opcodes
                    if isinstance(candidate, dict) and int(candidate.get("raw_opcode", -1)) == raw_opcode
                ),
                None,
            )
        elif isinstance(opcodes, dict):
            raw_opcode_hex = f"0x{raw_opcode:04X}"
            candidate = opcodes.get(raw_opcode_hex)
            if not isinstance(candidate, dict):
                candidate = opcodes.get(str(raw_opcode))
            if isinstance(candidate, dict):
                entry = candidate

        if entry is not None:
            artifact_entries[artifact_path.name] = copy.deepcopy(entry)
    return artifact_entries


def _load_clientscript_opcode_catalog_from_export_root(
    export_root: Path,
) -> tuple[dict[int, dict[str, object]], dict[int, str]]:
    catalog_path = export_root / "clientscript-opcode-catalog.json"
    raw_opcode_catalog: dict[int, dict[str, object]] = {}
    raw_opcode_types: dict[int, str] = {}
    if not catalog_path.exists():
        return raw_opcode_catalog, raw_opcode_types

    try:
        payload = json.loads(catalog_path.read_text(encoding="utf-8-sig"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return raw_opcode_catalog, raw_opcode_types

    opcodes = payload.get("opcodes")
    if not isinstance(opcodes, list):
        return raw_opcode_catalog, raw_opcode_types

    for entry in opcodes:
        if not isinstance(entry, dict):
            continue
        raw_opcode = entry.get("raw_opcode")
        if not isinstance(raw_opcode, int):
            continue
        raw_opcode_catalog[raw_opcode] = copy.deepcopy(entry)
        immediate_kind = entry.get("immediate_kind", entry.get("expected_immediate_kind"))
        if isinstance(immediate_kind, str) and immediate_kind in CLIENTSCRIPT_SUPPORTED_IMMEDIATE_TYPES:
            raw_opcode_types[raw_opcode] = immediate_kind
    return raw_opcode_catalog, raw_opcode_types


def _decode_clientscript_ready_annotated_steps(
    data: bytes,
    *,
    raw_opcode_types: dict[int, str] | None = None,
    raw_opcode_catalog: dict[int, dict[str, object]] | None = None,
) -> dict[str, object] | None:
    try:
        layout = _parse_clientscript_layout(data)
    except ValueError:
        return None

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
                and immediate_kind in CLIENTSCRIPT_SUPPORTED_IMMEDIATE_TYPES
                and int(raw_opcode) not in possible_types
            ):
                possible_types[int(raw_opcode)] = {immediate_kind}

    disassembly = _solve_clientscript_disassembly(
        layout.opcode_data,
        layout.instruction_count,
        possible_types=possible_types or None,
    )
    selected_steps = disassembly.get("selected_steps")
    selected_mapping = disassembly.get("selected_mapping")
    if not (isinstance(selected_steps, list) and isinstance(selected_mapping, dict)):
        return None
    if not _validate_clientscript_selected_steps_against_subtypes(
        layout,
        selected_steps,
        raw_opcode_catalog=raw_opcode_catalog,
        resolution_scope="global",
    ):
        return None

    annotated_steps = [
        _apply_clientscript_semantic_hints(
            copy.deepcopy(step),
            raw_opcode_catalog,
            resolution_scope="global",
        )
        for step in selected_steps
        if isinstance(step, dict)
    ]
    annotated_steps = _hydrate_clientscript_step_end_offsets(layout, annotated_steps)
    annotated_steps, stack_tracking = _annotate_clientscript_stack_effects(annotated_steps)
    return {
        "layout": layout,
        "annotated_steps": annotated_steps,
        "selected_mapping": dict(selected_mapping),
        "stack_tracking": stack_tracking,
    }


def _build_clientscript_opcode_probe_frontier_analysis(
    *,
    data_path: Path,
    frontier_offset: int,
    raw_opcode_types: dict[int, str] | None = None,
    raw_opcode_catalog: dict[int, dict[str, object]] | None = None,
) -> dict[str, object] | None:
    try:
        data = data_path.read_bytes()
        layout = _parse_clientscript_layout(data)
    except (OSError, ValueError):
        return None

    if frontier_offset < 0 or frontier_offset + 2 > len(layout.opcode_data):
        return None

    opcode_data = layout.opcode_data
    post_opcode_offset = frontier_offset + 2
    analysis: dict[str, object] = {
        "opcode_data_bytes": len(opcode_data),
        "remaining_opcode_bytes": max(len(opcode_data) - frontier_offset, 0),
        "remaining_bytes_after_opcode": max(len(opcode_data) - post_opcode_offset, 0),
        "hex_context": _sample_clientscript_hex_context(
            opcode_data,
            focus_offset=frontier_offset,
            focus_end_offset=min(len(opcode_data), frontier_offset + 2),
            bytes_before=8,
            bytes_after=16,
        ),
    }
    if post_opcode_offset < len(opcode_data):
        analysis["post_opcode_byte_hex"] = f"0x{opcode_data[post_opcode_offset]:02X}"

    width_landings: dict[str, dict[str, object]] = {}
    for width in range(0, 5):
        landing_offset = post_opcode_offset + width
        landing_entry: dict[str, object] = {"landing_offset": landing_offset}
        if landing_offset + 2 <= len(opcode_data):
            next_step = _peek_clientscript_next_opcode_instruction(
                layout,
                landing_offset,
                raw_opcode_types=raw_opcode_types,
                raw_opcode_catalog=raw_opcode_catalog,
            )
            if isinstance(next_step, dict):
                landing_entry["next_raw_opcode_hex"] = next_step.get("raw_opcode_hex")
                immediate_kind = next_step.get("immediate_kind")
                if isinstance(immediate_kind, str) and immediate_kind:
                    landing_entry["next_immediate_kind"] = immediate_kind
                semantic_label = next_step.get("semantic_label")
                if isinstance(semantic_label, str) and semantic_label:
                    landing_entry["next_semantic_label"] = semantic_label
                semantic_family = next_step.get("semantic_family")
                if isinstance(semantic_family, str) and semantic_family:
                    landing_entry["next_semantic_family"] = semantic_family
        width_landings[str(width)] = landing_entry
    analysis["width_landings"] = width_landings

    immediate_probes: dict[str, dict[str, object]] = {}
    for immediate_kind in ("byte", "short", "tribyte", "int", "switch"):
        immediate = _read_clientscript_immediate(opcode_data, post_opcode_offset, immediate_kind)
        if not isinstance(immediate, dict):
            continue
        probe_entry: dict[str, object] = {
            "immediate_value": immediate.get("immediate_value"),
            "end_offset": int(immediate["end_offset"]),
        }
        switch_subtype = immediate.get("switch_subtype")
        if isinstance(switch_subtype, int):
            probe_entry["switch_subtype"] = switch_subtype
        if int(immediate["end_offset"]) + 2 <= len(opcode_data):
            next_step = _peek_clientscript_next_opcode_instruction(
                layout,
                int(immediate["end_offset"]),
                raw_opcode_types=raw_opcode_types,
                raw_opcode_catalog=raw_opcode_catalog,
            )
            if isinstance(next_step, dict):
                probe_entry["next_raw_opcode_hex"] = next_step.get("raw_opcode_hex")
                next_immediate_kind = next_step.get("immediate_kind")
                if isinstance(next_immediate_kind, str) and next_immediate_kind:
                    probe_entry["next_immediate_kind"] = next_immediate_kind
                next_semantic_label = next_step.get("semantic_label")
                if isinstance(next_semantic_label, str) and next_semantic_label:
                    probe_entry["next_semantic_label"] = next_semantic_label
        immediate_probes[immediate_kind] = probe_entry
    if immediate_probes:
        analysis["immediate_probes"] = immediate_probes
    return analysis


CLIENTSCRIPT_OPCODE_PROBE_FRAMING_HYPOTHESES: tuple[dict[str, object], ...] = (
    {
        "name": "H0",
        "label": "zero-width-consumer",
        "immediate_kind": "none",
        "immediate_width": 0,
    },
    {
        "name": "H1",
        "label": "byte-payload-consumer",
        "immediate_kind": "byte",
        "immediate_width": 1,
    },
    {
        "name": "H2",
        "label": "short-payload-consumer",
        "immediate_kind": "short",
        "immediate_width": 2,
    },
    {
        "name": "H3",
        "label": "tribyte-payload-consumer",
        "immediate_kind": "tribyte",
        "immediate_width": 3,
    },
    {
        "name": "H4",
        "label": "int-payload-consumer",
        "immediate_kind": "int",
        "immediate_width": 4,
    },
)


def _make_clientscript_expression_from_operand_role(
    role: str,
    *,
    ordinal: int,
) -> dict[str, object]:
    normalized_role = str(role or "").strip()
    if normalized_role == "widget":
        return _make_clientscript_expression(
            "widget-reference",
            ordinal=ordinal,
            source="prefix-signature",
        )
    if normalized_role == "state-int":
        return _make_clientscript_expression(
            "state-reference",
            ordinal=ordinal,
            source_name="summary-state",
        )
    if normalized_role == "literal-int":
        return _make_clientscript_expression(
            "int-literal",
            value=0,
            ordinal=ordinal,
            source="prefix-signature",
        )
    if normalized_role == "slot-int":
        return _make_clientscript_expression(
            "slot-reference",
            slot=max(ordinal - 1, 0),
        )
    if normalized_role in {"string", "string-input"}:
        return _make_clientscript_expression(
            "string-input",
            ordinal=ordinal,
            stack_name="string",
        )
    return _make_clientscript_expression(
        "int-input",
        ordinal=ordinal,
        stack_name="int",
    )


def _build_clientscript_stack_state_from_operand_signature(
    signature: object,
) -> dict[str, object] | None:
    normalized_signature = str(signature or "").strip()
    if not normalized_signature:
        return None

    int_roles: list[str]
    string_roles: list[str]
    if normalized_signature == "widget-only":
        int_roles = ["widget"]
        string_roles = []
    elif normalized_signature == "widget+widget":
        int_roles = ["widget", "widget"]
        string_roles = []
    elif normalized_signature == "widget+state-int":
        int_roles = ["widget", "state-int"]
        string_roles = []
    elif normalized_signature == "widget+literal-int":
        int_roles = ["widget", "literal-int"]
        string_roles = []
    elif normalized_signature == "widget+slot-int":
        int_roles = ["widget", "slot-int"]
        string_roles = []
    elif normalized_signature == "widget+int":
        int_roles = ["widget", "symbolic-int"]
        string_roles = []
    elif normalized_signature == "int-only":
        int_roles = ["symbolic-int"]
        string_roles = []
    elif normalized_signature == "string-only":
        int_roles = []
        string_roles = ["string"]
    elif normalized_signature == "string+string":
        int_roles = []
        string_roles = ["string", "string"]
    elif normalized_signature == "int+string":
        int_roles = ["symbolic-int"]
        string_roles = ["string"]
    elif normalized_signature == "widget+string":
        int_roles = ["widget"]
        string_roles = ["string"]
    elif normalized_signature == "widget+int+string":
        int_roles = ["widget", "symbolic-int"]
        string_roles = ["string"]
    elif normalized_signature == "empty":
        int_roles = []
        string_roles = []
    else:
        return None

    state = _make_clientscript_stack_state()
    expression_stacks = state.setdefault(
        "expression_stacks",
        {stack_name: [] for stack_name in CLIENTSCRIPT_STACK_NAMES},
    )
    depths = state.setdefault("depths", {stack_name: 0 for stack_name in CLIENTSCRIPT_STACK_NAMES})
    expression_stacks["int"] = [
        _make_clientscript_expression_from_operand_role(role, ordinal=index + 1)
        for index, role in enumerate(int_roles)
    ]
    expression_stacks["string"] = [
        _make_clientscript_expression_from_operand_role(role, ordinal=index + 1)
        for index, role in enumerate(string_roles)
    ]
    expression_stacks.setdefault("long", [])
    depths["int"] = len(expression_stacks["int"])
    depths["string"] = len(expression_stacks["string"])
    depths.setdefault("long", 0)
    return state


def _hydrate_clientscript_stack_state_from_prefix_summary(
    summary: dict[str, object],
) -> dict[str, object] | None:
    if not isinstance(summary, dict) or not summary:
        return None
    has_concrete_stack_summary = any(
        key in summary
        for key in (
            "prefix_int_stack_expression_count",
            "prefix_string_stack_count",
            "prefix_int_stack_sample",
            "prefix_string_stack_sample",
        )
    )
    if not has_concrete_stack_summary:
        return _build_clientscript_stack_state_from_operand_signature(
            summary.get("prefix_operand_signature")
        )

    state = _make_clientscript_stack_state()
    depths = state.setdefault("depths", {stack_name: 0 for stack_name in CLIENTSCRIPT_STACK_NAMES})
    expression_stacks = state.setdefault(
        "expression_stacks",
        {stack_name: [] for stack_name in CLIENTSCRIPT_STACK_NAMES},
    )

    int_stack_sample = copy.deepcopy(summary.get("prefix_int_stack_sample", []))
    if not isinstance(int_stack_sample, list):
        int_stack_sample = []
    string_stack_sample = copy.deepcopy(summary.get("prefix_string_stack_sample", []))
    if not isinstance(string_stack_sample, list):
        string_stack_sample = []

    int_stack_count = int(summary.get("prefix_int_stack_expression_count", len(int_stack_sample)) or 0)
    string_stack_count = int(summary.get("prefix_string_stack_count", len(string_stack_sample)) or 0)

    int_stack: list[dict[str, object]] = [
        expression
        for expression in int_stack_sample
        if isinstance(expression, dict)
    ]
    string_stack: list[dict[str, object]] = [
        expression
        for expression in string_stack_sample
        if isinstance(expression, dict)
    ]

    missing_int_count = max(int_stack_count - len(int_stack), 0)
    missing_string_count = max(string_stack_count - len(string_stack), 0)
    if missing_int_count:
        int_stack = [
            _make_clientscript_expression(
                "symbolic-int",
                stack_name="int",
                ordinal=index + 1,
            )
            for index in range(missing_int_count)
        ] + int_stack
    if missing_string_count:
        string_stack = [
            _make_clientscript_expression(
                "string-input",
                stack_name="string",
                ordinal=index + 1,
            )
            for index in range(missing_string_count)
        ] + string_stack

    expression_stacks["int"] = int_stack
    expression_stacks["string"] = string_stack
    expression_stacks.setdefault("long", [])
    depths["int"] = len(int_stack)
    depths["string"] = len(string_stack)
    depths.setdefault("long", 0)
    return state


def _build_clientscript_opcode_probe_hypothesis_catalog(
    *,
    target_opcode: int,
    target_opcode_hex: str,
    stack_pops: Sequence[str],
    hypothesis: dict[str, object],
    sub_opcode: int | None,
) -> dict[int, dict[str, object]]:
    operand_signature = "+".join(str(token).strip() for token in stack_pops if str(token).strip()) or "empty"
    stack_effect_candidate = _make_clientscript_override_stack_effect_from_stack_pops(stack_pops)
    base_entry: dict[str, object] = {
        "mnemonic": f"{target_opcode_hex}_FRAMING_{str(hypothesis.get('name', 'H?'))}",
        "family": "opcode-probe-hypothesis",
        "operand_signature_candidate": {
            "signature": operand_signature,
            "confidence": 0.64,
            "notes": "Synthetic framing hypothesis derived from the blocked frontier prefix signature.",
        },
    }
    if isinstance(stack_effect_candidate, dict) and stack_effect_candidate:
        base_entry["stack_effect_candidate"] = dict(stack_effect_candidate)

    immediate_kind = str(hypothesis.get("immediate_kind", "") or "")
    if immediate_kind == "none":
        base_entry["immediate_kind"] = "none"
        return {target_opcode: base_entry}

    subtype_entry = {
        field: copy.deepcopy(value)
        for field, value in base_entry.items()
        if field != "operand_signature_candidate"
    }
    subtype_entry["operand_signature_candidate"] = copy.deepcopy(base_entry["operand_signature_candidate"])
    subtype_entry["immediate_kind"] = immediate_kind

    dispatch_entry = {
        "mnemonic": f"{target_opcode_hex}_FRAMING_DISPATCH",
        "family": "opcode-probe-hypothesis",
        "subtype_dispatch_mode": "strict",
        "subtypes": {
            int(sub_opcode or 0): subtype_entry,
        },
    }
    return {target_opcode: dispatch_entry}


def _score_clientscript_opcode_probe_framing_hypothesis_result(
    result: dict[str, object],
    *,
    target_opcode_hex: str,
    preferred_landing_opcode_hex: str | None = None,
) -> int:
    score = 0

    decode_status = str(result.get("decode_status", "") or "")
    if decode_status != "decoded":
        return -50

    step_required_input_delta = result.get("step_required_input_delta")
    if isinstance(step_required_input_delta, dict) and step_required_input_delta:
        score -= 20 * sum(int(value) for value in step_required_input_delta.values())
    else:
        score += 6

    path_required_input_delta = result.get("path_required_input_delta")
    if isinstance(path_required_input_delta, dict) and path_required_input_delta:
        score -= 12 * sum(int(value) for value in path_required_input_delta.values())
    else:
        score += 4

    path_status = str(result.get("path_status", "") or "")
    score += {
        "terminal": 10,
        "next-control-flow": 8,
        "frontier": 4,
        "instruction-budget": 1,
        "instruction-budget-hard": 0,
        "loop": -3,
        "out-of-bounds": -8,
        "invalid-immediate": -8,
        "missing-layout": -10,
        "missing-prefix-state": -10,
    }.get(path_status, 0)

    landing_probe = {
        "next_raw_opcode_hex": result.get("landing_raw_opcode_hex"),
        "next_semantic_label": result.get("landing_semantic_label"),
        "next_immediate_kind": result.get("landing_immediate_kind"),
    }
    score += _score_clientscript_opcode_probe_subtype_probe(
        landing_probe,
        target_opcode_hex=target_opcode_hex,
    )
    landing_raw_opcode_hex = result.get("landing_raw_opcode_hex")
    if isinstance(preferred_landing_opcode_hex, str) and preferred_landing_opcode_hex:
        if landing_raw_opcode_hex == preferred_landing_opcode_hex:
            score += 10
        elif isinstance(landing_raw_opcode_hex, str) and landing_raw_opcode_hex:
            score -= 3
    return score


def _probe_clientscript_opcode_frontier_framing_hypotheses(
    observation: dict[str, object],
    *,
    target_opcode: int,
    target_opcode_hex: str,
    raw_opcode_types: dict[int, str] | None = None,
    raw_opcode_catalog: dict[int, dict[str, object]] | None = None,
    data_path: Path | None = None,
    tail_stack_summary: dict[str, object] | None = None,
    tail_instruction_sample: list[dict[str, object]] | None = None,
    soft_instruction_limit: int = DEFAULT_CLIENTSCRIPT_BRANCH_PROBE_SOFT_LIMIT,
    hard_instruction_limit: int = DEFAULT_CLIENTSCRIPT_BRANCH_PROBE_HARD_LIMIT,
) -> dict[str, object] | None:
    if not isinstance(observation, dict):
        return None
    if not isinstance(data_path, Path):
        return None

    try:
        layout = _parse_clientscript_layout(data_path.read_bytes())
    except (OSError, ValueError):
        return None

    frontier_offset = observation.get("offset")
    if not isinstance(frontier_offset, int):
        return None
    if frontier_offset < 0 or frontier_offset + 2 > len(layout.opcode_data):
        return None

    initial_state = None
    if isinstance(tail_stack_summary, dict) and tail_stack_summary:
        initial_state = _hydrate_clientscript_stack_state_from_prefix_summary(tail_stack_summary)
    if initial_state is None and isinstance(tail_instruction_sample, list) and tail_instruction_sample:
        _annotated_steps, replay_state = _annotate_clientscript_opcode_probe_steps(tail_instruction_sample)
        initial_state = replay_state
    if initial_state is None:
        return {
            "archive_key": observation.get("archive_key"),
            "file_id": observation.get("file_id"),
            "offset": frontier_offset,
            "post_opcode_byte_hex": observation.get("post_opcode_byte_hex"),
            "operand_signature": observation.get("operand_signature"),
            "local_best_hypotheses": [],
            "local_winner": None,
            "local_tie": False,
            "hypotheses": [],
            "status": "missing-prefix-state",
        }

    probe_types = dict(raw_opcode_types or {})
    probe_types.pop(int(target_opcode), None)
    probe_catalog_base = dict(raw_opcode_catalog or {})
    stack_pops = _normalize_clientscript_opcode_probe_stack_pops(
        observation.get("operand_signature")
    )
    preferred_landing_opcode_hex = observation.get("tail_hint_raw_opcode_hex")
    if not isinstance(preferred_landing_opcode_hex, str) or not preferred_landing_opcode_hex:
        preferred_landing_opcode_hex = None
    sub_opcode = None
    if frontier_offset + 2 < len(layout.opcode_data):
        sub_opcode = int(layout.opcode_data[frontier_offset + 2])

    hypothesis_results: list[dict[str, object]] = []
    for hypothesis in CLIENTSCRIPT_OPCODE_PROBE_FRAMING_HYPOTHESES:
        hypothesis_name = str(hypothesis.get("name", "H?"))
        probe_catalog = dict(probe_catalog_base)
        probe_catalog.update(
            _build_clientscript_opcode_probe_hypothesis_catalog(
                target_opcode=target_opcode,
                target_opcode_hex=target_opcode_hex,
                stack_pops=stack_pops,
                hypothesis=hypothesis,
                sub_opcode=sub_opcode,
            )
        )

        decoded = _decode_clientscript_instruction_at_offset(
            layout,
            frontier_offset,
            raw_opcode_types=probe_types,
            raw_opcode_catalog=probe_catalog,
        )
        decode_status = str(decoded.get("status", "") or "")
        result: dict[str, object] = {
            "hypothesis": hypothesis_name,
            "label": hypothesis.get("label"),
            "immediate_kind": hypothesis.get("immediate_kind"),
            "immediate_width": hypothesis.get("immediate_width"),
            "decode_status": decode_status,
        }
        if decode_status != "decoded":
            result["score"] = _score_clientscript_opcode_probe_framing_hypothesis_result(
                result,
                target_opcode_hex=target_opcode_hex,
                preferred_landing_opcode_hex=preferred_landing_opcode_hex,
            )
            hypothesis_results.append(result)
            continue

        decoded_step = decoded.get("step")
        if not isinstance(decoded_step, dict):
            result["decode_status"] = "invalid-step"
            result["score"] = _score_clientscript_opcode_probe_framing_hypothesis_result(
                result,
                target_opcode_hex=target_opcode_hex,
                preferred_landing_opcode_hex=preferred_landing_opcode_hex,
            )
            hypothesis_results.append(result)
            continue

        pre_step_compact = _summarize_clientscript_stack_state_compact(initial_state)
        post_step_state = _clone_clientscript_stack_state(initial_state)
        annotated_step = _apply_clientscript_step_to_stack_state(
            copy.deepcopy(decoded_step),
            post_step_state,
        )
        post_step_compact = _summarize_clientscript_stack_state_compact(post_step_state)
        end_offset = annotated_step.get("end_offset")
        if not isinstance(end_offset, int):
            result["decode_status"] = "invalid-end-offset"
            result["score"] = _score_clientscript_opcode_probe_framing_hypothesis_result(
                result,
                target_opcode_hex=target_opcode_hex,
                preferred_landing_opcode_hex=preferred_landing_opcode_hex,
            )
            hypothesis_results.append(result)
            continue

        landing_step = _peek_clientscript_next_opcode_instruction(
            layout,
            end_offset,
            raw_opcode_types=probe_types,
            raw_opcode_catalog=probe_catalog,
        )
        path = _trace_clientscript_bounded_stack_path(
            layout,
            start_offset=end_offset,
            initial_state=post_step_state,
            raw_opcode_types=probe_types,
            raw_opcode_catalog=probe_catalog,
            soft_instruction_limit=soft_instruction_limit,
            hard_instruction_limit=hard_instruction_limit,
        )

        result.update(
            {
                "decoded_step": _sample_clientscript_opcode_probe_step(annotated_step),
                "decoded_immediate_value": annotated_step.get("immediate_value"),
                "step_required_input_delta": _diff_clientscript_required_inputs(
                    initial_state,
                    post_step_state,
                ),
                "step_survivor_delta": _compact_clientscript_stack_compact_survivor_delta(
                    pre_step_compact,
                    post_step_compact,
                ),
                "step_survivor_delta_detail": _diff_clientscript_stack_compact_survivor_delta(
                    pre_step_compact,
                    post_step_compact,
                ),
                "step_pre_operand_signature": pre_step_compact.get("operand_signature"),
                "step_pre_operand_signature_normalized": _normalize_clientscript_operand_signature_for_matching(
                    pre_step_compact.get("operand_signature")
                ),
                "step_post_operand_signature": post_step_compact.get("operand_signature"),
                "step_post_operand_signature_normalized": _normalize_clientscript_operand_signature_for_matching(
                    post_step_compact.get("operand_signature")
                ),
                "landing_raw_opcode_hex": (
                    landing_step.get("raw_opcode_hex")
                    if isinstance(landing_step, dict)
                    else None
                ),
                "landing_semantic_label": (
                    landing_step.get("semantic_label")
                    if isinstance(landing_step, dict)
                    else None
                ),
                "landing_immediate_kind": (
                    landing_step.get("immediate_kind")
                    if isinstance(landing_step, dict)
                    else None
                ),
                "path_status": path.get("status"),
                "path_required_input_delta": copy.deepcopy(path.get("required_input_delta", {})),
                "path_final_operand_signature": (
                    path.get("final_stack_compact", {}).get("operand_signature")
                    if isinstance(path.get("final_stack_compact"), dict)
                    else None
                ),
                "path_instruction_sample": list(path.get("instruction_sample", []))[:4]
                if isinstance(path.get("instruction_sample"), list)
                else [],
            }
        )
        result["score"] = _score_clientscript_opcode_probe_framing_hypothesis_result(
            result,
            target_opcode_hex=target_opcode_hex,
            preferred_landing_opcode_hex=preferred_landing_opcode_hex,
        )
        hypothesis_results.append(result)

    best_score = max((int(entry.get("score", -9999)) for entry in hypothesis_results), default=-9999)
    best_hypotheses = [
        str(entry.get("hypothesis"))
        for entry in hypothesis_results
        if int(entry.get("score", -9999)) == best_score
    ]
    local_winner_entry = None
    if hypothesis_results:
        local_winner_entry = min(
            (
                entry
                for entry in hypothesis_results
                if int(entry.get("score", -9999)) == best_score
            ),
            key=lambda entry: int(entry.get("immediate_width", 999)),
        )

    return {
        "archive_key": observation.get("archive_key"),
        "file_id": observation.get("file_id"),
        "offset": frontier_offset,
        "post_opcode_byte_hex": observation.get("post_opcode_byte_hex"),
        "operand_signature": observation.get("operand_signature"),
        "local_best_hypotheses": best_hypotheses,
        "local_winner": (
            str(local_winner_entry.get("hypothesis"))
            if isinstance(local_winner_entry, dict)
            else None
        ),
        "local_tie": len(best_hypotheses) > 1,
        "hypotheses": sorted(
            hypothesis_results,
            key=lambda entry: (
                -int(entry.get("score", -9999)),
                int(entry.get("immediate_width", 999)),
            ),
        ),
    }


def _classify_clientscript_opcode_probe_hypothesis_consensus(
    *,
    observation_count: int,
    dominant_winner_count: int,
    local_tie_count: int,
) -> str:
    if observation_count <= 0:
        return "low"
    winner_ratio = dominant_winner_count / observation_count
    tie_ratio = local_tie_count / observation_count
    if observation_count >= 2 and winner_ratio >= 0.8 and tie_ratio <= 0.2:
        return "high"
    if observation_count >= 2 and winner_ratio >= 0.5:
        return "medium"
    return "low"


def _summarize_clientscript_opcode_probe_framing_hypotheses(
    observations: list[dict[str, object]],
    *,
    contexts: dict[tuple[int, int, int], dict[str, object]],
    target_opcode: int,
    target_opcode_hex: str,
    raw_opcode_types: dict[int, str] | None = None,
    raw_opcode_catalog: dict[int, dict[str, object]] | None = None,
) -> dict[str, dict[str, object]]:
    summaries: dict[str, dict[str, object]] = {}

    for observation in observations:
        if not isinstance(observation, dict):
            continue
        archive_key = observation.get("archive_key")
        file_id = observation.get("file_id")
        offset = observation.get("offset")
        if not isinstance(archive_key, int) or not isinstance(file_id, int) or not isinstance(offset, int):
            continue
        context = contexts.get((archive_key, file_id, offset))
        if not isinstance(context, dict):
            continue

        probe_result = _probe_clientscript_opcode_frontier_framing_hypotheses(
            observation,
            target_opcode=target_opcode,
            target_opcode_hex=target_opcode_hex,
            raw_opcode_types=raw_opcode_types,
            raw_opcode_catalog=raw_opcode_catalog,
            data_path=context.get("data_path"),
            tail_stack_summary=context.get("tail_stack_summary"),
            tail_instruction_sample=context.get("tail_instruction_sample"),
        )
        if not isinstance(probe_result, dict):
            continue

        sub_opcode_hex = probe_result.get("post_opcode_byte_hex")
        if not isinstance(sub_opcode_hex, str) or not sub_opcode_hex:
            continue

        summary = summaries.setdefault(
            sub_opcode_hex,
            {
                "sub_opcode_hex": sub_opcode_hex,
                "observation_count": 0,
                "local_winner_counts": Counter(),
                "local_tie_count": 0,
                "hypothesis_profiles": {},
                "observation_sample": [],
            },
        )
        summary["observation_count"] = int(summary["observation_count"]) + 1
        if probe_result.get("local_tie") is True:
            summary["local_tie_count"] = int(summary.get("local_tie_count", 0)) + 1
        local_winner = probe_result.get("local_winner")
        if isinstance(local_winner, str) and local_winner:
            summary["local_winner_counts"][local_winner] += 1

        if len(summary["observation_sample"]) < 4:
            summary["observation_sample"].append(
                {
                    "archive_key": probe_result.get("archive_key"),
                    "file_id": probe_result.get("file_id"),
                    "offset": probe_result.get("offset"),
                    "operand_signature": probe_result.get("operand_signature"),
                    "local_best_hypotheses": list(probe_result.get("local_best_hypotheses", [])),
                    "local_winner": local_winner,
                    "local_tie": bool(probe_result.get("local_tie")),
                    "hypotheses": [
                        {
                            "hypothesis": entry.get("hypothesis"),
                            "immediate_kind": entry.get("immediate_kind"),
                            "immediate_width": entry.get("immediate_width"),
                            "decoded_immediate_value": entry.get("decoded_immediate_value"),
                            "landing_raw_opcode_hex": entry.get("landing_raw_opcode_hex"),
                            "landing_semantic_label": entry.get("landing_semantic_label"),
                            "path_status": entry.get("path_status"),
                            "step_survivor_delta": copy.deepcopy(
                                entry.get("step_survivor_delta", {})
                            ),
                            "step_survivor_delta_detail": copy.deepcopy(
                                entry.get("step_survivor_delta_detail", {})
                            ),
                            "step_pre_operand_signature": entry.get(
                                "step_pre_operand_signature"
                            ),
                            "step_pre_operand_signature_normalized": entry.get(
                                "step_pre_operand_signature_normalized"
                            ),
                            "step_post_operand_signature": entry.get(
                                "step_post_operand_signature"
                            ),
                            "step_post_operand_signature_normalized": entry.get(
                                "step_post_operand_signature_normalized"
                            ),
                            "step_required_input_delta": copy.deepcopy(
                                entry.get("step_required_input_delta", {})
                            ),
                            "path_required_input_delta": copy.deepcopy(
                                entry.get("path_required_input_delta", {})
                            ),
                            "score": entry.get("score"),
                        }
                        for entry in probe_result.get("hypotheses", [])
                        if isinstance(entry, dict)
                    ],
                }
            )

        for entry in probe_result.get("hypotheses", []):
            if not isinstance(entry, dict):
                continue
            hypothesis_name = str(entry.get("hypothesis", "H?"))
            profile = summary["hypothesis_profiles"].setdefault(
                hypothesis_name,
                {
                    "immediate_kind": entry.get("immediate_kind"),
                    "immediate_width": entry.get("immediate_width"),
                    "score_values": [],
                    "landing_opcode_counts": Counter(),
                    "landing_semantic_label_counts": Counter(),
                    "path_status_counts": Counter(),
                    "step_survivor_delta_counts": Counter(),
                    "step_post_operand_signature_counts": Counter(),
                    "step_post_operand_signature_normalized_counts": Counter(),
                    "step_phantom_input_count": 0,
                    "path_phantom_input_count": 0,
                    "local_win_count": 0,
                },
            )
            profile["score_values"].append(int(entry.get("score", 0)))
            landing_raw_opcode_hex = entry.get("landing_raw_opcode_hex")
            if isinstance(landing_raw_opcode_hex, str) and landing_raw_opcode_hex:
                profile["landing_opcode_counts"][landing_raw_opcode_hex] += 1
            landing_semantic_label = entry.get("landing_semantic_label")
            if isinstance(landing_semantic_label, str) and landing_semantic_label:
                profile["landing_semantic_label_counts"][landing_semantic_label] += 1
            path_status = entry.get("path_status")
            if isinstance(path_status, str) and path_status:
                profile["path_status_counts"][path_status] += 1
            step_survivor_delta = entry.get("step_survivor_delta")
            if isinstance(step_survivor_delta, dict):
                profile["step_survivor_delta_counts"][
                    json.dumps(step_survivor_delta, sort_keys=True)
                    if step_survivor_delta
                    else "{}"
                ] += 1
            step_post_operand_signature = entry.get("step_post_operand_signature")
            if isinstance(step_post_operand_signature, str) and step_post_operand_signature:
                profile["step_post_operand_signature_counts"][step_post_operand_signature] += 1
            step_post_operand_signature_normalized = entry.get(
                "step_post_operand_signature_normalized"
            )
            if (
                isinstance(step_post_operand_signature_normalized, str)
                and step_post_operand_signature_normalized
            ):
                profile["step_post_operand_signature_normalized_counts"][
                    step_post_operand_signature_normalized
                ] += 1
            if isinstance(entry.get("step_required_input_delta"), dict) and entry.get("step_required_input_delta"):
                profile["step_phantom_input_count"] = int(profile["step_phantom_input_count"]) + 1
            if isinstance(entry.get("path_required_input_delta"), dict) and entry.get("path_required_input_delta"):
                profile["path_phantom_input_count"] = int(profile["path_phantom_input_count"]) + 1
            if local_winner == hypothesis_name:
                profile["local_win_count"] = int(profile["local_win_count"]) + 1

    normalized_summaries: dict[str, dict[str, object]] = {}
    for sub_opcode_hex, summary in summaries.items():
        local_winner_counts = Counter(summary.get("local_winner_counts", Counter()))
        dominant_hypothesis, dominant_winner_count = (
            local_winner_counts.most_common(1)[0]
            if local_winner_counts
            else (None, 0)
        )
        normalized_profiles: dict[str, dict[str, object]] = {}
        for hypothesis_name, profile in summary.get("hypothesis_profiles", {}).items():
            if not isinstance(profile, dict):
                continue
            score_values = list(profile.get("score_values", []))
            landing_opcode_counts = Counter(profile.get("landing_opcode_counts", Counter()))
            landing_semantic_label_counts = Counter(
                profile.get("landing_semantic_label_counts", Counter())
            )
            path_status_counts = Counter(profile.get("path_status_counts", Counter()))
            step_survivor_delta_counts = Counter(profile.get("step_survivor_delta_counts", Counter()))
            step_post_operand_signature_counts = Counter(
                profile.get("step_post_operand_signature_counts", Counter())
            )
            step_post_operand_signature_normalized_counts = Counter(
                profile.get("step_post_operand_signature_normalized_counts", Counter())
            )
            normalized_profile = {
                "immediate_kind": profile.get("immediate_kind"),
                "immediate_width": profile.get("immediate_width"),
                "score_range": {
                    "min": min(score_values) if score_values else None,
                    "max": max(score_values) if score_values else None,
                },
                "landing_opcode_counts": dict(
                    sorted(landing_opcode_counts.items(), key=lambda item: (-int(item[1]), str(item[0])))
                ),
                "landing_semantic_label_counts": dict(
                    sorted(
                        landing_semantic_label_counts.items(),
                        key=lambda item: (-int(item[1]), str(item[0])),
                    )
                ),
                "path_status_counts": dict(
                    sorted(path_status_counts.items(), key=lambda item: (-int(item[1]), str(item[0])))
                ),
                "step_survivor_delta_counts": dict(
                    sorted(
                        step_survivor_delta_counts.items(),
                        key=lambda item: (-int(item[1]), str(item[0])),
                    )
                ),
                "step_post_operand_signature_counts": dict(
                    sorted(
                        step_post_operand_signature_counts.items(),
                        key=lambda item: (-int(item[1]), str(item[0])),
                    )
                ),
                "step_post_operand_signature_normalized_counts": dict(
                    sorted(
                        step_post_operand_signature_normalized_counts.items(),
                        key=lambda item: (-int(item[1]), str(item[0])),
                    )
                ),
                "step_phantom_input_count": int(profile.get("step_phantom_input_count", 0)),
                "path_phantom_input_count": int(profile.get("path_phantom_input_count", 0)),
                "local_win_count": int(profile.get("local_win_count", 0)),
            }
            normalized_profiles[hypothesis_name] = normalized_profile

        normalized_summary = {
            "sub_opcode_hex": sub_opcode_hex,
            "observation_count": int(summary.get("observation_count", 0)),
            "local_winner_counts": dict(
                sorted(local_winner_counts.items(), key=lambda item: (-int(item[1]), str(item[0])))
            ),
            "local_tie_count": int(summary.get("local_tie_count", 0)),
            "hypothesis_profiles": normalized_profiles,
            "observation_sample": list(summary.get("observation_sample", [])),
            "confidence": _classify_clientscript_opcode_probe_hypothesis_consensus(
                observation_count=int(summary.get("observation_count", 0)),
                dominant_winner_count=int(dominant_winner_count),
                local_tie_count=int(summary.get("local_tie_count", 0)),
            ),
        }
        if isinstance(dominant_hypothesis, str) and dominant_hypothesis:
            dominant_profile = normalized_profiles.get(dominant_hypothesis, {})
            normalized_summary["dominant_hypothesis"] = dominant_hypothesis
            normalized_summary["recommended_immediate_kind"] = dominant_profile.get("immediate_kind")
            normalized_summary["recommended_immediate_width"] = dominant_profile.get("immediate_width")
            landing_opcode_counts = dominant_profile.get("landing_opcode_counts", {})
            if isinstance(landing_opcode_counts, dict) and landing_opcode_counts:
                normalized_summary["recommended_landing_opcode_hex"] = next(iter(landing_opcode_counts))
            landing_semantic_label_counts = dominant_profile.get("landing_semantic_label_counts", {})
            if isinstance(landing_semantic_label_counts, dict) and landing_semantic_label_counts:
                normalized_summary["recommended_landing_semantic_label"] = next(
                    iter(landing_semantic_label_counts)
                )
            step_survivor_delta_counts = dominant_profile.get("step_survivor_delta_counts", {})
            if isinstance(step_survivor_delta_counts, dict) and step_survivor_delta_counts:
                first_delta_key = next(iter(step_survivor_delta_counts))
                try:
                    normalized_summary["recommended_step_survivor_delta"] = json.loads(
                        first_delta_key
                    )
                except (TypeError, ValueError, json.JSONDecodeError):
                    pass
            step_post_operand_signature_counts = dominant_profile.get(
                "step_post_operand_signature_counts", {}
            )
            if (
                isinstance(step_post_operand_signature_counts, dict)
                and step_post_operand_signature_counts
            ):
                normalized_summary["recommended_step_post_operand_signature"] = next(
                    iter(step_post_operand_signature_counts)
                )
            step_post_operand_signature_normalized_counts = dominant_profile.get(
                "step_post_operand_signature_normalized_counts", {}
            )
            if (
                isinstance(step_post_operand_signature_normalized_counts, dict)
                and step_post_operand_signature_normalized_counts
            ):
                normalized_summary["recommended_step_post_operand_signature_normalized"] = next(
                    iter(step_post_operand_signature_normalized_counts)
                )

        normalized_summaries[sub_opcode_hex] = normalized_summary

    return normalized_summaries


def _normalize_clientscript_operand_signature_for_matching(signature: str | None) -> str:
    if not isinstance(signature, str) or not signature.strip():
        return "empty"

    alias_map = {
        "literal-int": "int",
        "int-literal": "int",
        "state-int": "int",
        "slot-int": "int",
        "symbolic-int": "int",
        "const-int": "int",
        "widget-id": "widget",
    }
    normalized_tokens = [
        alias_map.get(token.strip(), token.strip())
        for token in signature.split("+")
        if token.strip()
    ]
    return "+".join(normalized_tokens) or "empty"


def _normalize_clientscript_opcode_probe_stack_pops(signature: str | None) -> list[str]:
    normalized_signature = _normalize_clientscript_operand_signature_for_matching(signature)
    if normalized_signature == "empty":
        return []

    token_alias_map = {
        "widget-only": "widget",
        "int-only": "int",
        "string-only": "string",
    }
    return [
        token_alias_map.get(token.strip(), token.strip())
        for token in normalized_signature.split("+")
        if token.strip()
    ]


def _reconcile_clientscript_opcode_probe_subtype_candidate_with_framing_summary(
    candidate: dict[str, object],
    framing_summary: dict[str, object],
) -> None:
    if not isinstance(candidate, dict) or not isinstance(framing_summary, dict):
        return

    framing_confidence = str(framing_summary.get("confidence", "") or "").lower()
    if framing_confidence not in {"high", "medium"}:
        return

    local_winner_counts = framing_summary.get("local_winner_counts")
    decisive_local_winner_count = 0
    if isinstance(local_winner_counts, dict):
        decisive_local_winner_count = sum(
            1
            for value in local_winner_counts.values()
            if isinstance(value, int) and value > 0
        )
    local_tie_count = framing_summary.get("local_tie_count")
    has_local_ties = isinstance(local_tie_count, int) and local_tie_count > 0
    framing_is_decisive = framing_confidence == "high" or (
        framing_confidence == "medium"
        and not has_local_ties
        and decisive_local_winner_count == 1
    )

    framing_kind = framing_summary.get("recommended_immediate_kind")
    framing_width = framing_summary.get("recommended_immediate_width")
    current_kind = candidate.get("recommended_immediate_kind")
    current_width = candidate.get("recommended_immediate_width")
    conflict = current_kind != framing_kind or current_width != framing_width

    candidate["framing_confidence"] = framing_confidence
    candidate["framing_conflict"] = conflict
    candidate["framing_decisive"] = framing_is_decisive
    if not conflict:
        candidate.setdefault("recommended_by", "raw-subtype")
        return
    if not framing_is_decisive:
        candidate.setdefault("recommended_by", "raw-subtype")
        return

    candidate["recommended_by"] = "bounded-hypothesis"
    candidate["raw_recommended_immediate_kind"] = current_kind
    candidate["raw_recommended_immediate_width"] = current_width
    candidate["raw_recommended_landing_opcode_hex"] = candidate.get("recommended_landing_opcode_hex")
    candidate["raw_recommended_landing_semantic_label"] = candidate.get(
        "recommended_landing_semantic_label"
    )

    if isinstance(framing_kind, str) and framing_kind:
        candidate["recommended_immediate_kind"] = framing_kind
    if isinstance(framing_width, int):
        candidate["recommended_immediate_width"] = framing_width
    elif "recommended_immediate_width" in candidate:
        candidate.pop("recommended_immediate_width", None)

    framing_landing_opcode = framing_summary.get("recommended_landing_opcode_hex")
    if isinstance(framing_landing_opcode, str) and framing_landing_opcode:
        candidate["recommended_landing_opcode_hex"] = framing_landing_opcode

    framing_landing_label = framing_summary.get("recommended_landing_semantic_label")
    if isinstance(framing_landing_label, str) and framing_landing_label:
        candidate["recommended_landing_semantic_label"] = framing_landing_label

    suggested_override = candidate.get("suggested_override")
    if isinstance(suggested_override, dict):
        if isinstance(framing_kind, str) and framing_kind:
            suggested_override["immediate_kind"] = framing_kind
        if isinstance(framing_width, int):
            suggested_override["immediate_width"] = framing_width
        reconciliation_note = (
            "Framing reconciled from the raw subtype score to the bounded hypothesis winner."
        )
        existing_notes = suggested_override.get("notes")
        if isinstance(existing_notes, str) and existing_notes.strip():
            suggested_override["notes"] = f"{existing_notes.strip()} {reconciliation_note}"
        else:
            suggested_override["notes"] = reconciliation_note


def _score_clientscript_opcode_probe_subtype_probe(
    probe_entry: dict[str, object],
    *,
    target_opcode_hex: str,
) -> int:
    score = 0
    next_raw_opcode_hex = probe_entry.get("next_raw_opcode_hex")
    if isinstance(next_raw_opcode_hex, str) and next_raw_opcode_hex:
        if next_raw_opcode_hex == target_opcode_hex:
            score -= 3
        elif next_raw_opcode_hex == "0x0000":
            score -= 1
        elif next_raw_opcode_hex == "0xFFFF":
            score -= 1
        else:
            score += 2
    else:
        score -= 2

    next_semantic_label = probe_entry.get("next_semantic_label")
    if isinstance(next_semantic_label, str) and next_semantic_label:
        score += 6

    next_immediate_kind = probe_entry.get("next_immediate_kind")
    if isinstance(next_immediate_kind, str) and next_immediate_kind:
        score += 1

    return score


def _build_clientscript_opcode_probe_subtype_name(
    sub_opcode_hex: str,
    *,
    stack_pops: Sequence[str],
) -> str:
    subtype_suffix = sub_opcode_hex.removeprefix("0x")
    if list(stack_pops) == ["widget", "widget"]:
        prefix = "WIDGET_LINK_EXTENSION"
    elif list(stack_pops) == ["widget", "string"]:
        prefix = "WIDGET_TEXT_EXTENSION"
    elif list(stack_pops) == ["widget", "int"]:
        prefix = "WIDGET_STATE_EXTENSION"
    elif stack_pops and stack_pops[0] == "widget":
        prefix = "WIDGET_EXTENSION"
    elif stack_pops and stack_pops[0] == "string":
        prefix = "STRING_EXTENSION"
    elif stack_pops and stack_pops[0] == "int":
        prefix = "STATE_EXTENSION"
    else:
        prefix = "EXTENSION_SUBTYPE"
    return f"{prefix}_{subtype_suffix}_CANDIDATE"


def _classify_clientscript_opcode_probe_subtype_confidence(
    *,
    observation_count: int,
    dominant_signature_count: int,
    dominant_width_count: int,
    dominant_next_opcode_count: int,
) -> str:
    if observation_count <= 0:
        return "low"

    signature_ratio = dominant_signature_count / observation_count
    width_ratio = dominant_width_count / observation_count
    next_opcode_ratio = dominant_next_opcode_count / observation_count

    if (
        observation_count >= 2
        and signature_ratio >= 0.85
        and width_ratio >= 0.85
        and next_opcode_ratio >= 0.7
    ):
        return "high"
    if (
        observation_count >= 2
        and signature_ratio >= 0.6
        and width_ratio >= 0.6
        and next_opcode_ratio >= 0.5
    ):
        return "medium"
    return "low"


def _summarize_clientscript_opcode_probe_subtype_candidates(
    observations: list[dict[str, object]],
    *,
    clusters: Sequence[dict[str, object]],
    target_opcode_hex: str,
) -> tuple[list[dict[str, object]], list[dict[str, object]]]:
    subtype_groups: dict[str, dict[str, object]] = {}
    clusters_by_subtype: dict[str, list[dict[str, object]]] = {}
    terminal_clusters: list[dict[str, object]] = []

    for cluster in clusters:
        if not isinstance(cluster, dict):
            continue
        post_opcode_byte_hex = cluster.get("post_opcode_byte_hex")
        cluster_entry = {
            "count": int(cluster.get("count", 0)),
            "operand_signature": cluster.get("operand_signature"),
            "post_opcode_byte_hex": post_opcode_byte_hex,
            "width_landing_pattern": copy.deepcopy(cluster.get("width_landing_pattern", {})),
            "key_sample": list(cluster.get("key_sample", []))[:10],
            "tail_hint_raw_opcode_counts": copy.deepcopy(cluster.get("tail_hint_raw_opcode_counts", {})),
            "previous_raw_opcode_counts": copy.deepcopy(cluster.get("previous_raw_opcode_counts", {})),
            "remaining_bytes_after_opcode_min": cluster.get("remaining_bytes_after_opcode_min"),
            "remaining_bytes_after_opcode_max": cluster.get("remaining_bytes_after_opcode_max"),
        }
        if isinstance(post_opcode_byte_hex, str) and post_opcode_byte_hex:
            clusters_by_subtype.setdefault(post_opcode_byte_hex, []).append(cluster_entry)
        else:
            terminal_clusters.append(cluster_entry)

    for observation in observations:
        if not isinstance(observation, dict):
            continue
        post_opcode_byte_hex = observation.get("post_opcode_byte_hex")
        if not isinstance(post_opcode_byte_hex, str) or not post_opcode_byte_hex:
            continue

        subtype_group = subtype_groups.setdefault(
            post_opcode_byte_hex,
            {
                "sub_opcode": int(post_opcode_byte_hex, 16),
                "sub_opcode_hex": post_opcode_byte_hex,
                "subtype_key": f"{target_opcode_hex}/{post_opcode_byte_hex}",
                "observation_count": 0,
                "key_sample": [],
                "operand_signature_counts": Counter(),
                "best_immediate_width_counts": Counter(),
                "best_immediate_kind_counts": Counter(),
                "best_next_opcode_counts": Counter(),
                "best_next_semantic_label_counts": Counter(),
                "best_probe_scores": [],
            },
        )
        subtype_group["observation_count"] = int(subtype_group["observation_count"]) + 1
        _append_int_sample(subtype_group["key_sample"], int(observation.get("archive_key", 0)))

        operand_signature = str(observation.get("operand_signature", "") or "unknown")
        subtype_group["operand_signature_counts"][operand_signature] += 1

        best_probe: dict[str, object] | None = None
        best_probe_key: str | None = None
        post_opcode_offset = None
        offset = observation.get("offset")
        if isinstance(offset, int):
            post_opcode_offset = offset + 2

        immediate_probes = observation.get("immediate_probes")
        if isinstance(immediate_probes, dict):
            for immediate_kind, probe_entry in immediate_probes.items():
                if not isinstance(probe_entry, dict):
                    continue
                score = _score_clientscript_opcode_probe_subtype_probe(
                    probe_entry,
                    target_opcode_hex=target_opcode_hex,
                )
                end_offset = probe_entry.get("end_offset")
                if isinstance(post_opcode_offset, int) and isinstance(end_offset, int):
                    immediate_width = max(end_offset - post_opcode_offset, 0)
                else:
                    immediate_width = None
                candidate = {
                    "immediate_kind": immediate_kind,
                    "immediate_width": immediate_width,
                    "score": score,
                    "next_raw_opcode_hex": probe_entry.get("next_raw_opcode_hex"),
                    "next_semantic_label": probe_entry.get("next_semantic_label"),
                }
                if best_probe is None:
                    best_probe = candidate
                    best_probe_key = str(immediate_kind)
                    continue
                previous_width = best_probe.get("immediate_width")
                current_width = candidate.get("immediate_width")
                if (
                    score > int(best_probe.get("score", 0))
                    or (
                        score == int(best_probe.get("score", 0))
                        and isinstance(current_width, int)
                        and (
                            not isinstance(previous_width, int)
                            or current_width < previous_width
                        )
                    )
                ):
                    best_probe = candidate
                    best_probe_key = str(immediate_kind)

        if isinstance(best_probe, dict):
            immediate_width = best_probe.get("immediate_width")
            if isinstance(immediate_width, int):
                subtype_group["best_immediate_width_counts"][immediate_width] += 1
            if isinstance(best_probe_key, str) and best_probe_key:
                subtype_group["best_immediate_kind_counts"][best_probe_key] += 1
            next_raw_opcode_hex = best_probe.get("next_raw_opcode_hex")
            if isinstance(next_raw_opcode_hex, str) and next_raw_opcode_hex:
                subtype_group["best_next_opcode_counts"][next_raw_opcode_hex] += 1
            next_semantic_label = best_probe.get("next_semantic_label")
            if isinstance(next_semantic_label, str) and next_semantic_label:
                subtype_group["best_next_semantic_label_counts"][next_semantic_label] += 1
            subtype_group["best_probe_scores"].append(int(best_probe.get("score", 0)))

    subtype_candidates: list[dict[str, object]] = []
    for sub_opcode_hex, subtype_group in subtype_groups.items():
        observation_count = int(subtype_group.get("observation_count", 0))
        operand_signature_counts = Counter(subtype_group.get("operand_signature_counts", Counter()))
        best_width_counts = Counter(subtype_group.get("best_immediate_width_counts", Counter()))
        best_kind_counts = Counter(subtype_group.get("best_immediate_kind_counts", Counter()))
        best_next_opcode_counts = Counter(subtype_group.get("best_next_opcode_counts", Counter()))
        best_next_semantic_label_counts = Counter(
            subtype_group.get("best_next_semantic_label_counts", Counter())
        )

        dominant_signature, dominant_signature_count = (
            operand_signature_counts.most_common(1)[0]
            if operand_signature_counts
            else ("unknown", 0)
        )
        dominant_width, dominant_width_count = (
            best_width_counts.most_common(1)[0]
            if best_width_counts
            else (None, 0)
        )
        dominant_kind, _dominant_kind_count = (
            best_kind_counts.most_common(1)[0]
            if best_kind_counts
            else (None, 0)
        )
        dominant_next_opcode, dominant_next_opcode_count = (
            best_next_opcode_counts.most_common(1)[0]
            if best_next_opcode_counts
            else (None, 0)
        )
        dominant_next_semantic_label, _dominant_label_count = (
            best_next_semantic_label_counts.most_common(1)[0]
            if best_next_semantic_label_counts
            else (None, 0)
        )

        confidence = _classify_clientscript_opcode_probe_subtype_confidence(
            observation_count=observation_count,
            dominant_signature_count=int(dominant_signature_count),
            dominant_width_count=int(dominant_width_count),
            dominant_next_opcode_count=int(dominant_next_opcode_count),
        )
        stack_pops = _normalize_clientscript_opcode_probe_stack_pops(dominant_signature)

        candidate: dict[str, object] = {
            "subtype_key": str(subtype_group["subtype_key"]),
            "sub_opcode": int(subtype_group["sub_opcode"]),
            "sub_opcode_hex": sub_opcode_hex,
            "observation_count": observation_count,
            "key_sample": list(subtype_group.get("key_sample", []))[:12],
            "operand_signature_counts": dict(
                sorted(operand_signature_counts.items(), key=lambda item: (-int(item[1]), str(item[0])))
            ),
            "best_immediate_width_counts": dict(
                sorted(best_width_counts.items(), key=lambda item: (-int(item[1]), int(item[0])))
            ),
            "best_immediate_kind_counts": dict(
                sorted(best_kind_counts.items(), key=lambda item: (-int(item[1]), str(item[0])))
            ),
            "best_next_opcode_counts": dict(
                sorted(best_next_opcode_counts.items(), key=lambda item: (-int(item[1]), str(item[0])))
            ),
            "best_next_semantic_label_counts": dict(
                sorted(
                    best_next_semantic_label_counts.items(),
                    key=lambda item: (-int(item[1]), str(item[0])),
                )
            ),
            "confidence": confidence,
            "dominant_operand_signature": dominant_signature,
            "dominant_stack_pops": stack_pops,
            "cluster_count": len(clusters_by_subtype.get(sub_opcode_hex, [])),
            "clusters": sorted(
                clusters_by_subtype.get(sub_opcode_hex, []),
                key=lambda entry: (-int(entry.get("count", 0)), str(entry.get("operand_signature") or "")),
            ),
        }

        probe_scores = subtype_group.get("best_probe_scores", [])
        if isinstance(probe_scores, list) and probe_scores:
            candidate["best_probe_score_range"] = {
                "min": min(int(score) for score in probe_scores),
                "max": max(int(score) for score in probe_scores),
            }

        if isinstance(dominant_width, int):
            candidate["recommended_immediate_width"] = dominant_width
        if isinstance(dominant_kind, str) and dominant_kind:
            candidate["recommended_immediate_kind"] = dominant_kind
        if isinstance(dominant_next_opcode, str) and dominant_next_opcode:
            candidate["recommended_landing_opcode_hex"] = dominant_next_opcode
        if isinstance(dominant_next_semantic_label, str) and dominant_next_semantic_label:
            candidate["recommended_landing_semantic_label"] = dominant_next_semantic_label

        if confidence in {"high", "medium"} and isinstance(dominant_width, int):
            candidate["suggested_override"] = {
                "opcode": target_opcode_hex,
                "sub_opcode": sub_opcode_hex,
                "name": _build_clientscript_opcode_probe_subtype_name(
                    sub_opcode_hex,
                    stack_pops=stack_pops,
                ),
                "immediate_width": dominant_width,
                "stack_pops": stack_pops,
                "confidence": confidence,
            }
            if isinstance(dominant_kind, str) and dominant_kind:
                candidate["suggested_override"]["immediate_kind"] = dominant_kind

        subtype_candidates.append(candidate)

    subtype_candidates.sort(
        key=lambda entry: (
            {"high": 0, "medium": 1, "low": 2}.get(str(entry.get("confidence")), 3),
            -int(entry.get("observation_count", 0)),
            str(entry.get("sub_opcode_hex") or ""),
        )
    )
    terminal_clusters.sort(
        key=lambda entry: (
            -int(entry.get("count", 0)),
            str(entry.get("operand_signature") or ""),
        )
    )
    return subtype_candidates, terminal_clusters


def _summarize_clientscript_opcode_probe_frontier_clusters(
    observations: list[dict[str, object]],
) -> list[dict[str, object]]:
    clusters: dict[
        tuple[str, str | None, tuple[tuple[str, str | None], ...]],
        dict[str, object],
    ] = {}

    for observation in observations:
        if not isinstance(observation, dict):
            continue
        operand_signature = str(observation.get("operand_signature", "") or "")
        post_opcode_byte_hex = observation.get("post_opcode_byte_hex")
        width_landing_pattern: tuple[tuple[str, str | None], ...] = tuple(
            (
                width,
                (
                    landing.get("next_raw_opcode_hex")
                    if isinstance(landing, dict)
                    else None
                ),
            )
            for width, landing in sorted(
                (
                    (str(width), landing)
                    for width, landing in observation.get("width_landings", {}).items()
                    if isinstance(landing, dict)
                ),
                key=lambda item: int(item[0]),
            )
        )
        cluster_key = (operand_signature, post_opcode_byte_hex, width_landing_pattern)
        cluster = clusters.setdefault(
            cluster_key,
            {
                "operand_signature": operand_signature or None,
                "post_opcode_byte_hex": post_opcode_byte_hex,
                "width_landing_pattern": {
                    width: raw_opcode_hex
                    for width, raw_opcode_hex in width_landing_pattern
                },
                "count": 0,
                "key_sample": [],
                "tail_hint_raw_opcode_counts": {},
                "previous_raw_opcode_counts": {},
                "remaining_bytes_after_opcode_min": None,
                "remaining_bytes_after_opcode_max": None,
                "frontier_sample": [],
                "immediate_probe_sample": [],
            },
        )
        cluster["count"] = int(cluster.get("count", 0)) + 1
        _append_int_sample(cluster["key_sample"], int(observation.get("archive_key", 0)))

        tail_hint_raw_opcode_hex = observation.get("tail_hint_raw_opcode_hex")
        if isinstance(tail_hint_raw_opcode_hex, str) and tail_hint_raw_opcode_hex:
            tail_hint_counts = cluster["tail_hint_raw_opcode_counts"]
            tail_hint_counts[tail_hint_raw_opcode_hex] = int(tail_hint_counts.get(tail_hint_raw_opcode_hex, 0)) + 1

        previous_raw_opcode_hex = observation.get("previous_raw_opcode_hex")
        if isinstance(previous_raw_opcode_hex, str) and previous_raw_opcode_hex:
            previous_counts = cluster["previous_raw_opcode_counts"]
            previous_counts[previous_raw_opcode_hex] = int(previous_counts.get(previous_raw_opcode_hex, 0)) + 1

        remaining_bytes_after_opcode = observation.get("remaining_bytes_after_opcode")
        if isinstance(remaining_bytes_after_opcode, int):
            current_min = cluster.get("remaining_bytes_after_opcode_min")
            current_max = cluster.get("remaining_bytes_after_opcode_max")
            cluster["remaining_bytes_after_opcode_min"] = (
                remaining_bytes_after_opcode
                if not isinstance(current_min, int)
                else min(current_min, remaining_bytes_after_opcode)
            )
            cluster["remaining_bytes_after_opcode_max"] = (
                remaining_bytes_after_opcode
                if not isinstance(current_max, int)
                else max(current_max, remaining_bytes_after_opcode)
            )

        if len(cluster["frontier_sample"]) < 8:
            cluster["frontier_sample"].append(
                {
                    field: observation[field]
                    for field in (
                        "archive_key",
                        "file_id",
                        "offset",
                        "previous_raw_opcode_hex",
                        "tail_hint_raw_opcode_hex",
                        "remaining_bytes_after_opcode",
                    )
                    if field in observation
                }
            )
        if len(cluster["immediate_probe_sample"]) < 4 and "immediate_probes" in observation:
            cluster["immediate_probe_sample"].append(copy.deepcopy(observation["immediate_probes"]))

    cluster_entries = list(clusters.values())
    cluster_entries.sort(
        key=lambda entry: (
            -int(entry.get("count", 0)),
            str(entry.get("operand_signature") or ""),
            str(entry.get("post_opcode_byte_hex") or ""),
        )
    )
    for entry in cluster_entries:
        for field in ("tail_hint_raw_opcode_counts", "previous_raw_opcode_counts"):
            counts = entry.get(field)
            if isinstance(counts, dict):
                entry[field] = dict(
                    sorted(counts.items(), key=lambda item: (-int(item[1]), str(item[0])))
                )
    return cluster_entries


def _extract_clientscript_branch_probe_path_landing_opcode_hex(
    path: dict[str, object] | None,
) -> str | None:
    if not isinstance(path, dict):
        return None
    next_instruction = path.get("next_instruction")
    if not isinstance(next_instruction, dict):
        return None
    raw_opcode_hex = next_instruction.get("raw_opcode_hex")
    if isinstance(raw_opcode_hex, str) and raw_opcode_hex:
        return raw_opcode_hex
    return None


def _classify_clientscript_branch_probe_quality(
    observation: dict[str, object],
) -> tuple[str, list[str]]:
    branch_required_input_delta = observation.get("branch_required_input_delta")
    if not isinstance(branch_required_input_delta, dict):
        branch_required_input_delta = {}

    path_comparison = observation.get("path_comparison")
    if not isinstance(path_comparison, dict):
        path_comparison = {}

    fallthrough_status = str(observation.get("fallthrough_status", "") or "")
    taken_status = str(observation.get("taken_status", "") or "")
    statuses = {fallthrough_status, taken_status}

    reasons: list[str] = []
    if branch_required_input_delta:
        reasons.append("branch-phantom-input")
    if bool(path_comparison.get("phantom_input_mismatch")):
        reasons.append("path-phantom-input")
    if statuses & {"instruction-budget", "instruction-budget-hard"}:
        reasons.append("instruction-budget-cap")
    if statuses & {"invalid-immediate", "missing"}:
        reasons.append("decode-fragile")

    if "branch-phantom-input" in reasons or "path-phantom-input" in reasons:
        return "phantom-input", reasons
    if "instruction-budget-cap" in reasons:
        return "instruction-budget", reasons
    if "decode-fragile" in reasons:
        return "decode-fragile", reasons
    return "structural", reasons


def _summarize_clientscript_branch_probe_clusters(
    observations: list[dict[str, object]],
    *,
    include_quality_bucket: bool = False,
) -> list[dict[str, object]]:
    clusters: dict[tuple[object, ...], dict[str, object]] = {}

    for observation in observations:
        if not isinstance(observation, dict):
            continue

        branch_required_input_delta = observation.get("branch_required_input_delta")
        if not isinstance(branch_required_input_delta, dict):
            branch_required_input_delta = {}

        divergence_flags = observation.get("divergence_flags")
        if not isinstance(divergence_flags, list):
            divergence_flags = []

        cluster_key_parts: list[object] = []
        if include_quality_bucket:
            cluster_key_parts.extend(
                [
                    str(observation.get("quality_bucket", "") or ""),
                    tuple(str(reason) for reason in observation.get("noise_reasons", []) or []),
                ]
            )
        cluster_key_parts.extend(
            [
                str(observation.get("branch_state_before_operand_signature", "") or ""),
                str(observation.get("branch_state_after_operand_signature", "") or ""),
                str(observation.get("fallthrough_status", "") or ""),
                str(observation.get("fallthrough_operand_signature", "") or ""),
                str(observation.get("taken_status", "") or ""),
                str(observation.get("taken_operand_signature", "") or ""),
                tuple(str(flag) for flag in divergence_flags),
                tuple(
                    (str(stack_name), int(count))
                    for stack_name, count in sorted(branch_required_input_delta.items())
                ),
            ]
        )
        cluster_key = tuple(cluster_key_parts)
        cluster = clusters.setdefault(
            cluster_key,
            {
                "quality_bucket": str(observation.get("quality_bucket", "") or ""),
                "noise_reasons": list(observation.get("noise_reasons", []) or []),
                "branch_state_before_operand_signature": observation.get(
                    "branch_state_before_operand_signature"
                ),
                "branch_state_after_operand_signature": observation.get(
                    "branch_state_after_operand_signature"
                ),
                "fallthrough_status": observation.get("fallthrough_status"),
                "fallthrough_operand_signature": observation.get("fallthrough_operand_signature"),
                "taken_status": observation.get("taken_status"),
                "taken_operand_signature": observation.get("taken_operand_signature"),
                "divergence_flags": list(divergence_flags),
                "branch_required_input_delta": copy.deepcopy(branch_required_input_delta),
                "observation_count": 0,
                "key_sample": [],
                "immediate_kind_counts": Counter(),
                "immediate_value_counts": Counter(),
                "fallthrough_landing_opcode_counts": Counter(),
                "taken_landing_opcode_counts": Counter(),
                "pseudocode_status_counts": Counter(),
                "noise_reason_counts": Counter(),
                "observation_sample": [],
            },
        )
        cluster["observation_count"] = int(cluster.get("observation_count", 0)) + 1
        _append_int_sample(cluster["key_sample"], int(observation.get("archive_key", 0)))

        immediate_kind = observation.get("immediate_kind")
        if isinstance(immediate_kind, str) and immediate_kind:
            cluster["immediate_kind_counts"][immediate_kind] += 1

        immediate_value = observation.get("immediate_value")
        if isinstance(immediate_value, int):
            cluster["immediate_value_counts"][immediate_value] += 1

        fallthrough_landing_opcode_hex = observation.get("fallthrough_landing_opcode_hex")
        if isinstance(fallthrough_landing_opcode_hex, str) and fallthrough_landing_opcode_hex:
            cluster["fallthrough_landing_opcode_counts"][fallthrough_landing_opcode_hex] += 1

        taken_landing_opcode_hex = observation.get("taken_landing_opcode_hex")
        if isinstance(taken_landing_opcode_hex, str) and taken_landing_opcode_hex:
            cluster["taken_landing_opcode_counts"][taken_landing_opcode_hex] += 1

        pseudocode_status = observation.get("pseudocode_status")
        if isinstance(pseudocode_status, str) and pseudocode_status:
            cluster["pseudocode_status_counts"][pseudocode_status] += 1

        for reason in observation.get("noise_reasons", []) or []:
            cluster["noise_reason_counts"][str(reason)] += 1

        if len(cluster["observation_sample"]) < 8:
            cluster["observation_sample"].append(
                {
                    field: observation[field]
                    for field in (
                        "archive_key",
                        "file_id",
                        "branch_offset",
                        "immediate_value",
                        "fallthrough_landing_opcode_hex",
                        "taken_landing_opcode_hex",
                        "quality_bucket",
                    )
                    if field in observation
                }
            )

    cluster_entries = list(clusters.values())
    cluster_entries.sort(
        key=lambda entry: (
            -int(entry.get("observation_count", 0)),
            str(entry.get("quality_bucket", "") or ""),
            str(entry.get("branch_state_before_operand_signature", "") or ""),
            str(entry.get("fallthrough_status", "") or ""),
        )
    )
    for entry in cluster_entries:
        immediate_kind_counts = entry.get("immediate_kind_counts")
        if isinstance(immediate_kind_counts, Counter):
            entry["immediate_kind_counts"] = dict(
                sorted(immediate_kind_counts.items(), key=lambda item: (-int(item[1]), str(item[0])))
            )
        immediate_value_counts = entry.get("immediate_value_counts")
        if isinstance(immediate_value_counts, Counter):
            entry["immediate_value_counts"] = {
                str(value): count
                for value, count in sorted(
                    immediate_value_counts.items(),
                    key=lambda item: (-int(item[1]), int(item[0])),
                )
            }
        for field in (
            "fallthrough_landing_opcode_counts",
            "taken_landing_opcode_counts",
            "pseudocode_status_counts",
            "noise_reason_counts",
        ):
            counts = entry.get(field)
            if isinstance(counts, Counter):
                entry[field] = dict(
                    sorted(counts.items(), key=lambda item: (-int(item[1]), str(item[0])))
                )
    return cluster_entries


def probe_js5_export_branch_clusters(
    source: str | Path,
    raw_opcode: int,
    *,
    table: str | None = None,
    key: int | None = None,
    file_id: int | None = None,
    max_hits: int = 32,
) -> dict[str, object]:
    manifest_path = _resolve_js5_export_manifest_path(source)
    if not manifest_path.exists():
        raise FileNotFoundError(f"JS5 export manifest not found: {manifest_path}")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    export_root = manifest_path.parent
    target_opcode = int(raw_opcode)
    target_opcode_hex = f"0x{target_opcode:04X}"
    if max_hits <= 0:
        max_hits = 1

    observations: list[dict[str, object]] = []
    matching_script_identities: set[tuple[str, int, int]] = set()
    quality_counter: Counter[str] = Counter()
    noise_reason_counter: Counter[str] = Counter()
    pseudocode_status_counter: Counter[str] = Counter()
    immediate_kind_counter: Counter[str] = Counter()
    immediate_value_counter: Counter[int] = Counter()

    tables = manifest.get("tables", {})
    if not isinstance(tables, dict):
        tables = {}

    for table_name, table_payload in tables.items():
        if table is not None and str(table_name) != str(table):
            continue
        if not isinstance(table_payload, dict):
            continue
        records = table_payload.get("records", [])
        if not isinstance(records, list):
            continue
        for record in records:
            if not isinstance(record, dict):
                continue
            try:
                archive_key = int(record.get("key", -1))
            except (TypeError, ValueError):
                continue
            if key is not None and archive_key != int(key):
                continue

            archive_files = record.get("archive_files", [])
            if not isinstance(archive_files, list):
                continue
            for archive_file in archive_files:
                if not isinstance(archive_file, dict):
                    continue
                try:
                    archive_file_id = int(archive_file.get("file_id", -1))
                except (TypeError, ValueError):
                    continue
                if file_id is not None and archive_file_id != int(file_id):
                    continue

                semantic_profile = archive_file.get("semantic_profile")
                if not isinstance(semantic_profile, dict):
                    continue
                branch_probe = semantic_profile.get("branch_state_probe")
                if not isinstance(branch_probe, dict):
                    continue

                branch_instruction = branch_probe.get("branch_instruction")
                if not isinstance(branch_instruction, dict):
                    continue
                branch_raw_opcode = branch_instruction.get("raw_opcode")
                branch_raw_opcode_hex = branch_instruction.get("raw_opcode_hex")
                if isinstance(branch_raw_opcode, int):
                    matches_opcode = branch_raw_opcode == target_opcode
                else:
                    matches_opcode = (
                        isinstance(branch_raw_opcode_hex, str)
                        and branch_raw_opcode_hex.upper() == target_opcode_hex
                    )
                if not matches_opcode:
                    continue

                before_compact = branch_probe.get("branch_state_before_compact")
                if not isinstance(before_compact, dict):
                    before_compact = {}
                after_compact = branch_probe.get("branch_state_after_compact")
                if not isinstance(after_compact, dict):
                    after_compact = {}
                fallthrough_path = branch_probe.get("fallthrough_path")
                if not isinstance(fallthrough_path, dict):
                    fallthrough_path = {}
                taken_path = branch_probe.get("taken_path")
                if not isinstance(taken_path, dict):
                    taken_path = {}
                fallthrough_compact = fallthrough_path.get("final_stack_compact")
                if not isinstance(fallthrough_compact, dict):
                    fallthrough_compact = {}
                taken_compact = taken_path.get("final_stack_compact")
                if not isinstance(taken_compact, dict):
                    taken_compact = {}
                path_comparison = branch_probe.get("path_comparison")
                if not isinstance(path_comparison, dict):
                    path_comparison = {}
                branch_required_input_delta = branch_probe.get("branch_required_input_delta")
                if not isinstance(branch_required_input_delta, dict):
                    branch_required_input_delta = {}

                observation = {
                    "table": str(table_name),
                    "archive_key": archive_key,
                    "file_id": archive_file_id,
                    "script_name": semantic_profile.get("script_name"),
                    "parser_status": semantic_profile.get("parser_status"),
                    "pseudocode_status": semantic_profile.get("pseudocode_status"),
                    "branch_offset": branch_instruction.get("offset"),
                    "immediate_kind": branch_instruction.get("immediate_kind"),
                    "immediate_value": branch_instruction.get("immediate_value"),
                    "branch_control_flow_kind": branch_probe.get("branch_control_flow_kind"),
                    "branch_state_before_operand_signature": before_compact.get("operand_signature"),
                    "branch_state_after_operand_signature": after_compact.get("operand_signature"),
                    "branch_state_before_compact": copy.deepcopy(before_compact),
                    "branch_state_after_compact": copy.deepcopy(after_compact),
                    "branch_required_input_delta": copy.deepcopy(branch_required_input_delta),
                    "fallthrough_status": fallthrough_path.get("status"),
                    "fallthrough_operand_signature": fallthrough_compact.get("operand_signature"),
                    "fallthrough_landing_opcode_hex": _extract_clientscript_branch_probe_path_landing_opcode_hex(
                        fallthrough_path
                    ),
                    "taken_status": taken_path.get("status") if taken_path else "missing",
                    "taken_operand_signature": taken_compact.get("operand_signature"),
                    "taken_landing_opcode_hex": _extract_clientscript_branch_probe_path_landing_opcode_hex(
                        taken_path
                    ),
                    "path_comparison": copy.deepcopy(path_comparison),
                    "divergence_flags": list(path_comparison.get("divergence_flags", []))
                    if isinstance(path_comparison.get("divergence_flags"), list)
                    else [],
                }
                quality_bucket, noise_reasons = _classify_clientscript_branch_probe_quality(observation)
                observation["quality_bucket"] = quality_bucket
                observation["noise_reasons"] = noise_reasons
                observations.append(observation)

                matching_script_identities.add((str(table_name), archive_key, archive_file_id))
                quality_counter[quality_bucket] += 1
                for reason in noise_reasons:
                    noise_reason_counter[reason] += 1
                pseudocode_status = semantic_profile.get("pseudocode_status")
                if isinstance(pseudocode_status, str) and pseudocode_status:
                    pseudocode_status_counter[pseudocode_status] += 1
                immediate_kind = branch_instruction.get("immediate_kind")
                if isinstance(immediate_kind, str) and immediate_kind:
                    immediate_kind_counter[immediate_kind] += 1
                immediate_value = branch_instruction.get("immediate_value")
                if isinstance(immediate_value, int):
                    immediate_value_counter[immediate_value] += 1

    quality_rank = {
        "structural": 0,
        "instruction-budget": 1,
        "phantom-input": 2,
        "decode-fragile": 3,
    }
    ordered_observations = sorted(
        observations,
        key=lambda observation: (
            int(quality_rank.get(str(observation.get("quality_bucket")), 9)),
            len(observation.get("noise_reasons", []) or []),
            -int(observation.get("archive_key", 0)),
            -int(observation.get("branch_offset", 0) or 0),
        ),
    )

    structural_observations = [
        observation
        for observation in ordered_observations
        if str(observation.get("quality_bucket")) == "structural"
    ]
    noise_observations = [
        observation
        for observation in ordered_observations
        if str(observation.get("quality_bucket")) != "structural"
    ]
    structural_clusters = _summarize_clientscript_branch_probe_clusters(structural_observations)
    noise_clusters = _summarize_clientscript_branch_probe_clusters(
        noise_observations,
        include_quality_bucket=True,
    )

    return {
        "kind": "clientscript-branch-cluster-probe",
        "manifest_path": str(manifest_path),
        "export_root": str(export_root),
        "raw_opcode": target_opcode,
        "raw_opcode_hex": target_opcode_hex,
        "filters": {
            "table": str(table) if table is not None else None,
            "key": int(key) if key is not None else None,
            "file_id": int(file_id) if file_id is not None else None,
            "max_hits": int(max_hits),
        },
        "hit_count": len(observations),
        "script_count": len(matching_script_identities),
        "quality_counts": dict(sorted(quality_counter.items(), key=lambda item: (-item[1], item[0]))),
        "noise_reason_counts": dict(
            sorted(noise_reason_counter.items(), key=lambda item: (-item[1], item[0]))
        ),
        "pseudocode_status_counts": dict(
            sorted(pseudocode_status_counter.items(), key=lambda item: (-item[1], item[0]))
        ),
        "immediate_kind_counts": dict(
            sorted(immediate_kind_counter.items(), key=lambda item: (-item[1], item[0]))
        ),
        "immediate_value_counts": {
            str(value): count
            for value, count in sorted(
                immediate_value_counter.items(),
                key=lambda item: (-int(item[1]), int(item[0])),
            )
        },
        "structural_observation_count": len(structural_observations),
        "noise_observation_count": len(noise_observations),
        "structural_cluster_count": len(structural_clusters),
        "structural_clusters": structural_clusters,
        "noise_cluster_count": len(noise_clusters),
        "noise_clusters": noise_clusters,
        "sample_observations": ordered_observations[: max_hits],
    }


def probe_js5_export_opcode(
    source: str | Path,
    raw_opcode: int,
    *,
    table: str | None = None,
    key: int | None = None,
    file_id: int | None = None,
    max_hits: int = 32,
) -> dict[str, object]:
    manifest_path = _resolve_js5_export_manifest_path(source)
    if not manifest_path.exists():
        raise FileNotFoundError(f"JS5 export manifest not found: {manifest_path}")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    export_root = manifest_path.parent
    target_opcode = int(raw_opcode)
    target_opcode_hex = f"0x{target_opcode:04X}"
    if max_hits <= 0:
        max_hits = 1

    raw_opcode_catalog, raw_opcode_types = _load_clientscript_opcode_catalog_from_export_root(export_root)
    hits_by_identity: dict[tuple[str, int, int, int], dict[str, object]] = {}
    matching_script_identities: set[tuple[str, int, int]] = set()
    pseudocode_status_counter: Counter[str] = Counter()
    blocking_kind_counter: Counter[str] = Counter()
    frontier_reason_counter: Counter[str] = Counter()
    blocked_frontier_observations: list[dict[str, object]] = []
    blocked_frontier_contexts: dict[tuple[int, int, int], dict[str, object]] = {}

    sample_fields = (
        "instruction_sample",
        "frontier_instruction_sample",
        "late_instruction_sample",
        "tail_instruction_sample",
    )

    tables = manifest.get("tables", {})
    if not isinstance(tables, dict):
        tables = {}

    for table_name, table_payload in tables.items():
        if table is not None and str(table_name) != str(table):
            continue
        if not isinstance(table_payload, dict):
            continue
        records = table_payload.get("records", [])
        if not isinstance(records, list):
            continue
        for record in records:
            if not isinstance(record, dict):
                continue
            try:
                archive_key = int(record.get("key", -1))
            except (TypeError, ValueError):
                continue
            if key is not None and archive_key != int(key):
                continue

            archive_files = record.get("archive_files", [])
            if not isinstance(archive_files, list):
                continue
            for archive_file in archive_files:
                if not isinstance(archive_file, dict):
                    continue
                try:
                    archive_file_id = int(archive_file.get("file_id", -1))
                except (TypeError, ValueError):
                    continue
                if file_id is not None and archive_file_id != int(file_id):
                    continue

                semantic_profile = archive_file.get("semantic_profile")
                if not isinstance(semantic_profile, dict):
                    continue

                script_hit = False
                blocker = semantic_profile.get("pseudocode_blocker")
                if isinstance(blocker, dict):
                    blocker_raw_opcode = blocker.get("frontier_raw_opcode")
                    blocker_raw_opcode_hex = blocker.get("frontier_raw_opcode_hex")
                    if isinstance(blocker_raw_opcode, int):
                        blocker_matches_opcode = blocker_raw_opcode == target_opcode
                    else:
                        blocker_matches_opcode = (
                            isinstance(blocker_raw_opcode_hex, str)
                            and blocker_raw_opcode_hex.upper() == target_opcode_hex
                        )
                    if blocker_matches_opcode:
                        frontier_offset = blocker.get("frontier_offset")
                        if not isinstance(frontier_offset, int):
                            frontier_offset = -1
                        hit_identity = (
                            str(table_name),
                            archive_key,
                            archive_file_id,
                            int(frontier_offset),
                        )
                        hit = hits_by_identity.setdefault(
                            hit_identity,
                            {
                                "table": str(table_name),
                                "archive_key": archive_key,
                                "file_id": archive_file_id,
                                "offset": int(frontier_offset),
                                "script_name": semantic_profile.get("script_name"),
                                "parser_status": semantic_profile.get("parser_status"),
                                "pseudocode_status": semantic_profile.get("pseudocode_status"),
                                "tail_trace_status": semantic_profile.get("tail_trace_status"),
                                "disassembly_text_path": semantic_profile.get("disassembly_text_path"),
                                "pseudocode_text_path": semantic_profile.get("pseudocode_text_path"),
                            },
                        )
                        hit["pseudocode_blocker"] = {
                            field: blocker[field]
                            for field in (
                                "blocking_kind",
                                "frontier_reason",
                                "frontier_raw_opcode_hex",
                                "tail_next_raw_opcode_hex",
                                "tail_hint_raw_opcode_hex",
                            )
                            if field in blocker
                        }
                        frontier_step = _build_clientscript_opcode_probe_frontier_step(
                            semantic_profile,
                            blocker,
                        )
                        previous_step = None
                        tail_instruction_sample = semantic_profile.get("tail_instruction_sample")
                        if isinstance(tail_instruction_sample, list) and tail_instruction_sample:
                            annotated_tail_steps, replay_state = _annotate_clientscript_opcode_probe_steps(
                                tail_instruction_sample
                            )
                            candidate_previous = annotated_tail_steps[-1]
                            if isinstance(candidate_previous, dict):
                                previous_step = candidate_previous
                            if isinstance(frontier_step, dict):
                                frontier_step = _apply_clientscript_step_to_stack_state(
                                    copy.deepcopy(frontier_step),
                                    replay_state,
                                )
                        _merge_clientscript_opcode_probe_hit(
                            hit,
                            step=frontier_step or {"raw_opcode": target_opcode, "raw_opcode_hex": target_opcode_hex},
                            sample_source="pseudocode_blocker",
                            previous_step=previous_step,
                            next_step=None,
                        )
                        data_path = archive_file.get("path")
                        if not (isinstance(data_path, str) and data_path):
                            data_path = semantic_profile.get("path")
                        if isinstance(data_path, str) and data_path:
                            frontier_analysis = _build_clientscript_opcode_probe_frontier_analysis(
                                data_path=Path(data_path),
                                frontier_offset=int(frontier_offset),
                                raw_opcode_types=raw_opcode_types or None,
                                raw_opcode_catalog=raw_opcode_catalog or None,
                            )
                            if isinstance(frontier_analysis, dict):
                                observation = {
                                    "archive_key": archive_key,
                                    "file_id": archive_file_id,
                                    "offset": int(frontier_offset),
                                    "operand_signature": (
                                        frontier_step.get("operand_signature_candidate", {}).get("signature")
                                        if isinstance(frontier_step, dict)
                                        else None
                                    ),
                                    "tail_hint_raw_opcode_hex": blocker.get("tail_hint_raw_opcode_hex"),
                                    "previous_raw_opcode_hex": (
                                        previous_step.get("raw_opcode_hex")
                                        if isinstance(previous_step, dict)
                                        else None
                                    ),
                                    **frontier_analysis,
                                }
                                blocked_frontier_observations.append(observation)
                                blocked_frontier_contexts[(archive_key, archive_file_id, int(frontier_offset))] = {
                                    "data_path": Path(data_path),
                                    "tail_stack_summary": copy.deepcopy(
                                        semantic_profile.get("tail_stack_summary", {})
                                    ),
                                    "tail_instruction_sample": copy.deepcopy(
                                        semantic_profile.get("tail_instruction_sample", [])
                                    ),
                                }
                        script_hit = True

                for sample_source in sample_fields:
                    steps = semantic_profile.get(sample_source)
                    if not isinstance(steps, list):
                        continue
                    annotated_steps, _replay_state = _annotate_clientscript_opcode_probe_steps(steps)

                    for index, step in enumerate(annotated_steps):
                        if not isinstance(step, dict):
                            continue
                        step_raw_opcode = step.get("raw_opcode")
                        step_raw_opcode_hex = step.get("raw_opcode_hex")
                        if isinstance(step_raw_opcode, int):
                            matches_opcode = step_raw_opcode == target_opcode
                        else:
                            matches_opcode = (
                                isinstance(step_raw_opcode_hex, str)
                                and step_raw_opcode_hex.upper() == target_opcode_hex
                            )
                        if not matches_opcode:
                            continue

                        offset = step.get("offset")
                        if not isinstance(offset, int):
                            offset = -1
                        hit_identity = (str(table_name), archive_key, archive_file_id, int(offset))
                        hit = hits_by_identity.setdefault(
                            hit_identity,
                            {
                                "table": str(table_name),
                                "archive_key": archive_key,
                                "file_id": archive_file_id,
                                "offset": int(offset),
                                "script_name": semantic_profile.get("script_name"),
                                "parser_status": semantic_profile.get("parser_status"),
                                "pseudocode_status": semantic_profile.get("pseudocode_status"),
                                "tail_trace_status": semantic_profile.get("tail_trace_status"),
                                "disassembly_text_path": semantic_profile.get("disassembly_text_path"),
                                "pseudocode_text_path": semantic_profile.get("pseudocode_text_path"),
                            },
                        )
                        if "pseudocode_blocker" not in hit:
                            blocker = semantic_profile.get("pseudocode_blocker")
                            if isinstance(blocker, dict) and blocker:
                                hit["pseudocode_blocker"] = {
                                    field: blocker[field]
                                    for field in (
                                        "blocking_kind",
                                        "frontier_reason",
                                        "frontier_raw_opcode_hex",
                                        "tail_next_raw_opcode_hex",
                                        "tail_hint_raw_opcode_hex",
                                    )
                                    if field in blocker
                                }

                        previous_step = (
                            annotated_steps[index - 1]
                            if index > 0 and isinstance(annotated_steps[index - 1], dict)
                            else None
                        )
                        next_step = (
                            annotated_steps[index + 1]
                            if index + 1 < len(annotated_steps) and isinstance(annotated_steps[index + 1], dict)
                            else None
                        )
                        _merge_clientscript_opcode_probe_hit(
                            hit,
                            step=step,
                            sample_source=sample_source,
                            previous_step=previous_step,
                            next_step=next_step,
                        )
                        script_hit = True

                if script_hit:
                    script_identity = (str(table_name), archive_key, archive_file_id)
                    if script_identity not in matching_script_identities:
                        matching_script_identities.add(script_identity)
                        pseudocode_status = str(semantic_profile.get("pseudocode_status", "") or "unknown")
                        pseudocode_status_counter[pseudocode_status] += 1
                        blocker = semantic_profile.get("pseudocode_blocker")
                        if isinstance(blocker, dict):
                            blocking_kind = str(blocker.get("blocking_kind", "") or "")
                            frontier_reason = str(blocker.get("frontier_reason", "") or "")
                            if blocking_kind:
                                blocking_kind_counter[blocking_kind] += 1
                            if frontier_reason:
                                frontier_reason_counter[frontier_reason] += 1

    immediate_kind_counter: Counter[str] = Counter()
    semantic_label_counter: Counter[str] = Counter()
    semantic_family_counter: Counter[str] = Counter()
    operand_signature_counter: Counter[str] = Counter()
    behavior_counter: Counter[str] = Counter()
    contextual_hint_applied_count = 0
    contextual_hint_match_prefix_counter: Counter[str] = Counter()
    hint_applied_survivor_delta_counter: Counter[str] = Counter()

    def _score_hit(hit: dict[str, object]) -> tuple[int, int]:
        step = hit.get("step")
        score = 0
        if isinstance(step, dict):
            if isinstance(step.get("semantic_label"), str) and step.get("semantic_label"):
                score += 4
            if isinstance(step.get("operand_signature_candidate"), dict):
                score += 4
            if isinstance(step.get("consumed_int_expressions"), list):
                score += 2
            if isinstance(step.get("consumed_string_expressions"), list):
                score += 2
            if isinstance(step.get("produced_int_expressions"), list):
                score += 1
            if isinstance(step.get("produced_string_expressions"), list):
                score += 1
        sample_sources = hit.get("sample_sources")
        if isinstance(sample_sources, list):
            score += len(sample_sources)
        return score, -int(hit.get("offset", 0))

    ordered_hits = sorted(
        hits_by_identity.values(),
        key=lambda hit: (_score_hit(hit), -int(hit.get("archive_key", 0))),
        reverse=True,
    )

    for hit in ordered_hits:
        step = hit.get("step")
        if not isinstance(step, dict):
            continue
        immediate_kind = step.get("immediate_kind")
        if isinstance(immediate_kind, str) and immediate_kind:
            immediate_kind_counter[immediate_kind] += 1
        semantic_label = step.get("semantic_label")
        if isinstance(semantic_label, str) and semantic_label:
            semantic_label_counter[semantic_label] += 1
        semantic_family = step.get("semantic_family")
        if isinstance(semantic_family, str) and semantic_family:
            semantic_family_counter[semantic_family] += 1
        operand_signature = step.get("operand_signature_candidate")
        if isinstance(operand_signature, dict):
            signature = operand_signature.get("signature")
            if isinstance(signature, str) and signature:
                operand_signature_counter[signature] += 1
        if step.get("contextual_stack_hint_applied") is True:
            contextual_hint_applied_count += 1
            matched_prefix_signature = step.get("contextual_stack_hint_match_prefix_operand_signature")
            if isinstance(matched_prefix_signature, str) and matched_prefix_signature:
                contextual_hint_match_prefix_counter[matched_prefix_signature] += 1
            hint_applied_survivor_delta = step.get("hint_applied_survivor_delta")
            if isinstance(hint_applied_survivor_delta, dict) and hint_applied_survivor_delta:
                delta_key = "|".join(
                    f"{name}:{int(delta)}"
                    for name, delta in sorted(hint_applied_survivor_delta.items())
                    if isinstance(name, str) and isinstance(delta, int)
                )
                if delta_key:
                    hint_applied_survivor_delta_counter[delta_key] += 1
        behavior_counter[_infer_clientscript_opcode_probe_behavior(step)] += 1

    artifact_entries = _load_clientscript_opcode_artifact_entries(export_root, raw_opcode=target_opcode)
    blocked_frontier_clusters = _summarize_clientscript_opcode_probe_frontier_clusters(
        blocked_frontier_observations
    )
    blocked_frontier_framing_summaries = _summarize_clientscript_opcode_probe_framing_hypotheses(
        blocked_frontier_observations,
        contexts=blocked_frontier_contexts,
        target_opcode=target_opcode,
        target_opcode_hex=target_opcode_hex,
        raw_opcode_types=raw_opcode_types or None,
        raw_opcode_catalog=raw_opcode_catalog or None,
    )
    blocked_frontier_subtype_candidates, blocked_frontier_terminal_clusters = (
        _summarize_clientscript_opcode_probe_subtype_candidates(
            blocked_frontier_observations,
            clusters=blocked_frontier_clusters,
            target_opcode_hex=target_opcode_hex,
        )
    )
    for candidate in blocked_frontier_subtype_candidates:
        if not isinstance(candidate, dict):
            continue
        sub_opcode_hex = candidate.get("sub_opcode_hex")
        if isinstance(sub_opcode_hex, str) and sub_opcode_hex:
            framing_summary = blocked_frontier_framing_summaries.get(sub_opcode_hex)
            if isinstance(framing_summary, dict) and framing_summary:
                candidate["bounded_hypothesis_summary"] = framing_summary
                _reconcile_clientscript_opcode_probe_subtype_candidate_with_framing_summary(
                    candidate,
                    framing_summary,
                )

    return {
        "kind": "clientscript-opcode-probe",
        "manifest_path": str(manifest_path),
        "export_root": str(export_root),
        "raw_opcode": target_opcode,
        "raw_opcode_hex": target_opcode_hex,
        "filters": {
            "table": str(table) if table is not None else None,
            "key": int(key) if key is not None else None,
            "file_id": int(file_id) if file_id is not None else None,
            "max_hits": int(max_hits),
        },
        "hit_count": len(ordered_hits),
        "script_count": len(matching_script_identities),
        "archive_key_count": len({int(hit["archive_key"]) for hit in ordered_hits}),
        "immediate_kind_counts": dict(sorted(immediate_kind_counter.items())),
        "semantic_label_counts": dict(
            sorted(semantic_label_counter.items(), key=lambda item: (-item[1], item[0]))
        ),
        "semantic_family_counts": dict(
            sorted(semantic_family_counter.items(), key=lambda item: (-item[1], item[0]))
        ),
        "operand_signature_counts": dict(
            sorted(operand_signature_counter.items(), key=lambda item: (-item[1], item[0]))
        ),
        "contextual_hint_applied_count": contextual_hint_applied_count,
        "contextual_hint_match_prefix_operand_signature_counts": dict(
            sorted(contextual_hint_match_prefix_counter.items(), key=lambda item: (-item[1], item[0]))
        ),
        "hint_applied_survivor_delta_counts": dict(
            sorted(hint_applied_survivor_delta_counter.items(), key=lambda item: (-item[1], item[0]))
        ),
        "behavior_counts": dict(
            sorted(behavior_counter.items(), key=lambda item: (-item[1], item[0]))
        ),
        "pseudocode_status_counts": dict(
            sorted(pseudocode_status_counter.items(), key=lambda item: (-item[1], item[0]))
        ),
        "blocking_kind_counts": dict(
            sorted(blocking_kind_counter.items(), key=lambda item: (-item[1], item[0]))
        ),
        "frontier_reason_counts": dict(
            sorted(frontier_reason_counter.items(), key=lambda item: (-item[1], item[0]))
        ),
        "blocked_frontier_observation_count": len(blocked_frontier_observations),
        "blocked_frontier_observation_sample": blocked_frontier_observations[: min(max_hits, 16)],
        "blocked_frontier_clusters": blocked_frontier_clusters,
        "blocked_frontier_subtype_candidate_count": len(blocked_frontier_subtype_candidates),
        "blocked_frontier_subtype_candidates": blocked_frontier_subtype_candidates,
        "blocked_frontier_bounded_hypothesis_count": len(blocked_frontier_framing_summaries),
        "blocked_frontier_bounded_hypotheses": dict(
            sorted(blocked_frontier_framing_summaries.items(), key=lambda item: item[0])
        ),
        "blocked_frontier_terminal_cluster_count": len(blocked_frontier_terminal_clusters),
        "blocked_frontier_terminal_clusters": blocked_frontier_terminal_clusters,
        "artifact_entries": artifact_entries,
        "sample_hits": ordered_hits[: max_hits],
    }


def probe_js5_export_interior_opcode(
    source: str | Path,
    raw_opcode: int,
    *,
    table: str | None = None,
    keys: Sequence[int] | None = None,
    file_id: int | None = None,
    max_hits: int = 32,
    ready_only: bool = False,
) -> dict[str, object]:
    manifest_path = _resolve_js5_export_manifest_path(source)
    if not manifest_path.exists():
        raise FileNotFoundError(f"JS5 export manifest not found: {manifest_path}")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8-sig"))
    export_root = manifest_path.parent
    target_opcode = int(raw_opcode)
    target_opcode_hex = f"0x{target_opcode:04X}"
    if max_hits <= 0:
        max_hits = 1

    requested_keys = {int(value) for value in (keys or [])}
    raw_opcode_catalog, raw_opcode_types = _load_clientscript_opcode_catalog_from_export_root(export_root)

    hits: list[dict[str, object]] = []
    pre_signature_counter: Counter[str] = Counter()
    post_signature_counter: Counter[str] = Counter()
    required_input_delta_counter: Counter[str] = Counter()
    survivor_delta_counter: Counter[str] = Counter()

    tables = manifest.get("tables", {})
    if not isinstance(tables, dict):
        tables = {}

    for table_name, table_payload in tables.items():
        if table is not None and str(table_name) != str(table):
            continue
        if not isinstance(table_payload, dict):
            continue
        records = table_payload.get("records", [])
        if not isinstance(records, list):
            continue
        for record in records:
            if not isinstance(record, dict):
                continue
            try:
                archive_key = int(record.get("key", -1))
            except (TypeError, ValueError):
                continue
            if requested_keys and archive_key not in requested_keys:
                continue

            archive_files = record.get("archive_files", [])
            if not isinstance(archive_files, list):
                continue
            for archive_file in archive_files:
                if not isinstance(archive_file, dict):
                    continue
                try:
                    archive_file_id = int(archive_file.get("file_id", -1))
                except (TypeError, ValueError):
                    continue
                if file_id is not None and archive_file_id != int(file_id):
                    continue

                semantic_profile = archive_file.get("semantic_profile")
                if not isinstance(semantic_profile, dict):
                    continue
                if ready_only and str(semantic_profile.get("pseudocode_status", "")) != "ready":
                    continue

                data_path = archive_file.get("path")
                if not (isinstance(data_path, str) and data_path):
                    data_path = semantic_profile.get("path")
                if not (isinstance(data_path, str) and data_path):
                    continue

                try:
                    data = Path(data_path).read_bytes()
                except OSError:
                    continue

                decoded = _decode_clientscript_ready_annotated_steps(
                    data,
                    raw_opcode_types=raw_opcode_types or None,
                    raw_opcode_catalog=raw_opcode_catalog or None,
                )
                if not isinstance(decoded, dict):
                    continue
                annotated_steps = decoded.get("annotated_steps")
                if not isinstance(annotated_steps, list) or not annotated_steps:
                    continue

                snapshots, _final_state = _replay_clientscript_stack_state_with_snapshots(annotated_steps)
                for index, snapshot in enumerate(snapshots):
                    if not isinstance(snapshot, dict):
                        continue
                    step = snapshot.get("step")
                    if not isinstance(step, dict):
                        continue

                    step_raw_opcode = step.get("raw_opcode")
                    step_raw_opcode_hex = step.get("raw_opcode_hex")
                    if isinstance(step_raw_opcode, int):
                        matches_opcode = step_raw_opcode == target_opcode
                    else:
                        matches_opcode = (
                            isinstance(step_raw_opcode_hex, str)
                            and step_raw_opcode_hex.upper() == target_opcode_hex
                        )
                    if not matches_opcode:
                        continue

                    pre_stack_compact = snapshot.get("pre_stack_compact")
                    if not isinstance(pre_stack_compact, dict):
                        pre_stack_compact = {}
                    post_stack_compact = snapshot.get("post_stack_compact")
                    if not isinstance(post_stack_compact, dict):
                        post_stack_compact = {}
                    required_input_delta = snapshot.get("required_input_delta")
                    if not isinstance(required_input_delta, dict):
                        required_input_delta = {}
                    survivor_delta = snapshot.get("survivor_delta")
                    if not isinstance(survivor_delta, dict):
                        survivor_delta = {}

                    pre_signature = str(pre_stack_compact.get("operand_signature", "") or "empty")
                    post_signature = str(post_stack_compact.get("operand_signature", "") or "empty")
                    pre_signature_counter[pre_signature] += 1
                    post_signature_counter[post_signature] += 1
                    required_input_delta_counter[
                        json.dumps(required_input_delta, sort_keys=True)
                        if required_input_delta
                        else "{}"
                    ] += 1
                    survivor_delta_counter[
                        json.dumps(survivor_delta, sort_keys=True)
                        if survivor_delta
                        else "{}"
                    ] += 1

                    previous_step = (
                        snapshots[index - 1].get("step")
                        if index > 0 and isinstance(snapshots[index - 1], dict)
                        else None
                    )
                    next_step = (
                        snapshots[index + 1].get("step")
                        if index + 1 < len(snapshots) and isinstance(snapshots[index + 1], dict)
                        else None
                    )

                    hits.append(
                        {
                            "table": str(table_name),
                            "archive_key": archive_key,
                            "file_id": archive_file_id,
                            "offset": int(step.get("offset", -1)),
                            "script_name": semantic_profile.get("script_name"),
                            "parser_status": semantic_profile.get("parser_status"),
                            "pseudocode_status": semantic_profile.get("pseudocode_status"),
                            "sample_source": "ready-disassembly-interior",
                            "step": _sample_clientscript_opcode_probe_step(step),
                            "previous_step": (
                                _sample_clientscript_opcode_probe_step(previous_step)
                                if isinstance(previous_step, dict)
                                else None
                            ),
                            "next_step": (
                                _sample_clientscript_opcode_probe_step(next_step)
                                if isinstance(next_step, dict)
                                else None
                            ),
                            "pre_stack_compact": pre_stack_compact,
                            "post_stack_compact": post_stack_compact,
                            "required_input_delta": required_input_delta,
                            "survivor_delta": survivor_delta,
                            "disassembly_text_path": semantic_profile.get("disassembly_text_path"),
                            "pseudocode_text_path": semantic_profile.get("pseudocode_text_path"),
                        }
                    )

    ordered_hits = sorted(
        hits,
        key=lambda entry: (
            str(entry.get("table", "")),
            int(entry.get("archive_key", -1)),
            int(entry.get("file_id", -1)),
            int(entry.get("offset", -1)),
        ),
    )
    return {
        "kind": "clientscript-opcode-interior-probe",
        "manifest_path": str(manifest_path),
        "export_root": str(export_root),
        "raw_opcode": target_opcode,
        "raw_opcode_hex": target_opcode_hex,
        "filters": {
            "table": str(table) if table is not None else None,
            "keys": sorted(requested_keys),
            "file_id": int(file_id) if file_id is not None else None,
            "max_hits": int(max_hits),
            "ready_only": bool(ready_only),
        },
        "hit_count": len(ordered_hits),
        "pre_operand_signature_counts": dict(
            sorted(pre_signature_counter.items(), key=lambda item: (-item[1], item[0]))
        ),
        "post_operand_signature_counts": dict(
            sorted(post_signature_counter.items(), key=lambda item: (-item[1], item[0]))
        ),
        "required_input_delta_counts": dict(
            sorted(required_input_delta_counter.items(), key=lambda item: (-item[1], item[0]))
        ),
        "survivor_delta_counts": dict(
            sorted(survivor_delta_counter.items(), key=lambda item: (-item[1], item[0]))
        ),
        "hits": ordered_hits[:max_hits],
    }


def probe_js5_export_opcode_subtypes(
    source: str | Path,
    raw_opcode: int,
    *,
    table: str | None = None,
    key: int | None = None,
    file_id: int | None = None,
    max_hits: int = 32,
) -> dict[str, object]:
    payload = probe_js5_export_opcode(
        source,
        raw_opcode,
        table=table,
        key=key,
        file_id=file_id,
        max_hits=max_hits,
    )
    return {
        "kind": "clientscript-opcode-subtype-probe",
        "manifest_path": payload.get("manifest_path"),
        "export_root": payload.get("export_root"),
        "raw_opcode": payload.get("raw_opcode"),
        "raw_opcode_hex": payload.get("raw_opcode_hex"),
        "filters": copy.deepcopy(payload.get("filters", {})),
        "scope": "blocked-frontier-only",
        "blocked_frontier_observation_count": payload.get("blocked_frontier_observation_count", 0),
        "blocked_frontier_subtype_candidate_count": payload.get(
            "blocked_frontier_subtype_candidate_count",
            0,
        ),
        "blocked_frontier_subtype_candidates": copy.deepcopy(
            payload.get("blocked_frontier_subtype_candidates", [])
        ),
        "blocked_frontier_bounded_hypothesis_count": payload.get(
            "blocked_frontier_bounded_hypothesis_count",
            0,
        ),
        "blocked_frontier_bounded_hypotheses": copy.deepcopy(
            payload.get("blocked_frontier_bounded_hypotheses", {})
        ),
        "blocked_frontier_terminal_cluster_count": payload.get(
            "blocked_frontier_terminal_cluster_count",
            0,
        ),
        "blocked_frontier_terminal_clusters": copy.deepcopy(
            payload.get("blocked_frontier_terminal_clusters", [])
        ),
    }
