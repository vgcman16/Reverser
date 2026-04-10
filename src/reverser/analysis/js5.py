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

    with sqlite3.connect(str(target)) as connection:
        cursor = connection.cursor()
        tables_present = [
            str(name)
            for name, in cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
            ).fetchall()
        ]
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

                records.append(
                    {
                        "key": int(key),
                        "version": int(version) if version is not None else None,
                        "crc": int(crc) if crc is not None else None,
                        **container.to_dict(),
                        "payload_path": str(payload_path) if payload_path else None,
                        "payload_sha256": payload_sha256,
                        "container_path": str(container_path) if container_path else None,
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
        },
        "warnings": warnings,
        "tables": table_payloads,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest
