from __future__ import annotations

import bz2
import gzip
import json
import re
import sqlite3
from functools import lru_cache
from pathlib import Path

from reverser.analysis.analyzers.base import Analyzer
from reverser.models import AnalysisReport


JCACHE_NAME_PATTERN = re.compile(r"^(?P<core>core-)?js5-(?P<archive_id>\d+)\.jcache$", re.IGNORECASE)
COMPRESSION_LABELS = {
    0: "none",
    1: "bzip2",
    2: "gzip",
}
MAX_RECORD_SAMPLES = 5
MAX_RECORD_DECOMPRESS_BYTES = 1_000_000


def _quote_identifier(name: str) -> str:
    return f'"{name.replace("\"", "\"\"")}"'


def _match_jcache_name(path: Path) -> re.Match[str] | None:
    return JCACHE_NAME_PATTERN.match(path.name)


@lru_cache(maxsize=128)
def _load_index_names(anchor: str) -> tuple[dict[int, str], str | None, int | None]:
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


def _parse_container_record(raw: bytes) -> dict[str, object]:
    if len(raw) < 5:
        return {
            "raw_bytes": len(raw),
            "compression_type": "truncated",
        }

    compression_code = raw[0]
    compression_type = COMPRESSION_LABELS.get(compression_code, f"unknown:{compression_code}")
    compressed_bytes = int.from_bytes(raw[1:5], "big")
    header_bytes = 5
    uncompressed_bytes: int | None = None

    if compression_code in {1, 2}:
        if len(raw) < 9:
            return {
                "raw_bytes": len(raw),
                "compression_type": compression_type,
                "compressed_bytes": compressed_bytes,
                "parse_error": "compressed record header truncated",
            }
        uncompressed_bytes = int.from_bytes(raw[5:9], "big")
        header_bytes = 9

    payload = raw[header_bytes : header_bytes + compressed_bytes]
    trailing_bytes = max(0, len(raw) - header_bytes - compressed_bytes)
    payload_magic = payload[:6].hex()

    parsed: dict[str, object] = {
        "raw_bytes": len(raw),
        "compression_type": compression_type,
        "compression_code": compression_code,
        "compressed_bytes": compressed_bytes,
        "uncompressed_bytes": uncompressed_bytes,
        "header_bytes": header_bytes,
        "payload_magic": payload_magic,
        "trailing_bytes": trailing_bytes,
    }
    if trailing_bytes == 2:
        parsed["trailing_revision_candidate"] = int.from_bytes(raw[-2:], "big")

    if not payload or compressed_bytes > MAX_RECORD_DECOMPRESS_BYTES:
        return parsed

    try:
        if compression_code == 1:
            unpacked = bz2.decompress(b"BZh1" + payload)
        elif compression_code == 2:
            unpacked = gzip.decompress(payload)
        else:
            unpacked = payload
    except (OSError, EOFError) as exc:
        parsed["decompression_error"] = str(exc)
        return parsed

    parsed["decoded_bytes"] = len(unpacked)
    parsed["decoded_matches_header"] = uncompressed_bytes is None or len(unpacked) == uncompressed_bytes
    parsed["decoded_prefix_hex"] = unpacked[:16].hex()
    return parsed


def _summarize_table(connection: sqlite3.Connection, table_name: str) -> dict[str, object]:
    cursor = connection.cursor()
    quoted = _quote_identifier(table_name)
    row_count, min_key, max_key, avg_data_len, max_data_len, min_version, max_version, min_crc, max_crc = cursor.execute(
        f"""
        SELECT
            COUNT(*),
            MIN("KEY"),
            MAX("KEY"),
            AVG(LENGTH("DATA")),
            MAX(LENGTH("DATA")),
            MIN("VERSION"),
            MAX("VERSION"),
            MIN("CRC"),
            MAX("CRC")
        FROM {quoted}
        """
    ).fetchone()

    compression_rows = cursor.execute(
        f"""
        SELECT hex(substr("DATA", 1, 1)) AS prefix, COUNT(*)
        FROM {quoted}
        WHERE "DATA" IS NOT NULL AND LENGTH("DATA") > 0
        GROUP BY prefix
        ORDER BY COUNT(*) DESC, prefix
        """
    ).fetchall()

    sample_rows = cursor.execute(
        f"""
        SELECT "KEY", "DATA", "VERSION", "CRC"
        FROM {quoted}
        WHERE "DATA" IS NOT NULL
        ORDER BY "KEY"
        LIMIT {MAX_RECORD_SAMPLES}
        """
    ).fetchall()

    return {
        "row_count": int(row_count or 0),
        "key_range": {
            "min": int(min_key) if min_key is not None else None,
            "max": int(max_key) if max_key is not None else None,
        },
        "data_bytes": {
            "average": round(float(avg_data_len), 2) if avg_data_len is not None else None,
            "max": int(max_data_len) if max_data_len is not None else None,
        },
        "version_range": {
            "min": int(min_version) if min_version is not None else None,
            "max": int(max_version) if max_version is not None else None,
        },
        "crc_range": {
            "min": int(min_crc) if min_crc is not None else None,
            "max": int(max_crc) if max_crc is not None else None,
        },
        "compression_types": [
            {
                "code": int(prefix, 16),
                "name": COMPRESSION_LABELS.get(int(prefix, 16), f"unknown:{int(prefix, 16)}"),
                "count": int(count),
            }
            for prefix, count in compression_rows
        ],
        "record_samples": [
            {
                "key": int(key),
                "version": int(version) if version is not None else None,
                "crc": int(crc) if crc is not None else None,
                **_parse_container_record(bytes(data)),
            }
            for key, data, version, crc in sample_rows
        ],
    }


class JS5CacheAnalyzer(Analyzer):
    name = "js5-cache"

    def supports(self, target: Path) -> bool:
        return target.is_file() and _match_jcache_name(target) is not None

    def analyze(self, target: Path, report: AnalysisReport) -> None:
        match = _match_jcache_name(target)
        if match is None:
            return

        archive_id = int(match.group("archive_id"))
        store_kind = "core-js5" if match.group("core") else "js5"
        index_names, mapping_source, mapping_build = _load_index_names(str(target))
        index_name = index_names.get(archive_id)

        with sqlite3.connect(str(target)) as connection:
            cursor = connection.cursor()
            tables_present = {
                str(name)
                for name, in cursor.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
                ).fetchall()
            }

            table_summaries = {}
            for table_name in ("cache", "cache_index"):
                if table_name in tables_present:
                    table_summaries[table_name] = _summarize_table(connection, table_name)

        report.add_section(
            "js5_cache",
            {
                "store_kind": store_kind,
                "archive_id": archive_id,
                "index_name": index_name,
                "mapping_source": mapping_source,
                "mapping_build": mapping_build,
                "tables_present": sorted(tables_present),
                "table_summaries": table_summaries,
            },
        )
