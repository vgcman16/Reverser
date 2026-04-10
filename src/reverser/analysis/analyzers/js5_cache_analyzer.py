from __future__ import annotations

import sqlite3
from pathlib import Path

from reverser.analysis.analyzers.base import Analyzer
from reverser.analysis.js5 import (
    COMPRESSION_LABELS,
    load_index_names,
    match_jcache_name,
    parse_js5_container_record,
    quote_identifier,
)
from reverser.models import AnalysisReport


MAX_RECORD_SAMPLES = 5


def _summarize_table(connection: sqlite3.Connection, table_name: str) -> dict[str, object]:
    cursor = connection.cursor()
    quoted = quote_identifier(table_name)
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
                **parse_js5_container_record(bytes(data)).to_dict(),
            }
            for key, data, version, crc in sample_rows
        ],
    }


class JS5CacheAnalyzer(Analyzer):
    name = "js5-cache"

    def supports(self, target: Path) -> bool:
        return target.is_file() and match_jcache_name(target) is not None

    def analyze(self, target: Path, report: AnalysisReport) -> None:
        match = match_jcache_name(target)
        if match is None:
            return

        archive_id = int(match.group("archive_id"))
        store_kind = "core-js5" if match.group("core") else "js5"
        index_names, mapping_source, mapping_build = load_index_names(str(target))
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
