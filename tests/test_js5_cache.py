from __future__ import annotations

import bz2
import gzip
import json
import sqlite3
from pathlib import Path

from reverser.analysis.orchestrator import AnalysisEngine


def _build_js5_record(payload: bytes, *, compression: str, revision: int = 1) -> bytes:
    if compression == "gzip":
        packed = gzip.compress(payload)
        return b"\x02" + len(packed).to_bytes(4, "big") + len(payload).to_bytes(4, "big") + packed + revision.to_bytes(2, "big")

    if compression == "bzip2":
        packed = bz2.compress(payload)
        stripped = packed[4:]
        return b"\x01" + len(stripped).to_bytes(4, "big") + len(payload).to_bytes(4, "big") + stripped + revision.to_bytes(2, "big")

    return b"\x00" + len(payload).to_bytes(4, "big") + payload + revision.to_bytes(2, "big")


def _write_js5_mapping(root: Path, *, build: int, index_names: dict[int, str]) -> None:
    mapping_path = root / "data" / "prot" / str(build) / "generated" / "shared" / "js5-archive-resolution.json"
    mapping_path.parent.mkdir(parents=True, exist_ok=True)
    mapping_path.write_text(
        json.dumps(
            {
                "build": build,
                "indexNames": {str(key): value for key, value in index_names.items()},
            }
        ),
        encoding="utf-8",
    )


def test_js5_cache_analyzer_reports_archive_details(tmp_path):
    root = tmp_path / "OpenNXT"
    target = root / "data" / "cache" / "js5-17.jcache"
    target.parent.mkdir(parents=True, exist_ok=True)
    _write_js5_mapping(root, build=947, index_names={17: "CONFIG_ENUM"})

    with sqlite3.connect(target) as connection:
        connection.execute("CREATE TABLE cache (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute("CREATE TABLE cache_index (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute(
            "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (0, _build_js5_record(b'{"hello":"world"}', compression="gzip", revision=321), 947001, 1234),
        )
        connection.execute(
            "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (1, _build_js5_record(b"enum payload", compression="bzip2", revision=654), 947002, 5678),
        )
        connection.execute(
            "INSERT INTO cache_index (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (17, _build_js5_record(b"index payload", compression="none", revision=111), -1, 999),
        )
        connection.commit()

    report = AnalysisEngine().analyze(target)

    assert report.sections["identity"]["signature"] == "sqlite"
    js5_cache = report.sections["js5_cache"]
    assert js5_cache["store_kind"] == "js5"
    assert js5_cache["archive_id"] == 17
    assert js5_cache["index_name"] == "CONFIG_ENUM"
    assert js5_cache["mapping_build"] == 947

    cache_summary = js5_cache["table_summaries"]["cache"]
    compression_names = {item["name"] for item in cache_summary["compression_types"]}
    assert {"gzip", "bzip2"} <= compression_names
    assert cache_summary["row_count"] == 2
    assert any(sample["decoded_matches_header"] is True for sample in cache_summary["record_samples"])
    assert any(sample.get("trailing_revision_candidate") == 321 for sample in cache_summary["record_samples"])

    assert "format:js5-jcache" in report.summary["tags"]
    assert "js5-archive:17" in report.summary["tags"]
    assert "js5-index:config-enum" in report.summary["tags"]
