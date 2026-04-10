from __future__ import annotations

import json
import bz2
import gzip
import lzma
import sqlite3
from pathlib import Path

from reverser.cli.main import main
from reverser import __version__


def _build_js5_record(payload: bytes, *, compression: str, revision: int = 1) -> bytes:
    if compression == "lzma":
        lc = 3
        lp = 0
        pb = 2
        dict_size = 1 << 20
        packed = lzma.compress(
            payload,
            format=lzma.FORMAT_RAW,
            filters=[
                {
                    "id": lzma.FILTER_LZMA1,
                    "dict_size": dict_size,
                    "lc": lc,
                    "lp": lp,
                    "pb": pb,
                }
            ],
        )
        property_byte = pb * 45 + lp * 9 + lc
        props = bytes([property_byte]) + dict_size.to_bytes(4, "little")
        packed = props + packed
        return b"\x03" + len(packed).to_bytes(4, "big") + len(payload).to_bytes(4, "big") + packed + revision.to_bytes(2, "big")

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


def test_cli_schema_outputs_json(capsys):
    exit_code = main(["schema"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["type"] == "object"


def test_cli_scan_schema_outputs_json(capsys):
    exit_code = main(["schema", "--kind", "scan-index"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert "entries" in payload["required"]


def test_cli_diff_schema_outputs_json(capsys):
    exit_code = main(["schema", "--kind", "diff"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert "artifact_kind" in payload["required"]


def test_cli_catalog_schemas_output_json(capsys):
    exit_code = main(["schema", "--kind", "catalog-search"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert "results" in payload["required"]

    exit_code = main(["schema", "--kind", "catalog-ingests"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert "ingests" in payload["required"]

    exit_code = main(["schema", "--kind", "js5-manifest"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert "export_root" in payload["required"]


def test_cli_lists_analyzers(capsys):
    exit_code = main(["analyzers"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert any(item["name"] == "portable-executable" for item in payload["analyzers"])
    assert any(item["name"] == "mach-o" for item in payload["analyzers"])
    assert any(item["name"] == "sqlite" for item in payload["analyzers"])
    assert any(item["name"] == "js5-cache" for item in payload["analyzers"])
    assert any(item["name"] == "js5-cache-directory" for item in payload["analyzers"])


def test_cli_analyze_outputs_machine_json(tmp_path, capsys):
    target = tmp_path / "sample.bin"
    target.write_bytes(b"hello headless world")

    exit_code = main(["analyze", str(target)])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["target"]["path"].endswith("sample.bin")
    assert payload["report_version"]
    assert payload["summary"]["section_count"] >= 1
    assert "identity" in payload["sections"]


def test_cli_version(capsys):
    try:
        main(["--version"])
    except SystemExit as exc:
        assert exc.code == 0

    captured = capsys.readouterr()
    assert __version__ in captured.out


def test_cli_scan_outputs_index_and_reports(tmp_path, capsys):
    root = tmp_path / "game"
    root.mkdir()
    (root / "Game.exe").write_bytes(b"MZ" + b"\x00" * 512)
    (root / "data.pak").write_bytes(b"demo")
    reports_dir = tmp_path / "reports"
    index_json = tmp_path / "index.json"
    index_ndjson = tmp_path / "index.ndjson"
    csv_out = tmp_path / "index.csv"

    exit_code = main(
        [
            "scan",
            str(root),
            "--reports-dir",
            str(reports_dir),
            "--index-json",
            str(index_json),
            "--index-ndjson",
            str(index_ndjson),
            "--csv-out",
            str(csv_out),
            "--stdout-format",
            "pretty",
        ]
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["summary"]["entry_count"] == 2
    assert index_json.exists()
    assert index_ndjson.exists()
    assert csv_out.exists()
    assert (reports_dir / "Game.exe.json").exists()


def test_cli_diff_outputs_json(tmp_path, capsys):
    base_target = tmp_path / "base.bin"
    head_target = tmp_path / "head.bin"
    base_target.write_bytes(b"hello")
    head_target.write_bytes(b"hello admin@example.com")

    exit_code = main(["diff", str(base_target), str(head_target), "--stdout-format", "pretty"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["artifact_kind"] == "report-diff"


def test_cli_catalog_ingest_and_search(tmp_path, capsys):
    db_path = tmp_path / "catalog.sqlite3"
    target = tmp_path / "sample.bin"
    target.write_bytes(b"hello admin@example.com")
    csv_out = tmp_path / "search.csv"

    exit_code = main(["catalog-ingest", str(target), "--db", str(db_path)])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["entry_count"] == 1

    exit_code = main(["catalog-search", "--db", str(db_path), "--min-findings", "1", "--csv-out", str(csv_out)])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["count"] == 1
    assert csv_out.exists()

    exit_code = main(["catalog-stats", "--db", str(db_path)])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["artifact_count"] == 1


def test_cli_js5_export_outputs_manifest_and_payloads(tmp_path, capsys):
    root = tmp_path / "OpenNXT"
    target = root / "data" / "cache" / "js5-47.jcache"
    export_dir = tmp_path / "exports"
    target.parent.mkdir(parents=True, exist_ok=True)
    _write_js5_mapping(root, build=947, index_names={47: "MODELS_RT7"})

    with sqlite3.connect(target) as connection:
        connection.execute("CREATE TABLE cache (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute("CREATE TABLE cache_index (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute(
            "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (1, _build_js5_record(b"model-bytes", compression="lzma", revision=947), 947047, 7777),
        )
        connection.commit()

    exit_code = main(
        [
            "js5-export",
            str(target),
            str(export_dir),
            "--table",
            "cache",
            "--stdout-format",
            "pretty",
        ]
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["archive_id"] == 47
    assert payload["index_name"] == "MODELS_RT7"
    assert payload["summary"]["decoded_record_count"] == 1
    assert (export_dir / "manifest.json").exists()
    exported_payload = export_dir / "cache" / "key-1.payload.bin"
    assert exported_payload.exists()
    assert exported_payload.read_bytes() == b"model-bytes"
