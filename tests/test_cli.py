from __future__ import annotations

import json
import bz2
import gzip
import lzma
import sqlite3
from pathlib import Path

import py7zr

from reverser.cli.main import main
from reverser import __version__
from tests.helpers_netdragon import build_netdragon_pair


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


def test_cli_js5_export_filters_records_by_key_range(tmp_path, capsys):
    root = tmp_path / "OpenNXT"
    target = root / "data" / "cache" / "js5-47.jcache"
    export_dir = tmp_path / "exports"
    target.parent.mkdir(parents=True, exist_ok=True)
    _write_js5_mapping(root, build=947, index_names={47: "MODELS_RT7"})

    with sqlite3.connect(target) as connection:
        connection.execute("CREATE TABLE cache (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute("CREATE TABLE cache_index (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        for key, payload_bytes in ((1, b"alpha"), (2, b"beta"), (3, b"gamma")):
            connection.execute(
                "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
                (key, _build_js5_record(payload_bytes, compression="none", revision=947), 947000 + key, 7700 + key),
            )
        connection.commit()

    exit_code = main(
        [
            "js5-export",
            str(target),
            str(export_dir),
            "--table",
            "cache",
            "--key-start",
            "2",
            "--key-end",
            "3",
            "--stdout-format",
            "pretty",
        ]
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["settings"]["key_start"] == 2
    assert payload["settings"]["key_end"] == 3
    exported_keys = [record["key"] for record in payload["tables"]["cache"]["records"]]
    assert exported_keys == [2, 3]
    assert not (export_dir / "cache" / "key-1.payload.bin").exists()
    assert (export_dir / "cache" / "key-2.payload.bin").read_bytes() == b"beta"
    assert (export_dir / "cache" / "key-3.payload.bin").read_bytes() == b"gamma"


def test_cli_netdragon_export_outputs_manifest_and_payloads(tmp_path, capsys):
    tpi_path, _ = build_netdragon_pair(tmp_path)
    export_dir = tmp_path / "exports"

    exit_code = main(
        [
            "netdragon-export",
            str(tpi_path),
            str(export_dir),
            "--include-stored",
            "--stdout-format",
            "pretty",
        ]
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["summary"]["decoded_count"] == 2
    assert (export_dir / "manifest.json").exists()
    assert (export_dir / "data" / "demo.txt").read_bytes() == b"hello from netdragon"


def test_cli_archive_export_extracts_7z_payloads(tmp_path, capsys):
    target = tmp_path / "script.dat"
    source = tmp_path / "hello.txt"
    export_dir = tmp_path / "exports"
    source.write_text("hello world", encoding="utf-8")
    with py7zr.SevenZipFile(target, "w") as archive:
        archive.write(source, arcname="hello.txt")

    exit_code = main(
        [
            "archive-export",
            str(target),
            str(export_dir),
            "--stdout-format",
            "pretty",
        ]
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["archive_type"] == "7z"
    assert payload["summary"]["extraction_status"] == "extracted"
    assert (export_dir / "manifest.json").exists()
    assert (export_dir / "hello.txt").read_text(encoding="utf-8") == "hello world"


def test_cli_archive_export_unlocks_password_protected_7z_payloads(tmp_path, capsys):
    target = tmp_path / "script.dat"
    source = tmp_path / "hello.txt"
    export_dir = tmp_path / "exports"
    source.write_text("hello world", encoding="utf-8")
    with py7zr.SevenZipFile(target, "w", password="secret", header_encryption=True) as archive:
        archive.write(source, arcname="hello.txt")

    exit_code = main(
        [
            "archive-export",
            str(target),
            str(export_dir),
            "--password",
            "secret",
            "--stdout-format",
            "pretty",
        ]
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["summary"]["extraction_status"] == "extracted"
    assert (export_dir / "hello.txt").read_text(encoding="utf-8") == "hello world"


def test_cli_archive_export_reports_password_required_without_password(tmp_path, capsys):
    target = tmp_path / "script.dat"
    source = tmp_path / "hello.txt"
    export_dir = tmp_path / "exports"
    source.write_text("hello world", encoding="utf-8")
    with py7zr.SevenZipFile(target, "w", password="secret", header_encryption=True) as archive:
        archive.write(source, arcname="hello.txt")

    exit_code = main(
        [
            "archive-export",
            str(target),
            str(export_dir),
            "--stdout-format",
            "pretty",
        ]
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["summary"]["extraction_status"] == "password-required"
    assert (export_dir / "manifest.json").exists()
    assert not (export_dir / "hello.txt").exists()


def test_cli_conquer_map_export_writes_manifest_and_sidecars(tmp_path, capsys):
    root = tmp_path / "Conquer"
    map_root = root / "map" / "map"
    map_root.mkdir(parents=True)
    archive_path = map_root / "arena.7z"
    source = tmp_path / "arena.DMap"
    export_dir = tmp_path / "exports"
    payload = bytearray(0x118)
    payload[0:4] = (1004).to_bytes(4, "little")
    encoded_path = b"map\\puzzle\\arena.pul"
    payload[8 : 8 + len(encoded_path)] = encoded_path
    payload[0x108:0x10C] = (65536).to_bytes(4, "little")
    payload[0x10C:0x110] = (96).to_bytes(4, "little")
    payload[0x110:0x114] = (96).to_bytes(4, "little")
    payload[0x114:0x118] = (1).to_bytes(4, "little")
    source.write_bytes(bytes(payload))
    with py7zr.SevenZipFile(archive_path, "w") as archive:
        archive.write(source, arcname="arena.DMap")
    (map_root / "arena.OtherData").write_text(
        "[Header]\nTerrainLayerAmount=1\nInteractiveLayerAmount=1\n\n[TerrainLayer0]\nMapObjAmount=12\n",
        encoding="utf-8",
    )

    exit_code = main(
        [
            "conquer-map-export",
            str(root),
            str(export_dir),
            "--stdout-format",
            "pretty",
        ]
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["summary"]["selected_archive_count"] == 1
    assert payload["summary"]["exported_archive_count"] == 1
    assert (export_dir / "manifest.json").exists()
    assert (export_dir / "arena" / "arena.DMap").exists()
    assert (export_dir / "arena" / "arena.OtherData").exists()
    assert payload["maps"][0]["dmap"]["asset_path"] == "map\\puzzle\\arena.pul"
    assert payload["maps"][0]["otherdata"]["map_obj_total"] == 12
