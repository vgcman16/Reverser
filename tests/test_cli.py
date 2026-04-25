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


def _build_clientscript_payload(
    *,
    instruction_count: int,
    body_bytes: bytes = b"",
) -> bytes:
    footer = bytearray()
    footer.extend(int(instruction_count).to_bytes(4, "big"))
    footer.extend((0).to_bytes(2, "big"))
    footer.extend((0).to_bytes(2, "big"))
    footer.extend((0).to_bytes(2, "big"))
    footer.extend((0).to_bytes(2, "big"))
    footer.extend((0).to_bytes(2, "big"))
    footer.extend((0).to_bytes(2, "big"))
    switch_payload = b"\x00"
    return b"\x00" + body_bytes + bytes(footer) + switch_payload + len(switch_payload).to_bytes(2, "big")


def _encode_clientscript_instruction(raw_opcode: int, immediate_kind: str, value: int) -> bytes:
    payload = bytearray()
    payload.extend(int(raw_opcode).to_bytes(2, "big"))
    if immediate_kind == "int":
        payload.extend(int(value).to_bytes(4, "big", signed=True))
    elif immediate_kind == "byte":
        payload.append(int(value) & 0xFF)
    elif immediate_kind == "short":
        payload.extend(int(value).to_bytes(2, "big", signed=True))
    else:
        raise AssertionError(f"Unsupported immediate kind in test helper: {immediate_kind}")
    return bytes(payload)


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

    exit_code = main(["schema", "--kind", "external-target-index"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert "targets" in payload["required"]

    exit_code = main(["schema", "--kind", "external-tool-inventory"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert "tools" in payload["required"]

    exit_code = main(["schema", "--kind", "pe-direct-calls"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert "results" in payload["required"]

    exit_code = main(["schema", "--kind", "pe-branch-targets"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert "results" in payload["required"]

    exit_code = main(["schema", "--kind", "pe-callsite-registers"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert "results" in payload["required"]

    exit_code = main(["schema", "--kind", "pe-address-refs"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert "results" in payload["required"]

    exit_code = main(["schema", "--kind", "pe-function-literals"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert "functions" in payload["required"]

    exit_code = main(["schema", "--kind", "pe-function-calls"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert "functions" in payload["required"]

    exit_code = main(["schema", "--kind", "pe-indirect-dispatches"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert "functions" in payload["required"]

    exit_code = main(["schema", "--kind", "pe-instructions"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert "windows" in payload["required"]

    exit_code = main(["schema", "--kind", "pe-runtime-functions"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert "queries" in payload["required"]

    exit_code = main(["schema", "--kind", "pe-qwords"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert "reads" in payload["required"]

    exit_code = main(["schema", "--kind", "pe-strings"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert "reads" in payload["required"]

    exit_code = main(["schema", "--kind", "pe-vtable-slots"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert "tables" in payload["required"]

    exit_code = main(["schema", "--kind", "pe-rtti-type-descriptors"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert "descriptors" in payload["required"]

    exit_code = main(["schema", "--kind", "pe-provider-descriptors"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert "descriptors" in payload["required"]

    exit_code = main(["schema", "--kind", "pe-provider-descriptor-scan"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert "scan" in payload["required"]

    exit_code = main(["schema", "--kind", "pe-provider-descriptor-clusters"])
    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert "clusters" in payload["required"]


def test_cli_js5_probe_schemas_output_json(capsys):
    for kind, required_field in (
        ("js5-opcode-probe", "raw_opcode"),
        ("js5-opcode-interior-probe", "hits"),
        ("js5-opcode-subtypes", "blocked_frontier_subtype_candidates"),
        ("js5-branch-clusters", "structural_clusters"),
        ("js5-pseudocode-blockers", "blocked_profile_count"),
    ):
        exit_code = main(["schema", "--kind", kind])
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        assert exit_code == 0
        assert required_field in payload["required"]


def test_cli_api_request_schemas_output_json(capsys):
    for kind, required_field, property_field in (
        ("analyze-request", "target", "max_strings"),
        ("scan-request", "target", "include_globs"),
        ("diff-request", "base", "head"),
        ("js5-export-request", "target", "output_dir"),
        ("js5-opcode-probe-request", "source", "opcode"),
        ("catalog-search-request", None, "limit"),
    ):
        exit_code = main(["schema", "--kind", kind])
        captured = capsys.readouterr()
        payload = json.loads(captured.out)
        assert exit_code == 0
        if required_field is not None:
            assert required_field in payload["required"]
        assert property_field in payload["properties"]


def test_cli_schema_list_outputs_registry(capsys):
    exit_code = main(["schema", "--list"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["count"] >= 18
    assert any(item["kind"] == "js5-opcode-probe" for item in payload["schemas"])
    assert any(item["path"] == "/schema/js5-pseudocode-blockers" for item in payload["schemas"])
    assert any(item["kind"] == "analyze-request" for item in payload["schemas"])
    assert any(item["path"] == "/schema/js5-opcode-probe-request" for item in payload["schemas"])
    assert any(item["kind"] == "external-target-index" for item in payload["schemas"])
    assert any(item["kind"] == "external-tool-inventory" for item in payload["schemas"])
    assert any(item["kind"] == "pe-branch-targets" for item in payload["schemas"])
    assert any(item["kind"] == "pe-callsite-registers" for item in payload["schemas"])
    assert any(item["kind"] == "pe-address-refs" for item in payload["schemas"])
    assert any(item["kind"] == "pe-function-literals" for item in payload["schemas"])
    assert any(item["kind"] == "pe-function-calls" for item in payload["schemas"])
    assert any(item["kind"] == "pe-indirect-dispatches" for item in payload["schemas"])
    assert any(item["kind"] == "pe-instructions" for item in payload["schemas"])
    assert any(item["kind"] == "pe-runtime-functions" for item in payload["schemas"])
    assert any(item["kind"] == "pe-qwords" for item in payload["schemas"])
    assert any(item["kind"] == "pe-strings" for item in payload["schemas"])
    assert any(item["kind"] == "pe-rtti-type-descriptors" for item in payload["schemas"])
    assert any(item["kind"] == "pe-provider-descriptors" for item in payload["schemas"])
    assert any(item["kind"] == "pe-provider-descriptor-scan" for item in payload["schemas"])
    assert any(item["kind"] == "pe-provider-descriptor-clusters" for item in payload["schemas"])


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


def test_cli_external_tool_inventory_outputs_json(capsys):
    exit_code = main(["external-tool-inventory", "--profile", "win64-pe"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["type"] == "external-tool-inventory"
    assert payload["profile"] == "win64-pe"
    assert any(tool["name"] == "Ghidra" for tool in payload["tools"])


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


def test_cli_external_target_index_outputs_json(tmp_path, capsys):
    root = tmp_path / "external-targets"
    target_dir = root / "rs2client-947"
    target_dir.mkdir(parents=True)
    (target_dir / "first.json").write_text(
        json.dumps(
            {
                "milestone": "bootstrap-a",
                "updated_conclusion": "First conclusion.",
                "next_targets": ["next-a"],
            }
        ),
        encoding="utf-8",
    )
    (target_dir / "second.json").write_text(
        json.dumps(
            {
                "milestone": "bootstrap-b",
                "updated_conclusion": "Second conclusion.",
                "next_targets": ["next-b"],
            }
        ),
        encoding="utf-8",
    )

    exit_code = main(["external-target-index", str(root), "--stdout-format", "pretty"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["target_count"] == 1
    assert payload["artifact_count"] == 2
    assert payload["targets"][0]["name"] == "rs2client-947"
    assert payload["targets"][0]["latest_artifact"] == "second.json"
    assert payload["targets"][0]["artifacts"][0]["artifact_name"] == "second.json"


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


def test_cli_js5_opcode_probe_outputs_summary(tmp_path, capsys):
    export_dir = tmp_path / "exports"
    export_dir.mkdir()
    (export_dir / "manifest.json").write_text(
        json.dumps(
            {
                "tables": {
                    "cache": {
                        "records": [
                            {
                                "key": 77,
                                "archive_files": [
                                    {
                                        "file_id": 0,
                                        "semantic_profile": {
                                            "kind": "clientscript-disassembly",
                                            "pseudocode_status": "ready",
                                            "instruction_sample": [
                                                {
                                                    "offset": 12,
                                                    "raw_opcode": 0x9500,
                                                    "raw_opcode_hex": "0x9500",
                                                    "immediate_kind": "short",
                                                    "semantic_label": "WIDGET_LINK_MUTATOR_CANDIDATE",
                                                    "semantic_family": "widget-link-action",
                                                    "operand_signature_candidate": {
                                                        "signature": "widget+widget",
                                                        "confidence": 0.8,
                                                    },
                                                }
                                            ],
                                        },
                                    }
                                ],
                            }
                        ]
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "js5-opcode-probe",
            str(export_dir),
            "0x9500",
            "--stdout-format",
            "pretty",
        ]
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["raw_opcode_hex"] == "0x9500"
    assert payload["hit_count"] == 1
    assert payload["script_count"] == 1
    assert payload["operand_signature_counts"] == {"widget+widget": 1}


def test_cli_js5_opcode_subtypes_outputs_summary(tmp_path, capsys):
    export_dir = tmp_path / "exports"
    export_dir.mkdir()
    payload_a = export_dir / "blocked-key-41-file-0.bin"
    payload_b = export_dir / "blocked-key-43-file-0.bin"
    blocked_payload = _build_clientscript_payload(
        instruction_count=2,
        body_bytes=(
            _encode_clientscript_instruction(0x0000, "int", 14942212)
            + bytes.fromhex("95 00 05 11 00 00")
        ),
    )
    payload_a.write_bytes(blocked_payload)
    payload_b.write_bytes(blocked_payload)
    (export_dir / "manifest.json").write_text(
        json.dumps(
            {
                "tables": {
                    "cache": {
                        "records": [
                            {
                                "key": 41,
                                "archive_files": [
                                    {
                                        "file_id": 0,
                                        "semantic_profile": {
                                            "kind": "clientscript-disassembly",
                                            "pseudocode_status": "blocked",
                                            "path": str(payload_a),
                                            "tail_next_instruction": {
                                                "offset": 6,
                                                "raw_opcode": 0x9500,
                                                "raw_opcode_hex": "0x9500",
                                            },
                                            "tail_instruction_sample": [
                                                {
                                                    "offset": 0,
                                                    "raw_opcode": 0x0000,
                                                    "raw_opcode_hex": "0x0000",
                                                    "immediate_kind": "int",
                                                    "immediate_value": 14942212,
                                                    "end_offset": 6,
                                                }
                                            ],
                                            "tail_stack_summary": {
                                                "prefix_operand_signature": "widget+int",
                                            },
                                            "pseudocode_blocker": {
                                                "blocking_kind": "opcode-frontier",
                                                "frontier_reason": "unknown-locked-opcode",
                                                "frontier_raw_opcode": 0x9500,
                                                "frontier_raw_opcode_hex": "0x9500",
                                                "frontier_offset": 6,
                                                "tail_hint_raw_opcode_hex": "0x1100",
                                            },
                                        },
                                    }
                                ],
                            },
                            {
                                "key": 43,
                                "archive_files": [
                                    {
                                        "file_id": 0,
                                        "semantic_profile": {
                                            "kind": "clientscript-disassembly",
                                            "pseudocode_status": "blocked",
                                            "path": str(payload_b),
                                            "tail_next_instruction": {
                                                "offset": 6,
                                                "raw_opcode": 0x9500,
                                                "raw_opcode_hex": "0x9500",
                                            },
                                            "tail_instruction_sample": [
                                                {
                                                    "offset": 0,
                                                    "raw_opcode": 0x0000,
                                                    "raw_opcode_hex": "0x0000",
                                                    "immediate_kind": "int",
                                                    "immediate_value": 14942212,
                                                    "end_offset": 6,
                                                }
                                            ],
                                            "tail_stack_summary": {
                                                "prefix_operand_signature": "widget+int",
                                            },
                                            "pseudocode_blocker": {
                                                "blocking_kind": "opcode-frontier",
                                                "frontier_reason": "unknown-locked-opcode",
                                                "frontier_raw_opcode": 0x9500,
                                                "frontier_raw_opcode_hex": "0x9500",
                                                "frontier_offset": 6,
                                                "tail_hint_raw_opcode_hex": "0x1100",
                                            },
                                        },
                                    }
                                ],
                            },
                        ]
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "js5-opcode-subtypes",
            str(export_dir),
            "0x9500",
            "--stdout-format",
            "pretty",
        ]
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["kind"] == "clientscript-opcode-subtype-probe"
    assert payload["blocked_frontier_subtype_candidate_count"] == 1
    subtype_candidate = payload["blocked_frontier_subtype_candidates"][0]
    assert subtype_candidate["sub_opcode_hex"] == "0x05"
    assert subtype_candidate["recommended_immediate_width"] == 1
    assert subtype_candidate["suggested_override"]["opcode"] == "0x9500"


def test_cli_js5_opcode_branch_clusters_outputs_summary(tmp_path, capsys):
    export_dir = tmp_path / "exports"
    export_dir.mkdir()
    (export_dir / "manifest.json").write_text(
        json.dumps(
            {
                "tables": {
                    "cache": {
                        "records": [
                            {
                                "key": 5,
                                "archive_files": [
                                    {
                                        "file_id": 0,
                                        "semantic_profile": {
                                            "kind": "clientscript-disassembly",
                                            "pseudocode_status": "blocked",
                                            "branch_state_probe": {
                                                "branch_instruction": {
                                                    "offset": 24,
                                                    "raw_opcode": 0x0005,
                                                    "raw_opcode_hex": "0x0005",
                                                    "immediate_kind": "short",
                                                    "immediate_value": 4352,
                                                },
                                                "branch_state_before_compact": {
                                                    "operand_signature": "widget+widget"
                                                },
                                                "branch_state_after_compact": {
                                                    "operand_signature": "widget+widget"
                                                },
                                                "branch_required_input_delta": {},
                                                "fallthrough_path": {
                                                    "status": "frontier",
                                                    "final_stack_compact": {
                                                        "operand_signature": "widget+widget"
                                                    },
                                                    "required_input_delta": {},
                                                    "next_instruction": {"raw_opcode_hex": "0x05D2"},
                                                },
                                                "taken_path": {
                                                    "status": "out-of-bounds",
                                                    "final_stack_compact": {
                                                        "operand_signature": "widget+widget"
                                                    },
                                                    "required_input_delta": {},
                                                },
                                                "path_comparison": {
                                                    "phantom_input_side": "none",
                                                    "phantom_input_mismatch": False,
                                                    "divergence_flags": ["path-status-divergence"],
                                                },
                                            },
                                        },
                                    }
                                ],
                            }
                        ]
                    }
                }
            }
        ),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "js5-opcode-branch-clusters",
            str(export_dir),
            "0x0005",
            "--stdout-format",
            "pretty",
        ]
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["kind"] == "clientscript-branch-cluster-probe"
    assert payload["raw_opcode_hex"] == "0x0005"
    assert payload["structural_observation_count"] == 1
    assert payload["structural_clusters"][0]["fallthrough_landing_opcode_counts"] == {"0x05D2": 1}


def test_cli_js5_pseudocode_blockers_outputs_summary(tmp_path, capsys):
    export_dir = tmp_path / "exports"
    export_dir.mkdir()
    blocker_path = export_dir / "clientscript-pseudocode-blockers.json"
    blocker_path.write_text(
        json.dumps(
            {
                "profile_count": 5,
                "ready_profile_count": 2,
                "blocked_profile_count": 3,
                "blocker_opcode_count": 2,
                "blocking_kind_counts": {"opcode-frontier": 2, "instruction-budget": 1},
                "frontier_reason_counts": {"unknown-locked-opcode": 2},
                "tail_status_counts": {"blocked": 3, "complete": 2},
                "tail_last_opcode_count": 2,
                "tail_hint_opcode_count": 1,
                "control_group_diff_count": 1,
                "blocked_key_sample": [41, 43, 99],
                "blocker_opcodes": [
                    {"raw_opcode_hex": "0x9500", "blocked_profile_count": 2},
                    {"raw_opcode_hex": "0x1D00", "blocked_profile_count": 1},
                ],
                "blocked_profile_sample": [
                    {"archive_key": 41, "blocking_kind": "opcode-frontier"},
                    {"archive_key": 43, "blocking_kind": "opcode-frontier"},
                    {"archive_key": 99, "blocking_kind": "instruction-budget"},
                ],
            }
        ),
        encoding="utf-8",
    )
    (export_dir / "manifest.json").write_text(
        json.dumps(
            {
                "clientscript_pseudocode_blockers_path": str(blocker_path),
                "clientscript_pseudocode": {
                    "profile_count": 5,
                    "ready_profile_count": 2,
                    "blocked_profile_count": 3,
                    "blocker_opcode_count": 2,
                    "blocking_kind_counts": {"opcode-frontier": 2, "instruction-budget": 1},
                    "frontier_reason_counts": {"unknown-locked-opcode": 2},
                    "tail_status_counts": {"blocked": 3, "complete": 2},
                    "tail_last_opcode_count": 2,
                    "tail_hint_opcode_count": 1,
                    "control_group_diff_count": 1,
                    "blocked_key_sample": [41, 43, 99],
                },
            }
        ),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "js5-pseudocode-blockers",
            str(export_dir),
            "--max-sample",
            "2",
            "--stdout-format",
            "pretty",
        ]
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["kind"] == "clientscript-pseudocode-blocker-probe"
    assert payload["profile_count"] == 5
    assert payload["ready_profile_count"] == 2
    assert payload["blocked_profile_count"] == 3
    assert payload["blocker_summary_path"] == str(blocker_path)
    assert payload["blocking_kind_counts"] == {"instruction-budget": 1, "opcode-frontier": 2}
    assert len(payload["blocked_profile_sample"]) == 2
    assert payload["blocked_profile_sample"][0]["archive_key"] == 41


def test_cli_js5_pseudocode_blockers_falls_back_to_manifest_summary(tmp_path, capsys):
    export_dir = tmp_path / "exports"
    export_dir.mkdir()
    (export_dir / "manifest.json").write_text(
        json.dumps(
            {
                "clientscript_pseudocode": {
                    "profile_count": 7,
                    "ready_profile_count": 4,
                    "blocked_profile_count": 3,
                    "blocker_opcode_count": 1,
                    "blocking_kind_counts": {"opcode-frontier": 3},
                    "frontier_reason_counts": {"unknown-locked-opcode": 3},
                    "tail_status_counts": {"blocked": 3, "complete": 4},
                    "tail_last_opcode_count": 1,
                    "tail_hint_opcode_count": 1,
                    "control_group_diff_count": 0,
                    "blocked_key_sample": [7, 8, 9],
                }
            }
        ),
        encoding="utf-8",
    )

    exit_code = main(
        [
            "js5-pseudocode-blockers",
            str(export_dir / "manifest.json"),
            "--stdout-format",
            "pretty",
        ]
    )

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["kind"] == "clientscript-pseudocode-blocker-probe"
    assert payload["profile_count"] == 7
    assert payload["ready_profile_count"] == 4
    assert payload["blocked_profile_count"] == 3
    assert payload["blocker_summary_path"] is None
    assert payload["artifact_status"] == "manifest-summary-only"
    assert payload["blocked_key_sample"] == [7, 8, 9]
    assert payload["blocked_profile_sample"] == []


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
