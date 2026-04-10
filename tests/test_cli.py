from __future__ import annotations

import json

from reverser.cli.main import main
from reverser import __version__


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


def test_cli_lists_analyzers(capsys):
    exit_code = main(["analyzers"])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert any(item["name"] == "portable-executable" for item in payload["analyzers"])
    assert any(item["name"] == "mach-o" for item in payload["analyzers"])
    assert any(item["name"] == "sqlite" for item in payload["analyzers"])
    assert any(item["name"] == "js5-cache" for item in payload["analyzers"])


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
