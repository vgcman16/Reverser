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


def test_cli_analyze_outputs_machine_json(tmp_path, capsys):
    target = tmp_path / "sample.bin"
    target.write_bytes(b"hello headless world")

    exit_code = main(["analyze", str(target)])

    captured = capsys.readouterr()
    payload = json.loads(captured.out)
    assert exit_code == 0
    assert payload["target"]["path"].endswith("sample.bin")
    assert "identity" in payload["sections"]


def test_cli_version(capsys):
    try:
        main(["--version"])
    except SystemExit as exc:
        assert exc.code == 0

    captured = capsys.readouterr()
    assert __version__ in captured.out
