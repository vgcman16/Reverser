from __future__ import annotations

import json

from reverser.analysis.exporters.json_exporter import export_json
from reverser.analysis.exporters.markdown_exporter import export_markdown
from reverser.analysis.orchestrator import AnalysisEngine


def test_exporters_write_files(tmp_path):
    target = tmp_path / "sample.bin"
    target.write_bytes(b"hello world")
    report = AnalysisEngine().analyze(target)

    json_path = export_json(report, tmp_path / "report.json")
    md_path = export_markdown(report, tmp_path / "report.md")

    payload = json.loads(json_path.read_text(encoding="utf-8"))
    assert payload["target"]["path"].endswith("sample.bin")
    assert md_path.read_text(encoding="utf-8").startswith("# Analysis Report")
