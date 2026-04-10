from __future__ import annotations

from reverser.analysis.diffing import diff_artifacts, load_or_generate_artifact


def test_diff_reports_detects_added_findings(tmp_path):
    base_target = tmp_path / "base.bin"
    head_target = tmp_path / "head.bin"
    base_target.write_bytes(b"hello world")
    head_target.write_bytes(b"hello world admin@example.com 10.1.2.3")

    base = load_or_generate_artifact(base_target)
    head = load_or_generate_artifact(head_target)
    diff = diff_artifacts(base, head, base_ref=str(base_target), head_ref=str(head_target)).to_dict()

    assert diff["artifact_kind"] == "report-diff"
    assert diff["summary"]["added_findings"] >= 1


def test_diff_scan_indexes_detects_added_entry(tmp_path):
    base_root = tmp_path / "base"
    head_root = tmp_path / "head"
    base_root.mkdir()
    head_root.mkdir()
    (base_root / "Game.exe").write_bytes(b"MZ" + b"\x00" * 256)
    (head_root / "Game.exe").write_bytes(b"MZ" + b"\x00" * 256)
    (head_root / "patch.pak").write_bytes(b"demo")

    base = load_or_generate_artifact(base_root)
    head = load_or_generate_artifact(head_root)
    diff = diff_artifacts(base, head, base_ref=str(base_root), head_ref=str(head_root)).to_dict()

    assert diff["artifact_kind"] == "scan-index-diff"
    assert diff["summary"]["added_entries"] == 1
