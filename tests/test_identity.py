from __future__ import annotations

import zipfile

from reverser.analysis.orchestrator import AnalysisEngine


def test_identity_reports_zip_signature(tmp_path):
    target = tmp_path / "sample.zip"
    with zipfile.ZipFile(target, "w") as archive:
        archive.writestr("hello.txt", "hello")

    report = AnalysisEngine().analyze(target)

    assert report.sections["identity"]["signature"] == "zip"
    assert report.sections["archive"]["member_count"] == 1


def test_directory_summary_collects_extensions(tmp_path):
    (tmp_path / "game.exe").write_bytes(b"MZ" + b"\x00" * 100)
    (tmp_path / "data.pak").write_bytes(b"demo")

    report = AnalysisEngine().analyze(tmp_path)

    identity = report.sections["identity"]
    assert identity["file_count"] == 2
    extensions = {item["extension"] for item in identity["top_extensions"]}
    assert ".exe" in extensions
    assert ".pak" in extensions
