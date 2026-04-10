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


def test_identity_flags_probable_packed_executable(tmp_path):
    target = tmp_path / "compressed.exe"
    target.write_bytes(bytes(range(256)) * 32)

    report = AnalysisEngine().analyze(target)

    identity = report.sections["identity"]
    assert identity["signature"] == "unknown"
    assert identity["probable_packed_executable"] is True
    assert any(finding.title == "Opaque executable-like file" for finding in report.findings)


def test_identity_does_not_flag_normal_pe_as_packed(tmp_path):
    target = tmp_path / "normal.exe"
    target.write_bytes(b"MZ" + b"\x00" * 512)

    report = AnalysisEngine().analyze(target)

    assert report.sections["identity"]["probable_packed_executable"] is False


def test_identity_samples_large_file_when_thresholds_are_low(tmp_path):
    target = tmp_path / "runtime-cache.bin"
    target.write_bytes(bytes(range(256)) * 64)

    report = AnalysisEngine(
        max_identity_hash_bytes=1024,
        max_identity_entropy_bytes=1024,
        identity_sample_window_bytes=384,
    ).analyze(target)

    identity = report.sections["identity"]
    assert identity["hash_strategy"] == "sampled"
    assert identity["entropy_strategy"] == "sampled"
    assert identity["hashes"] == {}
    assert identity["sampled_hashes"]["sha256"]
    assert identity["hash_sampled_bytes"] > 0
    assert identity["entropy_sampled_bytes"] > 0
    assert "hash:sampled" in report.summary["tags"]
    assert "entropy:sampled" in report.summary["tags"]
