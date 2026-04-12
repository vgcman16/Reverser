from __future__ import annotations

import zipfile

import py7zr

from reverser.analysis.orchestrator import AnalysisEngine
from reverser.analysis.analyzers.archive_analyzer import _parse_7z_listing


def test_identity_reports_zip_signature(tmp_path):
    target = tmp_path / "sample.zip"
    with zipfile.ZipFile(target, "w") as archive:
        archive.writestr("hello.txt", "hello")

    report = AnalysisEngine().analyze(target)

    assert report.sections["identity"]["signature"] == "zip"
    assert report.sections["archive"]["member_count"] == 1


def test_identity_reports_dds_signature(tmp_path):
    target = tmp_path / "arena000.dds"
    target.write_bytes(b"DDS " + b"\x00" * 64)

    report = AnalysisEngine().analyze(target)

    assert report.sections["identity"]["signature"] == "dds"


def test_identity_reports_7z_archive_signature_for_disguised_dat(tmp_path):
    target = tmp_path / "script.dat"
    source = tmp_path / "hello.txt"
    source.write_text("hello", encoding="utf-8")
    with py7zr.SevenZipFile(target, "w") as archive:
        archive.write(source, arcname="hello.txt")

    report = AnalysisEngine().analyze(target)

    assert report.sections["identity"]["signature"] == "7zip"
    assert report.sections["archive"]["type"] == "7z"
    assert report.sections["archive"]["listing_status"] == "listed"
    assert report.sections["archive"]["member_count"] == 1
    assert report.sections["archive"]["members"][0]["path"] == "hello.txt"


def test_identity_reports_password_required_7z_archive(tmp_path):
    target = tmp_path / "script.dat"
    source = tmp_path / "hello.txt"
    source.write_text("hello", encoding="utf-8")
    with py7zr.SevenZipFile(target, "w", password="secret", header_encryption=True) as archive:
        archive.write(source, arcname="hello.txt")

    report = AnalysisEngine().analyze(target)

    archive = report.sections["archive"]
    assert report.sections["identity"]["signature"] == "7zip"
    assert archive["listing_status"] == "password-required"
    assert archive["encrypted"] is True
    assert archive["listing_tool"] == "py7zr"
    assert archive["coder_stack"][0]["method_name"] == "7zAES"
    assert "archive:encrypted" in report.summary["tags"]
    assert "archive-status:password-required" in report.summary["tags"]
    assert any(finding.title == "Encrypted 7z archive detected" for finding in report.findings)


def test_parse_7z_listing_extracts_member_metadata():
    output = """
7-Zip 24.09

----------
Path = scripts/main.lua
Size = 12
Packed Size = 8
Attributes = A_ -rw-r--r--
Encrypted = -
Method = LZMA2:12

Path = scripts
Size = 0
Packed Size = 0
Folder = +
Attributes = D_ -rw-r--r--
"""

    entries = _parse_7z_listing(output)

    assert entries[0]["path"] == "scripts/main.lua"
    assert entries[0]["size_bytes"] == 12
    assert entries[0]["is_directory"] is False
    assert entries[1]["path"] == "scripts"
    assert entries[1]["is_directory"] is True


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
