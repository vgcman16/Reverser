from __future__ import annotations

from reverser.analysis.scan import scan_tree


def test_scan_tree_collects_reports_and_skips_large_files(tmp_path):
    root = tmp_path / "install"
    root.mkdir()
    (root / "Game.exe").write_bytes(b"MZ" + b"\x00" * 256)
    (root / "archive.zip").write_bytes(b"PK\x03\x04")
    (root / "big.pak").write_bytes(b"A" * 2048)

    index = scan_tree(root, max_files=10, max_file_bytes=1024)

    assert index.summary["entry_count"] == 2
    assert index.summary["skipped_count"] >= 1
    assert any(entry.signature == "portable-executable" for entry in index.entries)


def test_scan_tree_root_summary_includes_directory_inventory(tmp_path):
    root = tmp_path / "install"
    root.mkdir()
    (root / "Game.exe").write_bytes(b"MZ" + b"\x00" * 256)
    (root / "data.pak").write_bytes(b"demo")

    index = scan_tree(root)

    assert "directory_inventory" in index.root_summary["sections"]


def test_scan_tree_skips_common_noise_and_honors_globs(tmp_path):
    root = tmp_path / "install"
    root.mkdir()
    pycache = root / "__pycache__"
    pycache.mkdir()
    (pycache / "noise.pyc").write_bytes(b"noise")
    hidden_catalog = root / ".reverser"
    hidden_catalog.mkdir()
    (hidden_catalog / "catalog.sqlite3").write_bytes(b"noise")
    (root / "Game.exe").write_bytes(b"MZ" + b"\x00" * 256)
    (root / "notes.txt").write_text("hello", encoding="utf-8")

    index = scan_tree(root, include_globs=["*.exe"])

    assert index.summary["entry_count"] == 1
    assert index.entries[0].relative_path == "Game.exe"
