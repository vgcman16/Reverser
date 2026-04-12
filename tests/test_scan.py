from __future__ import annotations

import json
import os
import sqlite3
import struct

from reverser.analysis.scan import scan_tree
from tests.helpers_netdragon import build_netdragon_pair


def _minimal_pe_bytes() -> bytes:
    data = bytearray(2048)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    coff_offset = 0x84
    struct.pack_into("<HHIIIHH", data, coff_offset, 0x14C, 1, 0, 0, 0, 0xE0, 0x2022)
    optional_offset = coff_offset + 20
    struct.pack_into("<H", data, optional_offset, 0x10B)
    struct.pack_into("<I", data, optional_offset + 16, 0x1000)
    struct.pack_into("<I", data, optional_offset + 28, 0x400000)
    struct.pack_into("<H", data, optional_offset + 68, 2)
    struct.pack_into("<I", data, optional_offset + 92, 16)
    section_offset = optional_offset + 0xE0
    data[section_offset : section_offset + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIIIIIHHI", data, section_offset + 8, 0x200, 0x1000, 0x200, 0x400, 0, 0, 0, 0, 0x60000020)
    for index in range(0x400, 0x600):
        data[index] = 0x90
    return bytes(data)


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


def test_scan_tree_carries_js5_metadata(tmp_path):
    root = tmp_path / "OpenNXT"
    cache_dir = root / "data" / "cache"
    cache_dir.mkdir(parents=True)
    target = cache_dir / "js5-17.jcache"

    mapping_path = root / "data" / "prot" / "947" / "generated" / "shared" / "js5-archive-resolution.json"
    mapping_path.parent.mkdir(parents=True, exist_ok=True)
    mapping_path.write_text(json.dumps({"build": 947, "indexNames": {"17": "CONFIG_ENUM"}}), encoding="utf-8")

    with sqlite3.connect(target) as connection:
        connection.execute("CREATE TABLE cache (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute("CREATE TABLE cache_index (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute("INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (1, ?, 1, 2)", (b"\x00\x00\x00\x00\x04demo\x00\x01",))
        connection.commit()

    index = scan_tree(root, max_files=5)

    assert index.summary["entry_count"] >= 1
    entry = next(item for item in index.entries if item.relative_path.endswith("js5-17.jcache"))
    assert entry.signature == "sqlite"
    assert entry.js5_archive_id == 17
    assert entry.js5_index_name == "CONFIG_ENUM"
    assert entry.js5_store_kind == "js5"


def test_scan_tree_prefers_larger_jcache_when_scores_tie(tmp_path):
    root = tmp_path / "OpenNXT"
    cache_dir = root / "data" / "cache"
    cache_dir.mkdir(parents=True)

    small = cache_dir / "js5-0.jcache"
    large = cache_dir / "js5-17.jcache"

    for path in (small, large):
        with sqlite3.connect(path) as connection:
            connection.execute("CREATE TABLE cache (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
            connection.execute("CREATE TABLE cache_index (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
            connection.commit()

    with sqlite3.connect(large) as connection:
        for key in range(1, 33):
            payload = b"\x00" + (1024).to_bytes(4, "big") + (b"A" * 1024) + b"\x00\x01"
            connection.execute("INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, 1, 2)", (key, payload))
        connection.commit()

    index = scan_tree(root, max_files=1)

    assert index.summary["entry_count"] == 1
    assert index.entries[0].relative_path == "data\\cache\\js5-17.jcache"


def test_scan_tree_includes_oversized_jcache_as_metadata(tmp_path):
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    target = cache_dir / "js5-17.jcache"

    with sqlite3.connect(target) as connection:
        connection.execute("CREATE TABLE cache (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute("CREATE TABLE cache_index (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        for key in range(1, 9):
            payload = b"\x00" + (512).to_bytes(4, "big") + (b"A" * 512) + b"\x00\x01"
            connection.execute("INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, 1, 2)", (key, payload))
        connection.commit()

    index = scan_tree(cache_dir, max_files=5, max_file_bytes=1024)

    assert index.summary["entry_count"] == 1
    assert index.summary["skipped_count"] == 0
    assert index.entries[0].relative_path == "js5-17.jcache"
    assert "js5_cache_directory" in index.root_summary["sections"]


def test_scan_tree_includes_oversized_netdragon_package_as_metadata(tmp_path):
    root = tmp_path / "install"
    root.mkdir()
    build_netdragon_pair(root, entries=[("data/blob.bin", os.urandom(2048))])

    index = scan_tree(root, max_files=5, max_file_bytes=1024)

    assert index.summary["skipped_count"] == 0
    assert any(entry.relative_path == "data.tpd" for entry in index.entries)
    assert any(entry.relative_path == "data.tpi" for entry in index.entries)


def test_scan_tree_root_summary_includes_conquer_puzzle_directory(tmp_path):
    root = tmp_path / "Conquer"
    (root / "map" / "map").mkdir(parents=True)
    puzzle_root = root / "map" / "puzzle"
    puzzle_root.mkdir(parents=True, exist_ok=True)
    (puzzle_root / "arena.pul").write_bytes(b"PUZZLE2\x00ani\\room.ani\x00")

    index = scan_tree(root, max_files=5)

    assert "conquer_puzzle" in index.root_summary["sections"]


def test_scan_tree_root_summary_includes_conquer_animation_directory(tmp_path):
    root = tmp_path / "Conquer"
    (root / "map" / "map").mkdir(parents=True)
    ani_root = root / "ani"
    ani_root.mkdir(parents=True, exist_ok=True)
    (ani_root / "room.ani").write_text("[Puzzle0]\nFrameAmount=1\nFrame0=data/map/puzzle/room/arena/arena000.dds\n", encoding="utf-8")

    index = scan_tree(root, max_files=5)

    assert "conquer_animation" in index.root_summary["sections"]


def test_scan_tree_root_summary_includes_conquer_c3_directory(tmp_path):
    root = tmp_path / "Conquer"
    ini_root = root / "ini"
    ini_root.mkdir(parents=True)
    (ini_root / "3DEffectObj.ini").write_text("1=C3/Effect/LevelUp/1.C3\n", encoding="utf-8")
    build_netdragon_pair(
        root,
        stem="c3",
        entries=[("c3/effect/levelup/1.c3", b"MAXFILE C3 00001PTC3" + b"\x04\x00\x00\x00" + b"\x04\x00\x00\x00demo" + b"STEP\x04\x00\x00\x00\x00\x00\x00\x00")],
    )

    index = scan_tree(root, max_files=5)

    assert "conquer_c3" in index.root_summary["sections"]


def test_scan_tree_root_summary_includes_conquer_client_directory(tmp_path):
    root = tmp_path / "Conquer"
    root.mkdir()
    (root / "Play.exe").write_bytes(_minimal_pe_bytes())
    (root / "AutoPatch.exe").write_bytes(_minimal_pe_bytes())
    (root / "Conquer.exe").write_text("Click on Play.exe to log into the game.", encoding="utf-8")
    (root / "ini").mkdir()

    index = scan_tree(root, max_files=5)

    assert "conquer_client" in index.root_summary["sections"]
