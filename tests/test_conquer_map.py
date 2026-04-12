from __future__ import annotations

import py7zr

from reverser.analysis.orchestrator import AnalysisEngine


def _build_dmap_bytes(*, version: int = 1004, asset_path: str = "map\\puzzle\\arena.pul", grid_width: int = 96, grid_height: int = 96) -> bytes:
    payload = bytearray(0x118)
    payload[0:4] = version.to_bytes(4, "little")
    encoded_path = asset_path.encode("utf-8")
    payload[8 : 8 + len(encoded_path)] = encoded_path
    payload[0x108:0x10C] = (65536).to_bytes(4, "little")
    payload[0x10C:0x110] = grid_width.to_bytes(4, "little")
    payload[0x110:0x114] = grid_height.to_bytes(4, "little")
    payload[0x114:0x118] = (1).to_bytes(4, "little")
    return bytes(payload)


def test_conquer_map_analyzer_parses_dmap_file(tmp_path):
    root = tmp_path / "Conquer"
    map_root = root / "map" / "map"
    puzzle_root = root / "map" / "puzzle"
    map_root.mkdir(parents=True)
    puzzle_root.mkdir(parents=True)
    target = map_root / "arena.DMap"
    target.write_bytes(_build_dmap_bytes())
    (puzzle_root / "arena.pul").write_bytes(b"PUZZLE2\x00ani\\room.ani\x00")

    report = AnalysisEngine().analyze(target)

    section = report.sections["conquer_map"]
    assert section["resource_kind"] == "dmap"
    assert section["version"] == 1004
    assert section["asset_path"] == "map\\puzzle\\arena.pul"
    assert section["grid_width"] == 96
    assert section["grid_height"] == 96
    assert section["referenced_asset"]["exists"] is True
    assert section["referenced_asset"]["summary"]["resource_kind"] == "pul"
    assert "conquer:dmap" in report.summary["tags"]


def test_conquer_map_analyzer_parses_otherdata_file(tmp_path):
    root = tmp_path / "Conquer"
    map_root = root / "map" / "map"
    map_root.mkdir(parents=True)
    target = map_root / "arena.OtherData"
    target.write_text(
        "[Header]\nSenceLayerAmount=0\nTerrainLayerAmount=1\nInteractiveLayerAmount=1\n\n[TerrainLayer0]\nMapObjAmount=12\n",
        encoding="utf-8",
    )

    report = AnalysisEngine().analyze(target)

    section = report.sections["conquer_map"]
    assert section["resource_kind"] == "otherdata"
    assert section["section_count"] == 2
    assert section["map_obj_total"] == 12
    assert section["header"]["TerrainLayerAmount"] == "1"
    assert "conquer:otherdata" in report.summary["tags"]


def test_conquer_map_analyzer_parses_map_archive_file(tmp_path):
    root = tmp_path / "Conquer"
    map_root = root / "map" / "map"
    puzzle_root = root / "map" / "puzzle"
    map_root.mkdir(parents=True)
    puzzle_root.mkdir(parents=True)
    target = map_root / "arena.7z"
    source = tmp_path / "arena.DMap"
    source.write_bytes(_build_dmap_bytes())
    (puzzle_root / "arena.pul").write_bytes(b"PUZZLE2\x00ani\\room.ani\x00")
    with py7zr.SevenZipFile(target, "w") as archive:
        archive.write(source, arcname="arena.DMap")

    report = AnalysisEngine().analyze(target)

    section = report.sections["conquer_map"]
    assert section["resource_kind"] == "map-archive"
    assert section["member_count"] == 1
    assert section["dmap"]["asset_path"] == "map\\puzzle\\arena.pul"
    assert section["dmap"]["grid_width"] == 96
    assert section["referenced_asset"]["exists"] is True
    assert "conquer:map-archive" in report.summary["tags"]


def test_conquer_map_analyzer_summarizes_map_directory(tmp_path):
    root = tmp_path / "Conquer"
    map_root = root / "map" / "map"
    map_root.mkdir(parents=True)
    source = tmp_path / "arena.DMap"
    source.write_bytes(_build_dmap_bytes())
    with py7zr.SevenZipFile(map_root / "arena.7z", "w") as archive:
        archive.write(source, arcname="arena.DMap")
    (map_root / "arena.OtherData").write_text("[Header]\nTerrainLayerAmount=1\n", encoding="utf-8")

    report = AnalysisEngine().analyze(root)

    section = report.sections["conquer_map"]
    assert section["resource_kind"] == "map-directory"
    assert section["archive_count"] == 1
    assert section["otherdata_count"] == 1
    assert section["paired_archive_count"] == 1
    assert section["paired_archive_sample"][0]["archive"] == "arena.7z"
