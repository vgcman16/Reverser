from __future__ import annotations

from reverser.analysis.orchestrator import AnalysisEngine


def _build_pul_bytes(animation_path: str = "ani\\room.ani") -> bytes:
    payload = bytearray(256)
    payload[:8] = b"PUZZLE2\x00"
    encoded_path = animation_path.encode("utf-8")
    payload[8 : 8 + len(encoded_path)] = encoded_path
    return bytes(payload)


def _build_pux_bytes() -> bytes:
    payload = bytearray(256)
    payload[:10] = b"TqTerrain\x00"
    payload[0x10:0x14] = (1000).to_bytes(4, "little")
    payload[0x14:0x18] = (40).to_bytes(4, "little")
    payload[0x18:0x1C] = (30).to_bytes(4, "little")
    payload[0x1C:0x20] = (1000).to_bytes(4, "little")
    payload[0x20:0x24] = (722069).to_bytes(4, "little")
    strings = b"ANI\\ZF.ANI\x00Puzzle0\x00ANI\\ZF.ANI\x00Puzzle1\x00"
    payload[0x30 : 0x30 + len(strings)] = strings
    return bytes(payload)


def test_conquer_puzzle_analyzer_parses_pul_file(tmp_path):
    root = tmp_path / "Conquer"
    puzzle_root = root / "map" / "puzzle"
    ani_root = root / "ani"
    puzzle_root.mkdir(parents=True)
    ani_root.mkdir(parents=True)
    target = puzzle_root / "arena.pul"
    target.write_bytes(_build_pul_bytes())
    (ani_root / "room.ani").write_text(
        "[Puzzle0]\nFrameAmount=1\nFrame0=data/map/puzzle/room/arena/arena000.dds\n",
        encoding="utf-8",
    )

    report = AnalysisEngine().analyze(target)

    section = report.sections["conquer_puzzle"]
    assert section["resource_kind"] == "pul"
    assert section["signature"] == "PUZZLE2"
    assert section["animation_path"] == "ani\\room.ani"
    assert section["referenced_animation"]["exists"] is True
    assert section["referenced_animation"]["summary"]["resource_kind"] == "ani"
    assert report.sections["identity"]["signature"] == "conquer-pul"
    assert "conquer:pul" in report.summary["tags"]


def test_conquer_puzzle_analyzer_parses_pux_file(tmp_path):
    root = tmp_path / "Conquer"
    puzzle_root = root / "map" / "PuzzleSave"
    ani_root = root / "ani"
    puzzle_root.mkdir(parents=True)
    ani_root.mkdir(parents=True)
    target = puzzle_root / "arena.pux"
    target.write_bytes(_build_pux_bytes())
    (ani_root / "ZF.ANI").write_text(
        "[Puzzle0]\nFrameAmount=1\nFrame0=data/map/puzzle/oubliette/floor01/mix/oub01-001.dds\n",
        encoding="utf-8",
    )

    report = AnalysisEngine().analyze(target)

    section = report.sections["conquer_puzzle"]
    assert section["resource_kind"] == "pux"
    assert section["signature"] == "TqTerrain"
    assert section["animation_path_count"] == 1
    assert section["puzzle_label_count"] == 2
    assert section["max_puzzle_index"] == 1
    assert section["referenced_animations_sample"][0]["exists"] is True
    assert report.sections["identity"]["signature"] == "conquer-pux"
    assert "conquer:pux" in report.summary["tags"]


def test_conquer_puzzle_analyzer_summarizes_install_directory(tmp_path):
    root = tmp_path / "Conquer"
    (root / "map" / "map").mkdir(parents=True)
    puzzle_root = root / "map" / "puzzle"
    terrain_root = root / "map" / "PuzzleSave"
    puzzle_root.mkdir(parents=True, exist_ok=True)
    terrain_root.mkdir(parents=True, exist_ok=True)
    (puzzle_root / "arena.pul").write_bytes(_build_pul_bytes())
    (terrain_root / "arena.pux").write_bytes(_build_pux_bytes())

    report = AnalysisEngine().analyze(root)

    section = report.sections["conquer_puzzle"]
    assert section["resource_kind"] == "puzzle-directory"
    assert section["pul_count"] == 1
    assert section["pux_count"] == 1
    assert section["pul_sample"] == ["map/puzzle/arena.pul"]
    assert section["pux_sample"] == ["map/PuzzleSave/arena.pux"]
