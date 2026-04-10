from __future__ import annotations

from reverser.analysis.orchestrator import AnalysisEngine


def test_directory_inventory_collects_entrypoints_and_containers(tmp_path):
    (tmp_path / "Game-Win64-Shipping.exe").write_bytes(b"MZ" + b"\x00" * 128)
    (tmp_path / "pakchunk0-Windows.pak").write_bytes(b"demo")
    (tmp_path / "settings.ini").write_text("[demo]\n", encoding="utf-8")

    report = AnalysisEngine().analyze(tmp_path)

    inventory = report.sections["directory_inventory"]
    assert inventory["executable_count"] == 1
    assert inventory["game_container_count"] == 1
    assert inventory["config_count"] == 1
    assert inventory["entrypoint_candidates"]
