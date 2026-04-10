from __future__ import annotations

from reverser.analysis.orchestrator import AnalysisEngine


def test_directory_inventory_collects_entrypoints_and_containers(tmp_path):
    (tmp_path / "Game-Win64-Shipping.exe").write_bytes(b"MZ" + b"\x00" * 128)
    (tmp_path / "pakchunk0-Windows.pak").write_bytes(b"demo")
    (tmp_path / "js5-17.jcache").write_bytes(b"SQLite format 3\x00" + b"\x00" * 128)
    (tmp_path / "settings.ini").write_text("[demo]\n", encoding="utf-8")

    report = AnalysisEngine().analyze(tmp_path)

    inventory = report.sections["directory_inventory"]
    assert inventory["executable_count"] == 1
    assert inventory["game_container_count"] == 1
    assert inventory["js5_cache_count"] == 1
    assert inventory["config_count"] == 1
    assert inventory["entrypoint_candidates"]


def test_directory_inventory_separates_chromium_resource_packs(tmp_path):
    locales = tmp_path / "locales"
    locales.mkdir()
    (tmp_path / "resources.pak").write_bytes(b"demo")
    (tmp_path / "pakchunk0-Windows.pak").write_bytes(b"demo")
    (locales / "en-US.pak").write_bytes(b"demo")

    report = AnalysisEngine().analyze(tmp_path)

    inventory = report.sections["directory_inventory"]
    assert inventory["game_container_count"] == 1
    assert inventory["resource_pack_count"] == 2
    assert "pakchunk0-Windows.pak" in inventory["game_containers"]
    assert "resources.pak" in inventory["resource_packs"]
