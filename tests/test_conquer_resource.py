from __future__ import annotations

from reverser.analysis.orchestrator import AnalysisEngine


def test_conquer_resource_analyzer_summarizes_luacfg_install(tmp_path):
    root = tmp_path / "Conquer"
    luacfg = root / "ini" / "luacfg"
    luacfg.mkdir(parents=True)
    (root / "Conquer.exe").write_bytes(b"MZ" + b"\x00" * 128)
    (root / "ini" / "Server_Key.lua").write_text("return 'plaintext'\n", encoding="utf-8")
    (root / "ini" / "OnlyLua.lua").write_text("return 'lua only'\n", encoding="utf-8")
    (luacfg / "Server_Key.dat").write_bytes(bytes(range(64)))
    (luacfg / "OnlyDat.dat").write_bytes(bytes(range(32)))
    (root / "script.dat").write_bytes(b"7z\xbc\xaf\x27\x1c" + b"\x00" * 64)

    report = AnalysisEngine().analyze(root)

    section = report.sections["conquer_resource"]
    assert section["scope"] == "install"
    assert section["luacfg_dat_count"] == 2
    assert section["plaintext_lua_count"] == 2
    assert section["mirrored_pair_count"] == 1
    assert section["dat_only_count"] == 1
    assert section["lua_only_count"] == 1
    assert section["script_archives"][0]["relative_path"] == "script.dat"
    assert section["script_archives"][0]["looks_like_7z_archive"] is True
    assert "game:conquer-online" in report.summary["tags"]
    assert "format:conquer-resource" in report.summary["tags"]
    assert any(finding.title == "Conquer luacfg resources detected" for finding in report.findings)


def test_conquer_resource_analyzer_maps_plaintext_mirror_for_luacfg_file(tmp_path):
    root = tmp_path / "Conquer"
    luacfg = root / "ini" / "luacfg"
    luacfg.mkdir(parents=True)
    target = luacfg / "Server_Key.dat"
    (root / "ini" / "Server_Key.lua").write_text("return 'plaintext'\n", encoding="utf-8")
    target.write_bytes(bytes(range(64)))

    report = AnalysisEngine().analyze(target)

    section = report.sections["conquer_resource"]
    assert section["scope"] == "file"
    assert section["resource_kind"] == "luacfg-dat"
    assert section["plaintext_mirror_exists"] is True
    assert section["plaintext_mirror_relative_path"] == "ini/Server_Key.lua"
    assert "conquer:luacfg-dat" in report.summary["tags"]
    assert any(finding.title == "Conquer encrypted Lua/config resource detected" for finding in report.findings)
