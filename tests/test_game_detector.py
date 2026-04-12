from __future__ import annotations

from reverser.analysis.orchestrator import AnalysisEngine


def test_game_detector_finds_unity_directory(tmp_path):
    (tmp_path / "UnityPlayer.dll").write_bytes(b"demo")
    (tmp_path / "Example_Data").mkdir()

    report = AnalysisEngine().analyze(tmp_path)

    engines = report.sections["game_fingerprint"]["engines"]
    assert any(item["engine"] == "Unity" for item in engines)


def test_game_detector_finds_unreal_extension(tmp_path):
    target = tmp_path / "pakchunk0-Windows.pak"
    target.write_bytes(b"demo")

    report = AnalysisEngine().analyze(target)

    engines = report.sections["game_fingerprint"]["engines"]
    assert any(item["engine"] == "Unreal Engine" for item in engines)


def test_game_detector_does_not_treat_chromium_paks_as_unreal(tmp_path):
    patched = tmp_path / "patched"
    locales = patched / "locales"
    locales.mkdir(parents=True)
    (patched / "resources.pak").write_bytes(b"demo")
    (patched / "chrome_100_percent.pak").write_bytes(b"demo")
    (locales / "en-US.pak").write_bytes(b"demo")

    report = AnalysisEngine().analyze(tmp_path)

    assert "game_fingerprint" not in report.sections
