from __future__ import annotations

from reverser.analysis.orchestrator import AnalysisEngine


def test_strings_extract_ascii_and_utf16(tmp_path):
    target = tmp_path / "strings.bin"
    target.write_bytes(
        b"AAAAhttp://example.com/path BBBB "
        + "C:\\Games\\Example".encode("ascii")
        + b"\x00\x00"
        + "HELLO".encode("utf-16le")
    )

    report = AnalysisEngine(max_strings=50).analyze(target)

    strings = report.sections["strings"]
    assert any("http://example.com/path" in item for item in strings["sample"])
    assert strings["urls"]
    assert strings["paths"]
