from __future__ import annotations

from reverser.analysis.orchestrator import AnalysisEngine


def _build_dds_bytes(*, width: int = 1, height: int = 1, fourcc: bytes = b"DXT1", mipmap_count: int = 1) -> bytes:
    payload = bytearray(128)
    payload[:4] = b"DDS "
    payload[4:8] = (124).to_bytes(4, "little")
    payload[8:12] = (0x1007).to_bytes(4, "little")
    payload[12:16] = height.to_bytes(4, "little")
    payload[16:20] = width.to_bytes(4, "little")
    payload[20:24] = (8).to_bytes(4, "little")
    payload[28:32] = mipmap_count.to_bytes(4, "little")
    payload[76:80] = (32).to_bytes(4, "little")
    payload[80:84] = (0x4).to_bytes(4, "little")
    payload[84:88] = fourcc
    payload[108:112] = (0x1000).to_bytes(4, "little")
    return bytes(payload)


def test_dds_analyzer_parses_dds_file(tmp_path):
    target = tmp_path / "arena000.dds"
    target.write_bytes(_build_dds_bytes(width=128, height=64, mipmap_count=4))

    report = AnalysisEngine().analyze(target)

    section = report.sections["dds"]
    assert section["width"] == 128
    assert section["height"] == 64
    assert section["fourcc"] == "DXT1"
    assert section["mipmap_count"] == 4
    assert "format:dds" in report.summary["tags"]
