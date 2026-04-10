from __future__ import annotations

import struct

from reverser.analysis.orchestrator import AnalysisEngine


def _minimal_macho64_bytes() -> bytes:
    data = bytearray(128)
    struct.pack_into(">I", data, 0, 0xFEEDFACF)
    struct.pack_into(">iiiiiii", data, 4, 0x01000007, 3, 2, 1, 24, 0x2000, 0)
    struct.pack_into(">II", data, 32, 0x1B, 24)
    return bytes(data)


def test_macho_analyzer_parses_basic_headers(tmp_path):
    target = tmp_path / "sample.macho"
    target.write_bytes(_minimal_macho64_bytes())

    report = AnalysisEngine().analyze(target)

    macho = report.sections["macho"]
    assert macho["format"] == "mach-o-64"
    assert macho["cpu_type"] == "x64"
    assert macho["file_type"] == "executable"
