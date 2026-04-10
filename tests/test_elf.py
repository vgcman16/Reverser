from __future__ import annotations

import struct

from reverser.analysis.orchestrator import AnalysisEngine


def _minimal_elf64_bytes() -> bytes:
    data = bytearray(128)
    data[0:4] = b"\x7fELF"
    data[4] = 2  # 64-bit
    data[5] = 1  # little-endian
    data[6] = 1  # version
    data[7] = 3  # linux
    struct.pack_into("<HHIQQQIHHHHHH", data, 16, 2, 0x3E, 1, 0x401000, 64, 0, 0, 64, 56, 1, 64, 0, 0)
    return bytes(data)


def test_elf_analyzer_parses_basic_headers(tmp_path):
    target = tmp_path / "sample.elf"
    target.write_bytes(_minimal_elf64_bytes())

    report = AnalysisEngine().analyze(target)

    elf = report.sections["elf"]
    assert elf["class"] == "elf64"
    assert elf["machine"] == "x64"
    assert elf["type"] == "executable"
