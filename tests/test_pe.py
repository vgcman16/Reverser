from __future__ import annotations

import struct

from reverser.analysis.pe_direct_calls import find_pe_direct_calls
from reverser.analysis.orchestrator import AnalysisEngine


def _minimal_pe_bytes() -> bytes:
    data = bytearray(2048)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    coff_offset = 0x84
    struct.pack_into("<HHIIIHH", data, coff_offset, 0x8664, 1, 0, 0, 0, 0xF0, 0x2022)
    optional_offset = coff_offset + 20
    struct.pack_into("<H", data, optional_offset, 0x20B)
    struct.pack_into("<I", data, optional_offset + 16, 0x1000)
    struct.pack_into("<Q", data, optional_offset + 24, 0x140000000)
    struct.pack_into("<H", data, optional_offset + 68, 2)
    struct.pack_into("<I", data, optional_offset + 108, 16)
    section_offset = optional_offset + 0xF0
    data[section_offset : section_offset + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIIIIIHHI", data, section_offset + 8, 0x200, 0x1000, 0x200, 0x400, 0, 0, 0, 0, 0x60000020)
    for index in range(0x400, 0x600):
        data[index] = 0x90
    return bytes(data)


def test_pe_analyzer_parses_headers(tmp_path):
    target = tmp_path / "sample.exe"
    target.write_bytes(_minimal_pe_bytes())

    report = AnalysisEngine().analyze(target)

    pe = report.sections["pe"]
    assert pe["machine"] == "x64"
    assert pe["format"] == "pe32+"
    assert pe["section_count"] == 1
    assert pe["sections"][0]["name"] == ".text"


def test_pe_direct_calls_finds_rel32_target(tmp_path):
    data = bytearray(_minimal_pe_bytes())
    image_base = 0x140000000
    callsite_va = image_base + 0x1000
    target_va = image_base + 0x1100
    rel32 = target_va - (callsite_va + 5)
    data[0x400] = 0xE8
    struct.pack_into("<i", data, 0x401, rel32)
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    payload = find_pe_direct_calls(target, [hex(target_va)])

    result = payload["results"][0]
    assert result["hit_count"] == 1
    assert result["calls"][0]["callsite_va"] == hex(callsite_va)
