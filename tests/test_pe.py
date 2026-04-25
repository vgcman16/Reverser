from __future__ import annotations

import struct

from reverser.analysis.pe_address_refs import find_pe_address_refs
from reverser.analysis.pe_direct_calls import find_pe_direct_calls
from reverser.analysis.pe_function_calls import find_pe_function_calls
from reverser.analysis.pe_function_literals import find_pe_function_literals
from reverser.analysis.pe_imports import read_pe_imports
from reverser.analysis.pe_instructions import find_pe_instructions
from reverser.analysis.pe_provider_descriptors import (
    compact_provider_descriptor_clusters,
    provider_descriptor_cluster_rows,
    provider_descriptor_cluster_literal_payload,
    scan_pe_provider_descriptors,
    summarize_pe_provider_descriptors,
)
from reverser.analysis.pe_qwords import read_pe_qwords
from reverser.analysis.pe_rtti import read_pe_rtti_type_descriptors
from reverser.analysis.pe_runtime_functions import find_pe_runtime_functions
from reverser.cli.main import main
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


def _minimal_pe_with_data_bytes() -> bytes:
    data = bytearray(4096)
    data[: len(_minimal_pe_bytes())] = _minimal_pe_bytes()
    struct.pack_into("<H", data, 0x84 + 2, 2)
    optional_offset = 0x84 + 20
    section_offset = optional_offset + 0xF0
    data[section_offset + 40 : section_offset + 48] = b".data\x00\x00\x00"
    struct.pack_into(
        "<IIIIIIHHI",
        data,
        section_offset + 48,
        0x200,
        0x3000,
        0x200,
        0x800,
        0,
        0,
        0,
        0,
        0xC0000040,
    )
    return bytes(data)


def _minimal_pe_with_pdata_bytes() -> bytes:
    data = bytearray(_minimal_pe_with_data_bytes())
    struct.pack_into("<H", data, 0x84 + 2, 3)
    optional_offset = 0x84 + 20
    section_offset = optional_offset + 0xF0
    pdata_section_offset = section_offset + 80
    data[pdata_section_offset : pdata_section_offset + 8] = b".pdata\x00\x00"
    struct.pack_into(
        "<IIIIIIHHI",
        data,
        pdata_section_offset + 8,
        0x200,
        0x5000,
        0x200,
        0xA00,
        0,
        0,
        0,
        0,
        0x40000040,
    )
    struct.pack_into("<III", data, 0xA00, 0x1000, 0x1080, 0x3000)
    return bytes(data)


def _minimal_pe_with_import_bytes() -> bytes:
    data = bytearray(_minimal_pe_with_pdata_bytes())
    optional_offset = 0x84 + 20
    struct.pack_into("<II", data, optional_offset + 112 + 8, 0x3000, 0x28)

    descriptor_offset = 0x800
    struct.pack_into("<IIIII", data, descriptor_offset, 0x3040, 0, 0, 0x3060, 0x3050)
    data[0x860 : 0x86D] = b"kernel32.dll\x00"
    struct.pack_into("<Q", data, 0x840, 0x3070)
    struct.pack_into("<Q", data, 0x848, 0)
    struct.pack_into("<Q", data, 0x850, 0x3070)
    struct.pack_into("<Q", data, 0x858, 0)
    struct.pack_into("<H", data, 0x870, 0)
    data[0x872 : 0x887] = b"EnterCriticalSection\x00"
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
    data = bytearray(_minimal_pe_with_pdata_bytes())
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
    assert result["calls"][0]["function"]["start_va"] == hex(image_base + 0x1000)
    assert payload["scan"]["runtime_function_count"] == 1


def test_pe_address_refs_finds_qword_and_rip_relative_refs(tmp_path):
    data = bytearray(_minimal_pe_with_pdata_bytes())
    image_base = 0x140000000
    target_va = image_base + 0x3000
    qword_ref_va = image_base + 0x3080
    lea_ref_va = image_base + 0x1030

    struct.pack_into("<Q", data, 0x880, target_va)
    lea_offset = 0x400 + 0x30
    data[lea_offset : lea_offset + 3] = b"\x48\x8d\x05"
    struct.pack_into("<i", data, lea_offset + 3, target_va - (lea_ref_va + 7))

    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    payload = find_pe_address_refs(target, [hex(target_va)], max_hits_per_target=8)

    result = payload["results"][0]
    kinds = {hit["kind"] for hit in result["hits"]}
    assert payload["type"] == "pe-address-refs"
    assert result["hit_count"] == 2
    assert "absolute-qword" in kinds
    assert "rip-relative-lea" in kinds
    assert any(hit["reference_va"] == hex(qword_ref_va) for hit in result["hits"])
    lea_hit = next(hit for hit in result["hits"] if hit["reference_va"] == hex(lea_ref_va))
    assert lea_hit["function"]["start_va"] == hex(image_base + 0x1000)
    assert lea_hit["function"]["end_va"] == hex(image_base + 0x1080)
    assert payload["scan"]["runtime_function_count"] == 1


def test_pe_address_refs_finds_locked_cmpxchg_rip_relative_refs(tmp_path):
    data = bytearray(_minimal_pe_with_pdata_bytes())
    image_base = 0x140000000
    target_va = image_base + 0x3000
    cmpxchg_ref_va = image_base + 0x1030

    cmpxchg_offset = 0x400 + 0x30
    data[cmpxchg_offset : cmpxchg_offset + 5] = b"\xf0\x48\x0f\xb1\x0d"
    struct.pack_into("<i", data, cmpxchg_offset + 5, target_va - (cmpxchg_ref_va + 9))
    lock_lea_ref_va = image_base + 0x1040
    lock_lea_offset = 0x400 + 0x40
    data[lock_lea_offset : lock_lea_offset + 4] = b"\xf0\x48\x8d\x05"
    struct.pack_into("<i", data, lock_lea_offset + 4, target_va - (lock_lea_ref_va + 8))
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    payload = find_pe_address_refs(target, [hex(target_va)], max_hits_per_target=8)

    result = payload["results"][0]
    assert result["hit_count"] == 1
    hit = result["hits"][0]
    assert hit["kind"] == "rip-relative-cmpxchg-lock"
    assert hit["reference_va"] == hex(cmpxchg_ref_va)
    assert hit["target_va"] == hex(target_va)
    assert hit["lock_prefix"] is True
    assert hit["opcode2"] == "0xb1"


def test_cli_pe_address_refs_outputs_json(tmp_path, capsys):
    data = bytearray(_minimal_pe_with_data_bytes())
    image_base = 0x140000000
    target_va = image_base + 0x3000
    struct.pack_into("<Q", data, 0x880, target_va)
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    exit_code = main(["pe-address-refs", str(target), hex(target_va), "--max-hits-per-target", "2"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert '"type": "pe-address-refs"' in captured.out


def test_pe_imports_reports_iat_entries(tmp_path):
    target = tmp_path / "sample.exe"
    target.write_bytes(_minimal_pe_with_import_bytes())

    payload = read_pe_imports(target)

    assert payload["type"] == "pe-imports"
    assert payload["scan"]["descriptor_count"] == 1
    assert payload["scan"]["imported_function_count"] == 1
    function = payload["imports"][0]["functions"][0]
    assert function["dll"] == "kernel32.dll"
    assert function["name"] == "EnterCriticalSection"
    assert function["display_name"] == "kernel32.dll!EnterCriticalSection"
    assert function["iat_entry_va"] == hex(0x140003050)


def test_cli_pe_imports_outputs_json(tmp_path, capsys):
    target = tmp_path / "sample.exe"
    target.write_bytes(_minimal_pe_with_import_bytes())

    exit_code = main(["pe-imports", str(target)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert '"type": "pe-imports"' in captured.out
    assert "EnterCriticalSection" in captured.out


def test_pe_function_literals_finds_rip_relative_strings(tmp_path):
    data = bytearray(_minimal_pe_with_pdata_bytes())
    image_base = 0x140000000
    string_va = image_base + 0x3050
    lea_va = image_base + 0x1030
    data[0x850 : 0x850 + 12] = b"RuneLite\x00xxx"
    lea_offset = 0x400 + 0x30
    data[lea_offset : lea_offset + 3] = b"\x48\x8d\x05"
    struct.pack_into("<i", data, lea_offset + 3, string_va - (lea_va + 7))
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    payload = find_pe_function_literals(target, [f"{hex(image_base + 0x1000)}:{hex(image_base + 0x1080)}"])

    function = payload["functions"][0]
    literal = function["literals"][0]
    assert payload["type"] == "pe-function-literals"
    assert function["literal_hit_count"] == 1
    assert literal["value"] == "RuneLite"
    assert literal["reference_va"] == hex(lea_va)
    assert literal["target_va"] == hex(string_va)


def test_cli_pe_function_literals_outputs_json(tmp_path, capsys):
    data = bytearray(_minimal_pe_with_pdata_bytes())
    image_base = 0x140000000
    string_va = image_base + 0x3050
    lea_va = image_base + 0x1030
    data[0x850 : 0x850 + 10] = b"Config\x00xxx"
    data[0x430 : 0x433] = b"\x48\x8d\x05"
    struct.pack_into("<i", data, 0x433, string_va - (lea_va + 7))
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    exit_code = main(["pe-function-literals", str(target), f"{hex(image_base + 0x1000)}:{hex(image_base + 0x1080)}"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert '"type": "pe-function-literals"' in captured.out
    assert "Config" in captured.out


def test_pe_function_calls_lists_direct_and_indirect_calls(tmp_path):
    data = bytearray(_minimal_pe_with_pdata_bytes())
    image_base = 0x140000000
    direct_call_va = image_base + 0x1000
    target_va = image_base + 0x1060
    rip_call_va = image_base + 0x1008
    pointer_va = image_base + 0x3080

    data[0x400] = 0xE8
    struct.pack_into("<i", data, 0x401, target_va - (direct_call_va + 5))

    data[0x408 : 0x40A] = b"\xff\x15"
    struct.pack_into("<i", data, 0x40A, pointer_va - (rip_call_va + 6))
    struct.pack_into("<Q", data, 0x880, target_va)

    data[0x410 : 0x413] = b"\x41\xff\xd2"
    data[0x418 : 0x41B] = b"\xff\x50\x20"

    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    payload = find_pe_function_calls(target, [f"{hex(image_base + 0x1000)}:{hex(image_base + 0x1080)}"])

    function = payload["functions"][0]
    kinds = [call["kind"] for call in function["calls"]]
    assert payload["type"] == "pe-function-calls"
    assert function["call_hit_count"] == 4
    assert kinds == ["direct-rel32", "indirect-rip-memory", "indirect-register", "indirect-memory"]
    assert function["calls"][0]["target_function"]["start_va"] == hex(image_base + 0x1000)
    assert function["calls"][1]["resolved_pointer_va"] == hex(target_va)
    assert function["calls"][2]["register"] == "R10"
    assert function["calls"][3]["base_register"] == "RAX"
    assert function["calls"][3]["displacement"] == 0x20


def test_pe_function_calls_resolves_iat_import_names(tmp_path):
    data = bytearray(_minimal_pe_with_import_bytes())
    image_base = 0x140000000
    callsite_va = image_base + 0x1000
    iat_entry_va = image_base + 0x3050

    data[0x400 : 0x402] = b"\xff\x15"
    struct.pack_into("<i", data, 0x402, iat_entry_va - (callsite_va + 6))
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    payload = find_pe_function_calls(target, [f"{hex(image_base + 0x1000)}:{hex(image_base + 0x1080)}"])

    call = payload["functions"][0]["calls"][0]
    assert payload["scan"]["import_lookup_count"] == 1
    assert call["kind"] == "indirect-rip-memory"
    assert call["import"]["display_name"] == "kernel32.dll!EnterCriticalSection"
    assert call["import"]["iat_entry_va"] == hex(iat_entry_va)


def test_pe_function_calls_skips_embedded_e8_inside_decoded_instruction(tmp_path):
    data = bytearray(_minimal_pe_with_pdata_bytes())
    image_base = 0x140000000
    # 8b e8 is MOV EBP, EAX. The embedded e8 byte would look like a
    # plausible rel32 CALL if the scanner did not advance by instructions.
    data[0x400 : 0x406] = b"\x8b\xe8\x5a\x00\x00\x00"
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    payload = find_pe_function_calls(target, [f"{hex(image_base + 0x1000)}:{hex(image_base + 0x1008)}"])

    function = payload["functions"][0]
    assert function["call_hit_count"] == 0
    assert function["calls"] == []


def test_cli_pe_function_calls_outputs_json(tmp_path, capsys):
    data = bytearray(_minimal_pe_with_pdata_bytes())
    image_base = 0x140000000
    callsite_va = image_base + 0x1000
    target_va = image_base + 0x1060
    data[0x400] = 0xE8
    struct.pack_into("<i", data, 0x401, target_va - (callsite_va + 5))
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    exit_code = main(["pe-function-calls", str(target), f"{hex(image_base + 0x1000)}:{hex(image_base + 0x1080)}"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert '"type": "pe-function-calls"' in captured.out
    assert hex(target_va) in captured.out


def test_pe_instructions_decodes_common_window_instructions(tmp_path):
    data = bytearray(_minimal_pe_with_pdata_bytes())
    image_base = 0x140000000
    start_va = image_base + 0x1000
    callsite_va = image_base + 0x1004
    target_va = image_base + 0x1060
    data[0x400 : 0x404] = b"\x48\x8b\x41\x10"
    data[0x404] = 0xE8
    struct.pack_into("<i", data, 0x405, target_va - (callsite_va + 5))
    data[0x409 : 0x40E] = b"\x75\x02\xc3\xcc\x90"
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    payload = find_pe_instructions(target, [f"{hex(start_va)}:6"])

    instructions = payload["windows"][0]["instructions"]
    assert payload["type"] == "pe-instructions"
    assert payload["scan"]["decoded_instruction_count"] == 6
    assert instructions[0]["instruction"] == "MOV RAX, [RCX+0x10]"
    assert instructions[0]["length"] == 4
    assert instructions[1]["kind"] == "call"
    assert instructions[1]["target_va"] == hex(target_va)
    assert instructions[2]["instruction"] == f"JNZ {hex(image_base + 0x100d)}"
    assert instructions[3]["kind"] == "return"
    assert instructions[4]["mnemonic"] == "INT3"


def test_pe_instructions_decodes_xorps_and_one_operand_imul(tmp_path):
    data = bytearray(_minimal_pe_with_pdata_bytes())
    image_base = 0x140000000
    start_va = image_base + 0x1000
    data[0x400 : 0x406] = b"\x0f\x57\xc0\x48\xf7\xea"
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    payload = find_pe_instructions(target, [f"{hex(start_va)}:2"])

    instructions = payload["windows"][0]["instructions"]
    assert instructions[0]["instruction"] == "XORPS XMM0, XMM0"
    assert instructions[1]["instruction"] == "IMUL RDX"
    assert all(instruction["kind"] != "unknown" for instruction in instructions)


def test_pe_instructions_decodes_byte_shift_test_and_cmov(tmp_path):
    data = bytearray(_minimal_pe_with_pdata_bytes())
    image_base = 0x140000000
    start_va = image_base + 0x1000
    data[0x400 : 0x411] = b"\xc0\xe8\x07\xa8\x01\xc0\xea\x07\x84\xd2\x49\x0f\x45\xc0\x38\x1c\x29"
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    payload = find_pe_instructions(target, [f"{hex(start_va)}:6"])

    instructions = payload["windows"][0]["instructions"]
    assert [instruction["instruction"] for instruction in instructions] == [
        "SHR AL, 0x7",
        "TEST AL, 0x1",
        "SHR DL, 0x7",
        "TEST DL, DL",
        "CMOVNZ RAX, R8",
        "CMP [RCX+RBP], BL",
    ]
    assert all(instruction["kind"] != "unknown" for instruction in instructions)


def test_pe_instructions_preserves_segment_override_on_memory_operand(tmp_path):
    data = bytearray(_minimal_pe_with_pdata_bytes())
    image_base = 0x140000000
    start_va = image_base + 0x1000
    data[0x400 : 0x409] = b"\x65\x48\x8b\x04\x25\x58\x00\x00\x00"
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    payload = find_pe_instructions(target, [f"{hex(start_va)}:1"])

    instructions = payload["windows"][0]["instructions"]
    assert instructions[0]["instruction"] == "MOV RAX, GS:[0x58]"


def test_pe_instructions_decodes_sbb_movsx_movsxd_setcc_imul_and_accumulator_immediates(tmp_path):
    data = bytearray(_minimal_pe_with_pdata_bytes())
    image_base = 0x140000000
    start_va = image_base + 0x1000
    data[0x400 : 0x42F] = (
        b"\x1b\xc0"
        b"\x0f\xbf\x14\x48"
        b"\x48\x63\x01"
        b"\x0f\x94\xc0"
        b"\x4c\x0f\xaf\xff"
        b"\xf6\x44\x24\x78\x04"
        b"\x48\x3d\x00\x04\x00\x00"
        b"\x48\x98"
        b"\x48\x05\x28\x01\x00\x00"
        b"\x48\x99"
        b"\x2c\x2b"
        b"\x3c\x1f"
        b"\xfe\xc8"
        b"\x40\x32\xf6"
        b"\x00\x87\xbf\x00\x00\x00"
        b"\x0f\xab\xc1"
    )
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    payload = find_pe_instructions(target, [f"{hex(start_va)}:16"])

    instructions = payload["windows"][0]["instructions"]
    assert [instruction["instruction"] for instruction in instructions] == [
        "SBB EAX, EAX",
        "MOVSX EDX, [RAX+RCX*0x2]",
        "MOVSXD RAX, [RCX]",
        "SETZ AL",
        "IMUL R15, RDI",
        "TEST [RSP+0x78], 0x4",
        "CMP RAX, 0x400",
        "CDQE",
        "ADD RAX, 0x128",
        "CQO",
        "SUB AL, 0x2b",
        "CMP AL, 0x1f",
        "DEC AL",
        "XOR SIL, SIL",
        "ADD [RDI+0xbf], AL",
        "BTS ECX, EAX",
    ]
    assert all(instruction["kind"] != "unknown" for instruction in instructions)


def test_pe_instructions_decodes_locked_cmpxchg_memory(tmp_path):
    data = bytearray(_minimal_pe_with_pdata_bytes())
    image_base = 0x140000000
    start_va = image_base + 0x1000
    data[0x400 : 0x40A] = b"\xf0\x48\x0f\xb1\x0d\x00\x00\x00\x00\xc3"
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    payload = find_pe_instructions(target, [f"{hex(start_va)}:2"])

    instructions = payload["windows"][0]["instructions"]
    assert [instruction["instruction"] for instruction in instructions] == [
        "CMPXCHG.LOCK [0x140001009], RCX",
        "RET",
    ]
    assert instructions[0]["memory_target_va"] == "0x140001009"
    assert all(instruction["kind"] != "unknown" for instruction in instructions)


def test_pe_instructions_preserves_lock_prefix_on_memory_inc(tmp_path):
    data = bytearray(_minimal_pe_with_pdata_bytes())
    image_base = 0x140000000
    start_va = image_base + 0x1000
    target_va = image_base + 0x3000
    data[0x400 : 0x403] = b"\xf0\xff\x05"
    struct.pack_into("<i", data, 0x403, target_va - (start_va + 7))
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    payload = find_pe_instructions(target, [f"{hex(start_va)}:1"])

    instruction = payload["windows"][0]["instructions"][0]
    assert instruction["instruction"] == "INC.LOCK [0x140003000]"
    assert instruction["kind"] != "unknown"


def test_pe_instructions_decodes_ff_inc_operand_size(tmp_path):
    data = bytearray(_minimal_pe_with_pdata_bytes())
    image_base = 0x140000000
    start_va = image_base + 0x1000
    data[0x400 : 0x406] = b"\xff\xc0\x48\xff\xc0\xc3"
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    payload = find_pe_instructions(target, [f"{hex(start_va)}:3"])

    instructions = payload["windows"][0]["instructions"]
    assert [instruction["instruction"] for instruction in instructions] == [
        "INC EAX",
        "INC RAX",
        "RET",
    ]


def test_cli_pe_instructions_outputs_json(tmp_path, capsys):
    data = bytearray(_minimal_pe_with_pdata_bytes())
    image_base = 0x140000000
    data[0x400 : 0x404] = b"\x48\x8b\x41\x10"
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    exit_code = main(["pe-instructions", str(target), f"{hex(image_base + 0x1000)}:1"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert '"type": "pe-instructions"' in captured.out
    assert "MOV RAX" in captured.out


def test_pe_runtime_functions_maps_pdata_ranges_and_neighbors(tmp_path):
    data = bytearray(_minimal_pe_with_pdata_bytes())
    image_base = 0x140000000
    struct.pack_into("<III", data, 0xA0C, 0x1100, 0x1150, 0x3020)
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    payload = find_pe_runtime_functions(target, [hex(image_base + 0x1030), hex(image_base + 0x1080)], neighbors=1)

    inside = payload["queries"][0]
    boundary = payload["queries"][1]
    assert payload["type"] == "pe-runtime-functions"
    assert payload["scan"]["runtime_function_count"] == 2
    assert inside["containing_function"]["start_va"] == hex(image_base + 0x1000)
    assert inside["is_function_start"] is False
    assert boundary["containing_function"] is None
    assert boundary["previous_functions"][0]["end_va"] == hex(image_base + 0x1080)
    assert boundary["next_functions"][0]["start_va"] == hex(image_base + 0x1100)


def test_cli_pe_runtime_functions_outputs_json(tmp_path, capsys):
    target = tmp_path / "sample.exe"
    target.write_bytes(_minimal_pe_with_pdata_bytes())
    image_base = 0x140000000

    exit_code = main(["pe-runtime-functions", str(target), hex(image_base + 0x1030)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert '"type": "pe-runtime-functions"' in captured.out
    assert hex(image_base + 0x1000) in captured.out


def test_pe_read_qwords_maps_targets_and_sections(tmp_path):
    data = bytearray(_minimal_pe_bytes())
    image_base = 0x140000000
    read_va = image_base + 0x1008
    pointed_va = image_base + 0x1010
    struct.pack_into("<Q", data, 0x408, pointed_va)
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    payload = read_pe_qwords(target, [f"{hex(read_va)}:1"])

    read = payload["reads"][0]
    qword = read["qwords"][0]
    assert payload["type"] == "pe-qwords"
    assert read["section"] == ".text"
    assert read["count_returned"] == 1
    assert qword["value"] == hex(pointed_va)
    assert qword["target_section"] == ".text"
    assert qword["target_is_executable"] is True
    assert qword["annotation"] == "executable-target"


def test_cli_pe_read_qwords_outputs_json(tmp_path, capsys):
    data = bytearray(_minimal_pe_bytes())
    image_base = 0x140000000
    read_va = image_base + 0x1008
    struct.pack_into("<Q", data, 0x408, 0)
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    exit_code = main(["pe-read-qwords", str(target), hex(read_va), "--count", "1"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert '"type": "pe-qwords"' in captured.out


def test_pe_rtti_type_descriptors_decode_msvc_name(tmp_path):
    data = bytearray(_minimal_pe_with_data_bytes())
    image_base = 0x140000000
    descriptor_va = image_base + 0x3000
    struct.pack_into("<Q", data, 0x800, image_base + 0x1000)
    struct.pack_into("<Q", data, 0x808, 0)
    rtti_name = b".?AV<lambda_test>@@\x00"
    data[0x810 : 0x810 + len(rtti_name)] = rtti_name
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    payload = read_pe_rtti_type_descriptors(target, [hex(descriptor_va)])

    descriptor = payload["descriptors"][0]
    assert payload["type"] == "pe-rtti-type-descriptors"
    assert descriptor["section"] == ".data"
    assert descriptor["decorated_name"] == ".?AV<lambda_test>@@"
    assert descriptor["parsed_name"]["kind"] == "class"
    assert descriptor["parsed_name"]["name"] == "<lambda_test>"
    assert descriptor["vfptr"]["target_section"] == ".text"


def test_cli_pe_rtti_type_descriptors_outputs_json(tmp_path, capsys):
    data = bytearray(_minimal_pe_with_data_bytes())
    image_base = 0x140000000
    descriptor_va = image_base + 0x3000
    struct.pack_into("<Q", data, 0x800, image_base + 0x1000)
    data[0x810 : 0x810 + 16] = b".?AUprovider@@\x00"
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    exit_code = main(["pe-rtti-type-descriptors", str(target), hex(descriptor_va)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert '"type": "pe-rtti-type-descriptors"' in captured.out
    assert "provider" in captured.out


def test_pe_provider_descriptors_classifies_clone_and_rtti_getter(tmp_path):
    data = bytearray(_minimal_pe_with_data_bytes())
    image_base = 0x140000000
    descriptor_va = image_base + 0x3000
    clone_va = image_base + 0x1020
    getter_va = image_base + 0x1050
    rtti_va = image_base + 0x3040

    struct.pack_into("<Q", data, 0x800, clone_va)
    struct.pack_into("<Q", data, 0x808, clone_va)
    struct.pack_into("<Q", data, 0x810, getter_va)

    clone_offset = 0x400 + 0x20
    data[clone_offset : clone_offset + 3] = b"\x48\x8d\x05"
    struct.pack_into("<i", data, clone_offset + 3, descriptor_va - (clone_va + 7))
    data[clone_offset + 7 : clone_offset + 22] = bytes.fromhex("488902488b410848894208488bc2c3")

    getter_offset = 0x400 + 0x50
    data[getter_offset : getter_offset + 3] = b"\x48\x8d\x05"
    struct.pack_into("<i", data, getter_offset + 3, rtti_va - (getter_va + 7))
    data[getter_offset + 7] = 0xC3

    setter_va = image_base + 0x1070
    struct.pack_into("<Q", data, 0x818, setter_va)
    setter_offset = 0x400 + 0x70
    data[setter_offset : setter_offset + 6] = b"\x48\x8b\x41\x08\xc7\x80"
    struct.pack_into("<I", data, setter_offset + 6, 0x2FE0)
    struct.pack_into("<I", data, setter_offset + 10, 1)
    data[setter_offset + 14] = 0xC3

    struct.pack_into("<Q", data, 0x840, image_base + 0x1000)
    rtti_name = b".?AV<lambda_demo>@@\x00"
    data[0x850 : 0x850 + len(rtti_name)] = rtti_name

    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    payload = summarize_pe_provider_descriptors(target, [hex(descriptor_va)], slot_count=4)

    descriptor = payload["descriptors"][0]
    assert payload["type"] == "pe-provider-descriptors"
    assert descriptor["summary"]["clone_materializer_slots"] == [0, 1]
    assert descriptor["summary"]["has_duplicate_slot0_slot1"] is True
    assert descriptor["summary"]["primary_decorated_name"] == ".?AV<lambda_demo>@@"
    assert descriptor["slots"][0]["thunk"]["matches_descriptor"] is True
    assert descriptor["slots"][2]["thunk"]["kind"] == "rtti-type-getter"
    assert descriptor["slots"][3]["thunk"]["kind"] == "payload-dword-setter"
    assert descriptor["slots"][3]["thunk"]["field_offset"] == "0x2fe0"


def test_cli_pe_provider_descriptors_outputs_json(tmp_path, capsys):
    data = bytearray(_minimal_pe_with_data_bytes())
    image_base = 0x140000000
    descriptor_va = image_base + 0x3000
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    exit_code = main(["pe-provider-descriptors", str(target), hex(descriptor_va), "--slot-count", "1"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert '"type": "pe-provider-descriptors"' in captured.out


def test_pe_provider_descriptor_scan_finds_clone_backref_candidate(tmp_path):
    data = bytearray(_minimal_pe_with_pdata_bytes())
    image_base = 0x140000000
    descriptor_va = image_base + 0x3000
    clone_va = image_base + 0x1020
    getter_va = image_base + 0x1050
    rtti_va = image_base + 0x3040

    struct.pack_into("<Q", data, 0x800, clone_va)
    struct.pack_into("<Q", data, 0x808, clone_va)
    struct.pack_into("<Q", data, 0x818, getter_va)

    clone_offset = 0x400 + 0x20
    data[clone_offset : clone_offset + 3] = b"\x48\x8d\x05"
    struct.pack_into("<i", data, clone_offset + 3, descriptor_va - (clone_va + 7))
    data[clone_offset + 7 : clone_offset + 22] = bytes.fromhex("488902488b410848894208488bc2c3")

    getter_offset = 0x400 + 0x50
    data[getter_offset : getter_offset + 3] = b"\x48\x8d\x05"
    struct.pack_into("<i", data, getter_offset + 3, rtti_va - (getter_va + 7))
    data[getter_offset + 7] = 0xC3

    setup_va = image_base + 0x1070
    setup_offset = 0x400 + 0x70
    data[setup_offset : setup_offset + 3] = b"\x48\x8d\x05"
    struct.pack_into("<i", data, setup_offset + 3, descriptor_va - (setup_va + 7))

    literal_va = image_base + 0x3090
    literal_ref_va = image_base + 0x1078
    literal_ref_offset = 0x400 + 0x78
    data[literal_ref_offset : literal_ref_offset + 3] = b"\x48\x8d\x05"
    struct.pack_into("<i", data, literal_ref_offset + 3, literal_va - (literal_ref_va + 7))
    data[0x890 : 0x890 + 12] = b"Provider\x00xxx"

    struct.pack_into("<Q", data, 0x840, image_base + 0x1000)
    rtti_name = b".?AV<lambda_scan>@@\x00"
    data[0x850 : 0x850 + len(rtti_name)] = rtti_name
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    payload = scan_pe_provider_descriptors(target, section_names=[".data"], max_results=8, include_refs=True)

    assert payload["type"] == "pe-provider-descriptor-scan"
    assert payload["scan"]["candidate_count"] == 1
    assert payload["descriptors"][0]["address"] == hex(descriptor_va)
    assert payload["descriptors"][0]["summary"]["primary_decorated_name"] == ".?AV<lambda_scan>@@"
    assert payload["descriptors"][0]["references"]["hit_count"] == 2
    assert len(payload["descriptors"][0]["reference_roles"]["setup_references"]) == 1
    assert len(payload["descriptors"][0]["reference_roles"]["clone_materializer_references"]) == 1
    assert payload["descriptors"][0]["reference_roles"]["setup_references"][0]["reference_va"] == hex(setup_va)
    assert payload["descriptors"][0]["reference_roles"]["setup_references"][0]["function"]["start_va"] == hex(
        image_base + 0x1000
    )
    assert payload["reference_scan"]["target_count"] == 1
    assert payload["reference_scan"]["runtime_function_count"] == 1
    assert payload["reference_clusters"]["setup_function_cluster_count"] == 1
    assert payload["reference_clusters"]["setup_function_clusters"][0]["descriptor_count"] == 1
    literal_payload = provider_descriptor_cluster_literal_payload(
        target,
        payload,
        max_literals_per_function=1,
    )
    compact = compact_provider_descriptor_clusters(payload, max_descriptors_per_cluster=1, literal_payload=literal_payload)
    rows = provider_descriptor_cluster_rows(payload, max_descriptors_per_cluster=1, literal_payload=literal_payload)
    assert compact["type"] == "pe-provider-descriptor-clusters"
    assert compact["summary"]["setup_function_cluster_count"] == 1
    assert compact["clusters"][0]["descriptor_preview"][0]["address"] == hex(descriptor_va)
    assert compact["clusters"][0]["literals"]["literal_count"] == 1
    assert rows[0]["function_start_va"] == hex(image_base + 0x1000)
    assert rows[0]["sample_descriptors"] == hex(descriptor_va)


def test_cli_pe_provider_descriptor_scan_outputs_json(tmp_path, capsys):
    target = tmp_path / "sample.exe"
    target.write_bytes(_minimal_pe_with_data_bytes())

    exit_code = main(["pe-provider-descriptor-scan", str(target), "--section", ".data", "--max-results", "1"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert '"type": "pe-provider-descriptor-scan"' in captured.out


def test_cli_pe_provider_descriptor_scan_writes_cluster_exports(tmp_path, capsys):
    target = tmp_path / "sample.exe"
    target.write_bytes(_minimal_pe_with_data_bytes())
    cluster_json = tmp_path / "clusters.json"
    cluster_csv = tmp_path / "clusters.csv"

    exit_code = main(
        [
            "pe-provider-descriptor-scan",
            str(target),
            "--section",
            ".data",
            "--max-results",
            "1",
            "--cluster-json-out",
            str(cluster_json),
            "--cluster-csv-out",
            str(cluster_csv),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert '"include_refs": true' in captured.out
    assert '"type": "pe-provider-descriptor-scan"' in captured.out
    assert cluster_json.exists()
    assert cluster_csv.exists()
