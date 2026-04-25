from __future__ import annotations

import struct

from reverser.analysis.pe_address_refs import find_pe_address_refs
from reverser.analysis.pe_callsite_registers import find_pe_callsite_registers
from reverser.analysis.pe_direct_calls import find_pe_direct_calls
from reverser.analysis.pe_function_calls import find_pe_function_calls
from reverser.analysis.pe_function_literals import find_pe_function_literals
from reverser.analysis.pe_imports import read_pe_imports
from reverser.analysis.pe_indirect_dispatches import find_pe_indirect_dispatches
from reverser.analysis.pe_instructions import find_pe_instructions
from reverser.analysis.pe_provider_descriptors import (
    compact_provider_descriptor_clusters,
    provider_descriptor_cluster_rows,
    provider_descriptor_cluster_literal_payload,
    scan_pe_provider_descriptors,
    summarize_pe_provider_descriptors,
)
from reverser.analysis.pe_qwords import read_pe_qwords
from reverser.analysis.pe_resolver_invocations import find_pe_resolver_invocations
from reverser.analysis.pe_rtti import read_pe_rtti_type_descriptors
from reverser.analysis.pe_runtime_functions import find_pe_runtime_functions
from reverser.analysis.pe_strings import read_pe_strings
from reverser.analysis.pe_vtable_slots import read_pe_vtable_slots
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


def test_pe_address_refs_finds_rip_relative_immediate_store_refs(tmp_path):
    data = bytearray(_minimal_pe_with_pdata_bytes())
    image_base = 0x140000000
    target_va = image_base + 0x3000
    mov_byte_ref_va = image_base + 0x1030
    mov_dword_ref_va = image_base + 0x1040

    mov_byte_offset = 0x400 + 0x30
    data[mov_byte_offset : mov_byte_offset + 2] = b"\xc6\x05"
    struct.pack_into("<i", data, mov_byte_offset + 2, target_va - (mov_byte_ref_va + 7))
    data[mov_byte_offset + 6] = 1

    mov_dword_offset = 0x400 + 0x40
    data[mov_dword_offset : mov_dword_offset + 3] = b"\x48\xc7\x05"
    struct.pack_into("<i", data, mov_dword_offset + 3, target_va - (mov_dword_ref_va + 11))
    struct.pack_into("<i", data, mov_dword_offset + 7, 0x1234)
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    payload = find_pe_address_refs(target, [hex(target_va)], max_hits_per_target=8)

    result = payload["results"][0]
    hits_by_kind = {hit["kind"]: hit for hit in result["hits"]}
    assert result["hit_count"] == 2
    assert hits_by_kind["rip-relative-mov-imm-store-byte"]["reference_va"] == hex(mov_byte_ref_va)
    assert hits_by_kind["rip-relative-mov-imm-store-byte"]["immediate"] == 1
    assert hits_by_kind["rip-relative-mov-imm-store"]["reference_va"] == hex(mov_dword_ref_va)
    assert hits_by_kind["rip-relative-mov-imm-store"]["immediate"] == 0x1234
    assert hits_by_kind["rip-relative-mov-imm-store"]["rex_prefix"] == "0x48"


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


def test_pe_function_calls_resolves_single_address_with_pdata(tmp_path):
    data = bytearray(_minimal_pe_with_pdata_bytes())
    image_base = 0x140000000
    direct_call_va = image_base + 0x1000
    target_va = image_base + 0x1060

    data[0x400] = 0xE8
    struct.pack_into("<i", data, 0x401, target_va - (direct_call_va + 5))
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    payload = find_pe_function_calls(target, [hex(image_base + 0x1010)])

    function = payload["functions"][0]
    assert function["request"] == hex(image_base + 0x1010)
    assert function["start_va"] == hex(image_base + 0x1000)
    assert function["end_va"] == hex(image_base + 0x1080)
    assert function["call_hit_count"] == 1
    assert function["calls"][0]["target_va"] == hex(target_va)


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


def test_pe_function_calls_accepts_ff_call_after_rex_like_immediate_byte(tmp_path):
    data = bytearray(_minimal_pe_with_import_bytes())
    image_base = 0x140000000
    callsite_va = image_base + 0x1005
    iat_entry_va = image_base + 0x3050

    data[0x400 : 0x405] = b"\xba\x00\x00\x00\x40"
    data[0x405 : 0x407] = b"\xff\x15"
    struct.pack_into("<i", data, 0x407, iat_entry_va - (callsite_va + 6))
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    payload = find_pe_function_calls(target, [f"{hex(image_base + 0x1000)}:{hex(image_base + 0x1080)}"])

    call = payload["functions"][0]["calls"][0]
    assert call["callsite_va"] == hex(callsite_va)
    assert call["kind"] == "indirect-rip-memory"
    assert call["import"]["display_name"] == "kernel32.dll!EnterCriticalSection"


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


def test_pe_indirect_dispatches_backtracks_field_loaded_base_register(tmp_path):
    data = bytearray(_minimal_pe_with_pdata_bytes())
    image_base = 0x140000000
    start_va = image_base + 0x1000
    first_call_va = image_base + 0x100A
    second_call_va = image_base + 0x1014

    data[0x400 : 0x407] = b"\x48\x8b\x8e\x18\x99\x01\x00"
    data[0x407 : 0x40A] = b"\x48\x8b\x01"
    data[0x40A : 0x40D] = b"\xff\x50\x20"
    data[0x40D : 0x414] = b"\x4c\x8b\x92\x10\x8d\x01\x00"
    data[0x414 : 0x417] = b"\x41\xff\xd2"
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    payload = find_pe_indirect_dispatches(target, [hex(start_va + 0x20)])

    function = payload["functions"][0]
    dispatches = function["dispatches"]
    assert payload["type"] == "pe-indirect-dispatches"
    assert function["indirect_dispatch_hit_count"] == 2
    assert dispatches[0]["callsite_va"] == hex(first_call_va)
    assert dispatches[0]["dispatch_slot_displacement"] == 0x20
    assert dispatches[0]["origin"]["kind"] == "memory-load"
    assert dispatches[0]["origin"]["memory"]["base_register"] == "RCX"
    assert dispatches[0]["origin"]["memory"]["displacement"] == 0
    assert dispatches[0]["origin"]["base_register_origin"]["memory"]["base_register"] == "RSI"
    assert dispatches[0]["origin"]["base_register_origin"]["memory"]["displacement"] == 0x19918
    assert dispatches[1]["callsite_va"] == hex(second_call_va)
    assert dispatches[1]["kind"] == "indirect-register"
    assert dispatches[1]["origin"]["memory"]["base_register"] == "RDX"
    assert dispatches[1]["origin"]["memory"]["displacement"] == 0x18D10


def test_cli_pe_indirect_dispatches_outputs_json(tmp_path, capsys):
    data = bytearray(_minimal_pe_with_pdata_bytes())
    image_base = 0x140000000
    start_va = image_base + 0x1000
    data[0x400 : 0x407] = b"\x48\x8b\x81\x18\x99\x01\x00"
    data[0x407 : 0x40A] = b"\xff\x50\x20"
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    exit_code = main(["pe-indirect-dispatches", str(target), f"{hex(start_va)}:{hex(image_base + 0x1080)}"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert '"type": "pe-indirect-dispatches"' in captured.out
    assert '"dispatch_slot_displacement": 32' in captured.out


def test_pe_callsite_registers_recovers_static_rcx_setup(tmp_path):
    data = bytearray(_minimal_pe_with_pdata_bytes())
    image_base = 0x140000000
    callback_va = image_base + 0x1050
    callsite_va = image_base + 0x1011
    wrapper_va = image_base + 0x1060

    data[0x400 : 0x407] = b"\x48\x8d\x0d\x49\x00\x00\x00"
    data[0x407 : 0x411] = b"\x48\xb8\x11\xd3\x00\x00\x00\x00\x00\x80"
    data[0x411] = 0xE8
    struct.pack_into("<i", data, 0x412, wrapper_va - (callsite_va + 5))
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    payload = find_pe_callsite_registers(target, [hex(wrapper_va)], registers=["RCX"])

    call = payload["results"][0]["calls"][0]
    rcx = call["registers"]["RCX"]
    assert payload["type"] == "pe-callsite-registers"
    assert call["callsite_va"] == hex(callsite_va)
    assert rcx["kind"] == "rip-relative-address"
    assert rcx["value_va"] == hex(callback_va)
    assert rcx["value_section"] == ".text"


def test_cli_pe_callsite_registers_outputs_json(tmp_path, capsys):
    data = bytearray(_minimal_pe_with_pdata_bytes())
    image_base = 0x140000000
    callback_va = image_base + 0x1050
    callsite_va = image_base + 0x1007
    wrapper_va = image_base + 0x1060

    data[0x400 : 0x407] = b"\x48\x8d\x0d\x49\x00\x00\x00"
    data[0x407] = 0xE8
    struct.pack_into("<i", data, 0x408, wrapper_va - (callsite_va + 5))
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    exit_code = main(["pe-callsite-registers", str(target), hex(wrapper_va), "--register", "RCX"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert '"type": "pe-callsite-registers"' in captured.out
    assert hex(callback_va) in captured.out


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


def test_pe_instructions_decodes_scalar_sse_modrm_forms(tmp_path):
    data = bytearray(_minimal_pe_with_pdata_bytes())
    image_base = 0x140000000
    start_va = image_base + 0x1000
    data[0x400 : 0x416] = (
        b"\xf3\x0f\x2c\xd8"
        b"\xf3\x0f\x59\x05\x00\x00\x00\x00"
        b"\xf3\x0f\x10\x45\x08"
        b"\xf3\x0f\x11\x4d\x0c"
    )
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    payload = find_pe_instructions(target, [f"{hex(start_va)}:4"])

    instructions = payload["windows"][0]["instructions"]
    assert [instruction["instruction"] for instruction in instructions] == [
        "CVTTSS2SI EBX, XMM0",
        f"MULSS XMM0, [{hex(image_base + 0x100c)}]",
        "MOVSS XMM0, [RBP+0x8]",
        "MOVSS [RBP+0xc], XMM1",
    ]
    assert instructions[1]["memory_target_va"] == hex(image_base + 0x100c)
    assert all(instruction["kind"] != "unknown" for instruction in instructions)


def test_pe_instructions_decodes_simd_conversion_and_three_operand_imul(tmp_path):
    data = bytearray(_minimal_pe_with_pdata_bytes())
    image_base = 0x140000000
    start_va = image_base + 0x1000
    data[0x400 : 0x41F] = (
        b"\x66\x49\x0f\x7e\xc5"
        b"\x4c\x69\xe1\x60\x04\x00\x00"
        b"\x66\x41\x0f\x6e\xcf"
        b"\x0f\x5b\xc9"
        b"\x0f\x2e\xc3"
        b"\xf3\x0f\x58\x83\xd0\x00\x00\x00"
    )
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    payload = find_pe_instructions(target, [f"{hex(start_va)}:6"])

    instructions = payload["windows"][0]["instructions"]
    assert [instruction["instruction"] for instruction in instructions] == [
        "MOVQ R13, XMM0",
        "IMUL R12, RCX, 0x460",
        "MOVD XMM1, R15D",
        "CVTDQ2PS XMM1, XMM1",
        "UCOMISS XMM0, XMM3",
        "ADDSS XMM0, [RBX+0xd0]",
    ]
    assert all(instruction["kind"] != "unknown" for instruction in instructions)


def test_pe_instructions_decodes_repeated_stosq(tmp_path):
    data = bytearray(_minimal_pe_with_pdata_bytes())
    image_base = 0x140000000
    start_va = image_base + 0x1000
    data[0x400 : 0x404] = b"\xf3\x48\xab\xc3"
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    payload = find_pe_instructions(target, [f"{hex(start_va)}:2"])

    instructions = payload["windows"][0]["instructions"]
    assert instructions[0]["instruction"] == "REP STOSQ"
    assert instructions[0]["mnemonic"] == "STOSQ"
    assert instructions[0]["repeat_prefix"] == "REP"
    assert instructions[0]["length"] == 3
    assert instructions[1]["instruction"] == "RET"
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


def test_pe_instructions_decodes_rip_relative_immediate_store_target(tmp_path):
    data = bytearray(_minimal_pe_with_data_bytes())
    image_base = 0x140000000
    start_va = image_base + 0x1000
    target_va = image_base + 0x3000

    data[0x400 : 0x402] = b"\xc6\x05"
    struct.pack_into("<i", data, 0x402, target_va - (start_va + 7))
    data[0x406] = 1
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    payload = find_pe_instructions(target, [f"{hex(start_va)}:1"])

    instruction = payload["windows"][0]["instructions"][0]
    assert instruction["instruction"] == f"MOV [{hex(target_va)}], 0x1"
    assert instruction["memory_target_va"] == hex(target_va)
    assert instruction["memory_target_rva"] == "0x3000"


def test_pe_instructions_decodes_rex_xchg_sib_memory(tmp_path):
    data = bytearray(_minimal_pe_with_pdata_bytes())
    image_base = 0x140000000
    start_va = image_base + 0x1000
    data[0x400 : 0x410] = (
        b"\x49\x87\x84\xf6\xa0\x6b\xc5\x00"
        b"\x4b\x87\xbc\xfe\x50\x6c\xc5\x00"
    )
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    payload = find_pe_instructions(target, [f"{hex(start_va)}:2"])

    instructions = payload["windows"][0]["instructions"]
    assert [instruction["instruction"] for instruction in instructions] == [
        "XCHG [R14+RSI*0x8+0xc56ba0], RAX",
        "XCHG [R14+R15*0x8+0xc56c50], RDI",
    ]
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


def test_pe_read_qwords_previews_pointed_strings(tmp_path):
    data = bytearray(_minimal_pe_with_data_bytes())
    image_base = 0x140000000
    read_va = image_base + 0x3000
    pointed_va = image_base + 0x3020
    struct.pack_into("<Q", data, 0x800, pointed_va)
    text = "kernelbase".encode("utf-16le") + b"\x00\x00"
    data[0x820 : 0x820 + len(text)] = text
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    payload = read_pe_qwords(target, [f"{hex(read_va)}:1"])

    qword = payload["reads"][0]["qwords"][0]
    assert qword["annotation"] == "image-target"
    assert qword["target_section"] == ".data"
    assert qword["target_string_kind"] == "utf16le"
    assert qword["target_string"] == "kernelbase"
    assert qword["target_string_length"] == len("kernelbase")


def test_pe_read_qwords_previews_rva_import_names(tmp_path):
    data = bytearray(_minimal_pe_with_data_bytes())
    image_base = 0x140000000
    read_va = image_base + 0x3000
    import_name_rva = 0x3020
    struct.pack_into("<Q", data, 0x800, import_name_rva)
    struct.pack_into("<H", data, 0x820, 438)
    data[0x822 : 0x822 + len(b"FlsGetValue\x00")] = b"FlsGetValue\x00"
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    payload = read_pe_qwords(target, [f"{hex(read_va)}:1"])

    qword = payload["reads"][0]["qwords"][0]
    assert qword["annotation"] == "import-name-rva"
    assert qword["target_va"] == hex(image_base + import_name_rva)
    assert qword["target_rva"] == hex(import_name_rva)
    assert qword["target_section"] == ".data"
    assert qword["target_string_kind"] == "import-name"
    assert qword["target_string"] == "FlsGetValue"
    assert qword["target_import_hint"] == 438


def test_pe_vtable_slots_maps_function_targets(tmp_path):
    data = bytearray(_minimal_pe_with_pdata_bytes())
    image_base = 0x140000000
    table_va = image_base + 0x3000
    slot0_target = image_base + 0x1000
    slot1_target = image_base + 0x1104
    struct.pack_into("<III", data, 0xA0C, 0x1100, 0x1150, 0x3020)
    struct.pack_into("<Q", data, 0x800, slot0_target)
    struct.pack_into("<Q", data, 0x808, slot1_target)
    struct.pack_into("<Q", data, 0x810, 0)
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    payload = read_pe_vtable_slots(target, [f"{hex(table_va)}:3"])

    table = payload["tables"][0]
    assert payload["type"] == "pe-vtable-slots"
    assert table["count_returned"] == 3
    assert table["slots"][0]["slot_offset"] == "0x0"
    assert table["slots"][0]["target_function"]["start_va"] == hex(slot0_target)
    assert table["slots"][0]["target_is_function_start"] is True
    assert table["slots"][1]["target_function"]["start_va"] == hex(image_base + 0x1100)
    assert table["slots"][1]["target_is_function_start"] is False
    assert table["slots"][2]["annotation"] == "zero"


def test_cli_pe_vtable_slots_outputs_json(tmp_path, capsys):
    data = bytearray(_minimal_pe_with_pdata_bytes())
    image_base = 0x140000000
    table_va = image_base + 0x3000
    struct.pack_into("<Q", data, 0x800, image_base + 0x1000)
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    exit_code = main(["pe-vtable-slots", str(target), hex(table_va), "--count", "1"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert '"type": "pe-vtable-slots"' in captured.out
    assert hex(image_base + 0x1000) in captured.out


def test_pe_resolver_invocations_recovers_static_wrapper_args(tmp_path):
    data = bytearray(_minimal_pe_with_pdata_bytes())
    image_base = 0x140000000
    wrapper_va = image_base + 0x1000
    resolver_va = image_base + 0x1060
    module_indices_va = image_base + 0x3000
    module_indices_end_va = module_indices_va + 4
    api_name_va = image_base + 0x3020
    module_table_va = image_base + 0x3040
    module_name_va = image_base + 0x3060

    cursor = 0x400
    data[cursor : cursor + 7] = b"\x4c\x8d\x0d" + struct.pack(
        "<i", module_indices_end_va - (wrapper_va + 7)
    )
    cursor += 7
    data[cursor : cursor + 5] = b"\xb9\x02\x00\x00\x00"
    cursor += 5
    data[cursor : cursor + 7] = b"\x4c\x8d\x05" + struct.pack(
        "<i", module_indices_va - (wrapper_va + cursor - 0x400 + 7)
    )
    cursor += 7
    data[cursor : cursor + 7] = b"\x48\x8d\x15" + struct.pack(
        "<i", api_name_va - (wrapper_va + cursor - 0x400 + 7)
    )
    cursor += 7
    data[cursor] = 0xE8
    struct.pack_into("<i", data, cursor + 1, resolver_va - (wrapper_va + cursor - 0x400 + 5))

    struct.pack_into("<I", data, 0x800, 1)
    data[0x820 : 0x820 + len(b"GetLocaleInfoEx\x00")] = b"GetLocaleInfoEx\x00"
    struct.pack_into("<Q", data, 0x848, module_name_va)
    module_name = "kernel32".encode("utf-16le") + b"\x00\x00"
    data[0x860 : 0x860 + len(module_name)] = module_name
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    payload = find_pe_resolver_invocations(target, hex(resolver_va), module_table=hex(module_table_va))

    invocation = payload["invocations"][0]
    assert payload["type"] == "pe-resolver-invocations"
    assert payload["scan"]["transfer_hit_count"] == 1
    assert invocation["kind"] == "call"
    assert invocation["selector"] == 2
    assert invocation["api_name"] == "GetLocaleInfoEx"
    assert invocation["module_index_count"] == 1
    assert invocation["module_indices"][0]["index"] == 1
    assert invocation["module_indices"][0]["module_name"] == "kernel32"


def test_cli_pe_resolver_invocations_outputs_json(tmp_path, capsys):
    data = bytearray(_minimal_pe_with_pdata_bytes())
    image_base = 0x140000000
    wrapper_va = image_base + 0x1000
    resolver_va = image_base + 0x1060
    data[0x400 : 0x407] = b"\x4c\x8d\x0d\x00\x00\x00\x00"
    data[0x407 : 0x40C] = b"\x33\xc9\x4c\x8d\x05"
    struct.pack_into("<i", data, 0x40C, 0)
    data[0x410 : 0x417] = b"\x48\x8d\x15\x00\x00\x00\x00"
    data[0x417] = 0xE8
    struct.pack_into("<i", data, 0x418, resolver_va - (wrapper_va + 0x17 + 5))
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    exit_code = main(["pe-resolver-invocations", str(target), hex(resolver_va)])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert '"type": "pe-resolver-invocations"' in captured.out


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


def test_pe_read_strings_decodes_exact_address_cstrings(tmp_path):
    data = bytearray(_minimal_pe_with_data_bytes())
    image_base = 0x140000000
    ascii_va = image_base + 0x3000
    utf16_va = image_base + 0x3020
    data[0x800 : 0x800 + len(b"//\x00rest")] = b"//\x00rest"
    utf16 = "Rune".encode("utf-16le") + b"\x00\x00"
    data[0x820 : 0x820 + len(utf16)] = utf16
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    payload = read_pe_strings(target, [f"{hex(ascii_va)}:8", f"{hex(utf16_va)}:16"])

    assert payload["type"] == "pe-strings"
    assert payload["reads"][0]["ascii"]["value"] == "//"
    assert payload["reads"][0]["decoded"] is True
    assert payload["reads"][1]["utf16le"]["value"] == "Rune"


def test_cli_pe_read_strings_outputs_json(tmp_path, capsys):
    data = bytearray(_minimal_pe_with_data_bytes())
    image_base = 0x140000000
    read_va = image_base + 0x3000
    data[0x800 : 0x800 + len(b":\x00")] = b":\x00"
    target = tmp_path / "sample.exe"
    target.write_bytes(data)

    exit_code = main(["pe-read-strings", str(target), f"{hex(read_va)}:4"])

    captured = capsys.readouterr()
    assert exit_code == 0
    assert '"type": "pe-strings"' in captured.out
    assert '"value": ":"' in captured.out


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
