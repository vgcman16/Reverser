from __future__ import annotations

import struct

from reverser.analysis.pe_address_refs import find_pe_address_refs
from reverser.analysis.pe_direct_calls import find_pe_direct_calls
from reverser.analysis.pe_function_literals import find_pe_function_literals
from reverser.analysis.pe_provider_descriptors import (
    compact_provider_descriptor_clusters,
    provider_descriptor_cluster_rows,
    provider_descriptor_cluster_literal_payload,
    scan_pe_provider_descriptors,
    summarize_pe_provider_descriptors,
)
from reverser.analysis.pe_qwords import read_pe_qwords
from reverser.analysis.pe_rtti import read_pe_rtti_type_descriptors
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
