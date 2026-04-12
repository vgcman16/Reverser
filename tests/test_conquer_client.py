from __future__ import annotations

import struct

from reverser.analysis.orchestrator import AnalysisEngine


def _minimal_pe_bytes(*, machine: int = 0x14C, is_pe32_plus: bool = False, subsystem: int = 2) -> bytes:
    data = bytearray(2048)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, 0x80)
    data[0x80:0x84] = b"PE\x00\x00"
    coff_offset = 0x84
    optional_size = 0xF0 if is_pe32_plus else 0xE0
    struct.pack_into("<HHIIIHH", data, coff_offset, machine, 1, 0, 0, 0, optional_size, 0x2022)
    optional_offset = coff_offset + 20
    struct.pack_into("<H", data, optional_offset, 0x20B if is_pe32_plus else 0x10B)
    struct.pack_into("<I", data, optional_offset + 16, 0x1000)
    if is_pe32_plus:
        struct.pack_into("<Q", data, optional_offset + 24, 0x140000000)
        struct.pack_into("<H", data, optional_offset + 68, subsystem)
        struct.pack_into("<I", data, optional_offset + 108, 16)
    else:
        struct.pack_into("<I", data, optional_offset + 28, 0x400000)
        struct.pack_into("<H", data, optional_offset + 68, subsystem)
        struct.pack_into("<I", data, optional_offset + 92, 16)
    section_offset = optional_offset + optional_size
    data[section_offset : section_offset + 8] = b".text\x00\x00\x00"
    struct.pack_into("<IIIIIIHHI", data, section_offset + 8, 0x200, 0x1000, 0x200, 0x400, 0, 0, 0, 0, 0x60000020)
    for index in range(0x400, 0x600):
        data[index] = 0x90
    return bytes(data)


def test_conquer_client_analyzer_parses_stub_launcher(tmp_path):
    root = tmp_path / "Conquer"
    root.mkdir()
    (root / "Play.exe").write_bytes(_minimal_pe_bytes())
    (root / "AutoPatch.exe").write_bytes(_minimal_pe_bytes())
    (root / "Conquer.exe").write_text("Click on Player.exe to log into the game.", encoding="utf-8")

    report = AnalysisEngine().analyze(root / "Conquer.exe")

    section = report.sections["conquer_client"]
    assert section["role"] == "launcher-stub"
    assert section["likely_target"] == "Play.exe"
    assert section["referenced_executables"] == [
        {
            "name": "Player.exe",
            "status": "closest-match",
            "resolved_target": "Play.exe",
        }
    ]


def test_conquer_client_analyzer_parses_main_client_pe(tmp_path):
    root = tmp_path / "Conquer"
    root.mkdir()
    (root / "Play.exe").write_bytes(_minimal_pe_bytes() + b"ndCompress.dll\x00")
    (root / "AutoPatch.exe").write_bytes(_minimal_pe_bytes())
    (root / "ndCompress.dll").write_bytes(_minimal_pe_bytes())

    report = AnalysisEngine().analyze(root / "Play.exe")

    section = report.sections["conquer_client"]
    assert section["role"] == "main-client"
    assert "gui-subsystem" in section["feature_hints"]
    assert section["machine"] == "x86"
    assert section["embedded_dll_references"] == ["ndCompress.dll"]
    assert section["resolved_component_dependencies"] == [
        {
            "name": "ndCompress.dll",
            "source": "embedded-string",
            "status": "present",
            "resolved_target": "ndCompress.dll",
        }
    ]
    assert "format:conquer-client" in report.summary["tags"]


def test_conquer_client_analyzer_parses_support_library_file(tmp_path):
    root = tmp_path / "Conquer"
    root.mkdir()
    (root / "Play.exe").write_bytes(_minimal_pe_bytes())
    (root / "AutoPatch.exe").write_bytes(_minimal_pe_bytes())
    (root / "ini").mkdir()
    (root / "graphicDX9.dll").write_bytes(_minimal_pe_bytes() + b"TqPackage9.dll\x00")
    (root / "TqPackage9.dll").write_bytes(_minimal_pe_bytes())

    report = AnalysisEngine().analyze(root / "graphicDX9.dll")

    section = report.sections["conquer_client"]
    assert section["role"] == "rendering"
    assert section["embedded_dll_references"] == ["TqPackage9.dll"]
    assert section["resolved_component_dependencies"] == [
        {
            "name": "TqPackage9.dll",
            "source": "embedded-string",
            "status": "present",
            "resolved_target": "TqPackage9.dll",
        }
    ]


def test_conquer_client_analyzer_summarizes_install_directory(tmp_path):
    root = tmp_path / "Conquer"
    root.mkdir()
    (root / "Play.exe").write_bytes(_minimal_pe_bytes())
    (root / "AutoPatch.exe").write_bytes(_minimal_pe_bytes())
    (root / "nd_lanucher.exe").write_bytes(_minimal_pe_bytes())
    (root / "Conquer.exe").write_text("Click on Play.exe to log into the game.", encoding="utf-8")
    (root / "ini").mkdir()

    report = AnalysisEngine().analyze(root)

    section = report.sections["conquer_client"]
    assert section["resource_kind"] == "client-install"
    assert section["executable_count"] == 4
    assert section["primary_client"] == {
        "relative_path": "Play.exe",
        "role": "main-client",
        "file_size_bytes": 2048,
        "feature_hints": ["gui-subsystem"],
        "role_reasons": ["name:main-client"],
    }
    assert section["launcher_candidates"] == [
        {
            "relative_path": "nd_lanucher.exe",
            "role": "launcher",
            "file_size_bytes": 2048,
            "feature_hints": ["gui-subsystem"],
            "role_reasons": ["name:launcher"],
        }
    ]
    assert section["patcher_candidates"] == [
        {
            "relative_path": "AutoPatch.exe",
            "role": "patcher",
            "file_size_bytes": 2048,
            "feature_hints": ["gui-subsystem"],
            "role_reasons": ["name:patcher"],
        }
    ]
    assert section["stub_launchers"] == [
        {
            "relative_path": "Conquer.exe",
            "role": "launcher-stub",
            "file_size_bytes": 39,
            "feature_hints": ["text-launcher-instruction"],
            "role_reasons": ["tiny-text-executable-stub"],
            "likely_target": "Play.exe",
        }
    ]
    assert section["startup_chain_sample"] == [
        {
            "stub": "Conquer.exe",
            "referenced_executable": "Play.exe",
            "resolution_status": "present",
            "resolved_target": "Play.exe",
        }
    ]


def test_conquer_client_install_summarizes_support_library_stacks(tmp_path):
    root = tmp_path / "Conquer"
    root.mkdir()
    (root / "Play.exe").write_bytes(_minimal_pe_bytes())
    (root / "AutoPatch.exe").write_bytes(_minimal_pe_bytes())
    (root / "Conquer.exe").write_text("Click on Play.exe to log into the game.", encoding="utf-8")
    (root / "ini").mkdir()

    for name in [
        "graphicDX9.dll",
        "OpenAL32.dll",
        "Net.dll",
        "zlibwapi.dll",
        "TqNDProtect.dll",
        "GameInput.dll",
        "msvcr120.dll",
    ]:
        (root / name).write_bytes(_minimal_pe_bytes())

    report = AnalysisEngine().analyze(root)

    section = report.sections["conquer_client"]
    assert section["support_library_count"] == 7
    assert section["local_import_links"] == []

    role_counts = {item["role"]: item["count"] for item in section["support_library_roles"]}
    assert role_counts["rendering"] == 1
    assert role_counts["audio"] == 1
    assert role_counts["networking"] == 1
    assert role_counts["content"] == 1
    assert role_counts["security"] == 1
    assert role_counts["gameplay"] == 1
    assert role_counts["runtime"] == 1

    component_stacks = {item["role"]: item["components"] for item in section["component_stacks"]}
    assert component_stacks["rendering"] == ["graphicDX9.dll"]
    assert component_stacks["audio"] == ["OpenAL32.dll"]
    assert component_stacks["networking"] == ["Net.dll"]
    assert component_stacks["content"] == ["zlibwapi.dll"]
    assert component_stacks["security"] == ["TqNDProtect.dll"]
    assert component_stacks["gameplay"] == ["GameInput.dll"]
    assert component_stacks["runtime"] == ["msvcr120.dll"]

    dynamic_candidates = {item["relative_path"] for item in section["dynamic_component_candidates"]}
    assert dynamic_candidates == {
        "graphicDX9.dll",
        "OpenAL32.dll",
        "Net.dll",
        "zlibwapi.dll",
        "TqNDProtect.dll",
        "GameInput.dll",
    }


def test_conquer_client_install_tracks_component_dependency_links_and_missing_refs(tmp_path):
    root = tmp_path / "Conquer"
    root.mkdir()
    (root / "Play.exe").write_bytes(_minimal_pe_bytes() + b"ndCompress.dll\x00")
    (root / "AutoPatch.exe").write_bytes(_minimal_pe_bytes())
    (root / "Conquer.exe").write_text("Click on Play.exe to log into the game.", encoding="utf-8")
    (root / "ini").mkdir()

    (root / "ndCompress.dll").write_bytes(_minimal_pe_bytes())
    (root / "license.dll").write_bytes(_minimal_pe_bytes())
    (root / "tqpdata.dll").write_bytes(_minimal_pe_bytes() + b"license.dll\x00")
    (root / "graphicDX9.dll").write_bytes(_minimal_pe_bytes())
    (root / "NDSound.dll").write_bytes(_minimal_pe_bytes())
    (root / "GameRole.dll").write_bytes(_minimal_pe_bytes() + b"graphic.dll\x00GameData.dll\x00NDSound.dll\x00")

    report = AnalysisEngine().analyze(root)

    section = report.sections["conquer_client"]
    assert {
        "executable": "Play.exe",
        "dll": "ndCompress.dll",
        "status": "present",
        "source": "embedded-string",
    } in section["local_import_links"]
    assert {
        "executable": "tqpdata.dll",
        "dll": "license.dll",
        "status": "present",
        "source": "embedded-string",
    } in section["local_import_links"]
    assert {
        "executable": "GameRole.dll",
        "dll": "graphicDX9.dll",
        "status": "closest-match",
        "source": "embedded-string",
    } in section["local_import_links"]
    assert {
        "source_component": "GameRole.dll",
        "referenced_name": "graphic.dll",
        "resolution_status": "closest-match",
        "suggested_target": "graphicDX9.dll",
        "reference_source": "embedded-string",
    } in section["missing_component_dependencies"]
    assert {
        "source_component": "GameRole.dll",
        "referenced_name": "GameData.dll",
        "resolution_status": "missing",
        "suggested_target": None,
        "reference_source": "embedded-string",
    } in section["missing_component_dependencies"]

    graph = section["dependency_graph"]
    assert graph["node_count"] == 9
    assert graph["edge_count"] == 5
    assert graph["entrypoints"] == [
        {"relative_path": "Play.exe", "role": "main-client"},
        {"relative_path": "AutoPatch.exe", "role": "patcher"},
        {"relative_path": "Conquer.exe", "role": "launcher-stub"},
    ]
    assert {
        "source": "Conquer.exe",
        "target": "Play.exe",
        "link_kind": "startup-stub",
        "resolution_status": "present",
        "referenced_name": "Play.exe",
    } in graph["edges"]
    assert {
        "source": "Play.exe",
        "target": "ndCompress.dll",
        "link_kind": "embedded-string",
        "resolution_status": "present",
        "referenced_name": "ndCompress.dll",
    } in graph["edges"]
    assert {
        "source": "GameRole.dll",
        "target": "graphicDX9.dll",
        "link_kind": "embedded-string",
        "resolution_status": "closest-match",
        "referenced_name": "graphic.dll",
    } in graph["edges"]
    assert {
        "source": "GameRole.dll",
        "target": "NDSound.dll",
        "link_kind": "embedded-string",
        "resolution_status": "present",
        "referenced_name": "NDSound.dll",
    } in graph["edges"]
    assert graph["hotspots"] == [
        {
            "relative_path": "graphicDX9.dll",
            "role": "rendering",
            "incoming_count": 1,
            "incoming_sources": ["GameRole.dll"],
        },
        {
            "relative_path": "Play.exe",
            "role": "main-client",
            "incoming_count": 1,
            "incoming_sources": ["Conquer.exe"],
        },
        {
            "relative_path": "NDSound.dll",
            "role": "audio",
            "incoming_count": 1,
            "incoming_sources": ["GameRole.dll"],
        },
        {
            "relative_path": "ndCompress.dll",
            "role": "content",
            "incoming_count": 1,
            "incoming_sources": ["Play.exe"],
        },
        {
            "relative_path": "license.dll",
            "role": "security",
            "incoming_count": 1,
            "incoming_sources": ["tqpdata.dll"],
        },
    ]
    assert graph["entrypoint_clusters"] == [
        {
            "entrypoint": "Play.exe",
            "role": "main-client",
            "reachable_count": 1,
            "reachable_sample": ["ndCompress.dll"],
            "reachable_role_counts": [{"role": "content", "count": 1}],
        },
        {
            "entrypoint": "AutoPatch.exe",
            "role": "patcher",
            "reachable_count": 0,
            "reachable_sample": [],
            "reachable_role_counts": [],
        },
        {
            "entrypoint": "Conquer.exe",
            "role": "launcher-stub",
            "reachable_count": 2,
            "reachable_sample": ["Play.exe", "ndCompress.dll"],
            "reachable_role_counts": [
                {"role": "main-client", "count": 1},
                {"role": "content", "count": 1},
            ],
        },
    ]
