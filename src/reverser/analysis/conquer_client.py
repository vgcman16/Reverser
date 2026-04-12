from __future__ import annotations

import difflib
import re
from collections import Counter
from pathlib import Path

from reverser.analysis.analyzers.pe_analyzer import PEAnalyzer
from reverser.models import AnalysisReport, AnalysisTarget


TOP_LEVEL_EXECUTABLE_LIMIT = 16
TOP_LEVEL_LIBRARY_LIMIT = 24
TOP_LEVEL_GRAPH_EDGE_LIMIT = 24
FEATURE_SAMPLE_LIMIT = 12
STUB_MAX_BYTES = 4096
STUB_PRINTABLE_RATIO = 0.9
STUB_EXECUTABLE_PATTERN = re.compile(r"\b([A-Za-z0-9_.-]+\.exe)\b", re.IGNORECASE)
DLL_REFERENCE_PATTERN = re.compile(rb"([A-Za-z0-9_.-]{3,}\.dll)", re.IGNORECASE)
CONQUER_CLIENT_EXECUTABLE_HINTS = {
    "play.exe",
    "player.exe",
    "conquer.exe",
    "autop.exe",
    "autopatch.exe",
    "update.exe",
    "timedelay.exe",
    "nd_lanucher.exe",
}
INSTALL_MARKER_NAMES = {"data.tpi", "c3.tpi", "autopatch.exe", "play.exe", "map", "ini"}
ROLE_PRIORITY = {
    "main-client": 100,
    "launcher": 80,
    "patcher": 70,
    "utility": 55,
    "uninstaller": 30,
    "launcher-stub": 25,
    "unknown-executable": 10,
}
LIBRARY_ROLE_PRIORITY = {
    "rendering": 100,
    "audio": 90,
    "networking": 80,
    "content": 70,
    "security": 65,
    "gameplay": 60,
    "platform": 50,
    "runtime": 40,
    "utility": 30,
    "unknown-library": 10,
}
LIBRARY_STACK_ORDER = [
    "rendering",
    "audio",
    "networking",
    "content",
    "security",
    "gameplay",
    "platform",
    "runtime",
    "utility",
    "unknown-library",
]
COMMON_SYSTEM_DLLS = {
    "advapi32.dll",
    "bcrypt.dll",
    "comctl32.dll",
    "comdlg32.dll",
    "crypt32.dll",
    "d3d9.dll",
    "d3d9d.dll",
    "d3d11.dll",
    "d3d11_1sdklayers.dll",
    "dbghelp.dll",
    "dsound.dll",
    "ddraw.dll",
    "dinput.dll",
    "dinput8.dll",
    "dwmapi.dll",
    "dxgi.dll",
    "dxgidebug.dll",
    "dxva2.dll",
    "gdi32.dll",
    "gdiplus.dll",
    "hal.dll",
    "imm32.dll",
    "iphlpapi.dll",
    "kernel32.dll",
    "mfc42.dll",
    "mfplat.dll",
    "msimg32.dll",
    "msvcp120.dll",
    "msvcp60.dll",
    "msvcrt.dll",
    "msvcr120.dll",
    "netapi32.dll",
    "ntdll.dll",
    "ole32.dll",
    "oleacc.dll",
    "oleaut32.dll",
    "oledlg.dll",
    "olepro32.dll",
    "opengl32.dll",
    "psapi.dll",
    "secur32.dll",
    "setupapi.dll",
    "shell32.dll",
    "shfolder.dll",
    "shlwapi.dll",
    "user32.dll",
    "uxtheme.dll",
    "version.dll",
    "winhttp.dll",
    "wininet.dll",
    "winmm.dll",
    "wintrust.dll",
    "winspool.drv",
    "ws2_32.dll",
    "wsock32.dll",
    "mpr.dll",
}
EDGE_KIND_PRIORITY = {
    "startup-stub": 0,
    "import-table": 1,
    "embedded-string": 2,
}
EDGE_STATUS_PRIORITY = {
    "present": 0,
    "closest-match": 1,
}


def find_conquer_client_install_root(target: Path) -> Path | None:
    search_start = target if target.is_dir() else target.parent
    for candidate in [search_start, *search_start.parents]:
        if _looks_like_conquer_client_install_root(candidate):
            return candidate
    return None


def summarize_conquer_client_install(target: Path, *, install_root: Path | None = None) -> dict[str, object]:
    resolved_root = install_root or find_conquer_client_install_root(target)
    if resolved_root is None:
        raise FileNotFoundError(f"No Conquer client install root was found for {target}")

    executable_summaries: list[dict[str, object]] = []
    role_counts: Counter[str] = Counter()
    for path in sorted(resolved_root.glob("*.exe"), key=lambda item: item.name.lower()):
        summary = summarize_conquer_client_file(path, install_root=resolved_root)
        executable_summaries.append(summary)
        role_counts[str(summary["role"])] += 1

    primary_client = _select_primary_client(executable_summaries)
    launcher_candidates = [
        _summarize_client_entry(summary)
        for summary in executable_summaries
        if summary["role"] == "launcher"
    ][:FEATURE_SAMPLE_LIMIT]
    patcher_candidates = [
        _summarize_client_entry(summary)
        for summary in executable_summaries
        if summary["role"] == "patcher"
    ][:FEATURE_SAMPLE_LIMIT]
    utility_candidates = [
        _summarize_client_entry(summary)
        for summary in executable_summaries
        if summary["role"] == "utility"
    ][:FEATURE_SAMPLE_LIMIT]
    stub_launchers = [
        _summarize_client_entry(summary)
        for summary in executable_summaries
        if summary["role"] == "launcher-stub"
    ][:FEATURE_SAMPLE_LIMIT]
    startup_chain_sample = _build_startup_chain_sample(
        executable_summaries,
        primary_client_name=str(primary_client["relative_path"]) if isinstance(primary_client, dict) else None,
    )
    support_library_summary = _summarize_support_libraries(
        resolved_root,
        executable_summaries=executable_summaries,
    )

    return {
        "format": "conquer-online-client",
        "resource_kind": "client-install",
        "scope": "directory",
        "path": str(target),
        "install_root": str(resolved_root),
        "executable_count": len(executable_summaries),
        "role_counts": [
            {"role": role, "count": count}
            for role, count in role_counts.most_common(FEATURE_SAMPLE_LIMIT)
        ],
        "primary_client": primary_client,
        "launcher_candidates": launcher_candidates,
        "patcher_candidates": patcher_candidates,
        "utility_candidates": utility_candidates,
        "stub_launchers": stub_launchers,
        "startup_chain_sample": startup_chain_sample,
        "support_library_count": support_library_summary["support_library_count"],
        "support_library_roles": support_library_summary["support_library_roles"],
        "component_stacks": support_library_summary["component_stacks"],
        "local_import_links": support_library_summary["local_import_links"],
        "missing_component_dependencies": support_library_summary["missing_component_dependencies"],
        "dependency_graph": support_library_summary["dependency_graph"],
        "dynamic_component_candidates": support_library_summary["dynamic_component_candidates"],
        "support_libraries": support_library_summary["support_libraries"],
        "executables": executable_summaries[:TOP_LEVEL_EXECUTABLE_LIMIT],
    }


def summarize_conquer_client_file(target: Path, *, install_root: Path | None = None) -> dict[str, object]:
    resolved_root = install_root or find_conquer_client_install_root(target)
    relative_path = _relative_posix(target, resolved_root) if resolved_root is not None else target.name
    if _looks_like_text_launcher_stub(target):
        return _summarize_text_stub(target, relative_path=relative_path, install_root=resolved_root)
    if target.suffix.lower() == ".dll":
        if resolved_root is None:
            raise FileNotFoundError(f"No Conquer client install root was found for {target}")
        summary = _summarize_support_library(
            target,
            install_root=resolved_root,
        )
        return {
            "format": "conquer-online-client",
            "resource_kind": "client-file",
            "scope": "file",
            "path": str(target),
            **summary,
        }
    return _summarize_pe_client_file(target, relative_path=relative_path, install_root=resolved_root)


def _looks_like_conquer_client_install_root(path: Path) -> bool:
    if not path.is_dir():
        return False
    names = {child.name.lower() for child in path.iterdir()}
    return (
        ("play.exe" in names or "player.exe" in names)
        and ("autopatch.exe" in names or "data.tpi" in names or "ini" in names)
    ) or len(names & INSTALL_MARKER_NAMES) >= 4


def _looks_like_text_launcher_stub(path: Path) -> bool:
    if not path.is_file() or path.suffix.lower() != ".exe":
        return False
    size_bytes = path.stat().st_size
    if size_bytes <= 0 or size_bytes > STUB_MAX_BYTES:
        return False
    data = path.read_bytes()
    printable_count = sum(1 for byte in data if byte in {9, 10, 13} or 32 <= byte <= 126)
    if printable_count / max(1, len(data)) < STUB_PRINTABLE_RATIO:
        return False
    text = data.decode("utf-8", errors="ignore").strip()
    return bool(text) and ".exe" in text.lower()


def _summarize_text_stub(target: Path, *, relative_path: str, install_root: Path | None) -> dict[str, object]:
    text = target.read_text(encoding="utf-8", errors="ignore").strip()
    referenced = _resolve_stub_executable_references(text, install_root=install_root)
    closest_target = next(
        (
            item["resolved_target"]
            for item in referenced
            if isinstance(item.get("resolved_target"), str)
        ),
        None,
    )
    return {
        "format": "conquer-online-client",
        "resource_kind": "client-file",
        "scope": "file",
        "path": str(target),
        "relative_path": relative_path,
        "role": "launcher-stub",
        "role_reasons": ["tiny-text-executable-stub"],
        "file_size_bytes": target.stat().st_size,
        "stub_text": text,
        "referenced_executables": referenced,
        "likely_target": closest_target,
        "feature_hints": ["text-launcher-instruction"],
    }


def _summarize_pe_client_file(target: Path, *, relative_path: str, install_root: Path | None) -> dict[str, object]:
    temp_report = AnalysisReport(
        target=AnalysisTarget(
            path=target,
            kind="file",
            size_bytes=target.stat().st_size,
        )
    )
    PEAnalyzer().analyze(target, temp_report)
    pe = temp_report.sections.get("pe", {})
    dlls = [
        str(item["dll"])
        for item in pe.get("imports", [])
        if isinstance(item, dict) and isinstance(item.get("dll"), str)
    ]
    dll_counter = Counter(dll.lower() for dll in dlls)
    functions = {
        str(function).lower()
        for item in pe.get("imports", [])
        if isinstance(item, dict)
        for function in item.get("functions", [])
        if isinstance(function, str)
    }
    section_names = [
        str(item["name"])
        for item in pe.get("sections", [])
        if isinstance(item, dict) and isinstance(item.get("name"), str)
    ]
    section_entropy = sorted(
        [
            {
                "name": str(item["name"]),
                "entropy": item.get("entropy"),
            }
            for item in pe.get("sections", [])
            if isinstance(item, dict) and isinstance(item.get("name"), str)
        ],
        key=lambda item: (
            -(float(item["entropy"]) if isinstance(item.get("entropy"), float) else -1.0),
            item["name"].lower(),
        ),
    )[:FEATURE_SAMPLE_LIMIT]
    feature_hints = _derive_client_feature_hints(dll_counter, functions, pe)
    role, role_reasons = _classify_conquer_client_role(
        name=target.name,
        dll_counter=dll_counter,
        functions=functions,
        feature_hints=feature_hints,
    )
    local_imported_dlls = _resolve_local_imported_dlls(
        [
            {"dll": dll, "count": count}
            for dll, count in dll_counter.most_common(FEATURE_SAMPLE_LIMIT)
        ],
        install_root=install_root,
    )
    embedded_dll_references = _extract_embedded_dll_references(target)
    resolved_component_dependencies = _resolve_library_references(
        [
            *(
                {"name": str(item["dll"]), "source": "import-table"}
                for item in pe.get("imports", [])
                if isinstance(item, dict) and isinstance(item.get("dll"), str)
            ),
            *(
                {"name": dll_name, "source": "embedded-string"}
                for dll_name in embedded_dll_references
            ),
        ],
        install_root=install_root,
    )

    return {
        "format": "conquer-online-client",
        "resource_kind": "client-file",
        "scope": "file",
        "path": str(target),
        "relative_path": relative_path,
        "role": role,
        "role_reasons": role_reasons,
        "file_size_bytes": target.stat().st_size,
        "machine": pe.get("machine"),
        "subsystem": pe.get("subsystem"),
        "entry_point_rva": pe.get("entry_point_rva"),
        "timestamp": pe.get("timestamp"),
        "section_count": pe.get("section_count"),
        "section_name_sample": section_names[:FEATURE_SAMPLE_LIMIT],
        "highest_entropy_sections": section_entropy,
        "import_dlls": [
            {"dll": dll, "count": count}
            for dll, count in dll_counter.most_common(FEATURE_SAMPLE_LIMIT)
        ],
        "feature_hints": feature_hints,
        "network_imports": [
            dll
            for dll in dlls
            if dll.lower() in {"ws2_32.dll", "wininet.dll", "winhttp.dll", "iphlpapi.dll"}
        ][:FEATURE_SAMPLE_LIMIT],
        "crash_dump_support": "dbghelp.dll" in dll_counter and "minidumpwritedump" in functions,
        "local_imported_dlls": local_imported_dlls,
        "embedded_dll_references": embedded_dll_references,
        "resolved_component_dependencies": resolved_component_dependencies,
    }


def _derive_client_feature_hints(
    dll_counter: Counter[str],
    functions: set[str],
    pe: dict[str, object],
) -> list[str]:
    hints: list[str] = []
    if "user32.dll" in dll_counter and "gdi32.dll" in dll_counter:
        hints.append("windows-ui")
    if "gdiplus.dll" in dll_counter:
        hints.append("gdiplus-ui")
    if "ws2_32.dll" in dll_counter:
        hints.append("network-sockets")
    if {"wininet.dll", "winhttp.dll"} & set(dll_counter):
        hints.append("http-client")
    if "iphlpapi.dll" in dll_counter:
        hints.append("adapter-enumeration")
    if "dbghelp.dll" in dll_counter and "minidumpwritedump" in functions:
        hints.append("crash-dumps")
    if "advapi32.dll" in dll_counter:
        hints.append("registry-or-token-access")
    if "shell32.dll" in dll_counter or any(name.startswith("shellexecute") for name in functions):
        hints.append("shell-integration")
    if "winmm.dll" in dll_counter and {"timesetevent", "timekillevent"} & functions:
        hints.append("multimedia-timers")
    if pe.get("subsystem") == "windows-gui":
        hints.append("gui-subsystem")
    return hints


def _classify_conquer_client_role(
    *,
    name: str,
    dll_counter: Counter[str],
    functions: set[str],
    feature_hints: list[str],
) -> tuple[str, list[str]]:
    lowered_name = name.lower()
    reasons: list[str] = []

    if lowered_name.startswith("unins"):
        return "uninstaller", ["name:uninstaller"]

    if any(token in lowered_name for token in ("patch", "update", "autop")):
        reasons.append("name:patcher")
        if "http-client" in feature_hints:
            reasons.append("feature:http-client")
        return "patcher", reasons

    if any(token in lowered_name for token in ("launch", "lanucher")):
        reasons.append("name:launcher")
        if "shell-integration" in feature_hints:
            reasons.append("feature:shell-integration")
        return "launcher", reasons

    if lowered_name in {"play.exe", "player.exe"}:
        reasons.append("name:main-client")
        if "network-sockets" in feature_hints:
            reasons.append("feature:network-sockets")
        if "http-client" in feature_hints:
            reasons.append("feature:http-client")
        if "crash-dumps" in feature_hints:
            reasons.append("feature:crash-dumps")
        return "main-client", reasons

    if lowered_name == "timedelay.exe":
        return "utility", ["name:utility"]

    if {"network-sockets", "windows-ui"} <= set(feature_hints):
        reasons.append("feature:network-sockets")
        reasons.append("feature:windows-ui")
        if "http-client" in feature_hints:
            reasons.append("feature:http-client")
        return "main-client", reasons

    return "unknown-executable", ["fallback:unclassified-pe"]


def _resolve_stub_executable_references(text: str, *, install_root: Path | None) -> list[dict[str, object]]:
    available = {}
    if install_root is not None and install_root.is_dir():
        available = {item.name.lower(): item for item in install_root.glob("*.exe")}

    references: list[dict[str, object]] = []
    seen: set[str] = set()
    for match in STUB_EXECUTABLE_PATTERN.finditer(text):
        raw_name = match.group(1).strip()
        lowered = raw_name.lower()
        if lowered in seen:
            continue
        seen.add(lowered)
        if lowered in available:
            references.append(
                {
                    "name": raw_name,
                    "status": "present",
                    "resolved_target": _relative_posix(available[lowered], install_root),
                }
            )
            continue

        suggestion = _suggest_filename_match(lowered, available)
        references.append(
            {
                "name": raw_name,
                "status": "closest-match" if suggestion is not None else "missing",
                "resolved_target": _relative_posix(suggestion, install_root) if suggestion is not None else None,
            }
        )

    return references[:FEATURE_SAMPLE_LIMIT]


def _suggest_filename_match(reference_name: str, available: dict[str, Path]) -> Path | None:
    if not available:
        return None
    reference_stem = Path(reference_name).stem.lower()
    exact_close = difflib.get_close_matches(reference_name, list(available), n=1, cutoff=0.65)
    if exact_close:
        candidate_name = exact_close[0]
        if difflib.SequenceMatcher(None, reference_stem, Path(candidate_name).stem.lower()).ratio() >= 0.6:
            return available[candidate_name]
    candidates = sorted(
        available.items(),
        key=lambda item: (
            -difflib.SequenceMatcher(None, reference_stem, Path(item[0]).stem.lower()).ratio(),
            item[0],
        ),
    )
    if not candidates:
        return None
    best_name, best_path = candidates[0]
    if difflib.SequenceMatcher(None, reference_stem, Path(best_name).stem.lower()).ratio() >= 0.6:
        return best_path
    return None


def _select_primary_client(executable_summaries: list[dict[str, object]]) -> dict[str, object] | None:
    ranked = sorted(
        executable_summaries,
        key=lambda item: (
            -ROLE_PRIORITY.get(str(item.get("role")), 0),
            -int(item.get("file_size_bytes", 0)),
            str(item.get("relative_path", "")).lower(),
        ),
    )
    if not ranked:
        return None
    return _summarize_client_entry(ranked[0])


def _build_startup_chain_sample(
    executable_summaries: list[dict[str, object]],
    *,
    primary_client_name: str | None,
) -> list[dict[str, object]]:
    sample: list[dict[str, object]] = []
    for summary in executable_summaries:
        if summary.get("role") != "launcher-stub":
            continue
        for reference in summary.get("referenced_executables", []):
            if not isinstance(reference, dict):
                continue
            sample.append(
                {
                    "stub": summary.get("relative_path"),
                    "referenced_executable": reference.get("name"),
                    "resolution_status": reference.get("status"),
                    "resolved_target": reference.get("resolved_target") or primary_client_name,
                }
            )
            if len(sample) >= FEATURE_SAMPLE_LIMIT:
                return sample
    return sample


def _summarize_support_libraries(
    install_root: Path,
    *,
    executable_summaries: list[dict[str, object]],
) -> dict[str, object]:
    library_summaries: list[dict[str, object]] = []
    role_counts: Counter[str] = Counter()
    for path in sorted(install_root.glob("*.dll"), key=lambda item: item.name.lower()):
        summary = _summarize_support_library(
            path,
            install_root=install_root,
        )
        library_summaries.append(summary)
        role_counts[str(summary["role"])] += 1

    local_import_links = _build_local_import_links(
        [*executable_summaries, *library_summaries],
        install_root=install_root,
    )
    imported_library_names = {
        str(item["dll"]).lower()
        for item in local_import_links
        if isinstance(item, dict) and isinstance(item.get("dll"), str)
    }
    for summary in library_summaries:
        summary["statically_imported"] = str(summary.get("relative_path", "")).lower() in imported_library_names

    component_stacks = _build_component_stacks(library_summaries)
    missing_component_dependencies = _collect_missing_component_dependencies(
        [*executable_summaries, *library_summaries]
    )
    dependency_graph = _build_dependency_graph(
        executable_summaries=executable_summaries,
        library_summaries=library_summaries,
    )
    dynamic_component_candidates = [
        _summarize_library_entry(summary)
        for summary in sorted(
            library_summaries,
            key=lambda item: (
                -LIBRARY_ROLE_PRIORITY.get(str(item.get("role")), 0),
                -int(item.get("file_size_bytes", 0)),
                str(item.get("relative_path", "")).lower(),
            ),
        )
        if not summary.get("statically_imported") and summary.get("role") not in {"runtime", "unknown-library"}
    ][:FEATURE_SAMPLE_LIMIT]

    return {
        "support_library_count": len(library_summaries),
        "support_library_roles": [
            {"role": role, "count": count}
            for role, count in sorted(
                role_counts.items(),
                key=lambda item: (
                    -item[1],
                    -LIBRARY_ROLE_PRIORITY.get(item[0], 0),
                    item[0],
                ),
            )[:FEATURE_SAMPLE_LIMIT]
        ],
        "component_stacks": component_stacks,
        "local_import_links": local_import_links[:FEATURE_SAMPLE_LIMIT],
        "missing_component_dependencies": missing_component_dependencies,
        "dependency_graph": dependency_graph,
        "dynamic_component_candidates": dynamic_component_candidates,
        "support_libraries": [
            _summarize_library_entry(summary)
            for summary in sorted(
                library_summaries,
                key=lambda item: (
                    -LIBRARY_ROLE_PRIORITY.get(str(item.get("role")), 0),
                    -int(item.get("file_size_bytes", 0)),
                    str(item.get("relative_path", "")).lower(),
                ),
            )[:TOP_LEVEL_LIBRARY_LIMIT]
        ],
    }


def _build_local_import_links(
    executable_summaries: list[dict[str, object]],
    *,
    install_root: Path,
) -> list[dict[str, object]]:
    links: list[dict[str, object]] = []
    seen: set[tuple[str | None, str | None, str | None, str | None]] = set()
    for summary in executable_summaries:
        relative_path = summary.get("relative_path")
        for item in summary.get("resolved_component_dependencies", []):
            if not isinstance(item, dict):
                continue
            if item.get("status") not in {"present", "closest-match"}:
                continue
            key = (
                str(relative_path) if relative_path is not None else None,
                str(item.get("resolved_target")) if item.get("resolved_target") is not None else None,
                str(item.get("status")) if item.get("status") is not None else None,
                str(item.get("source")) if item.get("source") is not None else None,
            )
            if key in seen:
                continue
            seen.add(key)
            links.append(
                {
                    "executable": relative_path,
                    "dll": item.get("resolved_target"),
                    "status": item.get("status"),
                    "source": item.get("source"),
                }
            )
    return links


def _resolve_local_imported_dlls(
    imported_dlls: list[dict[str, object]],
    *,
    install_root: Path | None,
) -> list[str]:
    if install_root is None or not install_root.is_dir():
        return []
    available = {item.name.lower(): item for item in install_root.glob("*.dll")}
    resolved: list[str] = []
    for item in imported_dlls:
        dll_name = item.get("dll")
        if not isinstance(dll_name, str):
            continue
        matched = available.get(dll_name.lower())
        if matched is None:
            continue
        resolved.append(_relative_posix(matched, install_root))
    return resolved[:FEATURE_SAMPLE_LIMIT]


def _summarize_support_library(
    target: Path,
    *,
    install_root: Path,
) -> dict[str, object]:
    temp_report = AnalysisReport(
        target=AnalysisTarget(
            path=target,
            kind="file",
            size_bytes=target.stat().st_size,
        )
    )
    PEAnalyzer().analyze(target, temp_report)
    pe = temp_report.sections.get("pe", {})
    dlls = [
        str(item["dll"])
        for item in pe.get("imports", [])
        if isinstance(item, dict) and isinstance(item.get("dll"), str)
    ]
    dll_counter = Counter(dll.lower() for dll in dlls)
    functions = {
        str(function).lower()
        for item in pe.get("imports", [])
        if isinstance(item, dict)
        for function in item.get("functions", [])
        if isinstance(function, str)
    }
    feature_hints = _derive_client_feature_hints(dll_counter, functions, pe)
    role, role_reasons = _classify_support_library_role(
        name=target.name,
        dll_counter=dll_counter,
        feature_hints=feature_hints,
    )
    embedded_dll_references = _extract_embedded_dll_references(target)
    resolved_component_dependencies = _resolve_library_references(
        [
            *(
                {"name": str(item["dll"]), "source": "import-table"}
                for item in pe.get("imports", [])
                if isinstance(item, dict) and isinstance(item.get("dll"), str)
            ),
            *(
                {"name": dll_name, "source": "embedded-string"}
                for dll_name in embedded_dll_references
            ),
        ],
        install_root=install_root,
        self_name=target.name,
    )
    return {
        "relative_path": _relative_posix(target, install_root),
        "role": role,
        "role_reasons": role_reasons,
        "file_size_bytes": target.stat().st_size,
        "machine": pe.get("machine"),
        "feature_hints": feature_hints,
        "statically_imported": False,
        "embedded_dll_references": embedded_dll_references,
        "resolved_component_dependencies": resolved_component_dependencies,
    }


def _classify_support_library_role(
    *,
    name: str,
    dll_counter: Counter[str],
    feature_hints: list[str],
) -> tuple[str, list[str]]:
    lowered_name = name.lower()
    if lowered_name.startswith(("msvcr", "msvcp", "mfc")):
        return "runtime", ["name:runtime"]
    if any(token in lowered_name for token in ("graphic", "dx9", "d3d", "c3video", "c3requirecheck")):
        return "rendering", ["name:rendering"]
    if any(token in lowered_name for token in ("sound", "openal", "wrap_oal")):
        return "audio", ["name:audio"]
    if lowered_name in {"net.dll", "libcurl.dll"} or any(token in lowered_name for token in ("ndist",)):
        return "networking", ["name:networking"]
    if any(token in lowered_name for token in ("package", "compress", "zlib", "7z", "tqpdata", "ndac")):
        return "content", ["name:content"]
    if lowered_name in {"tqanp.dll"}:
        reasons = ["name:security"]
        if "network-sockets" in feature_hints:
            reasons.append("feature:network-sockets")
        return "security", reasons
    if any(
        token in lowered_name
        for token in ("protect", "license", "robot", "wordscheck", "analy", "safe", "microspot")
    ):
        reasons = ["name:security"]
        if "network-sockets" in feature_hints:
            reasons.append("feature:network-sockets")
        return "security", reasons
    if lowered_name in {"tqplat.dll"}:
        return "platform", ["name:platform"]
    if any(token in lowered_name for token in ("gameinput", "gamerole", "shop", "record", "assist", "browser")):
        return "gameplay", ["name:gameplay"]
    if {"network-sockets", "http-client"} & set(feature_hints):
        return "networking", ["feature:network-io"]
    if "windows-ui" in feature_hints:
        return "gameplay", ["feature:windows-ui"]
    return "unknown-library", ["fallback:unclassified-library"]


def _build_component_stacks(library_summaries: list[dict[str, object]]) -> list[dict[str, object]]:
    grouped: dict[str, list[dict[str, object]]] = {role: [] for role in LIBRARY_STACK_ORDER}
    for summary in library_summaries:
        grouped.setdefault(str(summary.get("role")), []).append(summary)

    stacks: list[dict[str, object]] = []
    for role in LIBRARY_STACK_ORDER:
        entries = grouped.get(role, [])
        if not entries:
            continue
        ordered_entries = sorted(
            entries,
            key=lambda item: (
                -int(item.get("file_size_bytes", 0)),
                str(item.get("relative_path", "")).lower(),
            ),
        )
        stacks.append(
            {
                "role": role,
                "count": len(entries),
                "components": [
                    str(item.get("relative_path"))
                    for item in ordered_entries[:FEATURE_SAMPLE_LIMIT]
                    if isinstance(item.get("relative_path"), str)
                ],
            }
        )
    return stacks[:FEATURE_SAMPLE_LIMIT]


def _extract_embedded_dll_references(target: Path) -> list[str]:
    seen: set[str] = set()
    references: list[str] = []
    for match in DLL_REFERENCE_PATTERN.finditer(target.read_bytes()):
        value = match.group(1).decode("ascii", errors="ignore")
        lowered = value.lower()
        if (
            lowered in COMMON_SYSTEM_DLLS
            or lowered.startswith("api-ms-")
            or lowered.startswith("ext-ms-")
        ):
            continue
        if lowered in seen:
            continue
        seen.add(lowered)
        references.append(value)
    return references[:FEATURE_SAMPLE_LIMIT]


def _resolve_library_references(
    references: list[dict[str, str]],
    *,
    install_root: Path | None,
    self_name: str | None = None,
) -> list[dict[str, object]]:
    if install_root is None or not install_root.is_dir():
        return []
    available = {
        item.name.lower(): item
        for item in install_root.glob("*.dll")
        if self_name is None or item.name.lower() != self_name.lower()
    }

    resolved: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for item in references:
        raw_name = item.get("name")
        source = item.get("source", "unknown")
        if not isinstance(raw_name, str):
            continue
        lowered = raw_name.lower()
        if self_name is not None and lowered == self_name.lower():
            continue
        if source == "import-table" and (
            lowered in COMMON_SYSTEM_DLLS
            or lowered.startswith("api-ms-")
            or lowered.startswith("ext-ms-")
        ):
            continue
        key = (lowered, source)
        if key in seen:
            continue
        seen.add(key)
        if lowered in available:
            resolved.append(
                {
                    "name": raw_name,
                    "source": source,
                    "status": "present",
                    "resolved_target": _relative_posix(available[lowered], install_root),
                }
            )
            continue

        suggestion = _suggest_filename_match(lowered, available)
        resolved.append(
            {
                "name": raw_name,
                "source": source,
                "status": "closest-match" if suggestion is not None else "missing",
                "resolved_target": _relative_posix(suggestion, install_root) if suggestion is not None else None,
            }
        )
    return resolved[:FEATURE_SAMPLE_LIMIT]


def _collect_missing_component_dependencies(
    summaries: list[dict[str, object]],
) -> list[dict[str, object]]:
    missing: list[dict[str, object]] = []
    for summary in summaries:
        relative_path = summary.get("relative_path")
        for item in summary.get("resolved_component_dependencies", []):
            if not isinstance(item, dict):
                continue
            if item.get("status") not in {"missing", "closest-match"}:
                continue
            missing.append(
                {
                    "source_component": relative_path,
                    "referenced_name": item.get("name"),
                    "resolution_status": item.get("status"),
                    "suggested_target": item.get("resolved_target"),
                    "reference_source": item.get("source"),
                }
            )
            if len(missing) >= FEATURE_SAMPLE_LIMIT:
                return missing
    return missing


def _build_dependency_graph(
    *,
    executable_summaries: list[dict[str, object]],
    library_summaries: list[dict[str, object]],
) -> dict[str, object]:
    all_summaries = [*executable_summaries, *library_summaries]
    nodes: dict[str, dict[str, object]] = {}
    for summary in all_summaries:
        relative_path = summary.get("relative_path")
        if not isinstance(relative_path, str):
            continue
        nodes[relative_path] = {
            "relative_path": relative_path,
            "binary_kind": "library" if relative_path.lower().endswith(".dll") else "executable",
            "role": summary.get("role"),
        }

    edges: list[dict[str, object]] = []
    seen_edges: set[tuple[str, str, str, str | None]] = set()

    for summary in executable_summaries:
        source = summary.get("relative_path")
        if not isinstance(source, str):
            continue
        for reference in summary.get("referenced_executables", []):
            if not isinstance(reference, dict):
                continue
            target = reference.get("resolved_target")
            if not isinstance(target, str) or target not in nodes:
                continue
            status = str(reference.get("status") or "unknown")
            key = (source, target, "startup-stub", status)
            if key in seen_edges:
                continue
            seen_edges.add(key)
            edges.append(
                {
                    "source": source,
                    "target": target,
                    "link_kind": "startup-stub",
                    "resolution_status": status,
                    "referenced_name": reference.get("name"),
                }
            )

    for summary in all_summaries:
        source = summary.get("relative_path")
        if not isinstance(source, str):
            continue
        for item in summary.get("resolved_component_dependencies", []):
            if not isinstance(item, dict):
                continue
            target = item.get("resolved_target")
            if not isinstance(target, str) or target not in nodes:
                continue
            link_kind = str(item.get("source") or "unknown")
            status = str(item.get("status") or "unknown")
            key = (source, target, link_kind, status)
            if key in seen_edges:
                continue
            seen_edges.add(key)
            edges.append(
                {
                    "source": source,
                    "target": target,
                    "link_kind": link_kind,
                    "resolution_status": status,
                    "referenced_name": item.get("name"),
                }
            )

    ordered_edges = sorted(
        edges,
        key=lambda item: (
            EDGE_KIND_PRIORITY.get(str(item.get("link_kind")), 9),
            EDGE_STATUS_PRIORITY.get(str(item.get("resolution_status")), 9),
            str(item.get("source", "")).lower(),
            str(item.get("target", "")).lower(),
            str(item.get("referenced_name", "")).lower(),
        ),
    )

    outgoing: dict[str, set[str]] = {name: set() for name in nodes}
    inbound_sources: dict[str, set[str]] = {name: set() for name in nodes}
    for edge in ordered_edges:
        source = str(edge["source"])
        target = str(edge["target"])
        outgoing.setdefault(source, set()).add(target)
        inbound_sources.setdefault(target, set()).add(source)

    entrypoint_nodes = sorted(
        [
            node
            for node in nodes.values()
            if node.get("binary_kind") == "executable"
            and node.get("role") in {"launcher-stub", "launcher", "main-client", "patcher", "utility"}
        ],
        key=lambda item: (
            -ROLE_PRIORITY.get(str(item.get("role")), 0),
            str(item.get("relative_path", "")).lower(),
        ),
    )

    hotspots = [
        {
            "relative_path": relative_path,
            "role": nodes[relative_path].get("role"),
            "incoming_count": len(sources),
            "incoming_sources": sorted(sources)[:FEATURE_SAMPLE_LIMIT],
        }
        for relative_path, sources in sorted(
            inbound_sources.items(),
            key=lambda item: (
                -len(item[1]),
                -_graph_node_priority(nodes.get(item[0], {})),
                item[0].lower(),
            ),
        )
        if sources
    ][:FEATURE_SAMPLE_LIMIT]

    entrypoint_clusters: list[dict[str, object]] = []
    for node in entrypoint_nodes[:FEATURE_SAMPLE_LIMIT]:
        seed = str(node["relative_path"])
        visited: set[str] = set()
        queue = [seed]
        while queue:
            current = queue.pop(0)
            if current in visited:
                continue
            visited.add(current)
            queue.extend(
                sorted(
                    dependency
                    for dependency in outgoing.get(current, set())
                    if dependency not in visited
                )
            )
        reachable = sorted(item for item in visited if item != seed)
        role_counts = Counter(
            str(nodes[item].get("role"))
            for item in reachable
            if item in nodes and isinstance(nodes[item].get("role"), str)
        )
        entrypoint_clusters.append(
            {
                "entrypoint": seed,
                "role": node.get("role"),
                "reachable_count": len(reachable),
                "reachable_sample": reachable[:FEATURE_SAMPLE_LIMIT],
                "reachable_role_counts": [
                    {"role": role, "count": count}
                    for role, count in role_counts.most_common(FEATURE_SAMPLE_LIMIT)
                ],
            }
        )

    return {
        "node_count": len(nodes),
        "edge_count": len(ordered_edges),
        "entrypoints": [
            {
                "relative_path": str(node["relative_path"]),
                "role": node.get("role"),
            }
            for node in entrypoint_nodes[:FEATURE_SAMPLE_LIMIT]
        ],
        "hotspots": hotspots,
        "entrypoint_clusters": entrypoint_clusters,
        "edges": ordered_edges[:TOP_LEVEL_GRAPH_EDGE_LIMIT],
    }


def _graph_node_priority(node: dict[str, object]) -> int:
    binary_kind = str(node.get("binary_kind") or "")
    role = str(node.get("role") or "")
    if binary_kind == "library":
        return LIBRARY_ROLE_PRIORITY.get(role, 0)
    return ROLE_PRIORITY.get(role, 0)


def _summarize_client_entry(summary: dict[str, object]) -> dict[str, object]:
    payload = {
        "relative_path": summary.get("relative_path"),
        "role": summary.get("role"),
        "file_size_bytes": summary.get("file_size_bytes"),
    }
    if isinstance(summary.get("feature_hints"), list):
        payload["feature_hints"] = summary.get("feature_hints", [])[:FEATURE_SAMPLE_LIMIT]
    if isinstance(summary.get("role_reasons"), list):
        payload["role_reasons"] = summary.get("role_reasons", [])[:FEATURE_SAMPLE_LIMIT]
    if isinstance(summary.get("likely_target"), str):
        payload["likely_target"] = summary.get("likely_target")
    return payload


def _summarize_library_entry(summary: dict[str, object]) -> dict[str, object]:
    payload = {
        "relative_path": summary.get("relative_path"),
        "role": summary.get("role"),
        "file_size_bytes": summary.get("file_size_bytes"),
        "statically_imported": bool(summary.get("statically_imported")),
    }
    if isinstance(summary.get("machine"), str):
        payload["machine"] = summary.get("machine")
    if isinstance(summary.get("feature_hints"), list):
        payload["feature_hints"] = summary.get("feature_hints", [])[:FEATURE_SAMPLE_LIMIT]
    if isinstance(summary.get("role_reasons"), list):
        payload["role_reasons"] = summary.get("role_reasons", [])[:FEATURE_SAMPLE_LIMIT]
    return payload


def _relative_posix(path: Path, install_root: Path | None) -> str:
    if install_root is None:
        return path.name
    try:
        return path.relative_to(install_root).as_posix()
    except ValueError:
        return path.as_posix()
