from __future__ import annotations

import os
import platform
import shutil
from dataclasses import dataclass
from pathlib import Path

from reverser import __version__


HACKINGTOOL_REVERSE_ENGINEERING_SOURCE = "https://github.com/Z4nzu/hackingtool#reverse-engineering-tools"


@dataclass(frozen=True)
class ExternalToolSpec:
    name: str
    commands: tuple[str, ...]
    scope: str
    profiles: tuple[str, ...]
    relevance: str
    notes: str


_HACKINGTOOL_REVERSE_ENGINEERING_TOOLS: tuple[ExternalToolSpec, ...] = (
    ExternalToolSpec(
        name="Ghidra",
        commands=("analyzeHeadless", "ghidraRun"),
        scope="native-binary",
        profiles=("win64-pe", "native", "all"),
        relevance="high",
        notes="Best fit for decompiler-backed call graphs, type recovery, and cross-reference validation.",
    ),
    ExternalToolSpec(
        name="Radare2",
        commands=("r2", "rabin2", "radare2"),
        scope="native-binary",
        profiles=("win64-pe", "native", "all"),
        relevance="medium",
        notes="Useful as an alternate scripted disassembly and metadata source when available locally.",
    ),
    ExternalToolSpec(
        name="JadX",
        commands=("jadx", "jadx-gui"),
        scope="android-apk",
        profiles=("android-apk", "mobile", "all"),
        relevance="low-for-win64-pe",
        notes="Android bytecode/decompiler tooling; not directly applicable to rs2client.exe.",
    ),
    ExternalToolSpec(
        name="Androguard",
        commands=("androguard",),
        scope="android-apk",
        profiles=("android-apk", "mobile", "all"),
        relevance="low-for-win64-pe",
        notes="Android analysis framework; useful only if the target corpus expands to APK/mobile artifacts.",
    ),
    ExternalToolSpec(
        name="Apk2Gold",
        commands=("apk2gold",),
        scope="android-apk",
        profiles=("android-apk", "mobile", "all"),
        relevance="low-for-win64-pe",
        notes="APK reverse-engineering helper; not directly applicable to the current Windows PE client.",
    ),
)


def _normalize_profile(profile: str | None) -> str:
    value = str(profile or "win64-pe").strip().lower()
    if value in {"pe", "windows-pe", "win64", "windows"}:
        return "win64-pe"
    if value in {"android", "apk"}:
        return "android-apk"
    if value in {"everything", "*"}:
        return "all"
    return value or "win64-pe"


def _which_all(commands: tuple[str, ...], *, path_env: str | None = None) -> list[dict[str, object]]:
    results: list[dict[str, object]] = []
    for command in commands:
        resolved = shutil.which(command, path=path_env)
        results.append(
            {
                "command": command,
                "path": str(Path(resolved)) if resolved else None,
                "available": resolved is not None,
            }
        )
    return results


def _recommended_for_profile(spec: ExternalToolSpec, profile: str) -> bool:
    if profile == "all":
        return True
    return profile in spec.profiles


def build_external_tool_inventory(
    *,
    profile: str | None = None,
    path_env: str | None = None,
) -> dict[str, object]:
    """Return a read-only inventory of external RE tools relevant to the current workflow."""

    normalized_profile = _normalize_profile(profile)
    path_value = os.environ.get("PATH", "") if path_env is None else path_env
    tools: list[dict[str, object]] = []
    available_count = 0
    recommended_available_count = 0

    for spec in _HACKINGTOOL_REVERSE_ENGINEERING_TOOLS:
        command_matches = _which_all(spec.commands, path_env=path_value)
        available = any(bool(item["available"]) for item in command_matches)
        recommended = _recommended_for_profile(spec, normalized_profile)
        if available:
            available_count += 1
        if available and recommended:
            recommended_available_count += 1
        tools.append(
            {
                "name": spec.name,
                "source_category": "hackingtool:reverse-engineering-tools",
                "scope": spec.scope,
                "profiles": list(spec.profiles),
                "relevance": spec.relevance,
                "recommended_for_profile": recommended,
                "available": available,
                "commands": command_matches,
                "notes": spec.notes,
            }
        )

    return {
        "type": "external-tool-inventory",
        "tool": {"name": "reverser-workbench", "version": __version__},
        "source": {
            "name": "Z4nzu/hackingtool reverse-engineering tools",
            "url": HACKINGTOOL_REVERSE_ENGINEERING_SOURCE,
            "mode": "read-only-catalog-reference",
            "policy": "Do not run hackingtool installers or batch install commands; detect and use already trusted local tools only.",
        },
        "profile": normalized_profile,
        "host": {
            "system": platform.system(),
            "machine": platform.machine(),
        },
        "scan": {
            "tool_count": len(tools),
            "available_tool_count": available_count,
            "recommended_available_tool_count": recommended_available_count,
        },
        "tools": tools,
    }
