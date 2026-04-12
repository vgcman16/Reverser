from __future__ import annotations

from pathlib import Path

from reverser.analysis.analyzers.base import Analyzer
from reverser.analysis.analyzers.pack_classification import is_chromium_resource_pack
from reverser.models import AnalysisReport


EXECUTABLE_EXTENSIONS = {".exe", ".dll", ".sys", ".drv"}
ARCHIVE_EXTENSIONS = {".zip", ".7z", ".rar", ".tar", ".gz", ".bz2", ".xz"}
GAME_CONTAINER_EXTENSIONS = {
    ".pak",
    ".utoc",
    ".ucas",
    ".vpk",
    ".pck",
    ".rpf",
    ".wad",
    ".bnk",
    ".assets",
    ".bundle",
    ".unity3d",
    ".tpd",
    ".tpi",
    ".dmap",
    ".pul",
    ".pux",
}
JS5_CACHE_EXTENSIONS = {".jcache"}
CONFIG_EXTENSIONS = {".json", ".ini", ".cfg", ".xml", ".toml", ".yaml", ".yml", ".otherdata", ".ani"}
ENTRYPOINT_HINTS = ("game", "shipping", "launcher", "client", "win64", "x64", "conquer", "play", "patch")
ENTRYPOINT_EXCLUDES = ("unins", "crash", "setup", "redist")
ENTRYPOINT_EXECUTABLE_EXTENSIONS = {".exe"}


class DirectoryInventoryAnalyzer(Analyzer):
    name = "directory-inventory"

    def supports(self, target: Path) -> bool:
        return target.is_dir()

    def analyze(self, target: Path, report: AnalysisReport) -> None:
        executables: list[str] = []
        archives: list[str] = []
        game_containers: list[str] = []
        resource_packs: list[str] = []
        js5_caches: list[str] = []
        configs: list[str] = []
        entrypoints: list[str] = []

        for child in target.rglob("*"):
            if not child.is_file():
                continue
            relative = str(child.relative_to(target))
            suffix = child.suffix.lower()
            lowered_name = child.name.lower()

            if suffix in EXECUTABLE_EXTENSIONS:
                executables.append(relative)
                if suffix in ENTRYPOINT_EXECUTABLE_EXTENSIONS and any(
                    hint in lowered_name for hint in ENTRYPOINT_HINTS
                ) and not any(
                    excluded in lowered_name for excluded in ENTRYPOINT_EXCLUDES
                ):
                    entrypoints.append(relative)
            if suffix in ARCHIVE_EXTENSIONS:
                archives.append(relative)
            if suffix in GAME_CONTAINER_EXTENSIONS:
                if suffix == ".pak" and is_chromium_resource_pack(child):
                    resource_packs.append(relative)
                else:
                    game_containers.append(relative)
            if suffix in JS5_CACHE_EXTENSIONS:
                js5_caches.append(relative)
            if suffix in CONFIG_EXTENSIONS:
                configs.append(relative)

        report.add_section(
            "directory_inventory",
            {
                "executable_count": len(executables),
                "archive_count": len(archives),
                "game_container_count": len(game_containers),
                "resource_pack_count": len(resource_packs),
                "js5_cache_count": len(js5_caches),
                "config_count": len(configs),
                "executables": executables[:25],
                "entrypoint_candidates": entrypoints[:15] or executables[:10],
                "archives": archives[:25],
                "game_containers": game_containers[:25],
                "resource_packs": resource_packs[:25],
                "js5_caches": js5_caches[:25],
                "configs": configs[:25],
            },
        )
