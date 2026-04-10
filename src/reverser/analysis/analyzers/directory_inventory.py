from __future__ import annotations

from pathlib import Path

from reverser.analysis.analyzers.base import Analyzer
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
}
CONFIG_EXTENSIONS = {".json", ".ini", ".cfg", ".xml", ".toml", ".yaml", ".yml"}
ENTRYPOINT_HINTS = ("game", "shipping", "launcher", "client", "win64", "x64")
ENTRYPOINT_EXCLUDES = ("unins", "crash", "setup", "redist")


class DirectoryInventoryAnalyzer(Analyzer):
    name = "directory-inventory"

    def supports(self, target: Path) -> bool:
        return target.is_dir()

    def analyze(self, target: Path, report: AnalysisReport) -> None:
        executables: list[str] = []
        archives: list[str] = []
        game_containers: list[str] = []
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
                if any(hint in lowered_name for hint in ENTRYPOINT_HINTS) and not any(
                    excluded in lowered_name for excluded in ENTRYPOINT_EXCLUDES
                ):
                    entrypoints.append(relative)
            if suffix in ARCHIVE_EXTENSIONS:
                archives.append(relative)
            if suffix in GAME_CONTAINER_EXTENSIONS:
                game_containers.append(relative)
            if suffix in CONFIG_EXTENSIONS:
                configs.append(relative)

        report.add_section(
            "directory_inventory",
            {
                "executable_count": len(executables),
                "archive_count": len(archives),
                "game_container_count": len(game_containers),
                "config_count": len(configs),
                "executables": executables[:25],
                "entrypoint_candidates": entrypoints[:15] or executables[:10],
                "archives": archives[:25],
                "game_containers": game_containers[:25],
                "configs": configs[:25],
            },
        )
