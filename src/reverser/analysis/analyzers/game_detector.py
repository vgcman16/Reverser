from __future__ import annotations

from pathlib import Path

from reverser.analysis.analyzers.base import Analyzer
from reverser.analysis.analyzers.pack_classification import looks_like_unreal_pak
from reverser.analysis.netdragon import looks_like_netdragon_package
from reverser.models import AnalysisReport


UNITY_MARKERS = {
    "unityplayer.dll",
    "globalgamemanagers",
    "sharedassets0.assets",
}
UNREAL_STRONG_EXTENSIONS = {".utoc", ".ucas", ".uproject", ".uasset", ".umap"}
SOURCE_EXTENSIONS = {".vpk"}
GODOT_EXTENSIONS = {".pck"}
NETDRAGON_EXTENSIONS = {".tpd", ".tpi"}


def _normalize_names(paths: list[Path]) -> set[str]:
    return {item.name.lower() for item in paths}


class GameFingerprintAnalyzer(Analyzer):
    name = "game-fingerprint"

    def analyze(self, target: Path, report: AnalysisReport) -> None:
        evidence: list[str] = []
        engines: list[dict[str, object]] = []
        titles: list[dict[str, object]] = []

        if target.is_dir():
            sample_paths = list(target.rglob("*"))[:3000]
            names = _normalize_names(sample_paths)
            files = [item for item in sample_paths if item.is_file()]
            suffixes = {item.suffix.lower() for item in files}
            unreal_paks = [item for item in files if item.suffix.lower() == ".pak" and looks_like_unreal_pak(item)]
            netdragon_indexes = [
                item for item in files if item.suffix.lower() == ".tpi" and looks_like_netdragon_package(item)
            ]

            if any(marker in names for marker in UNITY_MARKERS) or any(name.endswith("_data") for name in names):
                evidence.append("Unity markers detected in directory contents.")
                engines.append({"engine": "Unity", "confidence": 0.92})

            if suffixes & UNREAL_STRONG_EXTENSIONS or unreal_paks or ("binaries" in names and "content" in names):
                evidence.append("Unreal package or project markers detected.")
                engines.append({"engine": "Unreal Engine", "confidence": 0.88})

            if suffixes & GODOT_EXTENSIONS:
                evidence.append("Godot package markers detected.")
                engines.append({"engine": "Godot", "confidence": 0.8})

            if suffixes & SOURCE_EXTENSIONS:
                evidence.append("Valve VPK content detected.")
                engines.append({"engine": "Source-family", "confidence": 0.74})

            if netdragon_indexes:
                evidence.append("NetDragon package indexes detected.")
                engines.append({"engine": "NetDragon", "confidence": 0.93})
                if {"c3", "data", "ini", "map"} <= names or {"conquer.exe", "play.exe"} & names:
                    evidence.append("Conquer Online install markers detected.")
                    titles.append({"title": "Conquer Online", "confidence": 0.98})
        else:
            with target.open("rb") as handle:
                header = handle.read(32)

            suffix = target.suffix.lower()
            name = target.name.lower()

            if header.startswith(b"UnityFS") or suffix in {".assets", ".unity3d", ".bundle"}:
                evidence.append("Unity asset or bundle signature found.")
                engines.append({"engine": "Unity", "confidence": 0.9})
            if suffix in UNREAL_STRONG_EXTENSIONS or (suffix == ".pak" and looks_like_unreal_pak(target)):
                evidence.append("Unreal container extension found.")
                engines.append({"engine": "Unreal Engine", "confidence": 0.85})
            if suffix in GODOT_EXTENSIONS or header.startswith(b"GDPC"):
                evidence.append("Godot package marker found.")
                engines.append({"engine": "Godot", "confidence": 0.8})
            if suffix in SOURCE_EXTENSIONS or name.endswith("_dir.vpk"):
                evidence.append("Source-family package marker found.")
                engines.append({"engine": "Source-family", "confidence": 0.7})
            if suffix in NETDRAGON_EXTENSIONS or header.startswith(b"NetDragonDatPkg\x00"):
                evidence.append("NetDragon package signature found.")
                engines.append({"engine": "NetDragon", "confidence": 0.9})
                if "conquer" in name:
                    titles.append({"title": "Conquer Online", "confidence": 0.7})
            if suffix in {".rpf", ".wad", ".bnk"}:
                evidence.append("Common game archive or bank container extension found.")
                engines.append({"engine": "Custom/Container", "confidence": 0.55})

        if engines:
            payload: dict[str, object] = {"engines": engines, "evidence": evidence}
            if titles:
                payload["titles"] = titles
            report.add_section("game_fingerprint", payload)
            report.add_finding(
                "game",
                "Conquer Online markers found" if titles else "Game engine markers found",
                (
                    "The target matches Conquer Online install markers and NetDragon package patterns."
                    if titles
                    else "The target matches one or more known game engine or asset-container patterns."
                ),
                severity="info",
                engines=engines,
                titles=titles,
            )
