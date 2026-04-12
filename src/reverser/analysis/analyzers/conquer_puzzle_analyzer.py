from __future__ import annotations

from pathlib import Path

from reverser.analysis.conquer_animation import summarize_conquer_animation_path
from reverser.analysis.analyzers.base import Analyzer
from reverser.analysis.conquer_puzzle import (
    find_conquer_install_root,
    parse_pul_file,
    parse_pux_file,
    summarize_conquer_puzzle_directory,
)
from reverser.models import AnalysisReport


class ConquerPuzzleAnalyzer(Analyzer):
    name = "conquer-puzzle"

    def supports(self, target: Path) -> bool:
        if target.is_dir():
            install_root = find_conquer_install_root(target)
            if install_root is None:
                return False
            return (install_root / "map" / "puzzle").is_dir() or (install_root / "map" / "PuzzleSave").is_dir()

        return target.suffix.lower() in {".pul", ".pux"}

    def analyze(self, target: Path, report: AnalysisReport) -> None:
        if target.is_dir():
            payload = summarize_conquer_puzzle_directory(target)
            report.add_section("conquer_puzzle", payload)
            report.add_finding(
                "game",
                "Conquer puzzle assets detected",
                "The target includes Conquer Online puzzle or terrain assets referenced by DMap map headers.",
                severity="info",
                pul_count=payload["pul_count"],
                pux_count=payload["pux_count"],
            )
            return

        if target.suffix.lower() == ".pul":
            payload = parse_pul_file(target)
            payload["scope"] = "file"
            payload["referenced_animation"] = summarize_conquer_animation_path(
                str(payload["animation_path"]),
                install_root=find_conquer_install_root(target),
            )
            report.add_section("conquer_puzzle", payload)
            report.add_finding(
                "game",
                "Conquer puzzle descriptor detected",
                "This `.pul` file exposes the embedded animation reference used by a Conquer puzzle map asset.",
                severity="info",
                animation_path=payload["animation_path"],
            )
            return

        payload = parse_pux_file(target)
        payload["scope"] = "file"
        payload["referenced_animations_sample"] = [
            summarize_conquer_animation_path(animation_path, install_root=find_conquer_install_root(target))
            for animation_path in payload["animation_paths_sample"]
        ]
        report.add_section("conquer_puzzle", payload)
        report.add_finding(
            "game",
            "Conquer terrain payload detected",
            "This `.pux` file matches the Conquer terrain container layout and exposes puzzle labels plus animation references.",
            severity="info",
            puzzle_label_count=payload["puzzle_label_count"],
            animation_path_count=payload["animation_path_count"],
        )
