from __future__ import annotations

from pathlib import Path

from reverser.analysis.analyzers.base import Analyzer
from reverser.analysis.conquer_animation import find_conquer_install_root, parse_ani_file, summarize_conquer_animation_directory
from reverser.models import AnalysisReport


class ConquerAnimationAnalyzer(Analyzer):
    name = "conquer-animation"

    def supports(self, target: Path) -> bool:
        if target.is_dir():
            install_root = find_conquer_install_root(target)
            return bool(install_root and (install_root / "ani").is_dir())

        return target.suffix.lower() == ".ani"

    def analyze(self, target: Path, report: AnalysisReport) -> None:
        if target.is_dir():
            payload = summarize_conquer_animation_directory(target)
            report.add_section("conquer_animation", payload)
            report.add_finding(
                "game",
                "Conquer animation assets detected",
                "The target includes Conquer Online `.ani` descriptor files used by puzzle maps, UI, and other resource sets.",
                severity="info",
                ani_count=payload["ani_count"],
            )
            return

        payload = parse_ani_file(target, install_root=find_conquer_install_root(target))
        report.add_section("conquer_animation", payload)
        report.add_finding(
            "game",
            "Conquer animation descriptor detected",
            "This `.ani` file is a plaintext Conquer animation manifest with sectioned frame-path metadata.",
            severity="info",
            section_count=payload["section_count"],
            unique_frame_path_count=payload["unique_frame_path_count"],
            first_frame_path=payload["first_frame_path"],
        )
