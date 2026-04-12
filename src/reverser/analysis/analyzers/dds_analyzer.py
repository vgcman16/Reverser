from __future__ import annotations

from pathlib import Path

from reverser.analysis.analyzers.base import Analyzer
from reverser.analysis.dds import parse_dds_file
from reverser.models import AnalysisReport


class DDSAnalyzer(Analyzer):
    name = "dds"

    def supports(self, target: Path) -> bool:
        if target.is_dir():
            return False
        if target.suffix.lower() == ".dds":
            return True
        try:
            with target.open("rb") as handle:
                return handle.read(4) == b"DDS "
        except OSError:
            return False

    def analyze(self, target: Path, report: AnalysisReport) -> None:
        payload = parse_dds_file(target)
        report.add_section("dds", payload)
        report.add_finding(
            "asset",
            "DDS texture detected",
            "This file matches the DirectDraw Surface texture header layout.",
            severity="info",
            width=payload["width"],
            height=payload["height"],
            fourcc=payload["fourcc"],
            mipmap_count=payload["mipmap_count"],
        )
