from __future__ import annotations

from pathlib import Path

from reverser.analysis.analyzers.base import Analyzer
from reverser.analysis.netdragon import (
    looks_like_netdragon_package,
    resolve_netdragon_pair,
    summarize_netdragon_package,
)
from reverser.models import AnalysisReport


class NetDragonPackageAnalyzer(Analyzer):
    name = "netdragon-package"

    def supports(self, target: Path) -> bool:
        if not target.is_file():
            return False
        return target.suffix.lower() in {".tpi", ".tpd"} or looks_like_netdragon_package(target)

    def analyze(self, target: Path, report: AnalysisReport) -> None:
        index_path, data_path = resolve_netdragon_pair(target)

        if not index_path or not index_path.exists():
            report.add_section(
                "netdragon_package",
                {
                    "format": "netdragon-datpkg",
                    "inspected_path": str(target),
                    "index_path": None,
                    "data_path": str(data_path) if data_path else None,
                    "status": "missing-index",
                },
            )
            report.warn(f"NetDragon package detected but no sibling .tpi index was found for {target.name}.")
            return

        payload = summarize_netdragon_package(index_path, data_path)
        payload["inspected_path"] = str(target)
        payload["status"] = "ok"
        report.add_section("netdragon_package", payload)
        report.add_finding(
            "package",
            "NetDragon package detected",
            "The target matches a NetDragon package/index pair and the package table was parsed for structured inspection.",
            severity="info",
            entry_count=payload["entry_count"],
            index_path=str(index_path),
            data_path=str(data_path) if data_path else None,
        )

        if payload.get("parse_warning_count"):
            report.warn(
                f"NetDragon index parse completed with {payload['parse_warning_count']} warning(s) for {index_path.name}."
            )
