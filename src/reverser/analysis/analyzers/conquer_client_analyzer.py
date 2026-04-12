from __future__ import annotations

from pathlib import Path

from reverser.analysis.analyzers.base import Analyzer
from reverser.analysis.conquer_client import (
    find_conquer_client_install_root,
    summarize_conquer_client_file,
    summarize_conquer_client_install,
)
from reverser.models import AnalysisReport


class ConquerClientAnalyzer(Analyzer):
    name = "conquer-client"

    def supports(self, target: Path) -> bool:
        install_root = find_conquer_client_install_root(target)
        if install_root is None:
            return False
        if target.is_dir():
            return True
        return target.suffix.lower() in {".exe", ".dll"}

    def analyze(self, target: Path, report: AnalysisReport) -> None:
        install_root = find_conquer_client_install_root(target)
        if install_root is None:
            return

        if target.is_dir():
            payload = summarize_conquer_client_install(target, install_root=install_root)
            report.add_section("conquer_client", payload)
            report.add_finding(
                "game",
                "Conquer client executable set detected",
                "The target includes the Conquer Online client executable chain, including the main client, launcher, patch tools, support libraries, or placeholder startup stubs.",
                severity="info",
                executable_count=payload.get("executable_count"),
                primary_client=payload.get("primary_client"),
            )
            return

        payload = summarize_conquer_client_file(target, install_root=install_root)
        report.add_section("conquer_client", payload)
        report.add_finding(
            "game",
            "Conquer client binary detected",
            "This binary appears to be part of the Conquer Online client startup, patching, launcher, or support-library chain.",
            severity="info",
            role=payload.get("role"),
            relative_path=payload.get("relative_path"),
            feature_hints=payload.get("feature_hints"),
        )
