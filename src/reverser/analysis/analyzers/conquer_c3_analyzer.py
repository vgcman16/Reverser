from __future__ import annotations

from pathlib import Path

from reverser.analysis.analyzers.base import Analyzer
from reverser.analysis.conquer_c3 import (
    KNOWN_C3_REFERENCE_FILES,
    find_conquer_c3_install_root,
    looks_like_conquer_c3_file,
    parse_conquer_c3_file,
    parse_conquer_c3_reference_file,
    summarize_conquer_c3_install,
)
from reverser.models import AnalysisReport


class ConquerC3Analyzer(Analyzer):
    name = "conquer-c3"

    def supports(self, target: Path) -> bool:
        if target.is_file() and (target.suffix.lower() == ".c3" or looks_like_conquer_c3_file(target)):
            return True

        install_root = find_conquer_c3_install_root(target)
        if install_root is None:
            return False
        if target.is_dir():
            return True
        return (
            target.suffix.lower() == ".ini" and target.name.lower() in KNOWN_C3_REFERENCE_FILES
        )

    def analyze(self, target: Path, report: AnalysisReport) -> None:
        if target.is_file() and (target.suffix.lower() == ".c3" or looks_like_conquer_c3_file(target)):
            payload = parse_conquer_c3_file(target)
            report.add_section("conquer_c3", payload)
            report.add_finding(
                "game",
                "Conquer C3 asset detected",
                "This file uses the Conquer Online MAXFILE C3 container header used by packaged motion, particle, and mesh assets.",
                severity="info",
                top_tag=payload.get("top_tag"),
                object_name=payload.get("object_name"),
            )
            return

        install_root = find_conquer_c3_install_root(target)
        if install_root is None:
            return

        if target.is_dir():
            payload = summarize_conquer_c3_install(target, install_root=install_root)
            report.add_section("conquer_c3", payload)
            report.add_finding(
                "game",
                "Conquer C3 reference tables detected",
                "The target includes Conquer Online C3 reference tables and package-backed mesh, motion, or effect assets.",
                severity="info",
                reference_file_count=payload.get("reference_file_count"),
                unique_path_count=payload.get("unique_path_count"),
                resolved_unique_path_count=payload.get("resolved_unique_path_count"),
                missing_unique_path_count=payload.get("missing_unique_path_count"),
            )
            return

        if target.suffix.lower() == ".ini" and target.name.lower() in KNOWN_C3_REFERENCE_FILES:
            payload = parse_conquer_c3_reference_file(target, install_root=install_root)
            report.add_section("conquer_c3", payload)
            report.add_finding(
                "game",
                "Conquer C3 reference table detected",
                "This file maps Conquer Online numeric identifiers onto packaged C3 assets such as effects, NPC motions, or scene resources.",
                severity="info",
                reference_file_kind=payload.get("reference_file_kind"),
                entry_count=payload.get("entry_count"),
                unique_path_count=payload.get("unique_path_count"),
                resolved_unique_path_count=payload.get("resolved_unique_path_count"),
            )
            return
