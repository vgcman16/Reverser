from __future__ import annotations

from pathlib import Path

from reverser.analysis.analyzers.base import Analyzer
from reverser.analysis.conquer_map import (
    find_conquer_map_root,
    parse_dmap_header_bytes,
    parse_otherdata_file,
    summarize_conquer_map_archive,
    summarize_conquer_map_directory,
)
from reverser.analysis.conquer_puzzle import find_conquer_install_root, summarize_conquer_asset_path
from reverser.models import AnalysisReport


class ConquerMapAnalyzer(Analyzer):
    name = "conquer-map"

    def supports(self, target: Path) -> bool:
        map_root = find_conquer_map_root(target)
        if map_root is None:
            return False
        if target.is_dir():
            return True
        suffix = target.suffix.lower()
        return suffix in {".dmap", ".otherdata", ".7z"}

    def analyze(self, target: Path, report: AnalysisReport) -> None:
        map_root = find_conquer_map_root(target)
        if map_root is None:
            return

        if target.is_dir():
            payload = summarize_conquer_map_directory(target, map_root=map_root)
            report.add_section("conquer_map", payload)
            report.add_finding(
                "game",
                "Conquer map set detected",
                "The target includes Conquer Online map archives, DMap payloads, or `.OtherData` sidecar metadata.",
                severity="info",
                archive_count=payload["archive_count"],
                otherdata_count=payload["otherdata_count"],
                paired_archive_count=payload["paired_archive_count"],
            )
            return

        suffix = target.suffix.lower()
        if suffix == ".dmap":
            payload = parse_dmap_header_bytes(target.read_bytes())
            payload["scope"] = "file"
            payload["path"] = str(target)
            payload["paired_otherdata_exists"] = target.with_suffix(".OtherData").exists()
            payload["paired_otherdata_path"] = str(target.with_suffix(".OtherData")) if target.with_suffix(".OtherData").exists() else None
            payload["referenced_asset"] = summarize_conquer_asset_path(
                str(payload["asset_path"]),
                install_root=find_conquer_install_root(target),
            )
            report.add_section("conquer_map", payload)
            report.add_finding(
                "game",
                "Conquer DMap detected",
                "This file matches the Conquer Online DMap header layout and includes an embedded puzzle asset path.",
                severity="info",
                version=payload["version"],
                asset_path=payload["asset_path"],
                grid_width=payload["grid_width"],
                grid_height=payload["grid_height"],
            )
            return

        if suffix == ".otherdata":
            payload = parse_otherdata_file(target)
            payload["scope"] = "file"
            payload["path"] = str(target)
            payload["paired_archive_exists"] = target.with_suffix(".7z").exists()
            payload["paired_archive_path"] = str(target.with_suffix(".7z")) if target.with_suffix(".7z").exists() else None
            report.add_section("conquer_map", payload)
            report.add_finding(
                "game",
                "Conquer map sidecar config detected",
                "This `.OtherData` file is a plaintext Conquer Online map sidecar with layer and map-object metadata.",
                severity="info",
                section_count=payload["section_count"],
                map_obj_total=payload["map_obj_total"],
            )
            return

        if suffix == ".7z":
            payload = summarize_conquer_map_archive(target)
            payload["scope"] = "file"
            payload["path"] = str(target)
            report.add_section("conquer_map", payload)
            if payload.get("dmap"):
                report.add_finding(
                    "game",
                    "Conquer map archive detected",
                    "This archive contains a Conquer Online DMap payload and optional `.OtherData` sidecar metadata.",
                    severity="info",
                    member_count=payload["member_count"],
                    primary_dmap_member=payload.get("primary_dmap_member"),
                    paired_otherdata_exists=payload.get("paired_otherdata_exists"),
                )
