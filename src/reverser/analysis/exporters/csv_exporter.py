from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

from reverser.models import BatchScanIndex


def export_scan_csv(index: BatchScanIndex, destination: Path) -> Path:
    rows = [
        {
            "path": entry.path,
            "relative_path": entry.relative_path,
            "kind": entry.kind,
            "size_bytes": entry.size_bytes,
            "signature": entry.signature,
            "mime_guess": entry.mime_guess,
            "entropy": entry.entropy,
            "md5": entry.md5,
            "sha1": entry.sha1,
            "sha256": entry.sha256,
            "sample_sha256": entry.sample_sha256,
            "hash_strategy": entry.hash_strategy,
            "entropy_strategy": entry.entropy_strategy,
            "engines": ";".join(entry.engines),
            "js5_store_kind": entry.js5_store_kind,
            "js5_archive_id": entry.js5_archive_id,
            "js5_index_name": entry.js5_index_name,
            "finding_count": entry.finding_count,
            "severity_counts": str(entry.severity_counts),
            "warning_count": entry.warning_count,
            "error_count": entry.error_count,
            "tags": ";".join(entry.tags),
            "json_report_path": entry.json_report_path,
            "markdown_report_path": entry.markdown_report_path,
        }
        for entry in index.entries
    ]
    return export_rows_csv(rows, destination)


def export_rows_csv(rows: list[dict[str, Any]], destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = sorted({key for row in rows for key in row}) if rows else []
    with destination.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        if fieldnames:
            writer.writeheader()
            writer.writerows(rows)
    return destination
