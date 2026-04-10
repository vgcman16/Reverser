from __future__ import annotations

import json
from pathlib import Path

from reverser.models import BatchScanIndex


def export_scan_json(index: BatchScanIndex, destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(index.to_dict(), indent=2), encoding="utf-8")
    return destination


def export_scan_ndjson(index: BatchScanIndex, destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps(entry.to_dict()) for entry in index.entries]
    destination.write_text("\n".join(lines), encoding="utf-8")
    return destination
