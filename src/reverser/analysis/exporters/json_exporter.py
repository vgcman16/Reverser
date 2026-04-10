from __future__ import annotations

import json
from pathlib import Path

from reverser.models import AnalysisReport


def export_json(report: AnalysisReport, destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(report.to_dict(), indent=2), encoding="utf-8")
    return destination
