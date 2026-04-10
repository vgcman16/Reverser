from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def export_object_json(payload: dict[str, Any], destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    return destination
