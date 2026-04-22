from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

JsonDict = dict[str, Any]


@dataclass(slots=True)
class ExternalTargetArtifactEntry:
    target_name: str
    artifact_name: str
    path: Path
    modified_at: str
    milestone: str | None = None
    updated_conclusion: str | None = None
    next_targets: list[str] = field(default_factory=list)
    top_level_keys: list[str] = field(default_factory=list)

    def to_dict(self) -> JsonDict:
        payload = asdict(self)
        payload["path"] = str(self.path)
        return payload


def parse_external_target_artifact(path: str | Path, *, target_name: str | None = None) -> ExternalTargetArtifactEntry:
    artifact_path = Path(path).expanduser().resolve()
    payload = json.loads(artifact_path.read_text(encoding="utf-8"))
    inferred_target_name = target_name or artifact_path.parent.name

    next_targets: list[str] = []
    raw_next_targets = payload.get("next_targets")
    if isinstance(raw_next_targets, list):
        next_targets = [item for item in raw_next_targets if isinstance(item, str)]

    return ExternalTargetArtifactEntry(
        target_name=inferred_target_name,
        artifact_name=artifact_path.name,
        path=artifact_path,
        modified_at=_modified_at_iso(artifact_path),
        milestone=payload.get("milestone") if isinstance(payload.get("milestone"), str) else None,
        updated_conclusion=(
            payload.get("updated_conclusion")
            if isinstance(payload.get("updated_conclusion"), str)
            else None
        ),
        next_targets=next_targets,
        top_level_keys=sorted(payload),
    )


def build_external_target_index(root: str | Path) -> JsonDict:
    root_path = Path(root).expanduser().resolve()
    target_directories = sorted(
        (item for item in root_path.iterdir() if item.is_dir()),
        key=lambda item: item.name.lower(),
    )

    warnings: list[str] = []
    targets: list[JsonDict] = []
    artifact_count = 0

    for target_dir in target_directories:
        entries: list[ExternalTargetArtifactEntry] = []
        for artifact_path in sorted(target_dir.glob("*.json")):
            try:
                entry = parse_external_target_artifact(artifact_path, target_name=target_dir.name)
            except json.JSONDecodeError as exc:
                warnings.append(f"{artifact_path.name}: invalid JSON ({exc.msg})")
                continue
            entries.append(entry)

        entries.sort(key=lambda item: (item.modified_at, item.artifact_name), reverse=True)
        artifact_count += len(entries)

        latest = entries[0] if entries else None
        targets.append(
            {
                "name": target_dir.name,
                "artifact_count": len(entries),
                "latest_artifact": latest.artifact_name if latest else None,
                "latest_milestone": latest.milestone if latest else None,
                "latest_updated_conclusion": latest.updated_conclusion if latest else None,
                "artifacts": [entry.to_dict() for entry in entries],
            }
        )

    return {
        "root_path": str(root_path),
        "generated_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "target_count": len(targets),
        "artifact_count": artifact_count,
        "targets": targets,
        "warnings": warnings,
    }


def _modified_at_iso(path: Path) -> str:
    return datetime.fromtimestamp(path.stat().st_mtime, UTC).replace(microsecond=0).isoformat()
