from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from reverser import __version__
from reverser.analysis.orchestrator import AnalysisEngine
from reverser.analysis.scan import scan_tree
from reverser.models import REPORT_VERSION


JsonDict = dict[str, Any]


@dataclass(slots=True)
class ArtifactDiff:
    artifact_kind: str
    base_ref: str
    head_ref: str
    generated_at: str = field(
        default_factory=lambda: datetime.now(UTC).replace(microsecond=0).isoformat()
    )
    summary: JsonDict = field(default_factory=dict)
    changes: JsonDict = field(default_factory=dict)

    def to_dict(self) -> JsonDict:
        return {
            "report_version": REPORT_VERSION,
            "tool": {"name": "reverser-workbench", "version": __version__},
            "artifact_kind": self.artifact_kind,
            "base_ref": self.base_ref,
            "head_ref": self.head_ref,
            "generated_at": self.generated_at,
            "summary": self.summary,
            "changes": self.changes,
        }


def load_or_generate_artifact(
    path_or_artifact: str | Path,
    *,
    max_strings: int = 200,
    max_files: int = 250,
    max_file_mb: int = 256,
) -> JsonDict:
    path = Path(path_or_artifact).expanduser().resolve()
    if not path.exists():
        raise FileNotFoundError(f"Target does not exist: {path}")

    artifact = _try_load_artifact(path)
    if artifact is not None:
        return artifact

    if path.is_dir():
        return scan_tree(
            path,
            max_files=max_files,
            max_file_bytes=max_file_mb * 1024 * 1024,
            max_strings=max_strings,
        ).to_dict()

    return AnalysisEngine(max_strings=max_strings).analyze(path).to_dict()


def diff_artifacts(
    base: JsonDict,
    head: JsonDict,
    *,
    base_ref: str,
    head_ref: str,
) -> ArtifactDiff:
    base_kind = _artifact_kind(base)
    head_kind = _artifact_kind(head)
    if base_kind != head_kind:
        return ArtifactDiff(
            artifact_kind="mixed-diff",
            base_ref=base_ref,
            head_ref=head_ref,
            summary={
                "base_kind": base_kind,
                "head_kind": head_kind,
                "compatible": False,
            },
            changes={"note": "Artifacts are different kinds and were not structurally diffed."},
        )

    if base_kind == "report":
        return _diff_report(base, head, base_ref=base_ref, head_ref=head_ref)
    if base_kind == "scan-index":
        return _diff_scan_index(base, head, base_ref=base_ref, head_ref=head_ref)

    return ArtifactDiff(
        artifact_kind="unknown-diff",
        base_ref=base_ref,
        head_ref=head_ref,
        summary={"compatible": False},
        changes={"note": "Artifact format is not recognized."},
    )


def _artifact_kind(payload: JsonDict) -> str:
    if "target" in payload and "sections" in payload:
        return "report"
    if "entries" in payload and "root_path" in payload:
        return "scan-index"
    return "unknown"


def _try_load_artifact(path: Path) -> JsonDict | None:
    if path.suffix.lower() != ".json":
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        return None
    return payload if _artifact_kind(payload) != "unknown" else None


def _diff_report(base: JsonDict, head: JsonDict, *, base_ref: str, head_ref: str) -> ArtifactDiff:
    base_sections = set(base.get("sections", {}))
    head_sections = set(head.get("sections", {}))

    base_findings = {_finding_key(item): item for item in base.get("findings", [])}
    head_findings = {_finding_key(item): item for item in head.get("findings", [])}

    base_tags = set(base.get("summary", {}).get("tags", []))
    head_tags = set(head.get("summary", {}).get("tags", []))

    changed_sections = sorted(
        section
        for section in (base_sections & head_sections)
        if base["sections"].get(section) != head["sections"].get(section)
    )

    return ArtifactDiff(
        artifact_kind="report-diff",
        base_ref=base_ref,
        head_ref=head_ref,
        summary={
            "compatible": True,
            "added_findings": len(head_findings.keys() - base_findings.keys()),
            "removed_findings": len(base_findings.keys() - head_findings.keys()),
            "changed_sections": len(changed_sections),
            "tags_added": sorted(head_tags - base_tags),
            "tags_removed": sorted(base_tags - head_tags),
        },
        changes={
            "target": {
                "base_path": base.get("target", {}).get("path"),
                "head_path": head.get("target", {}).get("path"),
                "base_size_bytes": base.get("target", {}).get("size_bytes"),
                "head_size_bytes": head.get("target", {}).get("size_bytes"),
                "base_signature": base.get("sections", {}).get("identity", {}).get("signature"),
                "head_signature": head.get("sections", {}).get("identity", {}).get("signature"),
            },
            "sections_added": sorted(head_sections - base_sections),
            "sections_removed": sorted(base_sections - head_sections),
            "sections_changed": changed_sections,
            "findings_added": [head_findings[key] for key in sorted(head_findings.keys() - base_findings.keys())],
            "findings_removed": [base_findings[key] for key in sorted(base_findings.keys() - head_findings.keys())],
            "summary_before": base.get("summary", {}),
            "summary_after": head.get("summary", {}),
        },
    )


def _diff_scan_index(base: JsonDict, head: JsonDict, *, base_ref: str, head_ref: str) -> ArtifactDiff:
    base_entries = {item["relative_path"]: item for item in base.get("entries", [])}
    head_entries = {item["relative_path"]: item for item in head.get("entries", [])}

    added_paths = sorted(head_entries.keys() - base_entries.keys())
    removed_paths = sorted(base_entries.keys() - head_entries.keys())
    common_paths = sorted(base_entries.keys() & head_entries.keys())

    changed_entries = []
    for relative_path in common_paths:
        before = base_entries[relative_path]
        after = head_entries[relative_path]
        if before == after:
            continue
        changed_entries.append(
            {
                "relative_path": relative_path,
                "before": before,
                "after": after,
                "deltas": {
                    "size_bytes": int(after.get("size_bytes", 0)) - int(before.get("size_bytes", 0)),
                    "finding_count": int(after.get("finding_count", 0)) - int(before.get("finding_count", 0)),
                    "warning_count": int(after.get("warning_count", 0)) - int(before.get("warning_count", 0)),
                    "error_count": int(after.get("error_count", 0)) - int(before.get("error_count", 0)),
                    "signature_changed": before.get("signature") != after.get("signature"),
                    "tags_added": sorted(set(after.get("tags", [])) - set(before.get("tags", []))),
                    "tags_removed": sorted(set(before.get("tags", [])) - set(after.get("tags", []))),
                },
            }
        )

    return ArtifactDiff(
        artifact_kind="scan-index-diff",
        base_ref=base_ref,
        head_ref=head_ref,
        summary={
            "compatible": True,
            "added_entries": len(added_paths),
            "removed_entries": len(removed_paths),
            "changed_entries": len(changed_entries),
            "finding_delta": int(head.get("summary", {}).get("severity_counts", {}).get("medium", 0))
            + int(head.get("summary", {}).get("severity_counts", {}).get("high", 0))
            - int(base.get("summary", {}).get("severity_counts", {}).get("medium", 0))
            - int(base.get("summary", {}).get("severity_counts", {}).get("high", 0)),
        },
        changes={
            "entries_added": [head_entries[path] for path in added_paths],
            "entries_removed": [base_entries[path] for path in removed_paths],
            "entries_changed": changed_entries,
            "summary_before": base.get("summary", {}),
            "summary_after": head.get("summary", {}),
        },
    )


def _finding_key(finding: JsonDict) -> str:
    return "::".join(
        [
            str(finding.get("category", "")),
            str(finding.get("severity", "")),
            str(finding.get("title", "")),
            str(finding.get("summary", "")),
        ]
    )
