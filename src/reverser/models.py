from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


JsonDict = dict[str, Any]


@dataclass(slots=True)
class Finding:
    category: str
    title: str
    severity: str
    summary: str
    details: JsonDict = field(default_factory=dict)

    def to_dict(self) -> JsonDict:
        return asdict(self)


@dataclass(slots=True)
class AnalysisTarget:
    path: Path
    kind: str
    size_bytes: int

    @property
    def extension(self) -> str:
        return self.path.suffix.lower()

    def to_dict(self) -> JsonDict:
        return {
            "path": str(self.path),
            "kind": self.kind,
            "size_bytes": self.size_bytes,
            "extension": self.extension,
        }


@dataclass(slots=True)
class AnalysisReport:
    target: AnalysisTarget
    generated_at: str = field(
        default_factory=lambda: datetime.now(UTC).replace(microsecond=0).isoformat()
    )
    analyzers_run: list[str] = field(default_factory=list)
    sections: dict[str, JsonDict] = field(default_factory=dict)
    findings: list[Finding] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    def add_section(self, name: str, payload: JsonDict) -> None:
        self.sections[name] = payload

    def add_finding(
        self,
        category: str,
        title: str,
        summary: str,
        severity: str = "info",
        **details: Any,
    ) -> None:
        self.findings.append(
            Finding(
                category=category,
                title=title,
                severity=severity,
                summary=summary,
                details=details,
            )
        )

    def warn(self, message: str) -> None:
        self.warnings.append(message)

    def error(self, message: str) -> None:
        self.errors.append(message)

    def mark_analyzer(self, name: str) -> None:
        self.analyzers_run.append(name)

    def to_dict(self) -> JsonDict:
        return {
            "target": self.target.to_dict(),
            "generated_at": self.generated_at,
            "analyzers_run": self.analyzers_run,
            "sections": self.sections,
            "findings": [finding.to_dict() for finding in self.findings],
            "warnings": self.warnings,
            "errors": self.errors,
        }
