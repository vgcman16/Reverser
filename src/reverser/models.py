from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from reverser import __version__

JsonDict = dict[str, Any]
REPORT_VERSION = "1.1"


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

    @property
    def summary(self) -> JsonDict:
        severity_counts: dict[str, int] = {}
        for finding in self.findings:
            severity_counts[finding.severity] = severity_counts.get(finding.severity, 0) + 1

        return {
            "finding_count": len(self.findings),
            "severity_counts": severity_counts,
            "warning_count": len(self.warnings),
            "error_count": len(self.errors),
            "section_count": len(self.sections),
            "section_names": list(self.sections),
            "tags": self._summary_tags(),
        }

    def _summary_tags(self) -> list[str]:
        tags: list[str] = []

        identity = self.sections.get("identity", {})
        signature = identity.get("signature")
        if isinstance(signature, str) and signature and signature != "unknown":
            tags.append(signature)
        if identity.get("hash_strategy") == "sampled":
            tags.append("hash:sampled")
        if identity.get("entropy_strategy") == "sampled":
            tags.append("entropy:sampled")

        archive = self.sections.get("archive", {})
        archive_type = archive.get("type")
        if isinstance(archive_type, str):
            tags.append(f"archive:{archive_type}")

        sqlite = self.sections.get("sqlite", {})
        if isinstance(sqlite, dict) and sqlite:
            tags.append("database:sqlite")

        game_fingerprint = self.sections.get("game_fingerprint", {})
        engines = game_fingerprint.get("engines", [])
        if isinstance(engines, list):
            for engine in engines:
                if isinstance(engine, dict) and isinstance(engine.get("engine"), str):
                    tags.append(f"engine:{engine['engine'].lower().replace(' ', '-')}")

        js5_cache = self.sections.get("js5_cache", {})
        if isinstance(js5_cache, dict) and js5_cache:
            tags.append("format:js5-jcache")
            archive_id = js5_cache.get("archive_id")
            if isinstance(archive_id, int):
                tags.append(f"js5-archive:{archive_id}")
            store_kind = js5_cache.get("store_kind")
            if isinstance(store_kind, str) and store_kind:
                tags.append(f"js5-store:{store_kind}")
            index_name = js5_cache.get("index_name")
            if isinstance(index_name, str) and index_name:
                normalized_index = index_name.lower().replace("_", "-").replace(" ", "-")
                tags.append(f"js5-index:{normalized_index}")

        js5_cache_directory = self.sections.get("js5_cache_directory", {})
        if isinstance(js5_cache_directory, dict) and js5_cache_directory.get("cache_count"):
            tags.append("format:js5-jcache-directory")

        return sorted(set(tags))

    def to_dict(self) -> JsonDict:
        return {
            "report_version": REPORT_VERSION,
            "tool": {
                "name": "reverser-workbench",
                "version": __version__,
            },
            "target": self.target.to_dict(),
            "generated_at": self.generated_at,
            "summary": self.summary,
            "analyzers_run": self.analyzers_run,
            "sections": self.sections,
            "findings": [finding.to_dict() for finding in self.findings],
            "warnings": self.warnings,
            "errors": self.errors,
        }


@dataclass(slots=True)
class ScanEntry:
    path: str
    relative_path: str
    kind: str
    size_bytes: int
    signature: str
    mime_guess: str | None = None
    entropy: float | None = None
    md5: str | None = None
    sha1: str | None = None
    sha256: str | None = None
    sample_sha256: str | None = None
    hash_strategy: str | None = None
    entropy_strategy: str | None = None
    engines: list[str] = field(default_factory=list)
    js5_store_kind: str | None = None
    js5_archive_id: int | None = None
    js5_index_name: str | None = None
    finding_count: int = 0
    severity_counts: JsonDict = field(default_factory=dict)
    warning_count: int = 0
    error_count: int = 0
    tags: list[str] = field(default_factory=list)
    json_report_path: str | None = None
    markdown_report_path: str | None = None

    @classmethod
    def from_report(
        cls,
        report: AnalysisReport,
        *,
        relative_to: Path,
        json_report_path: Path | None = None,
        markdown_report_path: Path | None = None,
    ) -> "ScanEntry":
        identity = report.sections.get("identity", {})
        game_fingerprint = report.sections.get("game_fingerprint", {})
        js5_cache = report.sections.get("js5_cache", {})
        hashes = identity.get("hashes", {}) if isinstance(identity, dict) else {}
        sampled_hashes = identity.get("sampled_hashes", {}) if isinstance(identity, dict) else {}
        engines = []
        for item in game_fingerprint.get("engines", []):
            if isinstance(item, dict) and isinstance(item.get("engine"), str):
                engines.append(item["engine"])

        return cls(
            path=str(report.target.path),
            relative_path=str(report.target.path.relative_to(relative_to)),
            kind=report.target.kind,
            size_bytes=report.target.size_bytes,
            signature=str(identity.get("signature", "unknown")),
            mime_guess=str(identity.get("mime_guess")) if identity.get("mime_guess") is not None else None,
            entropy=float(identity.get("entropy")) if isinstance(identity.get("entropy"), (int, float)) else None,
            md5=str(hashes.get("md5")) if hashes.get("md5") is not None else None,
            sha1=str(hashes.get("sha1")) if hashes.get("sha1") is not None else None,
            sha256=str(hashes.get("sha256")) if hashes.get("sha256") is not None else None,
            sample_sha256=str(sampled_hashes.get("sha256")) if sampled_hashes.get("sha256") is not None else None,
            hash_strategy=str(identity.get("hash_strategy")) if identity.get("hash_strategy") is not None else None,
            entropy_strategy=str(identity.get("entropy_strategy")) if identity.get("entropy_strategy") is not None else None,
            engines=engines,
            js5_store_kind=str(js5_cache.get("store_kind")) if js5_cache.get("store_kind") is not None else None,
            js5_archive_id=int(js5_cache.get("archive_id")) if isinstance(js5_cache.get("archive_id"), int) else None,
            js5_index_name=str(js5_cache.get("index_name")) if js5_cache.get("index_name") is not None else None,
            finding_count=report.summary["finding_count"],
            severity_counts=report.summary["severity_counts"],
            warning_count=report.summary["warning_count"],
            error_count=report.summary["error_count"],
            tags=report.summary["tags"],
            json_report_path=str(json_report_path) if json_report_path else None,
            markdown_report_path=str(markdown_report_path) if markdown_report_path else None,
        )

    def to_dict(self) -> JsonDict:
        return asdict(self)


@dataclass(slots=True)
class BatchScanIndex:
    root_path: str
    generated_at: str = field(
        default_factory=lambda: datetime.now(UTC).replace(microsecond=0).isoformat()
    )
    settings: JsonDict = field(default_factory=dict)
    entries: list[ScanEntry] = field(default_factory=list)
    skipped_samples: list[JsonDict] = field(default_factory=list)
    root_summary: JsonDict = field(default_factory=dict)

    @property
    def summary(self) -> JsonDict:
        severity_counts: dict[str, int] = {}
        signature_counts: dict[str, int] = {}
        engine_counts: dict[str, int] = {}
        warning_count = 0
        error_count = 0

        for entry in self.entries:
            signature_counts[entry.signature] = signature_counts.get(entry.signature, 0) + 1
            warning_count += entry.warning_count
            error_count += entry.error_count
            for severity, count in entry.severity_counts.items():
                severity_counts[str(severity)] = severity_counts.get(str(severity), 0) + int(count)
            for engine in entry.engines:
                engine_counts[engine] = engine_counts.get(engine, 0) + 1

        return {
            "entry_count": len(self.entries),
            "skipped_count": int(self.settings.get("skipped_count", len(self.skipped_samples))),
            "severity_counts": severity_counts,
            "signature_counts": signature_counts,
            "engine_counts": engine_counts,
            "warning_count": warning_count,
            "error_count": error_count,
        }

    def to_dict(self) -> JsonDict:
        return {
            "report_version": REPORT_VERSION,
            "tool": {
                "name": "reverser-workbench",
                "version": __version__,
            },
            "root_path": self.root_path,
            "generated_at": self.generated_at,
            "settings": self.settings,
            "root_summary": self.root_summary,
            "summary": self.summary,
            "entries": [entry.to_dict() for entry in self.entries],
            "skipped_samples": self.skipped_samples,
        }
