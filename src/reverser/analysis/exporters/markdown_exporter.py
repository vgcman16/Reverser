from __future__ import annotations

import json
from pathlib import Path

from reverser.models import AnalysisReport


def export_markdown(report: AnalysisReport, destination: Path) -> Path:
    destination.parent.mkdir(parents=True, exist_ok=True)

    lines = [
        f"# Analysis Report: {report.target.path.name}",
        "",
        f"- Path: `{report.target.path}`",
        f"- Kind: `{report.target.kind}`",
        f"- Size: `{report.target.size_bytes}` bytes",
        f"- Generated: `{report.generated_at}`",
        f"- Analyzers: `{', '.join(report.analyzers_run)}`",
        "",
    ]

    if report.findings:
        lines.extend(["## Findings", ""])
        for finding in report.findings:
            lines.append(f"- **[{finding.severity.upper()}] {finding.title}**: {finding.summary}")
        lines.append("")

    for section_name, payload in report.sections.items():
        lines.extend([f"## {section_name.replace('_', ' ').title()}", "", "```json"])
        lines.append(json.dumps(payload, indent=2))
        lines.extend(["```", ""])

    if report.warnings:
        lines.extend(["## Warnings", ""])
        lines.extend(f"- {warning}" for warning in report.warnings)
        lines.append("")

    if report.errors:
        lines.extend(["## Errors", ""])
        lines.extend(f"- {error}" for error in report.errors)
        lines.append("")

    destination.write_text("\n".join(lines), encoding="utf-8")
    return destination
