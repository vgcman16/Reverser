from __future__ import annotations


def get_report_schema() -> dict[str, object]:
    return {
        "type": "object",
        "required": [
            "report_version",
            "tool",
            "target",
            "generated_at",
            "summary",
            "analyzers_run",
            "sections",
            "findings",
            "warnings",
            "errors",
        ],
        "properties": {
            "report_version": {"type": "string"},
            "tool": {
                "type": "object",
                "required": ["name", "version"],
            },
            "target": {
                "type": "object",
                "required": ["path", "kind", "size_bytes", "extension"],
            },
            "generated_at": {"type": "string", "description": "UTC ISO-8601 timestamp"},
            "summary": {
                "type": "object",
                "required": [
                    "finding_count",
                    "severity_counts",
                    "warning_count",
                    "error_count",
                    "section_count",
                    "section_names",
                    "tags",
                ],
            },
            "analyzers_run": {"type": "array", "items": {"type": "string"}},
            "sections": {"type": "object", "description": "Analyzer-specific structured payloads"},
            "findings": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["category", "title", "severity", "summary", "details"],
                },
            },
            "warnings": {"type": "array", "items": {"type": "string"}},
            "errors": {"type": "array", "items": {"type": "string"}},
        },
    }


def get_scan_index_schema() -> dict[str, object]:
    return {
        "type": "object",
        "required": [
            "report_version",
            "tool",
            "root_path",
            "generated_at",
            "settings",
            "root_summary",
            "summary",
            "entries",
            "skipped_samples",
        ],
        "properties": {
            "report_version": {"type": "string"},
            "tool": {
                "type": "object",
                "required": ["name", "version"],
            },
            "root_path": {"type": "string"},
            "generated_at": {"type": "string"},
            "settings": {"type": "object"},
            "root_summary": {"type": "object"},
            "summary": {"type": "object"},
            "entries": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": [
                        "path",
                        "relative_path",
                        "kind",
                        "size_bytes",
                        "signature",
                        "engines",
                        "finding_count",
                        "severity_counts",
                        "warning_count",
                        "error_count",
                        "tags",
                    ],
                },
            },
            "skipped_samples": {"type": "array", "items": {"type": "object"}},
        },
    }
