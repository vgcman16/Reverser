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
                        "mime_guess",
                        "entropy",
                        "md5",
                        "sha1",
                        "sha256",
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


def get_diff_schema() -> dict[str, object]:
    return {
        "type": "object",
        "required": [
            "report_version",
            "tool",
            "artifact_kind",
            "base_ref",
            "head_ref",
            "generated_at",
            "summary",
            "changes",
        ],
        "properties": {
            "report_version": {"type": "string"},
            "tool": {
                "type": "object",
                "required": ["name", "version"],
            },
            "artifact_kind": {"type": "string"},
            "base_ref": {"type": "string"},
            "head_ref": {"type": "string"},
            "generated_at": {"type": "string"},
            "summary": {"type": "object"},
            "changes": {"type": "object"},
        },
    }


def get_catalog_search_schema() -> dict[str, object]:
    return {
        "type": "object",
        "required": ["tool", "db_path", "filters", "count", "results"],
        "properties": {
            "tool": {"type": "object", "required": ["name", "version"]},
            "db_path": {"type": "string"},
            "filters": {"type": "object"},
            "count": {"type": "integer"},
            "results": {"type": "array", "items": {"type": "object"}},
        },
    }


def get_catalog_ingests_schema() -> dict[str, object]:
    return {
        "type": "object",
        "required": ["tool", "db_path", "count", "ingests"],
        "properties": {
            "tool": {"type": "object", "required": ["name", "version"]},
            "db_path": {"type": "string"},
            "count": {"type": "integer"},
            "ingests": {"type": "array", "items": {"type": "object"}},
        },
    }


def get_js5_manifest_schema() -> dict[str, object]:
    return {
        "type": "object",
        "required": [
            "report_version",
            "tool",
            "generated_at",
            "source_path",
            "export_root",
            "manifest_path",
            "store_kind",
            "archive_id",
            "tables_present",
            "settings",
            "summary",
            "warnings",
            "tables",
        ],
        "properties": {
            "report_version": {"type": "string"},
            "tool": {"type": "object", "required": ["name", "version"]},
            "generated_at": {"type": "string"},
            "source_path": {"type": "string"},
            "export_root": {"type": "string"},
            "manifest_path": {"type": "string"},
            "store_kind": {"type": "string"},
            "archive_id": {"type": "integer"},
            "index_name": {"type": ["string", "null"]},
            "mapping_source": {"type": ["string", "null"]},
            "mapping_build": {"type": ["integer", "null"]},
            "reference_table": {"type": "object"},
            "tables_present": {"type": "array", "items": {"type": "string"}},
            "settings": {"type": "object"},
            "summary": {"type": "object"},
            "warnings": {"type": "array", "items": {"type": "string"}},
            "tables": {"type": "object"},
        },
    }
