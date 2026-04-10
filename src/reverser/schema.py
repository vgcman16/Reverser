from __future__ import annotations


def get_report_schema() -> dict[str, object]:
    return {
        "type": "object",
        "required": [
            "target",
            "generated_at",
            "analyzers_run",
            "sections",
            "findings",
            "warnings",
            "errors",
        ],
        "properties": {
            "target": {
                "type": "object",
                "required": ["path", "kind", "size_bytes", "extension"],
            },
            "generated_at": {"type": "string", "description": "UTC ISO-8601 timestamp"},
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
