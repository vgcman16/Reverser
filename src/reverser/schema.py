from __future__ import annotations


def _build_js5_probe_schema(
    *,
    required: list[str],
    properties: dict[str, object],
) -> dict[str, object]:
    base_properties: dict[str, object] = {
        "kind": {"type": "string"},
        "manifest_path": {"type": "string"},
        "export_root": {"type": "string"},
        "filters": {"type": "object"},
        "raw_opcode": {"type": "integer"},
        "raw_opcode_hex": {"type": "string"},
    }
    base_properties.update(properties)
    return {
        "type": "object",
        "required": required,
        "properties": base_properties,
    }


def _build_request_schema(
    *,
    required: list[str],
    properties: dict[str, object],
) -> dict[str, object]:
    return {
        "type": "object",
        "required": required,
        "properties": properties,
    }


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


def get_external_target_index_schema() -> dict[str, object]:
    return {
        "type": "object",
        "required": [
            "root_path",
            "generated_at",
            "target_count",
            "artifact_count",
            "targets",
            "warnings",
        ],
        "properties": {
            "root_path": {"type": "string"},
            "generated_at": {"type": "string"},
            "target_count": {"type": "integer"},
            "artifact_count": {"type": "integer"},
            "warnings": {"type": "array", "items": {"type": "string"}},
            "targets": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": [
                        "name",
                        "artifact_count",
                        "latest_artifact",
                        "latest_milestone",
                        "latest_updated_conclusion",
                        "artifacts",
                    ],
                    "properties": {
                        "name": {"type": "string"},
                        "artifact_count": {"type": "integer"},
                        "latest_artifact": {"type": ["string", "null"]},
                        "latest_milestone": {"type": ["string", "null"]},
                        "latest_updated_conclusion": {"type": ["string", "null"]},
                        "artifacts": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "required": [
                                    "target_name",
                                    "artifact_name",
                                    "path",
                                    "modified_at",
                                    "next_targets",
                                    "top_level_keys",
                                ],
                                "properties": {
                                    "target_name": {"type": "string"},
                                    "artifact_name": {"type": "string"},
                                    "path": {"type": "string"},
                                    "modified_at": {"type": "string"},
                                    "milestone": {"type": ["string", "null"]},
                                    "updated_conclusion": {"type": ["string", "null"]},
                                    "next_targets": {"type": "array", "items": {"type": "string"}},
                                    "top_level_keys": {"type": "array", "items": {"type": "string"}},
                                },
                            },
                        },
                    },
                },
            },
        },
    }


def get_external_tool_inventory_schema() -> dict[str, object]:
    return {
        "type": "object",
        "required": ["type", "tool", "source", "profile", "host", "scan", "tools"],
        "properties": {
            "type": {"const": "external-tool-inventory"},
            "tool": {"type": "object", "required": ["name", "version"]},
            "source": {
                "type": "object",
                "required": ["name", "url", "mode", "policy"],
                "properties": {
                    "name": {"type": "string"},
                    "url": {"type": "string"},
                    "mode": {"type": "string"},
                    "policy": {"type": "string"},
                },
            },
            "profile": {"type": "string"},
            "host": {"type": "object"},
            "scan": {
                "type": "object",
                "required": ["tool_count", "available_tool_count", "recommended_available_tool_count"],
                "properties": {
                    "tool_count": {"type": "integer"},
                    "available_tool_count": {"type": "integer"},
                    "recommended_available_tool_count": {"type": "integer"},
                },
            },
            "tools": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": [
                        "name",
                        "source_category",
                        "scope",
                        "profiles",
                        "relevance",
                        "recommended_for_profile",
                        "available",
                        "commands",
                        "notes",
                    ],
                    "properties": {
                        "name": {"type": "string"},
                        "source_category": {"type": "string"},
                        "scope": {"type": "string"},
                        "profiles": {"type": "array", "items": {"type": "string"}},
                        "relevance": {"type": "string"},
                        "recommended_for_profile": {"type": "boolean"},
                        "available": {"type": "boolean"},
                        "commands": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "required": ["command", "path", "available"],
                                "properties": {
                                    "command": {"type": "string"},
                                    "path": {"type": ["string", "null"]},
                                    "available": {"type": "boolean"},
                                },
                            },
                        },
                        "notes": {"type": "string"},
                    },
                },
            },
        },
    }


def get_pe_direct_calls_schema() -> dict[str, object]:
    return {
        "type": "object",
        "required": ["type", "target", "image_base", "scan", "results"],
        "properties": {
            "type": {"const": "pe-direct-calls"},
            "target": {"type": "string"},
            "image_base": {"type": "string"},
            "scan": {
                "type": "object",
                "required": ["executable_section_count", "direct_call_opcode_count", "executable_sections"],
                "properties": {
                    "executable_section_count": {"type": "integer"},
                    "direct_call_opcode_count": {"type": "integer"},
                    "executable_sections": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["name", "virtual_address", "virtual_size", "raw_pointer", "raw_size"],
                            "properties": {
                                "name": {"type": "string"},
                                "virtual_address": {"type": "string"},
                                "virtual_size": {"type": "string"},
                                "raw_pointer": {"type": "string"},
                                "raw_size": {"type": "string"},
                            },
                        },
                    },
                },
            },
            "results": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["target_va", "target_rva", "hit_count", "calls"],
                    "properties": {
                        "target_va": {"type": "string"},
                        "target_rva": {"type": "string"},
                        "hit_count": {"type": "integer"},
                        "calls": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "required": [
                                    "callsite_va",
                                    "callsite_rva",
                                    "target_va",
                                    "target_rva",
                                    "rel32",
                                    "section",
                                    "raw_offset",
                                    "instruction",
                                ],
                                "properties": {
                                    "callsite_va": {"type": "string"},
                                    "callsite_rva": {"type": "string"},
                                    "target_va": {"type": "string"},
                                    "target_rva": {"type": "string"},
                                    "rel32": {"type": "integer"},
                                    "section": {"type": "string"},
                                    "raw_offset": {"type": "string"},
                                    "instruction": {"type": "string"},
                                },
                            },
                        },
                    },
                },
            },
        },
    }


def get_pe_branch_targets_schema() -> dict[str, object]:
    return {
        "type": "object",
        "required": ["type", "target", "image_base", "scan", "results"],
        "properties": {
            "type": {"const": "pe-branch-targets"},
            "target": {"type": "string"},
            "image_base": {"type": "string"},
            "scan": {
                "type": "object",
                "required": [
                    "target_count",
                    "executable_section_count",
                    "decoded_instruction_count",
                    "branch_instruction_count",
                    "branch_hit_count",
                    "runtime_function_count",
                    "function_filters",
                    "scan_range_count",
                    "scan_ranges",
                    "executable_sections",
                ],
                "properties": {
                    "target_count": {"type": "integer"},
                    "executable_section_count": {"type": "integer"},
                    "decoded_instruction_count": {"type": "integer"},
                    "branch_instruction_count": {"type": "integer"},
                    "branch_hit_count": {"type": "integer"},
                    "runtime_function_count": {"type": "integer"},
                    "function_filters": {"type": "array", "items": {"type": "string"}},
                    "scan_range_count": {"type": "integer"},
                    "scan_ranges": {"type": "array", "items": {"type": "object"}},
                    "executable_sections": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "required": ["name", "virtual_address", "virtual_size", "raw_pointer", "raw_size"],
                            "properties": {
                                "name": {"type": "string"},
                                "virtual_address": {"type": "string"},
                                "virtual_size": {"type": "string"},
                                "raw_pointer": {"type": "string"},
                                "raw_size": {"type": "string"},
                            },
                        },
                    },
                },
            },
            "results": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["target_va", "target_rva", "hit_count", "branches"],
                    "properties": {
                        "target_va": {"type": "string"},
                        "target_rva": {"type": "string"},
                        "hit_count": {"type": "integer"},
                        "branches": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "required": [
                                    "branchsite_va",
                                    "branchsite_rva",
                                    "target_va",
                                    "target_rva",
                                    "relative_offset",
                                    "branch_kind",
                                    "mnemonic",
                                    "section",
                                    "raw_offset",
                                    "raw_bytes",
                                    "instruction",
                                ],
                                "properties": {
                                    "branchsite_va": {"type": "string"},
                                    "branchsite_rva": {"type": "string"},
                                    "target_va": {"type": "string"},
                                    "target_rva": {"type": ["string", "null"]},
                                    "relative_offset": {"type": "integer"},
                                    "branch_kind": {"type": "string"},
                                    "mnemonic": {"type": "string"},
                                    "section": {"type": "string"},
                                    "raw_offset": {"type": "string"},
                                    "raw_bytes": {"type": "string"},
                                    "instruction": {"type": "string"},
                                },
                            },
                        },
                    },
                },
            },
        },
    }


def get_pe_immediates_schema() -> dict[str, object]:
    return {
        "type": "object",
        "required": ["type", "target", "image_base", "scan", "results", "warnings"],
        "properties": {
            "type": {"const": "pe-immediates"},
            "target": {"type": "string"},
            "image_base": {"type": "string"},
            "scan": {
                "type": "object",
                "required": [
                    "immediate_count",
                    "mnemonic_filter",
                    "function_filters",
                    "executable_section_count",
                    "decoded_instruction_count",
                    "immediate_instruction_count",
                    "immediate_hit_count",
                    "runtime_function_count",
                    "max_hits_per_immediate",
                    "scan_range_count",
                    "scan_ranges",
                    "executable_sections",
                ],
                "properties": {
                    "immediate_count": {"type": "integer"},
                    "mnemonic_filter": {"type": "array", "items": {"type": "string"}},
                    "function_filters": {"type": "array", "items": {"type": "string"}},
                    "executable_section_count": {"type": "integer"},
                    "decoded_instruction_count": {"type": "integer"},
                    "immediate_instruction_count": {"type": "integer"},
                    "immediate_hit_count": {"type": "integer"},
                    "runtime_function_count": {"type": "integer"},
                    "max_hits_per_immediate": {"type": "integer"},
                    "scan_range_count": {"type": "integer"},
                    "scan_ranges": {"type": "array", "items": {"type": "object"}},
                    "executable_sections": {"type": "array", "items": {"type": "object"}},
                },
            },
            "results": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": [
                        "immediate",
                        "value",
                        "hit_count",
                        "returned_hit_count",
                        "truncated_hit_count",
                        "hits",
                    ],
                    "properties": {
                        "immediate": {"type": "string"},
                        "value": {"type": "integer"},
                        "hit_count": {"type": "integer"},
                        "returned_hit_count": {"type": "integer"},
                        "truncated_hit_count": {"type": "integer"},
                        "hits": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "required": [
                                    "reference_va",
                                    "reference_rva",
                                    "section",
                                    "raw_offset",
                                    "raw_bytes",
                                    "length",
                                    "mnemonic",
                                    "operands",
                                    "instruction",
                                    "immediate",
                                    "immediate_hex",
                                ],
                                "properties": {
                                    "reference_va": {"type": "string"},
                                    "reference_rva": {"type": "string"},
                                    "section": {"type": "string"},
                                    "raw_offset": {"type": "string"},
                                    "raw_bytes": {"type": "string"},
                                    "length": {"type": "integer"},
                                    "mnemonic": {"type": "string"},
                                    "operands": {"type": "string"},
                                    "instruction": {"type": "string"},
                                    "immediate": {"type": "integer"},
                                    "immediate_hex": {"type": "string"},
                                },
                            },
                        },
                    },
                },
            },
            "warnings": {"type": "array", "items": {"type": "string"}},
        },
    }


def get_pe_callsite_registers_schema() -> dict[str, object]:
    return {
        "type": "object",
        "required": ["type", "target", "image_base", "scan", "results", "warnings"],
        "properties": {
            "type": {"const": "pe-callsite-registers"},
            "target": {"type": "string"},
            "image_base": {"type": "string"},
            "scan": {
                "type": "object",
                "required": [
                    "target_count",
                    "registers",
                    "max_backtrack_instructions",
                    "direct_call_opcode_count",
                    "runtime_function_count",
                    "instruction_window_count",
                ],
                "properties": {
                    "target_count": {"type": "integer"},
                    "registers": {"type": "array", "items": {"type": "string"}},
                    "max_backtrack_instructions": {"type": "integer"},
                    "direct_call_opcode_count": {"type": "integer"},
                    "runtime_function_count": {"type": "integer"},
                    "instruction_window_count": {"type": "integer"},
                },
            },
            "results": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["target_va", "target_rva", "hit_count", "calls"],
                    "properties": {
                        "target_va": {"type": "string"},
                        "target_rva": {"type": "string"},
                        "hit_count": {"type": "integer"},
                        "calls": {"type": "array", "items": {"type": "object"}},
                    },
                },
            },
            "warnings": {"type": "array", "items": {"type": "string"}},
        },
    }


def get_pe_address_refs_schema() -> dict[str, object]:
    return {
        "type": "object",
        "required": ["type", "target", "image_base", "scan", "results"],
        "properties": {
            "type": {"const": "pe-address-refs"},
            "target": {"type": "string"},
            "image_base": {"type": "string"},
            "scan": {
                "type": "object",
                "required": [
                    "section_filter",
                    "sections_scanned",
                    "target_count",
                    "scanned_qword_count",
                    "scanned_code_byte_count",
                    "runtime_function_count",
                    "max_hits_per_target",
                ],
                "properties": {
                    "section_filter": {"type": "array", "items": {"type": "string"}},
                    "sections_scanned": {"type": "array", "items": {"type": "object"}},
                    "target_count": {"type": "integer"},
                    "scanned_qword_count": {"type": "integer"},
                    "scanned_code_byte_count": {"type": "integer"},
                    "runtime_function_count": {"type": "integer"},
                    "max_hits_per_target": {"type": "integer"},
                },
            },
            "results": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": [
                        "target_va",
                        "target_rva",
                        "hit_count",
                        "returned_hit_count",
                        "truncated_hit_count",
                        "hits",
                    ],
                    "properties": {
                        "target_va": {"type": "string"},
                        "target_rva": {"type": "string"},
                        "hit_count": {"type": "integer"},
                        "returned_hit_count": {"type": "integer"},
                        "truncated_hit_count": {"type": "integer"},
                        "hits": {"type": "array", "items": {"type": "object"}},
                    },
                },
            },
        },
    }


def get_pe_field_refs_schema() -> dict[str, object]:
    return {
        "type": "object",
        "required": ["type", "target", "image_base", "scan", "results"],
        "properties": {
            "type": {"const": "pe-field-refs"},
            "target": {"type": "string"},
            "image_base": {"type": "string"},
            "scan": {
                "type": "object",
                "required": [
                    "section_filter",
                    "sections_scanned",
                    "offset_count",
                    "scanned_code_byte_count",
                    "runtime_function_count",
                    "max_hits_per_offset",
                    "base_register_filter",
                    "exclude_stack",
                ],
                "properties": {
                    "section_filter": {"type": "array", "items": {"type": "string"}},
                    "sections_scanned": {"type": "array", "items": {"type": "object"}},
                    "offset_count": {"type": "integer"},
                    "scanned_code_byte_count": {"type": "integer"},
                    "runtime_function_count": {"type": "integer"},
                    "max_hits_per_offset": {"type": "integer"},
                    "base_register_filter": {"type": "array", "items": {"type": "string"}},
                    "exclude_stack": {"type": "boolean"},
                },
            },
            "results": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": [
                        "offset",
                        "hit_count",
                        "returned_hit_count",
                        "truncated_hit_count",
                        "hits",
                    ],
                    "properties": {
                        "offset": {"type": "string"},
                        "hit_count": {"type": "integer"},
                        "returned_hit_count": {"type": "integer"},
                        "truncated_hit_count": {"type": "integer"},
                        "hits": {"type": "array", "items": {"type": "object"}},
                    },
                },
            },
        },
    }


def get_pe_object_field_trace_schema() -> dict[str, object]:
    return {
        "type": "object",
        "required": ["type", "target", "image_base", "scan", "functions", "warnings"],
        "properties": {
            "type": {"const": "pe-object-field-trace"},
            "target": {"type": "string"},
            "image_base": {"type": "string"},
            "scan": {
                "type": "object",
                "required": [
                    "root_offset",
                    "follow_offsets",
                    "target_offsets",
                    "explicit_functions",
                    "explicit_function_count",
                    "seeds",
                    "seed_register",
                    "seed_path",
                    "exclude_stack",
                    "max_root_hits",
                    "max_functions",
                    "max_events_per_function",
                    "root_hit_count",
                    "returned_root_hit_count",
                    "root_function_count",
                    "function_count",
                    "event_function_count",
                    "event_count",
                    "scanned_instruction_count",
                    "runtime_function_count",
                ],
                "properties": {
                    "root_offset": {"type": ["string", "null"]},
                    "follow_offsets": {"type": "array", "items": {"type": "string"}},
                    "target_offsets": {"type": "array", "items": {"type": "string"}},
                    "explicit_functions": {"type": "array", "items": {"type": "string"}},
                    "explicit_function_count": {"type": "integer"},
                    "seeds": {"type": "array", "items": {"type": "object"}},
                    "seed_register": {"type": ["string", "null"]},
                    "seed_path": {"type": "array", "items": {"type": "string"}},
                    "exclude_stack": {"type": "boolean"},
                    "max_root_hits": {"type": "integer"},
                    "max_functions": {"type": "integer"},
                    "max_events_per_function": {"type": "integer"},
                    "root_hit_count": {"type": "integer"},
                    "returned_root_hit_count": {"type": "integer"},
                    "root_function_count": {"type": "integer"},
                    "function_count": {"type": "integer"},
                    "event_function_count": {"type": "integer"},
                    "event_count": {"type": "integer"},
                    "scanned_instruction_count": {"type": "integer"},
                    "runtime_function_count": {"type": "integer"},
                },
            },
            "functions": {"type": "array", "items": {"type": "object"}},
            "warnings": {"type": "array", "items": {"type": "string"}},
        },
    }


def get_pe_function_literals_schema() -> dict[str, object]:
    return {
        "type": "object",
        "required": ["type", "target", "image_base", "scan", "functions", "warnings"],
        "properties": {
            "type": {"const": "pe-function-literals"},
            "target": {"type": "string"},
            "image_base": {"type": "string"},
            "scan": {"type": "object"},
            "functions": {"type": "array", "items": {"type": "object"}},
            "warnings": {"type": "array", "items": {"type": "string"}},
        },
    }


def get_pe_function_calls_schema() -> dict[str, object]:
    return {
        "type": "object",
        "required": ["type", "target", "image_base", "scan", "functions", "warnings"],
        "properties": {
            "type": {"const": "pe-function-calls"},
            "target": {"type": "string"},
            "image_base": {"type": "string"},
            "scan": {"type": "object"},
            "functions": {"type": "array", "items": {"type": "object"}},
            "warnings": {"type": "array", "items": {"type": "string"}},
        },
    }


def get_pe_indirect_dispatches_schema() -> dict[str, object]:
    return {
        "type": "object",
        "required": ["type", "target", "image_base", "scan", "functions", "warnings"],
        "properties": {
            "type": {"const": "pe-indirect-dispatches"},
            "target": {"type": "string"},
            "image_base": {"type": "string"},
            "scan": {"type": "object"},
            "functions": {"type": "array", "items": {"type": "object"}},
            "warnings": {"type": "array", "items": {"type": "string"}},
        },
    }


def get_pe_instructions_schema() -> dict[str, object]:
    return {
        "type": "object",
        "required": ["type", "target", "image_base", "scan", "windows", "warnings"],
        "properties": {
            "type": {"const": "pe-instructions"},
            "target": {"type": "string"},
            "image_base": {"type": "string"},
            "scan": {"type": "object"},
            "windows": {"type": "array", "items": {"type": "object"}},
            "warnings": {"type": "array", "items": {"type": "string"}},
        },
    }


def get_pe_imports_schema() -> dict[str, object]:
    return {
        "type": "object",
        "required": ["type", "target", "image_base", "scan", "imports", "warnings"],
        "properties": {
            "type": {"const": "pe-imports"},
            "target": {"type": "string"},
            "image_base": {"type": "string"},
            "scan": {"type": "object"},
            "imports": {"type": "array", "items": {"type": "object"}},
            "warnings": {"type": "array", "items": {"type": "string"}},
        },
    }


def get_pe_runtime_functions_schema() -> dict[str, object]:
    return {
        "type": "object",
        "required": ["type", "target", "image_base", "scan", "queries"],
        "properties": {
            "type": {"const": "pe-runtime-functions"},
            "target": {"type": "string"},
            "image_base": {"type": "string"},
            "scan": {"type": "object"},
            "queries": {"type": "array", "items": {"type": "object"}},
        },
    }


def get_pe_qwords_schema() -> dict[str, object]:
    return {
        "type": "object",
        "required": ["type", "target", "image_base", "reads", "warnings"],
        "properties": {
            "type": {"const": "pe-qwords"},
            "target": {"type": "string"},
            "image_base": {"type": "string"},
            "warnings": {"type": "array", "items": {"type": "string"}},
            "reads": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": [
                        "request",
                        "address",
                        "rva",
                        "section",
                        "count_requested",
                        "count_returned",
                        "qwords",
                    ],
                    "properties": {
                        "request": {"type": "string"},
                        "address": {"type": "string"},
                        "rva": {"type": "string"},
                        "section": {"type": ["string", "null"]},
                        "raw_offset": {"type": "string"},
                        "count_requested": {"type": "integer"},
                        "count_returned": {"type": "integer"},
                        "error": {"type": "string"},
                        "qwords": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "required": [
                                    "index",
                                    "address",
                                    "rva",
                                    "raw_offset",
                                    "raw_bytes",
                                    "value",
                                    "annotation",
                                ],
                                "properties": {
                                    "index": {"type": "integer"},
                                    "address": {"type": "string"},
                                    "rva": {"type": "string"},
                                    "raw_offset": {"type": "string"},
                                    "raw_bytes": {"type": "string"},
                                    "value": {"type": "string"},
                                    "annotation": {"type": "string"},
                                    "target_va": {"type": "string"},
                                    "target_rva": {"type": "string"},
                                    "target_section": {"type": "string"},
                                    "target_is_executable": {"type": "boolean"},
                                    "target_string_kind": {"type": "string"},
                                    "target_string": {"type": "string"},
                                    "target_string_length": {"type": "integer"},
                                    "target_import_hint": {"type": "integer"},
                                    "ascii_preview": {"type": "string"},
                                },
                            },
                        },
                    },
                },
            },
        },
    }


def get_pe_dwords_schema() -> dict[str, object]:
    return {
        "type": "object",
        "required": ["type", "target", "image_base", "reads", "warnings"],
        "properties": {
            "type": {"const": "pe-dwords"},
            "target": {"type": "string"},
            "image_base": {"type": "string"},
            "warnings": {"type": "array", "items": {"type": "string"}},
            "reads": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": [
                        "request",
                        "address",
                        "rva",
                        "section",
                        "count_requested",
                        "count_returned",
                        "dwords",
                    ],
                    "properties": {
                        "request": {"type": "string"},
                        "address": {"type": "string"},
                        "rva": {"type": "string"},
                        "section": {"type": ["string", "null"]},
                        "raw_offset": {"type": "string"},
                        "count_requested": {"type": "integer"},
                        "count_returned": {"type": "integer"},
                        "error": {"type": "string"},
                        "dwords": {
                            "type": "array",
                            "items": {
                                "type": "object",
                                "required": [
                                    "index",
                                    "address",
                                    "rva",
                                    "raw_offset",
                                    "raw_bytes",
                                    "value",
                                    "signed_value",
                                    "annotation",
                                ],
                                "properties": {
                                    "index": {"type": "integer"},
                                    "address": {"type": "string"},
                                    "rva": {"type": "string"},
                                    "raw_offset": {"type": "string"},
                                    "raw_bytes": {"type": "string"},
                                    "value": {"type": "string"},
                                    "signed_value": {"type": "integer"},
                                    "annotation": {"type": "string"},
                                    "target_va": {"type": "string"},
                                    "target_rva": {"type": "string"},
                                    "target_section": {"type": "string"},
                                    "target_is_executable": {"type": "boolean"},
                                    "target_string_kind": {"type": "string"},
                                    "target_string": {"type": "string"},
                                    "target_string_length": {"type": "integer"},
                                    "target_import_hint": {"type": "integer"},
                                },
                            },
                        },
                    },
                },
            },
        },
    }


def get_pe_delay_imports_schema() -> dict[str, object]:
    return {
        "type": "object",
        "required": ["type", "target", "image_base", "scan", "descriptors", "warnings"],
        "properties": {
            "type": {"const": "pe-delay-imports"},
            "target": {"type": "string"},
            "image_base": {"type": "string"},
            "scan": {"type": "object"},
            "descriptors": {"type": "array", "items": {"type": "object"}},
            "warnings": {"type": "array", "items": {"type": "string"}},
        },
    }


def get_pe_strings_schema() -> dict[str, object]:
    return {
        "type": "object",
        "required": ["type", "target", "image_base", "scan", "reads", "warnings"],
        "properties": {
            "type": {"const": "pe-strings"},
            "target": {"type": "string"},
            "image_base": {"type": "string"},
            "scan": {"type": "object"},
            "warnings": {"type": "array", "items": {"type": "string"}},
            "reads": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": [
                        "request",
                        "address",
                        "rva",
                        "section",
                        "max_bytes_requested",
                        "max_bytes_returned",
                    ],
                    "properties": {
                        "request": {"type": "string"},
                        "address": {"type": "string"},
                        "rva": {"type": "string"},
                        "section": {"type": ["string", "null"]},
                        "raw_offset": {"type": "string"},
                        "raw_bytes": {"type": "string"},
                        "max_bytes_requested": {"type": "integer"},
                        "max_bytes_returned": {"type": "integer"},
                        "decoded": {"type": "boolean"},
                        "error": {"type": "string"},
                        "ascii": {"type": ["object", "null"]},
                        "utf16le": {"type": ["object", "null"]},
                    },
                },
            },
        },
    }


def get_pe_vtable_slots_schema() -> dict[str, object]:
    return {
        "type": "object",
        "required": ["type", "target", "image_base", "scan", "tables", "warnings"],
        "properties": {
            "type": {"const": "pe-vtable-slots"},
            "target": {"type": "string"},
            "image_base": {"type": "string"},
            "scan": {"type": "object"},
            "warnings": {"type": "array", "items": {"type": "string"}},
            "tables": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": [
                        "request",
                        "address",
                        "rva",
                        "section",
                        "count_requested",
                        "count_returned",
                        "slots",
                    ],
                    "properties": {
                        "request": {"type": "string"},
                        "address": {"type": "string"},
                        "rva": {"type": "string"},
                        "section": {"type": ["string", "null"]},
                        "raw_offset": {"type": "string"},
                        "count_requested": {"type": "integer"},
                        "count_returned": {"type": "integer"},
                        "error": {"type": "string"},
                        "slots": {"type": "array", "items": {"type": "object"}},
                    },
                },
            },
        },
    }


def get_pe_resolver_invocations_schema() -> dict[str, object]:
    return {
        "type": "object",
        "required": [
            "type",
            "target",
            "image_base",
            "resolver_va",
            "resolver_rva",
            "module_table_va",
            "scan",
            "invocations",
            "warnings",
        ],
        "properties": {
            "type": {"const": "pe-resolver-invocations"},
            "target": {"type": "string"},
            "image_base": {"type": "string"},
            "resolver_va": {"type": "string"},
            "resolver_rva": {"type": "string"},
            "module_table_va": {"type": ["string", "null"]},
            "scan": {"type": "object"},
            "warnings": {"type": "array", "items": {"type": "string"}},
            "invocations": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": [
                        "kind",
                        "callsite_va",
                        "callsite_rva",
                        "target_va",
                        "target_rva",
                        "instruction",
                        "function",
                        "register_setup",
                    ],
                    "properties": {
                        "kind": {"type": "string"},
                        "callsite_va": {"type": "string"},
                        "callsite_rva": {"type": "string"},
                        "target_va": {"type": "string"},
                        "target_rva": {"type": "string"},
                        "rel32": {"type": "integer"},
                        "section": {"type": "string"},
                        "raw_offset": {"type": "string"},
                        "instruction": {"type": "string"},
                        "function": {"type": "object"},
                        "register_setup": {"type": "object"},
                        "selector": {"type": "integer"},
                        "selector_hex": {"type": "string"},
                        "api_name_va": {"type": "string"},
                        "api_name": {"type": "string"},
                        "api_name_kind": {"type": "string"},
                        "module_index_start_va": {"type": "string"},
                        "module_index_end_va": {"type": "string"},
                        "module_index_count": {"type": "integer"},
                        "module_index_truncated": {"type": "boolean"},
                        "module_index_error": {"type": "string"},
                        "module_indices": {
                            "type": "array",
                            "items": {"type": "object"},
                        },
                    },
                },
            },
        },
    }


def get_pe_rtti_type_descriptors_schema() -> dict[str, object]:
    return {
        "type": "object",
        "required": ["type", "target", "image_base", "descriptors", "warnings"],
        "properties": {
            "type": {"const": "pe-rtti-type-descriptors"},
            "target": {"type": "string"},
            "image_base": {"type": "string"},
            "warnings": {"type": "array", "items": {"type": "string"}},
            "descriptors": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": [
                        "request",
                        "address",
                        "rva",
                        "section",
                    ],
                    "properties": {
                        "request": {"type": "string"},
                        "address": {"type": "string"},
                        "rva": {"type": "string"},
                        "section": {"type": ["string", "null"]},
                        "raw_offset": {"type": "string"},
                        "vfptr": {"type": "object"},
                        "spare": {"type": "string"},
                        "name_address": {"type": "string"},
                        "name_rva": {"type": "string"},
                        "name_raw_offset": {"type": "string"},
                        "decorated_name": {"type": "string"},
                        "name_length": {"type": "integer"},
                        "parsed_name": {"type": "object"},
                        "looks_like_msvc_type_descriptor": {"type": "boolean"},
                        "error": {"type": "string"},
                    },
                },
            },
        },
    }


def get_pe_provider_descriptors_schema() -> dict[str, object]:
    return {
        "type": "object",
        "required": ["type", "target", "image_base", "descriptors", "warnings"],
        "properties": {
            "type": {"const": "pe-provider-descriptors"},
            "target": {"type": "string"},
            "image_base": {"type": "string"},
            "warnings": {"type": "array", "items": {"type": "string"}},
            "descriptors": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": [
                        "request",
                        "address",
                        "rva",
                        "section",
                        "slot_count_requested",
                        "slots",
                    ],
                    "properties": {
                        "request": {"type": "string"},
                        "address": {"type": "string"},
                        "rva": {"type": "string"},
                        "section": {"type": ["string", "null"]},
                        "raw_offset": {"type": "string"},
                        "slot_count_requested": {"type": "integer"},
                        "slot_count_returned": {"type": "integer"},
                        "slots": {"type": "array", "items": {"type": "object"}},
                        "summary": {"type": "object"},
                        "error": {"type": "string"},
                    },
                },
            },
        },
    }


def get_pe_provider_descriptor_scan_schema() -> dict[str, object]:
    return {
        "type": "object",
        "required": [
            "type",
            "target",
            "image_base",
            "scan",
            "descriptors",
            "reference_scan",
            "reference_clusters",
            "warnings",
        ],
        "properties": {
            "type": {"const": "pe-provider-descriptor-scan"},
            "target": {"type": "string"},
            "image_base": {"type": "string"},
            "scan": {"type": "object"},
            "descriptors": {"type": "array", "items": {"type": "object"}},
            "reference_scan": {"type": ["object", "null"]},
            "reference_clusters": {"type": ["object", "null"]},
            "warnings": {"type": "array", "items": {"type": "string"}},
        },
    }


def get_pe_provider_descriptor_clusters_schema() -> dict[str, object]:
    return {
        "type": "object",
        "required": ["type", "target", "image_base", "source_type", "scan", "summary", "clusters"],
        "properties": {
            "type": {"const": "pe-provider-descriptor-clusters"},
            "target": {"type": ["string", "null"]},
            "image_base": {"type": ["string", "null"]},
            "source_type": {"type": ["string", "null"]},
            "scan": {"type": "object"},
            "summary": {"type": "object"},
            "clusters": {"type": "array", "items": {"type": "object"}},
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


def get_js5_opcode_probe_schema() -> dict[str, object]:
    return _build_js5_probe_schema(
        required=[
            "kind",
            "manifest_path",
            "export_root",
            "raw_opcode",
            "raw_opcode_hex",
            "filters",
            "hit_count",
            "script_count",
            "archive_key_count",
            "sample_hits",
        ],
        properties={
            "hit_count": {"type": "integer"},
            "script_count": {"type": "integer"},
            "archive_key_count": {"type": "integer"},
            "immediate_kind_counts": {"type": "object"},
            "semantic_label_counts": {"type": "object"},
            "semantic_family_counts": {"type": "object"},
            "operand_signature_counts": {"type": "object"},
            "contextual_hint_applied_count": {"type": "integer"},
            "contextual_hint_match_prefix_operand_signature_counts": {"type": "object"},
            "hint_applied_survivor_delta_counts": {"type": "object"},
            "behavior_counts": {"type": "object"},
            "pseudocode_status_counts": {"type": "object"},
            "blocking_kind_counts": {"type": "object"},
            "frontier_reason_counts": {"type": "object"},
            "blocked_frontier_observation_count": {"type": "integer"},
            "blocked_frontier_observation_sample": {"type": "array", "items": {"type": "object"}},
            "blocked_frontier_clusters": {"type": "array", "items": {"type": "object"}},
            "blocked_frontier_subtype_candidate_count": {"type": "integer"},
            "blocked_frontier_subtype_candidates": {"type": "array", "items": {"type": "object"}},
            "blocked_frontier_bounded_hypothesis_count": {"type": "integer"},
            "blocked_frontier_bounded_hypotheses": {"type": "object"},
            "blocked_frontier_terminal_cluster_count": {"type": "integer"},
            "blocked_frontier_terminal_clusters": {"type": "array", "items": {"type": "object"}},
            "artifact_entries": {"type": "array", "items": {"type": "object"}},
            "sample_hits": {"type": "array", "items": {"type": "object"}},
        },
    )


def get_js5_opcode_interior_probe_schema() -> dict[str, object]:
    return _build_js5_probe_schema(
        required=[
            "kind",
            "manifest_path",
            "export_root",
            "raw_opcode",
            "raw_opcode_hex",
            "filters",
            "hit_count",
            "hits",
        ],
        properties={
            "hit_count": {"type": "integer"},
            "pre_operand_signature_counts": {"type": "object"},
            "post_operand_signature_counts": {"type": "object"},
            "required_input_delta_counts": {"type": "object"},
            "survivor_delta_counts": {"type": "object"},
            "hits": {"type": "array", "items": {"type": "object"}},
        },
    )


def get_js5_opcode_subtypes_schema() -> dict[str, object]:
    return _build_js5_probe_schema(
        required=[
            "kind",
            "manifest_path",
            "export_root",
            "raw_opcode",
            "raw_opcode_hex",
            "filters",
            "scope",
            "blocked_frontier_observation_count",
            "blocked_frontier_subtype_candidate_count",
            "blocked_frontier_subtype_candidates",
        ],
        properties={
            "scope": {"type": "string"},
            "blocked_frontier_observation_count": {"type": "integer"},
            "blocked_frontier_subtype_candidate_count": {"type": "integer"},
            "blocked_frontier_subtype_candidates": {"type": "array", "items": {"type": "object"}},
            "blocked_frontier_bounded_hypothesis_count": {"type": "integer"},
            "blocked_frontier_bounded_hypotheses": {"type": "object"},
            "blocked_frontier_terminal_cluster_count": {"type": "integer"},
            "blocked_frontier_terminal_clusters": {"type": "array", "items": {"type": "object"}},
        },
    )


def get_js5_branch_clusters_schema() -> dict[str, object]:
    return _build_js5_probe_schema(
        required=[
            "kind",
            "manifest_path",
            "export_root",
            "raw_opcode",
            "raw_opcode_hex",
            "filters",
            "hit_count",
            "script_count",
            "structural_clusters",
            "sample_observations",
        ],
        properties={
            "hit_count": {"type": "integer"},
            "script_count": {"type": "integer"},
            "quality_counts": {"type": "object"},
            "noise_reason_counts": {"type": "object"},
            "pseudocode_status_counts": {"type": "object"},
            "immediate_kind_counts": {"type": "object"},
            "immediate_value_counts": {"type": "object"},
            "structural_observation_count": {"type": "integer"},
            "noise_observation_count": {"type": "integer"},
            "structural_cluster_count": {"type": "integer"},
            "structural_clusters": {"type": "array", "items": {"type": "object"}},
            "noise_cluster_count": {"type": "integer"},
            "noise_clusters": {"type": "array", "items": {"type": "object"}},
            "sample_observations": {"type": "array", "items": {"type": "object"}},
        },
    )


def get_js5_pseudocode_blockers_schema() -> dict[str, object]:
    return {
        "type": "object",
        "required": [
            "kind",
            "manifest_path",
            "export_root",
            "artifact_status",
            "profile_count",
            "ready_profile_count",
            "blocked_profile_count",
            "blocking_kind_counts",
        ],
        "properties": {
            "kind": {"type": "string"},
            "manifest_path": {"type": "string"},
            "export_root": {"type": "string"},
            "blocker_summary_path": {"type": ["string", "null"]},
            "artifact_status": {"type": "string"},
            "profile_count": {"type": "integer"},
            "ready_profile_count": {"type": "integer"},
            "blocked_profile_count": {"type": "integer"},
            "blocker_opcode_count": {"type": "integer"},
            "tail_last_opcode_count": {"type": "integer"},
            "tail_next_opcode_count": {"type": "integer"},
            "tail_hint_opcode_count": {"type": "integer"},
            "instruction_budget_desync_count": {"type": "integer"},
            "instruction_budget_top_suspect_opcode_count": {"type": "integer"},
            "control_group_diff_count": {"type": "integer"},
            "control_group_leak_candidate_count": {"type": "integer"},
            "blocking_kind_counts": {"type": "object"},
            "frontier_reason_counts": {"type": "object"},
            "tail_status_counts": {"type": "object"},
            "ready_key_sample": {"type": "array", "items": {"type": "object"}},
            "blocked_key_sample": {"type": "array", "items": {"type": "object"}},
            "control_group_ready_key_sample": {"type": "array", "items": {"type": "object"}},
            "opcodes": {"type": "array", "items": {"type": "object"}},
            "tail_last_opcodes": {"type": "array", "items": {"type": "object"}},
            "tail_next_opcodes": {"type": "array", "items": {"type": "object"}},
            "tail_hint_opcodes": {"type": "array", "items": {"type": "object"}},
            "instruction_budget_top_suspect_opcodes": {"type": "array", "items": {"type": "object"}},
            "control_group_leak_candidates": {"type": "array", "items": {"type": "object"}},
            "blocked_profile_sample": {"type": "array", "items": {"type": "object"}},
        },
    }


def get_analyze_request_schema() -> dict[str, object]:
    return _build_request_schema(
        required=["target"],
        properties={
            "target": {"type": "string"},
            "max_strings": {"type": "integer"},
        },
    )


def get_scan_request_schema() -> dict[str, object]:
    return _build_request_schema(
        required=["target"],
        properties={
            "target": {"type": "string"},
            "max_files": {"type": "integer"},
            "max_file_mb": {"type": "integer"},
            "max_strings": {"type": "integer"},
            "include_globs": {"type": "array", "items": {"type": "string"}},
            "exclude_globs": {"type": "array", "items": {"type": "string"}},
            "workers": {"type": "integer"},
        },
    )


def get_diff_request_schema() -> dict[str, object]:
    return _build_request_schema(
        required=["base", "head"],
        properties={
            "base": {"type": "string"},
            "head": {"type": "string"},
            "max_strings": {"type": "integer"},
            "max_files": {"type": "integer"},
            "max_file_mb": {"type": "integer"},
        },
    )


def get_js5_export_request_schema() -> dict[str, object]:
    return _build_request_schema(
        required=["target", "output_dir"],
        properties={
            "target": {"type": "string"},
            "output_dir": {"type": "string"},
            "tables": {"type": "array", "items": {"type": "string"}},
            "keys": {"type": "array", "items": {"type": "integer"}},
            "limit": {"type": "integer"},
            "include_container": {"type": "boolean"},
            "max_decoded_mb": {"type": "integer"},
        },
    )


def get_js5_opcode_probe_request_schema() -> dict[str, object]:
    return _build_request_schema(
        required=["source", "opcode"],
        properties={
            "source": {"type": "string"},
            "opcode": {"type": "integer"},
            "table": {"type": "string"},
            "key": {"type": "integer"},
            "file_id": {"type": "integer"},
            "max_hits": {"type": "integer"},
        },
    )


def get_js5_opcode_interior_probe_request_schema() -> dict[str, object]:
    return _build_request_schema(
        required=["source", "opcode"],
        properties={
            "source": {"type": "string"},
            "opcode": {"type": "integer"},
            "table": {"type": "string"},
            "keys": {"type": "array", "items": {"type": "integer"}},
            "file_id": {"type": "integer"},
            "max_hits": {"type": "integer"},
            "ready_only": {"type": "boolean"},
        },
    )


def get_js5_opcode_subtypes_request_schema() -> dict[str, object]:
    return _build_request_schema(
        required=["source", "opcode"],
        properties={
            "source": {"type": "string"},
            "opcode": {"type": "integer"},
            "table": {"type": "string"},
            "key": {"type": "integer"},
            "file_id": {"type": "integer"},
            "max_hits": {"type": "integer"},
        },
    )


def get_js5_branch_clusters_request_schema() -> dict[str, object]:
    return _build_request_schema(
        required=["source", "opcode"],
        properties={
            "source": {"type": "string"},
            "opcode": {"type": "integer"},
            "table": {"type": "string"},
            "key": {"type": "integer"},
            "file_id": {"type": "integer"},
            "max_hits": {"type": "integer"},
        },
    )


def get_js5_pseudocode_blockers_request_schema() -> dict[str, object]:
    return _build_request_schema(
        required=["source"],
        properties={
            "source": {"type": "string"},
            "max_sample": {"type": "integer"},
        },
    )


def get_catalog_ingest_request_schema() -> dict[str, object]:
    return _build_request_schema(
        required=["source"],
        properties={
            "source": {"type": "string"},
            "db": {"type": "string"},
            "max_strings": {"type": "integer"},
            "max_files": {"type": "integer"},
            "max_file_mb": {"type": "integer"},
        },
    )


def get_catalog_search_request_schema() -> dict[str, object]:
    return _build_request_schema(
        required=[],
        properties={
            "db": {"type": "string"},
            "signature": {"type": "string"},
            "engine": {"type": "string"},
            "tag": {"type": "string"},
            "path_contains": {"type": "string"},
            "sha256": {"type": "string"},
            "min_findings": {"type": "integer"},
            "limit": {"type": "integer"},
        },
    )


def _iter_schema_registry_entries() -> tuple[dict[str, object], ...]:
    return (
        {
            "kind": "report",
            "path": "/schema/report",
            "description": "Stable JSON schema for analyze reports.",
            "factory": get_report_schema,
        },
        {
            "kind": "scan-index",
            "path": "/schema/scan-index",
            "description": "Stable JSON schema for batch scan indexes.",
            "factory": get_scan_index_schema,
        },
        {
            "kind": "diff",
            "path": "/schema/diff",
            "description": "Stable JSON schema for report and raw-target diffs.",
            "factory": get_diff_schema,
        },
        {
            "kind": "catalog-search",
            "path": "/schema/catalog-search",
            "description": "Stable JSON schema for catalog search results.",
            "factory": get_catalog_search_schema,
        },
        {
            "kind": "catalog-ingests",
            "path": "/schema/catalog-ingests",
            "description": "Stable JSON schema for recent catalog ingest listings.",
            "factory": get_catalog_ingests_schema,
        },
        {
            "kind": "external-target-index",
            "path": "/schema/external-target-index",
            "description": "Stable JSON schema for indexed external-target artifact trails.",
            "factory": get_external_target_index_schema,
        },
        {
            "kind": "external-tool-inventory",
            "path": "/schema/external-tool-inventory",
            "description": "Stable JSON schema for trusted local reverse-engineering tool availability.",
            "factory": get_external_tool_inventory_schema,
        },
        {
            "kind": "pe-direct-calls",
            "path": "/schema/pe-direct-calls",
            "description": "Stable JSON schema for PE direct CALL rel32 target scans.",
            "factory": get_pe_direct_calls_schema,
        },
        {
            "kind": "pe-branch-targets",
            "path": "/schema/pe-branch-targets",
            "description": "Stable JSON schema for PE branch-target scans.",
            "factory": get_pe_branch_targets_schema,
        },
        {
            "kind": "pe-immediates",
            "path": "/schema/pe-immediates",
            "description": "Stable JSON schema for decoded PE immediate-constant scans.",
            "factory": get_pe_immediates_schema,
        },
        {
            "kind": "pe-callsite-registers",
            "path": "/schema/pe-callsite-registers",
            "description": "Stable JSON schema for PE direct-call register setup recovery.",
            "factory": get_pe_callsite_registers_schema,
        },
        {
            "kind": "pe-address-refs",
            "path": "/schema/pe-address-refs",
            "description": "Stable JSON schema for PE address reference scans.",
            "factory": get_pe_address_refs_schema,
        },
        {
            "kind": "pe-field-refs",
            "path": "/schema/pe-field-refs",
            "description": "Stable JSON schema for PE structure-field displacement reference scans.",
            "factory": get_pe_field_refs_schema,
        },
        {
            "kind": "pe-object-field-trace",
            "path": "/schema/pe-object-field-trace",
            "description": "Stable JSON schema for PE local object-field path traces.",
            "factory": get_pe_object_field_trace_schema,
        },
        {
            "kind": "pe-function-literals",
            "path": "/schema/pe-function-literals",
            "description": "Stable JSON schema for PE function string literal reference scans.",
            "factory": get_pe_function_literals_schema,
        },
        {
            "kind": "pe-function-calls",
            "path": "/schema/pe-function-calls",
            "description": "Stable JSON schema for PE function call-instruction scans.",
            "factory": get_pe_function_calls_schema,
        },
        {
            "kind": "pe-indirect-dispatches",
            "path": "/schema/pe-indirect-dispatches",
            "description": "Stable JSON schema for PE indirect-call dispatch origin recovery.",
            "factory": get_pe_indirect_dispatches_schema,
        },
        {
            "kind": "pe-instructions",
            "path": "/schema/pe-instructions",
            "description": "Stable JSON schema for lightweight PE instruction-window scans.",
            "factory": get_pe_instructions_schema,
        },
        {
            "kind": "pe-imports",
            "path": "/schema/pe-imports",
            "description": "Stable JSON schema for PE import descriptor and IAT entry scans.",
            "factory": get_pe_imports_schema,
        },
        {
            "kind": "pe-runtime-functions",
            "path": "/schema/pe-runtime-functions",
            "description": "Stable JSON schema for PE .pdata runtime-function lookup results.",
            "factory": get_pe_runtime_functions_schema,
        },
        {
            "kind": "pe-qwords",
            "path": "/schema/pe-qwords",
            "description": "Stable JSON schema for PE mapped qword readbacks.",
            "factory": get_pe_qwords_schema,
        },
        {
            "kind": "pe-dwords",
            "path": "/schema/pe-dwords",
            "description": "Stable JSON schema for PE mapped dword readbacks.",
            "factory": get_pe_dwords_schema,
        },
        {
            "kind": "pe-delay-imports",
            "path": "/schema/pe-delay-imports",
            "description": "Stable JSON schema for PE delay-import descriptor readbacks.",
            "factory": get_pe_delay_imports_schema,
        },
        {
            "kind": "pe-strings",
            "path": "/schema/pe-strings",
            "description": "Stable JSON schema for PE mapped C-string readbacks.",
            "factory": get_pe_strings_schema,
        },
        {
            "kind": "pe-vtable-slots",
            "path": "/schema/pe-vtable-slots",
            "description": "Stable JSON schema for PE vtable slot readbacks with .pdata attribution.",
            "factory": get_pe_vtable_slots_schema,
        },
        {
            "kind": "pe-resolver-invocations",
            "path": "/schema/pe-resolver-invocations",
            "description": "Stable JSON schema for PE resolver wrapper invocation summaries.",
            "factory": get_pe_resolver_invocations_schema,
        },
        {
            "kind": "pe-rtti-type-descriptors",
            "path": "/schema/pe-rtti-type-descriptors",
            "description": "Stable JSON schema for PE MSVC RTTI TypeDescriptor readbacks.",
            "factory": get_pe_rtti_type_descriptors_schema,
        },
        {
            "kind": "pe-provider-descriptors",
            "path": "/schema/pe-provider-descriptors",
            "description": "Stable JSON schema for PE provider descriptor/vtable row summaries.",
            "factory": get_pe_provider_descriptors_schema,
        },
        {
            "kind": "pe-provider-descriptor-scan",
            "path": "/schema/pe-provider-descriptor-scan",
            "description": "Stable JSON schema for PE provider descriptor row scan results.",
            "factory": get_pe_provider_descriptor_scan_schema,
        },
        {
            "kind": "pe-provider-descriptor-clusters",
            "path": "/schema/pe-provider-descriptor-clusters",
            "description": "Stable JSON schema for compact PE provider descriptor setup-function clusters.",
            "factory": get_pe_provider_descriptor_clusters_schema,
        },
        {
            "kind": "js5-manifest",
            "path": "/schema/js5-manifest",
            "description": "Stable JSON schema for js5-export manifests.",
            "factory": get_js5_manifest_schema,
        },
        {
            "kind": "js5-opcode-probe",
            "path": "/schema/js5-opcode-probe",
            "description": "Stable JSON schema for JS5 clientscript opcode probe results.",
            "factory": get_js5_opcode_probe_schema,
        },
        {
            "kind": "js5-opcode-interior-probe",
            "path": "/schema/js5-opcode-interior-probe",
            "description": "Stable JSON schema for JS5 interior opcode probe results.",
            "factory": get_js5_opcode_interior_probe_schema,
        },
        {
            "kind": "js5-opcode-subtypes",
            "path": "/schema/js5-opcode-subtypes",
            "description": "Stable JSON schema for JS5 opcode subtype summaries.",
            "factory": get_js5_opcode_subtypes_schema,
        },
        {
            "kind": "js5-branch-clusters",
            "path": "/schema/js5-branch-clusters",
            "description": "Stable JSON schema for JS5 branch cluster probe results.",
            "factory": get_js5_branch_clusters_schema,
        },
        {
            "kind": "js5-pseudocode-blockers",
            "path": "/schema/js5-pseudocode-blockers",
            "description": "Stable JSON schema for JS5 pseudocode blocker summaries.",
            "factory": get_js5_pseudocode_blockers_schema,
        },
        {
            "kind": "analyze-request",
            "path": "/schema/analyze-request",
            "description": "JSON request body schema for POST /analyze.",
            "factory": get_analyze_request_schema,
        },
        {
            "kind": "scan-request",
            "path": "/schema/scan-request",
            "description": "JSON request body schema for POST /scan.",
            "factory": get_scan_request_schema,
        },
        {
            "kind": "diff-request",
            "path": "/schema/diff-request",
            "description": "JSON request body schema for POST /diff.",
            "factory": get_diff_request_schema,
        },
        {
            "kind": "js5-export-request",
            "path": "/schema/js5-export-request",
            "description": "JSON request body schema for POST /js5/export.",
            "factory": get_js5_export_request_schema,
        },
        {
            "kind": "js5-opcode-probe-request",
            "path": "/schema/js5-opcode-probe-request",
            "description": "JSON request body schema for POST /js5/opcode-probe.",
            "factory": get_js5_opcode_probe_request_schema,
        },
        {
            "kind": "js5-opcode-interior-probe-request",
            "path": "/schema/js5-opcode-interior-probe-request",
            "description": "JSON request body schema for POST /js5/opcode-interior-probe.",
            "factory": get_js5_opcode_interior_probe_request_schema,
        },
        {
            "kind": "js5-opcode-subtypes-request",
            "path": "/schema/js5-opcode-subtypes-request",
            "description": "JSON request body schema for POST /js5/opcode-subtypes.",
            "factory": get_js5_opcode_subtypes_request_schema,
        },
        {
            "kind": "js5-branch-clusters-request",
            "path": "/schema/js5-branch-clusters-request",
            "description": "JSON request body schema for POST /js5/branch-clusters.",
            "factory": get_js5_branch_clusters_request_schema,
        },
        {
            "kind": "js5-pseudocode-blockers-request",
            "path": "/schema/js5-pseudocode-blockers-request",
            "description": "JSON request body schema for POST /js5/pseudocode-blockers.",
            "factory": get_js5_pseudocode_blockers_request_schema,
        },
        {
            "kind": "catalog-ingest-request",
            "path": "/schema/catalog-ingest-request",
            "description": "JSON request body schema for POST /catalog/ingest.",
            "factory": get_catalog_ingest_request_schema,
        },
        {
            "kind": "catalog-search-request",
            "path": "/schema/catalog-search-request",
            "description": "JSON request body schema for POST /catalog/search.",
            "factory": get_catalog_search_request_schema,
        },
    )


def get_schema(kind: str) -> dict[str, object]:
    target_kind = str(kind)
    for entry in _iter_schema_registry_entries():
        if entry["kind"] == target_kind:
            factory = entry["factory"]
            return factory()
    raise KeyError(target_kind)


def get_schema_kinds() -> tuple[str, ...]:
    return tuple(str(entry["kind"]) for entry in _iter_schema_registry_entries())


def get_schema_registry() -> dict[str, object]:
    schemas = [
        {
            "kind": str(entry["kind"]),
            "path": str(entry["path"]),
            "description": str(entry["description"]),
        }
        for entry in _iter_schema_registry_entries()
    ]
    return {
        "type": "schema-registry",
        "count": len(schemas),
        "schemas": schemas,
    }
