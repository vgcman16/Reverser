from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path

from reverser import __version__
from reverser.api import run_api_server
from reverser.analysis.archive_export import export_archive
from reverser.analysis.external_targets import build_external_target_index
from reverser.catalog import (
    catalog_stats,
    ingest_into_catalog,
    init_catalog,
    list_catalog_ingests,
    search_catalog,
)
from reverser.analysis.diffing import diff_artifacts, load_or_generate_artifact
from reverser.analysis.exporters.csv_exporter import export_rows_csv, export_scan_csv
from reverser.analysis.exporters.index_exporter import export_scan_json, export_scan_ndjson
from reverser.analysis.js5 import (
    export_js5_cache,
    probe_js5_export_branch_clusters,
    probe_js5_export_interior_opcode,
    probe_js5_export_opcode,
    probe_js5_export_opcode_subtypes,
    probe_js5_export_pseudocode_blockers,
)
from reverser.analysis.pe_address_refs import find_pe_address_refs
from reverser.analysis.pe_callsite_registers import find_pe_callsite_registers
from reverser.analysis.pe_direct_calls import find_pe_direct_calls
from reverser.analysis.pe_function_literals import find_pe_function_literals
from reverser.analysis.pe_function_calls import find_pe_function_calls
from reverser.analysis.pe_imports import read_pe_imports
from reverser.analysis.pe_instructions import find_pe_instructions
from reverser.analysis.pe_provider_descriptors import (
    compact_provider_descriptor_clusters,
    provider_descriptor_cluster_literal_payload,
    provider_descriptor_cluster_rows,
    scan_pe_provider_descriptors,
    summarize_pe_provider_descriptors,
)
from reverser.analysis.pe_qwords import read_pe_qwords
from reverser.analysis.pe_resolver_invocations import find_pe_resolver_invocations
from reverser.analysis.pe_rtti import read_pe_rtti_type_descriptors
from reverser.analysis.pe_runtime_functions import find_pe_runtime_functions
from reverser.analysis.pe_vtable_slots import read_pe_vtable_slots
from reverser.analysis.exporters.object_exporter import export_object_json
from reverser.analysis.exporters.json_exporter import export_json
from reverser.analysis.exporters.markdown_exporter import export_markdown
from reverser.analysis.orchestrator import AnalysisEngine
from reverser.analysis.scan import scan_tree
from reverser.analysis.tool_inventory import build_external_tool_inventory
from reverser.schema import (
    get_schema,
    get_schema_kinds,
    get_schema_registry,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reverser",
        description="Authorized binary and game-file analysis workbench.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser("analyze", help="Analyze a file or directory.")
    analyze.add_argument("target", help="Path to a file or directory to inspect.")
    analyze.add_argument("--json-out", type=Path, help="Optional JSON report destination.")
    analyze.add_argument("--md-out", type=Path, help="Optional Markdown report destination.")
    analyze.add_argument("--max-strings", type=int, default=200, help="Maximum unique strings to retain.")
    analyze.add_argument(
        "--fail-on-errors",
        action="store_true",
        help="Return a non-zero exit code if any analyzer records errors.",
    )
    analyze.add_argument(
        "--stdout-format",
        choices=("json", "pretty"),
        default="json",
        help="Machine-readable JSON or human-readable pretty JSON on stdout.",
    )

    subparsers.add_parser("gui", help="Launch the desktop GUI.")
    subparsers.add_parser("analyzers", help="List the built-in analyzers and their order.")
    api = subparsers.add_parser("api", help="Run a local JSON API for automation and agent workflows.")
    api.add_argument("--host", default="127.0.0.1", help="Bind address. Defaults to localhost only.")
    api.add_argument("--port", type=int, default=8765, help="Port to listen on.")

    catalog_init = subparsers.add_parser("catalog-init", help="Initialize the local investigation catalog.")
    catalog_init.add_argument("--db", type=Path, help="Optional SQLite database path.")

    catalog_ingest = subparsers.add_parser("catalog-ingest", help="Analyze or ingest an artifact into the catalog.")
    catalog_ingest.add_argument("source", help="Raw file/folder or existing report/index JSON.")
    catalog_ingest.add_argument("--db", type=Path, help="Optional SQLite database path.")
    catalog_ingest.add_argument("--max-files", type=int, default=250, help="Maximum files when ingesting raw folders.")
    catalog_ingest.add_argument("--max-file-mb", type=int, default=256, help="Maximum file size for raw folder ingest.")
    catalog_ingest.add_argument("--max-strings", type=int, default=200, help="Maximum unique strings for raw targets.")

    catalog_search_cmd = subparsers.add_parser("catalog-search", help="Search the local investigation catalog.")
    catalog_search_cmd.add_argument("--db", type=Path, help="Optional SQLite database path.")
    catalog_search_cmd.add_argument("--signature", help="Filter by detected signature.")
    catalog_search_cmd.add_argument("--engine", help="Filter by engine label.")
    catalog_search_cmd.add_argument("--tag", help="Filter by summary tag.")
    catalog_search_cmd.add_argument("--path-contains", help="Case-insensitive path substring match.")
    catalog_search_cmd.add_argument("--sha256", help="Filter by SHA-256 hash.")
    catalog_search_cmd.add_argument("--min-findings", type=int, help="Minimum finding count.")
    catalog_search_cmd.add_argument("--limit", type=int, default=50, help="Maximum results to return.")
    catalog_search_cmd.add_argument("--csv-out", type=Path, help="Optional destination for flat CSV search results.")

    catalog_ingests_cmd = subparsers.add_parser("catalog-ingests", help="List recent catalog ingests.")
    catalog_ingests_cmd.add_argument("--db", type=Path, help="Optional SQLite database path.")
    catalog_ingests_cmd.add_argument("--limit", type=int, default=20, help="Maximum ingest records to return.")

    catalog_stats_cmd = subparsers.add_parser("catalog-stats", help="Show catalog summary statistics.")
    catalog_stats_cmd.add_argument("--db", type=Path, help="Optional SQLite database path.")

    scan = subparsers.add_parser("scan", help="Batch-scan a file tree and emit an index.")
    scan.add_argument("target", help="Root directory or file to scan.")
    scan.add_argument("--reports-dir", type=Path, help="Optional destination for per-target JSON reports.")
    scan.add_argument(
        "--include-markdown",
        action="store_true",
        help="Write Markdown reports alongside JSON reports when --reports-dir is used.",
    )
    scan.add_argument("--csv-out", type=Path, help="Optional destination for a flat CSV scan export.")
    scan.add_argument("--index-json", type=Path, help="Optional destination for the scan index JSON.")
    scan.add_argument("--index-ndjson", type=Path, help="Optional destination for per-entry NDJSON.")
    scan.add_argument("--max-files", type=int, default=250, help="Maximum number of files to analyze in a tree.")
    scan.add_argument("--workers", type=int, help="Optional parallel worker count for batch scanning.")
    scan.add_argument(
        "--max-file-mb",
        type=int,
        default=256,
        help="Skip files larger than this size when batch scanning directories.",
    )
    scan.add_argument(
        "--include-glob",
        action="append",
        default=[],
        help="Optional glob to include, for example *.exe or */Binaries/*.pak. Repeatable.",
    )
    scan.add_argument(
        "--exclude-glob",
        action="append",
        default=[],
        help="Optional glob to exclude. Repeatable.",
    )
    scan.add_argument("--max-strings", type=int, default=200, help="Maximum unique strings to retain per file.")
    scan.add_argument(
        "--stdout-format",
        choices=("json", "pretty"),
        default="json",
        help="Machine-readable JSON or human-readable pretty JSON on stdout.",
    )

    external_target_index = subparsers.add_parser(
        "external-target-index",
        help="Summarize external-target artifact trails into a stable JSON index.",
    )
    external_target_index.add_argument(
        "root",
        type=Path,
        help="Directory containing per-target external artifact folders.",
    )
    external_target_index.add_argument(
        "--json-out",
        type=Path,
        help="Optional destination for the external-target index JSON.",
    )
    external_target_index.add_argument(
        "--stdout-format",
        choices=("json", "pretty"),
        default="json",
        help="Machine-readable JSON or human-readable pretty JSON on stdout.",
    )

    external_tool_inventory = subparsers.add_parser(
        "external-tool-inventory",
        help="Detect trusted local reverse-engineering tools from the curated external tool catalog.",
    )
    external_tool_inventory.add_argument(
        "--profile",
        default="win64-pe",
        help="Workflow profile to prioritize, such as win64-pe, android-apk, native, mobile, or all.",
    )
    external_tool_inventory.add_argument("--json-out", type=Path, help="Optional destination for the inventory JSON.")
    external_tool_inventory.add_argument(
        "--stdout-format",
        choices=("json", "pretty"),
        default="json",
        help="Machine-readable JSON or human-readable pretty JSON on stdout.",
    )

    pe_direct_calls = subparsers.add_parser(
        "pe-direct-calls",
        help="Scan a PE image for raw x86/x64 direct CALL rel32 sites to one or more targets.",
    )
    pe_direct_calls.add_argument("target", type=Path, help="Path to the PE file to scan.")
    pe_direct_calls.add_argument(
        "address",
        nargs="+",
        help="Target VA or RVA to find, for example 0x140679500 or 0x679500.",
    )
    pe_direct_calls.add_argument("--json-out", type=Path, help="Optional destination for the callsite JSON.")
    pe_direct_calls.add_argument(
        "--stdout-format",
        choices=("json", "pretty"),
        default="json",
        help="Machine-readable JSON or human-readable pretty JSON on stdout.",
    )

    pe_callsite_registers = subparsers.add_parser(
        "pe-callsite-registers",
        help="Recover simple static register setup before PE direct callsites.",
    )
    pe_callsite_registers.add_argument("target", type=Path, help="Path to the PE file to scan.")
    pe_callsite_registers.add_argument(
        "address",
        nargs="+",
        help="Direct-call target VA or RVA to inspect, for example 0x1407B8460.",
    )
    pe_callsite_registers.add_argument(
        "--register",
        action="append",
        default=[],
        help="Argument register to recover, such as RCX, RDX, R8, or R9. Repeatable; defaults to all four.",
    )
    pe_callsite_registers.add_argument(
        "--max-backtrack-instructions",
        type=int,
        default=16,
        help="Maximum decoded instructions to inspect before each direct callsite.",
    )
    pe_callsite_registers.add_argument("--json-out", type=Path, help="Optional destination for the register JSON.")
    pe_callsite_registers.add_argument(
        "--stdout-format",
        choices=("json", "pretty"),
        default="json",
        help="Machine-readable JSON or human-readable pretty JSON on stdout.",
    )

    pe_address_refs = subparsers.add_parser(
        "pe-address-refs",
        help="Find PE data qword and common x64 RIP-relative references to VA/RVA targets.",
    )
    pe_address_refs.add_argument("target", type=Path, help="Path to the PE file to inspect.")
    pe_address_refs.add_argument(
        "address",
        nargs="+",
        help="Target VA or RVA to find references to, for example 0x140B83B90.",
    )
    pe_address_refs.add_argument(
        "--section",
        action="append",
        default=[],
        help="Optional section name to scan, such as .text or .rdata. Repeatable.",
    )
    pe_address_refs.add_argument(
        "--max-hits-per-target",
        type=int,
        default=32,
        help="Maximum reference records to include per target address.",
    )
    pe_address_refs.add_argument("--json-out", type=Path, help="Optional destination for the reference JSON.")
    pe_address_refs.add_argument(
        "--stdout-format",
        choices=("json", "pretty"),
        default="json",
        help="Machine-readable JSON or human-readable pretty JSON on stdout.",
    )

    pe_function_literals = subparsers.add_parser(
        "pe-function-literals",
        help="Find string literals referenced from PE function ranges.",
    )
    pe_function_literals.add_argument("target", type=Path, help="Path to the PE file to inspect.")
    pe_function_literals.add_argument(
        "function",
        nargs="+",
        help="Function range START:END or START..END, using VA or RVA addresses.",
    )
    pe_function_literals.add_argument(
        "--max-literals-per-function",
        type=int,
        default=16,
        help="Maximum unique literals to include per function.",
    )
    pe_function_literals.add_argument(
        "--max-string-bytes",
        type=int,
        default=256,
        help="Maximum bytes to read for each candidate string.",
    )
    pe_function_literals.add_argument(
        "--min-string-length",
        type=int,
        default=4,
        help="Minimum string length to report.",
    )
    pe_function_literals.add_argument("--json-out", type=Path, help="Optional destination for the literal JSON.")
    pe_function_literals.add_argument(
        "--stdout-format",
        choices=("json", "pretty"),
        default="json",
        help="Machine-readable JSON or human-readable pretty JSON on stdout.",
    )

    pe_function_calls = subparsers.add_parser(
        "pe-function-calls",
        help="List recognized call instructions inside PE function ranges.",
    )
    pe_function_calls.add_argument("target", type=Path, help="Path to the PE file to inspect.")
    pe_function_calls.add_argument(
        "function",
        nargs="+",
        help="Function range START:END or START..END, using VA or RVA addresses.",
    )
    pe_function_calls.add_argument(
        "--max-calls-per-function",
        type=int,
        default=128,
        help="Maximum recognized call instructions to include per function.",
    )
    pe_function_calls.add_argument("--json-out", type=Path, help="Optional destination for the call map JSON.")
    pe_function_calls.add_argument(
        "--stdout-format",
        choices=("json", "pretty"),
        default="json",
        help="Machine-readable JSON or human-readable pretty JSON on stdout.",
    )

    pe_instructions = subparsers.add_parser(
        "pe-instructions",
        help="Decode lightweight x64 instruction windows from a PE file.",
    )
    pe_instructions.add_argument("target", type=Path, help="Path to the PE file to inspect.")
    pe_instructions.add_argument(
        "window",
        nargs="+",
        help="Instruction window START:COUNT or byte window START..END, using VA or RVA addresses.",
    )
    pe_instructions.add_argument("--json-out", type=Path, help="Optional destination for the instruction JSON.")
    pe_instructions.add_argument(
        "--stdout-format",
        choices=("json", "pretty"),
        default="json",
        help="Machine-readable JSON or human-readable pretty JSON on stdout.",
    )

    pe_imports = subparsers.add_parser(
        "pe-imports",
        help="List PE import descriptors and IAT entry addresses.",
    )
    pe_imports.add_argument("target", type=Path, help="Path to the PE file to inspect.")
    pe_imports.add_argument("--json-out", type=Path, help="Optional destination for the import JSON.")
    pe_imports.add_argument(
        "--stdout-format",
        choices=("json", "pretty"),
        default="json",
        help="Machine-readable JSON or human-readable pretty JSON on stdout.",
    )

    pe_runtime_functions = subparsers.add_parser(
        "pe-runtime-functions",
        help="Map PE addresses to .pdata runtime-function ranges and neighbors.",
    )
    pe_runtime_functions.add_argument("target", type=Path, help="Path to the PE file to inspect.")
    pe_runtime_functions.add_argument(
        "address",
        nargs="+",
        help="VA or RVA to locate in .pdata, for example 0x14058f122.",
    )
    pe_runtime_functions.add_argument(
        "--neighbors",
        type=int,
        default=1,
        help="Number of previous and next runtime-function records to include per query.",
    )
    pe_runtime_functions.add_argument("--json-out", type=Path, help="Optional destination for the function map JSON.")
    pe_runtime_functions.add_argument(
        "--stdout-format",
        choices=("json", "pretty"),
        default="json",
        help="Machine-readable JSON or human-readable pretty JSON on stdout.",
    )

    pe_read_qwords = subparsers.add_parser(
        "pe-read-qwords",
        help="Read little-endian qword rows from mapped PE VA/RVA addresses.",
    )
    pe_read_qwords.add_argument("target", type=Path, help="Path to the PE file to inspect.")
    pe_read_qwords.add_argument(
        "address",
        nargs="+",
        help="VA/RVA read spec, optionally ADDRESS:COUNT, for example 0x140B69FC0:12.",
    )
    pe_read_qwords.add_argument(
        "--count",
        type=int,
        default=8,
        help="Default qword count for address specs that do not include :COUNT.",
    )
    pe_read_qwords.add_argument("--json-out", type=Path, help="Optional destination for the qword JSON.")
    pe_read_qwords.add_argument(
        "--stdout-format",
        choices=("json", "pretty"),
        default="json",
        help="Machine-readable JSON or human-readable pretty JSON on stdout.",
    )

    pe_vtable_slots = subparsers.add_parser(
        "pe-vtable-slots",
        help="Read PE vtable slot qwords with executable target and .pdata attribution.",
    )
    pe_vtable_slots.add_argument("target", type=Path, help="Path to the PE file to inspect.")
    pe_vtable_slots.add_argument(
        "address",
        nargs="+",
        help="VA/RVA vtable spec, optionally ADDRESS:COUNT, for example 0x140B5D9D0:24.",
    )
    pe_vtable_slots.add_argument(
        "--count",
        type=int,
        default=16,
        help="Default slot count for address specs that do not include :COUNT.",
    )
    pe_vtable_slots.add_argument("--json-out", type=Path, help="Optional destination for the slot JSON.")
    pe_vtable_slots.add_argument(
        "--stdout-format",
        choices=("json", "pretty"),
        default="json",
        help="Machine-readable JSON or human-readable pretty JSON on stdout.",
    )

    pe_resolver_invocations = subparsers.add_parser(
        "pe-resolver-invocations",
        help="Recover static selector/API/module-list arguments for PE resolver wrapper calls.",
    )
    pe_resolver_invocations.add_argument("target", type=Path, help="Path to the PE file to inspect.")
    pe_resolver_invocations.add_argument(
        "resolver",
        help="Resolver function VA or RVA, for example 0x1407DB960.",
    )
    pe_resolver_invocations.add_argument(
        "--module-table",
        help="Optional qword module-name table VA/RVA used to annotate module indices.",
    )
    pe_resolver_invocations.add_argument(
        "--max-backtrack-instructions",
        type=int,
        default=12,
        help="Maximum setup instructions to inspect before each resolver transfer.",
    )
    pe_resolver_invocations.add_argument(
        "--max-module-indices",
        type=int,
        default=64,
        help="Maximum dword module-index entries to decode per invocation.",
    )
    pe_resolver_invocations.add_argument("--json-out", type=Path, help="Optional destination for invocation JSON.")
    pe_resolver_invocations.add_argument(
        "--stdout-format",
        choices=("json", "pretty"),
        default="json",
        help="Machine-readable JSON or human-readable pretty JSON on stdout.",
    )

    pe_rtti_type_descriptors = subparsers.add_parser(
        "pe-rtti-type-descriptors",
        help="Read MSVC RTTI TypeDescriptor records from mapped PE VA/RVA addresses.",
    )
    pe_rtti_type_descriptors.add_argument("target", type=Path, help="Path to the PE file to inspect.")
    pe_rtti_type_descriptors.add_argument(
        "address",
        nargs="+",
        help="TypeDescriptor VA or RVA to inspect, for example 0x140C51CE0.",
    )
    pe_rtti_type_descriptors.add_argument(
        "--max-name-bytes",
        type=int,
        default=256,
        help="Maximum bytes to read for each decorated RTTI name.",
    )
    pe_rtti_type_descriptors.add_argument(
        "--json-out",
        type=Path,
        help="Optional destination for the RTTI descriptor JSON.",
    )
    pe_rtti_type_descriptors.add_argument(
        "--stdout-format",
        choices=("json", "pretty"),
        default="json",
        help="Machine-readable JSON or human-readable pretty JSON on stdout.",
    )

    pe_provider_descriptors = subparsers.add_parser(
        "pe-provider-descriptors",
        help="Summarize descriptor/vtable rows with common provider thunk and RTTI getter recognition.",
    )
    pe_provider_descriptors.add_argument("target", type=Path, help="Path to the PE file to inspect.")
    pe_provider_descriptors.add_argument(
        "address",
        nargs="+",
        help="Descriptor row VA or RVA to inspect, for example 0x140B83B90.",
    )
    pe_provider_descriptors.add_argument(
        "--slot-count",
        type=int,
        default=6,
        help="Number of qword slots to read from each descriptor row.",
    )
    pe_provider_descriptors.add_argument(
        "--max-name-bytes",
        type=int,
        default=256,
        help="Maximum bytes to read for RTTI decorated names reached by getter thunks.",
    )
    pe_provider_descriptors.add_argument(
        "--json-out",
        type=Path,
        help="Optional destination for the provider descriptor summary JSON.",
    )
    pe_provider_descriptors.add_argument(
        "--stdout-format",
        choices=("json", "pretty"),
        default="json",
        help="Machine-readable JSON or human-readable pretty JSON on stdout.",
    )

    pe_provider_descriptor_scan = subparsers.add_parser(
        "pe-provider-descriptor-scan",
        help="Scan non-executable PE sections for provider descriptor rows.",
    )
    pe_provider_descriptor_scan.add_argument("target", type=Path, help="Path to the PE file to inspect.")
    pe_provider_descriptor_scan.add_argument(
        "--section",
        action="append",
        default=[],
        help="Optional section name to scan, such as .rdata. Repeatable.",
    )
    pe_provider_descriptor_scan.add_argument(
        "--slot-count",
        type=int,
        default=6,
        help="Number of qword slots to summarize for each candidate.",
    )
    pe_provider_descriptor_scan.add_argument(
        "--max-results",
        type=int,
        default=128,
        help="Maximum candidate descriptor summaries to include.",
    )
    pe_provider_descriptor_scan.add_argument(
        "--include-without-rtti",
        action="store_true",
        help="Include rows that match the clone-materializer pattern even when no RTTI getter slot is detected.",
    )
    pe_provider_descriptor_scan.add_argument(
        "--include-refs",
        action="store_true",
        help="Attach PE address references for each returned descriptor row.",
    )
    pe_provider_descriptor_scan.add_argument(
        "--max-refs-per-descriptor",
        type=int,
        default=16,
        help="Maximum reference records to include per returned descriptor when --include-refs is used.",
    )
    pe_provider_descriptor_scan.add_argument(
        "--max-name-bytes",
        type=int,
        default=256,
        help="Maximum bytes to read for RTTI decorated names reached by getter thunks.",
    )
    pe_provider_descriptor_scan.add_argument(
        "--json-out",
        type=Path,
        help="Optional destination for the provider descriptor scan JSON.",
    )
    pe_provider_descriptor_scan.add_argument(
        "--cluster-json-out",
        type=Path,
        help="Optional destination for compact setup-function cluster JSON. Implies --include-refs.",
    )
    pe_provider_descriptor_scan.add_argument(
        "--cluster-csv-out",
        type=Path,
        help="Optional destination for compact setup-function cluster CSV rows. Implies --include-refs.",
    )
    pe_provider_descriptor_scan.add_argument(
        "--cluster-max-descriptors",
        type=int,
        default=8,
        help="Maximum descriptor previews retained per compact setup-function cluster.",
    )
    pe_provider_descriptor_scan.add_argument(
        "--cluster-include-literals",
        action="store_true",
        help="Include setup-function string literal previews in compact cluster exports.",
    )
    pe_provider_descriptor_scan.add_argument(
        "--cluster-max-literals",
        type=int,
        default=8,
        help="Maximum setup-function literals retained per compact cluster.",
    )
    pe_provider_descriptor_scan.add_argument(
        "--cluster-max-string-bytes",
        type=int,
        default=256,
        help="Maximum bytes to read for each setup-function string literal candidate.",
    )
    pe_provider_descriptor_scan.add_argument(
        "--stdout-format",
        choices=("json", "pretty"),
        default="json",
        help="Machine-readable JSON or human-readable pretty JSON on stdout.",
    )

    js5_export = subparsers.add_parser(
        "js5-export",
        help="Export decoded JS5 cache rows and a JSON manifest for headless inspection.",
    )
    js5_export.add_argument("target", help="Path to a js5-<id>.jcache SQLite database.")
    js5_export.add_argument("output_dir", type=Path, help="Directory to write extracted records into.")
    js5_export.add_argument(
        "--table",
        action="append",
        default=[],
        help="Specific table(s) to export, such as cache or cache_index. Repeatable.",
    )
    js5_export.add_argument(
        "--key",
        type=int,
        action="append",
        default=[],
        help="Optional record key(s) to export. Repeatable.",
    )
    js5_export.add_argument(
        "--key-start",
        type=int,
        help="Optional inclusive lower bound for exported record keys.",
    )
    js5_export.add_argument(
        "--key-end",
        type=int,
        help="Optional inclusive upper bound for exported record keys.",
    )
    js5_export.add_argument("--limit", type=int, help="Optional maximum rows per table.")
    js5_export.add_argument(
        "--include-container",
        action="store_true",
        help="Also write the original JS5 container blobs alongside decoded payloads.",
    )
    js5_export.add_argument(
        "--clientscript-cache-dir",
        type=Path,
        help="Optional prior js5-export directory whose clientscript artifacts should be reused for warm-started CLIENTSCRIPTS exports.",
    )
    js5_export.add_argument(
        "--max-decoded-mb",
        type=int,
        default=64,
        help="Skip decode when the declared output exceeds this size in MiB.",
    )
    js5_export.add_argument(
        "--manifest-out",
        type=Path,
        help="Optional second path to write the JSON manifest to.",
    )
    js5_export.add_argument(
        "--stdout-format",
        choices=("json", "pretty"),
        default="json",
        help="Machine-readable JSON or human-readable pretty JSON on stdout.",
    )

    js5_probe = subparsers.add_parser(
        "js5-opcode-probe",
        help="Inspect one clientscript opcode across an existing js5-export manifest.",
    )
    js5_probe.add_argument(
        "source",
        help="Path to a js5-export directory or its manifest.json.",
    )
    js5_probe.add_argument(
        "opcode",
        type=lambda value: int(str(value), 0),
        help="Raw opcode to inspect, for example 0x9500.",
    )
    js5_probe.add_argument(
        "--table",
        help="Optional table name filter, such as cache.",
    )
    js5_probe.add_argument(
        "--key",
        type=int,
        help="Optional archive key filter.",
    )
    js5_probe.add_argument(
        "--file-id",
        type=int,
        help="Optional split archive file id filter.",
    )
    js5_probe.add_argument(
        "--max-hits",
        type=int,
        default=32,
        help="Maximum number of sampled hits to include in the output.",
    )
    js5_probe.add_argument(
        "--json-out",
        type=Path,
        help="Optional destination for the probe JSON.",
    )
    js5_probe.add_argument(
        "--stdout-format",
        choices=("json", "pretty"),
        default="json",
        help="Machine-readable JSON or human-readable pretty JSON on stdout.",
    )

    js5_probe_interior = subparsers.add_parser(
        "js5-opcode-interior-probe",
        help="Reconstruct interior opcode hits from ready clientscript disassemblies.",
    )
    js5_probe_interior.add_argument(
        "source",
        help="Path to a js5-export directory or its manifest.json.",
    )
    js5_probe_interior.add_argument(
        "opcode",
        type=lambda value: int(str(value), 0),
        help="Raw opcode to inspect, for example 0x5E00.",
    )
    js5_probe_interior.add_argument(
        "--table",
        help="Optional table name filter, such as cache.",
    )
    js5_probe_interior.add_argument(
        "--key",
        type=int,
        action="append",
        default=[],
        help="Optional archive key filter. Repeatable.",
    )
    js5_probe_interior.add_argument(
        "--file-id",
        type=int,
        help="Optional split archive file id filter.",
    )
    js5_probe_interior.add_argument(
        "--max-hits",
        type=int,
        default=32,
        help="Maximum number of sampled hits to include in the output.",
    )
    js5_probe_interior.add_argument(
        "--ready-only",
        action="store_true",
        help="Restrict matches to scripts whose pseudocode status is already ready.",
    )
    js5_probe_interior.add_argument(
        "--json-out",
        type=Path,
        help="Optional destination for the probe JSON.",
    )
    js5_probe_interior.add_argument(
        "--stdout-format",
        choices=("json", "pretty"),
        default="json",
        help="Machine-readable JSON or human-readable pretty JSON on stdout.",
    )

    js5_probe_subtypes = subparsers.add_parser(
        "js5-opcode-subtypes",
        help="Inspect blocked clientscript frontier subtypes for one opcode across an existing js5-export manifest.",
    )
    js5_probe_subtypes.add_argument(
        "source",
        help="Path to a js5-export directory or its manifest.json.",
    )
    js5_probe_subtypes.add_argument(
        "opcode",
        type=lambda value: int(str(value), 0),
        help="Raw opcode to inspect, for example 0x9500.",
    )
    js5_probe_subtypes.add_argument(
        "--table",
        help="Optional table name filter, such as cache.",
    )
    js5_probe_subtypes.add_argument(
        "--key",
        type=int,
        help="Optional archive key filter.",
    )
    js5_probe_subtypes.add_argument(
        "--file-id",
        type=int,
        help="Optional split archive file id filter.",
    )
    js5_probe_subtypes.add_argument(
        "--max-hits",
        type=int,
        default=32,
        help="Maximum number of sampled hits to include in the output.",
    )
    js5_probe_subtypes.add_argument(
        "--json-out",
        type=Path,
        help="Optional destination for the subtype probe JSON.",
    )
    js5_probe_subtypes.add_argument(
        "--stdout-format",
        choices=("json", "pretty"),
        default="json",
        help="Machine-readable JSON or human-readable pretty JSON on stdout.",
    )

    js5_probe_branch_clusters = subparsers.add_parser(
        "js5-opcode-branch-clusters",
        help="Cluster branch-state probe behavior for one clientscript opcode across an existing js5-export manifest.",
    )
    js5_probe_branch_clusters.add_argument(
        "source",
        help="Path to a js5-export directory or its manifest.json.",
    )
    js5_probe_branch_clusters.add_argument(
        "opcode",
        type=lambda value: int(str(value), 0),
        help="Raw opcode to inspect, for example 0x0005.",
    )
    js5_probe_branch_clusters.add_argument(
        "--table",
        help="Optional table name filter, such as cache.",
    )
    js5_probe_branch_clusters.add_argument(
        "--key",
        type=int,
        help="Optional archive key filter.",
    )
    js5_probe_branch_clusters.add_argument(
        "--file-id",
        type=int,
        help="Optional split archive file id filter.",
    )
    js5_probe_branch_clusters.add_argument(
        "--max-hits",
        type=int,
        default=32,
        help="Maximum number of sampled observations to include in the output.",
    )
    js5_probe_branch_clusters.add_argument(
        "--json-out",
        type=Path,
        help="Optional destination for the branch cluster JSON.",
    )
    js5_probe_branch_clusters.add_argument(
        "--stdout-format",
        choices=("json", "pretty"),
        default="json",
        help="Machine-readable JSON or human-readable pretty JSON on stdout.",
    )

    js5_pseudocode_blockers = subparsers.add_parser(
        "js5-pseudocode-blockers",
        help="Summarize ready and blocked clientscript pseudocode profiles from an existing js5-export manifest.",
    )
    js5_pseudocode_blockers.add_argument(
        "source",
        help="Path to a js5-export directory or its manifest.json.",
    )
    js5_pseudocode_blockers.add_argument(
        "--max-sample",
        type=int,
        default=16,
        help="Maximum sampled entries to include from blocker lists and blocked-profile samples.",
    )
    js5_pseudocode_blockers.add_argument(
        "--json-out",
        type=Path,
        help="Optional destination for the blocker summary JSON.",
    )
    js5_pseudocode_blockers.add_argument(
        "--stdout-format",
        choices=("json", "pretty"),
        default="json",
        help="Machine-readable JSON or human-readable pretty JSON on stdout.",
    )

    archive_export = subparsers.add_parser(
        "archive-export",
        help="Extract ZIP, TAR, or 7z archives with optional authorized password input.",
    )
    archive_export.add_argument("target", help="Path to an archive file.")
    archive_export.add_argument("output_dir", type=Path, help="Directory to write extracted members into.")
    archive_export.add_argument("--password", help="Optional archive password.")
    archive_export.add_argument(
        "--password-env",
        help="Read the archive password from an environment variable name.",
    )
    archive_export.add_argument(
        "--password-prompt",
        action="store_true",
        help="Prompt for the archive password in the terminal.",
    )
    archive_export.add_argument(
        "--manifest-out",
        type=Path,
        help="Optional second path to write the JSON manifest to.",
    )
    archive_export.add_argument(
        "--stdout-format",
        choices=("json", "pretty"),
        default="json",
        help="Machine-readable JSON or human-readable pretty JSON on stdout.",
    )

    diff = subparsers.add_parser("diff", help="Compare two reports, scan indexes, or raw targets.")
    diff.add_argument("base", help="Base report/index JSON or raw file/directory.")
    diff.add_argument("head", help="Head report/index JSON or raw file/directory.")
    diff.add_argument("--json-out", type=Path, help="Optional destination for diff JSON.")
    diff.add_argument("--max-files", type=int, default=250, help="Maximum files when diffing raw directories.")
    diff.add_argument("--max-file-mb", type=int, default=256, help="Maximum file size when diffing raw directories.")
    diff.add_argument("--max-strings", type=int, default=200, help="Maximum unique strings for raw target analysis.")
    diff.add_argument(
        "--stdout-format",
        choices=("json", "pretty"),
        default="json",
        help="Machine-readable JSON or human-readable pretty JSON on stdout.",
    )

    schema = subparsers.add_parser("schema", help="Print the stable JSON schema for report consumers.")
    schema.add_argument(
        "--kind",
        choices=get_schema_kinds(),
        default="report",
        help="Which schema to print.",
    )
    schema.add_argument(
        "--list",
        action="store_true",
        help="List available schema kinds and their API paths.",
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "gui":
        from reverser.app import main as gui_main

        return gui_main()

    if args.command == "api":
        run_api_server(host=args.host, port=args.port)
        return 0

    if args.command == "catalog-init":
        path = init_catalog(args.db)
        print(json.dumps({"db_path": str(path)}, indent=2))
        return 0

    if args.command == "catalog-ingest":
        payload = ingest_into_catalog(
            args.source,
            db_path=args.db,
            max_strings=args.max_strings,
            max_files=args.max_files,
            max_file_mb=args.max_file_mb,
        ).to_dict()
        print(json.dumps(payload, indent=2))
        return 0

    if args.command == "catalog-search":
        payload = search_catalog(
            db_path=args.db,
            signature=args.signature,
            engine=args.engine,
            tag=args.tag,
            path_contains=args.path_contains,
            sha256=args.sha256,
            min_findings=args.min_findings,
            limit=args.limit,
        )
        if args.csv_out:
            export_rows_csv(payload["results"], args.csv_out)
        print(json.dumps(payload, indent=2))
        return 0

    if args.command == "catalog-ingests":
        payload = list_catalog_ingests(db_path=args.db, limit=args.limit)
        print(json.dumps(payload, indent=2))
        return 0

    if args.command == "catalog-stats":
        payload = catalog_stats(db_path=args.db)
        print(json.dumps(payload, indent=2))
        return 0

    if args.command == "schema":
        if args.list:
            schema = get_schema_registry()
        else:
            schema = get_schema(args.kind)
        print(json.dumps(schema, indent=2))
        return 0

    if args.command == "analyzers":
        analyzers = [
            {
                "name": analyzer.name,
                "class": analyzer.__class__.__name__,
            }
            for analyzer in AnalysisEngine().analyzers
        ]
        print(json.dumps({"analyzers": analyzers}, indent=2))
        return 0

    if args.command == "scan":
        index = scan_tree(
            args.target,
            max_files=args.max_files,
            max_file_bytes=args.max_file_mb * 1024 * 1024,
            max_strings=args.max_strings,
            reports_dir=args.reports_dir,
            include_markdown=args.include_markdown,
            include_globs=args.include_glob,
            exclude_globs=args.exclude_glob,
            workers=args.workers,
        )

        if args.index_json:
            export_scan_json(index, args.index_json)
        if args.index_ndjson:
            export_scan_ndjson(index, args.index_ndjson)
        if args.csv_out:
            export_scan_csv(index, args.csv_out)

        indent = 2 if args.stdout_format == "pretty" else None
        print(json.dumps(index.to_dict(), indent=indent))
        return 0

    if args.command == "external-target-index":
        payload = build_external_target_index(args.root)
        if args.json_out:
            export_object_json(payload, args.json_out)
        indent = 2 if args.stdout_format == "pretty" else None
        print(json.dumps(payload, indent=indent))
        return 0

    if args.command == "external-tool-inventory":
        payload = build_external_tool_inventory(profile=args.profile)
        if args.json_out:
            export_object_json(payload, args.json_out)
        indent = 2 if args.stdout_format == "pretty" else None
        print(json.dumps(payload, indent=indent))
        return 0

    if args.command == "pe-direct-calls":
        payload = find_pe_direct_calls(args.target, args.address)
        if args.json_out:
            export_object_json(payload, args.json_out)
        indent = 2 if args.stdout_format == "pretty" else None
        print(json.dumps(payload, indent=indent))
        return 0

    if args.command == "pe-callsite-registers":
        payload = find_pe_callsite_registers(
            args.target,
            args.address,
            registers=args.register or ("RCX", "RDX", "R8", "R9"),
            max_backtrack_instructions=args.max_backtrack_instructions,
        )
        if args.json_out:
            export_object_json(payload, args.json_out)
        indent = 2 if args.stdout_format == "pretty" else None
        print(json.dumps(payload, indent=indent))
        return 0

    if args.command == "pe-address-refs":
        payload = find_pe_address_refs(
            args.target,
            args.address,
            max_hits_per_target=args.max_hits_per_target,
            section_names=args.section or None,
        )
        if args.json_out:
            export_object_json(payload, args.json_out)
        indent = 2 if args.stdout_format == "pretty" else None
        print(json.dumps(payload, indent=indent))
        return 0

    if args.command == "pe-function-literals":
        payload = find_pe_function_literals(
            args.target,
            args.function,
            max_literals_per_function=args.max_literals_per_function,
            max_string_bytes=args.max_string_bytes,
            min_string_length=args.min_string_length,
        )
        if args.json_out:
            export_object_json(payload, args.json_out)
        indent = 2 if args.stdout_format == "pretty" else None
        print(json.dumps(payload, indent=indent))
        return 0

    if args.command == "pe-function-calls":
        payload = find_pe_function_calls(
            args.target,
            args.function,
            max_calls_per_function=args.max_calls_per_function,
        )
        if args.json_out:
            export_object_json(payload, args.json_out)
        indent = 2 if args.stdout_format == "pretty" else None
        print(json.dumps(payload, indent=indent))
        return 0

    if args.command == "pe-instructions":
        payload = find_pe_instructions(args.target, args.window)
        if args.json_out:
            export_object_json(payload, args.json_out)
        indent = 2 if args.stdout_format == "pretty" else None
        print(json.dumps(payload, indent=indent))
        return 0

    if args.command == "pe-imports":
        payload = read_pe_imports(args.target)
        if args.json_out:
            export_object_json(payload, args.json_out)
        indent = 2 if args.stdout_format == "pretty" else None
        print(json.dumps(payload, indent=indent))
        return 0

    if args.command == "pe-runtime-functions":
        payload = find_pe_runtime_functions(args.target, args.address, neighbors=args.neighbors)
        if args.json_out:
            export_object_json(payload, args.json_out)
        indent = 2 if args.stdout_format == "pretty" else None
        print(json.dumps(payload, indent=indent))
        return 0

    if args.command == "pe-read-qwords":
        payload = read_pe_qwords(args.target, args.address, default_count=args.count)
        if args.json_out:
            export_object_json(payload, args.json_out)
        indent = 2 if args.stdout_format == "pretty" else None
        print(json.dumps(payload, indent=indent))
        return 0

    if args.command == "pe-vtable-slots":
        payload = read_pe_vtable_slots(args.target, args.address, default_count=args.count)
        if args.json_out:
            export_object_json(payload, args.json_out)
        indent = 2 if args.stdout_format == "pretty" else None
        print(json.dumps(payload, indent=indent))
        return 0

    if args.command == "pe-resolver-invocations":
        payload = find_pe_resolver_invocations(
            args.target,
            args.resolver,
            module_table=args.module_table,
            max_backtrack_instructions=args.max_backtrack_instructions,
            max_module_indices=args.max_module_indices,
        )
        if args.json_out:
            export_object_json(payload, args.json_out)
        indent = 2 if args.stdout_format == "pretty" else None
        print(json.dumps(payload, indent=indent))
        return 0

    if args.command == "pe-rtti-type-descriptors":
        payload = read_pe_rtti_type_descriptors(
            args.target,
            args.address,
            max_name_bytes=args.max_name_bytes,
        )
        if args.json_out:
            export_object_json(payload, args.json_out)
        indent = 2 if args.stdout_format == "pretty" else None
        print(json.dumps(payload, indent=indent))
        return 0

    if args.command == "pe-provider-descriptors":
        payload = summarize_pe_provider_descriptors(
            args.target,
            args.address,
            slot_count=args.slot_count,
            max_name_bytes=args.max_name_bytes,
        )
        if args.json_out:
            export_object_json(payload, args.json_out)
        indent = 2 if args.stdout_format == "pretty" else None
        print(json.dumps(payload, indent=indent))
        return 0

    if args.command == "pe-provider-descriptor-scan":
        include_refs = args.include_refs or bool(args.cluster_json_out) or bool(args.cluster_csv_out)
        payload = scan_pe_provider_descriptors(
            args.target,
            section_names=args.section or None,
            slot_count=args.slot_count,
            max_results=args.max_results,
            require_rtti=not args.include_without_rtti,
            include_refs=include_refs,
            max_refs_per_descriptor=args.max_refs_per_descriptor,
            max_name_bytes=args.max_name_bytes,
        )
        if args.json_out:
            export_object_json(payload, args.json_out)
        literal_payload = None
        if args.cluster_include_literals and (args.cluster_json_out or args.cluster_csv_out):
            literal_payload = provider_descriptor_cluster_literal_payload(
                args.target,
                payload,
                max_literals_per_function=args.cluster_max_literals,
                max_string_bytes=args.cluster_max_string_bytes,
            )
        if args.cluster_json_out:
            export_object_json(
                compact_provider_descriptor_clusters(
                    payload,
                    max_descriptors_per_cluster=args.cluster_max_descriptors,
                    literal_payload=literal_payload,
                ),
                args.cluster_json_out,
            )
        if args.cluster_csv_out:
            export_rows_csv(
                provider_descriptor_cluster_rows(
                    payload,
                    max_descriptors_per_cluster=args.cluster_max_descriptors,
                    literal_payload=literal_payload,
                ),
                args.cluster_csv_out,
            )
        indent = 2 if args.stdout_format == "pretty" else None
        print(json.dumps(payload, indent=indent))
        return 0

    if args.command == "js5-export":
        manifest = export_js5_cache(
            args.target,
            args.output_dir,
            tables=args.table or None,
            keys=args.key or None,
            key_start=args.key_start,
            key_end=args.key_end,
            limit=args.limit,
            include_container=args.include_container,
            clientscript_cache_dir=args.clientscript_cache_dir,
            max_decoded_bytes=args.max_decoded_mb * 1024 * 1024,
        )
        if args.manifest_out:
            export_object_json(manifest, args.manifest_out)
        indent = 2 if args.stdout_format == "pretty" else None
        print(json.dumps(manifest, indent=indent))
        return 0

    if args.command == "js5-opcode-probe":
        payload = probe_js5_export_opcode(
            args.source,
            args.opcode,
            table=args.table,
            key=args.key,
            file_id=args.file_id,
            max_hits=args.max_hits,
        )
        if args.json_out:
            export_object_json(payload, args.json_out)
        indent = 2 if args.stdout_format == "pretty" else None
        print(json.dumps(payload, indent=indent))
        return 0

    if args.command == "js5-opcode-interior-probe":
        payload = probe_js5_export_interior_opcode(
            args.source,
            args.opcode,
            table=args.table,
            keys=args.key,
            file_id=args.file_id,
            max_hits=args.max_hits,
            ready_only=args.ready_only,
        )
        if args.json_out:
            export_object_json(payload, args.json_out)
        indent = 2 if args.stdout_format == "pretty" else None
        print(json.dumps(payload, indent=indent))
        return 0

    if args.command == "js5-opcode-subtypes":
        payload = probe_js5_export_opcode_subtypes(
            args.source,
            args.opcode,
            table=args.table,
            key=args.key,
            file_id=args.file_id,
            max_hits=args.max_hits,
        )
        if args.json_out:
            export_object_json(payload, args.json_out)
        indent = 2 if args.stdout_format == "pretty" else None
        print(json.dumps(payload, indent=indent))
        return 0

    if args.command == "js5-opcode-branch-clusters":
        payload = probe_js5_export_branch_clusters(
            args.source,
            args.opcode,
            table=args.table,
            key=args.key,
            file_id=args.file_id,
            max_hits=args.max_hits,
        )
        if args.json_out:
            export_object_json(payload, args.json_out)
        indent = 2 if args.stdout_format == "pretty" else None
        print(json.dumps(payload, indent=indent))
        return 0

    if args.command == "js5-pseudocode-blockers":
        payload = probe_js5_export_pseudocode_blockers(
            args.source,
            max_sample=args.max_sample,
        )
        if args.json_out:
            export_object_json(payload, args.json_out)
        indent = 2 if args.stdout_format == "pretty" else None
        print(json.dumps(payload, indent=indent))
        return 0

    if args.command == "archive-export":
        password = _resolve_archive_password(args)
        manifest = export_archive(
            args.target,
            args.output_dir,
            password=password,
        )
        if args.manifest_out:
            export_object_json(manifest, args.manifest_out)
        indent = 2 if args.stdout_format == "pretty" else None
        print(json.dumps(manifest, indent=indent))
        return 0

    if args.command == "diff":
        base = load_or_generate_artifact(
            args.base,
            max_strings=args.max_strings,
            max_files=args.max_files,
            max_file_mb=args.max_file_mb,
        )
        head = load_or_generate_artifact(
            args.head,
            max_strings=args.max_strings,
            max_files=args.max_files,
            max_file_mb=args.max_file_mb,
        )
        diff = diff_artifacts(base, head, base_ref=args.base, head_ref=args.head).to_dict()
        if args.json_out:
            export_object_json(diff, args.json_out)
        indent = 2 if args.stdout_format == "pretty" else None
        print(json.dumps(diff, indent=indent))
        return 0

    engine = AnalysisEngine(max_strings=args.max_strings)
    report = engine.analyze(args.target)

    if args.json_out:
        export_json(report, args.json_out)
    if args.md_out:
        export_markdown(report, args.md_out)

    indent = 2 if args.stdout_format == "pretty" else None
    print(json.dumps(report.to_dict(), indent=indent))
    return 2 if args.fail_on_errors and report.errors else 0


def _resolve_archive_password(args: argparse.Namespace) -> str | None:
    if getattr(args, "password", None):
        return str(args.password)
    password_env = getattr(args, "password_env", None)
    if password_env:
        return os.environ.get(str(password_env))
    if getattr(args, "password_prompt", False):
        return getpass.getpass("Archive password: ")
    return None


if __name__ == "__main__":
    raise SystemExit(main())
