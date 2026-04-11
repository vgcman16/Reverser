from __future__ import annotations

import argparse
import getpass
import json
import os
from pathlib import Path

from reverser import __version__
from reverser.api import run_api_server
from reverser.analysis.archive_export import export_archive
from reverser.analysis.conquer_map import export_conquer_maps
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
from reverser.analysis.js5 import export_js5_cache
from reverser.analysis.netdragon import export_netdragon_package
from reverser.analysis.exporters.object_exporter import export_object_json
from reverser.analysis.exporters.json_exporter import export_json
from reverser.analysis.exporters.markdown_exporter import export_markdown
from reverser.analysis.orchestrator import AnalysisEngine
from reverser.analysis.scan import scan_tree
from reverser.schema import (
    get_catalog_ingests_schema,
    get_catalog_search_schema,
    get_diff_schema,
    get_js5_manifest_schema,
    get_report_schema,
    get_scan_index_schema,
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

    netdragon_export = subparsers.add_parser(
        "netdragon-export",
        help="Export files from a NetDragon .tpi/.tpd package pair.",
    )
    netdragon_export.add_argument("target", help="Path to a .tpi or .tpd NetDragon package file.")
    netdragon_export.add_argument("output_dir", type=Path, help="Directory to write extracted files into.")
    netdragon_export.add_argument("--limit", type=int, help="Optional maximum number of entries to export.")
    netdragon_export.add_argument(
        "--include-stored",
        action="store_true",
        help="Also write the stored compressed blobs alongside decoded output.",
    )
    netdragon_export.add_argument(
        "--manifest-out",
        type=Path,
        help="Optional second path to write the JSON manifest to.",
    )
    netdragon_export.add_argument(
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

    conquer_map_export = subparsers.add_parser(
        "conquer-map-export",
        help="Export openable Conquer map archives with parsed DMap and OtherData metadata.",
    )
    conquer_map_export.add_argument(
        "target",
        help="Path to the Conquer install root, map root, or a single map .7z archive.",
    )
    conquer_map_export.add_argument("output_dir", type=Path, help="Directory to write extracted map content into.")
    conquer_map_export.add_argument("--limit", type=int, help="Optional maximum number of map archives to export.")
    conquer_map_export.add_argument(
        "--include-archives",
        action="store_true",
        help="Also copy the original .7z map archives into the export folder.",
    )
    conquer_map_export.add_argument(
        "--manifest-out",
        type=Path,
        help="Optional second path to write the JSON manifest to.",
    )
    conquer_map_export.add_argument(
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
        choices=("report", "scan-index", "diff", "catalog-search", "catalog-ingests", "js5-manifest"),
        default="report",
        help="Which schema to print.",
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
        if args.kind == "report":
            schema = get_report_schema()
        elif args.kind == "scan-index":
            schema = get_scan_index_schema()
        elif args.kind == "catalog-search":
            schema = get_catalog_search_schema()
        elif args.kind == "catalog-ingests":
            schema = get_catalog_ingests_schema()
        elif args.kind == "js5-manifest":
            schema = get_js5_manifest_schema()
        else:
            schema = get_diff_schema()
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

    if args.command == "js5-export":
        manifest = export_js5_cache(
            args.target,
            args.output_dir,
            tables=args.table or None,
            keys=args.key or None,
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

    if args.command == "netdragon-export":
        manifest = export_netdragon_package(
            args.target,
            args.output_dir,
            limit=args.limit,
            include_stored=args.include_stored,
        )
        if args.manifest_out:
            export_object_json(manifest, args.manifest_out)
        indent = 2 if args.stdout_format == "pretty" else None
        print(json.dumps(manifest, indent=indent))
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

    if args.command == "conquer-map-export":
        manifest = export_conquer_maps(
            args.target,
            args.output_dir,
            limit=args.limit,
            include_archives=args.include_archives,
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
