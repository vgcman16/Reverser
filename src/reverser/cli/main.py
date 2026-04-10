from __future__ import annotations

import argparse
import json
from pathlib import Path

from reverser import __version__
from reverser.api import run_api_server
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
from reverser.analysis.exporters.object_exporter import export_object_json
from reverser.analysis.exporters.json_exporter import export_json
from reverser.analysis.exporters.markdown_exporter import export_markdown
from reverser.analysis.orchestrator import AnalysisEngine
from reverser.analysis.scan import scan_tree
from reverser.schema import (
    get_catalog_ingests_schema,
    get_catalog_search_schema,
    get_diff_schema,
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
        choices=("report", "scan-index", "diff", "catalog-search", "catalog-ingests"),
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
