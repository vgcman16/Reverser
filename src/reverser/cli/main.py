from __future__ import annotations

import argparse
import json
from pathlib import Path

from reverser import __version__
from reverser.analysis.exporters.index_exporter import export_scan_json, export_scan_ndjson
from reverser.analysis.exporters.json_exporter import export_json
from reverser.analysis.exporters.markdown_exporter import export_markdown
from reverser.analysis.orchestrator import AnalysisEngine
from reverser.analysis.scan import scan_tree
from reverser.schema import get_report_schema, get_scan_index_schema


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

    scan = subparsers.add_parser("scan", help="Batch-scan a file tree and emit an index.")
    scan.add_argument("target", help="Root directory or file to scan.")
    scan.add_argument("--reports-dir", type=Path, help="Optional destination for per-target JSON reports.")
    scan.add_argument(
        "--include-markdown",
        action="store_true",
        help="Write Markdown reports alongside JSON reports when --reports-dir is used.",
    )
    scan.add_argument("--index-json", type=Path, help="Optional destination for the scan index JSON.")
    scan.add_argument("--index-ndjson", type=Path, help="Optional destination for per-entry NDJSON.")
    scan.add_argument("--max-files", type=int, default=250, help="Maximum number of files to analyze in a tree.")
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

    schema = subparsers.add_parser("schema", help="Print the stable JSON schema for report consumers.")
    schema.add_argument(
        "--kind",
        choices=("report", "scan-index"),
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

    if args.command == "schema":
        schema = get_report_schema() if args.kind == "report" else get_scan_index_schema()
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
        )

        if args.index_json:
            export_scan_json(index, args.index_json)
        if args.index_ndjson:
            export_scan_ndjson(index, args.index_ndjson)

        indent = 2 if args.stdout_format == "pretty" else None
        print(json.dumps(index.to_dict(), indent=indent))
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
