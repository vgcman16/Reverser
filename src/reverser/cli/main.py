from __future__ import annotations

import argparse
import json
from pathlib import Path

from reverser.analysis.exporters.json_exporter import export_json
from reverser.analysis.exporters.markdown_exporter import export_markdown
from reverser.analysis.orchestrator import AnalysisEngine
from reverser.schema import get_report_schema


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="reverser",
        description="Authorized binary and game-file analysis workbench.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    analyze = subparsers.add_parser("analyze", help="Analyze a file or directory.")
    analyze.add_argument("target", help="Path to a file or directory to inspect.")
    analyze.add_argument("--json-out", type=Path, help="Optional JSON report destination.")
    analyze.add_argument("--md-out", type=Path, help="Optional Markdown report destination.")
    analyze.add_argument("--max-strings", type=int, default=200, help="Maximum unique strings to retain.")
    analyze.add_argument(
        "--stdout-format",
        choices=("json", "pretty"),
        default="json",
        help="Machine-readable JSON or human-readable pretty JSON on stdout.",
    )

    subparsers.add_parser("gui", help="Launch the desktop GUI.")
    subparsers.add_parser("schema", help="Print the stable JSON schema for report consumers.")
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "gui":
        from reverser.app import main as gui_main

        return gui_main()

    if args.command == "schema":
        print(json.dumps(get_report_schema(), indent=2))
        return 0

    engine = AnalysisEngine(max_strings=args.max_strings)
    report = engine.analyze(args.target)

    if args.json_out:
        export_json(report, args.json_out)
    if args.md_out:
        export_markdown(report, args.md_out)

    indent = 2 if args.stdout_format == "pretty" else None
    print(json.dumps(report.to_dict(), indent=indent))
    return 0
