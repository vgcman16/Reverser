from __future__ import annotations

import os
from concurrent.futures import ThreadPoolExecutor
from fnmatch import fnmatch
from pathlib import Path

from reverser.analysis.exporters.json_exporter import export_json
from reverser.analysis.exporters.markdown_exporter import export_markdown
from reverser.analysis.orchestrator import AnalysisEngine
from reverser.models import AnalysisReport, BatchScanIndex, ScanEntry


INTERESTING_EXTENSIONS = {
    ".exe": 100,
    ".dll": 95,
    ".sys": 95,
    ".drv": 95,
    ".pak": 92,
    ".jcache": 92,
    ".utoc": 92,
    ".ucas": 92,
    ".vpk": 90,
    ".pck": 90,
    ".dds": 70,
    ".rpf": 88,
    ".wad": 88,
    ".bnk": 88,
    ".assets": 88,
    ".bundle": 88,
    ".unity3d": 88,
    ".zip": 84,
    ".7z": 84,
    ".rar": 84,
    ".tar": 84,
    ".sqlite": 76,
    ".db": 74,
    ".db3": 74,
    ".json": 52,
    ".ini": 50,
    ".cfg": 50,
    ".xml": 48,
    ".toml": 48,
    ".yaml": 48,
    ".yml": 48,
}
DEFAULT_EXCLUDED_PARTS = {
    ".git",
    ".pytest_cache",
    ".reverser",
    "__pycache__",
    "node_modules",
    ".venv",
    "build",
    "dist",
    "reports",
}
DEFAULT_EXCLUDED_EXTENSIONS = {".pyc"}
LARGE_METADATA_EXTENSIONS = {".jcache", ".sqlite", ".db", ".db3"}
SKIPPED_SAMPLE_LIMIT = 20


def scan_tree(
    root_path: str | Path,
    *,
    max_files: int = 250,
    max_file_bytes: int = 256 * 1024 * 1024,
    max_strings: int = 200,
    reports_dir: Path | None = None,
    include_markdown: bool = False,
    include_globs: list[str] | None = None,
    exclude_globs: list[str] | None = None,
    workers: int | None = None,
) -> BatchScanIndex:
    root = Path(root_path).expanduser().resolve()
    if not root.exists():
        raise FileNotFoundError(f"Target does not exist: {root}")

    engine = AnalysisEngine(max_strings=max_strings)
    base = root if root.is_dir() else root.parent
    index = BatchScanIndex(
        root_path=str(root),
        settings={
            "max_files": max_files,
            "max_file_bytes": max_file_bytes,
            "max_strings": max_strings,
            "reports_dir": str(reports_dir) if reports_dir else None,
            "include_markdown": include_markdown,
            "include_globs": include_globs or [],
            "exclude_globs": exclude_globs or [],
            "workers": workers or _default_workers(),
            "candidate_count": 0,
            "skipped_count": 0,
        },
    )

    root_report = engine.analyze(root)
    index.root_summary = _report_excerpt(root_report)

    if root.is_file():
        report = root_report
        json_path, markdown_path = _export_report_pair(
            report,
            base=base,
            reports_dir=reports_dir,
            include_markdown=include_markdown,
        )
        index.entries.append(
            ScanEntry.from_report(
                report,
                relative_to=base,
                json_report_path=json_path,
                markdown_report_path=markdown_path,
            )
        )
        index.settings["candidate_count"] = 1
        return index

    candidates = _collect_candidates(
        root,
        max_file_bytes=max_file_bytes,
        include_globs=include_globs or [],
        exclude_globs=exclude_globs or [],
    )
    index.settings["candidate_count"] = len(candidates["selected"]) + candidates["skipped_count"]
    index.settings["skipped_count"] = candidates["skipped_count"]
    index.skipped_samples.extend(candidates["skipped_samples"])

    limited_candidates = candidates["selected"][:max_files]
    omitted_count = max(0, len(candidates["selected"]) - len(limited_candidates))
    if omitted_count:
        index.settings["skipped_count"] = int(index.settings["skipped_count"]) + omitted_count
        for path in candidates["selected"][max_files : max_files + SKIPPED_SAMPLE_LIMIT]:
            index.skipped_samples.append(
                {
                    "path": str(path.relative_to(root)),
                    "reason": "max_files_limit",
                }
            )

    worker_count = max(1, workers or _default_workers())
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        reports = list(executor.map(engine.analyze, limited_candidates))

    for report in reports:
        json_path, markdown_path = _export_report_pair(
            report,
            base=base,
            reports_dir=reports_dir,
            include_markdown=include_markdown,
        )
        index.entries.append(
            ScanEntry.from_report(
                report,
                relative_to=base,
                json_report_path=json_path,
                markdown_report_path=markdown_path,
            )
        )

    return index


def _collect_candidates(
    root: Path,
    *,
    max_file_bytes: int,
    include_globs: list[str],
    exclude_globs: list[str],
) -> dict[str, object]:
    selected: list[Path] = []
    skipped_count = 0
    skipped_samples: list[dict[str, str]] = []

    all_files = [
        path
        for path in root.rglob("*")
        if path.is_file() and not _is_excluded(path, root, include_globs=include_globs, exclude_globs=exclude_globs)
    ]
    ranked = sorted(
        all_files,
        key=lambda path: (
            -_interesting_score(path),
            -path.stat().st_size,
            str(path.relative_to(root)).lower(),
        ),
    )

    for path in ranked:
        file_size = path.stat().st_size
        if file_size > max_file_bytes and not _allow_oversized_metadata(path):
            skipped_count += 1
            if len(skipped_samples) < SKIPPED_SAMPLE_LIMIT:
                skipped_samples.append(
                    {
                        "path": str(path.relative_to(root)),
                        "reason": "max_file_bytes",
                    }
                )
            continue
        selected.append(path)

    return {
        "selected": selected,
        "skipped_count": skipped_count,
        "skipped_samples": skipped_samples,
    }


def _allow_oversized_metadata(path: Path) -> bool:
    return path.suffix.lower() in LARGE_METADATA_EXTENSIONS


def _is_excluded(rooted_path: Path, root: Path, *, include_globs: list[str], exclude_globs: list[str]) -> bool:
    relative = rooted_path.relative_to(root)
    relative_string = str(relative).replace("\\", "/")
    lowered_parts = {part.lower() for part in relative.parts}

    if lowered_parts & DEFAULT_EXCLUDED_PARTS:
        return True
    if rooted_path.suffix.lower() in DEFAULT_EXCLUDED_EXTENSIONS:
        return True

    if include_globs and not any(fnmatch(relative_string, pattern) for pattern in include_globs):
        return True
    if any(fnmatch(relative_string, pattern) for pattern in exclude_globs):
        return True

    return False


def _interesting_score(path: Path) -> int:
    score = INTERESTING_EXTENSIONS.get(path.suffix.lower(), 10)
    lowered_name = path.name.lower()
    if "game" in lowered_name or "launcher" in lowered_name or "shipping" in lowered_name:
        score += 10
    return score


def _default_workers() -> int:
    cpu_count = os.cpu_count() or 4
    return min(8, max(2, cpu_count))


def _export_report_pair(
    report: AnalysisReport,
    *,
    base: Path,
    reports_dir: Path | None,
    include_markdown: bool,
) -> tuple[Path | None, Path | None]:
    if not reports_dir:
        return None, None

    relative = report.target.path.relative_to(base)
    json_path = reports_dir / relative.with_suffix(relative.suffix + ".json")
    export_json(report, json_path)

    markdown_path = None
    if include_markdown:
        markdown_path = reports_dir / relative.with_suffix(relative.suffix + ".md")
        export_markdown(report, markdown_path)

    return json_path, markdown_path


def _report_excerpt(report: AnalysisReport) -> dict[str, object]:
    sections = {}
    for name in (
        "identity",
        "directory_inventory",
        "js5_cache_directory",
        "game_fingerprint",
        "archive",
    ):
        if name in report.sections:
            sections[name] = report.sections[name]

    return {
        "target": report.target.to_dict(),
        "summary": report.summary,
        "sections": sections,
        "warnings": report.warnings,
        "errors": report.errors,
    }
