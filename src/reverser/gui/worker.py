from __future__ import annotations

from pathlib import Path

from reverser.analysis.orchestrator import AnalysisEngine
from reverser.analysis.scan import scan_tree


def run_analysis(path: str | Path, *, max_strings: int = 200):
    engine = AnalysisEngine(max_strings=max_strings)
    return engine.analyze(path)


def run_scan(path: str | Path, *, max_strings: int = 200, max_files: int = 250):
    return scan_tree(path, max_strings=max_strings, max_files=max_files)
