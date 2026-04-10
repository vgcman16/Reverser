from __future__ import annotations

from pathlib import Path

from reverser.analysis.orchestrator import AnalysisEngine


def run_analysis(path: str | Path, *, max_strings: int = 200):
    engine = AnalysisEngine(max_strings=max_strings)
    return engine.analyze(path)
