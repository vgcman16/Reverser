from __future__ import annotations

from pathlib import Path

from reverser.analysis.analyzers.archive_analyzer import ArchiveAnalyzer
from reverser.analysis.analyzers.base import Analyzer
from reverser.analysis.analyzers.directory_inventory import DirectoryInventoryAnalyzer
from reverser.analysis.analyzers.elf_analyzer import ELFAnalyzer
from reverser.analysis.analyzers.file_identity import FileIdentityAnalyzer
from reverser.analysis.analyzers.game_detector import GameFingerprintAnalyzer
from reverser.analysis.analyzers.ioc_analyzer import IOCAnalyzer
from reverser.analysis.analyzers.js5_cache_analyzer import JS5CacheAnalyzer
from reverser.analysis.analyzers.macho_analyzer import MachOAnalyzer
from reverser.analysis.analyzers.pe_analyzer import PEAnalyzer
from reverser.analysis.analyzers.sqlite_analyzer import SQLiteAnalyzer
from reverser.analysis.analyzers.string_analyzer import StringsAnalyzer
from reverser.models import AnalysisReport, AnalysisTarget


class AnalysisEngine:
    def __init__(self, analyzers: list[Analyzer] | None = None, *, max_strings: int = 200) -> None:
        self.analyzers = analyzers or [
            FileIdentityAnalyzer(),
            DirectoryInventoryAnalyzer(),
            ArchiveAnalyzer(),
            SQLiteAnalyzer(),
            JS5CacheAnalyzer(),
            PEAnalyzer(),
            ELFAnalyzer(),
            MachOAnalyzer(),
            StringsAnalyzer(max_results=max_strings),
            IOCAnalyzer(),
            GameFingerprintAnalyzer(),
        ]

    def analyze(self, target_path: str | Path) -> AnalysisReport:
        target = Path(target_path).expanduser().resolve()
        if not target.exists():
            raise FileNotFoundError(f"Target does not exist: {target}")

        report = AnalysisReport(
            target=AnalysisTarget(
                path=target,
                kind="directory" if target.is_dir() else "file",
                size_bytes=self._size_bytes(target),
            )
        )

        for analyzer in self.analyzers:
            if not analyzer.supports(target):
                continue

            try:
                analyzer.analyze(target, report)
                report.mark_analyzer(analyzer.name)
            except Exception as exc:  # pragma: no cover
                report.error(f"{analyzer.name}: {exc}")

        return report

    @staticmethod
    def _size_bytes(target: Path) -> int:
        if target.is_file():
            return target.stat().st_size
        return sum(item.stat().st_size for item in target.rglob("*") if item.is_file())
