from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from reverser.models import AnalysisReport


class Analyzer(ABC):
    name = "base"

    def supports(self, target: Path) -> bool:
        return target.exists()

    @abstractmethod
    def analyze(self, target: Path, report: AnalysisReport) -> None:
        raise NotImplementedError
