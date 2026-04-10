from __future__ import annotations

import re
from pathlib import Path

from reverser.analysis.analyzers.base import Analyzer
from reverser.models import AnalysisReport


ASCII_PATTERN = re.compile(rb"[\x20-\x7e]{4,}")
UTF16LE_PATTERN = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
URL_PATTERN = re.compile(r"https?://[^\s\"']+")
PATH_PATTERN = re.compile(r"[A-Za-z]:\\[^:*?\"<>|\r\n]+")
DEFAULT_MAX_BYTES = 8 * 1024 * 1024


def _decode_utf16_chunks(matches: list[bytes]) -> list[str]:
    decoded: list[str] = []
    for match in matches:
        try:
            decoded.append(match.decode("utf-16le"))
        except UnicodeDecodeError:
            continue
    return decoded


class StringsAnalyzer(Analyzer):
    name = "strings"

    def __init__(self, *, max_results: int = 200, max_bytes: int = DEFAULT_MAX_BYTES) -> None:
        self.max_results = max_results
        self.max_bytes = max_bytes

    def supports(self, target: Path) -> bool:
        return target.is_file()

    def analyze(self, target: Path, report: AnalysisReport) -> None:
        data, truncated = self._read_windowed_bytes(target)
        ascii_matches = [item.decode("ascii", errors="ignore") for item in ASCII_PATTERN.findall(data)]
        utf16_matches = _decode_utf16_chunks(UTF16LE_PATTERN.findall(data))

        combined = []
        seen: set[str] = set()
        for candidate in ascii_matches + utf16_matches:
            stripped = candidate.strip()
            if stripped and stripped not in seen:
                combined.append(stripped)
                seen.add(stripped)
            if len(combined) >= self.max_results:
                break

        urls = [match.group(0) for item in combined if (match := URL_PATTERN.search(item))]
        paths = [match.group(0) for item in combined if (match := PATH_PATTERN.search(item))]

        report.add_section(
            "strings",
            {
                "count": len(combined),
                "sample": combined[: min(40, len(combined))],
                "urls": urls[:20],
                "paths": paths[:20],
                "truncated": truncated,
                "inspected_bytes": len(data),
                "source_size_bytes": target.stat().st_size,
            },
        )

        if urls:
            report.add_finding(
                "network",
                "Embedded URLs found",
                f"Recovered {len(urls)} URL-like strings from the target.",
                severity="medium",
                urls=urls[:20],
            )

    def _read_windowed_bytes(self, target: Path) -> tuple[bytes, bool]:
        total_size = target.stat().st_size
        if total_size <= self.max_bytes:
            return target.read_bytes(), False

        head_bytes = self.max_bytes // 2
        tail_bytes = self.max_bytes - head_bytes
        separator = b"\n[TRUNCATED]\n"
        with target.open("rb") as handle:
            prefix = handle.read(head_bytes)
            handle.seek(max(0, total_size - tail_bytes))
            suffix = handle.read(tail_bytes)
        return prefix + separator + suffix, True
