from __future__ import annotations

import re
from pathlib import Path

from reverser.analysis.analyzers.base import Analyzer
from reverser.models import AnalysisReport


IPV4_PATTERN = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"
)
EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
SECRET_PATTERNS = (
    re.compile(r"(?i)\b(?:password|passwd|api[_-]?key|apikey|client[_-]?secret|private[_-]?key|token)\b\s*[:=]"),
    re.compile(r"(?i)\bauthorization\b\s*:\s*bearer\s+[A-Za-z0-9._\-]{6,}"),
    re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{10,}"),
)


class IOCAnalyzer(Analyzer):
    name = "ioc"

    def supports(self, target: Path) -> bool:
        return target.is_file()

    def analyze(self, target: Path, report: AnalysisReport) -> None:
        strings = report.sections.get("strings", {})
        samples = strings.get("sample", []) if isinstance(strings, dict) else []
        text_items = [item for item in samples if isinstance(item, str)]

        ipv4_hits = sorted({match.group(0) for item in text_items for match in IPV4_PATTERN.finditer(item)})
        email_hits = sorted({match.group(0) for item in text_items for match in EMAIL_PATTERN.finditer(item)})
        secret_hits = []
        for item in text_items:
            for pattern in SECRET_PATTERNS:
                if pattern.search(item):
                    secret_hits.append(item[:120])
                    break

        pe = report.sections.get("pe", {})
        high_entropy_sections = []
        if isinstance(pe, dict):
            for section in pe.get("sections", []):
                if isinstance(section, dict) and float(section.get("entropy", 0.0)) >= 7.2:
                    high_entropy_sections.append(
                        {
                            "name": section.get("name", "<unknown>"),
                            "entropy": section.get("entropy", 0.0),
                        }
                    )

        report.add_section(
            "ioc",
            {
                "ipv4_addresses": ipv4_hits[:20],
                "email_addresses": email_hits[:20],
                "secret_like_strings": secret_hits[:20],
                "high_entropy_sections": high_entropy_sections[:20],
            },
        )

        if ipv4_hits or email_hits:
            report.add_finding(
                "ioc",
                "Network indicators found",
                "Recovered IP addresses or email addresses from embedded strings.",
                severity="medium",
                ipv4_addresses=ipv4_hits[:20],
                email_addresses=email_hits[:20],
            )

        if secret_hits:
            report.add_finding(
                "ioc",
                "Secret-like material referenced",
                "Recovered strings that look like credentials, tokens, or secret references.",
                severity="medium",
                sample=secret_hits[:10],
            )

        if high_entropy_sections:
            report.add_finding(
                "ioc",
                "High-entropy PE sections",
                "One or more PE sections are highly compressed or packed.",
                severity="low",
                sections=high_entropy_sections[:10],
            )
