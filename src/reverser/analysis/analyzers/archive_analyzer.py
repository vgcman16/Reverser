from __future__ import annotations

import tarfile
import zipfile
from pathlib import Path

from reverser.analysis.analyzers.base import Analyzer
from reverser.models import AnalysisReport


ARCHIVE_EXTENSIONS = {".zip", ".tar", ".gz", ".tgz", ".bz2", ".tbz", ".xz", ".txz"}


class ArchiveAnalyzer(Analyzer):
    name = "archive"

    def supports(self, target: Path) -> bool:
        return target.is_file() and (
            zipfile.is_zipfile(target) or tarfile.is_tarfile(target) or target.suffix.lower() in ARCHIVE_EXTENSIONS
        )

    def analyze(self, target: Path, report: AnalysisReport) -> None:
        if zipfile.is_zipfile(target):
            with zipfile.ZipFile(target) as archive:
                members = archive.infolist()
                report.add_section(
                    "archive",
                    {
                        "type": "zip",
                        "member_count": len(members),
                        "members": [member.filename for member in members[:50]],
                        "total_uncompressed_bytes": sum(member.file_size for member in members),
                    },
                )
            return

        if tarfile.is_tarfile(target):
            with tarfile.open(target) as archive:
                members = archive.getmembers()
                report.add_section(
                    "archive",
                    {
                        "type": "tar",
                        "member_count": len(members),
                        "members": [member.name for member in members[:50]],
                        "total_uncompressed_bytes": sum(member.size for member in members),
                    },
                )
