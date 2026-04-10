from __future__ import annotations

from pathlib import Path

from reverser.analysis.analyzers.base import Analyzer
from reverser.analysis.analyzers.js5_cache_analyzer import _load_index_names, _match_jcache_name
from reverser.models import AnalysisReport


MAX_ARCHIVE_LIST = 25


class JS5CacheDirectoryAnalyzer(Analyzer):
    name = "js5-cache-directory"

    def supports(self, target: Path) -> bool:
        if not target.is_dir():
            return False
        return any(child.is_file() and _match_jcache_name(child) is not None for child in target.iterdir())

    def analyze(self, target: Path, report: AnalysisReport) -> None:
        index_names, mapping_source, mapping_build = _load_index_names(str(target))
        archives: list[dict[str, object]] = []

        for child in target.iterdir():
            if not child.is_file():
                continue
            match = _match_jcache_name(child)
            if match is None:
                continue

            archive_id = int(match.group("archive_id"))
            store_kind = "core-js5" if match.group("core") else "js5"
            archives.append(
                {
                    "path": child.name,
                    "archive_id": archive_id,
                    "store_kind": store_kind,
                    "index_name": index_names.get(archive_id),
                    "size_bytes": child.stat().st_size,
                }
            )

        if not archives:
            return

        archives_by_id = sorted(archives, key=lambda item: (str(item["store_kind"]), int(item["archive_id"])))
        largest_archives = sorted(archives, key=lambda item: (-int(item["size_bytes"]), str(item["path"])))
        mapped_count = sum(1 for item in archives if isinstance(item.get("index_name"), str))

        report.add_section(
            "js5_cache_directory",
            {
                "cache_count": len(archives),
                "core_cache_count": sum(1 for item in archives if item["store_kind"] == "core-js5"),
                "mapped_archive_count": mapped_count,
                "unmapped_archive_count": len(archives) - mapped_count,
                "total_bytes": sum(int(item["size_bytes"]) for item in archives),
                "mapping_source": mapping_source,
                "mapping_build": mapping_build,
                "archives_by_id": archives_by_id[:MAX_ARCHIVE_LIST],
                "largest_archives": largest_archives[:MAX_ARCHIVE_LIST],
            },
        )
