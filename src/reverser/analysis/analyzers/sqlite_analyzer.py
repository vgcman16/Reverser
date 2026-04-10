from __future__ import annotations

import sqlite3
from pathlib import Path

from reverser.analysis.analyzers.base import Analyzer
from reverser.models import AnalysisReport


SQLITE_HEADER = b"SQLite format 3\x00"
MAX_OBJECT_NAMES = 50
MAX_TABLES = 25
MAX_COLUMNS = 16


def _looks_like_sqlite(path: Path) -> bool:
    if not path.is_file():
        return False
    with path.open("rb") as handle:
        return handle.read(len(SQLITE_HEADER)) == SQLITE_HEADER


def _quote_identifier(name: str) -> str:
    return f'"{name.replace("\"", "\"\"")}"'


class SQLiteAnalyzer(Analyzer):
    name = "sqlite"

    def supports(self, target: Path) -> bool:
        return _looks_like_sqlite(target)

    def analyze(self, target: Path, report: AnalysisReport) -> None:
        with sqlite3.connect(str(target)) as connection:
            cursor = connection.cursor()

            page_size = int(cursor.execute("PRAGMA page_size").fetchone()[0])
            page_count = int(cursor.execute("PRAGMA page_count").fetchone()[0])
            freelist_count = int(cursor.execute("PRAGMA freelist_count").fetchone()[0])
            schema_version = int(cursor.execute("PRAGMA schema_version").fetchone()[0])
            user_version = int(cursor.execute("PRAGMA user_version").fetchone()[0])
            encoding = str(cursor.execute("PRAGMA encoding").fetchone()[0])
            journal_mode = str(cursor.execute("PRAGMA journal_mode").fetchone()[0])

            objects = cursor.execute(
                """
                SELECT type, name
                FROM sqlite_master
                WHERE type IN ('table', 'index', 'view', 'trigger')
                ORDER BY type, name
                """
            ).fetchall()

            tables: list[str] = []
            indexes: list[str] = []
            views: list[str] = []
            triggers: list[str] = []
            for object_type, name in objects:
                if object_type == "table":
                    tables.append(str(name))
                elif object_type == "index":
                    indexes.append(str(name))
                elif object_type == "view":
                    views.append(str(name))
                elif object_type == "trigger":
                    triggers.append(str(name))

            table_summaries: list[dict[str, object]] = []
            for table_name in tables[:MAX_TABLES]:
                quoted_name = _quote_identifier(table_name)
                row_count = int(cursor.execute(f"SELECT COUNT(*) FROM {quoted_name}").fetchone()[0])
                columns = cursor.execute(f"PRAGMA table_info({quoted_name})").fetchall()
                table_summaries.append(
                    {
                        "name": table_name,
                        "row_count": row_count,
                        "column_count": len(columns),
                        "columns": [
                            {
                                "name": str(column[1]),
                                "type": str(column[2] or ""),
                                "not_null": bool(column[3]),
                                "primary_key_position": int(column[5]),
                            }
                            for column in columns[:MAX_COLUMNS]
                        ],
                    }
                )

        report.add_section(
            "sqlite",
            {
                "page_size": page_size,
                "page_count": page_count,
                "freelist_count": freelist_count,
                "approx_database_bytes": page_size * page_count,
                "encoding": encoding,
                "journal_mode": journal_mode,
                "schema_version": schema_version,
                "user_version": user_version,
                "object_counts": {
                    "tables": len(tables),
                    "indexes": len(indexes),
                    "views": len(views),
                    "triggers": len(triggers),
                },
                "tables": table_summaries,
                "indexes": indexes[:MAX_OBJECT_NAMES],
                "views": views[:MAX_OBJECT_NAMES],
                "triggers": triggers[:MAX_OBJECT_NAMES],
            },
        )
