from __future__ import annotations

import sqlite3

from reverser.analysis.orchestrator import AnalysisEngine


def test_sqlite_analyzer_reports_schema_and_counts(tmp_path):
    target = tmp_path / "sample.sqlite"
    with sqlite3.connect(target) as connection:
        connection.execute("CREATE TABLE demo (id INTEGER PRIMARY KEY, name TEXT, payload BLOB)")
        connection.execute("INSERT INTO demo (name, payload) VALUES (?, ?)", ("hello", b"payload"))
        connection.commit()

    report = AnalysisEngine().analyze(target)

    assert report.sections["identity"]["signature"] == "sqlite"
    sqlite = report.sections["sqlite"]
    assert sqlite["object_counts"]["tables"] == 1
    assert sqlite["page_size"] > 0
    assert sqlite["approx_database_bytes"] >= target.stat().st_size
    assert sqlite["tables"][0]["name"] == "demo"
    assert sqlite["tables"][0]["row_count"] == 1
