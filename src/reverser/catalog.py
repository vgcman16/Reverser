from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from reverser import __version__
from reverser.analysis.diffing import load_or_generate_artifact


JsonDict = dict[str, Any]


def default_catalog_path() -> Path:
    return Path(".reverser") / "catalog.sqlite3"


@dataclass(slots=True)
class CatalogIngestResult:
    db_path: str
    ingest_id: int
    artifact_kind: str
    entry_count: int
    created_at: str
    source_ref: str

    def to_dict(self) -> JsonDict:
        return {
            "tool": {"name": "reverser-workbench", "version": __version__},
            "db_path": self.db_path,
            "ingest_id": self.ingest_id,
            "artifact_kind": self.artifact_kind,
            "entry_count": self.entry_count,
            "created_at": self.created_at,
            "source_ref": self.source_ref,
        }


def init_catalog(db_path: str | Path | None = None) -> Path:
    path = Path(db_path) if db_path else default_catalog_path()
    path = path.expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)

    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS ingests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                artifact_kind TEXT NOT NULL,
                source_ref TEXT NOT NULL,
                root_path TEXT,
                summary_json TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS artifacts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ingest_id INTEGER NOT NULL REFERENCES ingests(id) ON DELETE CASCADE,
                path TEXT NOT NULL,
                relative_path TEXT NOT NULL,
                kind TEXT NOT NULL,
                size_bytes INTEGER NOT NULL,
                signature TEXT NOT NULL,
                mime_guess TEXT,
                entropy REAL,
                md5 TEXT,
                sha1 TEXT,
                sha256 TEXT,
                finding_count INTEGER NOT NULL,
                severity_counts_json TEXT NOT NULL,
                warning_count INTEGER NOT NULL,
                error_count INTEGER NOT NULL,
                json_report_path TEXT,
                markdown_report_path TEXT
            );

            CREATE TABLE IF NOT EXISTS artifact_tags (
                artifact_id INTEGER NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
                tag TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS artifact_engines (
                artifact_id INTEGER NOT NULL REFERENCES artifacts(id) ON DELETE CASCADE,
                engine TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_ingests_created_at ON ingests(created_at DESC);
            CREATE INDEX IF NOT EXISTS idx_artifacts_signature ON artifacts(signature);
            CREATE INDEX IF NOT EXISTS idx_artifacts_sha256 ON artifacts(sha256);
            CREATE INDEX IF NOT EXISTS idx_artifacts_relative_path ON artifacts(relative_path);
            CREATE INDEX IF NOT EXISTS idx_artifacts_finding_count ON artifacts(finding_count DESC);
            CREATE INDEX IF NOT EXISTS idx_artifact_tags_tag ON artifact_tags(tag);
            CREATE INDEX IF NOT EXISTS idx_artifact_engines_engine ON artifact_engines(engine);
            """
        )

    return path


def ingest_into_catalog(
    source: str | Path,
    *,
    db_path: str | Path | None = None,
    max_strings: int = 200,
    max_files: int = 250,
    max_file_mb: int = 256,
) -> CatalogIngestResult:
    path = init_catalog(db_path)
    artifact = load_or_generate_artifact(
        source,
        max_strings=max_strings,
        max_files=max_files,
        max_file_mb=max_file_mb,
    )
    artifact_kind = _artifact_kind(artifact)
    created_at = datetime.now(UTC).replace(microsecond=0).isoformat()
    source_ref = str(Path(source).expanduser().resolve())

    if artifact_kind == "report":
        root_path = str(Path(artifact["target"]["path"]).parent)
        summary = artifact.get("summary", {})
        entries = [_entry_from_report_artifact(artifact)]
    elif artifact_kind == "scan-index":
        root_path = str(artifact.get("root_path", source_ref))
        summary = artifact.get("summary", {})
        entries = [dict(item) for item in artifact.get("entries", [])]
    else:
        raise ValueError("Unsupported artifact type for catalog ingest.")

    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA foreign_keys=ON")
        cursor = connection.execute(
            """
            INSERT INTO ingests(created_at, artifact_kind, source_ref, root_path, summary_json)
            VALUES (?, ?, ?, ?, ?)
            """,
            (created_at, artifact_kind, source_ref, root_path, json.dumps(summary)),
        )
        ingest_id = int(cursor.lastrowid)

        for entry in entries:
            artifact_cursor = connection.execute(
                """
                INSERT INTO artifacts(
                    ingest_id, path, relative_path, kind, size_bytes, signature,
                    mime_guess, entropy, md5, sha1, sha256, finding_count,
                    severity_counts_json, warning_count, error_count,
                    json_report_path, markdown_report_path
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    ingest_id,
                    entry.get("path"),
                    entry.get("relative_path"),
                    entry.get("kind"),
                    int(entry.get("size_bytes", 0)),
                    entry.get("signature", "unknown"),
                    entry.get("mime_guess"),
                    entry.get("entropy"),
                    entry.get("md5"),
                    entry.get("sha1"),
                    entry.get("sha256"),
                    int(entry.get("finding_count", 0)),
                    json.dumps(entry.get("severity_counts", {})),
                    int(entry.get("warning_count", 0)),
                    int(entry.get("error_count", 0)),
                    entry.get("json_report_path"),
                    entry.get("markdown_report_path"),
                ),
            )
            artifact_id = int(artifact_cursor.lastrowid)

            for tag in entry.get("tags", []):
                connection.execute(
                    "INSERT INTO artifact_tags(artifact_id, tag) VALUES (?, ?)",
                    (artifact_id, str(tag)),
                )
            for engine in entry.get("engines", []):
                connection.execute(
                    "INSERT INTO artifact_engines(artifact_id, engine) VALUES (?, ?)",
                    (artifact_id, str(engine)),
                )

    return CatalogIngestResult(
        db_path=str(path),
        ingest_id=ingest_id,
        artifact_kind=artifact_kind,
        entry_count=len(entries),
        created_at=created_at,
        source_ref=source_ref,
    )


def search_catalog(
    *,
    db_path: str | Path | None = None,
    signature: str | None = None,
    engine: str | None = None,
    tag: str | None = None,
    path_contains: str | None = None,
    sha256: str | None = None,
    min_findings: int | None = None,
    limit: int = 50,
) -> JsonDict:
    path = init_catalog(db_path)
    query = """
        SELECT
            a.id,
            a.path,
            a.relative_path,
            a.kind,
            a.size_bytes,
            a.signature,
            a.mime_guess,
            a.entropy,
            a.md5,
            a.sha1,
            a.sha256,
            a.finding_count,
            a.severity_counts_json,
            a.warning_count,
            a.error_count,
            a.json_report_path,
            a.markdown_report_path,
            i.id,
            i.created_at,
            i.source_ref,
            i.root_path
        FROM artifacts a
        JOIN ingests i ON i.id = a.ingest_id
        WHERE (? IS NULL OR a.signature = ?)
          AND (? IS NULL OR a.sha256 = ?)
          AND (? IS NULL OR a.finding_count >= ?)
          AND (? IS NULL OR LOWER(a.path) LIKE '%' || LOWER(?) || '%')
          AND (? IS NULL OR EXISTS (
                SELECT 1 FROM artifact_engines e
                WHERE e.artifact_id = a.id AND e.engine = ?
          ))
          AND (? IS NULL OR EXISTS (
                SELECT 1 FROM artifact_tags t
                WHERE t.artifact_id = a.id AND t.tag = ?
          ))
        ORDER BY a.finding_count DESC, a.size_bytes DESC, i.created_at DESC
        LIMIT ?
    """
    params = (
        signature,
        signature,
        sha256,
        sha256,
        min_findings,
        min_findings,
        path_contains,
        path_contains,
        engine,
        engine,
        tag,
        tag,
        limit,
    )

    with sqlite3.connect(path) as connection:
        rows = connection.execute(query, params).fetchall()

        results = []
        for row in rows:
            artifact_id = int(row[0])
            tags = [item[0] for item in connection.execute("SELECT tag FROM artifact_tags WHERE artifact_id = ?", (artifact_id,))]
            engines = [
                item[0]
                for item in connection.execute("SELECT engine FROM artifact_engines WHERE artifact_id = ?", (artifact_id,))
            ]
            results.append(
                {
                    "path": row[1],
                    "relative_path": row[2],
                    "kind": row[3],
                    "size_bytes": row[4],
                    "signature": row[5],
                    "mime_guess": row[6],
                    "entropy": row[7],
                    "md5": row[8],
                    "sha1": row[9],
                    "sha256": row[10],
                    "finding_count": row[11],
                    "severity_counts": json.loads(row[12]),
                    "warning_count": row[13],
                    "error_count": row[14],
                    "json_report_path": row[15],
                    "markdown_report_path": row[16],
                    "ingest": {
                        "id": row[17],
                        "created_at": row[18],
                        "source_ref": row[19],
                        "root_path": row[20],
                    },
                    "tags": tags,
                    "engines": engines,
                }
            )

    return {
        "tool": {"name": "reverser-workbench", "version": __version__},
        "db_path": str(path),
        "filters": {
            "signature": signature,
            "engine": engine,
            "tag": tag,
            "path_contains": path_contains,
            "sha256": sha256,
            "min_findings": min_findings,
            "limit": limit,
        },
        "count": len(results),
        "results": results,
    }


def list_catalog_ingests(*, db_path: str | Path | None = None, limit: int = 20) -> JsonDict:
    path = init_catalog(db_path)
    with sqlite3.connect(path) as connection:
        rows = connection.execute(
            """
            SELECT id, created_at, artifact_kind, source_ref, root_path, summary_json
            FROM ingests
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()

    ingests = [
        {
            "id": row[0],
            "created_at": row[1],
            "artifact_kind": row[2],
            "source_ref": row[3],
            "root_path": row[4],
            "summary": json.loads(row[5]),
        }
        for row in rows
    ]
    return {
        "tool": {"name": "reverser-workbench", "version": __version__},
        "db_path": str(path),
        "count": len(ingests),
        "ingests": ingests,
    }


def catalog_stats(*, db_path: str | Path | None = None) -> JsonDict:
    path = init_catalog(db_path)
    with sqlite3.connect(path) as connection:
        ingest_count = connection.execute("SELECT COUNT(*) FROM ingests").fetchone()[0]
        artifact_count = connection.execute("SELECT COUNT(*) FROM artifacts").fetchone()[0]
        signatures = connection.execute(
            "SELECT signature, COUNT(*) FROM artifacts GROUP BY signature ORDER BY COUNT(*) DESC LIMIT 20"
        ).fetchall()
        tags = connection.execute(
            "SELECT tag, COUNT(*) FROM artifact_tags GROUP BY tag ORDER BY COUNT(*) DESC LIMIT 20"
        ).fetchall()
        engines = connection.execute(
            "SELECT engine, COUNT(*) FROM artifact_engines GROUP BY engine ORDER BY COUNT(*) DESC LIMIT 20"
        ).fetchall()

    return {
        "tool": {"name": "reverser-workbench", "version": __version__},
        "db_path": str(path),
        "ingest_count": ingest_count,
        "artifact_count": artifact_count,
        "top_signatures": [{"signature": item[0], "count": item[1]} for item in signatures],
        "top_tags": [{"tag": item[0], "count": item[1]} for item in tags],
        "top_engines": [{"engine": item[0], "count": item[1]} for item in engines],
    }


def _artifact_kind(payload: JsonDict) -> str:
    if "target" in payload and "sections" in payload:
        return "report"
    if "entries" in payload and "root_path" in payload:
        return "scan-index"
    return "unknown"


def _entry_from_report_artifact(payload: JsonDict) -> JsonDict:
    identity = payload.get("sections", {}).get("identity", {})
    hashes = identity.get("hashes", {}) if isinstance(identity, dict) else {}
    engines = [
        item["engine"]
        for item in payload.get("sections", {}).get("game_fingerprint", {}).get("engines", [])
        if isinstance(item, dict) and isinstance(item.get("engine"), str)
    ]
    target_path = Path(payload["target"]["path"])
    return {
        "path": str(target_path),
        "relative_path": target_path.name,
        "kind": payload["target"]["kind"],
        "size_bytes": payload["target"]["size_bytes"],
        "signature": identity.get("signature", "unknown"),
        "mime_guess": identity.get("mime_guess"),
        "entropy": identity.get("entropy"),
        "md5": hashes.get("md5"),
        "sha1": hashes.get("sha1"),
        "sha256": hashes.get("sha256"),
        "engines": engines,
        "finding_count": payload.get("summary", {}).get("finding_count", 0),
        "severity_counts": payload.get("summary", {}).get("severity_counts", {}),
        "warning_count": payload.get("summary", {}).get("warning_count", 0),
        "error_count": payload.get("summary", {}).get("error_count", 0),
        "tags": payload.get("summary", {}).get("tags", []),
        "json_report_path": None,
        "markdown_report_path": None,
    }
