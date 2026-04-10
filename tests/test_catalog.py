from __future__ import annotations

from reverser.catalog import catalog_stats, ingest_into_catalog, list_catalog_ingests, search_catalog


def test_catalog_ingest_and_search(tmp_path):
    db_path = tmp_path / "catalog.sqlite3"
    target = tmp_path / "sample.bin"
    target.write_bytes(b"hello admin@example.com 10.2.3.4")

    ingest = ingest_into_catalog(target, db_path=db_path)
    search = search_catalog(db_path=db_path, min_findings=1)
    ingests = list_catalog_ingests(db_path=db_path)
    stats = catalog_stats(db_path=db_path)

    assert ingest.entry_count == 1
    assert search["count"] == 1
    assert search["results"][0]["sha256"]
    assert ingests["count"] == 1
    assert stats["artifact_count"] == 1


def test_catalog_ingest_scan_index_and_filter_by_signature(tmp_path):
    db_path = tmp_path / "catalog.sqlite3"
    root = tmp_path / "game"
    root.mkdir()
    (root / "Game.exe").write_bytes(b"MZ" + b"\x00" * 512)
    (root / "patch.pak").write_bytes(b"demo")

    ingest_into_catalog(root, db_path=db_path, max_files=10)
    search = search_catalog(db_path=db_path, signature="portable-executable")

    assert search["count"] == 1
    assert search["results"][0]["relative_path"] == "Game.exe"
