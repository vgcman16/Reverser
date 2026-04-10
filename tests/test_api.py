from __future__ import annotations

import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

import bz2
import gzip
import lzma

from reverser.api import build_handler


def _build_js5_record(payload: bytes, *, compression: str, revision: int = 1) -> bytes:
    if compression == "lzma":
        lc = 3
        lp = 0
        pb = 2
        dict_size = 1 << 20
        packed = lzma.compress(
            payload,
            format=lzma.FORMAT_RAW,
            filters=[
                {
                    "id": lzma.FILTER_LZMA1,
                    "dict_size": dict_size,
                    "lc": lc,
                    "lp": lp,
                    "pb": pb,
                }
            ],
        )
        property_byte = pb * 45 + lp * 9 + lc
        props = bytes([property_byte]) + dict_size.to_bytes(4, "little")
        packed = props + packed
        return b"\x03" + len(packed).to_bytes(4, "big") + len(payload).to_bytes(4, "big") + packed + revision.to_bytes(2, "big")

    if compression == "gzip":
        packed = gzip.compress(payload)
        return b"\x02" + len(packed).to_bytes(4, "big") + len(payload).to_bytes(4, "big") + packed + revision.to_bytes(2, "big")

    if compression == "bzip2":
        packed = bz2.compress(payload)
        stripped = packed[4:]
        return b"\x01" + len(stripped).to_bytes(4, "big") + len(payload).to_bytes(4, "big") + stripped + revision.to_bytes(2, "big")

    return b"\x00" + len(payload).to_bytes(4, "big") + payload + revision.to_bytes(2, "big")


def _write_js5_mapping(root: Path, *, build: int, index_names: dict[int, str]) -> None:
    mapping_path = root / "data" / "prot" / str(build) / "generated" / "shared" / "js5-archive-resolution.json"
    mapping_path.parent.mkdir(parents=True, exist_ok=True)
    mapping_path.write_text(
        json.dumps(
            {
                "build": build,
                "indexNames": {str(key): value for key, value in index_names.items()},
            }
        ),
        encoding="utf-8",
    )


def _request_json(url: str, body: dict | None = None) -> dict:
    data = None
    headers = {}
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"

    request = urllib.request.Request(url, data=data, headers=headers)
    with urllib.request.urlopen(request, timeout=10) as response:
        return json.loads(response.read().decode("utf-8"))


def test_api_health_and_analyzers():
    server = ThreadingHTTPServer(("127.0.0.1", 0), build_handler())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"

    try:
        health = _request_json(f"{base_url}/health")
        analyzers = _request_json(f"{base_url}/analyzers")
    finally:
        server.shutdown()
        thread.join(timeout=10)

    assert health["status"] == "ok"
    assert any(item["name"] == "mach-o" for item in analyzers["analyzers"])


def test_api_analyze_endpoint(tmp_path):
    target = tmp_path / "sample.bin"
    target.write_bytes(b"hello admin@example.com")

    server = ThreadingHTTPServer(("127.0.0.1", 0), build_handler())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"

    try:
        payload = _request_json(f"{base_url}/analyze", {"target": str(target)})
    finally:
        server.shutdown()
        thread.join(timeout=10)

    assert payload["target"]["path"].endswith("sample.bin")
    assert "ioc" in payload["sections"]


def test_api_catalog_ingest_and_search(tmp_path):
    db_path = tmp_path / "catalog.sqlite3"
    target = tmp_path / "sample.bin"
    target.write_bytes(b"hello admin@example.com")

    server = ThreadingHTTPServer(("127.0.0.1", 0), build_handler())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"

    try:
        ingest_payload = _request_json(
            f"{base_url}/catalog/ingest",
            {"db": str(db_path), "source": str(target)},
        )
        search_payload = _request_json(
            f"{base_url}/catalog/search",
            {"db": str(db_path), "min_findings": 1},
        )
    finally:
        server.shutdown()
        thread.join(timeout=10)

    assert ingest_payload["entry_count"] == 1
    assert search_payload["count"] == 1


def test_api_js5_export_endpoint(tmp_path):
    import sqlite3

    root = tmp_path / "OpenNXT"
    target = root / "data" / "cache" / "js5-47.jcache"
    export_dir = tmp_path / "exports"
    target.parent.mkdir(parents=True, exist_ok=True)
    _write_js5_mapping(root, build=947, index_names={47: "MODELS_RT7"})

    with sqlite3.connect(target) as connection:
        connection.execute("CREATE TABLE cache (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute(
            "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (5, _build_js5_record(b"payload", compression="lzma"), 1, 2),
        )
        connection.commit()

    server = ThreadingHTTPServer(("127.0.0.1", 0), build_handler())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"

    try:
        manifest = _request_json(
            f"{base_url}/js5/export",
            {"target": str(target), "output_dir": str(export_dir), "tables": ["cache"]},
        )
    finally:
        server.shutdown()
        thread.join(timeout=10)

    assert manifest["archive_id"] == 47
    assert manifest["summary"]["decoded_record_count"] == 1
    assert (export_dir / "cache" / "key-5.payload.bin").exists()
