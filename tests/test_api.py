from __future__ import annotations

import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer

from reverser.api import build_handler


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
