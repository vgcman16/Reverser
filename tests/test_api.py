from __future__ import annotations

import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

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


def test_api_js5_probe_schema_endpoints():
    server = ThreadingHTTPServer(("127.0.0.1", 0), build_handler())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"

    try:
        for path, required_field in (
            ("/schema/js5-opcode-probe", "raw_opcode"),
            ("/schema/js5-opcode-interior-probe", "hits"),
            ("/schema/js5-opcode-subtypes", "blocked_frontier_subtype_candidates"),
            ("/schema/js5-branch-clusters", "structural_clusters"),
            ("/schema/js5-pseudocode-blockers", "blocked_profile_count"),
        ):
            payload = _request_json(f"{base_url}{path}")
            assert payload["type"] == "object"
            assert required_field in payload["required"]
    finally:
        server.shutdown()
        thread.join(timeout=10)


def test_api_request_schema_endpoints():
    server = ThreadingHTTPServer(("127.0.0.1", 0), build_handler())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"

    try:
        for path, required_field, property_field in (
            ("/schema/analyze-request", "target", "max_strings"),
            ("/schema/scan-request", "target", "workers"),
            ("/schema/diff-request", "base", "head"),
            ("/schema/js5-export-request", "target", "output_dir"),
            ("/schema/js5-opcode-probe-request", "source", "opcode"),
            ("/schema/catalog-search-request", None, "limit"),
        ):
            payload = _request_json(f"{base_url}{path}")
            assert payload["type"] == "object"
            if required_field is not None:
                assert required_field in payload["required"]
            assert property_field in payload["properties"]
    finally:
        server.shutdown()
        thread.join(timeout=10)


def test_api_schema_index_lists_available_schemas():
    server = ThreadingHTTPServer(("127.0.0.1", 0), build_handler())
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base_url = f"http://127.0.0.1:{server.server_port}"

    try:
        payload = _request_json(f"{base_url}/schema")
    finally:
        server.shutdown()
        thread.join(timeout=10)

    assert payload["count"] >= 17
    assert any(item["kind"] == "report" for item in payload["schemas"])
    assert any(item["kind"] == "js5-opcode-probe" for item in payload["schemas"])
    assert any(item["path"] == "/schema/js5-pseudocode-blockers" for item in payload["schemas"])
    assert any(item["kind"] == "analyze-request" for item in payload["schemas"])
    assert any(item["path"] == "/schema/js5-opcode-probe-request" for item in payload["schemas"])
    assert any(item["path"] == "/schema/pe-address-refs" for item in payload["schemas"])
    assert any(item["path"] == "/schema/pe-field-refs" for item in payload["schemas"])
    assert any(item["path"] == "/schema/pe-function-literals" for item in payload["schemas"])
    assert any(item["path"] == "/schema/pe-indirect-dispatches" for item in payload["schemas"])
    assert any(item["path"] == "/schema/pe-registration-records" for item in payload["schemas"])
    assert any(item["path"] == "/schema/pe-selector-table-dispatches" for item in payload["schemas"])
    assert any(item["path"] == "/schema/pe-runtime-functions" for item in payload["schemas"])
    assert any(item["path"] == "/schema/pe-qwords" for item in payload["schemas"])
    assert any(item["path"] == "/schema/pe-dwords" for item in payload["schemas"])
    assert any(item["path"] == "/schema/pe-delay-imports" for item in payload["schemas"])
    assert any(item["path"] == "/schema/pe-strings" for item in payload["schemas"])
    assert any(item["path"] == "/schema/pe-vtable-slots" for item in payload["schemas"])
    assert any(item["path"] == "/schema/pe-rtti-type-descriptors" for item in payload["schemas"])
    assert any(item["path"] == "/schema/pe-provider-descriptors" for item in payload["schemas"])
    assert any(item["path"] == "/schema/pe-provider-descriptor-scan" for item in payload["schemas"])
    assert any(item["path"] == "/schema/pe-provider-descriptor-clusters" for item in payload["schemas"])


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


def test_api_js5_probe_endpoints_dispatch_expected_analysis_calls(tmp_path):
    manifest_path = tmp_path / "exports" / "manifest.json"
    manifest_path.parent.mkdir(parents=True, exist_ok=True)
    manifest_path.write_text("{}", encoding="utf-8")

    opcode_payload = {"kind": "clientscript-opcode-probe", "hit_count": 1}
    interior_payload = {"kind": "clientscript-opcode-interior-probe", "hit_count": 2}
    subtype_payload = {
        "kind": "clientscript-opcode-subtype-probe",
        "blocked_frontier_subtype_candidate_count": 3,
    }
    branch_payload = {"kind": "clientscript-branch-cluster-probe", "hit_count": 4}
    blocker_payload = {
        "kind": "clientscript-pseudocode-blocker-probe",
        "blocked_profile_count": 5,
    }

    with (
        patch("reverser.api.probe_js5_export_opcode", return_value=opcode_payload) as opcode_probe,
        patch(
            "reverser.api.probe_js5_export_interior_opcode",
            return_value=interior_payload,
        ) as interior_probe,
        patch(
            "reverser.api.probe_js5_export_opcode_subtypes",
            return_value=subtype_payload,
        ) as subtype_probe,
        patch(
            "reverser.api.probe_js5_export_branch_clusters",
            return_value=branch_payload,
        ) as branch_probe,
        patch(
            "reverser.api.probe_js5_export_pseudocode_blockers",
            return_value=blocker_payload,
        ) as blocker_probe,
    ):
        server = ThreadingHTTPServer(("127.0.0.1", 0), build_handler())
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        base_url = f"http://127.0.0.1:{server.server_port}"

        try:
            opcode_response = _request_json(
                f"{base_url}/js5/opcode-probe",
                {
                    "source": str(manifest_path),
                    "opcode": 317,
                    "table": "cache",
                    "key": 5,
                    "file_id": 2,
                    "max_hits": 9,
                },
            )
            interior_response = _request_json(
                f"{base_url}/js5/opcode-interior-probe",
                {
                    "source": str(manifest_path),
                    "opcode": 317,
                    "table": "cache",
                    "keys": [5, 7],
                    "file_id": 3,
                    "max_hits": 11,
                    "ready_only": True,
                },
            )
            subtype_response = _request_json(
                f"{base_url}/js5/opcode-subtypes",
                {
                    "source": str(manifest_path),
                    "opcode": 317,
                    "table": "cache",
                    "key": 13,
                    "file_id": 4,
                    "max_hits": 6,
                },
            )
            branch_response = _request_json(
                f"{base_url}/js5/branch-clusters",
                {
                    "source": str(manifest_path),
                    "opcode": 317,
                    "table": "cache",
                    "key": 17,
                    "file_id": 8,
                    "max_hits": 5,
                },
            )
            blocker_response = _request_json(
                f"{base_url}/js5/pseudocode-blockers",
                {
                    "source": str(manifest_path),
                    "max_sample": 12,
                },
            )
        finally:
            server.shutdown()
            thread.join(timeout=10)

    assert opcode_response == opcode_payload
    assert interior_response == interior_payload
    assert subtype_response == subtype_payload
    assert branch_response == branch_payload
    assert blocker_response == blocker_payload

    opcode_probe.assert_called_once_with(
        str(manifest_path),
        317,
        table="cache",
        key=5,
        file_id=2,
        max_hits=9,
    )
    interior_probe.assert_called_once_with(
        str(manifest_path),
        317,
        table="cache",
        keys=[5, 7],
        file_id=3,
        max_hits=11,
        ready_only=True,
    )
    subtype_probe.assert_called_once_with(
        str(manifest_path),
        317,
        table="cache",
        key=13,
        file_id=4,
        max_hits=6,
    )
    branch_probe.assert_called_once_with(
        str(manifest_path),
        317,
        table="cache",
        key=17,
        file_id=8,
        max_hits=5,
    )
    blocker_probe.assert_called_once_with(
        str(manifest_path),
        max_sample=12,
    )
