from __future__ import annotations

import json
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from reverser.analysis.diffing import diff_artifacts, load_or_generate_artifact
from reverser.analysis.orchestrator import AnalysisEngine
from reverser.analysis.scan import scan_tree
from reverser.schema import get_diff_schema, get_report_schema, get_scan_index_schema


def run_api_server(host: str = "127.0.0.1", port: int = 8765) -> None:
    handler = build_handler()
    with ThreadingHTTPServer((host, port), handler) as server:
        server.serve_forever()


def build_handler():
    class ReverserAPIHandler(BaseHTTPRequestHandler):
        server_version = "ReverserAPI/0.2"

        def do_GET(self) -> None:  # noqa: N802
            if self.path == "/health":
                self._json_response(HTTPStatus.OK, {"status": "ok"})
                return
            if self.path == "/analyzers":
                analyzers = [
                    {"name": analyzer.name, "class": analyzer.__class__.__name__}
                    for analyzer in AnalysisEngine().analyzers
                ]
                self._json_response(HTTPStatus.OK, {"analyzers": analyzers})
                return
            if self.path == "/schema/report":
                self._json_response(HTTPStatus.OK, get_report_schema())
                return
            if self.path == "/schema/scan-index":
                self._json_response(HTTPStatus.OK, get_scan_index_schema())
                return
            if self.path == "/schema/diff":
                self._json_response(HTTPStatus.OK, get_diff_schema())
                return

            self._json_response(HTTPStatus.NOT_FOUND, {"error": "not_found"})

        def do_POST(self) -> None:  # noqa: N802
            try:
                payload = self._read_json()
            except ValueError as exc:
                self._json_response(HTTPStatus.BAD_REQUEST, {"error": str(exc)})
                return

            try:
                if self.path == "/analyze":
                    result = AnalysisEngine(max_strings=int(payload.get("max_strings", 200))).analyze(
                        payload["target"]
                    ).to_dict()
                    self._json_response(HTTPStatus.OK, result)
                    return

                if self.path == "/scan":
                    result = scan_tree(
                        payload["target"],
                        max_files=int(payload.get("max_files", 250)),
                        max_file_bytes=int(payload.get("max_file_mb", 256)) * 1024 * 1024,
                        max_strings=int(payload.get("max_strings", 200)),
                        include_globs=_as_list(payload.get("include_globs")),
                        exclude_globs=_as_list(payload.get("exclude_globs")),
                        workers=int(payload["workers"]) if "workers" in payload else None,
                    ).to_dict()
                    self._json_response(HTTPStatus.OK, result)
                    return

                if self.path == "/diff":
                    base = load_or_generate_artifact(
                        payload["base"],
                        max_strings=int(payload.get("max_strings", 200)),
                        max_files=int(payload.get("max_files", 250)),
                        max_file_mb=int(payload.get("max_file_mb", 256)),
                    )
                    head = load_or_generate_artifact(
                        payload["head"],
                        max_strings=int(payload.get("max_strings", 200)),
                        max_files=int(payload.get("max_files", 250)),
                        max_file_mb=int(payload.get("max_file_mb", 256)),
                    )
                    result = diff_artifacts(
                        base,
                        head,
                        base_ref=str(payload["base"]),
                        head_ref=str(payload["head"]),
                    ).to_dict()
                    self._json_response(HTTPStatus.OK, result)
                    return
            except KeyError as exc:
                self._json_response(HTTPStatus.BAD_REQUEST, {"error": f"missing field: {exc}"})
                return
            except FileNotFoundError as exc:
                self._json_response(HTTPStatus.NOT_FOUND, {"error": str(exc)})
                return
            except Exception as exc:  # pragma: no cover
                self._json_response(HTTPStatus.INTERNAL_SERVER_ERROR, {"error": str(exc)})
                return

            self._json_response(HTTPStatus.NOT_FOUND, {"error": "not_found"})

        def log_message(self, format: str, *args) -> None:  # noqa: A003
            return

        def _read_json(self) -> dict[str, Any]:
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0:
                return {}
            raw = self.rfile.read(content_length)
            try:
                return json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise ValueError("invalid JSON body") from exc

        def _json_response(self, status: HTTPStatus, payload: dict[str, Any]) -> None:
            body = json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    return ReverserAPIHandler


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [str(item) for item in value]
    return [str(value)]
