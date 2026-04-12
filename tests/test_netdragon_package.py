from __future__ import annotations

from reverser.analysis.netdragon import export_netdragon_package
from reverser.analysis.orchestrator import AnalysisEngine
from tests.helpers_netdragon import build_netdragon_pair


def test_netdragon_package_analyzer_summarizes_index(tmp_path):
    tpi_path, _ = build_netdragon_pair(tmp_path)

    report = AnalysisEngine().analyze(tpi_path)

    assert report.sections["identity"]["signature"] == "netdragon-datpkg"
    package = report.sections["netdragon_package"]
    assert package["entry_count"] == 2
    assert package["decode_probe"]["decoded_entries"] >= 1
    assert any(item["extension"] == ".dds" for item in package["top_extensions"])
    assert "format:netdragon-datpkg" in report.summary["tags"]


def test_netdragon_package_analyzer_uses_sibling_index_for_data_package(tmp_path):
    _, tpd_path = build_netdragon_pair(tmp_path)

    report = AnalysisEngine().analyze(tpd_path)

    package = report.sections["netdragon_package"]
    assert package["status"] == "ok"
    assert package["entry_count"] == 2
    assert package["index_path"].endswith("data.tpi")
    assert any(finding.title == "NetDragon package detected" for finding in report.findings)


def test_netdragon_export_writes_manifest_and_decoded_payloads(tmp_path):
    tpi_path, _ = build_netdragon_pair(tmp_path)
    export_dir = tmp_path / "exports"

    manifest = export_netdragon_package(tpi_path, export_dir, include_stored=True)

    assert manifest["summary"]["decoded_count"] == 2
    assert (export_dir / "manifest.json").exists()
    assert (export_dir / "data" / "demo.txt").read_bytes() == b"hello from netdragon"
    assert (export_dir / "_stored" / "data" / "demo.txt.stored.bin").exists()
