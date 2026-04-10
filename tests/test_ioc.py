from __future__ import annotations

from reverser.analysis.orchestrator import AnalysisEngine


def test_ioc_analyzer_finds_network_and_secret_strings(tmp_path):
    target = tmp_path / "ioc.bin"
    target.write_bytes(
        b"Contact admin@example.com or 10.20.30.40 "
        b"Authorization: Bearer abc123 "
        b"http://example.com/api"
    )

    report = AnalysisEngine().analyze(target)

    ioc = report.sections["ioc"]
    assert "10.20.30.40" in ioc["ipv4_addresses"]
    assert "admin@example.com" in ioc["email_addresses"]
    assert ioc["secret_like_strings"]


def test_ioc_analyzer_avoids_plain_secret_word_false_positive(tmp_path):
    target = tmp_path / "readme.bin"
    target.write_bytes(b"this document mentions secret-like strings in general guidance")

    report = AnalysisEngine().analyze(target)

    assert report.sections["ioc"]["secret_like_strings"] == []
