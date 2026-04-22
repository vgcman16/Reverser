from __future__ import annotations

import json
from pathlib import Path

from reverser.analysis.external_targets import build_external_target_index, parse_external_target_artifact


def test_parse_external_target_artifact_extracts_expected_fields(tmp_path: Path):
    artifact = tmp_path / "win64c-login-sample.json"
    artifact.write_text(
        json.dumps(
            {
                "milestone": "login-sample-mapped",
                "updated_conclusion": "Mapped a sample login chain.",
                "next_targets": ["Recover the next field.", 9, None],
                "extra": True,
            }
        ),
        encoding="utf-8",
    )

    entry = parse_external_target_artifact(artifact, target_name="rs2client-947")

    assert entry.target_name == "rs2client-947"
    assert entry.artifact_name == "win64c-login-sample.json"
    assert entry.milestone == "login-sample-mapped"
    assert entry.updated_conclusion == "Mapped a sample login chain."
    assert entry.next_targets == ["Recover the next field."]
    assert entry.top_level_keys == ["extra", "milestone", "next_targets", "updated_conclusion"]


def test_build_external_target_index_summarizes_targets_and_latest_artifacts(tmp_path: Path):
    root = tmp_path / "external-targets"
    rs_target = root / "rs2client-947"
    opennxt_target = root / "opennxt"
    rs_target.mkdir(parents=True)
    opennxt_target.mkdir(parents=True)

    older = rs_target / "older.json"
    older.write_text(json.dumps({"milestone": "older", "updated_conclusion": "Old."}), encoding="utf-8")
    newer = rs_target / "newer.json"
    newer.write_text(json.dumps({"milestone": "newer", "updated_conclusion": "New."}), encoding="utf-8")
    sibling = opennxt_target / "artifact.json"
    sibling.write_text(json.dumps({"milestone": "open", "updated_conclusion": "Open."}), encoding="utf-8")

    older.touch()
    newer.touch()
    sibling.touch()

    index = build_external_target_index(root)

    assert index["target_count"] == 2
    assert index["artifact_count"] == 3

    rs_entry = next(item for item in index["targets"] if item["name"] == "rs2client-947")
    assert rs_entry["artifact_count"] == 2
    assert rs_entry["latest_artifact"] in {"newer.json", "older.json"}
    assert {item["artifact_name"] for item in rs_entry["artifacts"]} == {"older.json", "newer.json"}

    opennxt_entry = next(item for item in index["targets"] if item["name"] == "opennxt")
    assert opennxt_entry["latest_milestone"] == "open"


def test_build_external_target_index_skips_invalid_json_and_records_warning(tmp_path: Path):
    root = tmp_path / "external-targets"
    target = root / "rs2client-947"
    target.mkdir(parents=True)

    (target / "valid.json").write_text(json.dumps({"milestone": "ok"}), encoding="utf-8")
    (target / "invalid.json").write_text("{not-valid", encoding="utf-8")
    (target / "notes.txt").write_text("ignored", encoding="utf-8")

    index = build_external_target_index(root)

    assert index["artifact_count"] == 1
    assert index["targets"][0]["artifact_count"] == 1
    assert len(index["warnings"]) == 1
    assert "invalid.json" in index["warnings"][0]
