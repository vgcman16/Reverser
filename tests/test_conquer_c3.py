from __future__ import annotations

from reverser.analysis.orchestrator import AnalysisEngine
from tests.helpers_netdragon import build_netdragon_pair


def _build_dds_bytes() -> bytes:
    payload = bytearray(128)
    payload[:4] = b"DDS "
    payload[4:8] = (124).to_bytes(4, "little")
    payload[8:12] = (0x1007).to_bytes(4, "little")
    payload[12:16] = (1).to_bytes(4, "little")
    payload[16:20] = (1).to_bytes(4, "little")
    payload[20:24] = (8).to_bytes(4, "little")
    payload[28:32] = (1).to_bytes(4, "little")
    payload[76:80] = (32).to_bytes(4, "little")
    payload[80:84] = (0x4).to_bytes(4, "little")
    payload[84:88] = b"DXT1"
    payload[108:112] = (0x1000).to_bytes(4, "little")
    return bytes(payload)


def _build_c3_bytes(
    tag: str = "PHY4",
    name: str = "1-Plane004",
    *,
    chunks: list[tuple[str, int]] | None = None,
    ascii_tail: list[bytes] | None = None,
) -> bytes:
    name_bytes = name.encode("ascii")
    body = bytearray()
    for chunk_tag, payload_size in chunks or [("STEP", 16), ("MOTI", 12), ("KKEY", 8)]:
        body.extend(chunk_tag.encode("ascii"))
        body.extend(payload_size.to_bytes(4, "little"))
        body.extend(b"\x00" * payload_size)
    for tail in ascii_tail or [b"\\UnifyObserverDX9\\UData\\Demo\\\x00", b"\\9.tga\x00"]:
        body.extend(tail)

    padding = b"\x00" * ((4 - (len(name_bytes) % 4)) % 4)
    payload = bytearray()
    payload.extend(b"MAXFILE C3 00001")
    payload.extend(tag.encode("ascii"))
    payload.extend(len(body).to_bytes(4, "little"))
    payload.extend(len(name_bytes).to_bytes(4, "little"))
    payload.extend(name_bytes)
    payload.extend(padding)
    payload.extend(body)
    return bytes(payload)


def test_conquer_c3_analyzer_parses_loose_c3_file(tmp_path):
    target = tmp_path / "effect.c3"
    target.write_bytes(_build_c3_bytes())

    report = AnalysisEngine().analyze(target)

    assert report.sections["identity"]["signature"] == "conquer-c3"
    section = report.sections["conquer_c3"]
    assert section["resource_kind"] == "c3"
    assert section["top_tag"] == "PHY4"
    assert section["top_tag_role"] == "mesh-or-model"
    assert section["object_name"] == "1-Plane004"
    assert section["structural_role_hints"] == ["mesh-or-model", "motion", "keyframe"]
    assert section["chunk_signature"] == ["PHY4", "STEP", "MOTI", "KKEY"]
    assert section["chunk_tag_sequence_sample"][:4] == ["PHY4", "STEP", "MOTI", "KKEY"]
    assert any(item["tag"] == "STEP" for item in section["chunk_tag_counts"])
    assert any("9.tga" in item for item in section["path_hint_sample"])
    assert "format:conquer-c3" in report.summary["tags"]


def test_conquer_c3_analyzer_classifies_particle_top_tag_variant(tmp_path):
    target = tmp_path / "particle.c3"
    target.write_bytes(_build_c3_bytes(tag="PTCL", name="ParticleNode", chunks=[("PTC3", 16)]))

    report = AnalysisEngine().analyze(target)

    section = report.sections["conquer_c3"]
    assert section["top_tag"] == "PTCL"
    assert section["top_tag_role"] == "particle"
    assert section["structural_role_hints"] == ["particle"]
    assert section["chunk_signature"] == ["PTCL", "PTC3"]


def test_conquer_c3_analyzer_surfaces_unknown_chunk_tags(tmp_path):
    target = tmp_path / "unknown-tags.c3"
    target.write_bytes(
        _build_c3_bytes(
            tag="PHY4",
            name="MysteryNode",
            chunks=[("4VUU", 12), ("6TU5", 8), ("MOTI", 8)],
        )
    )

    report = AnalysisEngine().analyze(target)

    section = report.sections["conquer_c3"]
    assert section["chunk_signature"] == ["PHY4", "4VUU", "6TU5", "MOTI"]
    assert section["unknown_chunk_tags"] == [
        {"tag": "4VUU", "count": 1},
        {"tag": "6TU5", "count": 1},
    ]
    assert section["unknown_chunk_tag_profiles"] == [
        {
            "tag": "4VUU",
            "count": 1,
            "declared_size_min": 12,
            "declared_size_max": 12,
            "declared_size_sample": [12],
            "leading_zero_prefix_min": 12,
            "leading_zero_prefix_max": 12,
            "float_like_ratio_min": 1.0,
            "float_like_ratio_max": 1.0,
            "payload_prefix_hex_sample": ["000000000000000000000000"],
            "cooccurring_known_tags": [
                {"tag": "PHY4", "count": 1},
                {"tag": "MOTI", "count": 1},
            ],
            "parent_known_tags": [{"tag": "PHY4", "count": 1}],
            "preceding_known_tags": [{"tag": "PHY4", "count": 1}],
            "following_known_tags": [{"tag": "MOTI", "count": 1}],
            "between_known_tags": [
                {"preceding_tag": "PHY4", "following_tag": "MOTI", "count": 1}
            ],
            "layout_hints": [
                "fixed-size-block",
                "small-block",
                "zero-prefixed-block",
                "float-heavy-block",
            ],
            "subformat_hints": ["compact-float-control-block"],
            "sequence_context_hints": [
                "between-phy4-and-moti",
                "nested-under-phy4",
                "after-phy4",
                "before-moti",
            ],
            "attachment_hints": [
                "mesh-to-motion-control-block",
                "mesh-nested-control-block",
            ],
        },
        {
            "tag": "6TU5",
            "count": 1,
            "declared_size_min": 8,
            "declared_size_max": 8,
            "declared_size_sample": [8],
            "leading_zero_prefix_min": 8,
            "leading_zero_prefix_max": 8,
            "float_like_ratio_min": 1.0,
            "float_like_ratio_max": 1.0,
            "payload_prefix_hex_sample": ["0000000000000000"],
            "cooccurring_known_tags": [
                {"tag": "PHY4", "count": 1},
                {"tag": "MOTI", "count": 1},
            ],
            "parent_known_tags": [{"tag": "PHY4", "count": 1}],
            "preceding_known_tags": [{"tag": "PHY4", "count": 1}],
            "following_known_tags": [{"tag": "MOTI", "count": 1}],
            "between_known_tags": [
                {"preceding_tag": "PHY4", "following_tag": "MOTI", "count": 1}
            ],
            "layout_hints": [
                "fixed-size-block",
                "small-block",
                "zero-prefixed-block",
                "float-heavy-block",
            ],
            "subformat_hints": ["compact-float-control-block"],
            "sequence_context_hints": [
                "between-phy4-and-moti",
                "nested-under-phy4",
                "after-phy4",
                "before-moti",
            ],
            "attachment_hints": [
                "mesh-to-motion-control-block",
                "mesh-nested-control-block",
            ],
        },
    ]


def test_conquer_c3_analyzer_derives_bulk_attachment_hints(tmp_path):
    target = tmp_path / "unknown-bulk-tags.c3"
    target.write_bytes(
        _build_c3_bytes(
            tag="PHY4",
            name="BulkMysteryNode",
            chunks=[("C6VU", 5000), ("MOTI", 8)],
        )
    )

    report = AnalysisEngine().analyze(target)

    section = report.sections["conquer_c3"]
    assert section["unknown_chunk_tag_profiles"] == [
        {
            "tag": "C6VU",
            "count": 1,
            "declared_size_min": 5000,
            "declared_size_max": 5000,
            "declared_size_sample": [5000],
            "leading_zero_prefix_min": 5000,
            "leading_zero_prefix_max": 5000,
            "float_like_ratio_min": 1.0,
            "float_like_ratio_max": 1.0,
            "payload_prefix_hex_sample": ["00000000000000000000000000000000"],
            "cooccurring_known_tags": [
                {"tag": "PHY4", "count": 1},
                {"tag": "MOTI", "count": 1},
            ],
            "parent_known_tags": [{"tag": "PHY4", "count": 1}],
            "preceding_known_tags": [{"tag": "PHY4", "count": 1}],
            "following_known_tags": [{"tag": "MOTI", "count": 1}],
            "between_known_tags": [
                {"preceding_tag": "PHY4", "following_tag": "MOTI", "count": 1}
            ],
            "layout_hints": [
                "fixed-size-block",
                "large-block",
                "zero-prefixed-block",
                "float-heavy-block",
            ],
            "subformat_hints": ["bulk-float-buffer-block"],
            "sequence_context_hints": [
                "between-phy4-and-moti",
                "nested-under-phy4",
                "after-phy4",
                "before-moti",
            ],
            "attachment_hints": [
                "mesh-to-motion-bulk-float-block",
                "mesh-nested-bulk-float-block",
            ],
        }
    ]


def test_conquer_c3_analyzer_derives_postlude_bulk_attachment_hints(tmp_path):
    target = tmp_path / "unknown-postlude-bulk-tags.c3"
    target.write_bytes(
        _build_c3_bytes(
            tag="PHY4",
            name="PostludeBulkNode",
            chunks=[("C6VU", 5000)],
        )
    )

    report = AnalysisEngine().analyze(target)

    section = report.sections["conquer_c3"]
    assert section["unknown_chunk_tag_profiles"] == [
        {
            "tag": "C6VU",
            "count": 1,
            "declared_size_min": 5000,
            "declared_size_max": 5000,
            "declared_size_sample": [5000],
            "leading_zero_prefix_min": 5000,
            "leading_zero_prefix_max": 5000,
            "float_like_ratio_min": 1.0,
            "float_like_ratio_max": 1.0,
            "payload_prefix_hex_sample": ["00000000000000000000000000000000"],
            "cooccurring_known_tags": [{"tag": "PHY4", "count": 1}],
            "parent_known_tags": [{"tag": "PHY4", "count": 1}],
            "preceding_known_tags": [{"tag": "PHY4", "count": 1}],
            "following_known_tags": [],
            "between_known_tags": [],
            "layout_hints": [
                "fixed-size-block",
                "large-block",
                "zero-prefixed-block",
                "float-heavy-block",
            ],
            "subformat_hints": ["bulk-float-buffer-block"],
            "sequence_context_hints": [
                "nested-under-phy4",
                "after-phy4",
            ],
            "attachment_hints": [
                "mesh-nested-bulk-float-block",
                "mesh-postlude-bulk-float-block",
            ],
        }
    ]


def test_netdragon_package_summary_probes_c3_entries(tmp_path):
    tpi_path, _ = build_netdragon_pair(
        tmp_path,
        stem="c3",
        entries=[
            ("c3/effect/demo/1.c3", _build_c3_bytes(tag="PTC3", name="010PCloud001w")),
            ("c3/effect/demo/1.dds", _build_dds_bytes()),
        ],
    )

    report = AnalysisEngine().analyze(tpi_path)

    package = report.sections["netdragon_package"]
    assert any(item["extension"] == ".c3" for item in package["top_extensions"])
    assert package["c3_probe"]["c3_entry_count"] == 1
    assert package["c3_probe"]["probed_entries"] == 1
    assert package["c3_probe"]["top_tags"][0]["tag"] == "PTC3"
    assert package["c3_probe"]["samples"][0]["object_name"] == "010PCloud001w"


def test_conquer_c3_analyzer_summarizes_reference_map_file(tmp_path):
    root = tmp_path / "Conquer"
    ini_dir = root / "ini"
    ini_dir.mkdir(parents=True)
    (ini_dir / "3DEffectObj.ini").write_text(
        "\n".join(
            [
                "1=C3/Effect/LevelUp/1.C3",
                "2=C3/Effect/LevelUp/1.C3",
                "3=C3/Effect/Health/1.C3",
                "4=C3/Effect/Missing/9.C3",
            ]
        ),
        encoding="utf-8",
    )
    build_netdragon_pair(
        root,
        stem="c3",
        entries=[
            ("c3/effect/levelup/1.c3", _build_c3_bytes(tag="PTC3", name="LevelUp01")),
            ("c3/effect/health/1.c3", _build_c3_bytes(tag="MOTI", name="Health01")),
        ],
    )

    report = AnalysisEngine().analyze(ini_dir / "3DEffectObj.ini")

    section = report.sections["conquer_c3"]
    assert section["resource_kind"] == "c3-reference-map"
    assert section["reference_file_kind"] == "3deffectobj"
    assert section["entry_count"] == 4
    assert section["unique_path_count"] == 3
    assert section["duplicate_path_count"] == 1
    assert section["resolved_unique_path_count"] == 2
    assert section["missing_unique_path_count"] == 1
    assert section["resolution_unique_path_counts"] == [
        {"status": "c3", "count": 2},
        {"status": "missing", "count": 1},
    ]
    assert section["family_resolution_coverage_sample"] == [
        {
            "family": "effect",
            "unique_path_count": 3,
            "resolved_unique_path_count": 2,
            "missing_unique_path_count": 1,
            "coverage_ratio": 0.6667,
            "status_counts": [
                {"status": "c3", "count": 2},
                {"status": "missing", "count": 1},
            ],
        }
    ]
    assert section["duplicate_path_sample"][0]["path"] == "C3/Effect/LevelUp/1.C3"
    assert section["resolved_c3_sample"][0]["package"] == "c3"
    assert section["resolved_c3_sample"][0]["top_tag"] == "PTC3"
    assert any(finding.title == "Conquer C3 reference table detected" for finding in report.findings)


def test_conquer_c3_analyzer_summarizes_install_directory(tmp_path):
    root = tmp_path / "Conquer"
    ini_dir = root / "ini"
    ini_dir.mkdir(parents=True)
    (ini_dir / "3DEffectObj.ini").write_text(
        "\n".join(
            [
                "1=C3/Effect/LevelUp/1.C3",
                "2=C3/Effect/Glow/1.C3",
            ]
        ),
        encoding="utf-8",
    )
    (ini_dir / "3dmotion.ini").write_text(
        "\n".join(
            [
                "100=C3/Npc/001.C3",
                "101=C3/Effect/Glow/1.C3",
                "102=C3/Npc/Missing.C3",
            ]
        ),
        encoding="utf-8",
    )
    build_netdragon_pair(
        root,
        stem="c3",
        entries=[
            ("c3/effect/levelup/1.c3", _build_c3_bytes(tag="PTC3", name="LevelUp01")),
            ("c3/effect/glow/1.c3", _build_c3_bytes(tag="MOTI", name="Glow01")),
        ],
    )
    build_netdragon_pair(
        root,
        stem="c31",
        entries=[
            ("c3/npc/001.c3", _build_c3_bytes(tag="PHY4", name="Npc001")),
        ],
    )

    report = AnalysisEngine().analyze(root)

    section = report.sections["conquer_c3"]
    assert section["resource_kind"] == "c3-install"
    assert section["reference_file_count"] == 2
    assert section["entry_count"] == 5
    assert section["unique_path_count"] == 4
    assert section["resolved_unique_path_count"] == 3
    assert section["missing_unique_path_count"] == 1
    assert section["cross_file_overlap_count"] == 1
    assert section["package_inventory"][0]["package"] == "c3"
    assert section["package_inventory"][0]["referenced_unique_c3_count"] == 2
    assert section["package_inventory"][0]["top_families"] == [{"family": "effect", "count": 2}]
    assert section["package_inventory"][1]["package"] == "c31"
    assert section["package_inventory"][1]["referenced_unique_c3_count"] == 1
    assert section["package_inventory"][1]["top_families"] == [{"family": "npc", "count": 1}]
    assert section["reference_files"][0]["path"] == "ini/3DEffectObj.ini"
    assert section["reference_files"][1]["path"] == "ini/3dmotion.ini"
    assert section["effective_resolved_unique_path_count"] == 3
    assert section["effective_missing_unique_path_count"] == 1
    assert section["effective_unique_path_coverage_ratio"] == 0.75
    assert section["validated_missing_family_alias_candidate_sample"] == []
    assert section["validated_missing_branch_alias_candidate_sample"] == []
    assert section["residual_missing_branch_unknown_chunk_archetype_sample"] == []
    assert section["residual_missing_family_sample"] == [
        {
            "family": "npc",
            "unique_path_count": 2,
            "resolved_unique_path_count": 1,
            "missing_unique_path_count": 1,
            "effective_coverage_ratio": 0.5,
        }
    ]
    assert section["family_resolution_coverage_sample"] == [
        {
            "family": "effect",
            "unique_path_count": 2,
            "resolved_unique_path_count": 2,
            "missing_unique_path_count": 0,
            "coverage_ratio": 1.0,
            "status_counts": [{"status": "c3", "count": 2}],
        },
        {
            "family": "npc",
            "unique_path_count": 2,
            "resolved_unique_path_count": 1,
            "missing_unique_path_count": 1,
            "coverage_ratio": 0.5,
            "status_counts": [
                {"status": "c31", "count": 1},
                {"status": "missing", "count": 1},
            ],
        },
    ]
    assert section["effective_family_resolution_coverage_sample"] == section["family_resolution_coverage_sample"]
    assert any(finding.title == "Conquer C3 reference tables detected" for finding in report.findings)


def test_conquer_c3_analyzer_suggests_missing_branch_alias_candidates(tmp_path):
    root = tmp_path / "Conquer"
    ini_dir = root / "ini"
    ini_dir.mkdir(parents=True)
    (ini_dir / "3dmotion.ini").write_text(
        "\n".join(
            [
                "1=C3/0001/611/100.C3",
                "2=C3/0001/611/105.C3",
                "3=C3/0001/611/110.C3",
            ]
        ),
        encoding="utf-8",
    )
    build_netdragon_pair(
        root,
        stem="c3",
        entries=[
            ("c3/0007/611/100.c3", _build_c3_bytes(tag="MOTI", name="A")),
            ("c3/0007/611/105.c3", _build_c3_bytes(tag="MOTI", name="B")),
            ("c3/0007/611/110.c3", _build_c3_bytes(tag="MOTI", name="C")),
            ("c3/miscmotion/0007/100.c3", _build_c3_bytes(tag="MOTI", name="D")),
            ("c3/miscmotion/0007/105.c3", _build_c3_bytes(tag="MOTI", name="E")),
            ("c3/miscmotion/0007/110.c3", _build_c3_bytes(tag="MOTI", name="F")),
        ],
    )

    report = AnalysisEngine().analyze(root)

    section = report.sections["conquer_c3"]
    branch_alias = section["missing_branch_alias_candidate_sample"][0]
    assert branch_alias["branch"] == "0001/611"
    assert branch_alias["missing_unique_path_count"] == 3
    first_candidate = branch_alias["replacement_candidates"][0]
    assert first_candidate["branch"] == "0007/611"
    assert first_candidate["packages"] == ["c3"]
    assert first_candidate["overlap_count"] == 3
    assert first_candidate["overlap_ratio"] == 1.0
    assert first_candidate["same_leaf_segment"] is True
    assert first_candidate["same_numeric_family_shape"] is True

    family_alias = section["missing_family_alias_candidate_sample"][0]
    assert family_alias["family"] == "0001"
    assert family_alias["replacement_candidates"][0]["family"] == "0007"


def test_conquer_c3_analyzer_reports_effective_alias_coverage(tmp_path):
    root = tmp_path / "Conquer"
    ini_dir = root / "ini"
    ini_dir.mkdir(parents=True)
    (ini_dir / "3dmotion.ini").write_text(
        "\n".join(
            [
                "1=C3/0001/611/100.C3",
                "2=C3/0001/611/105.C3",
                "3=C3/0001/611/110.C3",
                "4=C3/0001/611/115.C3",
                "5=C3/0001/611/120.C3",
                "6=C3/0001/611/125.C3",
                "7=C3/0001/611/130.C3",
                "8=C3/0001/611/135.C3",
            ]
        ),
        encoding="utf-8",
    )
    build_netdragon_pair(
        root,
        stem="c3",
        entries=[
            ("c3/0007/611/100.c3", _build_c3_bytes(tag="MOTI", name="A")),
            ("c3/0007/611/105.c3", _build_c3_bytes(tag="MOTI", name="B")),
            ("c3/0007/611/110.c3", _build_c3_bytes(tag="MOTI", name="C")),
            ("c3/0007/611/115.c3", _build_c3_bytes(tag="MOTI", name="D")),
            ("c3/0007/611/120.c3", _build_c3_bytes(tag="MOTI", name="E")),
            ("c3/0007/611/125.c3", _build_c3_bytes(tag="MOTI", name="F")),
            ("c3/0007/611/130.c3", _build_c3_bytes(tag="MOTI", name="G")),
            ("c3/0007/611/135.c3", _build_c3_bytes(tag="MOTI", name="H")),
        ],
    )

    report = AnalysisEngine().analyze(root)

    section = report.sections["conquer_c3"]
    assert section["resolved_unique_path_count"] == 0
    assert section["missing_unique_path_count"] == 8
    assert section["alias_resolved_unique_path_count"] == 8
    assert section["branch_alias_resolved_unique_path_count"] == 8
    assert section["family_alias_resolved_unique_path_count"] == 0
    assert section["effective_resolved_unique_path_count"] == 8
    assert section["effective_missing_unique_path_count"] == 0
    assert section["effective_unique_path_coverage_ratio"] == 1.0
    assert section["alias_resolved_path_sample"][0] == {
        "path": "C3/0001/611/100.C3",
        "alias_type": "branch",
        "candidate_bucket": "0007/611",
        "overlap_ratio": 1.0,
        "same_leaf_segment": True,
        "same_numeric_family_shape": True,
    }
    assert section["validated_missing_family_alias_candidate_sample"] == []
    assert section["validated_missing_branch_alias_candidate_sample"][0]["branch"] == "0001/611"
    assert section["effective_family_resolution_coverage_sample"] == [
        {
            "family": "0001",
            "unique_path_count": 8,
            "resolved_unique_path_count": 8,
            "missing_unique_path_count": 0,
            "coverage_ratio": 1.0,
            "status_counts": [{"status": "alias-branch", "count": 8}],
        }
    ]
    assert section["effective_branch_resolution_coverage_sample"] == [
        {
            "branch": "0001/611",
            "unique_path_count": 8,
            "resolved_unique_path_count": 8,
            "missing_unique_path_count": 0,
            "coverage_ratio": 1.0,
            "status_counts": [{"status": "alias-branch", "count": 8}],
        }
    ]
    assert section["residual_missing_family_sample"] == []
    assert section["residual_missing_branch_sample"] == []
    assert section["highest_family_alias_gain_sample"] == [
        {
            "family": "0001",
            "unique_path_count": 8,
            "direct_resolved_unique_path_count": 0,
            "effective_resolved_unique_path_count": 8,
            "alias_resolved_unique_path_count": 8,
            "direct_coverage_ratio": 0.0,
            "effective_coverage_ratio": 1.0,
        }
    ]
    assert section["highest_branch_alias_gain_sample"] == [
        {
            "branch": "0001/611",
            "unique_path_count": 8,
            "direct_resolved_unique_path_count": 0,
            "effective_resolved_unique_path_count": 8,
            "alias_resolved_unique_path_count": 8,
            "direct_coverage_ratio": 0.0,
            "effective_coverage_ratio": 1.0,
        }
    ]


def test_conquer_c3_analyzer_profiles_residual_missing_branch_packages(tmp_path):
    root = tmp_path / "Conquer"
    ini_dir = root / "ini"
    ini_dir.mkdir(parents=True)
    (ini_dir / "3DEffectObj.ini").write_text(
        "\n".join(
            [
                "1=C3/Effect/Flash/200.C3",
                "2=C3/Effect/Flash/201.C3",
            ]
        ),
        encoding="utf-8",
    )
    build_netdragon_pair(
        root,
        stem="c3",
        entries=[
            (
                "c3/effect/flash/100.c3",
                _build_c3_bytes(
                    tag="CAME",
                    name="FlashCam01",
                    chunks=[("SHAP", 12), ("SMOT", 8)],
                    ascii_tail=[b"\\administrator\\\x00", b"\\1.tga\x00"],
                ),
            ),
            (
                "c3/effect/flash/101.c3",
                _build_c3_bytes(
                    tag="CAME",
                    name="FlashCam02",
                    chunks=[("SHAP", 12), ("SMOT", 8)],
                    ascii_tail=[b"\\administrator\\\x00", b"\\2.tga\x00"],
                ),
            ),
        ],
    )

    report = AnalysisEngine().analyze(root)

    section = report.sections["conquer_c3"]
    assert section["residual_missing_branch_sample"] == [
        {
            "branch": "effect/flash",
            "unique_path_count": 2,
            "resolved_unique_path_count": 0,
            "missing_unique_path_count": 2,
            "effective_coverage_ratio": 0.0,
        }
    ]
    assert section["residual_missing_branch_package_profile_sample"] == [
        {
            "branch": "effect/flash",
            "package_entry_count": 2,
            "sampled_entry_count": 2,
            "packages": ["c3"],
            "top_tags": [{"tag": "CAME", "count": 2}],
            "top_tag_roles": [{"role": "camera", "count": 2}],
            "structural_roles": [
                {"role": "camera", "count": 2},
                {"role": "shape", "count": 2},
                {"role": "motion", "count": 2},
            ],
            "chunk_signatures": [{"tags": ["CAME", "SHAP", "SMOT"], "count": 2}],
            "unknown_chunk_tags": [],
            "unknown_chunk_tag_profiles": [],
            "unknown_chunk_clusters": [],
            "unknown_chunk_archetypes": [],
            "path_sample": [
                "c3/effect/flash/100.c3",
                "c3/effect/flash/101.c3",
            ],
            "object_name_sample": ["FlashCam01", "FlashCam02"],
        }
    ]
    assert section["residual_missing_branch_unknown_chunk_archetype_sample"] == []


def test_conquer_c3_analyzer_profiles_unknown_chunk_tags_in_residual_branch_packages(tmp_path):
    root = tmp_path / "Conquer"
    ini_dir = root / "ini"
    ini_dir.mkdir(parents=True)
    (ini_dir / "3DEffectObj.ini").write_text(
        "\n".join(
            [
                "1=C3/Effect/Other/Missing200.C3",
            ]
        ),
        encoding="utf-8",
    )
    build_netdragon_pair(
        root,
        stem="c3",
        entries=[
            (
                "c3/effect/other/100.c3",
                _build_c3_bytes(
                    tag="PHY4",
                    name="OtherNode01",
                    chunks=[("4VUU", 12), ("6TU5", 8), ("MOTI", 8)],
                ),
            ),
            (
                "c3/effect/other/101.c3",
                _build_c3_bytes(
                    tag="PHY4",
                    name="OtherNode02",
                    chunks=[("4VUU", 12), ("MOTI", 8)],
                ),
            ),
        ],
    )

    report = AnalysisEngine().analyze(root)

    section = report.sections["conquer_c3"]
    assert section["residual_missing_branch_sample"] == [
        {
            "branch": "effect/other",
            "unique_path_count": 1,
            "resolved_unique_path_count": 0,
            "missing_unique_path_count": 1,
            "effective_coverage_ratio": 0.0,
        }
    ]
    assert section["residual_missing_branch_package_profile_sample"] == [
        {
            "branch": "effect/other",
            "package_entry_count": 2,
            "sampled_entry_count": 2,
            "packages": ["c3"],
            "top_tags": [{"tag": "PHY4", "count": 2}],
            "top_tag_roles": [{"role": "mesh-or-model", "count": 2}],
            "structural_roles": [
                {"role": "mesh-or-model", "count": 2},
                {"role": "motion", "count": 2},
            ],
            "chunk_signatures": [
                {"tags": ["PHY4", "4VUU", "6TU5", "MOTI"], "count": 1},
                {"tags": ["PHY4", "4VUU", "MOTI"], "count": 1},
            ],
            "unknown_chunk_tags": [
                {"tag": "4VUU", "count": 2},
                {"tag": "6TU5", "count": 1},
            ],
            "unknown_chunk_tag_profiles": [
                {
                    "tag": "4VUU",
                    "entry_count": 2,
                    "count": 2,
                    "declared_size_min": 12,
                    "declared_size_max": 12,
                    "declared_size_sample": [12],
                    "leading_zero_prefix_min": 12,
                    "leading_zero_prefix_max": 12,
                    "float_like_ratio_min": 1.0,
                    "float_like_ratio_max": 1.0,
                    "payload_prefix_hex_sample": ["000000000000000000000000"],
                    "cooccurring_known_tags": [
                        {"tag": "PHY4", "count": 2},
                        {"tag": "MOTI", "count": 2},
                    ],
                    "parent_known_tags": [{"tag": "PHY4", "count": 2}],
                    "preceding_known_tags": [{"tag": "PHY4", "count": 2}],
                    "following_known_tags": [{"tag": "MOTI", "count": 2}],
                    "between_known_tags": [
                        {"preceding_tag": "PHY4", "following_tag": "MOTI", "count": 2}
                    ],
                    "layout_hints": [
                        "fixed-size-block",
                        "float-heavy-block",
                        "small-block",
                        "zero-prefixed-block",
                    ],
                    "subformat_hints": ["compact-float-control-block"],
                    "sequence_context_hints": [
                        "between-phy4-and-moti",
                        "nested-under-phy4",
                        "after-phy4",
                        "before-moti",
                    ],
                    "attachment_hints": [
                        "mesh-to-motion-control-block",
                        "mesh-nested-control-block",
                    ],
                    "path_sample": [
                        "c3/effect/other/100.c3",
                        "c3/effect/other/101.c3",
                    ],
                },
                {
                    "tag": "6TU5",
                    "entry_count": 1,
                    "count": 1,
                    "declared_size_min": 8,
                    "declared_size_max": 8,
                    "declared_size_sample": [8],
                    "leading_zero_prefix_min": 8,
                    "leading_zero_prefix_max": 8,
                    "float_like_ratio_min": 1.0,
                    "float_like_ratio_max": 1.0,
                    "payload_prefix_hex_sample": ["0000000000000000"],
                    "cooccurring_known_tags": [
                        {"tag": "PHY4", "count": 1},
                        {"tag": "MOTI", "count": 1},
                    ],
                    "parent_known_tags": [{"tag": "PHY4", "count": 1}],
                    "preceding_known_tags": [{"tag": "PHY4", "count": 1}],
                    "following_known_tags": [{"tag": "MOTI", "count": 1}],
                    "between_known_tags": [
                        {"preceding_tag": "PHY4", "following_tag": "MOTI", "count": 1}
                    ],
                    "layout_hints": [
                        "fixed-size-block",
                        "float-heavy-block",
                        "small-block",
                        "zero-prefixed-block",
                    ],
                    "subformat_hints": ["compact-float-control-block"],
                    "sequence_context_hints": [
                        "between-phy4-and-moti",
                        "nested-under-phy4",
                        "after-phy4",
                        "before-moti",
                    ],
                    "attachment_hints": [
                        "mesh-to-motion-control-block",
                        "mesh-nested-control-block",
                    ],
                    "path_sample": ["c3/effect/other/100.c3"],
                },
            ],
            "unknown_chunk_clusters": [
                {
                    "tags": ["4VUU", "6TU5"],
                    "tag_count": 2,
                    "total_occurrence_count": 3,
                    "sampled_path_count": 2,
                    "declared_size_min": 8,
                    "declared_size_max": 12,
                    "declared_size_sample": [8, 12],
                    "leading_zero_prefix_min": 8,
                    "leading_zero_prefix_max": 12,
                    "float_like_ratio_min": 1.0,
                    "float_like_ratio_max": 1.0,
                    "payload_prefix_hex_sample": [
                        "000000000000000000000000",
                        "0000000000000000",
                    ],
                    "cooccurring_known_tags": [
                        {"tag": "PHY4", "count": 3},
                        {"tag": "MOTI", "count": 3},
                    ],
                    "parent_known_tags": [{"tag": "PHY4", "count": 3}],
                    "preceding_known_tags": [{"tag": "PHY4", "count": 3}],
                    "following_known_tags": [{"tag": "MOTI", "count": 3}],
                    "between_known_tags": [
                        {"preceding_tag": "PHY4", "following_tag": "MOTI", "count": 3}
                    ],
                    "layout_hints": [
                        "fixed-size-block",
                        "float-heavy-block",
                        "small-block",
                        "zero-prefixed-block",
                    ],
                    "subformat_hints": [
                        "compact-float-control-family",
                        "stable-size-variant-family",
                    ],
                    "sequence_context_hints": [
                        "between-phy4-and-moti",
                        "nested-under-phy4",
                        "after-phy4",
                        "before-moti",
                    ],
                    "attachment_hints": [
                        "mesh-to-motion-control-family",
                        "mesh-nested-control-family",
                    ],
                    "path_sample": [
                        "c3/effect/other/100.c3",
                        "c3/effect/other/101.c3",
                    ],
                }
            ],
            "unknown_chunk_archetypes": [
                {
                    "attachment_hints": [
                        "mesh-to-motion-control-block",
                        "mesh-nested-control-block",
                    ],
                    "subformat_hints": ["compact-float-control-block"],
                    "sequence_context_hints": [
                        "between-phy4-and-moti",
                        "nested-under-phy4",
                        "after-phy4",
                        "before-moti",
                    ],
                    "layout_hints": [
                        "fixed-size-block",
                        "float-heavy-block",
                        "small-block",
                        "zero-prefixed-block",
                    ],
                    "declared_size_min": 8,
                    "declared_size_max": 12,
                    "declared_size_sample": [8, 12],
                    "cooccurring_known_tags": [
                        {"tag": "PHY4", "count": 3},
                        {"tag": "MOTI", "count": 3},
                    ],
                    "tag_sample": ["4VUU", "6TU5"],
                    "tag_count": 2,
                    "total_occurrence_count": 3,
                    "entry_count": 3,
                    "sampled_path_count": 2,
                    "path_sample": [
                        "c3/effect/other/100.c3",
                        "c3/effect/other/101.c3",
                    ],
                }
            ],
            "path_sample": [
                "c3/effect/other/100.c3",
                "c3/effect/other/101.c3",
            ],
            "object_name_sample": ["OtherNode01", "OtherNode02"],
        }
    ]
    assert section["residual_missing_branch_unknown_chunk_archetype_sample"] == [
        {
            "attachment_hints": [
                "mesh-to-motion-control-block",
                "mesh-nested-control-block",
            ],
            "subformat_hints": ["compact-float-control-block"],
            "sequence_context_hints": [
                "between-phy4-and-moti",
                "nested-under-phy4",
                "after-phy4",
                "before-moti",
            ],
            "layout_hints": [
                "fixed-size-block",
                "float-heavy-block",
                "small-block",
                "zero-prefixed-block",
            ],
            "declared_size_min": 8,
            "declared_size_max": 12,
            "declared_size_sample": [8, 12],
            "cooccurring_known_tags": [
                {"tag": "PHY4", "count": 3},
                {"tag": "MOTI", "count": 3},
            ],
            "tag_sample": ["4VUU", "6TU5"],
            "tag_count": 2,
            "total_occurrence_count": 3,
            "entry_count": 3,
            "packages": ["c3"],
            "branch_count": 1,
            "branch_sample": ["effect/other"],
            "sampled_path_count": 2,
            "path_sample": [
                "c3/effect/other/100.c3",
                "c3/effect/other/101.c3",
            ],
        }
    ]
