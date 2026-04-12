from __future__ import annotations

from reverser.analysis.conquer_animation import _classify_overlap_strength, _normalize_filename_stem
from reverser.analysis.orchestrator import AnalysisEngine
from tests.helpers_netdragon import build_netdragon_pair


def _build_ani_text() -> str:
    return (
        "[Puzzle0]\n"
        "FrameAmount=1\n"
        "Frame0=data/map/puzzle/room/arena/arena000.dds\n\n"
        "[Puzzle1]\n"
        "FrameAmount=1\n"
        "Frame0=data/map/puzzle/room/arena/arena001.dds\n"
    )


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


def test_classify_overlap_strength_downweights_generic_stem_only_matches():
    assert _classify_overlap_strength(
        0.0,
        1.0,
        weighted_exact_score=0.0,
        weighted_stem_score=0.0466,
    ) == "weak"
    assert _classify_overlap_strength(
        0.0,
        1.0,
        weighted_exact_score=0.0,
        weighted_stem_score=11.0,
    ) == "strong"


def test_classify_overlap_strength_rejects_generic_exact_name_matches():
    assert _classify_overlap_strength(
        1.0,
        1.0,
        weighted_exact_score=32.0,
        weighted_stem_score=32.0,
        generic_overlap_only=True,
    ) == "weak"


def test_normalize_filename_stem_preserves_numeric_only_names():
    assert _normalize_filename_stem("72.dds") == "72.dds"
    assert _normalize_filename_stem("001.dds") == "001.dds"
    assert _normalize_filename_stem("city044.dds") == "city.dds"


def test_conquer_animation_analyzer_parses_ani_file(tmp_path):
    root = tmp_path / "Conquer"
    ani_root = root / "ani"
    frame_root = root / "data" / "map" / "puzzle" / "room" / "arena"
    ani_root.mkdir(parents=True)
    frame_root.mkdir(parents=True)
    target = ani_root / "room.ani"
    target.write_text(_build_ani_text(), encoding="utf-8")
    (frame_root / "arena000.dds").write_bytes(_build_dds_bytes())

    report = AnalysisEngine().analyze(target)

    section = report.sections["conquer_animation"]
    assert section["resource_kind"] == "ani"
    assert section["section_count"] == 2
    assert section["contains_puzzle_sections"] is True
    assert section["max_puzzle_index"] == 1
    assert section["unique_frame_reference_count"] == 2
    assert section["unique_frame_path_count"] == 2
    assert section["first_frame_directory"] == "data/map/puzzle/room/arena"
    assert section["resolved_frames_sample"][0]["exists"] is True
    assert section["resolved_frames_sample"][0]["resource_kind"] == "dds"
    assert section["resolved_frames_sample"][0]["dds"]["width"] == 1
    assert section["existing_frame_sample_count"] == 1
    assert section["existing_frame_count"] == 1
    assert section["missing_frame_count"] == 1
    assert section["frame_coverage_ratio"] == 0.5
    assert section["missing_frame_sample"] == ["data/map/puzzle/room/arena/arena001.dds"]
    assert section["resolution_source_counts"] == [
        {"source": "filesystem", "count": 1},
        {"source": "missing", "count": 1},
    ]
    assert section["missing_frame_directory_counts"] == [
        {"directory": "data/map/puzzle/room/arena", "count": 1},
    ]
    assert section["missing_frame_directory_file_counts"] == [
        {
            "directory": "data/map/puzzle/room/arena",
            "file_counts": [{"name": "arena001.dds", "count": 1}],
        },
    ]
    assert section["missing_frame_directory_hints"] == [
        {
            "directory": "data/map/puzzle/room/arena",
            "count": 1,
            "exists": True,
            "exists_on_filesystem": True,
            "exists_in_package": False,
            "nearest_existing_parent": None,
            "sibling_directories_sample": [],
            "same_basename_matches_sample": [],
            "close_directory_matches_sample": [],
            "replacement_candidates": [],
        },
    ]
    assert section["missing_frame_directory_clusters"] == []
    assert section["validated_missing_frame_directory_clusters"] == []
    assert section["alias_resolved_frame_sample"] == []
    assert section["alias_resolved_frame_count"] == 0
    assert section["sequence_alias_resolved_frame_count"] == 0
    assert section["residual_missing_frame_count"] == 1
    assert section["residual_missing_frame_sample"] == ["data/map/puzzle/room/arena/arena001.dds"]
    assert section["residual_missing_frame_directory_counts"] == [
        {"directory": "data/map/puzzle/room/arena", "count": 1},
    ]
    assert section["validated_residual_missing_frame_directory_clusters"] == []
    assert section["effective_existing_frame_count"] == 1
    assert section["effective_missing_frame_count"] == 1
    assert section["effective_frame_coverage_ratio"] == 0.5
    assert "conquer:ani" in report.summary["tags"]


def test_conquer_animation_analyzer_handles_cropped_frame_references(tmp_path):
    root = tmp_path / "Conquer"
    ani_root = root / "ani"
    frame_root = root / "data" / "interface" / "Style01" / "skill"
    ani_root.mkdir(parents=True)
    frame_root.mkdir(parents=True)
    target = ani_root / "Magic.Ani"
    target.write_text(
        "[Magic0]\nFrameAmount=1\nFrame0=data/interface/Style01/skill/MainImgMagic.dds,0,0,50,50\n",
        encoding="utf-8",
    )
    (frame_root / "MainImgMagic.dds").write_bytes(_build_dds_bytes())

    report = AnalysisEngine().analyze(target)

    section = report.sections["conquer_animation"]
    assert section["cropped_frame_reference_count"] == 1
    assert section["frame_reference_sample"] == ["data/interface/Style01/skill/MainImgMagic.dds,0,0,50,50"]
    assert section["frame_paths_sample"] == ["data/interface/Style01/skill/MainImgMagic.dds"]
    assert section["resolved_frames_sample"][0]["exists"] is True
    assert section["resolved_frames_sample"][0]["resolved_path"].endswith("MainImgMagic.dds")


def test_conquer_animation_analyzer_summarizes_install_directory(tmp_path):
    root = tmp_path / "Conquer"
    (root / "map" / "map").mkdir(parents=True)
    ani_root = root / "ani"
    frame_root = root / "data" / "map" / "puzzle" / "room" / "arena"
    ani_root.mkdir(parents=True)
    frame_root.mkdir(parents=True)
    (ani_root / "room.ani").write_text(_build_ani_text(), encoding="utf-8")
    (frame_root / "arena000.dds").write_bytes(_build_dds_bytes())

    report = AnalysisEngine().analyze(root)

    section = report.sections["conquer_animation"]
    assert section["resource_kind"] == "animation-directory"
    assert section["ani_count"] == 1
    assert section["puzzle_animation_count"] == 1
    assert section["ani_sample"] == ["ani/room.ani"]
    assert section["total_unique_frame_path_count"] == 2
    assert section["total_existing_frame_count"] == 1
    assert section["total_missing_frame_count"] == 1
    assert section["overall_frame_coverage_ratio"] == 0.5
    assert section["section_family_counts"][0]["family"] == "Puzzle"
    assert section["resolution_source_counts"] == [
        {"source": "filesystem", "count": 1},
        {"source": "missing", "count": 1},
    ]
    assert section["missing_frame_directory_counts"] == [
        {"directory": "data/map/puzzle/room/arena", "count": 1},
    ]
    assert section["missing_frame_directory_file_counts"] == [
        {
            "directory": "data/map/puzzle/room/arena",
            "file_counts": [{"name": "arena001.dds", "count": 1}],
        },
    ]
    assert section["missing_frame_directory_hints"] == [
        {
            "directory": "data/map/puzzle/room/arena",
            "count": 1,
            "exists": True,
            "exists_on_filesystem": True,
            "exists_in_package": False,
            "nearest_existing_parent": None,
            "sibling_directories_sample": [],
            "same_basename_matches_sample": [],
            "close_directory_matches_sample": [],
            "replacement_candidates": [],
        },
    ]
    assert section["missing_frame_directory_clusters"] == []
    assert section["validated_missing_frame_directory_clusters"] == []
    assert section["total_alias_resolved_frame_count"] == 0
    assert section["total_sequence_alias_resolved_frame_count"] == 0
    assert section["total_residual_missing_frame_count"] == 1
    assert section["residual_missing_frame_directory_counts"] == [
        {"directory": "data/map/puzzle/room/arena", "count": 1},
    ]
    assert section["validated_residual_missing_frame_directory_clusters"] == []
    assert section["effective_existing_frame_count"] == 1
    assert section["effective_missing_frame_count"] == 1
    assert section["effective_frame_coverage_ratio"] == 0.5
    assert section["lowest_effective_coverage_sample"][0]["path"] == "ani/room.ani"
    assert section["highest_alias_gain_sample"][0]["path"] == "ani/room.ani"
    assert section["largest_animations_sample"][0]["path"] == "ani/room.ani"


def test_conquer_animation_analyzer_resolves_package_backed_dds_frames(tmp_path):
    root = tmp_path / "Conquer"
    ani_root = root / "ani"
    ani_root.mkdir(parents=True)
    target = ani_root / "icons.ani"
    target.write_text("[Item0]\nFrameAmount=1\nFrame0=data/ItemMinIcon/000000.dds\n", encoding="utf-8")
    build_netdragon_pair(
        root,
        entries=[("data/ItemMinIcon/000000.dds", _build_dds_bytes())],
    )

    report = AnalysisEngine().analyze(target)

    frame = report.sections["conquer_animation"]["resolved_frames_sample"][0]
    assert frame["exists"] is True
    assert frame["exists_on_filesystem"] is False
    assert frame["exists_in_package"] is True
    assert frame["resolution_source"] == "netdragon-package"
    assert frame["package_entry"]["path"] == "data/ItemMinIcon/000000.dds"
    assert frame["dds"]["fourcc"] == "DXT1"


def test_conquer_animation_analyzer_reports_missing_directory_hints(tmp_path):
    root = tmp_path / "Conquer"
    ani_root = root / "ani"
    sibling_root = root / "data" / "map" / "puzzle" / "menpai" / "scene" / "devil"
    ani_root.mkdir(parents=True)
    sibling_root.mkdir(parents=True)
    target = ani_root / "menpai.ani"
    target.write_text(
        "[Puzzle0]\nFrameAmount=1\nFrame0=data/map/puzzle/menpai/scene/fire/fire000.dds\n",
        encoding="utf-8",
    )

    report = AnalysisEngine().analyze(target)

    hints = report.sections["conquer_animation"]["missing_frame_directory_hints"]
    assert hints == [
        {
            "directory": "data/map/puzzle/menpai/scene/fire",
            "count": 1,
            "exists": False,
            "exists_on_filesystem": False,
            "exists_in_package": False,
            "nearest_existing_parent": "data/map/puzzle/menpai/scene",
            "sibling_directories_sample": ["data/map/puzzle/menpai/scene/devil"],
            "same_basename_matches_sample": [],
            "close_directory_matches_sample": ["data/map/puzzle/menpai/scene/devil"],
            "replacement_candidates": [
                {
                    "directory": "data/map/puzzle/menpai/scene/devil",
                    "reason": "branch-swap-nearest-parent",
                    "exact_filename_overlap_count": 0,
                    "exact_filename_overlap_ratio": 0.0,
                    "exact_filename_overlap_sample": [],
                    "exact_filename_overlap_weighted_score": 0.0,
                    "exact_filename_overlap_weighted_ratio": 0.0,
                    "stem_overlap_count": 0,
                    "stem_overlap_ratio": 0.0,
                    "stem_overlap_sample": [],
                    "stem_overlap_weighted_score": 0.0,
                    "stem_overlap_weighted_ratio": 0.0,
                    "overlap_sequence_families": [],
                    "dds_profile_counts": [],
                    "dds_profile_sample_count": 0,
                    "dds_profiled_file_count": 0,
                    "dds_profile_consistency_ratio": None,
                    "generic_overlap_only": False,
                    "overlap_strength": "weak",
                },
            ],
        },
    ]
    assert report.sections["conquer_animation"]["missing_frame_directory_clusters"] == [
        {
            "replacement_directory": "data/map/puzzle/menpai/scene/devil",
            "reason": "branch-swap-nearest-parent",
            "missing_directory_count": 1,
            "missing_frame_count": 1,
            "exact_filename_overlap_count": 0,
            "stem_overlap_count": 0,
            "exact_filename_overlap_weighted_score": 0.0,
            "stem_overlap_weighted_score": 0.0,
            "generic_overlap_only": False,
            "exact_filename_overlap_ratio": 0.0,
            "stem_overlap_ratio": 0.0,
            "exact_filename_overlap_sample": [],
            "stem_overlap_sample": [],
            "overlap_strength": "weak",
            "missing_directories_sample": ["data/map/puzzle/menpai/scene/fire"],
        },
    ]
    assert report.sections["conquer_animation"]["validated_missing_frame_directory_clusters"] == []


def test_conquer_animation_analyzer_prefers_nearby_branch_replacements(tmp_path):
    root = tmp_path / "Conquer"
    ani_root = root / "ani"
    candidate_root = root / "data" / "map" / "puzzle" / "newplain" / "city"
    candidate_root.mkdir(parents=True)
    (root / "data" / "map" / "mapobj" / "city").mkdir(parents=True)
    (candidate_root / "city000.dds").write_bytes(_build_dds_bytes())
    ani_root.mkdir(parents=True)
    target = ani_root / "plain.ani"
    target.write_text(
        "[Puzzle0]\nFrameAmount=1\nFrame0=data/map/puzzle/plain/city/city000.dds\n",
        encoding="utf-8",
    )

    report = AnalysisEngine().analyze(target)

    hint = report.sections["conquer_animation"]["missing_frame_directory_hints"][0]
    assert hint["directory"] == "data/map/puzzle/plain/city"
    assert hint["replacement_candidates"][0] == {
        "directory": "data/map/puzzle/newplain/city",
        "reason": "branch-swap-nearest-parent",
        "exact_filename_overlap_count": 1,
        "exact_filename_overlap_ratio": 1.0,
        "exact_filename_overlap_sample": ["city000.dds"],
        "exact_filename_overlap_weighted_score": 1.0,
        "exact_filename_overlap_weighted_ratio": 1.0,
        "stem_overlap_count": 1,
        "stem_overlap_ratio": 1.0,
        "stem_overlap_sample": ["city.dds"],
        "stem_overlap_weighted_score": 1.0,
        "stem_overlap_weighted_ratio": 1.0,
        "overlap_sequence_families": [
            {
                "family": "city.dds",
                "count": 1,
                "min_index": 0,
                "max_index": 0,
                "longest_run": 1,
                "coverage_ratio": 1.0,
                "sample": ["city000.dds"],
            },
        ],
        "dds_profile_counts": [{"profile": "1x1 DXT1", "count": 1}],
        "dds_profile_sample_count": 1,
        "dds_profiled_file_count": 1,
        "dds_profile_consistency_ratio": 1.0,
        "generic_overlap_only": False,
        "overlap_strength": "strong",
    }
    assert report.sections["conquer_animation"]["missing_frame_directory_clusters"] == [
        {
            "replacement_directory": "data/map/puzzle/newplain/city",
            "reason": "branch-swap-nearest-parent",
            "missing_directory_count": 1,
            "missing_frame_count": 1,
            "exact_filename_overlap_count": 1,
            "stem_overlap_count": 1,
            "exact_filename_overlap_weighted_score": 1.0,
            "stem_overlap_weighted_score": 1.0,
            "generic_overlap_only": False,
            "exact_filename_overlap_ratio": 1.0,
            "stem_overlap_ratio": 1.0,
            "exact_filename_overlap_sample": ["city000.dds"],
            "stem_overlap_sample": ["city.dds"],
            "overlap_strength": "strong",
            "missing_directories_sample": ["data/map/puzzle/plain/city"],
        },
    ]
    assert report.sections["conquer_animation"]["validated_missing_frame_directory_clusters"] == [
        {
            "replacement_directory": "data/map/puzzle/newplain/city",
            "reason": "branch-swap-nearest-parent",
            "missing_directory_count": 1,
            "missing_frame_count": 1,
            "exact_filename_overlap_count": 1,
            "stem_overlap_count": 1,
            "exact_filename_overlap_weighted_score": 1.0,
            "stem_overlap_weighted_score": 1.0,
            "generic_overlap_only": False,
            "exact_filename_overlap_ratio": 1.0,
            "stem_overlap_ratio": 1.0,
            "exact_filename_overlap_sample": ["city000.dds"],
            "stem_overlap_sample": ["city.dds"],
            "overlap_strength": "strong",
            "missing_directories_sample": ["data/map/puzzle/plain/city"],
        },
    ]
    assert report.sections["conquer_animation"]["alias_resolved_frame_count"] == 1
    assert report.sections["conquer_animation"]["sequence_alias_resolved_frame_count"] == 0
    assert report.sections["conquer_animation"]["residual_missing_frame_count"] == 0
    assert report.sections["conquer_animation"]["residual_missing_frame_sample"] == []
    assert report.sections["conquer_animation"]["validated_residual_missing_frame_directory_clusters"] == []
    assert report.sections["conquer_animation"]["effective_existing_frame_count"] == 1
    assert report.sections["conquer_animation"]["effective_missing_frame_count"] == 0
    assert report.sections["conquer_animation"]["effective_frame_coverage_ratio"] == 1.0
    assert report.sections["conquer_animation"]["alias_resolved_frame_sample"] == [
        {
            "frame_path": "data/map/puzzle/plain/city/city000.dds",
            "alias_frame_path": "data/map/puzzle/newplain/city/city000.dds",
            "replacement_directory": "data/map/puzzle/newplain/city",
            "reason": "branch-swap-nearest-parent",
            "overlap_strength": "strong",
            "exact_filename_overlap_ratio": 1.0,
            "stem_overlap_ratio": 1.0,
            "resolution_kind": "same-name-directory-alias",
            "resolved": {
                "frame_path": "data/map/puzzle/newplain/city/city000.dds",
                "resolved_path": str(candidate_root / "city000.dds"),
                "exists": True,
                "exists_on_filesystem": True,
                "exists_in_package": False,
                "resolution_source": "filesystem",
                "resource_kind": "dds",
                "size_bytes": 128,
                "signature": "DDS ",
                "dds": {
                    "format": "dds",
                    "resource_kind": "texture",
                    "path": str(candidate_root / "city000.dds"),
                    "file_size_bytes": 128,
                    "header_size": 124,
                    "flags": 4103,
                    "height": 1,
                    "width": 1,
                    "pitch_or_linear_size": 8,
                    "depth": 0,
                    "mipmap_count": 1,
                    "pixel_format_size": 32,
                    "pixel_format_flags": 4,
                    "fourcc": "DXT1",
                    "rgb_bit_count": 0,
                    "caps": 4096,
                    "caps2": 0,
                    "dxgi_format": None,
                    "header_head_hex": _build_dds_bytes()[:64].hex(),
                },
            },
        },
    ]


def test_conquer_animation_analyzer_resolves_sequence_offset_aliases(tmp_path):
    root = tmp_path / "Conquer"
    ani_root = root / "ani"
    candidate_root = root / "data" / "map" / "puzzle" / "newplain" / "city"
    candidate_root.mkdir(parents=True)
    (candidate_root / "city000.dds").write_bytes(_build_dds_bytes())
    ani_root.mkdir(parents=True)
    target = ani_root / "plain-offset.ani"
    target.write_text(
        "[Puzzle0]\nFrameAmount=1\nFrame0=data/map/puzzle/plain/city/city044.dds\n",
        encoding="utf-8",
    )

    report = AnalysisEngine().analyze(target)

    hint = report.sections["conquer_animation"]["missing_frame_directory_hints"][0]
    assert hint["directory"] == "data/map/puzzle/plain/city"
    assert hint["replacement_candidates"][0]["sequence_rewrite_candidates"] == [
        {
            "family": "city.dds",
            "index_offset": -44,
            "aligned_count": 1,
            "aligned_coverage_ratio": 1.0,
            "missing_index_min": 44,
            "missing_index_max": 44,
            "candidate_index_min": 0,
            "candidate_index_max": 0,
            "sample_mappings": [
                {
                    "missing_name": "city044.dds",
                    "candidate_name": "city000.dds",
                },
            ],
        },
    ]
    assert report.sections["conquer_animation"]["alias_resolved_frame_count"] == 1
    assert report.sections["conquer_animation"]["sequence_alias_resolved_frame_count"] == 1
    assert report.sections["conquer_animation"]["residual_missing_frame_count"] == 0
    assert report.sections["conquer_animation"]["residual_missing_frame_sample"] == []
    assert report.sections["conquer_animation"]["validated_residual_missing_frame_directory_clusters"] == []
    assert report.sections["conquer_animation"]["effective_existing_frame_count"] == 1
    assert report.sections["conquer_animation"]["effective_missing_frame_count"] == 0
    assert report.sections["conquer_animation"]["effective_frame_coverage_ratio"] == 1.0
    assert report.sections["conquer_animation"]["alias_resolved_frame_sample"] == [
        {
            "frame_path": "data/map/puzzle/plain/city/city044.dds",
            "alias_frame_path": "data/map/puzzle/newplain/city/city000.dds",
            "replacement_directory": "data/map/puzzle/newplain/city",
            "reason": "branch-swap-nearest-parent",
            "overlap_strength": "moderate",
            "exact_filename_overlap_ratio": 0.0,
            "stem_overlap_ratio": 1.0,
            "resolution_kind": "sequence-offset-alias",
            "sequence_family": "city.dds",
            "sequence_index_offset": -44,
            "sequence_aligned_coverage_ratio": 1.0,
            "resolved": {
                "frame_path": "data/map/puzzle/newplain/city/city000.dds",
                "resolved_path": str(candidate_root / "city000.dds"),
                "exists": True,
                "exists_on_filesystem": True,
                "exists_in_package": False,
                "resolution_source": "filesystem",
                "resource_kind": "dds",
                "size_bytes": 128,
                "signature": "DDS ",
                "dds": {
                    "format": "dds",
                    "resource_kind": "texture",
                    "path": str(candidate_root / "city000.dds"),
                    "file_size_bytes": 128,
                    "header_size": 124,
                    "flags": 4103,
                    "height": 1,
                    "width": 1,
                    "pitch_or_linear_size": 8,
                    "depth": 0,
                    "mipmap_count": 1,
                    "pixel_format_size": 32,
                    "pixel_format_flags": 4,
                    "fourcc": "DXT1",
                    "rgb_bit_count": 0,
                    "caps": 4096,
                    "caps2": 0,
                    "dxgi_format": None,
                    "header_head_hex": _build_dds_bytes()[:64].hex(),
                },
            },
        },
    ]


def test_conquer_animation_analyzer_matches_legacy_basename_stems(tmp_path):
    root = tmp_path / "Conquer"
    ani_root = root / "ani"
    main_root = root / "data" / "Main"
    main_root.mkdir(parents=True)
    (root / "data" / "Hair").mkdir(parents=True)
    (main_root / "DialogLogin.dds").write_bytes(_build_dds_bytes())
    ani_root.mkdir(parents=True)
    target = ani_root / "Control2.Ani"
    target.write_text(
        "[Main0]\nFrameAmount=1\nFrame0=Data/Main1/DialogLogin.dds\n",
        encoding="utf-8",
    )

    report = AnalysisEngine().analyze(target)

    hint = report.sections["conquer_animation"]["missing_frame_directory_hints"][0]
    assert hint["directory"] == "Data/Main1"
    assert hint["replacement_candidates"][0] == {
        "directory": "data/Main",
        "reason": "branch-swap-nearest-parent",
        "exact_filename_overlap_count": 1,
        "exact_filename_overlap_ratio": 1.0,
        "exact_filename_overlap_sample": ["DialogLogin.dds"],
        "exact_filename_overlap_weighted_score": 1.0,
        "exact_filename_overlap_weighted_ratio": 1.0,
        "stem_overlap_count": 1,
        "stem_overlap_ratio": 1.0,
        "stem_overlap_sample": ["dialoglogin.dds"],
        "stem_overlap_weighted_score": 1.0,
        "stem_overlap_weighted_ratio": 1.0,
        "overlap_sequence_families": [
            {
                "family": "dialoglogin.dds",
                "count": 1,
                "min_index": None,
                "max_index": None,
                "longest_run": None,
                "coverage_ratio": None,
                "sample": ["DialogLogin.dds"],
            },
        ],
        "dds_profile_counts": [{"profile": "1x1 DXT1", "count": 1}],
        "dds_profile_sample_count": 1,
        "dds_profiled_file_count": 1,
        "dds_profile_consistency_ratio": 1.0,
        "generic_overlap_only": False,
        "overlap_strength": "strong",
    }
    assert report.sections["conquer_animation"]["missing_frame_directory_clusters"] == [
        {
            "replacement_directory": "data/Main",
            "reason": "branch-swap-nearest-parent",
            "missing_directory_count": 1,
            "missing_frame_count": 1,
            "exact_filename_overlap_count": 1,
            "stem_overlap_count": 1,
            "exact_filename_overlap_weighted_score": 1.0,
            "stem_overlap_weighted_score": 1.0,
            "generic_overlap_only": False,
            "exact_filename_overlap_ratio": 1.0,
            "stem_overlap_ratio": 1.0,
            "exact_filename_overlap_sample": ["DialogLogin.dds"],
            "stem_overlap_sample": ["dialoglogin.dds"],
            "overlap_strength": "strong",
            "missing_directories_sample": ["Data/Main1"],
        },
    ]
    assert report.sections["conquer_animation"]["validated_missing_frame_directory_clusters"] == [
        {
            "replacement_directory": "data/Main",
            "reason": "branch-swap-nearest-parent",
            "missing_directory_count": 1,
            "missing_frame_count": 1,
            "exact_filename_overlap_count": 1,
            "stem_overlap_count": 1,
            "exact_filename_overlap_weighted_score": 1.0,
            "stem_overlap_weighted_score": 1.0,
            "generic_overlap_only": False,
            "exact_filename_overlap_ratio": 1.0,
            "stem_overlap_ratio": 1.0,
            "exact_filename_overlap_sample": ["DialogLogin.dds"],
            "stem_overlap_sample": ["dialoglogin.dds"],
            "overlap_strength": "strong",
            "missing_directories_sample": ["Data/Main1"],
        },
    ]
    assert report.sections["conquer_animation"]["alias_resolved_frame_count"] == 1
    assert report.sections["conquer_animation"]["sequence_alias_resolved_frame_count"] == 0
    assert report.sections["conquer_animation"]["residual_missing_frame_count"] == 0
    assert report.sections["conquer_animation"]["residual_missing_frame_sample"] == []
    assert report.sections["conquer_animation"]["validated_residual_missing_frame_directory_clusters"] == []
    assert report.sections["conquer_animation"]["effective_existing_frame_count"] == 1
    assert report.sections["conquer_animation"]["effective_missing_frame_count"] == 0
    assert report.sections["conquer_animation"]["effective_frame_coverage_ratio"] == 1.0
    assert report.sections["conquer_animation"]["alias_resolved_frame_sample"] == [
        {
            "frame_path": "Data/Main1/DialogLogin.dds",
            "alias_frame_path": "data/Main/DialogLogin.dds",
            "replacement_directory": "data/Main",
            "reason": "branch-swap-nearest-parent",
            "overlap_strength": "strong",
            "exact_filename_overlap_ratio": 1.0,
            "stem_overlap_ratio": 1.0,
            "resolution_kind": "same-name-directory-alias",
            "resolved": {
                "frame_path": "data/Main/DialogLogin.dds",
                "resolved_path": str(main_root / "DialogLogin.dds"),
                "exists": True,
                "exists_on_filesystem": True,
                "exists_in_package": False,
                "resolution_source": "filesystem",
                "resource_kind": "dds",
                "size_bytes": 128,
                "signature": "DDS ",
                "dds": {
                    "format": "dds",
                    "resource_kind": "texture",
                    "path": str(main_root / "DialogLogin.dds"),
                    "file_size_bytes": 128,
                    "header_size": 124,
                    "flags": 4103,
                    "height": 1,
                    "width": 1,
                    "pitch_or_linear_size": 8,
                    "depth": 0,
                    "mipmap_count": 1,
                    "pixel_format_size": 32,
                    "pixel_format_flags": 4,
                    "fourcc": "DXT1",
                    "rgb_bit_count": 0,
                    "caps": 4096,
                    "caps2": 0,
                    "dxgi_format": None,
                    "header_head_hex": _build_dds_bytes()[:64].hex(),
                },
            },
        },
    ]
