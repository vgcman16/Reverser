from __future__ import annotations

import difflib
import re
from collections import Counter
from functools import lru_cache
from pathlib import Path

from reverser.analysis.dds import parse_dds_file
from reverser.analysis.dds import parse_dds_bytes
from reverser.analysis.netdragon import (
    build_netdragon_entry_lookup,
    NetDragonEntry,
    normalize_netdragon_path,
    read_netdragon_entry_bytes,
)


MAX_SAMPLE_ITEMS = 25
MAX_HINT_ITEMS = 5
MAX_SEQUENCE_ALIGNMENT_PAIRINGS = 300_000
REPLACEMENT_REASON_WEIGHTS = {
    "branch-swap-nearest-parent": 45,
    "sibling-nearest-parent": 40,
    "same-basename": 25,
    "same-stem": 22,
    "close-match": 15,
}
SECTION_PATTERN = re.compile(r"^\[([^\]]*)\]$")
FRAME_KEY_PATTERN = re.compile(r"^Frame(\d+)$")
SEQUENCE_FILENAME_PATTERN = re.compile(r"^(.*?)(\d+)(\.[^.]+)$")


def find_conquer_install_root(target: Path) -> Path | None:
    search_start = target if target.is_dir() else target.parent

    for candidate in [search_start, *search_start.parents]:
        if (
            (candidate / "map" / "map").is_dir()
            or (candidate / "map" / "puzzle").is_dir()
            or (candidate / "map" / "PuzzleSave").is_dir()
            or (candidate / "ani").is_dir()
        ):
            return candidate

    return None


def resolve_conquer_animation_path(animation_path: str, *, install_root: Path | None) -> Path | None:
    if not animation_path or install_root is None:
        return None

    normalized = animation_path.replace("\\", "/").lstrip("/")
    if not normalized:
        return None

    return install_root / Path(normalized)


def summarize_conquer_animation_path(animation_path: str, *, install_root: Path | None) -> dict[str, object]:
    resolved_path = resolve_conquer_animation_path(animation_path, install_root=install_root)
    payload: dict[str, object] = {
        "animation_path": animation_path,
        "resolved_path": str(resolved_path) if resolved_path else None,
        "exists": bool(resolved_path and resolved_path.exists()),
    }

    if resolved_path is None or not resolved_path.exists():
        return payload

    payload["resource_kind"] = "ani"
    summary = parse_ani_file(resolved_path, install_root=install_root)
    payload["summary"] = summary
    return payload


def summarize_conquer_animation_directory(target: Path, *, install_root: Path | None = None) -> dict[str, object]:
    resolved_install_root = install_root or find_conquer_install_root(target)
    if resolved_install_root is None:
        raise FileNotFoundError(f"No Conquer install root was found for {target}")

    ani_root = resolved_install_root / "ani"
    ani_files = sorted(
        path
        for path in ani_root.iterdir()
        if path.is_file() and path.suffix.lower() == ".ani"
    ) if ani_root.is_dir() else []

    animation_summaries = [parse_ani_file(path, install_root=resolved_install_root) for path in ani_files]
    total_unique_frame_path_count = sum(int(summary.get("unique_frame_path_count", 0)) for summary in animation_summaries)
    total_existing_frame_count = sum(int(summary.get("existing_frame_count", 0)) for summary in animation_summaries)
    total_missing_frame_count = sum(int(summary.get("missing_frame_count", 0)) for summary in animation_summaries)
    total_alias_resolved_frame_count = sum(int(summary.get("alias_resolved_frame_count", 0)) for summary in animation_summaries)
    total_sequence_alias_resolved_frame_count = sum(int(summary.get("sequence_alias_resolved_frame_count", 0)) for summary in animation_summaries)
    total_residual_missing_frame_count = sum(int(summary.get("residual_missing_frame_count", 0)) for summary in animation_summaries)
    puzzle_animation_count = sum(1 for summary in animation_summaries if summary.get("contains_puzzle_sections") is True)
    section_family_counts: Counter[str] = Counter()
    resolution_source_counts: Counter[str] = Counter()
    missing_frame_directory_counts: Counter[str] = Counter()
    missing_frame_directory_file_counts: dict[str, Counter[str]] = {}
    residual_missing_frame_directory_counts: Counter[str] = Counter()
    residual_missing_frame_directory_file_counts: dict[str, Counter[str]] = {}
    largest_animations: list[dict[str, object]] = []
    lowest_coverage: list[dict[str, object]] = []
    lowest_effective_coverage: list[dict[str, object]] = []
    highest_alias_gain: list[dict[str, object]] = []
    highest_sequence_alias_gain: list[dict[str, object]] = []

    for summary in animation_summaries:
        for family_entry in summary.get("section_family_counts", []):
            family = family_entry.get("family")
            count = family_entry.get("count")
            if isinstance(family, str) and isinstance(count, int):
                section_family_counts[family] += count
        for source_entry in summary.get("resolution_source_counts", []):
            source = source_entry.get("source")
            count = source_entry.get("count")
            if isinstance(source, str) and isinstance(count, int):
                resolution_source_counts[source] += count
        for directory_entry in summary.get("missing_frame_directory_counts", []):
            directory = directory_entry.get("directory")
            count = directory_entry.get("count")
            if isinstance(directory, str) and isinstance(count, int):
                missing_frame_directory_counts[directory] += count
        for directory_entry in summary.get("missing_frame_directory_file_counts", []):
            directory = directory_entry.get("directory")
            file_counts = directory_entry.get("file_counts")
            if not isinstance(directory, str) or not isinstance(file_counts, list):
                continue
            directory_counter = missing_frame_directory_file_counts.setdefault(directory, Counter())
            for file_entry in file_counts:
                if not isinstance(file_entry, dict):
                    continue
                name = file_entry.get("name")
                count = file_entry.get("count")
                if isinstance(name, str) and isinstance(count, int):
                    directory_counter[name] += count
        for directory_entry in summary.get("residual_missing_frame_directory_counts", []):
            directory = directory_entry.get("directory")
            count = directory_entry.get("count")
            if isinstance(directory, str) and isinstance(count, int):
                residual_missing_frame_directory_counts[directory] += count
        for directory_entry in summary.get("residual_missing_frame_directory_file_counts", []):
            directory = directory_entry.get("directory")
            file_counts = directory_entry.get("file_counts")
            if not isinstance(directory, str) or not isinstance(file_counts, list):
                continue
            directory_counter = residual_missing_frame_directory_file_counts.setdefault(directory, Counter())
            for file_entry in file_counts:
                if not isinstance(file_entry, dict):
                    continue
                name = file_entry.get("name")
                count = file_entry.get("count")
                if isinstance(name, str) and isinstance(count, int):
                    directory_counter[name] += count

        entry = {
            "path": relative_posix(Path(str(summary["path"])), resolved_install_root),
            "section_count": int(summary.get("section_count", 0)),
            "unique_frame_path_count": int(summary.get("unique_frame_path_count", 0)),
            "existing_frame_count": int(summary.get("existing_frame_count", 0)),
            "missing_frame_count": int(summary.get("missing_frame_count", 0)),
            "frame_coverage_ratio": summary.get("frame_coverage_ratio"),
            "alias_resolved_frame_count": int(summary.get("alias_resolved_frame_count", 0)),
            "sequence_alias_resolved_frame_count": int(summary.get("sequence_alias_resolved_frame_count", 0)),
            "effective_existing_frame_count": int(summary.get("effective_existing_frame_count", 0)),
            "effective_missing_frame_count": int(summary.get("effective_missing_frame_count", 0)),
            "effective_frame_coverage_ratio": summary.get("effective_frame_coverage_ratio"),
            "first_frame_directory": summary.get("first_frame_directory"),
        }
        largest_animations.append(entry)
        lowest_coverage.append(entry)
        lowest_effective_coverage.append(entry)
        highest_alias_gain.append(entry)
        highest_sequence_alias_gain.append(entry)

    all_directory_hints = _build_missing_directory_hints(
        resolved_install_root,
        missing_frame_directory_counts,
        directory_file_counts=missing_frame_directory_file_counts,
        limit=None,
    )
    directory_hints = all_directory_hints[:MAX_SAMPLE_ITEMS]

    all_missing_directory_clusters = _build_missing_directory_clusters(all_directory_hints, limit=None)
    missing_directory_clusters = all_missing_directory_clusters[:MAX_SAMPLE_ITEMS]
    all_residual_directory_hints = _build_missing_directory_hints(
        resolved_install_root,
        residual_missing_frame_directory_counts,
        directory_file_counts=residual_missing_frame_directory_file_counts,
        limit=None,
    )
    residual_directory_hints = all_residual_directory_hints[:MAX_SAMPLE_ITEMS]
    all_residual_directory_clusters = _build_missing_directory_clusters(all_residual_directory_hints, limit=None)
    residual_directory_clusters = all_residual_directory_clusters[:MAX_SAMPLE_ITEMS]

    return {
        "format": "conquer-online-animation",
        "scope": "directory",
        "resource_kind": "animation-directory",
        "analyzed_path": str(target),
        "install_root": str(resolved_install_root),
        "ani_root": str(ani_root) if ani_root.is_dir() else None,
        "ani_count": len(ani_files),
        "puzzle_animation_count": puzzle_animation_count,
        "total_unique_frame_path_count": total_unique_frame_path_count,
        "total_existing_frame_count": total_existing_frame_count,
        "total_missing_frame_count": total_missing_frame_count,
        "total_alias_resolved_frame_count": total_alias_resolved_frame_count,
        "total_sequence_alias_resolved_frame_count": total_sequence_alias_resolved_frame_count,
        "total_residual_missing_frame_count": total_residual_missing_frame_count,
        "overall_frame_coverage_ratio": (
            round(total_existing_frame_count / total_unique_frame_path_count, 4)
            if total_unique_frame_path_count
            else None
        ),
        "effective_existing_frame_count": total_existing_frame_count + total_alias_resolved_frame_count,
        "effective_missing_frame_count": max(0, total_missing_frame_count - total_alias_resolved_frame_count),
        "effective_frame_coverage_ratio": (
            round((total_existing_frame_count + total_alias_resolved_frame_count) / total_unique_frame_path_count, 4)
            if total_unique_frame_path_count
            else None
        ),
        "section_family_counts": [
            {"family": family, "count": count}
            for family, count in section_family_counts.most_common(MAX_SAMPLE_ITEMS)
        ],
        "resolution_source_counts": [
            {"source": source, "count": count}
            for source, count in resolution_source_counts.most_common(MAX_SAMPLE_ITEMS)
        ],
        "missing_frame_directory_counts": [
            {"directory": directory, "count": count}
            for directory, count in missing_frame_directory_counts.most_common(MAX_SAMPLE_ITEMS)
        ],
        "missing_frame_directory_file_counts": [
            {
                "directory": directory,
                "file_counts": [
                    {"name": name, "count": count}
                    for name, count in file_counts.most_common(MAX_SAMPLE_ITEMS)
                ],
            }
            for directory, file_counts in sorted(
                missing_frame_directory_file_counts.items(),
                key=lambda item: (-missing_frame_directory_counts[item[0]], item[0].lower()),
            )[:MAX_SAMPLE_ITEMS]
        ],
        "missing_frame_directory_hints": directory_hints,
        "missing_frame_directory_clusters": missing_directory_clusters,
        "validated_missing_frame_directory_clusters": _build_validated_missing_directory_clusters(all_missing_directory_clusters),
        "residual_missing_frame_directory_counts": [
            {"directory": directory, "count": count}
            for directory, count in residual_missing_frame_directory_counts.most_common(MAX_SAMPLE_ITEMS)
        ],
        "residual_missing_frame_directory_file_counts": [
            {
                "directory": directory,
                "file_counts": [
                    {"name": name, "count": count}
                    for name, count in file_counts.most_common(MAX_SAMPLE_ITEMS)
                ],
            }
            for directory, file_counts in sorted(
                residual_missing_frame_directory_file_counts.items(),
                key=lambda item: (-residual_missing_frame_directory_counts[item[0]], item[0].lower()),
            )[:MAX_SAMPLE_ITEMS]
        ],
        "residual_missing_frame_directory_hints": residual_directory_hints,
        "residual_missing_frame_directory_clusters": residual_directory_clusters,
        "validated_residual_missing_frame_directory_clusters": _build_validated_missing_directory_clusters(all_residual_directory_clusters),
        "ani_sample": [relative_posix(path, resolved_install_root) for path in ani_files[:MAX_SAMPLE_ITEMS]],
        "largest_animations_sample": sorted(
            largest_animations,
            key=lambda item: (-int(item["unique_frame_path_count"]), str(item["path"]).lower()),
        )[:MAX_SAMPLE_ITEMS],
        "lowest_coverage_sample": sorted(
            lowest_coverage,
            key=lambda item: (
                2 if item["frame_coverage_ratio"] is None else float(item["frame_coverage_ratio"]),
                -int(item["unique_frame_path_count"]),
                str(item["path"]).lower(),
            ),
        )[:MAX_SAMPLE_ITEMS],
        "lowest_effective_coverage_sample": sorted(
            lowest_effective_coverage,
            key=lambda item: (
                2 if item["effective_frame_coverage_ratio"] is None else float(item["effective_frame_coverage_ratio"]),
                -int(item["effective_missing_frame_count"]),
                str(item["path"]).lower(),
            ),
        )[:MAX_SAMPLE_ITEMS],
        "highest_alias_gain_sample": sorted(
            highest_alias_gain,
            key=lambda item: (
                -int(item["alias_resolved_frame_count"]),
                -int(item["sequence_alias_resolved_frame_count"]),
                -int(item["effective_missing_frame_count"]),
                str(item["path"]).lower(),
            ),
        )[:MAX_SAMPLE_ITEMS],
        "highest_sequence_alias_gain_sample": sorted(
            highest_sequence_alias_gain,
            key=lambda item: (
                -int(item["sequence_alias_resolved_frame_count"]),
                -int(item["alias_resolved_frame_count"]),
                -int(item["effective_missing_frame_count"]),
                str(item["path"]).lower(),
            ),
        )[:MAX_SAMPLE_ITEMS],
    }


def parse_ani_file(path: Path, *, install_root: Path | None = None) -> dict[str, object]:
    data = path.read_bytes()
    text, encoding = _decode_ani_text(data)
    summary, frame_paths = _parse_ani_text_internal(
        text,
        path=path,
        encoding=encoding,
        file_size_bytes=len(data),
    )
    if install_root is not None:
        _attach_frame_resolution(summary, install_root=install_root, frame_paths=frame_paths)
    return summary


def parse_ani_text(
    text: str,
    *,
    path: Path | None = None,
    encoding: str | None = None,
    file_size_bytes: int | None = None,
) -> dict[str, object]:
    summary, _ = _parse_ani_text_internal(
        text,
        path=path,
        encoding=encoding,
        file_size_bytes=file_size_bytes,
    )
    return summary


def _parse_ani_text_internal(
    text: str,
    *,
    path: Path | None = None,
    encoding: str | None = None,
    file_size_bytes: int | None = None,
) -> tuple[dict[str, object], list[str]]:
    section_names: list[str] = []
    section_family_counts: Counter[str] = Counter()
    unique_frame_paths: list[str] = []
    seen_frame_paths: set[str] = set()
    unique_frame_references: list[str] = []
    seen_frame_references: set[str] = set()
    frame_amount_total = 0
    frame_entry_count = 0
    max_frame_index: int | None = None
    max_puzzle_index: int | None = None
    cropped_frame_reference_count = 0

    for raw_line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = raw_line.strip()
        if not line or line.startswith("//") or line.startswith(";") or line.startswith("#"):
            continue

        section_match = SECTION_PATTERN.match(line)
        if section_match:
            section_name = section_match.group(1)
            section_names.append(section_name)
            section_family_counts[_section_family(section_name)] += 1
            puzzle_index = _puzzle_index(section_name)
            if puzzle_index is not None:
                max_puzzle_index = puzzle_index if max_puzzle_index is None else max(max_puzzle_index, puzzle_index)
            continue

        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()

        if key == "FrameAmount":
            try:
                frame_amount_total += int(value)
            except ValueError:
                continue
            continue

        frame_match = FRAME_KEY_PATTERN.match(key)
        if frame_match:
            frame_entry_count += 1
            frame_index = int(frame_match.group(1))
            max_frame_index = frame_index if max_frame_index is None else max(max_frame_index, frame_index)
            reference = parse_frame_reference(value)
            if value and value not in seen_frame_references:
                seen_frame_references.add(value)
                unique_frame_references.append(value)
            if reference["has_crop_metadata"]:
                cropped_frame_reference_count += 1
            asset_path = reference["asset_path"]
            if asset_path and asset_path not in seen_frame_paths:
                seen_frame_paths.add(asset_path)
                unique_frame_paths.append(asset_path)

    first_frame_path = unique_frame_paths[0] if unique_frame_paths else None
    first_frame_directory = _frame_directory(first_frame_path) if first_frame_path else None

    return ({
        "format": "conquer-online-animation",
        "scope": "file",
        "resource_kind": "ani",
        "path": str(path) if path else None,
        "file_size_bytes": file_size_bytes if file_size_bytes is not None else len(text.encode("utf-8")),
        "text_encoding": encoding,
        "section_count": len(section_names),
        "section_names_sample": section_names[:MAX_SAMPLE_ITEMS],
        "section_family_counts": [
            {"family": family, "count": count}
            for family, count in section_family_counts.most_common(MAX_SAMPLE_ITEMS)
        ],
        "contains_puzzle_sections": section_family_counts.get("Puzzle", 0) > 0,
        "max_puzzle_index": max_puzzle_index,
        "frame_amount_total": frame_amount_total,
        "frame_entry_count": frame_entry_count,
        "max_frame_index": max_frame_index,
        "unique_frame_reference_count": len(unique_frame_references),
        "frame_reference_sample": unique_frame_references[:MAX_SAMPLE_ITEMS],
        "cropped_frame_reference_count": cropped_frame_reference_count,
        "unique_frame_path_count": len(unique_frame_paths),
        "frame_paths_sample": unique_frame_paths[:MAX_SAMPLE_ITEMS],
        "first_frame_path": first_frame_path,
        "first_frame_directory": first_frame_directory,
        "header_head_text": text[:160].replace("\n", "\\n"),
    }, unique_frame_paths)


def relative_posix(path: Path, base: Path) -> str:
    return str(path.relative_to(base)).replace("\\", "/")


def _decode_ani_text(data: bytes) -> tuple[str, str]:
    for encoding in ("utf-8", "gbk"):
        try:
            return data.decode(encoding), encoding
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace"), "utf-8-replace"


def attach_animation_frame_resolution(
    summary: dict[str, object],
    *,
    install_root: Path | None,
    frame_paths: list[str] | None = None,
) -> None:
    _attach_frame_resolution(summary, install_root=install_root, frame_paths=frame_paths)


def _section_family(section_name: str) -> str:
    match = re.match(r"([A-Za-z_]+)", section_name)
    if match:
        return match.group(1)
    return section_name or "<empty>"


def _puzzle_index(section_name: str) -> int | None:
    match = re.fullmatch(r"Puzzle(\d+)", section_name)
    if not match:
        return None
    return int(match.group(1))


def _frame_directory(frame_path: str) -> str:
    normalized = frame_path.replace("\\", "/")
    if "/" not in normalized:
        return "."
    return normalized.rsplit("/", 1)[0]


def parse_frame_reference(value: str) -> dict[str, object]:
    raw = value.strip()
    if not raw:
        return {
            "raw": value,
            "asset_path": "",
            "has_crop_metadata": False,
            "crop_rect": None,
        }

    parts = [part.strip() for part in raw.split(",")]
    asset_path = parts[0]
    crop_rect = None
    if len(parts) >= 5:
        try:
            crop_rect = [int(part) for part in parts[1:5]]
        except ValueError:
            crop_rect = None

    return {
        "raw": raw,
        "asset_path": asset_path,
        "has_crop_metadata": len(parts) > 1,
        "crop_rect": crop_rect,
    }


def _attach_frame_resolution(
    summary: dict[str, object],
    *,
    install_root: Path | None,
    frame_paths: list[str] | None = None,
) -> None:
    candidate_frame_paths = frame_paths
    if candidate_frame_paths is None:
        sample_frame_paths = summary.get("frame_paths_sample")
        if isinstance(sample_frame_paths, list):
            candidate_frame_paths = [str(item) for item in sample_frame_paths]

    if not candidate_frame_paths or install_root is None:
        return

    existing_frame_count = 0
    missing_frame_sample: list[str] = []
    missing_frame_paths: list[str] = []
    resolution_source_counts: Counter[str] = Counter()
    missing_frame_directory_counts: Counter[str] = Counter()
    missing_frame_directory_file_counts: dict[str, Counter[str]] = {}
    for frame_path in candidate_frame_paths:
        resolved_path = _resolve_install_relative_path(frame_path, install_root=install_root)
        package_entry = _find_conquer_package_entry(frame_path, install_root=install_root)
        frame_directory = _frame_directory(frame_path)
        frame_name = Path(frame_path.replace("\\", "/")).name
        if resolved_path and resolved_path.exists() and package_entry is not None:
            existing_frame_count += 1
            resolution_source_counts["filesystem+package"] += 1
        elif resolved_path and resolved_path.exists():
            existing_frame_count += 1
            resolution_source_counts["filesystem"] += 1
        elif package_entry is not None:
            existing_frame_count += 1
            resolution_source_counts["netdragon-package"] += 1
        elif len(missing_frame_sample) < MAX_SAMPLE_ITEMS:
            missing_frame_paths.append(frame_path)
            missing_frame_sample.append(frame_path)
            resolution_source_counts["missing"] += 1
            missing_frame_directory_counts[frame_directory] += 1
            if frame_name:
                missing_frame_directory_file_counts.setdefault(frame_directory, Counter())[frame_name] += 1
        else:
            missing_frame_paths.append(frame_path)
            resolution_source_counts["missing"] += 1
            missing_frame_directory_counts[frame_directory] += 1
            if frame_name:
                missing_frame_directory_file_counts.setdefault(frame_directory, Counter())[frame_name] += 1

    resolved_frames = [
        summarize_conquer_frame_path(str(frame_path), install_root=install_root)
        for frame_path in candidate_frame_paths[:MAX_SAMPLE_ITEMS]
    ]
    unique_frame_path_count = int(summary.get("unique_frame_path_count", len(candidate_frame_paths)))
    missing_frame_count = max(0, unique_frame_path_count - existing_frame_count)
    summary["resolved_frames_sample"] = resolved_frames
    summary["existing_frame_sample_count"] = sum(1 for item in resolved_frames if item["exists"])
    summary["existing_frame_count"] = existing_frame_count
    summary["missing_frame_count"] = missing_frame_count
    summary["frame_coverage_ratio"] = round(existing_frame_count / unique_frame_path_count, 4) if unique_frame_path_count else None
    summary["missing_frame_sample"] = missing_frame_sample
    summary["resolution_source_counts"] = [
        {"source": source, "count": count}
        for source, count in resolution_source_counts.most_common(MAX_SAMPLE_ITEMS)
    ]
    summary["missing_frame_directory_counts"] = [
        {"directory": directory, "count": count}
        for directory, count in missing_frame_directory_counts.most_common(MAX_SAMPLE_ITEMS)
    ]
    summary["missing_frame_directory_file_counts"] = [
        {
            "directory": directory,
            "file_counts": [
                {"name": name, "count": count}
                for name, count in file_counts.most_common(MAX_SAMPLE_ITEMS)
            ],
        }
        for directory, file_counts in sorted(
            missing_frame_directory_file_counts.items(),
            key=lambda item: (-missing_frame_directory_counts[item[0]], item[0].lower()),
        )[:MAX_SAMPLE_ITEMS]
    ]
    all_directory_hints = _build_missing_directory_hints(
        install_root,
        missing_frame_directory_counts,
        directory_file_counts=missing_frame_directory_file_counts,
        limit=None,
    )
    directory_hints = all_directory_hints[:MAX_SAMPLE_ITEMS]
    all_directory_clusters = _build_missing_directory_clusters(all_directory_hints, limit=None)
    directory_clusters = all_directory_clusters[:MAX_SAMPLE_ITEMS]
    summary["missing_frame_directory_hints"] = directory_hints
    summary["missing_frame_directory_clusters"] = directory_clusters
    summary["validated_missing_frame_directory_clusters"] = _build_validated_missing_directory_clusters(all_directory_clusters)
    alias_summary = _build_alias_resolution_summary(
        install_root,
        missing_frame_paths,
        all_directory_hints,
    )
    summary["alias_resolved_frame_sample"] = alias_summary["resolved_sample"]
    summary["alias_resolved_frame_count"] = alias_summary["resolved_count"]
    summary["sequence_alias_resolved_frame_count"] = alias_summary["sequence_resolved_count"]
    unresolved_frame_paths = alias_summary["unresolved_paths"]
    residual_missing_frame_directory_counts: Counter[str] = Counter()
    residual_missing_frame_directory_file_counts: dict[str, Counter[str]] = {}
    for frame_path in unresolved_frame_paths:
        frame_directory = _frame_directory(frame_path)
        frame_name = Path(frame_path.replace("\\", "/")).name
        residual_missing_frame_directory_counts[frame_directory] += 1
        if frame_name:
            residual_missing_frame_directory_file_counts.setdefault(frame_directory, Counter())[frame_name] += 1
    all_residual_directory_hints = _build_missing_directory_hints(
        install_root,
        residual_missing_frame_directory_counts,
        directory_file_counts=residual_missing_frame_directory_file_counts,
        limit=None,
    )
    all_residual_directory_clusters = _build_missing_directory_clusters(all_residual_directory_hints, limit=None)
    summary["residual_missing_frame_count"] = len(unresolved_frame_paths)
    summary["residual_missing_frame_sample"] = unresolved_frame_paths[:MAX_SAMPLE_ITEMS]
    summary["residual_missing_frame_directory_counts"] = [
        {"directory": directory, "count": count}
        for directory, count in residual_missing_frame_directory_counts.most_common(MAX_SAMPLE_ITEMS)
    ]
    summary["residual_missing_frame_directory_file_counts"] = [
        {
            "directory": directory,
            "file_counts": [
                {"name": name, "count": count}
                for name, count in file_counts.most_common(MAX_SAMPLE_ITEMS)
            ],
        }
        for directory, file_counts in sorted(
            residual_missing_frame_directory_file_counts.items(),
            key=lambda item: (-residual_missing_frame_directory_counts[item[0]], item[0].lower()),
        )[:MAX_SAMPLE_ITEMS]
    ]
    summary["residual_missing_frame_directory_hints"] = all_residual_directory_hints[:MAX_SAMPLE_ITEMS]
    summary["residual_missing_frame_directory_clusters"] = all_residual_directory_clusters[:MAX_SAMPLE_ITEMS]
    summary["validated_residual_missing_frame_directory_clusters"] = _build_validated_missing_directory_clusters(all_residual_directory_clusters)
    summary["effective_existing_frame_count"] = existing_frame_count + alias_summary["resolved_count"]
    summary["effective_missing_frame_count"] = max(0, missing_frame_count - alias_summary["resolved_count"])
    summary["effective_frame_coverage_ratio"] = (
        round((existing_frame_count + alias_summary["resolved_count"]) / unique_frame_path_count, 4)
        if unique_frame_path_count
        else None
    )


def summarize_conquer_frame_path(frame_path: str, *, install_root: Path | None) -> dict[str, object]:
    resolved_path = _resolve_install_relative_path(frame_path, install_root=install_root)
    package_summary = _resolve_conquer_package_resource(frame_path, install_root=install_root)
    exists_on_filesystem = bool(resolved_path and resolved_path.exists())
    exists_in_package = bool(package_summary)
    payload: dict[str, object] = {
        "frame_path": frame_path,
        "resolved_path": str(resolved_path) if resolved_path else None,
        "exists": exists_on_filesystem or exists_in_package,
        "exists_on_filesystem": exists_on_filesystem,
        "exists_in_package": exists_in_package,
    }

    if exists_on_filesystem:
        payload["resolution_source"] = "filesystem+package" if exists_in_package else "filesystem"
        payload["resource_kind"] = resolved_path.suffix.lower().lstrip(".") or "<none>"
        payload["size_bytes"] = resolved_path.stat().st_size
        with resolved_path.open("rb") as handle:
            signature = handle.read(4)
        payload["signature"] = signature.decode("ascii", errors="replace")
        if signature == b"DDS ":
            try:
                payload["dds"] = parse_dds_file(resolved_path)
            except ValueError:
                payload["dds_error"] = "invalid-dds-header"
    elif exists_in_package and package_summary is not None:
        payload["resolution_source"] = "netdragon-package"
        payload["resource_kind"] = package_summary["resource_kind"]
        payload["size_bytes"] = package_summary["size_bytes"]
        payload["signature"] = package_summary["signature"]
        if "dds" in package_summary:
            payload["dds"] = package_summary["dds"]
    else:
        payload["resolution_source"] = "missing"

    if package_summary is not None:
        payload["package_entry"] = package_summary["package_entry"]
    return payload


def _resolve_install_relative_path(resource_path: str, *, install_root: Path | None) -> Path | None:
    if not resource_path or install_root is None:
        return None

    normalized = resource_path.replace("\\", "/").lstrip("/")
    if not normalized:
        return None

    return install_root / Path(normalized)


def _build_missing_directory_hints(
    install_root: Path | None,
    directory_counts: Counter[str],
    *,
    directory_file_counts: dict[str, Counter[str]] | None = None,
    limit: int | None = MAX_SAMPLE_ITEMS,
) -> list[dict[str, object]]:
    if install_root is None or not directory_counts:
        return []

    directory_index = _collect_existing_resource_directories(str(install_root.expanduser().resolve()))
    filesystem_directories = directory_index["filesystem_directories"]
    package_directories = directory_index["package_directories"]
    all_directories = directory_index["all_directories"]
    all_directory_keys = directory_index["all_directory_keys"]
    children_by_parent = directory_index["children_by_parent"]
    directories_by_basename = directory_index["directories_by_basename"]
    directories_by_stem = directory_index["directories_by_stem"]
    directory_filenames = directory_index["directory_filenames"]
    directory_filename_stems = directory_index["directory_filename_stems"]
    filename_directory_frequency = directory_index["filename_directory_frequency"]
    filename_stem_directory_frequency = directory_index["filename_stem_directory_frequency"]
    hints: list[dict[str, object]] = []
    file_counts_by_directory = directory_file_counts or {}

    for raw_directory, count in directory_counts.most_common():
        directory = raw_directory.replace("\\", "/")
        normalized = normalize_netdragon_path(directory)
        filesystem_match = filesystem_directories.get(normalized)
        package_match = package_directories.get(normalized)
        directory_exists = bool(filesystem_match or package_match)
        nearest_parent = None if directory_exists else _nearest_existing_parent(normalized, all_directories)
        basename = normalized.rsplit("/", 1)[-1] if normalized else normalized
        sibling_sample = _display_directory_samples(
            children_by_parent.get(nearest_parent, ()),
            all_directories,
            exclude={normalized},
        ) if nearest_parent else []
        same_basename_sample = _display_directory_samples(
            directories_by_basename.get(basename, ()),
            all_directories,
            exclude={normalized},
        )
        close_match_sample = [] if directory_exists else _display_directory_samples(
            [
                candidate
                for candidate in difflib.get_close_matches(
                    normalized,
                    all_directory_keys,
                    n=MAX_HINT_ITEMS * 3,
                    cutoff=0.6,
                )
                if not _is_same_or_ancestor_directory(candidate, normalized)
            ],
            all_directories,
            exclude={normalized},
        )
        replacement_candidates = [] if directory_exists else _build_replacement_candidates(
            directory,
            install_root=install_root,
            nearest_existing_parent=all_directories.get(nearest_parent) if nearest_parent else None,
            all_directories=all_directories,
            all_directory_keys=all_directory_keys,
            children_by_parent=children_by_parent,
            directories_by_basename=directories_by_basename,
            directories_by_stem=directories_by_stem,
            directory_filenames=directory_filenames,
            directory_filename_stems=directory_filename_stems,
            filename_directory_frequency=filename_directory_frequency,
            filename_stem_directory_frequency=filename_stem_directory_frequency,
            missing_file_counts=file_counts_by_directory.get(directory, Counter()),
        )
        hints.append({
            "directory": directory,
            "count": count,
            "exists": directory_exists,
            "exists_on_filesystem": filesystem_match is not None,
            "exists_in_package": package_match is not None,
            "nearest_existing_parent": all_directories.get(nearest_parent) if nearest_parent else None,
            "sibling_directories_sample": sibling_sample,
            "same_basename_matches_sample": same_basename_sample,
            "close_directory_matches_sample": close_match_sample,
            "replacement_candidates": replacement_candidates,
        })

    return hints if limit is None else hints[:limit]


def _build_missing_directory_clusters(
    directory_hints: list[dict[str, object]],
    *,
    limit: int | None = MAX_SAMPLE_ITEMS,
) -> list[dict[str, object]]:
    clusters: dict[tuple[str, str], dict[str, object]] = {}

    for hint in directory_hints:
        if hint.get("exists") is True:
            continue

        replacement_candidates = hint.get("replacement_candidates")
        if not isinstance(replacement_candidates, list) or not replacement_candidates:
            continue

        replacement = replacement_candidates[0]
        replacement_directory = replacement.get("directory")
        reason = replacement.get("reason")
        directory = hint.get("directory")
        count = hint.get("count")
        if not isinstance(replacement_directory, str) or not isinstance(reason, str):
            continue
        if not isinstance(directory, str) or not isinstance(count, int):
            continue

        key = (replacement_directory, reason)
        cluster = clusters.setdefault(key, {
            "replacement_directory": replacement_directory,
            "reason": reason,
            "missing_directory_count": 0,
            "missing_frame_count": 0,
            "exact_filename_overlap_count": 0,
            "stem_overlap_count": 0,
            "exact_filename_overlap_weighted_score": 0.0,
            "stem_overlap_weighted_score": 0.0,
            "generic_overlap_only": True,
            "exact_filename_overlap_sample": [],
            "stem_overlap_sample": [],
            "missing_directories_sample": [],
        })
        cluster["missing_directory_count"] = int(cluster["missing_directory_count"]) + 1
        cluster["missing_frame_count"] = int(cluster["missing_frame_count"]) + count
        cluster["exact_filename_overlap_count"] = int(cluster["exact_filename_overlap_count"]) + int(replacement.get("exact_filename_overlap_count", 0))
        cluster["stem_overlap_count"] = int(cluster["stem_overlap_count"]) + int(replacement.get("stem_overlap_count", 0))
        cluster["exact_filename_overlap_weighted_score"] = float(cluster["exact_filename_overlap_weighted_score"]) + float(replacement.get("exact_filename_overlap_weighted_score", 0.0))
        cluster["stem_overlap_weighted_score"] = float(cluster["stem_overlap_weighted_score"]) + float(replacement.get("stem_overlap_weighted_score", 0.0))
        cluster["generic_overlap_only"] = bool(cluster.get("generic_overlap_only", True)) and bool(replacement.get("generic_overlap_only", False))
        sample = cluster["missing_directories_sample"]
        if isinstance(sample, list) and directory not in sample and len(sample) < MAX_HINT_ITEMS:
            sample.append(directory)
        exact_sample = cluster["exact_filename_overlap_sample"]
        if isinstance(exact_sample, list):
            for name in replacement.get("exact_filename_overlap_sample", []):
                if isinstance(name, str) and name not in exact_sample and len(exact_sample) < MAX_HINT_ITEMS:
                    exact_sample.append(name)
        stem_sample = cluster["stem_overlap_sample"]
        if isinstance(stem_sample, list):
            for name in replacement.get("stem_overlap_sample", []):
                if isinstance(name, str) and name not in stem_sample and len(stem_sample) < MAX_HINT_ITEMS:
                    stem_sample.append(name)

    for cluster in clusters.values():
        missing_frame_count = int(cluster["missing_frame_count"])
        exact_overlap_count = int(cluster["exact_filename_overlap_count"])
        stem_overlap_count = int(cluster["stem_overlap_count"])
        cluster["exact_filename_overlap_ratio"] = (
            round(exact_overlap_count / missing_frame_count, 4)
            if missing_frame_count
            else None
        )
        cluster["stem_overlap_ratio"] = (
            round(stem_overlap_count / missing_frame_count, 4)
            if missing_frame_count
            else None
        )
        cluster["exact_filename_overlap_weighted_score"] = round(float(cluster["exact_filename_overlap_weighted_score"]), 4)
        cluster["stem_overlap_weighted_score"] = round(float(cluster["stem_overlap_weighted_score"]), 4)
        cluster["overlap_strength"] = _classify_overlap_strength(
            cluster["exact_filename_overlap_ratio"],
            cluster["stem_overlap_ratio"],
            weighted_exact_score=cluster["exact_filename_overlap_weighted_score"],
            weighted_stem_score=cluster["stem_overlap_weighted_score"],
            generic_overlap_only=bool(cluster.get("generic_overlap_only", False)),
        )

    sorted_clusters = sorted(
        clusters.values(),
        key=lambda item: (
            -int(item["missing_frame_count"]),
            -int(item["missing_directory_count"]),
            _replacement_reason_sort_key(str(item["reason"])),
            str(item["replacement_directory"]).lower(),
        ),
    )
    return sorted_clusters if limit is None else sorted_clusters[:limit]


def _build_validated_missing_directory_clusters(
    clusters: list[dict[str, object]],
) -> list[dict[str, object]]:
    validated_clusters = [
        cluster
        for cluster in clusters
        if str(cluster.get("overlap_strength")) in {"strong", "moderate"}
    ]
    return sorted(
        validated_clusters,
        key=lambda item: (
            _overlap_strength_sort_key(str(item.get("overlap_strength"))),
            -float(item.get("exact_filename_overlap_weighted_score", 0.0)),
            -float(item.get("stem_overlap_weighted_score", 0.0)),
            -float(item.get("exact_filename_overlap_ratio", 0.0)),
            -int(item.get("missing_frame_count", 0)),
            str(item.get("replacement_directory", "")).lower(),
        ),
    )[:MAX_SAMPLE_ITEMS]


def _build_alias_resolution_summary(
    install_root: Path | None,
    missing_frame_paths: list[str],
    directory_hints: list[dict[str, object]],
) -> dict[str, object]:
    if install_root is None or not missing_frame_paths:
        return {
            "resolved_count": 0,
            "sequence_resolved_count": 0,
            "resolved_sample": [],
            "unresolved_paths": list(missing_frame_paths),
        }

    hints_by_directory = {
        str(hint["directory"]): hint
        for hint in directory_hints
        if isinstance(hint, dict) and isinstance(hint.get("directory"), str)
    }
    resolved_sample: list[dict[str, object]] = []
    resolved_count = 0
    sequence_resolved_count = 0
    unresolved_paths: list[str] = []

    for frame_path in missing_frame_paths:
        resolution = _resolve_alias_frame_path(
            frame_path,
            install_root=install_root,
            hints_by_directory=hints_by_directory,
        )
        if resolution is None:
            unresolved_paths.append(frame_path)
            continue
        resolved_count += 1
        if str(resolution.get("resolution_kind")) == "sequence-offset-alias":
            sequence_resolved_count += 1
        if len(resolved_sample) < MAX_SAMPLE_ITEMS:
            resolved_sample.append(resolution)

    return {
        "resolved_count": resolved_count,
        "sequence_resolved_count": sequence_resolved_count,
        "resolved_sample": resolved_sample,
        "unresolved_paths": unresolved_paths,
    }


def _resolve_alias_frame_path(
    frame_path: str,
    *,
    install_root: Path,
    hints_by_directory: dict[str, dict[str, object]],
) -> dict[str, object] | None:
    frame_directory = _frame_directory(frame_path)
    basename = Path(frame_path.replace("\\", "/")).name
    hint = hints_by_directory.get(frame_directory)
    if hint is None:
        return None

    candidates = hint.get("replacement_candidates")
    if not isinstance(candidates, list):
        return None

    for candidate in candidates:
        if not isinstance(candidate, dict):
            continue
        if not _candidate_supports_alias_resolution(candidate):
            continue
        replacement_directory = candidate.get("directory")
        if not isinstance(replacement_directory, str):
            continue
        alias_frame_path = f"{replacement_directory.rstrip('/')}/{basename}"
        alias_payload = summarize_conquer_frame_path(alias_frame_path, install_root=install_root)
        if alias_payload.get("exists") is not True:
            sequence_resolution = _resolve_sequence_alias_frame_path(
                frame_path,
                replacement_directory=replacement_directory,
                candidate=candidate,
                install_root=install_root,
            )
            if sequence_resolution is not None:
                return {
                    "frame_path": frame_path,
                    "alias_frame_path": sequence_resolution["alias_frame_path"],
                    "replacement_directory": replacement_directory,
                    "reason": candidate.get("reason"),
                    "overlap_strength": candidate.get("overlap_strength"),
                    "exact_filename_overlap_ratio": candidate.get("exact_filename_overlap_ratio"),
                    "stem_overlap_ratio": candidate.get("stem_overlap_ratio"),
                    "resolution_kind": "sequence-offset-alias",
                    "sequence_family": sequence_resolution["sequence_family"],
                    "sequence_index_offset": sequence_resolution["sequence_index_offset"],
                    "sequence_aligned_coverage_ratio": sequence_resolution["sequence_aligned_coverage_ratio"],
                    "resolved": sequence_resolution["resolved"],
                }
            continue
        return {
            "frame_path": frame_path,
            "alias_frame_path": alias_frame_path,
            "replacement_directory": replacement_directory,
            "reason": candidate.get("reason"),
            "overlap_strength": candidate.get("overlap_strength"),
            "exact_filename_overlap_ratio": candidate.get("exact_filename_overlap_ratio"),
            "stem_overlap_ratio": candidate.get("stem_overlap_ratio"),
            "resolution_kind": "same-name-directory-alias",
            "resolved": alias_payload,
        }

    return None


def _resolve_sequence_alias_frame_path(
    frame_path: str,
    *,
    replacement_directory: str,
    candidate: dict[str, object],
    install_root: Path,
) -> dict[str, object] | None:
    basename = Path(frame_path.replace("\\", "/")).name
    parsed = _parse_sequence_filename(basename)
    if parsed is None:
        return None

    sequence_rewrites = candidate.get("sequence_rewrite_candidates")
    if not isinstance(sequence_rewrites, list):
        return None

    family = str(parsed["family"])
    index = int(parsed["index"])
    width = int(parsed["index_width"])
    prefix = str(parsed["prefix"])
    extension = str(parsed["extension"])

    for rewrite in sequence_rewrites:
        if not isinstance(rewrite, dict):
            continue
        if str(rewrite.get("family")) != family:
            continue
        offset = rewrite.get("index_offset")
        if not isinstance(offset, int):
            continue
        candidate_index = index + offset
        if candidate_index < 0:
            continue
        alias_name = f"{prefix}{candidate_index:0{width}d}{extension}"
        if alias_name.lower() == basename.lower():
            continue
        alias_frame_path = f"{replacement_directory.rstrip('/')}/{alias_name}"
        alias_payload = summarize_conquer_frame_path(alias_frame_path, install_root=install_root)
        if alias_payload.get("exists") is not True:
            continue
        return {
            "alias_frame_path": alias_frame_path,
            "sequence_family": family,
            "sequence_index_offset": offset,
            "sequence_aligned_coverage_ratio": rewrite.get("aligned_coverage_ratio"),
            "resolved": alias_payload,
        }

    return None


def _candidate_supports_alias_resolution(candidate: dict[str, object]) -> bool:
    exact_ratio = candidate.get("exact_filename_overlap_ratio")
    stem_ratio = candidate.get("stem_overlap_ratio")
    sequence_rewrites = candidate.get("sequence_rewrite_candidates")
    if isinstance(sequence_rewrites, list):
        for rewrite in sequence_rewrites:
            if not isinstance(rewrite, dict):
                continue
            aligned_coverage_ratio = rewrite.get("aligned_coverage_ratio")
            aligned_count = rewrite.get("aligned_count")
            if (
                isinstance(aligned_coverage_ratio, float)
                and aligned_coverage_ratio >= 0.5
                and isinstance(aligned_count, int)
                and aligned_count > 0
            ):
                return True
    if candidate.get("generic_overlap_only") is True:
        return False
    if str(candidate.get("overlap_strength")) != "strong":
        return False
    return (
        (isinstance(exact_ratio, float) and exact_ratio >= 0.1)
        or (isinstance(stem_ratio, float) and stem_ratio >= 0.5)
    )


def _build_replacement_candidates(
    missing_directory: str,
    *,
    install_root: Path | None,
    nearest_existing_parent: str | None,
    all_directories: dict[str, str],
    all_directory_keys: tuple[str, ...],
    children_by_parent: dict[str, tuple[str, ...]],
    directories_by_basename: dict[str, tuple[str, ...]],
    directories_by_stem: dict[str, tuple[str, ...]],
    directory_filenames: dict[str, tuple[str, ...]],
    directory_filename_stems: dict[str, tuple[str, ...]],
    filename_directory_frequency: dict[str, int],
    filename_stem_directory_frequency: dict[str, int],
    missing_file_counts: Counter[str],
) -> list[dict[str, object]]:
    candidates: list[dict[str, object]] = []
    seen: set[str] = set()
    missing_normalized = normalize_netdragon_path(missing_directory)
    nearest_parent_normalized = normalize_netdragon_path(nearest_existing_parent) if nearest_existing_parent else ""
    missing_filename_stem_counts = Counter(
        _normalize_filename_stem(name)
        for name, count in missing_file_counts.items()
        for _ in range(count)
        if _normalize_filename_stem(name)
    )

    def add_candidate(directory_key: str, reason: str) -> None:
        if not directory_key or directory_key in seen:
            return
        display = all_directories.get(directory_key)
        if not display:
            return
        seen.add(directory_key)
        overlap_names = _list_overlapping_names(
            missing_file_counts,
            directory_filenames.get(directory_key, ()),
        )
        generic_overlap_only = bool(overlap_names) and all(
            _is_low_signal_overlap_name(name)
            for name in overlap_names
        )
        exact_overlap, exact_overlap_sample = _count_filename_overlap(
            missing_file_counts,
            directory_filenames.get(directory_key, ()),
        )
        stem_overlap, stem_overlap_sample = _count_filename_overlap(
            missing_filename_stem_counts,
            directory_filename_stems.get(directory_key, ()),
        )
        missing_total = sum(missing_file_counts.values())
        stem_total = sum(missing_filename_stem_counts.values())
        exact_weighted_score = _compute_weighted_overlap_score(
            missing_file_counts,
            directory_filenames.get(directory_key, ()),
            filename_directory_frequency,
        )
        stem_weighted_score = _compute_weighted_overlap_score(
            missing_filename_stem_counts,
            directory_filename_stems.get(directory_key, ()),
            filename_stem_directory_frequency,
        )
        exact_weighted_total = _compute_weighted_overlap_total(
            missing_file_counts,
            filename_directory_frequency,
        )
        stem_weighted_total = _compute_weighted_overlap_total(
            missing_filename_stem_counts,
            filename_stem_directory_frequency,
        )
        sequence_families = _summarize_overlap_sequence_families(overlap_names, missing_file_counts)
        dds_profile_summary = _summarize_candidate_dds_profiles(
            display,
            overlap_names,
            install_root=install_root,
        )
        sequence_rewrite_candidates = _build_sequence_rewrite_candidates(
            missing_file_counts,
            directory_filenames.get(directory_key, ()),
        )
        candidates.append({
            "directory": display,
            "reason": reason,
            "exact_filename_overlap_count": exact_overlap,
            "exact_filename_overlap_ratio": round(exact_overlap / missing_total, 4) if missing_total else None,
            "exact_filename_overlap_sample": exact_overlap_sample,
            "exact_filename_overlap_weighted_score": round(exact_weighted_score, 4),
            "exact_filename_overlap_weighted_ratio": (
                round(exact_weighted_score / exact_weighted_total, 4)
                if exact_weighted_total
                else None
            ),
            "stem_overlap_count": stem_overlap,
            "stem_overlap_ratio": round(stem_overlap / stem_total, 4) if stem_total else None,
            "stem_overlap_sample": stem_overlap_sample,
            "stem_overlap_weighted_score": round(stem_weighted_score, 4),
            "stem_overlap_weighted_ratio": (
                round(stem_weighted_score / stem_weighted_total, 4)
                if stem_weighted_total
                else None
            ),
            "overlap_sequence_families": sequence_families,
            "dds_profile_counts": dds_profile_summary["dds_profile_counts"],
            "dds_profile_sample_count": dds_profile_summary["sample_count"],
            "dds_profiled_file_count": dds_profile_summary["profiled_file_count"],
            "dds_profile_consistency_ratio": dds_profile_summary["profile_consistency_ratio"],
            "generic_overlap_only": generic_overlap_only,
            **(
                {"sequence_rewrite_candidates": sequence_rewrite_candidates}
                if sequence_rewrite_candidates
                else {}
            ),
            "overlap_strength": _classify_overlap_strength(
                round(exact_overlap / missing_total, 4) if missing_total else None,
                round(stem_overlap / stem_total, 4) if stem_total else None,
                weighted_exact_score=round(exact_weighted_score, 4),
                weighted_stem_score=round(stem_weighted_score, 4),
                generic_overlap_only=generic_overlap_only,
            ),
        })

    if (
        nearest_parent_normalized
        and missing_normalized.startswith(f"{nearest_parent_normalized}/")
    ):
        relative_suffix = missing_normalized[len(nearest_parent_normalized) + 1:]
        relative_parts = [part for part in relative_suffix.split("/") if part]
        branch_tail = relative_parts[1:] if relative_parts else []
        for sibling_directory in children_by_parent.get(nearest_parent_normalized, ()):
            if branch_tail:
                candidate_directory = "/".join([sibling_directory, *branch_tail])
            else:
                candidate_directory = sibling_directory
            if candidate_directory != missing_normalized and candidate_directory in all_directories:
                add_candidate(candidate_directory, "branch-swap-nearest-parent")

    basename = missing_normalized.rsplit("/", 1)[-1] if missing_normalized else ""
    for directory_key in directories_by_basename.get(basename, ()):
        add_candidate(directory_key, "same-basename")

    stem = _normalize_directory_leaf_stem(missing_normalized)
    for directory_key in directories_by_stem.get(stem, ()):
        add_candidate(directory_key, "same-stem")

    for directory_key in difflib.get_close_matches(
        missing_normalized,
        all_directory_keys,
        n=MAX_HINT_ITEMS * 4,
        cutoff=0.6,
    ):
        if _is_same_or_ancestor_directory(directory_key, missing_normalized):
            continue
        add_candidate(directory_key, "close-match")

    return sorted(
        candidates,
        key=lambda item: _replacement_candidate_sort_key(
            missing_directory,
            str(item["directory"]),
            candidate=item,
            nearest_existing_parent=nearest_existing_parent,
        ),
    )[:MAX_HINT_ITEMS]


def _replacement_candidate_sort_key(
    missing_directory: str,
    candidate_directory: str,
    *,
    candidate: dict[str, object],
    nearest_existing_parent: str | None,
) -> tuple[int, int, str]:
    score = _replacement_candidate_score(
        missing_directory,
        candidate_directory,
        reason=str(candidate["reason"]),
        nearest_existing_parent=nearest_existing_parent,
        exact_overlap_count=int(candidate.get("exact_filename_overlap_count", 0)),
        stem_overlap_count=int(candidate.get("stem_overlap_count", 0)),
        exact_overlap_weighted_score=float(candidate.get("exact_filename_overlap_weighted_score", 0.0)),
        stem_overlap_weighted_score=float(candidate.get("stem_overlap_weighted_score", 0.0)),
    )
    return (-score, _replacement_reason_sort_key(str(candidate["reason"])), normalize_netdragon_path(candidate_directory))


def _replacement_candidate_score(
    missing_directory: str,
    candidate_directory: str,
    *,
    reason: str,
    nearest_existing_parent: str | None,
    exact_overlap_count: int,
    stem_overlap_count: int,
    exact_overlap_weighted_score: float,
    stem_overlap_weighted_score: float,
) -> float:
    missing_normalized = normalize_netdragon_path(missing_directory)
    candidate_normalized = normalize_netdragon_path(candidate_directory)
    nearest_parent_normalized = (
        normalize_netdragon_path(nearest_existing_parent)
        if nearest_existing_parent
        else ""
    )
    missing_parts = [part for part in missing_normalized.split("/") if part]
    candidate_parts = [part for part in candidate_normalized.split("/") if part]
    prefix_depth = _path_prefix_depth(missing_normalized, candidate_normalized)
    same_basename = (
        missing_normalized.rsplit("/", 1)[-1] == candidate_normalized.rsplit("/", 1)[-1]
        if missing_normalized and candidate_normalized
        else False
    )
    shares_nearest_parent_branch = bool(
        nearest_parent_normalized
        and candidate_normalized.startswith(f"{nearest_parent_normalized}/")
    )
    stem_match = (
        _normalize_directory_leaf_stem(missing_normalized)
        and _normalize_directory_leaf_stem(missing_normalized) == _normalize_directory_leaf_stem(candidate_normalized)
    )
    similarity_bonus = int(
        difflib.SequenceMatcher(None, missing_normalized, candidate_normalized).ratio() * 20
    )
    depth_penalty = abs(len(missing_parts) - len(candidate_parts)) * 18

    return (
        REPLACEMENT_REASON_WEIGHTS.get(reason, 0)
        + (exact_overlap_weighted_score * 120)
        + (stem_overlap_weighted_score * 40)
        + (exact_overlap_count * 2)
        + stem_overlap_count
        + (40 if shares_nearest_parent_branch else 0)
        + (20 if same_basename else 0)
        + (30 if stem_match and not same_basename else 0)
        + (prefix_depth * 6)
        + similarity_bonus
        - depth_penalty
    )


def _replacement_reason_sort_key(reason: str) -> int:
    ordered_reasons = (
        "branch-swap-nearest-parent",
        "sibling-nearest-parent",
        "same-basename",
        "same-stem",
        "close-match",
    )
    try:
        return ordered_reasons.index(reason)
    except ValueError:
        return len(ordered_reasons)


def _overlap_strength_sort_key(strength: str) -> int:
    ordered_strengths = ("strong", "moderate", "weak")
    try:
        return ordered_strengths.index(strength)
    except ValueError:
        return len(ordered_strengths)


def _normalize_directory_leaf_stem(directory: str) -> str:
    basename = normalize_netdragon_path(directory).rsplit("/", 1)[-1]
    return re.sub(r"\d+", "", basename)


def _normalize_filename_stem(name: str) -> str:
    normalized = name.replace("\\", "/").rsplit("/", 1)[-1].lower()
    stem = Path(normalized).stem
    suffix = Path(normalized).suffix
    stripped_stem = re.sub(r"\d+", "", stem)
    if not stripped_stem:
        return normalized
    return f"{stripped_stem}{suffix}"


def _is_low_signal_overlap_name(name: str) -> bool:
    normalized = name.replace("\\", "/").rsplit("/", 1)[-1].lower()
    stem = Path(normalized).stem
    return stem.isdigit() or re.fullmatch(r"pic\d*", stem) is not None


def _count_filename_overlap(
    missing_file_counts: Counter[str],
    candidate_names: tuple[str, ...],
) -> tuple[int, list[str]]:
    candidate_name_set = {name.lower() for name in candidate_names}
    overlap_count = 0
    overlap_sample: list[str] = []
    for name, count in missing_file_counts.most_common():
        normalized_name = name.lower()
        if normalized_name not in candidate_name_set:
            continue
        overlap_count += count
        if len(overlap_sample) < MAX_HINT_ITEMS:
            overlap_sample.append(name)
    return overlap_count, overlap_sample


def _list_overlapping_names(
    missing_file_counts: Counter[str],
    candidate_names: tuple[str, ...],
) -> list[str]:
    candidate_name_set = {name.lower() for name in candidate_names}
    overlap_names = [
        name
        for name, _count in missing_file_counts.most_common()
        if name.lower() in candidate_name_set
    ]
    return overlap_names


def _compute_weighted_overlap_score(
    missing_file_counts: Counter[str],
    candidate_names: tuple[str, ...],
    frequency_map: dict[str, int],
) -> float:
    candidate_name_set = {name.lower() for name in candidate_names}
    score = 0.0
    for name, count in missing_file_counts.items():
        normalized_name = name.lower()
        if normalized_name not in candidate_name_set:
            continue
        frequency = max(1, int(frequency_map.get(normalized_name, 1)))
        score += count / frequency
    return score


def _compute_weighted_overlap_total(
    missing_file_counts: Counter[str],
    frequency_map: dict[str, int],
) -> float:
    total = 0.0
    for name, count in missing_file_counts.items():
        frequency = max(1, int(frequency_map.get(name.lower(), 1)))
        total += count / frequency
    return total


def _summarize_overlap_sequence_families(
    overlap_names: list[str],
    missing_file_counts: Counter[str],
) -> list[dict[str, object]]:
    families: dict[str, dict[str, object]] = {}

    for name in overlap_names:
        parsed = _parse_sequence_filename(name)
        family_key = parsed["family"] if parsed is not None else name.lower()
        family = families.setdefault(family_key, {
            "family": family_key,
            "count": 0,
            "names": [],
            "indices": [],
        })
        count = int(missing_file_counts.get(name, 0))
        family["count"] = int(family["count"]) + count
        names = family["names"]
        if isinstance(names, list):
            names.append(name)
        if parsed is not None:
            indices = family["indices"]
            if isinstance(indices, list):
                indices.append(int(parsed["index"]))

    summaries: list[dict[str, object]] = []
    for family in families.values():
        names = family["names"] if isinstance(family["names"], list) else []
        indices = sorted(set(family["indices"])) if isinstance(family["indices"], list) else []
        if indices:
            min_index = min(indices)
            max_index = max(indices)
            span = max_index - min_index + 1
            longest_run = _compute_longest_run(indices)
            coverage_ratio = round(len(indices) / span, 4) if span else None
        else:
            min_index = None
            max_index = None
            longest_run = None
            coverage_ratio = None
        summaries.append({
            "family": str(family["family"]),
            "count": int(family["count"]),
            "min_index": min_index,
            "max_index": max_index,
            "longest_run": longest_run,
            "coverage_ratio": coverage_ratio,
            "sample": names[:MAX_HINT_ITEMS],
        })

    return sorted(
        summaries,
        key=lambda item: (
            -int(item["count"]),
            0 if item["coverage_ratio"] is None else -float(item["coverage_ratio"]),
            str(item["family"]).lower(),
        ),
    )[:MAX_HINT_ITEMS]


def _build_sequence_rewrite_candidates(
    missing_file_counts: Counter[str],
    candidate_names: tuple[str, ...],
) -> list[dict[str, object]]:
    missing_families = _collect_sequence_families_from_missing_counts(missing_file_counts)
    candidate_families = _collect_sequence_families_from_names(candidate_names)
    rewrites: list[dict[str, object]] = []

    for family, missing_family in missing_families.items():
        candidate_family = candidate_families.get(family)
        if candidate_family is None:
            continue
        rewrite = _infer_sequence_rewrite_candidate(
            family,
            missing_family=missing_family,
            candidate_family=candidate_family,
        )
        if rewrite is not None:
            rewrites.append(rewrite)

    return sorted(
        rewrites,
        key=lambda item: (
            -int(item["aligned_count"]),
            0 if item["aligned_coverage_ratio"] is None else -float(item["aligned_coverage_ratio"]),
            abs(int(item["index_offset"])),
            str(item["family"]).lower(),
        ),
    )[:MAX_HINT_ITEMS]


def _collect_sequence_families_from_missing_counts(
    missing_file_counts: Counter[str],
) -> dict[str, dict[str, object]]:
    families: dict[str, dict[str, object]] = {}
    for name, count in missing_file_counts.items():
        parsed = _parse_sequence_filename(name)
        if parsed is None:
            continue
        family = str(parsed["family"])
        entry = families.setdefault(family, {
            "index_counts": Counter(),
            "names_by_index": {},
        })
        entry["index_counts"][int(parsed["index"])] += int(count)
        names_by_index = entry["names_by_index"]
        if isinstance(names_by_index, dict):
            names_by_index.setdefault(int(parsed["index"]), name)
    return families


def _collect_sequence_families_from_names(
    candidate_names: tuple[str, ...],
) -> dict[str, dict[str, object]]:
    families: dict[str, dict[str, object]] = {}
    for name in candidate_names:
        parsed = _parse_sequence_filename(name)
        if parsed is None:
            continue
        family = str(parsed["family"])
        entry = families.setdefault(family, {
            "indices": set(),
            "names_by_index": {},
        })
        indices = entry["indices"]
        if isinstance(indices, set):
            indices.add(int(parsed["index"]))
        names_by_index = entry["names_by_index"]
        if isinstance(names_by_index, dict):
            names_by_index.setdefault(int(parsed["index"]), name)
    return families


def _infer_sequence_rewrite_candidate(
    family: str,
    *,
    missing_family: dict[str, object],
    candidate_family: dict[str, object],
) -> dict[str, object] | None:
    missing_index_counts = missing_family.get("index_counts")
    candidate_indices = candidate_family.get("indices")
    if not isinstance(missing_index_counts, Counter) or not isinstance(candidate_indices, set):
        return None
    if not missing_index_counts or not candidate_indices:
        return None

    missing_indices = sorted(int(index) for index in missing_index_counts)
    candidate_index_list = sorted(int(index) for index in candidate_indices)
    if not missing_indices or not candidate_index_list:
        return None

    offset_counter: Counter[int] = Counter()
    pairings = len(missing_indices) * len(candidate_index_list)
    if pairings <= MAX_SEQUENCE_ALIGNMENT_PAIRINGS:
        for missing_index in missing_indices:
            weight = int(missing_index_counts[missing_index])
            for candidate_index in candidate_index_list:
                offset_counter[candidate_index - missing_index] += weight
    else:
        sampled_candidate_indices = _sample_indices_for_alignment(candidate_index_list)
        for missing_index in missing_indices:
            weight = int(missing_index_counts[missing_index])
            for candidate_index in sampled_candidate_indices:
                offset_counter[candidate_index - missing_index] += weight

    if not offset_counter:
        return None

    offset, aligned_count = max(
        offset_counter.items(),
        key=lambda item: (item[1], -abs(item[0])),
    )
    if offset == 0 or int(aligned_count) <= 0:
        return None

    candidate_index_set = {int(index) for index in candidate_index_list}
    aligned_missing_indices = [
        missing_index
        for missing_index in missing_indices
        if missing_index + offset in candidate_index_set
    ]
    if not aligned_missing_indices:
        return None

    aligned_count = sum(int(missing_index_counts[missing_index]) for missing_index in aligned_missing_indices)
    total_missing = sum(int(count) for count in missing_index_counts.values())
    if aligned_count <= 0 or total_missing <= 0:
        return None

    names_by_index = missing_family.get("names_by_index")
    candidate_names_by_index = candidate_family.get("names_by_index")
    if not isinstance(names_by_index, dict) or not isinstance(candidate_names_by_index, dict):
        return None

    sample_mappings: list[dict[str, str]] = []
    for missing_index in aligned_missing_indices[:MAX_HINT_ITEMS]:
        candidate_index = missing_index + offset
        missing_name = names_by_index.get(missing_index)
        candidate_name = candidate_names_by_index.get(candidate_index)
        if isinstance(missing_name, str) and isinstance(candidate_name, str):
            sample_mappings.append({
                "missing_name": missing_name,
                "candidate_name": candidate_name,
            })

    return {
        "family": family,
        "index_offset": int(offset),
        "aligned_count": int(aligned_count),
        "aligned_coverage_ratio": round(aligned_count / total_missing, 4),
        "missing_index_min": min(aligned_missing_indices),
        "missing_index_max": max(aligned_missing_indices),
        "candidate_index_min": min(missing_index + offset for missing_index in aligned_missing_indices),
        "candidate_index_max": max(missing_index + offset for missing_index in aligned_missing_indices),
        "sample_mappings": sample_mappings,
    }


def _sample_indices_for_alignment(indices: list[int]) -> list[int]:
    if len(indices) <= MAX_HINT_ITEMS * 16:
        return indices
    step = max(1, len(indices) // (MAX_HINT_ITEMS * 16))
    sampled = indices[::step]
    if indices[-1] not in sampled:
        sampled.append(indices[-1])
    return sampled


def _parse_sequence_filename(name: str) -> dict[str, object] | None:
    raw_name = name.replace("\\", "/").rsplit("/", 1)[-1]
    normalized_name = raw_name.lower()
    match = SEQUENCE_FILENAME_PATTERN.fullmatch(normalized_name)
    if not match:
        return None
    prefix, raw_index, extension = match.groups()
    raw_match = SEQUENCE_FILENAME_PATTERN.fullmatch(raw_name)
    raw_prefix = raw_match.group(1) if raw_match is not None else prefix
    raw_extension = raw_match.group(3) if raw_match is not None else extension
    return {
        "family": f"{prefix}{extension}",
        "index": int(raw_index),
        "index_width": len(raw_index),
        "prefix": raw_prefix,
        "extension": raw_extension,
    }


def _compute_longest_run(indices: list[int]) -> int:
    if not indices:
        return 0
    longest = 1
    current = 1
    for previous, current_value in zip(indices, indices[1:]):
        if current_value == previous + 1:
            current += 1
        else:
            longest = max(longest, current)
            current = 1
    return max(longest, current)


def _summarize_candidate_dds_profiles(
    candidate_directory: str,
    overlap_names: list[str],
    *,
    install_root: Path | None,
) -> dict[str, object]:
    if install_root is None or not overlap_names:
        return {
            "sample_count": 0,
            "profiled_file_count": 0,
            "profile_consistency_ratio": None,
            "dds_profile_counts": [],
        }

    profile_counts: Counter[str] = Counter()
    sampled_file_count = 0
    profiled_file_count = 0
    for name in overlap_names[:MAX_HINT_ITEMS]:
        frame_path = f"{candidate_directory.rstrip('/')}/{name}"
        profile = _probe_conquer_dds_profile(str(install_root.expanduser().resolve()), frame_path)
        sampled_file_count += 1
        if profile is None:
            continue
        profiled_file_count += 1
        profile_counts[profile] += 1

    return {
        "sample_count": sampled_file_count,
        "profiled_file_count": profiled_file_count,
        "profile_consistency_ratio": (
            round(profile_counts.most_common(1)[0][1] / profiled_file_count, 4)
            if profiled_file_count and profile_counts
            else None
        ),
        "dds_profile_counts": [
            {"profile": profile, "count": count}
            for profile, count in profile_counts.most_common(MAX_HINT_ITEMS)
        ],
    }


@lru_cache(maxsize=4096)
def _probe_conquer_dds_profile(install_root: str, frame_path: str) -> str | None:
    payload = summarize_conquer_frame_path(frame_path, install_root=Path(install_root))
    dds = payload.get("dds")
    if not isinstance(dds, dict):
        return None
    width = dds.get("width")
    height = dds.get("height")
    fourcc = dds.get("fourcc")
    if isinstance(width, int) and isinstance(height, int):
        return f"{width}x{height} {fourcc or '<none>'}"
    return None


def _classify_overlap_strength(
    exact_ratio: float | None,
    stem_ratio: float | None,
    *,
    weighted_exact_score: float = 0.0,
    weighted_stem_score: float = 0.0,
    generic_overlap_only: bool = False,
) -> str:
    if generic_overlap_only:
        return "weak"
    exact_value = float(exact_ratio) if exact_ratio is not None else 0.0
    stem_value = float(stem_ratio) if stem_ratio is not None else 0.0
    has_exact_signal = exact_value > 0.0 or weighted_exact_score > 0.0
    if has_exact_signal and (
        exact_value >= 0.35 or stem_value >= 0.75 or weighted_exact_score >= 25 or weighted_stem_score >= 40
    ):
        return "strong"
    if not has_exact_signal:
        if weighted_stem_score >= 8:
            return "strong"
        if (stem_value >= 0.75 and weighted_stem_score >= 0.25) or weighted_stem_score >= 1:
            return "moderate"
        return "weak"
    if exact_value >= 0.1 or stem_value >= 0.3 or weighted_exact_score >= 5 or weighted_stem_score >= 12:
        return "moderate"
    return "weak"


@lru_cache(maxsize=8)
def _collect_existing_resource_directories(install_root: str) -> dict[str, object]:
    resolved_install_root = Path(install_root)
    filesystem_directories: dict[str, str] = {}
    package_directories: dict[str, str] = {}

    data_root = resolved_install_root / "data"
    if data_root.is_dir():
        for directory_path in [data_root, *data_root.rglob("*")]:
            if not directory_path.is_dir():
                continue
            relative_directory = relative_posix(directory_path, resolved_install_root)
            _record_directory_ancestors(filesystem_directories, relative_directory)

    index_path = resolved_install_root / "data.tpi"
    data_path = resolved_install_root / "data.tpd"
    if index_path.exists() and data_path.exists():
        for entry in build_netdragon_entry_lookup(index_path).values():
            parent_directory = _frame_directory(entry.path)
            if parent_directory != ".":
                _record_directory_ancestors(package_directories, parent_directory)

    all_directories = dict(package_directories)
    all_directories.update(filesystem_directories)
    children_by_parent: dict[str, list[str]] = {}
    directories_by_basename: dict[str, list[str]] = {}
    directories_by_stem: dict[str, list[str]] = {}
    directory_filenames: dict[str, set[str]] = {}
    directory_filename_stems: dict[str, set[str]] = {}

    if data_root.is_dir():
        for file_path in data_root.rglob("*"):
            if not file_path.is_file():
                continue
            relative_path = relative_posix(file_path, resolved_install_root)
            parent_directory = normalize_netdragon_path(_frame_directory(relative_path))
            if parent_directory and parent_directory != ".":
                directory_filenames.setdefault(parent_directory, set()).add(file_path.name.lower())
                directory_filename_stems.setdefault(parent_directory, set()).add(_normalize_filename_stem(file_path.name))

    if index_path.exists() and data_path.exists():
        for entry in build_netdragon_entry_lookup(index_path).values():
            parent_directory = normalize_netdragon_path(_frame_directory(entry.path))
            if not parent_directory or parent_directory == ".":
                continue
            entry_name = Path(entry.path.replace("\\", "/")).name
            directory_filenames.setdefault(parent_directory, set()).add(entry_name.lower())
            directory_filename_stems.setdefault(parent_directory, set()).add(_normalize_filename_stem(entry_name))

    filename_directory_frequency = Counter[str]()
    filename_stem_directory_frequency = Counter[str]()
    for names in directory_filenames.values():
        for name in names:
            filename_directory_frequency[name] += 1
    for stems in directory_filename_stems.values():
        for stem in stems:
            filename_stem_directory_frequency[stem] += 1

    for normalized in sorted(all_directories):
        parent = _parent_directory(normalized)
        if parent is not None:
            children_by_parent.setdefault(parent, []).append(normalized)
        directories_by_basename.setdefault(normalized.rsplit("/", 1)[-1], []).append(normalized)
        directories_by_stem.setdefault(_normalize_directory_leaf_stem(normalized), []).append(normalized)

    return {
        "filesystem_directories": filesystem_directories,
        "package_directories": package_directories,
        "all_directories": all_directories,
        "all_directory_keys": tuple(sorted(all_directories)),
        "children_by_parent": {
            parent: tuple(children)
            for parent, children in children_by_parent.items()
        },
        "directories_by_basename": {
            basename: tuple(children)
            for basename, children in directories_by_basename.items()
        },
        "directories_by_stem": {
            stem: tuple(children)
            for stem, children in directories_by_stem.items()
        },
        "directory_filenames": {
            directory: tuple(sorted(names))
            for directory, names in directory_filenames.items()
        },
        "directory_filename_stems": {
            directory: tuple(sorted(stems))
            for directory, stems in directory_filename_stems.items()
        },
        "filename_directory_frequency": dict(filename_directory_frequency),
        "filename_stem_directory_frequency": dict(filename_stem_directory_frequency),
    }


def _record_directory_ancestors(directory_map: dict[str, str], directory: str) -> None:
    for candidate in _iter_directory_ancestors(directory):
        normalized = normalize_netdragon_path(candidate)
        if normalized and normalized not in directory_map:
            directory_map[normalized] = candidate


def _iter_directory_ancestors(directory: str) -> list[str]:
    display = directory.replace("\\", "/").strip("/")
    if not display or display == ".":
        return []

    parts = [part for part in display.split("/") if part]
    return ["/".join(parts[:index]) for index in range(1, len(parts) + 1)]


def _parent_directory(directory: str) -> str | None:
    if "/" not in directory:
        return None
    return directory.rsplit("/", 1)[0]


def _path_prefix_depth(left: str, right: str) -> int:
    left_parts = [part for part in left.split("/") if part]
    right_parts = [part for part in right.split("/") if part]
    depth = 0
    for left_part, right_part in zip(left_parts, right_parts):
        if left_part != right_part:
            break
        depth += 1
    return depth


def _nearest_existing_parent(directory: str, all_directories: dict[str, str]) -> str | None:
    current = directory
    while True:
        current = _parent_directory(current)
        if current is None:
            return None
        if current in all_directories:
            return current


def _is_same_or_ancestor_directory(candidate: str, target: str) -> bool:
    return candidate == target or target.startswith(f"{candidate}/")


def _display_directory_samples(
    candidates: tuple[str, ...] | list[str],
    all_directories: dict[str, str],
    *,
    exclude: set[str],
) -> list[str]:
    sample: list[str] = []
    seen: set[str] = set()

    for candidate in candidates:
        if candidate in exclude:
            continue
        display = all_directories.get(candidate)
        if not display or display in seen:
            continue
        seen.add(display)
        sample.append(display)
        if len(sample) >= MAX_HINT_ITEMS:
            break

    return sample


def _resolve_conquer_package_resource(resource_path: str, *, install_root: Path | None) -> dict[str, object] | None:
    package_entry = _find_conquer_package_entry(resource_path, install_root=install_root)
    if package_entry is None:
        return None

    index_path, data_path, entry = package_entry
    payload = {
        "resource_kind": Path(resource_path).suffix.lower().lstrip(".") or "<none>",
        "size_bytes": entry.decoded_size_bytes or entry.stored_size_bytes,
        "signature": "<package>",
        "package_entry": {
            "index_path": str(index_path),
            "data_path": str(data_path),
            "path": entry.path,
            "method": entry.method,
            "stored_size_bytes": entry.stored_size_bytes,
            "decoded_size_bytes": entry.decoded_size_bytes,
            "offset_bytes": entry.offset_bytes,
        },
    }

    try:
        decoded_bytes, _ = read_netdragon_entry_bytes(data_path, entry)
    except ValueError:
        return payload

    if decoded_bytes:
        payload["size_bytes"] = len(decoded_bytes)
        payload["signature"] = decoded_bytes[:4].decode("ascii", errors="replace")
        if decoded_bytes.startswith(b"DDS "):
            try:
                payload["dds"] = parse_dds_bytes(decoded_bytes)
            except ValueError:
                payload["dds_error"] = "invalid-dds-header"

    return payload


def _find_conquer_package_entry(
    resource_path: str,
    *,
    install_root: Path | None,
) -> tuple[Path, Path, NetDragonEntry] | None:
    if install_root is None:
        return None

    index_path = install_root / "data.tpi"
    data_path = install_root / "data.tpd"
    if not index_path.exists() or not data_path.exists():
        return None

    entry = build_netdragon_entry_lookup(index_path).get(normalize_netdragon_path(resource_path))
    if entry is None:
        return None
    return index_path, data_path, entry
