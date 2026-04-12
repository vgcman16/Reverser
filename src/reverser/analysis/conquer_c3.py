from __future__ import annotations

import math
import re
import struct
from collections import Counter
from pathlib import Path


CONQUER_C3_MAGIC = b"MAXFILE C3 00001"
MAX_SAMPLE_ITEMS = 12
ASCII_STRING_PATTERN = re.compile(rb"[ -~]{4,}")
PATH_REFERENCE_SUFFIXES = (".tga", ".dds", ".c3", ".ani", ".bmp", ".png", ".jpg", ".jpeg")
PLAUSIBLE_PATH_PATTERN = re.compile(r"^[A-Za-z0-9_ ./\\:\-\(\)\[\]]+$")
KNOWN_C3_REFERENCE_FILES = {
    "3deffectobj.ini": "3deffectobj",
    "3dmotion.ini": "3dmotion",
}
MAX_ALIAS_CANDIDATES = 5
TOP_TAG_ROLE_HINTS = {
    "CAME": "camera",
    "MOTI": "motion",
    "PHY4": "mesh-or-model",
    "PTC3": "particle",
    "PTCL": "particle",
    "SHAP": "shape",
    "SMOT": "motion",
}
CHUNK_ROLE_HINTS = {
    "CAME": "camera",
    "MOTI": "motion",
    "SMOT": "motion",
    "PHY4": "mesh-or-model",
    "PTC3": "particle",
    "PTCL": "particle",
    "SHAP": "shape",
    "XKEY": "keyframe",
    "YKEY": "keyframe",
    "ZKEY": "keyframe",
    "KKEY": "keyframe",
    "OKEY": "keyframe",
    "RKEY": "keyframe",
}
KEYFRAME_TAGS = {"XKEY", "YKEY", "ZKEY", "KKEY", "OKEY", "RKEY"}
CHUNK_SIGNATURE_LIMIT = 6
PACKAGE_PROFILE_SAMPLE_LIMIT = 6
KNOWN_C3_CHUNK_TAGS = set(CHUNK_ROLE_HINTS)
UNKNOWN_CHUNK_SIZE_SAMPLE_LIMIT = 6
UNKNOWN_CHUNK_CLUSTER_SIZE_TOLERANCE = 64
UNKNOWN_CHUNK_PREFIX_SAMPLE_LIMIT = 4
UNKNOWN_CHUNK_FLOAT_WORD_SAMPLE_LIMIT = 32


def looks_like_conquer_c3_bytes(data: bytes) -> bool:
    return data.startswith(CONQUER_C3_MAGIC)


def looks_like_conquer_c3_file(path: Path) -> bool:
    if not path.is_file():
        return False
    with path.open("rb") as handle:
        return looks_like_conquer_c3_bytes(handle.read(len(CONQUER_C3_MAGIC)))


def parse_conquer_c3_file(path: Path) -> dict[str, object]:
    return parse_conquer_c3_bytes(path.read_bytes(), source_path=path)


def find_conquer_c3_install_root(target: Path) -> Path | None:
    search_start = target if target.is_dir() else target.parent

    for candidate in [search_start, *search_start.parents]:
        if _has_conquer_c3_artifacts(candidate):
            return candidate
        if candidate.name.lower() == "ini" and _has_known_c3_reference_files(candidate):
            return candidate.parent

    return None


def summarize_conquer_c3_install(target: Path, *, install_root: Path | None = None) -> dict[str, object]:
    resolved_install_root = install_root or find_conquer_c3_install_root(target)
    if resolved_install_root is None:
        raise FileNotFoundError(f"No Conquer C3 install root was found for {target}")

    reference_files = _find_conquer_c3_reference_files(resolved_install_root)
    package_catalog = build_conquer_c3_package_catalog(resolved_install_root)

    reference_rows: list[dict[str, str | int]] = []
    reference_summaries: list[dict[str, object]] = []
    normalized_to_files: dict[str, set[str]] = {}
    normalized_to_path: dict[str, str] = {}

    for reference_path in reference_files:
        payload, rows = _parse_conquer_c3_reference_file_internal(reference_path)
        _attach_conquer_c3_reference_resolution(payload, rows=rows, package_catalog=package_catalog)
        reference_summaries.append(
            {
                "path": _relative_posix(reference_path, resolved_install_root),
                "reference_file_kind": payload["reference_file_kind"],
                "entry_count": payload["entry_count"],
                "unique_path_count": payload["unique_path_count"],
                "duplicate_path_count": payload["duplicate_path_count"],
                "resolved_unique_path_count": payload.get("resolved_unique_path_count"),
                "missing_unique_path_count": payload.get("missing_unique_path_count"),
                "top_families": payload["top_families"],
                "top_branches": payload["top_branches"],
            }
        )
        reference_rows.extend(rows)
        for row in rows:
            normalized = str(row["normalized_path"])
            normalized_to_files.setdefault(normalized, set()).add(str(payload["reference_file_kind"]))
            normalized_to_path.setdefault(normalized, str(row["path"]))

    payload = _build_conquer_c3_reference_payload(
        reference_rows,
        path=target,
        encoding=None,
        file_size_bytes=None,
        scope="install",
        resource_kind="c3-install",
        reference_file_kind=None,
    )
    _attach_conquer_c3_reference_resolution(payload, rows=reference_rows, package_catalog=package_catalog)

    cross_file_overlap_sample = [
        {
            "path": normalized_to_path[normalized],
            "reference_file_count": len(file_kinds),
            "reference_files": sorted(file_kinds),
        }
        for normalized, file_kinds in sorted(
            normalized_to_files.items(),
            key=lambda item: (-len(item[1]), item[0]),
        )
        if len(file_kinds) > 1
    ][:MAX_SAMPLE_ITEMS]

    payload.update(
        {
            "format": "conquer-online-c3",
            "scope": "install",
            "resource_kind": "c3-install",
            "analyzed_path": str(target),
            "install_root": str(resolved_install_root),
            "reference_file_count": len(reference_files),
            "reference_files": reference_summaries,
            "cross_file_overlap_count": sum(1 for file_kinds in normalized_to_files.values() if len(file_kinds) > 1),
            "cross_file_overlap_sample": cross_file_overlap_sample,
        }
    )
    return payload


def parse_conquer_c3_reference_file(path: Path, *, install_root: Path | None = None) -> dict[str, object]:
    payload, rows = _parse_conquer_c3_reference_file_internal(path)
    resolved_install_root = install_root or find_conquer_c3_install_root(path)
    package_catalog = build_conquer_c3_package_catalog(resolved_install_root) if resolved_install_root else None
    _attach_conquer_c3_reference_resolution(payload, rows=rows, package_catalog=package_catalog)
    payload["install_root"] = str(resolved_install_root) if resolved_install_root is not None else None
    return payload


def parse_conquer_c3_bytes(data: bytes, *, source_path: str | Path | None = None) -> dict[str, object]:
    if not looks_like_conquer_c3_bytes(data):
        raise ValueError("Not a Conquer C3 payload.")

    top_tag = _decode_ascii_tag(data[16:20]) if len(data) >= 20 else None
    declared_payload_size = _read_u32le(data, 20)
    header_value_0x18 = _read_u32le(data, 24)
    object_name = _extract_c3_object_name(data, header_value_0x18)
    ascii_strings = _extract_ascii_strings(data)
    path_hint_sample = _extract_path_hints(ascii_strings)
    texture_reference_sample = [
        item
        for item in path_hint_sample
        if any(item.lower().endswith(suffix) for suffix in PATH_REFERENCE_SUFFIXES)
    ][:MAX_SAMPLE_ITEMS]
    chunk_headers = _scan_c3_chunk_headers(data)
    chunk_headers = _annotate_c3_chunk_headers(chunk_headers)
    chunk_tag_counts = Counter(item["tag"] for item in chunk_headers)
    chunk_tag_sequence = [str(item["tag"]) for item in chunk_headers[:MAX_SAMPLE_ITEMS]]
    chunk_signature = _build_chunk_signature(chunk_headers)
    unknown_chunk_tag_counts = _build_unknown_chunk_tag_counts(chunk_headers)
    unknown_chunk_tag_profiles = _build_unknown_chunk_tag_profiles(
        data,
        chunk_headers,
        chunk_tag_counts=chunk_tag_counts,
    )
    keyframe_tag_counts = {
        tag: count
        for tag, count in chunk_tag_counts.items()
        if tag in KEYFRAME_TAGS
    }

    return {
        "format": "conquer-online-c3",
        "resource_kind": "c3",
        "path": str(source_path) if source_path is not None else None,
        "file_size_bytes": len(data),
        "magic": CONQUER_C3_MAGIC.decode("ascii"),
        "top_tag": top_tag,
        "top_tag_role": _classify_conquer_c3_top_tag(top_tag),
        "declared_payload_size": declared_payload_size,
        "header_value_0x18": header_value_0x18,
        "object_name": object_name,
        "ascii_string_sample": ascii_strings[:MAX_SAMPLE_ITEMS],
        "path_hint_sample": path_hint_sample[:MAX_SAMPLE_ITEMS],
        "texture_reference_sample": texture_reference_sample,
        "structural_role_hints": _derive_structural_role_hints(top_tag=top_tag, chunk_headers=chunk_headers),
        "chunk_signature": chunk_signature,
        "chunk_tag_sequence_sample": chunk_tag_sequence,
        "unknown_chunk_tags": unknown_chunk_tag_counts,
        "unknown_chunk_tag_profiles": unknown_chunk_tag_profiles,
        "keyframe_tag_counts": [
            {"tag": tag, "count": count}
            for tag, count in sorted(keyframe_tag_counts.items(), key=lambda item: (-item[1], item[0]))[:MAX_SAMPLE_ITEMS]
        ],
        "chunk_tag_counts": [
            {"tag": tag, "count": count}
            for tag, count in chunk_tag_counts.most_common(MAX_SAMPLE_ITEMS)
        ],
        "chunk_header_sample": chunk_headers[:MAX_SAMPLE_ITEMS],
        "header_head_hex": data[:64].hex(),
    }


def build_conquer_c3_package_catalog(install_root: Path) -> dict[str, object]:
    package_infos: list[dict[str, object]] = []
    path_sources: dict[str, list[dict[str, object]]] = {}

    for stem in ("c3", "c31"):
        index_path = install_root / f"{stem}.tpi"
        data_path = install_root / f"{stem}.tpd"
        if not index_path.is_file() or not data_path.is_file():
            continue

        from reverser.analysis.netdragon import build_netdragon_entry_lookup

        lookup = build_netdragon_entry_lookup(index_path)
        c3_entries = {
            normalized_path: entry
            for normalized_path, entry in lookup.items()
            if entry.extension == ".c3"
        }
        package_infos.append(
            {
                "package": stem,
                "index_path": str(index_path),
                "data_path": str(data_path),
                "c3_entry_count": len(c3_entries),
                "top_families": _top_conquer_c3_path_buckets(c3_entries, key="family"),
                "top_branches": _top_conquer_c3_path_buckets(c3_entries, key="branch"),
            }
        )
        for normalized_path, entry in c3_entries.items():
            path_sources.setdefault(normalized_path, []).append(
                {
                    "package": stem,
                    "index_path": index_path,
                    "data_path": data_path,
                    "entry": entry,
                }
            )

    return {
        "status": "ok" if package_infos else "missing-packages",
        "install_root": str(install_root),
        "packages": package_infos,
        "path_sources": path_sources,
    }


def _read_u32le(data: bytes, offset: int) -> int | None:
    if offset + 4 > len(data):
        return None
    return int.from_bytes(data[offset : offset + 4], "little")


def _decode_ascii_tag(raw: bytes) -> str | None:
    if len(raw) != 4:
        return None
    if not all(48 <= byte <= 57 or 65 <= byte <= 90 for byte in raw):
        return None
    return raw.decode("ascii")


def _extract_c3_object_name(data: bytes, header_value_0x18: int | None) -> str | None:
    if not isinstance(header_value_0x18, int) or header_value_0x18 <= 0 or header_value_0x18 > 128:
        return None
    start = 28
    end = start + header_value_0x18
    if end > len(data):
        return None
    candidate = data[start:end].split(b"\x00", 1)[0]
    if not candidate:
        return None
    if any(byte < 32 or byte > 126 for byte in candidate):
        return None
    decoded = candidate.decode("ascii", errors="ignore").strip()
    return decoded or None


def _extract_ascii_strings(data: bytes) -> list[str]:
    strings: list[str] = []
    seen: set[str] = set()
    for match in ASCII_STRING_PATTERN.finditer(data):
        value = match.group().decode("latin1", errors="ignore").strip()
        if not value or value in seen:
            continue
        seen.add(value)
        strings.append(value)
    return strings


def _extract_path_hints(strings: list[str]) -> list[str]:
    hints: list[str] = []
    seen: set[str] = set()

    def add_hint(value: str) -> None:
        normalized = value.replace("\\\\", "\\").strip()
        if not normalized or normalized in seen or not _is_plausible_path_hint(normalized):
            return
        seen.add(normalized)
        hints.append(normalized)

    for index, value in enumerate(strings):
        lower_value = value.lower()
        is_path_like = "\\" in value or "/" in value or any(lower_value.endswith(suffix) for suffix in PATH_REFERENCE_SUFFIXES)
        if is_path_like:
            add_hint(value)

        if index + 1 >= len(strings):
            continue
        next_value = strings[index + 1]
        lower_next = next_value.lower()
        if not ("\\" in value or "/" in value):
            continue
        if not any(lower_next.endswith(suffix) for suffix in PATH_REFERENCE_SUFFIXES):
            continue
        joined = value.rstrip("\\/") + "/" + next_value.lstrip("\\/")
        add_hint(joined)

    return hints


def _scan_c3_chunk_headers(data: bytes) -> list[dict[str, object]]:
    samples: list[dict[str, object]] = []
    seen_offsets: set[int] = set()
    for offset in range(16, max(16, len(data) - 8), 4):
        tag = _decode_ascii_tag(data[offset : offset + 4])
        if tag is None or offset in seen_offsets:
            continue
        declared_size = _read_u32le(data, offset + 4)
        if not isinstance(declared_size, int) or declared_size <= 0:
            continue
        if declared_size > len(data):
            continue
        seen_offsets.add(offset)
        samples.append(
            {
                "offset_bytes": offset,
                "tag": tag,
                "declared_size": declared_size,
            }
        )
    return samples


def _annotate_c3_chunk_headers(chunk_headers: list[dict[str, object]]) -> list[dict[str, object]]:
    annotated: list[dict[str, object]] = []

    for index, header in enumerate(chunk_headers):
        current = dict(header)
        offset = int(current["offset_bytes"])
        parent: dict[str, object] | None = None
        for candidate in annotated:
            candidate_offset = int(candidate["offset_bytes"])
            candidate_end = candidate_offset + 8 + int(candidate["declared_size"])
            if candidate_offset + 8 <= offset < candidate_end:
                parent = candidate

        current["parent_tag"] = parent["tag"] if parent is not None else None
        current["parent_offset_bytes"] = parent["offset_bytes"] if parent is not None else None
        current["nesting_depth"] = int(parent.get("nesting_depth", 0)) + 1 if parent is not None else 0

        preceding_known = next(
            (candidate for candidate in reversed(annotated) if str(candidate["tag"]) in KNOWN_C3_CHUNK_TAGS),
            None,
        )
        following_known = next(
            (
                candidate
                for candidate in chunk_headers[index + 1 :]
                if str(candidate["tag"]) in KNOWN_C3_CHUNK_TAGS
            ),
            None,
        )
        current["preceding_known_tag"] = preceding_known["tag"] if preceding_known is not None else None
        current["following_known_tag"] = following_known["tag"] if following_known is not None else None
        annotated.append(current)

    return annotated


def _has_conquer_c3_artifacts(candidate: Path) -> bool:
    return _has_known_c3_reference_files(candidate / "ini") or any(
        (candidate / f"{stem}.tpi").is_file() or (candidate / f"{stem}.tpd").is_file()
        for stem in ("c3", "c31")
    )


def _has_known_c3_reference_files(ini_dir: Path) -> bool:
    return any(_find_casefold_child(ini_dir, name) is not None for name in KNOWN_C3_REFERENCE_FILES)


def _find_conquer_c3_reference_files(install_root: Path) -> list[Path]:
    ini_dir = install_root / "ini"
    reference_files: list[Path] = []
    for filename in KNOWN_C3_REFERENCE_FILES:
        candidate = _find_casefold_child(ini_dir, filename)
        if candidate is not None:
            reference_files.append(candidate)
    return reference_files


def _find_casefold_child(directory: Path, target_name: str) -> Path | None:
    if not directory.is_dir():
        return None
    lowered_target = target_name.lower()
    for child in directory.iterdir():
        if child.name.lower() == lowered_target:
            return child
    return None


def _parse_conquer_c3_reference_file_internal(path: Path) -> tuple[dict[str, object], list[dict[str, str | int]]]:
    data = path.read_bytes()
    text, encoding = _decode_conquer_c3_reference_text(data)
    reference_file_kind = KNOWN_C3_REFERENCE_FILES.get(path.name.lower(), "c3-reference-map")
    rows: list[dict[str, str | int]] = []
    ignored_line_count = 0
    non_c3_value_count = 0

    for raw_line in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = raw_line.strip()
        if not line or line.startswith("//") or line.startswith(";") or line.startswith("#"):
            continue
        if "=" not in line:
            ignored_line_count += 1
            continue

        key, value = line.split("=", 1)
        key = key.strip()
        raw_path = value.strip().strip("\"'")
        if not raw_path:
            continue

        normalized_path = raw_path.replace("\\", "/").strip().lstrip("/")
        if not normalized_path.lower().endswith(".c3"):
            non_c3_value_count += 1
            continue

        family, branch = _conquer_c3_path_family(normalized_path)
        rows.append(
            {
                "key": key,
                "path": normalized_path,
                "normalized_path": normalized_path.lower(),
                "family": family,
                "branch": branch,
                "reference_file_kind": reference_file_kind,
            }
        )

    payload = _build_conquer_c3_reference_payload(
        rows,
        path=path,
        encoding=encoding,
        file_size_bytes=len(data),
        scope="file",
        resource_kind="c3-reference-map",
        reference_file_kind=reference_file_kind,
    )
    payload["ignored_line_count"] = ignored_line_count
    payload["non_c3_value_count"] = non_c3_value_count
    return payload, rows


def _build_conquer_c3_reference_payload(
    rows: list[dict[str, str | int]],
    *,
    path: Path | str,
    encoding: str | None,
    file_size_bytes: int | None,
    scope: str,
    resource_kind: str,
    reference_file_kind: str | None,
) -> dict[str, object]:
    normalized_counts: Counter[str] = Counter()
    family_counts: Counter[str] = Counter()
    branch_counts: Counter[str] = Counter()
    path_samples: dict[str, str] = {}
    key_samples: dict[str, list[str]] = {}

    for row in rows:
        normalized_path = str(row["normalized_path"])
        normalized_counts[normalized_path] += 1
        family_counts[str(row["family"])] += 1
        branch_counts[str(row["branch"])] += 1
        path_samples.setdefault(normalized_path, str(row["path"]))
        key_samples.setdefault(normalized_path, []).append(str(row["key"]))

    duplicate_path_sample = [
        {
            "path": path_samples[normalized_path],
            "count": count,
            "key_sample": key_samples[normalized_path][:MAX_SAMPLE_ITEMS],
        }
        for normalized_path, count in normalized_counts.most_common()
        if count > 1
    ][:MAX_SAMPLE_ITEMS]

    family_coverage = _build_coverage_sample(rows, field="family")
    branch_coverage = _build_coverage_sample(rows, field="branch")

    payload = {
        "format": "conquer-online-c3",
        "scope": scope,
        "resource_kind": resource_kind,
        "path": str(path),
        "file_size_bytes": file_size_bytes,
        "text_encoding": encoding,
        "entry_count": len(rows),
        "unique_path_count": len(normalized_counts),
        "duplicate_path_count": sum(1 for count in normalized_counts.values() if count > 1),
        "reference_sample": [
            {
                "key": str(row["key"]),
                "path": str(row["path"]),
            }
            for row in rows[:MAX_SAMPLE_ITEMS]
        ],
        "top_referenced_paths": [
            {
                "path": path_samples[normalized_path],
                "count": count,
            }
            for normalized_path, count in normalized_counts.most_common(MAX_SAMPLE_ITEMS)
        ],
        "duplicate_path_sample": duplicate_path_sample,
        "top_families": [
            {"family": family, "count": count}
            for family, count in family_counts.most_common(MAX_SAMPLE_ITEMS)
        ],
        "top_branches": [
            {"branch": branch, "count": count}
            for branch, count in branch_counts.most_common(MAX_SAMPLE_ITEMS)
        ],
        "family_reference_coverage_sample": family_coverage,
        "branch_reference_coverage_sample": branch_coverage,
    }
    if reference_file_kind is not None:
        payload["reference_file_kind"] = reference_file_kind
    return payload


def _attach_conquer_c3_reference_resolution(
    payload: dict[str, object],
    *,
    rows: list[dict[str, str | int]],
    package_catalog: dict[str, object] | None,
) -> None:
    normalized_counts = Counter(str(row["normalized_path"]) for row in rows)
    normalized_paths_in_order = list(dict.fromkeys(str(row["normalized_path"]) for row in rows))
    normalized_to_path = {
        str(row["normalized_path"]): str(row["path"])
        for row in rows
    }
    normalized_to_row = {
        str(row["normalized_path"]): row
        for row in rows
    }

    if not package_catalog or package_catalog.get("status") != "ok":
        payload.update(
            {
                "package_resolution_status": "missing-packages",
                "resolution_reference_counts": [{"status": "unverified", "count": len(rows)}] if rows else [],
                "resolution_unique_path_counts": [{"status": "unverified", "count": len(normalized_counts)}] if normalized_counts else [],
                "resolved_reference_count": 0,
                "resolved_unique_path_count": 0,
                "missing_reference_count": len(rows),
                "missing_unique_path_count": len(normalized_counts),
                "missing_path_sample": [normalized_to_path[path] for path in normalized_paths_in_order[:MAX_SAMPLE_ITEMS]],
                "resolved_c3_sample": [],
                "top_resolved_tags": [],
                "package_inventory": [],
                "family_resolution_coverage_sample": [],
                "branch_resolution_coverage_sample": [],
                "alias_resolved_reference_count": 0,
                "alias_resolved_unique_path_count": 0,
                "branch_alias_resolved_unique_path_count": 0,
                "family_alias_resolved_unique_path_count": 0,
                "effective_resolved_reference_count": 0,
                "effective_missing_reference_count": len(rows),
                "effective_reference_coverage_ratio": 0.0 if rows else None,
                "effective_resolved_unique_path_count": 0,
                "effective_missing_unique_path_count": len(normalized_counts),
                "effective_unique_path_coverage_ratio": 0.0 if normalized_counts else None,
                "alias_resolved_path_sample": [],
                "missing_family_alias_candidate_sample": [],
                "missing_branch_alias_candidate_sample": [],
                "validated_missing_family_alias_candidate_sample": [],
                "validated_missing_branch_alias_candidate_sample": [],
                "effective_family_resolution_coverage_sample": [],
                "effective_branch_resolution_coverage_sample": [],
                "residual_missing_family_sample": [],
                "residual_missing_branch_sample": [],
                "lowest_effective_family_coverage_sample": [],
                "lowest_effective_branch_coverage_sample": [],
                "highest_family_alias_gain_sample": [],
                "highest_branch_alias_gain_sample": [],
                "residual_missing_family_package_profile_sample": [],
                "residual_missing_branch_package_profile_sample": [],
                "residual_missing_branch_unknown_chunk_archetype_sample": [],
            }
        )
        return

    reference_status_counts: Counter[str] = Counter()
    unique_status_counts: Counter[str] = Counter()
    missing_path_sample: list[str] = []
    resolved_c3_sample: list[dict[str, object]] = []
    top_resolved_tags: Counter[str] = Counter()
    referenced_paths_by_package: dict[str, set[str]] = {
        str(package_info["package"]): set()
        for package_info in package_catalog["packages"]
        if isinstance(package_info, dict)
    }
    family_status_counts: dict[str, Counter[str]] = {}
    branch_status_counts: dict[str, Counter[str]] = {}
    missing_family_files: dict[str, set[str]] = {}
    missing_branch_files: dict[str, set[str]] = {}

    for normalized_path in normalized_paths_in_order:
        sources = package_catalog["path_sources"].get(normalized_path, [])
        if not sources:
            status = "missing"
            if len(missing_path_sample) < MAX_SAMPLE_ITEMS:
                missing_path_sample.append(normalized_to_path[normalized_path])
        elif len(sources) == 1:
            status = str(sources[0]["package"])
        else:
            status = "multiple"

        unique_status_counts[status] += 1
        reference_status_counts[status] += normalized_counts[normalized_path]
        row = normalized_to_row[normalized_path]
        family = str(row["family"])
        branch = str(row["branch"])
        family_status_counts.setdefault(family, Counter())[status] += 1
        branch_status_counts.setdefault(branch, Counter())[status] += 1
        if status == "missing":
            filename = normalized_path.split("/")[-1]
            missing_family_files.setdefault(family, set()).add(filename)
            missing_branch_files.setdefault(branch, set()).add(filename)

        for source in sources:
            referenced_paths_by_package.setdefault(str(source["package"]), set()).add(normalized_path)

        if not sources or len(resolved_c3_sample) >= MAX_SAMPLE_ITEMS:
            continue

        summary = _summarize_resolved_c3_source(sources[0])
        if summary is None:
            continue
        top_tag = summary.get("top_tag")
        if isinstance(top_tag, str) and top_tag:
            top_resolved_tags[top_tag] += 1
        resolved_c3_sample.append(summary)

    package_inventory = []
    for package_info in package_catalog["packages"]:
        package_name = str(package_info["package"])
        referenced_unique_count = len(referenced_paths_by_package.get(package_name, set()))
        package_inventory.append(
            {
                **package_info,
                "referenced_unique_c3_count": referenced_unique_count,
                "unreferenced_unique_c3_count": max(0, int(package_info["c3_entry_count"]) - referenced_unique_count),
            }
        )

    package_family_files, package_branch_files, family_packages, branch_packages = _build_package_filename_buckets(package_catalog)

    all_family_alias_candidates = _build_missing_alias_candidate_sample(
        missing_files_by_bucket=missing_family_files,
        status_counts=family_status_counts,
        candidate_files_by_bucket=package_family_files,
        candidate_packages=family_packages,
        field="family",
        limit=None,
    )
    all_branch_alias_candidates = _build_missing_alias_candidate_sample(
        missing_files_by_bucket=missing_branch_files,
        status_counts=branch_status_counts,
        candidate_files_by_bucket=package_branch_files,
        candidate_packages=branch_packages,
        field="branch",
        limit=None,
    )
    validated_family_alias_candidates = _validated_alias_candidate_sample(all_family_alias_candidates, field="family")
    validated_branch_alias_candidates = _validated_alias_candidate_sample(all_branch_alias_candidates, field="branch")
    validated_family_alias_map = {item["family"]: item for item in validated_family_alias_candidates}
    validated_branch_alias_map = {item["branch"]: item for item in validated_branch_alias_candidates}
    effective_family_status_counts = {
        family: Counter(counts)
        for family, counts in family_status_counts.items()
    }
    effective_branch_status_counts = {
        branch: Counter(counts)
        for branch, counts in branch_status_counts.items()
    }

    alias_resolved_reference_count = 0
    alias_resolved_unique_path_count = 0
    branch_alias_resolved_unique_path_count = 0
    family_alias_resolved_unique_path_count = 0
    alias_resolved_path_sample: list[dict[str, object]] = []

    for normalized_path in normalized_paths_in_order:
        if package_catalog["path_sources"].get(normalized_path):
            continue

        row = normalized_to_row[normalized_path]
        branch = str(row["branch"])
        family = str(row["family"])
        alias_bucket: dict[str, object] | None = None
        alias_type: str | None = None

        if branch in validated_branch_alias_map:
            alias_bucket = validated_branch_alias_map[branch]
            alias_type = "branch"
        elif family in validated_family_alias_map:
            alias_bucket = validated_family_alias_map[family]
            alias_type = "family"

        if alias_bucket is None or alias_type is None:
            continue

        candidate = alias_bucket["replacement_candidates"][0]
        alias_resolved_reference_count += normalized_counts[normalized_path]
        alias_resolved_unique_path_count += 1
        if alias_type == "branch":
            branch_alias_resolved_unique_path_count += 1
        else:
            family_alias_resolved_unique_path_count += 1
        _promote_counter_status(effective_family_status_counts[family], f"alias-{alias_type}")
        _promote_counter_status(effective_branch_status_counts[branch], f"alias-{alias_type}")

        if len(alias_resolved_path_sample) < MAX_SAMPLE_ITEMS:
            alias_resolved_path_sample.append(
                {
                    "path": normalized_to_path[normalized_path],
                    "alias_type": alias_type,
                    "candidate_bucket": candidate[alias_type],
                    "overlap_ratio": candidate.get("overlap_ratio"),
                    "same_leaf_segment": candidate.get("same_leaf_segment"),
                    "same_numeric_family_shape": candidate.get("same_numeric_family_shape"),
                }
            )

    resolved_reference_count = len(rows) - reference_status_counts.get("missing", 0)
    resolved_unique_path_count = len(normalized_counts) - unique_status_counts.get("missing", 0)
    effective_resolved_reference_count = resolved_reference_count + alias_resolved_reference_count
    effective_missing_reference_count = max(0, reference_status_counts.get("missing", 0) - alias_resolved_reference_count)
    effective_resolved_unique_path_count = resolved_unique_path_count + alias_resolved_unique_path_count
    effective_missing_unique_path_count = max(0, unique_status_counts.get("missing", 0) - alias_resolved_unique_path_count)
    residual_missing_family_sample = _build_residual_missing_sample(
        effective_family_status_counts,
        field="family",
    )
    residual_missing_branch_sample = _build_residual_missing_sample(
        effective_branch_status_counts,
        field="branch",
    )
    residual_missing_family_package_profile_sample = _build_package_bucket_profile_sample(
        package_catalog,
        bucket_names=[str(item["family"]) for item in residual_missing_family_sample],
        field="family",
    )
    residual_missing_branch_package_profile_sample = _build_package_bucket_profile_sample(
        package_catalog,
        bucket_names=[str(item["branch"]) for item in residual_missing_branch_sample],
        field="branch",
    )

    payload.update(
        {
            "package_resolution_status": "ok",
            "resolution_reference_counts": [
                {"status": status, "count": count}
                for status, count in reference_status_counts.most_common(MAX_SAMPLE_ITEMS)
            ],
            "resolution_unique_path_counts": [
                {"status": status, "count": count}
                for status, count in unique_status_counts.most_common(MAX_SAMPLE_ITEMS)
            ],
            "resolved_reference_count": resolved_reference_count,
            "resolved_unique_path_count": resolved_unique_path_count,
            "missing_reference_count": reference_status_counts.get("missing", 0),
            "missing_unique_path_count": unique_status_counts.get("missing", 0),
            "missing_path_sample": missing_path_sample,
            "resolved_c3_sample": resolved_c3_sample,
            "top_resolved_tags": [
                {"tag": tag, "count": count}
                for tag, count in top_resolved_tags.most_common(MAX_SAMPLE_ITEMS)
            ],
            "package_inventory": package_inventory,
            "family_resolution_coverage_sample": _format_status_coverage_sample(family_status_counts, field="family"),
            "branch_resolution_coverage_sample": _format_status_coverage_sample(branch_status_counts, field="branch"),
            "alias_resolved_reference_count": alias_resolved_reference_count,
            "alias_resolved_unique_path_count": alias_resolved_unique_path_count,
            "branch_alias_resolved_unique_path_count": branch_alias_resolved_unique_path_count,
            "family_alias_resolved_unique_path_count": family_alias_resolved_unique_path_count,
            "effective_resolved_reference_count": effective_resolved_reference_count,
            "effective_missing_reference_count": effective_missing_reference_count,
            "effective_reference_coverage_ratio": round(effective_resolved_reference_count / len(rows), 4) if rows else None,
            "effective_resolved_unique_path_count": effective_resolved_unique_path_count,
            "effective_missing_unique_path_count": effective_missing_unique_path_count,
            "effective_unique_path_coverage_ratio": round(effective_resolved_unique_path_count / len(normalized_counts), 4) if normalized_counts else None,
            "alias_resolved_path_sample": alias_resolved_path_sample,
            "missing_family_alias_candidate_sample": all_family_alias_candidates[:MAX_SAMPLE_ITEMS],
            "missing_branch_alias_candidate_sample": all_branch_alias_candidates[:MAX_SAMPLE_ITEMS],
            "validated_missing_family_alias_candidate_sample": validated_family_alias_candidates[:MAX_SAMPLE_ITEMS],
            "validated_missing_branch_alias_candidate_sample": validated_branch_alias_candidates[:MAX_SAMPLE_ITEMS],
            "effective_family_resolution_coverage_sample": _format_status_coverage_sample(
                effective_family_status_counts,
                field="family",
            ),
            "effective_branch_resolution_coverage_sample": _format_status_coverage_sample(
                effective_branch_status_counts,
                field="branch",
            ),
            "residual_missing_family_sample": residual_missing_family_sample,
            "residual_missing_branch_sample": residual_missing_branch_sample,
            "lowest_effective_family_coverage_sample": _build_lowest_effective_coverage_sample(
                effective_family_status_counts,
                field="family",
            ),
            "lowest_effective_branch_coverage_sample": _build_lowest_effective_coverage_sample(
                effective_branch_status_counts,
                field="branch",
            ),
            "highest_family_alias_gain_sample": _build_alias_gain_sample(
                direct_status_counts=family_status_counts,
                effective_status_counts=effective_family_status_counts,
                field="family",
            ),
            "highest_branch_alias_gain_sample": _build_alias_gain_sample(
                direct_status_counts=branch_status_counts,
                effective_status_counts=effective_branch_status_counts,
                field="branch",
            ),
            "residual_missing_family_package_profile_sample": residual_missing_family_package_profile_sample,
            "residual_missing_branch_package_profile_sample": residual_missing_branch_package_profile_sample,
            "residual_missing_branch_unknown_chunk_archetype_sample": _build_unknown_chunk_archetype_rollup_sample(
                residual_missing_branch_package_profile_sample,
                field="branch",
            ),
        }
    )


def _summarize_resolved_c3_source(source: dict[str, object]) -> dict[str, object] | None:
    from reverser.analysis.netdragon import read_netdragon_entry_bytes

    entry = source.get("entry")
    data_path = source.get("data_path")
    if data_path is None or entry is None:
        return None

    try:
        decoded_bytes, decoded = read_netdragon_entry_bytes(Path(str(data_path)), entry)
    except (OSError, ValueError):
        return None

    try:
        summary = parse_conquer_c3_bytes(decoded_bytes, source_path=entry.path)
    except ValueError:
        return None

    return {
        "package": source["package"],
        "path": entry.path,
        "decoded": decoded,
        "top_tag": summary.get("top_tag"),
        "top_tag_role": summary.get("top_tag_role"),
        "object_name": summary.get("object_name"),
        "structural_role_hints": summary.get("structural_role_hints", []),
        "chunk_signature": summary.get("chunk_signature", []),
        "unknown_chunk_tags": summary.get("unknown_chunk_tags", []),
        "unknown_chunk_tag_profiles": summary.get("unknown_chunk_tag_profiles", []),
        "texture_reference_sample": summary.get("texture_reference_sample", []),
    }


def _decode_conquer_c3_reference_text(data: bytes) -> tuple[str, str]:
    for encoding in ("utf-8", "gbk", "gb18030"):
        try:
            return data.decode(encoding), encoding
        except UnicodeDecodeError:
            continue
    return data.decode("utf-8", errors="replace"), "utf-8-replace"


def _conquer_c3_path_family(path: str) -> tuple[str, str]:
    parts = [part for part in path.replace("\\", "/").split("/") if part]
    if not parts:
        return "<root>", "<root>"

    if parts[0].lower() in {"c3", "c31"}:
        parts = parts[1:]

    if not parts:
        return "<root>", "<root>"

    family = parts[0].lower()
    branch = "/".join(part.lower() for part in parts[:2])
    return family, branch


def _classify_conquer_c3_top_tag(top_tag: str | None) -> str | None:
    if not isinstance(top_tag, str):
        return None
    return TOP_TAG_ROLE_HINTS.get(top_tag)


def _derive_structural_role_hints(
    *,
    top_tag: str | None,
    chunk_headers: list[dict[str, object]],
) -> list[str]:
    roles: list[str] = []
    seen: set[str] = set()

    def add_role(role: str | None) -> None:
        if not isinstance(role, str) or not role or role in seen:
            return
        seen.add(role)
        roles.append(role)

    add_role(_classify_conquer_c3_top_tag(top_tag))
    for header in chunk_headers:
        add_role(CHUNK_ROLE_HINTS.get(str(header["tag"])))

    return roles


def _build_chunk_signature(chunk_headers: list[dict[str, object]]) -> list[str]:
    signature: list[str] = []
    seen: set[str] = set()
    for header in chunk_headers:
        tag = str(header["tag"])
        if tag in seen:
            continue
        seen.add(tag)
        signature.append(tag)
        if len(signature) >= CHUNK_SIGNATURE_LIMIT:
            break
    return signature


def _build_unknown_chunk_tag_counts(chunk_headers: list[dict[str, object]]) -> list[dict[str, object]]:
    counts: Counter[str] = Counter(
        str(header["tag"])
        for header in chunk_headers
        if str(header["tag"]) not in KNOWN_C3_CHUNK_TAGS
    )
    return [
        {"tag": tag, "count": count}
        for tag, count in counts.most_common(MAX_SAMPLE_ITEMS)
    ]


def _format_chunk_tag_counter(counter: Counter[str]) -> list[dict[str, object]]:
    return [
        {"tag": tag, "count": count}
        for tag, count in counter.most_common(MAX_SAMPLE_ITEMS)
    ]


def _format_chunk_pair_counter(counter: Counter[tuple[str, str]]) -> list[dict[str, object]]:
    return [
        {
            "preceding_tag": preceding_tag,
            "following_tag": following_tag,
            "count": count,
        }
        for (preceding_tag, following_tag), count in counter.most_common(MAX_SAMPLE_ITEMS)
    ]


def _derive_unknown_chunk_sequence_context_hints(
    *,
    parent_counts: Counter[str],
    preceding_counts: Counter[str],
    following_counts: Counter[str],
    between_counts: Counter[tuple[str, str]],
) -> list[str]:
    hints: list[str] = []
    seen: set[str] = set()

    def add_hint(value: str) -> None:
        if not value or value in seen:
            return
        seen.add(value)
        hints.append(value)

    for (preceding_tag, following_tag), _count in between_counts.most_common(MAX_SAMPLE_ITEMS):
        add_hint(f"between-{preceding_tag.lower()}-and-{following_tag.lower()}")
    for tag, _count in parent_counts.most_common(MAX_SAMPLE_ITEMS):
        add_hint(f"nested-under-{tag.lower()}")
    for tag, _count in preceding_counts.most_common(MAX_SAMPLE_ITEMS):
        add_hint(f"after-{tag.lower()}")
    for tag, _count in following_counts.most_common(MAX_SAMPLE_ITEMS):
        add_hint(f"before-{tag.lower()}")

    return hints[:MAX_SAMPLE_ITEMS]


def _context_role_slug_for_chunk_tag(tag: str | None) -> str | None:
    if not isinstance(tag, str) or not tag:
        return None
    role = CHUNK_ROLE_HINTS.get(tag)
    if role == "mesh-or-model":
        return "mesh"
    if role == "keyframe":
        return "keyframe"
    if role == "particle":
        return "particle"
    if role == "motion":
        return "motion"
    if role == "camera":
        return "camera"
    if role == "shape":
        return "shape"
    return None


def _derive_unknown_chunk_attachment_hints(
    *,
    parent_counts: Counter[str],
    preceding_counts: Counter[str],
    following_counts: Counter[str],
    between_counts: Counter[tuple[str, str]],
    layout_hints: list[str],
    tag_count: int,
) -> list[str]:
    hints: list[str] = []
    seen: set[str] = set()
    layout_set = set(layout_hints)

    def add_hint(value: str | None) -> None:
        if not isinstance(value, str) or not value or value in seen:
            return
        seen.add(value)
        hints.append(value)

    suffix = "family" if tag_count > 1 else "block"

    for (preceding_tag, following_tag), _count in between_counts.most_common(MAX_SAMPLE_ITEMS):
        preceding_role = _context_role_slug_for_chunk_tag(preceding_tag)
        following_role = _context_role_slug_for_chunk_tag(following_tag)
        if not preceding_role or not following_role:
            continue
        if {"small-block", "float-heavy-block"} <= layout_set:
            add_hint(f"{preceding_role}-to-{following_role}-control-{suffix}")
        if {"large-block", "float-heavy-block"} <= layout_set:
            add_hint(f"{preceding_role}-to-{following_role}-bulk-float-{suffix}")

    for parent_tag, _count in parent_counts.most_common(MAX_SAMPLE_ITEMS):
        parent_role = _context_role_slug_for_chunk_tag(parent_tag)
        if not parent_role:
            continue
        if {"small-block", "float-heavy-block"} <= layout_set:
            add_hint(f"{parent_role}-nested-control-{suffix}")
        if {"large-block", "float-heavy-block"} <= layout_set:
            add_hint(f"{parent_role}-nested-bulk-float-{suffix}")

    if not between_counts:
        for tag, _count in preceding_counts.most_common(MAX_SAMPLE_ITEMS):
            role = _context_role_slug_for_chunk_tag(tag)
            if not role:
                continue
            if {"small-block", "float-heavy-block"} <= layout_set:
                add_hint(f"{role}-postlude-control-{suffix}")
            if {"large-block", "float-heavy-block"} <= layout_set:
                add_hint(f"{role}-postlude-bulk-float-{suffix}")

        for tag, _count in following_counts.most_common(MAX_SAMPLE_ITEMS):
            role = _context_role_slug_for_chunk_tag(tag)
            if not role:
                continue
            if {"small-block", "float-heavy-block"} <= layout_set:
                add_hint(f"{role}-prelude-control-{suffix}")
            if {"large-block", "float-heavy-block"} <= layout_set:
                add_hint(f"{role}-prelude-bulk-float-{suffix}")

    return hints[:MAX_SAMPLE_ITEMS]


def _build_unknown_chunk_tag_profiles(
    data: bytes,
    chunk_headers: list[dict[str, object]],
    *,
    chunk_tag_counts: Counter[str],
) -> list[dict[str, object]]:
    size_by_tag: dict[str, list[int]] = {}
    zero_prefix_by_tag: dict[str, list[int]] = {}
    float_ratio_by_tag: dict[str, list[float]] = {}
    prefix_hex_by_tag: dict[str, list[str]] = {}
    parent_known_by_tag: dict[str, Counter[str]] = {}
    preceding_known_by_tag: dict[str, Counter[str]] = {}
    following_known_by_tag: dict[str, Counter[str]] = {}
    between_known_by_tag: dict[str, Counter[tuple[str, str]]] = {}
    for header in chunk_headers:
        tag = str(header["tag"])
        if tag in KNOWN_C3_CHUNK_TAGS:
            continue
        parent_tag = header.get("parent_tag")
        if isinstance(parent_tag, str) and parent_tag in KNOWN_C3_CHUNK_TAGS:
            parent_known_by_tag.setdefault(tag, Counter())[parent_tag] += 1
        preceding_tag = header.get("preceding_known_tag")
        if isinstance(preceding_tag, str) and preceding_tag in KNOWN_C3_CHUNK_TAGS:
            preceding_known_by_tag.setdefault(tag, Counter())[preceding_tag] += 1
        following_tag = header.get("following_known_tag")
        if isinstance(following_tag, str) and following_tag in KNOWN_C3_CHUNK_TAGS:
            following_known_by_tag.setdefault(tag, Counter())[following_tag] += 1
        if (
            isinstance(preceding_tag, str)
            and preceding_tag in KNOWN_C3_CHUNK_TAGS
            and isinstance(following_tag, str)
            and following_tag in KNOWN_C3_CHUNK_TAGS
        ):
            between_known_by_tag.setdefault(tag, Counter())[(preceding_tag, following_tag)] += 1
        offset = header.get("offset_bytes")
        declared_size = header.get("declared_size")
        if not isinstance(offset, int) or not isinstance(declared_size, int):
            size_by_tag.setdefault(tag, [])
            zero_prefix_by_tag.setdefault(tag, [])
            float_ratio_by_tag.setdefault(tag, [])
            prefix_hex_by_tag.setdefault(tag, [])
            continue

        payload = data[offset + 8 : offset + 8 + declared_size]
        size_by_tag.setdefault(tag, []).append(declared_size)
        zero_prefix_by_tag.setdefault(tag, []).append(_count_leading_zero_bytes(payload))
        float_ratio = _estimate_float_like_ratio(payload)
        if float_ratio is not None:
            float_ratio_by_tag.setdefault(tag, []).append(float_ratio)
        else:
            float_ratio_by_tag.setdefault(tag, [])
        prefix_hex = payload[:16].hex()
        if prefix_hex:
            prefixes = prefix_hex_by_tag.setdefault(tag, [])
            if prefix_hex not in prefixes and len(prefixes) < UNKNOWN_CHUNK_PREFIX_SAMPLE_LIMIT:
                prefixes.append(prefix_hex)
        else:
            prefix_hex_by_tag.setdefault(tag, [])

    profiles: list[dict[str, object]] = []
    for tag, sizes in sorted(size_by_tag.items(), key=lambda item: (-chunk_tag_counts[item[0]], item[0])):
        layout_hints = _derive_unknown_chunk_layout_hints(
            size_min=min(sizes) if sizes else None,
            size_max=max(sizes) if sizes else None,
            zero_prefix_min=min(zero_prefix_by_tag.get(tag, [])) if zero_prefix_by_tag.get(tag) else None,
            zero_prefix_max=max(zero_prefix_by_tag.get(tag, [])) if zero_prefix_by_tag.get(tag) else None,
            float_ratio_min=min(float_ratio_by_tag.get(tag, [])) if float_ratio_by_tag.get(tag) else None,
            float_ratio_max=max(float_ratio_by_tag.get(tag, [])) if float_ratio_by_tag.get(tag) else None,
        )
        known_cooccurring = Counter(
            known_tag
            for known_tag, count in chunk_tag_counts.items()
            if known_tag in KNOWN_C3_CHUNK_TAGS
            for _ in range(count)
        )
        profiles.append(
            {
                "tag": tag,
                "count": chunk_tag_counts[tag],
                "declared_size_min": min(sizes) if sizes else None,
                "declared_size_max": max(sizes) if sizes else None,
                "declared_size_sample": sorted(set(sizes))[:UNKNOWN_CHUNK_SIZE_SAMPLE_LIMIT],
                "leading_zero_prefix_min": min(zero_prefix_by_tag.get(tag, [])) if zero_prefix_by_tag.get(tag) else None,
                "leading_zero_prefix_max": max(zero_prefix_by_tag.get(tag, [])) if zero_prefix_by_tag.get(tag) else None,
                "float_like_ratio_min": round(min(float_ratio_by_tag.get(tag, [])), 4) if float_ratio_by_tag.get(tag) else None,
                "float_like_ratio_max": round(max(float_ratio_by_tag.get(tag, [])), 4) if float_ratio_by_tag.get(tag) else None,
                "payload_prefix_hex_sample": prefix_hex_by_tag.get(tag, [])[:UNKNOWN_CHUNK_PREFIX_SAMPLE_LIMIT],
                "cooccurring_known_tags": [
                    {"tag": known_tag, "count": count}
                    for known_tag, count in known_cooccurring.most_common(MAX_SAMPLE_ITEMS)
                ],
                "parent_known_tags": _format_chunk_tag_counter(parent_known_by_tag.get(tag, Counter())),
                "preceding_known_tags": _format_chunk_tag_counter(preceding_known_by_tag.get(tag, Counter())),
                "following_known_tags": _format_chunk_tag_counter(following_known_by_tag.get(tag, Counter())),
                "between_known_tags": _format_chunk_pair_counter(between_known_by_tag.get(tag, Counter())),
                "layout_hints": layout_hints,
                "subformat_hints": _derive_unknown_chunk_subformat_hints(
                    size_min=min(sizes) if sizes else None,
                    size_max=max(sizes) if sizes else None,
                    layout_hints=layout_hints,
                    tag_count=1,
                ),
                "sequence_context_hints": _derive_unknown_chunk_sequence_context_hints(
                    parent_counts=parent_known_by_tag.get(tag, Counter()),
                    preceding_counts=preceding_known_by_tag.get(tag, Counter()),
                    following_counts=following_known_by_tag.get(tag, Counter()),
                    between_counts=between_known_by_tag.get(tag, Counter()),
                ),
                "attachment_hints": _derive_unknown_chunk_attachment_hints(
                    parent_counts=parent_known_by_tag.get(tag, Counter()),
                    preceding_counts=preceding_known_by_tag.get(tag, Counter()),
                    following_counts=following_known_by_tag.get(tag, Counter()),
                    between_counts=between_known_by_tag.get(tag, Counter()),
                    layout_hints=layout_hints,
                    tag_count=1,
                ),
            }
        )

    return profiles[:MAX_SAMPLE_ITEMS]


def _count_leading_zero_bytes(payload: bytes) -> int:
    count = 0
    for byte in payload:
        if byte != 0:
            break
        count += 1
    return count


def _estimate_float_like_ratio(payload: bytes) -> float | None:
    word_count = min(len(payload) // 4, UNKNOWN_CHUNK_FLOAT_WORD_SAMPLE_LIMIT)
    if word_count <= 0:
        return None

    float_like_count = 0
    for index in range(word_count):
        value = struct.unpack("<f", payload[index * 4 : index * 4 + 4])[0]
        if math.isfinite(value) and abs(value) < 1e35:
            float_like_count += 1

    return float_like_count / word_count


def _derive_unknown_chunk_layout_hints(
    *,
    size_min: int | None,
    size_max: int | None,
    zero_prefix_min: int | None,
    zero_prefix_max: int | None,
    float_ratio_min: float | None,
    float_ratio_max: float | None,
) -> list[str]:
    hints: list[str] = []

    if isinstance(size_min, int) and isinstance(size_max, int) and size_min == size_max:
        hints.append("fixed-size-block")
    if isinstance(size_max, int) and size_max <= 128:
        hints.append("small-block")
    elif isinstance(size_min, int) and size_min >= 4096:
        hints.append("large-block")

    if isinstance(zero_prefix_min, int) and zero_prefix_min >= 8:
        hints.append("zero-prefixed-block")
    elif isinstance(zero_prefix_max, int) and zero_prefix_max == 0:
        hints.append("nonzero-prefixed-block")

    if isinstance(float_ratio_min, float) and float_ratio_min >= 0.75:
        hints.append("float-heavy-block")

    return hints


def _derive_unknown_chunk_subformat_hints(
    *,
    size_min: int | None,
    size_max: int | None,
    layout_hints: list[str],
    tag_count: int,
) -> list[str]:
    layout_set = set(layout_hints)
    hints: list[str] = []

    if {"small-block", "zero-prefixed-block", "float-heavy-block"} <= layout_set:
        hints.append("compact-float-control-family" if tag_count > 1 else "compact-float-control-block")

    if {"large-block", "float-heavy-block"} <= layout_set:
        if {"zero-prefixed-block", "nonzero-prefixed-block"} <= layout_set:
            hints.append("mixed-prefix-bulk-float-family" if tag_count > 1 else "mixed-prefix-bulk-float-block")
        else:
            hints.append("bulk-float-buffer-family" if tag_count > 1 else "bulk-float-buffer-block")

    if (
        tag_count > 1
        and isinstance(size_min, int)
        and isinstance(size_max, int)
        and abs(size_max - size_min) <= UNKNOWN_CHUNK_CLUSTER_SIZE_TOLERANCE
    ):
        hints.append("stable-size-variant-family")

    return hints


def _is_plausible_path_hint(value: str) -> bool:
    if not PLAUSIBLE_PATH_PATTERN.fullmatch(value):
        return False

    lowered = value.lower()
    if any(lowered.endswith(suffix) for suffix in PATH_REFERENCE_SUFFIXES):
        return bool(re.search(r"[A-Za-z0-9]", value))

    if "\\" not in value and "/" not in value:
        return False

    parts = [part for part in value.replace("\\", "/").split("/") if part]
    if len(parts) < 2:
        return False
    if not all(re.search(r"[A-Za-z0-9]", part) for part in parts[: min(3, len(parts))]):
        return False

    separator_count = value.count("\\") + value.count("/")
    if value[:1] in {"\\", "/"} or ":" in value[:3] or separator_count >= 2:
        return True

    return False


def _top_conquer_c3_path_buckets(
    c3_entries: dict[str, object],
    *,
    key: str,
) -> list[dict[str, object]]:
    counts: Counter[str] = Counter()
    for normalized_path in c3_entries:
        family, branch = _conquer_c3_path_family(normalized_path)
        if key == "family":
            counts[family] += 1
        elif key == "branch":
            counts[branch] += 1
    field_name = "family" if key == "family" else "branch"
    return [
        {field_name: name, "count": count}
        for name, count in counts.most_common(MAX_SAMPLE_ITEMS)
    ]


def _build_coverage_sample(
    rows: list[dict[str, str | int]],
    *,
    field: str,
) -> list[dict[str, object]]:
    normalized_to_value: dict[str, str] = {}
    for row in rows:
        normalized_to_value.setdefault(str(row["normalized_path"]), str(row[field]))

    bucket_counts: Counter[str] = Counter(normalized_to_value.values())
    output_field = "family" if field == "family" else "branch"
    return [
        {
            output_field: name,
            "unique_path_count": count,
        }
        for name, count in bucket_counts.most_common(MAX_SAMPLE_ITEMS)
    ]


def _format_status_coverage_sample(
    status_counts: dict[str, Counter[str]],
    *,
    field: str,
) -> list[dict[str, object]]:
    sample: list[dict[str, object]] = []

    for name, counts in sorted(
        status_counts.items(),
        key=lambda item: (-sum(item[1].values()), item[0]),
    )[:MAX_SAMPLE_ITEMS]:
        total = sum(counts.values())
        resolved = total - counts.get("missing", 0)
        sample.append(
            {
                field: name,
                "unique_path_count": total,
                "resolved_unique_path_count": resolved,
                "missing_unique_path_count": counts.get("missing", 0),
                "coverage_ratio": round(resolved / total, 4) if total else None,
                "status_counts": [
                    {"status": status, "count": count}
                    for status, count in counts.most_common(MAX_SAMPLE_ITEMS)
                ],
            }
        )

    return sample


def _promote_counter_status(counts: Counter[str], alias_status: str) -> None:
    counts["missing"] -= 1
    if counts["missing"] <= 0:
        counts.pop("missing", None)
    counts[alias_status] += 1


def _build_residual_missing_sample(
    status_counts: dict[str, Counter[str]],
    *,
    field: str,
) -> list[dict[str, object]]:
    sample: list[dict[str, object]] = []

    for name, counts in sorted(
        status_counts.items(),
        key=lambda item: (-item[1].get("missing", 0), -sum(item[1].values()), item[0]),
    ):
        missing_count = counts.get("missing", 0)
        if missing_count <= 0:
            continue
        total = sum(counts.values())
        resolved = total - missing_count
        sample.append(
            {
                field: name,
                "unique_path_count": total,
                "resolved_unique_path_count": resolved,
                "missing_unique_path_count": missing_count,
                "effective_coverage_ratio": round(resolved / total, 4) if total else None,
            }
        )
        if len(sample) >= MAX_SAMPLE_ITEMS:
            break

    return sample


def _build_lowest_effective_coverage_sample(
    status_counts: dict[str, Counter[str]],
    *,
    field: str,
) -> list[dict[str, object]]:
    ranked: list[dict[str, object]] = []

    for name, counts in status_counts.items():
        total = sum(counts.values())
        if total <= 0:
            continue
        missing_count = counts.get("missing", 0)
        resolved = total - missing_count
        alias_resolved = sum(
            count
            for status, count in counts.items()
            if status.startswith("alias-")
        )
        ranked.append(
            {
                field: name,
                "unique_path_count": total,
                "resolved_unique_path_count": resolved,
                "missing_unique_path_count": missing_count,
                "alias_resolved_unique_path_count": alias_resolved,
                "effective_coverage_ratio": round(resolved / total, 4) if total else None,
            }
        )

    ranked.sort(
        key=lambda item: (
            2.0 if item["effective_coverage_ratio"] is None else float(item["effective_coverage_ratio"]),
            -int(item["missing_unique_path_count"]),
            str(item[field]).lower(),
        )
    )
    return ranked[:MAX_SAMPLE_ITEMS]


def _build_alias_gain_sample(
    *,
    direct_status_counts: dict[str, Counter[str]],
    effective_status_counts: dict[str, Counter[str]],
    field: str,
) -> list[dict[str, object]]:
    ranked: list[dict[str, object]] = []

    for name, direct_counts in direct_status_counts.items():
        effective_counts = effective_status_counts.get(name, Counter())
        total = sum(direct_counts.values())
        if total <= 0:
            continue
        direct_resolved = total - direct_counts.get("missing", 0)
        effective_resolved = total - effective_counts.get("missing", 0)
        alias_gain = effective_resolved - direct_resolved
        if alias_gain <= 0:
            continue
        ranked.append(
            {
                field: name,
                "unique_path_count": total,
                "direct_resolved_unique_path_count": direct_resolved,
                "effective_resolved_unique_path_count": effective_resolved,
                "alias_resolved_unique_path_count": alias_gain,
                "direct_coverage_ratio": round(direct_resolved / total, 4) if total else None,
                "effective_coverage_ratio": round(effective_resolved / total, 4) if total else None,
            }
        )

    ranked.sort(
        key=lambda item: (
            -int(item["alias_resolved_unique_path_count"]),
            -(float(item["effective_coverage_ratio"]) if isinstance(item["effective_coverage_ratio"], float) else 0.0),
            str(item[field]).lower(),
        )
    )
    return ranked[:MAX_SAMPLE_ITEMS]


def _build_package_filename_buckets(
    package_catalog: dict[str, object],
) -> tuple[dict[str, set[str]], dict[str, set[str]], dict[str, set[str]], dict[str, set[str]]]:
    family_files: dict[str, set[str]] = {}
    branch_files: dict[str, set[str]] = {}
    family_packages: dict[str, set[str]] = {}
    branch_packages: dict[str, set[str]] = {}

    for normalized_path, sources in package_catalog.get("path_sources", {}).items():
        family, branch = _conquer_c3_path_family(str(normalized_path))
        filename = str(normalized_path).split("/")[-1]
        family_files.setdefault(family, set()).add(filename)
        branch_files.setdefault(branch, set()).add(filename)
        for source in sources:
            package_name = str(source["package"])
            family_packages.setdefault(family, set()).add(package_name)
            branch_packages.setdefault(branch, set()).add(package_name)

    return family_files, branch_files, family_packages, branch_packages


def _build_package_bucket_profile_sample(
    package_catalog: dict[str, object],
    *,
    bucket_names: list[str],
    field: str,
) -> list[dict[str, object]]:
    selected_bucket_names = [name for name in bucket_names if name]
    if not selected_bucket_names:
        return []

    package_paths_by_bucket: dict[str, list[tuple[str, dict[str, object]]]] = {}
    for normalized_path, sources in package_catalog.get("path_sources", {}).items():
        if not sources:
            continue
        family, branch = _conquer_c3_path_family(str(normalized_path))
        bucket_name = family if field == "family" else branch
        if bucket_name not in selected_bucket_names:
            continue
        package_paths_by_bucket.setdefault(bucket_name, []).append((str(normalized_path), sources[0]))

    sample: list[dict[str, object]] = []
    for bucket_name in selected_bucket_names:
        bucket_entries = sorted(package_paths_by_bucket.get(bucket_name, []), key=lambda item: item[0].lower())
        if not bucket_entries:
            continue

        packages = sorted({str(source["package"]) for _path, source in bucket_entries})
        top_tags: Counter[str] = Counter()
        top_tag_roles: Counter[str] = Counter()
        structural_roles: Counter[str] = Counter()
        chunk_signatures: Counter[tuple[str, ...]] = Counter()
        unknown_chunk_tags: Counter[str] = Counter()
        unknown_chunk_tag_entry_counts: Counter[str] = Counter()
        unknown_chunk_tag_path_sample: dict[str, list[str]] = {}
        unknown_chunk_tag_sizes: dict[str, list[int]] = {}
        unknown_chunk_tag_known_cooccurrence: dict[str, Counter[str]] = {}
        unknown_chunk_tag_zero_prefixes: dict[str, list[int]] = {}
        unknown_chunk_tag_float_ratios: dict[str, list[float]] = {}
        unknown_chunk_tag_prefix_hexes: dict[str, list[str]] = {}
        unknown_chunk_tag_layout_hints: dict[str, set[str]] = {}
        unknown_chunk_tag_parent_known: dict[str, Counter[str]] = {}
        unknown_chunk_tag_preceding_known: dict[str, Counter[str]] = {}
        unknown_chunk_tag_following_known: dict[str, Counter[str]] = {}
        unknown_chunk_tag_between_known: dict[str, Counter[tuple[str, str]]] = {}
        path_sample: list[str] = []
        object_name_sample: list[str] = []
        sampled_entry_count = 0

        for _normalized_path, source in bucket_entries:
            summary = _summarize_resolved_c3_source(source)
            if summary is None:
                continue
            sampled_entry_count += 1
            path_sample.append(str(summary["path"]))
            top_tag = summary.get("top_tag")
            if isinstance(top_tag, str) and top_tag:
                top_tags[top_tag] += 1
            top_tag_role = summary.get("top_tag_role")
            if isinstance(top_tag_role, str) and top_tag_role:
                top_tag_roles[top_tag_role] += 1
            for role in summary.get("structural_role_hints", []):
                if isinstance(role, str) and role:
                    structural_roles[role] += 1
            chunk_signature = tuple(
                tag
                for tag in summary.get("chunk_signature", [])
                if isinstance(tag, str) and tag
            )
            if chunk_signature:
                chunk_signatures[chunk_signature] += 1
            for item in summary.get("unknown_chunk_tags", []):
                tag = item.get("tag")
                count = item.get("count")
                if isinstance(tag, str) and isinstance(count, int):
                    unknown_chunk_tags[tag] += count
            for profile in summary.get("unknown_chunk_tag_profiles", []):
                tag = profile.get("tag")
                if not isinstance(tag, str) or not tag:
                    continue
                unknown_chunk_tag_entry_counts[tag] += 1
                if summary["path"] not in unknown_chunk_tag_path_sample.setdefault(tag, []):
                    if len(unknown_chunk_tag_path_sample[tag]) < MAX_SAMPLE_ITEMS:
                        unknown_chunk_tag_path_sample[tag].append(str(summary["path"]))
                for size in profile.get("declared_size_sample", []):
                    if isinstance(size, int):
                        unknown_chunk_tag_sizes.setdefault(tag, []).append(size)
                zero_prefix_min = profile.get("leading_zero_prefix_min")
                zero_prefix_max = profile.get("leading_zero_prefix_max")
                if isinstance(zero_prefix_min, int):
                    unknown_chunk_tag_zero_prefixes.setdefault(tag, []).append(zero_prefix_min)
                if isinstance(zero_prefix_max, int) and zero_prefix_max != zero_prefix_min:
                    unknown_chunk_tag_zero_prefixes.setdefault(tag, []).append(zero_prefix_max)
                float_ratio_min = profile.get("float_like_ratio_min")
                float_ratio_max = profile.get("float_like_ratio_max")
                if isinstance(float_ratio_min, float):
                    unknown_chunk_tag_float_ratios.setdefault(tag, []).append(float_ratio_min)
                if isinstance(float_ratio_max, float) and float_ratio_max != float_ratio_min:
                    unknown_chunk_tag_float_ratios.setdefault(tag, []).append(float_ratio_max)
                for prefix_hex in profile.get("payload_prefix_hex_sample", []):
                    if isinstance(prefix_hex, str) and prefix_hex:
                        prefixes = unknown_chunk_tag_prefix_hexes.setdefault(tag, [])
                        if prefix_hex not in prefixes and len(prefixes) < UNKNOWN_CHUNK_PREFIX_SAMPLE_LIMIT:
                            prefixes.append(prefix_hex)
                for item in profile.get("cooccurring_known_tags", []):
                    known_tag = item.get("tag")
                    count = item.get("count")
                    if isinstance(known_tag, str) and isinstance(count, int):
                        unknown_chunk_tag_known_cooccurrence.setdefault(tag, Counter())[known_tag] += count
                for item in profile.get("parent_known_tags", []):
                    known_tag = item.get("tag")
                    count = item.get("count")
                    if isinstance(known_tag, str) and isinstance(count, int):
                        unknown_chunk_tag_parent_known.setdefault(tag, Counter())[known_tag] += count
                for item in profile.get("preceding_known_tags", []):
                    known_tag = item.get("tag")
                    count = item.get("count")
                    if isinstance(known_tag, str) and isinstance(count, int):
                        unknown_chunk_tag_preceding_known.setdefault(tag, Counter())[known_tag] += count
                for item in profile.get("following_known_tags", []):
                    known_tag = item.get("tag")
                    count = item.get("count")
                    if isinstance(known_tag, str) and isinstance(count, int):
                        unknown_chunk_tag_following_known.setdefault(tag, Counter())[known_tag] += count
                for item in profile.get("between_known_tags", []):
                    preceding_tag = item.get("preceding_tag")
                    following_tag = item.get("following_tag")
                    count = item.get("count")
                    if isinstance(preceding_tag, str) and isinstance(following_tag, str) and isinstance(count, int):
                        unknown_chunk_tag_between_known.setdefault(tag, Counter())[(preceding_tag, following_tag)] += count
                for hint in profile.get("layout_hints", []):
                    if isinstance(hint, str) and hint:
                        unknown_chunk_tag_layout_hints.setdefault(tag, set()).add(hint)
            object_name = summary.get("object_name")
            if isinstance(object_name, str) and object_name:
                object_name_sample.append(object_name)
            if sampled_entry_count >= PACKAGE_PROFILE_SAMPLE_LIMIT:
                break

        if sampled_entry_count <= 0:
            continue

        sample.append(
            {
                field: bucket_name,
                "package_entry_count": len(bucket_entries),
                "sampled_entry_count": sampled_entry_count,
                "packages": packages,
                "top_tags": [
                    {"tag": tag, "count": count}
                    for tag, count in top_tags.most_common(MAX_SAMPLE_ITEMS)
                ],
                "top_tag_roles": [
                    {"role": role, "count": count}
                    for role, count in top_tag_roles.most_common(MAX_SAMPLE_ITEMS)
                ],
                "structural_roles": [
                    {"role": role, "count": count}
                    for role, count in structural_roles.most_common(MAX_SAMPLE_ITEMS)
                ],
                "chunk_signatures": [
                    {"tags": list(signature), "count": count}
                    for signature, count in chunk_signatures.most_common(MAX_SAMPLE_ITEMS)
                ],
                "unknown_chunk_tags": [
                    {"tag": tag, "count": count}
                    for tag, count in unknown_chunk_tags.most_common(MAX_SAMPLE_ITEMS)
                ],
                "unknown_chunk_tag_profiles": [
                    {
                        "tag": tag,
                        "entry_count": unknown_chunk_tag_entry_counts[tag],
                        "count": count,
                        "declared_size_min": min(unknown_chunk_tag_sizes.get(tag, [])) if unknown_chunk_tag_sizes.get(tag) else None,
                        "declared_size_max": max(unknown_chunk_tag_sizes.get(tag, [])) if unknown_chunk_tag_sizes.get(tag) else None,
                        "declared_size_sample": sorted(set(unknown_chunk_tag_sizes.get(tag, [])))[:UNKNOWN_CHUNK_SIZE_SAMPLE_LIMIT],
                        "leading_zero_prefix_min": min(unknown_chunk_tag_zero_prefixes.get(tag, [])) if unknown_chunk_tag_zero_prefixes.get(tag) else None,
                        "leading_zero_prefix_max": max(unknown_chunk_tag_zero_prefixes.get(tag, [])) if unknown_chunk_tag_zero_prefixes.get(tag) else None,
                        "float_like_ratio_min": round(min(unknown_chunk_tag_float_ratios.get(tag, [])), 4) if unknown_chunk_tag_float_ratios.get(tag) else None,
                        "float_like_ratio_max": round(max(unknown_chunk_tag_float_ratios.get(tag, [])), 4) if unknown_chunk_tag_float_ratios.get(tag) else None,
                        "payload_prefix_hex_sample": unknown_chunk_tag_prefix_hexes.get(tag, [])[:UNKNOWN_CHUNK_PREFIX_SAMPLE_LIMIT],
                        "cooccurring_known_tags": [
                            {"tag": known_tag, "count": known_count}
                            for known_tag, known_count in unknown_chunk_tag_known_cooccurrence.get(tag, Counter()).most_common(MAX_SAMPLE_ITEMS)
                        ],
                        "parent_known_tags": _format_chunk_tag_counter(unknown_chunk_tag_parent_known.get(tag, Counter())),
                        "preceding_known_tags": _format_chunk_tag_counter(unknown_chunk_tag_preceding_known.get(tag, Counter())),
                        "following_known_tags": _format_chunk_tag_counter(unknown_chunk_tag_following_known.get(tag, Counter())),
                        "between_known_tags": _format_chunk_pair_counter(unknown_chunk_tag_between_known.get(tag, Counter())),
                        "layout_hints": sorted(unknown_chunk_tag_layout_hints.get(tag, set())),
                        "subformat_hints": _derive_unknown_chunk_subformat_hints(
                            size_min=min(unknown_chunk_tag_sizes.get(tag, [])) if unknown_chunk_tag_sizes.get(tag) else None,
                            size_max=max(unknown_chunk_tag_sizes.get(tag, [])) if unknown_chunk_tag_sizes.get(tag) else None,
                            layout_hints=sorted(unknown_chunk_tag_layout_hints.get(tag, set())),
                            tag_count=1,
                        ),
                        "sequence_context_hints": _derive_unknown_chunk_sequence_context_hints(
                            parent_counts=unknown_chunk_tag_parent_known.get(tag, Counter()),
                            preceding_counts=unknown_chunk_tag_preceding_known.get(tag, Counter()),
                            following_counts=unknown_chunk_tag_following_known.get(tag, Counter()),
                            between_counts=unknown_chunk_tag_between_known.get(tag, Counter()),
                        ),
                        "attachment_hints": _derive_unknown_chunk_attachment_hints(
                            parent_counts=unknown_chunk_tag_parent_known.get(tag, Counter()),
                            preceding_counts=unknown_chunk_tag_preceding_known.get(tag, Counter()),
                            following_counts=unknown_chunk_tag_following_known.get(tag, Counter()),
                            between_counts=unknown_chunk_tag_between_known.get(tag, Counter()),
                            layout_hints=sorted(unknown_chunk_tag_layout_hints.get(tag, set())),
                            tag_count=1,
                        ),
                        "path_sample": unknown_chunk_tag_path_sample.get(tag, [])[:MAX_SAMPLE_ITEMS],
                    }
                    for tag, count in unknown_chunk_tags.most_common(MAX_SAMPLE_ITEMS)
                ],
                "unknown_chunk_clusters": _build_unknown_chunk_cluster_sample(
                    [
                        {
                            "tag": tag,
                            "entry_count": unknown_chunk_tag_entry_counts[tag],
                            "count": count,
                            "declared_size_min": min(unknown_chunk_tag_sizes.get(tag, [])) if unknown_chunk_tag_sizes.get(tag) else None,
                            "declared_size_max": max(unknown_chunk_tag_sizes.get(tag, [])) if unknown_chunk_tag_sizes.get(tag) else None,
                            "declared_size_sample": sorted(set(unknown_chunk_tag_sizes.get(tag, [])))[:UNKNOWN_CHUNK_SIZE_SAMPLE_LIMIT],
                            "leading_zero_prefix_min": min(unknown_chunk_tag_zero_prefixes.get(tag, [])) if unknown_chunk_tag_zero_prefixes.get(tag) else None,
                            "leading_zero_prefix_max": max(unknown_chunk_tag_zero_prefixes.get(tag, [])) if unknown_chunk_tag_zero_prefixes.get(tag) else None,
                            "float_like_ratio_min": round(min(unknown_chunk_tag_float_ratios.get(tag, [])), 4) if unknown_chunk_tag_float_ratios.get(tag) else None,
                            "float_like_ratio_max": round(max(unknown_chunk_tag_float_ratios.get(tag, [])), 4) if unknown_chunk_tag_float_ratios.get(tag) else None,
                            "payload_prefix_hex_sample": unknown_chunk_tag_prefix_hexes.get(tag, [])[:UNKNOWN_CHUNK_PREFIX_SAMPLE_LIMIT],
                            "cooccurring_known_tags": [
                                {"tag": known_tag, "count": known_count}
                                for known_tag, known_count in unknown_chunk_tag_known_cooccurrence.get(tag, Counter()).most_common(MAX_SAMPLE_ITEMS)
                            ],
                            "parent_known_tags": _format_chunk_tag_counter(unknown_chunk_tag_parent_known.get(tag, Counter())),
                            "preceding_known_tags": _format_chunk_tag_counter(unknown_chunk_tag_preceding_known.get(tag, Counter())),
                            "following_known_tags": _format_chunk_tag_counter(unknown_chunk_tag_following_known.get(tag, Counter())),
                            "between_known_tags": _format_chunk_pair_counter(unknown_chunk_tag_between_known.get(tag, Counter())),
                            "layout_hints": sorted(unknown_chunk_tag_layout_hints.get(tag, set())),
                            "path_sample": unknown_chunk_tag_path_sample.get(tag, [])[:MAX_SAMPLE_ITEMS],
                        }
                        for tag, count in unknown_chunk_tags.most_common(MAX_SAMPLE_ITEMS)
                    ]
                ),
                "unknown_chunk_archetypes": _build_unknown_chunk_archetype_sample(
                    [
                        {
                            "tag": tag,
                            "entry_count": unknown_chunk_tag_entry_counts[tag],
                            "count": count,
                            "declared_size_min": min(unknown_chunk_tag_sizes.get(tag, [])) if unknown_chunk_tag_sizes.get(tag) else None,
                            "declared_size_max": max(unknown_chunk_tag_sizes.get(tag, [])) if unknown_chunk_tag_sizes.get(tag) else None,
                            "declared_size_sample": sorted(set(unknown_chunk_tag_sizes.get(tag, [])))[:UNKNOWN_CHUNK_SIZE_SAMPLE_LIMIT],
                            "cooccurring_known_tags": [
                                {"tag": known_tag, "count": known_count}
                                for known_tag, known_count in unknown_chunk_tag_known_cooccurrence.get(tag, Counter()).most_common(MAX_SAMPLE_ITEMS)
                            ],
                            "layout_hints": sorted(unknown_chunk_tag_layout_hints.get(tag, set())),
                            "subformat_hints": _derive_unknown_chunk_subformat_hints(
                                size_min=min(unknown_chunk_tag_sizes.get(tag, [])) if unknown_chunk_tag_sizes.get(tag) else None,
                                size_max=max(unknown_chunk_tag_sizes.get(tag, [])) if unknown_chunk_tag_sizes.get(tag) else None,
                                layout_hints=sorted(unknown_chunk_tag_layout_hints.get(tag, set())),
                                tag_count=1,
                            ),
                            "sequence_context_hints": _derive_unknown_chunk_sequence_context_hints(
                                parent_counts=unknown_chunk_tag_parent_known.get(tag, Counter()),
                                preceding_counts=unknown_chunk_tag_preceding_known.get(tag, Counter()),
                                following_counts=unknown_chunk_tag_following_known.get(tag, Counter()),
                                between_counts=unknown_chunk_tag_between_known.get(tag, Counter()),
                            ),
                            "attachment_hints": _derive_unknown_chunk_attachment_hints(
                                parent_counts=unknown_chunk_tag_parent_known.get(tag, Counter()),
                                preceding_counts=unknown_chunk_tag_preceding_known.get(tag, Counter()),
                                following_counts=unknown_chunk_tag_following_known.get(tag, Counter()),
                                between_counts=unknown_chunk_tag_between_known.get(tag, Counter()),
                                layout_hints=sorted(unknown_chunk_tag_layout_hints.get(tag, set())),
                                tag_count=1,
                            ),
                            "path_sample": unknown_chunk_tag_path_sample.get(tag, [])[:MAX_SAMPLE_ITEMS],
                        }
                        for tag, count in unknown_chunk_tags.most_common(MAX_SAMPLE_ITEMS)
                    ]
                ),
                "path_sample": path_sample[:MAX_SAMPLE_ITEMS],
                "object_name_sample": object_name_sample[:MAX_SAMPLE_ITEMS],
            }
        )

    return sample


def _build_unknown_chunk_cluster_sample(
    profiles: list[dict[str, object]],
) -> list[dict[str, object]]:
    clusters: list[dict[str, object]] = []

    for profile in profiles:
        tag = profile.get("tag")
        if not isinstance(tag, str) or not tag:
            continue

        matched_cluster: dict[str, object] | None = None
        for cluster in clusters:
            if _unknown_chunk_profile_matches_cluster(profile, cluster):
                matched_cluster = cluster
                break

        if matched_cluster is None:
            matched_cluster = {
                "tags": [],
                "tag_count": 0,
                "total_occurrence_count": 0,
                "declared_size_min": profile.get("declared_size_min"),
                "declared_size_max": profile.get("declared_size_max"),
                "declared_size_sample": [],
                "leading_zero_prefix_min": profile.get("leading_zero_prefix_min"),
                "leading_zero_prefix_max": profile.get("leading_zero_prefix_max"),
                "float_like_ratio_min": profile.get("float_like_ratio_min"),
                "float_like_ratio_max": profile.get("float_like_ratio_max"),
                "payload_prefix_hex_sample": [],
                "cooccurring_known_tags": Counter(),
                "parent_known_tags": Counter(),
                "preceding_known_tags": Counter(),
                "following_known_tags": Counter(),
                "between_known_tags": Counter(),
                "layout_hints": set(),
                "path_sample": [],
            }
            clusters.append(matched_cluster)

        matched_cluster["tags"].append(tag)
        matched_cluster["tags"] = sorted(set(matched_cluster["tags"]))
        matched_cluster["tag_count"] = len(matched_cluster["tags"])
        matched_cluster["total_occurrence_count"] = int(matched_cluster["total_occurrence_count"]) + int(profile.get("count", 0))

        size_min = profile.get("declared_size_min")
        size_max = profile.get("declared_size_max")
        if isinstance(size_min, int):
            current_min = matched_cluster.get("declared_size_min")
            matched_cluster["declared_size_min"] = size_min if current_min is None else min(int(current_min), size_min)
        if isinstance(size_max, int):
            current_max = matched_cluster.get("declared_size_max")
            matched_cluster["declared_size_max"] = size_max if current_max is None else max(int(current_max), size_max)

        zero_prefix_min = profile.get("leading_zero_prefix_min")
        zero_prefix_max = profile.get("leading_zero_prefix_max")
        if isinstance(zero_prefix_min, int):
            current_min = matched_cluster.get("leading_zero_prefix_min")
            matched_cluster["leading_zero_prefix_min"] = zero_prefix_min if current_min is None else min(int(current_min), zero_prefix_min)
        if isinstance(zero_prefix_max, int):
            current_max = matched_cluster.get("leading_zero_prefix_max")
            matched_cluster["leading_zero_prefix_max"] = zero_prefix_max if current_max is None else max(int(current_max), zero_prefix_max)

        float_ratio_min = profile.get("float_like_ratio_min")
        float_ratio_max = profile.get("float_like_ratio_max")
        if isinstance(float_ratio_min, float):
            current_min = matched_cluster.get("float_like_ratio_min")
            matched_cluster["float_like_ratio_min"] = float_ratio_min if current_min is None else min(float(current_min), float_ratio_min)
        if isinstance(float_ratio_max, float):
            current_max = matched_cluster.get("float_like_ratio_max")
            matched_cluster["float_like_ratio_max"] = float_ratio_max if current_max is None else max(float(current_max), float_ratio_max)

        size_sample = matched_cluster.setdefault("declared_size_sample", [])
        for size in profile.get("declared_size_sample", []):
            if isinstance(size, int) and size not in size_sample:
                size_sample.append(size)
        matched_cluster["declared_size_sample"] = sorted(size_sample)[:UNKNOWN_CHUNK_SIZE_SAMPLE_LIMIT]

        prefix_sample = matched_cluster.setdefault("payload_prefix_hex_sample", [])
        for prefix_hex in profile.get("payload_prefix_hex_sample", []):
            if isinstance(prefix_hex, str) and prefix_hex and prefix_hex not in prefix_sample and len(prefix_sample) < UNKNOWN_CHUNK_PREFIX_SAMPLE_LIMIT:
                prefix_sample.append(prefix_hex)

        cooccurring_counter = matched_cluster.setdefault("cooccurring_known_tags", Counter())
        for item in profile.get("cooccurring_known_tags", []):
            known_tag = item.get("tag")
            count = item.get("count")
            if isinstance(known_tag, str) and isinstance(count, int):
                cooccurring_counter[known_tag] += count

        parent_counter = matched_cluster.setdefault("parent_known_tags", Counter())
        for item in profile.get("parent_known_tags", []):
            known_tag = item.get("tag")
            count = item.get("count")
            if isinstance(known_tag, str) and isinstance(count, int):
                parent_counter[known_tag] += count

        preceding_counter = matched_cluster.setdefault("preceding_known_tags", Counter())
        for item in profile.get("preceding_known_tags", []):
            known_tag = item.get("tag")
            count = item.get("count")
            if isinstance(known_tag, str) and isinstance(count, int):
                preceding_counter[known_tag] += count

        following_counter = matched_cluster.setdefault("following_known_tags", Counter())
        for item in profile.get("following_known_tags", []):
            known_tag = item.get("tag")
            count = item.get("count")
            if isinstance(known_tag, str) and isinstance(count, int):
                following_counter[known_tag] += count

        between_counter = matched_cluster.setdefault("between_known_tags", Counter())
        for item in profile.get("between_known_tags", []):
            preceding_tag = item.get("preceding_tag")
            following_tag = item.get("following_tag")
            count = item.get("count")
            if isinstance(preceding_tag, str) and isinstance(following_tag, str) and isinstance(count, int):
                between_counter[(preceding_tag, following_tag)] += count

        layout_hints = matched_cluster.setdefault("layout_hints", set())
        for hint in profile.get("layout_hints", []):
            if isinstance(hint, str) and hint:
                layout_hints.add(hint)

        path_sample = matched_cluster.setdefault("path_sample", [])
        for path in profile.get("path_sample", []):
            if isinstance(path, str) and path not in path_sample and len(path_sample) < MAX_SAMPLE_ITEMS:
                path_sample.append(path)

    formatted_clusters = [
        {
            "tags": list(cluster["tags"]),
            "tag_count": int(cluster["tag_count"]),
            "total_occurrence_count": int(cluster["total_occurrence_count"]),
            "sampled_path_count": len(cluster.get("path_sample", [])),
            "declared_size_min": cluster.get("declared_size_min"),
            "declared_size_max": cluster.get("declared_size_max"),
            "declared_size_sample": list(cluster.get("declared_size_sample", [])),
            "leading_zero_prefix_min": cluster.get("leading_zero_prefix_min"),
            "leading_zero_prefix_max": cluster.get("leading_zero_prefix_max"),
            "float_like_ratio_min": round(float(cluster["float_like_ratio_min"]), 4) if isinstance(cluster.get("float_like_ratio_min"), float) else cluster.get("float_like_ratio_min"),
            "float_like_ratio_max": round(float(cluster["float_like_ratio_max"]), 4) if isinstance(cluster.get("float_like_ratio_max"), float) else cluster.get("float_like_ratio_max"),
            "payload_prefix_hex_sample": list(cluster.get("payload_prefix_hex_sample", []))[:UNKNOWN_CHUNK_PREFIX_SAMPLE_LIMIT],
            "cooccurring_known_tags": [
                {"tag": known_tag, "count": count}
                for known_tag, count in cluster["cooccurring_known_tags"].most_common(MAX_SAMPLE_ITEMS)
            ],
            "parent_known_tags": _format_chunk_tag_counter(cluster.get("parent_known_tags", Counter())),
            "preceding_known_tags": _format_chunk_tag_counter(cluster.get("preceding_known_tags", Counter())),
            "following_known_tags": _format_chunk_tag_counter(cluster.get("following_known_tags", Counter())),
            "between_known_tags": _format_chunk_pair_counter(cluster.get("between_known_tags", Counter())),
            "layout_hints": sorted(cluster.get("layout_hints", set())),
            "subformat_hints": _derive_unknown_chunk_subformat_hints(
                size_min=cluster.get("declared_size_min"),
                size_max=cluster.get("declared_size_max"),
                layout_hints=sorted(cluster.get("layout_hints", set())),
                tag_count=int(cluster["tag_count"]),
            ),
            "sequence_context_hints": _derive_unknown_chunk_sequence_context_hints(
                parent_counts=cluster.get("parent_known_tags", Counter()),
                preceding_counts=cluster.get("preceding_known_tags", Counter()),
                following_counts=cluster.get("following_known_tags", Counter()),
                between_counts=cluster.get("between_known_tags", Counter()),
            ),
            "attachment_hints": _derive_unknown_chunk_attachment_hints(
                parent_counts=cluster.get("parent_known_tags", Counter()),
                preceding_counts=cluster.get("preceding_known_tags", Counter()),
                following_counts=cluster.get("following_known_tags", Counter()),
                between_counts=cluster.get("between_known_tags", Counter()),
                layout_hints=sorted(cluster.get("layout_hints", set())),
                tag_count=int(cluster["tag_count"]),
            ),
            "path_sample": list(cluster.get("path_sample", []))[:MAX_SAMPLE_ITEMS],
        }
        for cluster in clusters
    ]
    formatted_clusters.sort(
        key=lambda item: (
            -int(item["total_occurrence_count"]),
            -int(item["tag_count"]),
            item["tags"][0] if item["tags"] else "",
        )
    )
    return formatted_clusters[:MAX_SAMPLE_ITEMS]


def _build_unknown_chunk_archetype_sample(
    profiles: list[dict[str, object]],
) -> list[dict[str, object]]:
    archetypes: dict[
        tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...]],
        dict[str, object],
    ] = {}

    for profile in profiles:
        tag = profile.get("tag")
        if not isinstance(tag, str) or not tag:
            continue

        attachment_hints = tuple(
            hint for hint in profile.get("attachment_hints", []) if isinstance(hint, str) and hint
        )
        subformat_hints = tuple(
            hint for hint in profile.get("subformat_hints", []) if isinstance(hint, str) and hint
        )
        sequence_context_hints = tuple(
            hint for hint in profile.get("sequence_context_hints", []) if isinstance(hint, str) and hint
        )
        key = (attachment_hints, subformat_hints, sequence_context_hints)
        archetype = archetypes.setdefault(
            key,
            {
                "attachment_hints": list(attachment_hints),
                "subformat_hints": list(subformat_hints),
                "sequence_context_hints": list(sequence_context_hints),
                "layout_hints": sorted(
                    hint for hint in profile.get("layout_hints", []) if isinstance(hint, str) and hint
                ),
                "declared_size_min": profile.get("declared_size_min"),
                "declared_size_max": profile.get("declared_size_max"),
                "declared_size_sample": [],
                "cooccurring_known_tags": Counter(),
                "tag_sample": [],
                "tag_count": 0,
                "total_occurrence_count": 0,
                "entry_count": 0,
                "path_sample": [],
            },
        )

        tag_sample = archetype.setdefault("tag_sample", [])
        if tag not in tag_sample and len(tag_sample) < MAX_SAMPLE_ITEMS:
            tag_sample.append(tag)
        archetype["tag_count"] = len(tag_sample)
        archetype["total_occurrence_count"] = int(archetype["total_occurrence_count"]) + int(profile.get("count", 0))
        archetype["entry_count"] = int(archetype["entry_count"]) + int(profile.get("entry_count", 0))

        size_min = profile.get("declared_size_min")
        if isinstance(size_min, int):
            current_min = archetype.get("declared_size_min")
            archetype["declared_size_min"] = size_min if current_min is None else min(int(current_min), size_min)
        size_max = profile.get("declared_size_max")
        if isinstance(size_max, int):
            current_max = archetype.get("declared_size_max")
            archetype["declared_size_max"] = size_max if current_max is None else max(int(current_max), size_max)

        size_sample = archetype.setdefault("declared_size_sample", [])
        for size in profile.get("declared_size_sample", []):
            if isinstance(size, int) and size not in size_sample:
                size_sample.append(size)
        archetype["declared_size_sample"] = sorted(size_sample)[:UNKNOWN_CHUNK_SIZE_SAMPLE_LIMIT]

        known_counter = archetype.setdefault("cooccurring_known_tags", Counter())
        for item in profile.get("cooccurring_known_tags", []):
            known_tag = item.get("tag")
            count = item.get("count")
            if isinstance(known_tag, str) and isinstance(count, int):
                known_counter[known_tag] += count

        path_sample = archetype.setdefault("path_sample", [])
        for path in profile.get("path_sample", []):
            if isinstance(path, str) and path not in path_sample and len(path_sample) < MAX_SAMPLE_ITEMS:
                path_sample.append(path)

    formatted = [
        {
            "attachment_hints": list(archetype.get("attachment_hints", [])),
            "subformat_hints": list(archetype.get("subformat_hints", [])),
            "sequence_context_hints": list(archetype.get("sequence_context_hints", [])),
            "layout_hints": list(archetype.get("layout_hints", [])),
            "declared_size_min": archetype.get("declared_size_min"),
            "declared_size_max": archetype.get("declared_size_max"),
            "declared_size_sample": list(archetype.get("declared_size_sample", [])),
            "cooccurring_known_tags": [
                {"tag": known_tag, "count": count}
                for known_tag, count in archetype["cooccurring_known_tags"].most_common(MAX_SAMPLE_ITEMS)
            ],
            "tag_sample": list(archetype.get("tag_sample", []))[:MAX_SAMPLE_ITEMS],
            "tag_count": int(archetype.get("tag_count", 0)),
            "total_occurrence_count": int(archetype.get("total_occurrence_count", 0)),
            "entry_count": int(archetype.get("entry_count", 0)),
            "sampled_path_count": len(archetype.get("path_sample", [])),
            "path_sample": list(archetype.get("path_sample", []))[:MAX_SAMPLE_ITEMS],
        }
        for archetype in archetypes.values()
    ]
    formatted.sort(
        key=lambda item: (
            -int(item["total_occurrence_count"]),
            -int(item["tag_count"]),
            item["attachment_hints"][0] if item["attachment_hints"] else "",
            item["tag_sample"][0] if item["tag_sample"] else "",
        )
    )
    return formatted[:MAX_SAMPLE_ITEMS]


def _build_unknown_chunk_archetype_rollup_sample(
    package_profiles: list[dict[str, object]],
    *,
    field: str,
) -> list[dict[str, object]]:
    rollups: dict[
        tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], tuple[str, ...]],
        dict[str, object],
    ] = {}
    sample_field = f"{field}_sample"
    count_field = f"{field}_count"

    for package_profile in package_profiles:
        bucket_name = package_profile.get(field)
        if not isinstance(bucket_name, str) or not bucket_name:
            continue
        packages = [
            package
            for package in package_profile.get("packages", [])
            if isinstance(package, str) and package
        ]
        for archetype in package_profile.get("unknown_chunk_archetypes", []):
            attachment_hints = tuple(
                hint for hint in archetype.get("attachment_hints", []) if isinstance(hint, str) and hint
            )
            subformat_hints = tuple(
                hint for hint in archetype.get("subformat_hints", []) if isinstance(hint, str) and hint
            )
            sequence_context_hints = tuple(
                hint for hint in archetype.get("sequence_context_hints", []) if isinstance(hint, str) and hint
            )
            layout_hints = tuple(
                hint for hint in archetype.get("layout_hints", []) if isinstance(hint, str) and hint
            )
            key = (attachment_hints, subformat_hints, sequence_context_hints, layout_hints)
            rollup = rollups.setdefault(
                key,
                {
                    "attachment_hints": list(attachment_hints),
                    "subformat_hints": list(subformat_hints),
                    "sequence_context_hints": list(sequence_context_hints),
                    "layout_hints": list(layout_hints),
                    "declared_size_min": archetype.get("declared_size_min"),
                    "declared_size_max": archetype.get("declared_size_max"),
                    "declared_size_sample": [],
                    "cooccurring_known_tags": Counter(),
                    "tag_sample": [],
                    "tag_count": 0,
                    "total_occurrence_count": 0,
                    "entry_count": 0,
                    "packages": set(),
                    sample_field: [],
                    count_field: 0,
                    "path_sample": [],
                },
            )

            rollup["packages"].update(packages)
            bucket_sample = rollup.setdefault(sample_field, [])
            if bucket_name not in bucket_sample and len(bucket_sample) < MAX_SAMPLE_ITEMS:
                bucket_sample.append(bucket_name)
            rollup[count_field] = len(rollup.get(sample_field, []))

            tag_sample = rollup.setdefault("tag_sample", [])
            for tag in archetype.get("tag_sample", []):
                if isinstance(tag, str) and tag not in tag_sample and len(tag_sample) < MAX_SAMPLE_ITEMS:
                    tag_sample.append(tag)
            rollup["tag_count"] = len(tag_sample)

            rollup["total_occurrence_count"] = int(rollup["total_occurrence_count"]) + int(archetype.get("total_occurrence_count", 0))
            rollup["entry_count"] = int(rollup["entry_count"]) + int(archetype.get("entry_count", 0))

            size_min = archetype.get("declared_size_min")
            if isinstance(size_min, int):
                current_min = rollup.get("declared_size_min")
                rollup["declared_size_min"] = size_min if current_min is None else min(int(current_min), size_min)
            size_max = archetype.get("declared_size_max")
            if isinstance(size_max, int):
                current_max = rollup.get("declared_size_max")
                rollup["declared_size_max"] = size_max if current_max is None else max(int(current_max), size_max)

            size_sample = rollup.setdefault("declared_size_sample", [])
            for size in archetype.get("declared_size_sample", []):
                if isinstance(size, int) and size not in size_sample:
                    size_sample.append(size)
            rollup["declared_size_sample"] = sorted(size_sample)[:UNKNOWN_CHUNK_SIZE_SAMPLE_LIMIT]

            known_counter = rollup.setdefault("cooccurring_known_tags", Counter())
            for item in archetype.get("cooccurring_known_tags", []):
                known_tag = item.get("tag")
                count = item.get("count")
                if isinstance(known_tag, str) and isinstance(count, int):
                    known_counter[known_tag] += count

            path_sample = rollup.setdefault("path_sample", [])
            for path in archetype.get("path_sample", []):
                if isinstance(path, str) and path not in path_sample and len(path_sample) < MAX_SAMPLE_ITEMS:
                    path_sample.append(path)

    formatted = [
        {
            "attachment_hints": list(rollup.get("attachment_hints", [])),
            "subformat_hints": list(rollup.get("subformat_hints", [])),
            "sequence_context_hints": list(rollup.get("sequence_context_hints", [])),
            "layout_hints": list(rollup.get("layout_hints", [])),
            "declared_size_min": rollup.get("declared_size_min"),
            "declared_size_max": rollup.get("declared_size_max"),
            "declared_size_sample": list(rollup.get("declared_size_sample", [])),
            "cooccurring_known_tags": [
                {"tag": known_tag, "count": count}
                for known_tag, count in rollup["cooccurring_known_tags"].most_common(MAX_SAMPLE_ITEMS)
            ],
            "tag_sample": list(rollup.get("tag_sample", []))[:MAX_SAMPLE_ITEMS],
            "tag_count": int(rollup.get("tag_count", 0)),
            "total_occurrence_count": int(rollup.get("total_occurrence_count", 0)),
            "entry_count": int(rollup.get("entry_count", 0)),
            "packages": sorted(rollup.get("packages", set())),
            count_field: int(rollup.get(count_field, 0)),
            sample_field: list(rollup.get(sample_field, []))[:MAX_SAMPLE_ITEMS],
            "sampled_path_count": len(rollup.get("path_sample", [])),
            "path_sample": list(rollup.get("path_sample", []))[:MAX_SAMPLE_ITEMS],
        }
        for rollup in rollups.values()
    ]
    formatted.sort(
        key=lambda item: (
            -int(item["total_occurrence_count"]),
            -int(item[count_field]),
            item["attachment_hints"][0] if item["attachment_hints"] else "",
            item["tag_sample"][0] if item["tag_sample"] else "",
        )
    )
    return formatted[:MAX_SAMPLE_ITEMS]


def _unknown_chunk_profile_matches_cluster(
    profile: dict[str, object],
    cluster: dict[str, object],
) -> bool:
    profile_names = tuple(
        item.get("tag")
        for item in profile.get("cooccurring_known_tags", [])
        if isinstance(item.get("tag"), str)
    )
    cluster_names = tuple(
        tag
        for tag, _count in cluster.get("cooccurring_known_tags", Counter()).most_common(MAX_SAMPLE_ITEMS)
    )
    if profile_names != cluster_names:
        return False

    profile_min = profile.get("declared_size_min")
    profile_max = profile.get("declared_size_max")
    cluster_min = cluster.get("declared_size_min")
    cluster_max = cluster.get("declared_size_max")
    if not all(isinstance(value, int) for value in (profile_min, profile_max, cluster_min, cluster_max)):
        return profile_min is None and profile_max is None and cluster_min is None and cluster_max is None

    return (
        abs(int(profile_min) - int(cluster_min)) <= UNKNOWN_CHUNK_CLUSTER_SIZE_TOLERANCE
        and abs(int(profile_max) - int(cluster_max)) <= UNKNOWN_CHUNK_CLUSTER_SIZE_TOLERANCE
    )


def _build_missing_alias_candidate_sample(
    *,
    missing_files_by_bucket: dict[str, set[str]],
    status_counts: dict[str, Counter[str]],
    candidate_files_by_bucket: dict[str, set[str]],
    candidate_packages: dict[str, set[str]],
    field: str,
    limit: int | None = MAX_SAMPLE_ITEMS,
) -> list[dict[str, object]]:
    ranked_buckets: list[tuple[int, dict[str, object]]] = []

    for bucket_name, missing_files in sorted(
        missing_files_by_bucket.items(),
        key=lambda item: (-len(item[1]), item[0]),
    ):
        candidates: list[dict[str, object]] = []
        for candidate_name, candidate_files in candidate_files_by_bucket.items():
            overlap_files = sorted(missing_files & candidate_files)
            if not overlap_files:
                continue
            overlap_ratio = len(overlap_files) / len(missing_files) if missing_files else 0.0
            same_leaf_segment = _c3_bucket_leaf(bucket_name) == _c3_bucket_leaf(candidate_name)
            bucket_shape = _c3_bucket_family_shape(bucket_name)
            candidate_shape = _c3_bucket_family_shape(candidate_name)
            same_numeric_family_shape = bool(bucket_shape) and bucket_shape == candidate_shape
            if not _passes_c3_alias_candidate_threshold(
                overlap_count=len(overlap_files),
                overlap_ratio=overlap_ratio,
                same_leaf_segment=same_leaf_segment,
                same_numeric_family_shape=same_numeric_family_shape,
                field=field,
            ):
                continue
            score = _score_c3_alias_candidate(
                bucket_name=bucket_name,
                candidate_name=candidate_name,
                overlap_count=len(overlap_files),
                missing_count=len(missing_files),
                candidate_count=len(candidate_files),
                field=field,
            )
            candidates.append(
                {
                    field: candidate_name,
                    "packages": sorted(candidate_packages.get(candidate_name, set())),
                    "overlap_count": len(overlap_files),
                    "overlap_ratio": round(overlap_ratio, 4) if missing_files else None,
                    "candidate_unique_path_count": len(candidate_files),
                    "candidate_coverage_ratio": round(len(overlap_files) / len(candidate_files), 4) if candidate_files else None,
                    "same_leaf_segment": same_leaf_segment,
                    "same_numeric_family_shape": same_numeric_family_shape,
                    "filename_sample": overlap_files[:MAX_SAMPLE_ITEMS],
                    "score": score,
                }
            )

        candidates.sort(
            key=lambda item: (
                -int(item["score"]),
                -int(item["overlap_count"]),
                -(float(item["overlap_ratio"]) if isinstance(item["overlap_ratio"], float) else 0.0),
                str(item[field]).lower(),
            )
        )
        if not candidates:
            continue

        ranked_buckets.append(
            (
                int(candidates[0]["score"]),
                {
                    field: bucket_name,
                    "missing_unique_path_count": status_counts.get(bucket_name, Counter()).get("missing", len(missing_files)),
                    "filename_sample": sorted(missing_files)[:MAX_SAMPLE_ITEMS],
                    "replacement_candidates": [
                        {key: value for key, value in candidate.items() if key != "score"}
                        for candidate in candidates[:MAX_ALIAS_CANDIDATES]
                    ],
                },
            )
        )

    ranked_buckets.sort(
        key=lambda item: (
            -item[0],
            -int(item[1]["missing_unique_path_count"]),
            str(item[1][field]).lower(),
        )
    )

    sample = [
        bucket
        for _score, bucket in ranked_buckets[: limit if limit is not None else len(ranked_buckets)]
    ]

    return sample


def _passes_c3_alias_candidate_threshold(
    *,
    overlap_count: int,
    overlap_ratio: float,
    same_leaf_segment: bool,
    same_numeric_family_shape: bool,
    field: str,
) -> bool:
    if overlap_count < 2:
        return False
    if field == "branch":
        return overlap_ratio >= 0.25 or (same_leaf_segment and overlap_count >= 3)
    return overlap_ratio >= 0.2 or (same_numeric_family_shape and overlap_count >= 5)


def _score_c3_alias_candidate(
    *,
    bucket_name: str,
    candidate_name: str,
    overlap_count: int,
    missing_count: int,
    candidate_count: int,
    field: str,
) -> int:
    score = overlap_count * 1000
    score += int((overlap_count / missing_count) * 100) if missing_count else 0
    score += int((overlap_count / candidate_count) * 50) if candidate_count else 0

    bucket_shape = _c3_bucket_family_shape(bucket_name)
    candidate_shape = _c3_bucket_family_shape(candidate_name)
    if bucket_shape and bucket_shape == candidate_shape:
        score += 500

    if field == "branch" and _c3_bucket_leaf(bucket_name) == _c3_bucket_leaf(candidate_name):
        score += 15000

    return score


def _validated_alias_candidate_sample(
    alias_candidates: list[dict[str, object]],
    *,
    field: str,
) -> list[dict[str, object]]:
    validated: list[dict[str, object]] = []

    for bucket in alias_candidates:
        candidates = bucket.get("replacement_candidates", [])
        if not candidates:
            continue
        candidate = candidates[0]
        bucket_name = str(bucket[field])
        candidate_name = str(candidate[field])
        if candidate_name == bucket_name:
            continue
        if not _is_validated_alias_candidate(candidate, field=field):
            continue
        validated.append(bucket)

    return validated


def _is_validated_alias_candidate(candidate: dict[str, object], *, field: str) -> bool:
    overlap_count = int(candidate.get("overlap_count", 0))
    overlap_ratio = float(candidate.get("overlap_ratio", 0.0))
    same_leaf_segment = bool(candidate.get("same_leaf_segment"))
    same_numeric_family_shape = bool(candidate.get("same_numeric_family_shape"))

    if field == "branch":
        return same_leaf_segment and same_numeric_family_shape and overlap_count >= 8 and overlap_ratio >= 0.5

    return same_numeric_family_shape and overlap_count >= 20 and overlap_ratio >= 0.7


def _c3_bucket_leaf(name: str) -> str:
    parts = [part for part in name.split("/") if part]
    return parts[-1] if parts else ""


def _c3_bucket_family_shape(name: str) -> str:
    parts = [part for part in name.split("/") if part]
    family = parts[0] if parts else ""
    if family.isdigit():
        return f"digits:{len(family)}"
    return ""


def _relative_posix(path: Path, base: Path) -> str:
    return str(path.relative_to(base)).replace("\\", "/")
