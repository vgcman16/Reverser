from __future__ import annotations

import re
from pathlib import Path

from reverser.analysis.conquer_animation import summarize_conquer_animation_path


MAX_SAMPLE_ITEMS = 25
PUL_SIGNATURE = b"PUZZLE2\x00"
PUX_SIGNATURE = b"TqTerrain\x00"
PUL_PATH_SLICE = slice(8, 0x100)
PUZZLE_LABEL_PATTERN = re.compile(rb"Puzzle\d+")
ANIMATION_PATH_PATTERN = re.compile(rb"(?i)ani[\\/][ -~]{1,240}?\.ani")


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


def summarize_conquer_asset_path(asset_path: str, *, install_root: Path | None) -> dict[str, object]:
    resolved_path = resolve_conquer_asset_path(asset_path, install_root=install_root)
    payload: dict[str, object] = {
        "asset_path": asset_path,
        "resolved_path": str(resolved_path) if resolved_path else None,
        "exists": bool(resolved_path and resolved_path.exists()),
    }

    if resolved_path is None or not resolved_path.exists():
        return payload

    payload["resource_kind"] = resolved_path.suffix.lower().lstrip(".")

    if resolved_path.suffix.lower() == ".pul":
        summary = parse_pul_file(resolved_path)
        summary["referenced_animation"] = summarize_conquer_animation_path(
            str(summary["animation_path"]),
            install_root=install_root,
        )
        payload["summary"] = summary
    elif resolved_path.suffix.lower() == ".pux":
        summary = parse_pux_file(resolved_path)
        summary["referenced_animations_sample"] = [
            summarize_conquer_animation_path(animation_path, install_root=install_root)
            for animation_path in summary["animation_paths_sample"]
        ]
        payload["summary"] = summary

    return payload


def resolve_conquer_asset_path(asset_path: str, *, install_root: Path | None) -> Path | None:
    if not asset_path or install_root is None:
        return None

    normalized = asset_path.replace("\\", "/").lstrip("/")
    if not normalized:
        return None

    candidate = install_root / Path(normalized)
    return candidate


def parse_pul_file(path: Path) -> dict[str, object]:
    return parse_pul_bytes(path.read_bytes(), path=path)


def parse_pul_bytes(data: bytes, *, path: Path | None = None) -> dict[str, object]:
    if not data.startswith(PUL_SIGNATURE):
        raise ValueError("Not a Conquer .pul puzzle file.")

    animation_path = _decode_c_string(data[PUL_PATH_SLICE])
    return {
        "format": "conquer-online-puzzle",
        "resource_kind": "pul",
        "signature": "PUZZLE2",
        "path": str(path) if path else None,
        "file_size_bytes": len(data),
        "animation_path": animation_path,
        "animation_basename": Path(animation_path).name,
        "animation_extension": Path(animation_path).suffix.lower() or "<none>",
        "header_head_hex": data[:32].hex(),
    }


def parse_pux_file(path: Path) -> dict[str, object]:
    return parse_pux_bytes(path.read_bytes(), path=path)


def parse_pux_bytes(data: bytes, *, path: Path | None = None) -> dict[str, object]:
    if not data.startswith(PUX_SIGNATURE):
        raise ValueError("Not a Conquer .pux terrain file.")

    puzzle_labels = [match.decode("ascii", errors="replace") for match in PUZZLE_LABEL_PATTERN.findall(data)]
    animation_paths = _extract_unique_ascii_matches(ANIMATION_PATH_PATTERN, data)
    puzzle_indices = [_parse_puzzle_index(label) for label in puzzle_labels]
    valid_indices = [index for index in puzzle_indices if index is not None]

    return {
        "format": "conquer-online-puzzle",
        "resource_kind": "pux",
        "signature": "TqTerrain",
        "path": str(path) if path else None,
        "file_size_bytes": len(data),
        "u32_0x08": int.from_bytes(data[0x08:0x0C], "little"),
        "u32_0x0C": int.from_bytes(data[0x0C:0x10], "little"),
        "u32_0x10": int.from_bytes(data[0x10:0x14], "little"),
        "u32_0x14": int.from_bytes(data[0x14:0x18], "little"),
        "u32_0x18": int.from_bytes(data[0x18:0x1C], "little"),
        "u32_0x1C": int.from_bytes(data[0x1C:0x20], "little"),
        "u32_0x20": int.from_bytes(data[0x20:0x24], "little"),
        "animation_path_count": len(animation_paths),
        "animation_paths_sample": animation_paths[:MAX_SAMPLE_ITEMS],
        "puzzle_label_count": len(puzzle_labels),
        "puzzle_labels_sample": puzzle_labels[:MAX_SAMPLE_ITEMS],
        "max_puzzle_index": max(valid_indices) if valid_indices else None,
        "header_head_hex": data[:48].hex(),
    }


def summarize_conquer_puzzle_directory(target: Path, *, install_root: Path | None = None) -> dict[str, object]:
    resolved_install_root = install_root or find_conquer_install_root(target)
    if resolved_install_root is None:
        raise FileNotFoundError(f"No Conquer install root was found for {target}")

    pul_root = resolved_install_root / "map" / "puzzle"
    pux_root = resolved_install_root / "map" / "PuzzleSave"
    pul_files = sorted(path for path in pul_root.glob("*.pul") if path.is_file()) if pul_root.is_dir() else []
    pux_files = sorted(path for path in pux_root.glob("*.pux") if path.is_file()) if pux_root.is_dir() else []

    return {
        "format": "conquer-online-puzzle",
        "scope": "directory",
        "resource_kind": "puzzle-directory",
        "analyzed_path": str(target),
        "install_root": str(resolved_install_root),
        "pul_root": str(pul_root) if pul_root.is_dir() else None,
        "pux_root": str(pux_root) if pux_root.is_dir() else None,
        "pul_count": len(pul_files),
        "pux_count": len(pux_files),
        "pul_sample": [relative_posix(path, resolved_install_root) for path in pul_files[:MAX_SAMPLE_ITEMS]],
        "pux_sample": [relative_posix(path, resolved_install_root) for path in pux_files[:MAX_SAMPLE_ITEMS]],
    }


def relative_posix(path: Path, base: Path) -> str:
    return str(path.relative_to(base)).replace("\\", "/")


def _decode_c_string(raw: bytes) -> str:
    prefix = raw.split(b"\x00", 1)[0]
    return prefix.decode("utf-8", errors="replace")


def _extract_unique_ascii_matches(pattern: re.Pattern[bytes], data: bytes) -> list[str]:
    seen: set[str] = set()
    values: list[str] = []
    for match in pattern.findall(data):
        decoded = match.decode("ascii", errors="replace")
        if decoded in seen:
            continue
        seen.add(decoded)
        values.append(decoded)
    return values


def _parse_puzzle_index(label: str) -> int | None:
    try:
        return int(label.removeprefix("Puzzle"))
    except ValueError:
        return None
