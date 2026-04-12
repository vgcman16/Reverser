from __future__ import annotations

import configparser
import json
import shutil
import tempfile
from datetime import UTC, datetime
from pathlib import Path

from reverser import __version__
from reverser.analysis.conquer_puzzle import find_conquer_install_root, summarize_conquer_asset_path

try:
    import py7zr
    from py7zr.exceptions import PasswordRequired
except ImportError:  # pragma: no cover - runtime dependency guard
    py7zr = None
    PasswordRequired = ValueError


DMAP_PATH_SLICE = slice(8, 0x100)
DMAP_HEADER_MIN_BYTES = 0x118
MAX_SAMPLE_ITEMS = 25


def relative_posix(path: Path, base: Path) -> str:
    return str(path.relative_to(base)).replace("\\", "/")


def find_conquer_map_root(target: Path) -> Path | None:
    search_start = target if target.is_dir() else target.parent

    for candidate in [search_start, *search_start.parents]:
        nested_map = candidate / "map" / "map"
        if nested_map.is_dir():
            return nested_map
        if candidate.name.lower() == "map" and candidate.parent.name.lower() == "map":
            return candidate

    return None


def parse_dmap_header_bytes(data: bytes) -> dict[str, object]:
    if len(data) < DMAP_HEADER_MIN_BYTES:
        raise ValueError("DMap payload is too small to contain the expected header.")

    asset_path = _decode_c_string(data[DMAP_PATH_SLICE])
    version = int.from_bytes(data[0:4], "little")
    unknown_zero = int.from_bytes(data[4:8], "little")
    grid_width = int.from_bytes(data[0x10C:0x110], "little")
    grid_height = int.from_bytes(data[0x110:0x114], "little")
    header_flag = int.from_bytes(data[0x114:0x118], "little")

    return {
        "format": "conquer-online-map",
        "resource_kind": "dmap",
        "version": version,
        "asset_path": asset_path,
        "asset_extension": Path(asset_path).suffix.lower() or "<none>",
        "asset_basename": Path(asset_path).name,
        "grid_width": grid_width,
        "grid_height": grid_height,
        "u32_0x100": int.from_bytes(data[0x100:0x104], "little"),
        "u32_0x104": int.from_bytes(data[0x104:0x108], "little"),
        "u32_0x108": int.from_bytes(data[0x108:0x10C], "little"),
        "header_flag": header_flag,
        "reserved_u32_0x04": unknown_zero,
        "header_head_hex": data[:32].hex(),
    }


def parse_otherdata_file(path: Path) -> dict[str, object]:
    parser = configparser.ConfigParser(interpolation=None)
    parser.optionxform = str
    parser.read(path, encoding="utf-8")

    header = dict(parser.items("Header")) if parser.has_section("Header") else {}
    map_obj_total = 0
    sections_with_map_objects = 0
    for section_name in parser.sections():
        if parser.has_option(section_name, "MapObjAmount"):
            try:
                map_obj_total += parser.getint(section_name, "MapObjAmount")
                sections_with_map_objects += 1
            except ValueError:
                continue

    return {
        "format": "conquer-online-map",
        "resource_kind": "otherdata",
        "section_count": len(parser.sections()),
        "section_names_sample": parser.sections()[:MAX_SAMPLE_ITEMS],
        "header": header,
        "map_obj_total": map_obj_total,
        "sections_with_map_objects": sections_with_map_objects,
    }


def summarize_conquer_map_archive(path: Path) -> dict[str, object]:
    install_root = find_conquer_install_root(path)
    if py7zr is None:
        return {
            "format": "conquer-online-map",
            "resource_kind": "map-archive",
            "archive_path": str(path),
            "status": "missing-py7zr",
        }

    with py7zr.SevenZipFile(path, mode="r") as archive:
        entries = list(archive.list())
        member_names = [str(getattr(entry, "filename", "")) for entry in entries]
        dmap_members = [name for name in member_names if name.lower().endswith(".dmap")]

        payload: dict[str, object] = {
            "format": "conquer-online-map",
            "resource_kind": "map-archive",
            "archive_path": str(path),
            "member_count": len(member_names),
            "member_names": member_names[:MAX_SAMPLE_ITEMS],
            "dmap_member_count": len(dmap_members),
            "paired_otherdata_exists": path.with_suffix(".OtherData").exists(),
            "paired_otherdata_path": str(path.with_suffix(".OtherData")) if path.with_suffix(".OtherData").exists() else None,
            "status": "listed",
        }

        if not dmap_members:
            return payload

        primary_member = dmap_members[0]
        with tempfile.TemporaryDirectory() as tmp_dir:
            archive.reset()
            archive.extract(path=tmp_dir, targets=[primary_member])
            extracted_path = Path(tmp_dir) / Path(primary_member)
            if extracted_path.exists():
                payload["dmap"] = parse_dmap_header_bytes(extracted_path.read_bytes())
                payload["referenced_asset"] = summarize_conquer_asset_path(
                    str(payload["dmap"]["asset_path"]),
                    install_root=install_root,
                )
                payload["primary_dmap_member"] = primary_member

        return payload


def summarize_conquer_map_directory(target: Path, *, map_root: Path | None = None) -> dict[str, object]:
    resolved_map_root = map_root or find_conquer_map_root(target)
    if resolved_map_root is None:
        raise FileNotFoundError(f"No Conquer map root was found for {target}")

    archives = sorted(path for path in resolved_map_root.glob("*.7z") if path.is_file())
    otherdata_files = sorted(path for path in resolved_map_root.glob("*.OtherData") if path.is_file())
    direct_dmaps = sorted(
        path for path in resolved_map_root.iterdir() if path.is_file() and path.suffix.lower() == ".dmap"
    )
    paired_archives = [path for path in archives if path.with_suffix(".OtherData").exists()]

    return {
        "format": "conquer-online-map",
        "scope": "directory",
        "resource_kind": "map-directory",
        "analyzed_path": str(target),
        "map_root": str(resolved_map_root),
        "archive_count": len(archives),
        "otherdata_count": len(otherdata_files),
        "paired_archive_count": len(paired_archives),
        "direct_dmap_count": len(direct_dmaps),
        "archive_sample": [relative_posix(path, resolved_map_root) for path in archives[:MAX_SAMPLE_ITEMS]],
        "otherdata_sample": [relative_posix(path, resolved_map_root) for path in otherdata_files[:MAX_SAMPLE_ITEMS]],
        "paired_archive_sample": [
            {
                "archive": relative_posix(path, resolved_map_root),
                "otherdata": relative_posix(path.with_suffix(".OtherData"), resolved_map_root),
            }
            for path in paired_archives[:MAX_SAMPLE_ITEMS]
        ],
    }


def export_conquer_maps(
    source: str | Path,
    output_dir: str | Path,
    *,
    limit: int | None = None,
    include_archives: bool = False,
) -> dict[str, object]:
    target = Path(source).expanduser().resolve()
    if not target.exists():
        raise FileNotFoundError(f"Target does not exist: {target}")

    map_root = find_conquer_map_root(target)
    if map_root is None:
        raise FileNotFoundError(f"No Conquer map root was found for {target}")

    if target.is_file() and target.suffix.lower() == ".7z":
        archives = [target]
    else:
        archives = sorted(path for path in map_root.glob("*.7z") if path.is_file())

    selected_archives = archives[:limit] if limit is not None else archives
    destination = Path(output_dir).expanduser().resolve()
    destination.mkdir(parents=True, exist_ok=True)
    manifest_path = destination / "manifest.json"
    archives_copy_root = destination / "_archives"

    exported_maps: list[dict[str, object]] = []
    extracted_archive_count = 0
    paired_otherdata_count = 0
    warnings: list[str] = []

    for archive_path in selected_archives:
        entry = summarize_conquer_map_archive(archive_path)
        entry["relative_archive_path"] = relative_posix(archive_path, map_root)
        entry["status"] = str(entry.get("status", "unknown"))
        entry["output_root"] = None
        entry["copied_archive_path"] = None
        entry["copied_otherdata_path"] = None
        entry["extracted_files"] = []

        if include_archives:
            copied_archive_path = archives_copy_root / relative_posix(archive_path, map_root)
            copied_archive_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(archive_path, copied_archive_path)
            entry["copied_archive_path"] = str(copied_archive_path)

        if py7zr is None:
            exported_maps.append(entry)
            continue

        if entry["status"] != "listed":
            warnings.append(f"Skipping {archive_path.name}: archive status {entry['status']}.")
            exported_maps.append(entry)
            continue

        archive_output_root = destination / archive_path.stem
        archive_output_root.mkdir(parents=True, exist_ok=True)
        entry["output_root"] = str(archive_output_root)

        try:
            with py7zr.SevenZipFile(archive_path, mode="r") as archive:
                archive.extractall(path=archive_output_root)
        except PasswordRequired:
            entry["status"] = "password-required"
            warnings.append(f"Skipping {archive_path.name}: password required.")
            exported_maps.append(entry)
            continue

        extracted_archive_count += 1
        extracted_files = sorted(path for path in archive_output_root.rglob("*") if path.is_file())
        entry["extracted_files"] = [relative_posix(path, archive_output_root) for path in extracted_files[:MAX_SAMPLE_ITEMS]]
        entry["extracted_file_count"] = len(extracted_files)

        otherdata_path = archive_path.with_suffix(".OtherData")
        if otherdata_path.exists():
            copied_otherdata_path = archive_output_root / otherdata_path.name
            shutil.copy2(otherdata_path, copied_otherdata_path)
            entry["copied_otherdata_path"] = str(copied_otherdata_path)
            entry["otherdata"] = parse_otherdata_file(otherdata_path)
            paired_otherdata_count += 1

        dmap_outputs = [path for path in extracted_files if path.suffix.lower() == ".dmap"]
        if dmap_outputs and "dmap" not in entry:
            entry["dmap"] = parse_dmap_header_bytes(dmap_outputs[0].read_bytes())
        if entry.get("dmap"):
            entry["referenced_asset"] = summarize_conquer_asset_path(
                str(entry["dmap"]["asset_path"]),
                install_root=find_conquer_install_root(archive_path),
            )

        exported_maps.append(entry)

    manifest = {
        "report_version": "1.0",
        "tool": {
            "name": "reverser-workbench",
            "version": __version__,
        },
        "generated_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "source_path": str(target),
        "map_root": str(map_root),
        "export_root": str(destination),
        "manifest_path": str(manifest_path),
        "settings": {
            "limit": limit,
            "include_archives": include_archives,
        },
        "summary": {
            "available_archive_count": len(archives),
            "selected_archive_count": len(selected_archives),
            "exported_archive_count": extracted_archive_count,
            "paired_otherdata_count": paired_otherdata_count,
        },
        "warnings": warnings,
        "maps": exported_maps,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def _decode_c_string(raw: bytes) -> str:
    prefix = raw.split(b"\x00", 1)[0]
    return prefix.decode("utf-8", errors="replace")
