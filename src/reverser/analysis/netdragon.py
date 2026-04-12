from __future__ import annotations

import hashlib
import json
import struct
import zlib
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path

from reverser import __version__
from reverser.analysis.conquer_c3 import parse_conquer_c3_bytes


NETDRAGON_MAGIC = b"NetDragonDatPkg\x00"
NETDRAGON_INDEX_HEADER_SIZE = 0x30
NETDRAGON_ENTRY = struct.Struct("<HIIIII")
NETDRAGON_SHORT_ENTRY = struct.Struct("<HII")
NETDRAGON_METHOD2_EXTRA = struct.Struct("<III")
NETDRAGON_SAMPLE_LIMIT = 8
NETDRAGON_MAX_PROBE_BYTES = 2 * 1024 * 1024


@dataclass(slots=True)
class NetDragonEntry:
    path: str
    method: int
    allocation_size_bytes: int
    stored_size_bytes: int
    compressed_size_bytes: int
    decoded_size_bytes: int
    offset_bytes: int
    index_offset_bytes: int
    extra_fields: tuple[int, ...] = ()

    @property
    def extension(self) -> str:
        return Path(self.path).suffix.lower() or "<none>"

    @property
    def root(self) -> str:
        normalized = self.path.replace("\\", "/").strip("/")
        parts = normalized.split("/", 1)
        return parts[0].lower() if parts and parts[0] else "<root>"

    def to_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "method": self.method,
            "allocation_size_bytes": self.allocation_size_bytes,
            "stored_size_bytes": self.stored_size_bytes,
            "compressed_size_bytes": self.compressed_size_bytes,
            "decoded_size_bytes": self.decoded_size_bytes,
            "offset_bytes": self.offset_bytes,
            "extra_fields": list(self.extra_fields),
        }


def normalize_netdragon_path(raw_path: str) -> str:
    return raw_path.replace("\\", "/").strip("/").lower()


def looks_like_netdragon_package(path: Path) -> bool:
    if not path.is_file():
        return False
    with path.open("rb") as handle:
        return handle.read(len(NETDRAGON_MAGIC)) == NETDRAGON_MAGIC


def resolve_netdragon_pair(target: Path) -> tuple[Path | None, Path | None]:
    suffix = target.suffix.lower()
    sibling_tpi = target.with_suffix(".tpi")
    sibling_tpd = target.with_suffix(".tpd")

    if suffix == ".tpi":
        return target, sibling_tpd if sibling_tpd.exists() else None
    if suffix == ".tpd":
        return (sibling_tpi if sibling_tpi.exists() else None), target
    if sibling_tpi.exists() and sibling_tpd.exists():
        return sibling_tpi, sibling_tpd
    return None, None


def parse_netdragon_index(index_path: Path) -> tuple[dict[str, int | str], list[NetDragonEntry], list[str]]:
    data = index_path.read_bytes()
    if not data.startswith(NETDRAGON_MAGIC):
        raise ValueError(f"Not a NetDragon package index: {index_path}")
    if len(data) < NETDRAGON_INDEX_HEADER_SIZE:
        raise ValueError(f"NetDragon index is too small: {index_path}")

    table_offset = int.from_bytes(data[0x20:0x24], "little")
    table_size = int.from_bytes(data[0x28:0x2C], "little")
    if table_offset <= 0:
        table_offset = NETDRAGON_INDEX_HEADER_SIZE
    if table_size <= 0:
        table_size = max(0, len(data) - table_offset)

    table_end = min(len(data), table_offset + table_size)
    header = {
        "magic": NETDRAGON_MAGIC.rstrip(b"\x00").decode("ascii", errors="replace"),
        "version": int.from_bytes(data[0x10:0x14], "little"),
        "header_value_0x14": int.from_bytes(data[0x14:0x18], "little"),
        "header_value_0x18": int.from_bytes(data[0x18:0x1C], "little"),
        "header_value_0x1c": int.from_bytes(data[0x1C:0x20], "little"),
        "table_offset": table_offset,
        "table_size": table_size,
    }

    entries: list[NetDragonEntry] = []
    warnings: list[str] = []
    position = table_offset

    while position < table_end:
        if table_end - position < 1 + NETDRAGON_ENTRY.size:
            warnings.append(f"Trailing bytes remain at 0x{position:x}; stopping parse.")
            break

        name_length = data[position]
        position += 1
        if name_length == 0:
            warnings.append(f"Zero-length path encountered at 0x{position - 1:x}; stopping parse.")
            break

        if position + name_length + 2 > table_end:
            warnings.append(f"Path at 0x{position - 1:x} overruns the declared table; stopping parse.")
            break

        raw_path = data[position : position + name_length]
        position += name_length
        path = _decode_netdragon_path(raw_path)
        if path is None:
            warnings.append(f"Undecodable path bytes encountered at 0x{position - name_length:x}; stopping parse.")
            break
        metadata_offset = position
        method = int.from_bytes(data[position : position + 2], "little")
        extra_fields: tuple[int, ...] = ()

        if method == 0:
            if position + NETDRAGON_SHORT_ENTRY.size > table_end:
                warnings.append(f"Method-0 metadata overruns the declared table at 0x{position:x}; stopping parse.")
                break
            method, allocation, stored = NETDRAGON_SHORT_ENTRY.unpack_from(data, position)
            compressed = 0
            decoded = 0
            offset = 0
            position += NETDRAGON_SHORT_ENTRY.size
        else:
            if position + NETDRAGON_ENTRY.size > table_end:
                warnings.append(f"Metadata overruns the declared table at 0x{position:x}; stopping parse.")
                break
            method, allocation, stored, compressed, decoded, offset = NETDRAGON_ENTRY.unpack_from(data, position)
            position += NETDRAGON_ENTRY.size

            if method == 2:
                if position + NETDRAGON_METHOD2_EXTRA.size > table_end:
                    warnings.append(f"Method-2 metadata overruns the declared table at 0x{position:x}; stopping parse.")
                    break
                extra_fields = NETDRAGON_METHOD2_EXTRA.unpack_from(data, position)
                position += NETDRAGON_METHOD2_EXTRA.size

        entries.append(
            NetDragonEntry(
                path=path,
                method=method,
                allocation_size_bytes=allocation,
                stored_size_bytes=stored,
                compressed_size_bytes=compressed,
                decoded_size_bytes=decoded,
                offset_bytes=offset,
                index_offset_bytes=metadata_offset,
                extra_fields=extra_fields,
            )
        )

    return header, entries, warnings


def summarize_netdragon_package(
    index_path: Path,
    data_path: Path | None = None,
    *,
    sample_limit: int = 12,
) -> dict[str, object]:
    header, entries, warnings = parse_netdragon_index(index_path)
    top_extensions = Counter(entry.extension for entry in entries)
    top_roots = Counter(entry.root for entry in entries)
    methods = Counter(entry.method for entry in entries)
    paired_data_size = data_path.stat().st_size if data_path and data_path.exists() else None

    largest_entries = sorted(entries, key=lambda item: item.decoded_size_bytes, reverse=True)
    payload = {
        "format": "netdragon-datpkg",
        "index_path": str(index_path),
        "data_path": str(data_path) if data_path else None,
        "header": header,
        "entry_count": len(entries),
        "parse_warnings": warnings[:10],
        "parse_warning_count": len(warnings),
        "compression_methods": [
            {"method": method, "count": count}
            for method, count in methods.most_common(10)
        ],
        "top_extensions": [
            {"extension": extension, "count": count}
            for extension, count in top_extensions.most_common(10)
        ],
        "top_roots": [
            {"root": root, "count": count}
            for root, count in top_roots.most_common(10)
        ],
        "stored_bytes": sum(entry.stored_size_bytes for entry in entries),
        "compressed_bytes": sum(entry.compressed_size_bytes for entry in entries),
        "decoded_bytes": sum(entry.decoded_size_bytes for entry in entries),
        "paired_data_size_bytes": paired_data_size,
        "sample_entries": [entry.to_dict() for entry in entries[:sample_limit]],
        "largest_entries": [entry.to_dict() for entry in largest_entries[:sample_limit]],
        "decode_probe": _probe_netdragon_entries(entries, data_path),
    }
    c3_probe = _probe_conquer_c3_entries(entries, data_path)
    if c3_probe is not None:
        payload["c3_probe"] = c3_probe

    if paired_data_size is not None:
        payload["out_of_range_entries"] = sum(
            1 for entry in entries if entry.offset_bytes + entry.stored_size_bytes > paired_data_size
        )

    return payload


def export_netdragon_package(
    source: str | Path,
    output_dir: str | Path,
    *,
    limit: int | None = None,
    include_stored: bool = False,
) -> dict[str, object]:
    target = Path(source)
    index_path, data_path = resolve_netdragon_pair(target)
    if not index_path or not index_path.exists():
        raise FileNotFoundError(f"No sibling .tpi index was found for {target}")
    if not data_path or not data_path.exists():
        raise FileNotFoundError(f"No sibling .tpd data package was found for {target}")

    destination = Path(output_dir)
    destination.mkdir(parents=True, exist_ok=True)

    header, entries, warnings = parse_netdragon_index(index_path)
    selected_entries = entries[:limit] if limit is not None else entries
    manifest_path = destination / "manifest.json"
    stored_root = destination / "_stored"

    exported_entries: list[dict[str, object]] = []
    decoded_count = 0
    raw_count = 0
    skipped_count = 0
    data_size = data_path.stat().st_size

    with data_path.open("rb") as handle:
        for entry in selected_entries:
            result = {
                "path": entry.path,
                "method": entry.method,
                "allocation_size_bytes": entry.allocation_size_bytes,
                "stored_size_bytes": entry.stored_size_bytes,
                "compressed_size_bytes": entry.compressed_size_bytes,
                "decoded_size_bytes": entry.decoded_size_bytes,
                "offset_bytes": entry.offset_bytes,
                "extra_fields": list(entry.extra_fields),
                "output_path": None,
                "stored_path": None,
            }

            if entry.stored_size_bytes <= 0:
                result["status"] = "placeholder"
                skipped_count += 1
                exported_entries.append(result)
                continue

            if entry.offset_bytes + entry.stored_size_bytes > data_size:
                result["status"] = "out-of-range"
                skipped_count += 1
                exported_entries.append(result)
                continue

            handle.seek(entry.offset_bytes)
            stored_blob = handle.read(entry.stored_size_bytes)
            if include_stored:
                stored_path = stored_root / _safe_relative_netdragon_path(entry.path)
                stored_path = stored_path.with_name(stored_path.name + ".stored.bin")
                stored_path.parent.mkdir(parents=True, exist_ok=True)
                stored_path.write_bytes(stored_blob)
                result["stored_path"] = str(stored_path)

            try:
                decoded_blob = zlib.decompress(stored_blob)
            except zlib.error:
                decoded_blob = stored_blob
                result["status"] = "raw"
                raw_count += 1
                result["decoded"] = False
                result["decoded_size_matches"] = False
            else:
                result["status"] = "decoded"
                decoded_count += 1
                result["decoded"] = True
                result["decoded_size_matches"] = len(decoded_blob) == entry.decoded_size_bytes

            output_path = destination / _safe_relative_netdragon_path(entry.path)
            output_path.parent.mkdir(parents=True, exist_ok=True)
            output_path.write_bytes(decoded_blob)
            result["output_path"] = str(output_path)
            result["output_sha256"] = hashlib.sha256(decoded_blob).hexdigest()
            result["output_size_bytes"] = len(decoded_blob)
            exported_entries.append(result)

    manifest = {
        "report_version": "1.0",
        "tool": {
            "name": "reverser-workbench",
            "version": __version__,
        },
        "generated_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "source_path": str(target),
        "index_path": str(index_path),
        "data_path": str(data_path),
        "export_root": str(destination),
        "manifest_path": str(manifest_path),
        "settings": {
            "limit": limit,
            "include_stored": include_stored,
        },
        "header": header,
        "summary": {
            "entry_count": len(entries),
            "exported_entry_count": len(exported_entries),
            "decoded_count": decoded_count,
            "raw_count": raw_count,
            "skipped_count": skipped_count,
        },
        "warnings": warnings,
        "entries": exported_entries,
    }
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def build_netdragon_entry_lookup(index_path: str | Path) -> dict[str, NetDragonEntry]:
    resolved_path = str(Path(index_path).expanduser().resolve())
    return _build_netdragon_entry_lookup_cached(resolved_path)


def read_netdragon_entry_bytes(data_path: str | Path, entry: NetDragonEntry) -> tuple[bytes, bool]:
    resolved_data_path = Path(data_path).expanduser().resolve()
    data_size = resolved_data_path.stat().st_size
    if entry.stored_size_bytes <= 0:
        return b"", False
    if entry.offset_bytes + entry.stored_size_bytes > data_size:
        raise ValueError(f"NetDragon entry {entry.path} points beyond {resolved_data_path.name}.")

    with resolved_data_path.open("rb") as handle:
        handle.seek(entry.offset_bytes)
        stored_blob = handle.read(entry.stored_size_bytes)

    try:
        return zlib.decompress(stored_blob), True
    except zlib.error:
        return stored_blob, False


def _probe_netdragon_entries(entries: list[NetDragonEntry], data_path: Path | None) -> dict[str, object]:
    if not data_path or not data_path.exists():
        return {
            "probed_entries": 0,
            "decoded_entries": 0,
            "samples": [],
            "status": "missing-data-package",
        }

    samples: list[dict[str, object]] = []
    decoded_entries = 0

    with data_path.open("rb") as handle:
        for entry in _select_probe_entries(entries):
            if entry.stored_size_bytes <= 0 or entry.stored_size_bytes > NETDRAGON_MAX_PROBE_BYTES:
                continue

            handle.seek(entry.offset_bytes)
            blob = handle.read(entry.stored_size_bytes)
            sample = {
                "path": entry.path,
                "method": entry.method,
                "stored_size_bytes": entry.stored_size_bytes,
                "decoded_size_bytes": entry.decoded_size_bytes,
                "raw_head_hex": blob[:16].hex(),
            }

            try:
                decoded = zlib.decompress(blob)
            except zlib.error:
                sample["decoded"] = False
                sample["decoded_head_hex"] = ""
            else:
                decoded_entries += 1
                sample["decoded"] = True
                sample["decoded_head_hex"] = decoded[:16].hex()
                sample["decoded_size_matches"] = len(decoded) == entry.decoded_size_bytes

            samples.append(sample)
            if len(samples) >= NETDRAGON_SAMPLE_LIMIT:
                break

    return {
        "probed_entries": len(samples),
        "decoded_entries": decoded_entries,
        "samples": samples,
        "status": "ok",
    }


def _select_probe_entries(entries: list[NetDragonEntry]) -> list[NetDragonEntry]:
    selected: list[NetDragonEntry] = []
    seen_methods: set[int] = set()

    for entry in entries:
        if entry.method not in seen_methods:
            selected.append(entry)
            seen_methods.add(entry.method)
        if len(selected) >= NETDRAGON_SAMPLE_LIMIT:
            return selected

    for entry in entries:
        if entry in selected:
            continue
        selected.append(entry)
        if len(selected) >= NETDRAGON_SAMPLE_LIMIT:
            break

    return selected


def _probe_conquer_c3_entries(entries: list[NetDragonEntry], data_path: Path | None) -> dict[str, object] | None:
    c3_entries = [entry for entry in entries if entry.extension == ".c3"]
    if not c3_entries:
        return None
    if not data_path or not data_path.exists():
        return {
            "status": "missing-data-package",
            "c3_entry_count": len(c3_entries),
            "probed_entries": 0,
            "samples": [],
        }

    samples: list[dict[str, object]] = []
    top_tags: Counter[str] = Counter()
    object_names: Counter[str] = Counter()
    texture_references: Counter[str] = Counter()

    for entry in _select_c3_probe_entries(c3_entries):
        try:
            decoded_bytes, _decoded = read_netdragon_entry_bytes(data_path, entry)
        except ValueError:
            continue
        try:
            summary = parse_conquer_c3_bytes(decoded_bytes, source_path=entry.path)
        except ValueError:
            continue

        top_tag = summary.get("top_tag")
        if isinstance(top_tag, str) and top_tag:
            top_tags[top_tag] += 1
        object_name = summary.get("object_name")
        if isinstance(object_name, str) and object_name:
            object_names[object_name] += 1
        for reference in summary.get("texture_reference_sample", []):
            if isinstance(reference, str):
                texture_references[reference] += 1

        samples.append(summary)
        if len(samples) >= NETDRAGON_SAMPLE_LIMIT:
            break

    return {
        "status": "ok",
        "c3_entry_count": len(c3_entries),
        "probed_entries": len(samples),
        "top_tags": [
            {"tag": tag, "count": count}
            for tag, count in top_tags.most_common(NETDRAGON_SAMPLE_LIMIT)
        ],
        "object_name_sample": [
            {"name": name, "count": count}
            for name, count in object_names.most_common(NETDRAGON_SAMPLE_LIMIT)
        ],
        "texture_reference_sample": [
            {"path": path, "count": count}
            for path, count in texture_references.most_common(NETDRAGON_SAMPLE_LIMIT)
        ],
        "samples": samples,
    }


def _select_c3_probe_entries(entries: list[NetDragonEntry]) -> list[NetDragonEntry]:
    selected: list[NetDragonEntry] = []
    seen_prefixes: set[str] = set()

    for entry in entries:
        normalized = entry.path.replace("\\", "/").strip("/")
        prefix = "/".join(normalized.split("/")[:3]).lower()
        if prefix in seen_prefixes:
            continue
        selected.append(entry)
        seen_prefixes.add(prefix)
        if len(selected) >= NETDRAGON_SAMPLE_LIMIT:
            return selected

    for entry in entries:
        if entry in selected:
            continue
        selected.append(entry)
        if len(selected) >= NETDRAGON_SAMPLE_LIMIT:
            break

    return selected


@lru_cache(maxsize=8)
def _build_netdragon_entry_lookup_cached(index_path: str) -> dict[str, NetDragonEntry]:
    _, entries, _ = parse_netdragon_index(Path(index_path))
    return {normalize_netdragon_path(entry.path): entry for entry in entries}


def _decode_netdragon_path(raw_path: bytes) -> str | None:
    for encoding in ("utf-8", "gb18030", "latin-1"):
        try:
            return raw_path.decode(encoding)
        except UnicodeDecodeError:
            continue
    return None


def _safe_relative_netdragon_path(raw_path: str) -> Path:
    normalized = raw_path.replace("\\", "/").lstrip("/")
    candidate = Path(normalized)
    safe_parts = [part for part in candidate.parts if part not in {"", ".", ".."}]
    if not safe_parts:
        return Path("unnamed.bin")
    return Path(*safe_parts)
