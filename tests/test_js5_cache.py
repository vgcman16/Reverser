from __future__ import annotations

import bz2
import gzip
import json
import lzma
import sqlite3
from pathlib import Path

import reverser.analysis.js5 as js5_module
from reverser.analysis.js5 import (
    _build_clientscript_effective_semantic_suggestions,
    _build_clientscript_pseudocode_profile_status,
    _combine_clientscript_control_flow_candidates,
    _build_clientscript_control_flow_candidates,
    _build_clientscript_contextual_frontier_candidates,
    _build_clientscript_semantic_suggestions,
    _build_clientscript_string_transform_arity_candidates,
    _build_clientscript_string_transform_frontier_candidates,
    _decode_clientscript_metadata,
    _format_clientscript_expression,
    _infer_clientscript_frontier_candidate,
    _infer_clientscript_produced_expression,
    _infer_clientscript_stack_effect,
    _infer_clientscript_widget_operand_signature,
    _infer_clientscript_contextual_frontier_candidate,
    _merge_clientscript_catalog_entry,
    _promote_clientscript_control_flow_candidates,
    _promote_clientscript_string_frontier_candidates,
    _refine_clientscript_consumed_operand_payload_candidate,
    _refine_clientscript_consumed_operand_role_candidate,
    _refine_clientscript_frontier_state_reader_candidate,
    _refine_clientscript_string_payload_frontier_candidate,
    _refine_clientscript_switch_case_payload_candidate,
    _refine_clientscript_widget_mutator_candidate,
    _resolve_clientscript_contextual_frontier_passes,
    _seed_clientscript_catalog_with_semantic_overrides,
    _summarize_clientscript_pseudocode_blockers,
    _summarize_clientscript_consumed_operand_window,
    _summarize_clientscript_prefix_stack_state,
    export_js5_cache,
    profile_archive_file,
)
from reverser.analysis.orchestrator import AnalysisEngine


def _build_js5_record(payload: bytes, *, compression: str, revision: int = 1) -> bytes:
    if compression == "lzma":
        lc = 3
        lp = 0
        pb = 2
        dict_size = 1 << 20
        packed = lzma.compress(
            payload,
            format=lzma.FORMAT_RAW,
            filters=[
                {
                    "id": lzma.FILTER_LZMA1,
                    "dict_size": dict_size,
                    "lc": lc,
                    "lp": lp,
                    "pb": pb,
                }
            ],
        )
        property_byte = pb * 45 + lp * 9 + lc
        props = bytes([property_byte]) + dict_size.to_bytes(4, "little")
        packed = props + packed
        return b"\x03" + len(packed).to_bytes(4, "big") + len(payload).to_bytes(4, "big") + packed + revision.to_bytes(2, "big")

    if compression == "gzip":
        packed = gzip.compress(payload)
        return b"\x02" + len(packed).to_bytes(4, "big") + len(payload).to_bytes(4, "big") + packed + revision.to_bytes(2, "big")

    if compression == "bzip2":
        packed = bz2.compress(payload)
        stripped = packed[4:]
        return b"\x01" + len(stripped).to_bytes(4, "big") + len(payload).to_bytes(4, "big") + stripped + revision.to_bytes(2, "big")

    return b"\x00" + len(payload).to_bytes(4, "big") + payload + revision.to_bytes(2, "big")


def _write_js5_mapping(root: Path, *, build: int, index_names: dict[int, str]) -> None:
    mapping_path = root / "data" / "prot" / str(build) / "generated" / "shared" / "js5-archive-resolution.json"
    mapping_path.parent.mkdir(parents=True, exist_ok=True)
    mapping_path.write_text(
        json.dumps(
            {
                "build": build,
                "indexNames": {str(key): value for key, value in index_names.items()},
            }
        ),
        encoding="utf-8",
    )


def _write_clientscript_semantics(root: Path, *, build: int, opcodes: dict[str, dict[str, object]]) -> None:
    mapping_path = root / "data" / "prot" / str(build) / "generated" / "shared" / "clientscript-opcode-semantics.json"
    mapping_path.parent.mkdir(parents=True, exist_ok=True)
    mapping_path.write_text(
        json.dumps(
            {
                "build": build,
                "opcodes": opcodes,
            }
        ),
        encoding="utf-8",
    )


def _put_smart_int(value: int) -> bytes:
    if value >= 0x7FFF:
        encoded = value | 0x80000000
        return encoded.to_bytes(4, "big", signed=False)
    return value.to_bytes(2, "big", signed=False)


def _build_reference_table(archives: dict[int, list[int]], *, format_version: int = 7, table_version: int = 1) -> bytes:
    payload = bytearray()
    payload.append(format_version)
    if format_version >= 6:
        payload.extend(table_version.to_bytes(4, "big"))
    payload.append(0)
    archive_ids = sorted(archives)
    payload.extend(_put_smart_int(len(archive_ids)))

    previous_archive = 0
    for archive_id in archive_ids:
        payload.extend(_put_smart_int(archive_id - previous_archive))
        previous_archive = archive_id

    for _archive_id in archive_ids:
        payload.extend((0).to_bytes(4, "big"))
    for _archive_id in archive_ids:
        payload.extend((1).to_bytes(4, "big"))
    for archive_id in archive_ids:
        file_ids = archives[archive_id]
        payload.extend(_put_smart_int(len(file_ids)))
    for archive_id in archive_ids:
        file_ids = archives[archive_id]
        previous_file = 0
        for file_id in file_ids:
            payload.extend(_put_smart_int(file_id - previous_file))
            previous_file = file_id

    return bytes(payload)


def _build_grouped_archive(files: dict[int, bytes]) -> bytes:
    ordered = [files[file_id] for file_id in sorted(files)]
    payload = bytearray()
    for data in ordered:
        payload.extend(data)
    previous_size = 0
    for data in ordered:
        payload.extend((len(data) - previous_size).to_bytes(4, "big", signed=True))
        previous_size = len(data)
    payload.append(1)
    return bytes(payload)


def _build_enum_definition(key_type_id: int, value_type_id: int, values: dict[int, object]) -> bytes:
    payload = bytearray()
    payload.append(101)
    payload.append(key_type_id)
    payload.append(102)
    payload.append(value_type_id)

    string_values = all(isinstance(value, str) for value in values.values())
    payload.append(5 if string_values else 6)
    payload.extend(len(values).to_bytes(2, "big"))
    for key, value in values.items():
        payload.extend(int(key).to_bytes(4, "big", signed=True))
        if string_values:
            payload.extend(str(value).encode("cp1252"))
            payload.append(0)
        else:
            payload.extend(int(value).to_bytes(4, "big", signed=True))
    payload.append(0)
    return bytes(payload)


def _build_varbit_definition(base_var: int, least_significant_bit: int, most_significant_bit: int) -> bytes:
    payload = bytearray()
    payload.append(1)
    payload.extend(base_var.to_bytes(2, "big"))
    payload.append(least_significant_bit)
    payload.append(most_significant_bit)
    payload.append(0)
    return bytes(payload)


def _build_var_definition(*, type_id: int, lifetime: int = 0, force_default: bool = True) -> bytes:
    payload = bytearray()
    payload.append(101)
    payload.append(type_id)
    if lifetime:
        payload.append(2)
        payload.append(lifetime)
    if not force_default:
        payload.append(4)
    payload.append(0)
    return bytes(payload)


def _build_object_definition(
    *,
    name: str | None = None,
    actions: list[str | None] | None = None,
    size_x: int | None = None,
    size_y: int | None = None,
    animation_id: int | None = None,
) -> bytes:
    payload = bytearray()
    if name:
        payload.append(2)
        payload.extend(name.encode("cp1252"))
        payload.append(0)
    if size_x is not None:
        payload.append(14)
        payload.append(int(size_x))
    if size_y is not None:
        payload.append(15)
        payload.append(int(size_y))
    if animation_id is not None:
        payload.append(24)
        payload.extend(int(animation_id).to_bytes(2, "big"))
    for index, action in enumerate(actions or []):
        if index >= 5:
            break
        if action:
            payload.append(30 + index)
            payload.extend(str(action).encode("cp1252"))
            payload.append(0)
    payload.append(0)
    return bytes(payload)


def _build_sprite_archive(
    *,
    canvas_width: int,
    canvas_height: int,
    palette: list[int],
    sprites: list[dict[str, object]],
) -> bytes:
    pixel_section = bytearray()
    for sprite in sprites:
        width = int(sprite["width"])
        height = int(sprite["height"])
        indices = bytes(sprite["indices"])
        if len(indices) != width * height:
            raise ValueError("sprite indices length does not match dimensions")
        alpha = sprite.get("alpha")
        flags = 0
        if alpha is not None:
            alpha_bytes = bytes(alpha)
            if len(alpha_bytes) != width * height:
                raise ValueError("sprite alpha length does not match dimensions")
            flags |= 0x2
        else:
            alpha_bytes = b""
        pixel_section.append(flags)
        pixel_section.extend(indices)
        pixel_section.extend(alpha_bytes)

    palette_section = bytearray()
    for color in palette[1:]:
        palette_section.extend(int(color).to_bytes(3, "big"))

    footer = bytearray()
    footer.extend(canvas_width.to_bytes(2, "big"))
    footer.extend(canvas_height.to_bytes(2, "big"))
    footer.append(len(palette) - 1)
    for key in ("offset_x", "offset_y", "width", "height"):
        for sprite in sprites:
            footer.extend(int(sprite[key]).to_bytes(2, "big"))
    footer.extend(len(sprites).to_bytes(2, "big"))
    return bytes(pixel_section + palette_section + footer)


def _build_clientscript_payload(
    *,
    instruction_count: int,
    local_int_count: int = 0,
    local_string_count: int = 0,
    local_long_count: int = 0,
    int_argument_count: int = 0,
    string_argument_count: int = 0,
    long_argument_count: int = 0,
    switch_tables: list[dict[int, int]] | None = None,
    byte0: int = 0,
    body_bytes: bytes = b"",
) -> bytes:
    switch_tables = switch_tables or []
    switch_payload = bytearray()
    switch_payload.append(len(switch_tables))
    for table in switch_tables:
        switch_payload.extend(len(table).to_bytes(2, "big"))
        for key, offset in table.items():
            switch_payload.extend(int(key).to_bytes(4, "big", signed=True))
            switch_payload.extend(int(offset).to_bytes(4, "big", signed=True))

    footer = bytearray()
    footer.extend(int(instruction_count).to_bytes(4, "big"))
    footer.extend(int(local_int_count).to_bytes(2, "big"))
    footer.extend(int(local_string_count).to_bytes(2, "big"))
    footer.extend(int(local_long_count).to_bytes(2, "big"))
    footer.extend(int(int_argument_count).to_bytes(2, "big"))
    footer.extend(int(string_argument_count).to_bytes(2, "big"))
    footer.extend(int(long_argument_count).to_bytes(2, "big"))

    return (
        bytes([int(byte0) & 0xFF])
        + body_bytes
        + bytes(footer)
        + bytes(switch_payload)
        + len(switch_payload).to_bytes(2, "big")
    )


def _encode_clientscript_instruction(raw_opcode: int, immediate_kind: str, value: object) -> bytes:
    payload = bytearray()
    payload.extend(int(raw_opcode).to_bytes(2, "big"))
    if immediate_kind == "short":
        payload.extend(int(value).to_bytes(2, "big", signed=True))
    elif immediate_kind == "byte":
        payload.append(int(value) & 0xFF)
    elif immediate_kind == "int":
        payload.extend(int(value).to_bytes(4, "big", signed=True))
    elif immediate_kind == "tribyte":
        payload.extend(int(value).to_bytes(3, "big", signed=False))
    elif immediate_kind == "string":
        payload.extend(str(value).encode("cp1252"))
        payload.append(0)
    elif immediate_kind == "switch-int":
        payload.append(0)
        payload.extend(int(value).to_bytes(4, "big", signed=True))
    elif immediate_kind == "switch-string":
        payload.append(2)
        payload.extend(str(value).encode("cp1252"))
        payload.append(0)
    else:
        raise ValueError(f"unsupported immediate kind: {immediate_kind}")
    return bytes(payload)


def _build_rt7_model_payload(
    *,
    positions: list[tuple[int, int, int]],
    indices: list[int],
    material_argument: int = 1,
    format_id: int = 2,
    version: int = 5,
) -> bytes:
    vertex_count = len(positions)
    face_count = 0
    mesh_count = 1
    group_flags = 0x01

    payload = bytearray()
    payload.extend(
        bytes(
            [
                format_id,
                version,
                0x0F,
                mesh_count,
                0,
                0,
                0,
                0,
                0,
                group_flags,
                0,
            ]
        )
    )
    payload.extend(face_count.to_bytes(2, "little"))
    payload.extend(vertex_count.to_bytes(4, "little"))
    for x, y, z in positions:
        payload.extend(int(x).to_bytes(2, "little", signed=True))
        payload.extend(int(y).to_bytes(2, "little", signed=True))
        payload.extend(int(z).to_bytes(2, "little", signed=True))
    for _ in positions:
        payload.extend(bytes([0, 127, 0]))
    for _ in positions:
        payload.extend((0).to_bytes(2, "little", signed=True))
        payload.extend((0).to_bytes(2, "little", signed=True))
    for _ in positions:
        payload.extend((0).to_bytes(2, "little"))
        payload.extend((0).to_bytes(2, "little"))
    for _ in positions:
        payload.extend((0).to_bytes(2, "little"))
    for _ in positions:
        payload.extend(bytes([255]))

    payload.append(0x81)
    payload.extend((0).to_bytes(4, "big"))
    payload.extend(int(material_argument).to_bytes(2, "little"))
    payload.append(0)
    payload.extend(len(indices).to_bytes(2, "little"))
    for index in indices:
        payload.extend(int(index).to_bytes(2, "little"))
    return bytes(payload)


def _write_smart_short(value: int) -> bytes:
    if 0 <= value < 128:
        return bytes([value])
    if 128 <= value < 32768:
        return int(value + 32768).to_bytes(2, "big")
    raise ValueError(f"smart short value out of range: {value}")


def _build_mapsquare_locations_payload(
    placements: list[dict[str, object]],
) -> bytes:
    payload = bytearray()
    grouped: dict[int, list[dict[str, object]]] = {}
    for placement in placements:
        grouped.setdefault(int(placement["loc_id"]), []).append(placement)

    last_loc_id = -1
    for loc_id in sorted(grouped):
        payload.extend(_write_smart_short(loc_id - last_loc_id))
        last_loc_id = loc_id
        last_packed_location = 0
        uses = sorted(
            grouped[loc_id],
            key=lambda item: ((int(item["plane"]) << 12) | (int(item["x"]) << 6) | int(item["y"])),
        )
        for use in uses:
            packed_location = (int(use["plane"]) << 12) | (int(use["x"]) << 6) | int(use["y"])
            payload.extend(_write_smart_short((packed_location - last_packed_location) + 1))
            last_packed_location = packed_location
            extra = use.get("extra")
            type_id = int(use["type"])
            rotation = int(use["rotation"])
            packed_data = rotation | (type_id << 2)
            if isinstance(extra, dict):
                packed_data |= 0x80
            payload.append(packed_data)
            if isinstance(extra, dict):
                extra_flags = int(extra.get("flags", 0))
                payload.append(extra_flags)
                if extra_flags & 0x01:
                    for value in extra.get("rotation_override", [0, 0, 0, 0]):
                        payload.extend(int(value).to_bytes(2, "big", signed=True))
                if extra_flags & 0x02:
                    payload.extend(int(extra.get("translate_x", 0)).to_bytes(2, "big", signed=True))
                if extra_flags & 0x04:
                    payload.extend(int(extra.get("translate_y", 0)).to_bytes(2, "big", signed=True))
                if extra_flags & 0x08:
                    payload.extend(int(extra.get("translate_z", 0)).to_bytes(2, "big", signed=True))
                if extra_flags & 0x10:
                    payload.extend(int(extra.get("scale", 0)).to_bytes(2, "big"))
                if extra_flags & 0x20:
                    payload.extend(int(extra.get("scale_x", 0)).to_bytes(2, "big"))
                if extra_flags & 0x40:
                    payload.extend(int(extra.get("scale_y", 0)).to_bytes(2, "big"))
                if extra_flags & 0x80:
                    payload.extend(int(extra.get("scale_z", 0)).to_bytes(2, "big"))
        payload.append(0)
    payload.append(0)
    return bytes(payload)


def _build_mapsquare_tile_payload(
    *,
    tiles: dict[int, dict[str, int]],
    environment_id: int | None = None,
) -> bytes:
    payload = bytearray(b"jagx\x01")
    for tile_index in range(64 * 64 * 4):
        tile = tiles.get(tile_index)
        if tile is None:
            payload.append(0)
            continue
        flags = 0
        if "overlay" in tile or "shape" in tile:
            flags |= 0x01
        if "settings" in tile:
            flags |= 0x02
        if "underlay" in tile:
            flags |= 0x04
        if "height" in tile:
            flags |= 0x08
        payload.append(flags)
        if flags & 0x01:
            payload.append(int(tile.get("shape", 0)))
            payload.extend(_write_smart_short(int(tile.get("overlay", 0))))
        if flags & 0x02:
            payload.append(int(tile["settings"]))
        if flags & 0x04:
            payload.extend(_write_smart_short(int(tile["underlay"])))
        if flags & 0x08:
            payload.extend(int(tile["height"]).to_bytes(2, "big"))
    payload.extend(b"\x00" * 8)
    if environment_id is not None:
        payload.append(0x80)
        payload.extend(int(environment_id).to_bytes(2, "big"))
        payload.extend(b"\x00" * 8)
    return bytes(payload)


def _build_mapsquare_tile_nxt_payload(
    *,
    levels: dict[int, dict[int, dict[str, int]]],
) -> bytes:
    payload = bytearray(b"jagx\x01")
    for level in sorted(levels):
        payload.append(level)
        tiles = levels[level]
        for cell_index in range(66 * 66):
            tile = tiles.get(cell_index, {})
            flags = int(tile.get("flags", 0))
            height = int(tile.get("height", 0))
            payload.append(flags)
            payload.extend(height.to_bytes(2, "big"))
            if flags & 0x01:
                if flags & 0x10:
                    payload.extend(int(tile.get("water_height", 0)).to_bytes(2, "big"))
                underlay = int(tile.get("underlay", 0))
                payload.extend(_write_smart_short(underlay))
                if underlay != 0:
                    payload.extend(int(tile.get("underlay_color", 0)).to_bytes(2, "big"))
                overlay = int(tile.get("overlay", 0))
                payload.extend(_write_smart_short(overlay))
                if flags & 0x10:
                    payload.extend(_write_smart_short(int(tile.get("overlay_under", 0))))
                if overlay != 0:
                    payload.append(int(tile.get("shape", 0)))
                if overlay != 0 and flags & 0x10:
                    payload.extend(_write_smart_short(int(tile.get("underlay_under", 0))))
    return bytes(payload)


def test_js5_cache_analyzer_reports_archive_details(tmp_path):
    root = tmp_path / "OpenNXT"
    target = root / "data" / "cache" / "js5-17.jcache"
    target.parent.mkdir(parents=True, exist_ok=True)
    _write_js5_mapping(root, build=947, index_names={17: "CONFIG_ENUM"})

    with sqlite3.connect(target) as connection:
        connection.execute("CREATE TABLE cache (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute("CREATE TABLE cache_index (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute(
            "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (0, _build_js5_record(b'{"hello":"world"}', compression="gzip", revision=321), 947001, 1234),
        )
        connection.execute(
            "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (1, _build_js5_record(b"enum payload", compression="bzip2", revision=654), 947002, 5678),
        )
        connection.execute(
            "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (2, _build_js5_record(b"model payload", compression="lzma", revision=777), 947003, 9012),
        )
        connection.execute(
            "INSERT INTO cache_index (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (17, _build_js5_record(b"index payload", compression="none", revision=111), -1, 999),
        )
        connection.commit()

    report = AnalysisEngine().analyze(target)

    assert report.sections["identity"]["signature"] == "sqlite"
    js5_cache = report.sections["js5_cache"]
    assert js5_cache["store_kind"] == "js5"
    assert js5_cache["archive_id"] == 17
    assert js5_cache["index_name"] == "CONFIG_ENUM"
    assert js5_cache["mapping_build"] == 947

    cache_summary = js5_cache["table_summaries"]["cache"]
    compression_names = {item["name"] for item in cache_summary["compression_types"]}
    assert {"gzip", "bzip2", "lzma"} <= compression_names
    assert cache_summary["row_count"] == 3
    assert all(sample["decoded_matches_header"] is True for sample in cache_summary["record_samples"])
    assert any(sample.get("trailing_revision_candidate") == 321 for sample in cache_summary["record_samples"])
    assert any(sample["compression_type"] == "lzma" for sample in cache_summary["record_samples"])

    assert "format:js5-jcache" in report.summary["tags"]
    assert "js5-archive:17" in report.summary["tags"]
    assert "js5-index:config-enum" in report.summary["tags"]


def test_js5_cache_directory_analyzer_reports_cache_inventory(tmp_path):
    root = tmp_path / "OpenNXT"
    cache_dir = root / "data" / "cache"
    cache_dir.mkdir(parents=True)
    _write_js5_mapping(root, build=947, index_names={0: "ANIMS", 17: "CONFIG_ENUM"})

    for name in ("js5-0.jcache", "js5-17.jcache"):
        path = cache_dir / name
        with sqlite3.connect(path) as connection:
            connection.execute("CREATE TABLE cache (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
            connection.execute("CREATE TABLE cache_index (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
            connection.commit()

    report = AnalysisEngine().analyze(cache_dir)

    directory = report.sections["js5_cache_directory"]
    assert directory["cache_count"] == 2
    assert directory["mapped_archive_count"] == 2
    assert directory["mapping_build"] == 947
    assert directory["archives_by_id"][0]["archive_id"] == 0
    assert directory["archives_by_id"][1]["index_name"] == "CONFIG_ENUM"
    assert "format:js5-jcache-directory" in report.summary["tags"]


def test_js5_export_splits_grouped_archives_and_profiles_enums(tmp_path):
    root = tmp_path / "OpenNXT"
    target = root / "data" / "cache" / "js5-17.jcache"
    export_dir = tmp_path / "exports"
    target.parent.mkdir(parents=True, exist_ok=True)
    _write_js5_mapping(root, build=947, index_names={17: "CONFIG_ENUM"})

    reference_table = _build_reference_table({0: [0, 1]})
    grouped_archive = _build_grouped_archive(
        {
            0: _build_enum_definition(0, 36, {100: "hello"}),
            1: _build_enum_definition(0, 36, {200: "world"}),
        }
    )

    with sqlite3.connect(target) as connection:
        connection.execute("CREATE TABLE cache (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute("CREATE TABLE cache_index (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute(
            "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (0, _build_js5_record(grouped_archive, compression="none", revision=11), 100, 200),
        )
        connection.execute(
            "INSERT INTO cache_index (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (1, _build_js5_record(reference_table, compression="gzip"), -1, 999),
        )
        connection.commit()

    manifest = export_js5_cache(target, export_dir, tables=["cache"])

    assert manifest["summary"]["split_file_count"] == 2
    assert manifest["summary"]["semantic_profile_count"] == 2
    assert manifest["summary"]["semantic_kind_counts"]["config-enum"] == 2
    assert manifest["reference_table"]["archive_count"] == 1
    record = manifest["tables"]["cache"]["records"][0]
    assert record["archive_file_count"] == 2
    file0 = record["archive_files"][0]
    file1 = record["archive_files"][1]
    assert Path(file0["path"]).exists()
    assert Path(file1["path"]).exists()
    assert file0["semantic_profile"]["kind"] == "config-enum"
    assert file0["semantic_profile"]["definition_id"] == 0
    assert file0["semantic_profile"]["entry_count"] == 1
    assert file0["semantic_profile"]["entry_samples"][0]["value"] == "hello"
    assert file1["semantic_profile"]["definition_id"] == 1


def test_js5_export_profiles_varbit_payloads(tmp_path):
    root = tmp_path / "OpenNXT"
    target = root / "data" / "cache" / "js5-22.jcache"
    export_dir = tmp_path / "exports"
    target.parent.mkdir(parents=True, exist_ok=True)
    _write_js5_mapping(root, build=947, index_names={22: "CONFIG_STRUCT"})

    reference_table = _build_reference_table({0: [0]})
    grouped_archive = _build_grouped_archive({0: _build_varbit_definition(321, 2, 6)})

    with sqlite3.connect(target) as connection:
        connection.execute("CREATE TABLE cache (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute("CREATE TABLE cache_index (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute(
            "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (0, _build_js5_record(grouped_archive, compression="none", revision=11), 100, 200),
        )
        connection.execute(
            "INSERT INTO cache_index (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (1, _build_js5_record(reference_table, compression="gzip"), -1, 999),
        )
        connection.commit()

    manifest = export_js5_cache(target, export_dir, tables=["cache"])
    file0 = manifest["tables"]["cache"]["records"][0]["archive_files"][0]
    assert manifest["summary"]["semantic_kind_counts"]["config-varbit"] == 1
    assert file0["semantic_profile"]["kind"] == "config-varbit"
    assert file0["semantic_profile"]["base_var"] == 321
    assert file0["semantic_profile"]["least_significant_bit"] == 2
    assert file0["semantic_profile"]["most_significant_bit"] == 6


def test_js5_export_profiles_var_definition_payloads(tmp_path):
    root = tmp_path / "OpenNXT"
    target = root / "data" / "cache" / "js5-2.jcache"
    export_dir = tmp_path / "exports"
    target.parent.mkdir(parents=True, exist_ok=True)
    _write_js5_mapping(root, build=947, index_names={2: "CONFIG"})

    reference_table = _build_reference_table({0: [7]})
    grouped_archive = _build_grouped_archive({7: _build_var_definition(type_id=31, lifetime=2, force_default=False)})

    with sqlite3.connect(target) as connection:
        connection.execute("CREATE TABLE cache (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute("CREATE TABLE cache_index (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute(
            "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (0, _build_js5_record(grouped_archive, compression="none", revision=11), 100, 200),
        )
        connection.execute(
            "INSERT INTO cache_index (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (1, _build_js5_record(reference_table, compression="gzip"), -1, 999),
        )
        connection.commit()

    manifest = export_js5_cache(target, export_dir, tables=["cache"])
    file0 = manifest["tables"]["cache"]["records"][0]["archive_files"][0]
    assert manifest["summary"]["semantic_kind_counts"]["config-var-definition"] == 1
    assert file0["semantic_profile"]["kind"] == "config-var-definition"
    assert file0["semantic_profile"]["type_id"] == 31
    assert file0["semantic_profile"]["type_name"] == "MODEL"
    assert file0["semantic_profile"]["lifetime"] == 2
    assert file0["semantic_profile"]["force_default"] is False


def test_profile_archive_file_decodes_item_payloads():
    payload = bytes.fromhex(
        "010a2307fffc08000c0406f40601b4050140100f2744657374726f7900"
        "b20244776172662072656d61696e7300f9020000001f0000000100000575"
        "0000000190002d00"
    )

    profile = profile_archive_file(payload, index_name="CONFIG_ITEM", archive_key=0, file_id=0)

    assert profile is not None
    assert profile["kind"] == "config-item"
    assert profile["parser_status"] == "parsed"
    assert profile["definition_id"] == 0
    assert profile["model_id"] == 2595
    assert profile["name"] == "Dwarf remains"
    assert profile["members_only"] is True
    assert profile["inventory_actions"][4] == "Destroy"
    assert profile["opaque_flags"] == [15, 178]
    assert profile["opaque_values"]["144"] == 45
    assert profile["param_count"] == 2


def test_profile_archive_file_decodes_npc_payloads():
    payload = bytes.fromhex(
        "7f00710c011f41747461636b005f000502536e616b650001010bbaf906"
        "00000b310000008c00000b20000000030000000e000000040000028100"
        "0000a00000001d0000008c0000001a00000001770389002a00"
    )

    profile = profile_archive_file(payload, index_name="CONFIG_NPC", archive_key=0, file_id=0)

    assert profile is not None
    assert profile["kind"] == "config-npc"
    assert profile["parser_status"] == "parsed"
    assert profile["definition_id"] == 0
    assert profile["name"] == "Snake"
    assert profile["size"] == 1
    assert profile["combat_level"] == 5
    assert profile["actions"][1] == "Attack"
    assert profile["model_ids"] == [3002]
    assert profile["opaque_values"]["127"] == 113
    assert profile["opaque_values"]["137"] == 42


def test_profile_archive_file_decodes_object_payloads_without_overrun():
    payload = bytes.fromhex(
        "4100644200644300641e53656172636800180c8628061614151c16181518159c"
        "199a15a11d1c152521211529151801010a013c2a02437261746500be00386700"
    )

    profile = profile_archive_file(payload, index_name="CONFIG_OBJECT", archive_key=0, file_id=0)

    assert profile is not None
    assert profile["kind"] == "config-object"
    assert profile["parser_status"] == "parsed"
    assert profile["definition_id"] == 0
    assert profile["name"] == "Crate"
    assert profile["actions"][0] == "Search"
    assert profile["resize_x"] == 100
    assert profile["animation_id"] == 3206
    assert profile["opaque_flags"] == [42, 103]
    assert profile["opaque_values"]["190"] == 56
    assert profile["consumed_bytes"] == len(payload)


def test_profile_archive_file_decodes_sprite_archives():
    payload = _build_sprite_archive(
        canvas_width=2,
        canvas_height=2,
        palette=[0x000000, 0xFF0000, 0x00FF00],
        sprites=[
            {
                "offset_x": 0,
                "offset_y": 0,
                "width": 2,
                "height": 2,
                "indices": [1, 2, 2, 1],
            }
        ],
    )

    profile = profile_archive_file(payload, index_name="SPRITES", archive_key=0, file_id=0)

    assert profile is not None
    assert profile["kind"] == "sprite-sheet"
    assert profile["parser_status"] == "parsed"
    assert profile["sprite_count"] == 1
    assert profile["canvas_width"] == 2
    assert profile["canvas_height"] == 2
    assert profile["palette_size"] == 3
    assert profile["frames_sample"][0]["width"] == 2
    assert profile["frames_sample"][0]["height"] == 2
    assert profile["_preview_png_bytes"].startswith(b"\x89PNG\r\n\x1a\n")


def test_js5_export_writes_sprite_preview_png(tmp_path):
    root = tmp_path / "OpenNXT"
    target = root / "data" / "cache" / "js5-8.jcache"
    export_dir = tmp_path / "exports"
    target.parent.mkdir(parents=True, exist_ok=True)
    _write_js5_mapping(root, build=947, index_names={8: "SPRITES"})

    reference_table = _build_reference_table({0: [0]})
    sprite_archive = _build_sprite_archive(
        canvas_width=2,
        canvas_height=2,
        palette=[0x000000, 0xFF0000, 0x00FF00],
        sprites=[
            {
                "offset_x": 0,
                "offset_y": 0,
                "width": 2,
                "height": 2,
                "indices": [1, 2, 2, 1],
            }
        ],
    )

    with sqlite3.connect(target) as connection:
        connection.execute("CREATE TABLE cache (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute("CREATE TABLE cache_index (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute(
            "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (0, _build_js5_record(sprite_archive, compression='none', revision=11), 100, 200),
        )
        connection.execute(
            "INSERT INTO cache_index (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (1, _build_js5_record(reference_table, compression='gzip'), -1, 999),
        )
        connection.commit()

    manifest = export_js5_cache(target, export_dir, tables=["cache"])
    file0 = manifest["tables"]["cache"]["records"][0]["archive_files"][0]
    preview_path = Path(file0["semantic_profile"]["preview_png_path"])

    assert manifest["summary"]["semantic_kind_counts"]["sprite-sheet"] == 1
    assert file0["semantic_profile"]["kind"] == "sprite-sheet"
    assert preview_path.exists()
    assert preview_path.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")


def test_profile_archive_file_decodes_clientscript_metadata():
    payload = _build_clientscript_payload(
        instruction_count=38,
        local_int_count=1,
        int_argument_count=1,
        switch_tables=[{54533: 1, 54534: 9, 54535: 17, 54536: 25}],
        body_bytes=b"\x01\x02\x03\x04",
    )

    profile = profile_archive_file(payload, index_name="CLIENTSCRIPTS", archive_key=0, file_id=2)

    assert profile is not None
    assert profile["kind"] == "clientscript-metadata"
    assert profile["parser_status"] == "parsed"
    assert profile["instruction_count"] == 38
    assert profile["local_int_count"] == 1
    assert profile["int_argument_count"] == 1
    assert profile["switch_table_count"] == 1
    assert profile["switch_case_count"] == 4
    assert profile["switch_tables_sample"][0]["case_samples"][0]["value"] == 54533
    assert profile["byte0"] == 0
    assert profile["opcode_data_bytes"] == 4
    assert profile["script_name"] is None


def test_profile_archive_file_builds_switch_skeleton_cfg_for_metadata_only_script():
    payload = _build_clientscript_payload(
        instruction_count=12,
        switch_tables=[{100: 1, 200: 5, 300: 9}],
        body_bytes=b"\x01\x02\x03\x04",
    )

    profile = profile_archive_file(payload, index_name="CLIENTSCRIPTS", archive_key=0, file_id=7)

    assert profile is not None
    assert profile["kind"] == "clientscript-metadata"
    assert profile["cfg_mode"] == "switch-skeleton"
    assert profile["cfg_block_count"] == 4
    assert profile["cfg_edge_count"] == 3
    assert profile["cfg_terminal_block_count"] == 3
    assert profile["switch_dispatch_candidate_count"] == 1
    assert {edge["target"] for edge in profile["cfg_edges_sample"]} == {
        "block_i0001",
        "block_i0005",
        "block_i0009",
    }


def test_profile_archive_file_surfaces_clientscript_frontier_with_locked_prefix():
    payload = _build_clientscript_payload(
        instruction_count=2,
        switch_tables=[{10: 1, 20: 5}],
        body_bytes=(
            _encode_clientscript_instruction(0x1001, "int", 42)
            + b"\x30\x03"
        ),
    )

    profile = profile_archive_file(
        payload,
        index_name="CLIENTSCRIPTS",
        archive_key=0,
        file_id=9,
        clientscript_opcode_types={0x1001: "int"},
        clientscript_opcode_catalog={
            0x3003: {
                "candidate_mnemonic": "SWITCH_DISPATCH_FRONTIER_CANDIDATE",
                "family": "control-flow",
                "candidate_confidence": 0.44,
            }
        },
    )

    assert profile is not None
    assert profile["kind"] == "clientscript-metadata"
    assert profile["frontier_mode"] == "locked-prefix"
    assert profile["frontier_reason"] == "unknown-locked-opcode"
    assert profile["frontier_raw_opcode_hex"] == "0x3003"
    assert profile["frontier_previous_raw_opcode_hex"] == "0x1001"
    assert profile["frontier_candidate_label"] == "SWITCH_DISPATCH_FRONTIER_CANDIDATE"
    assert profile["frontier_instruction_sample"][0]["raw_opcode_hex"] == "0x1001"
    assert profile["cfg_mode"] == "switch-skeleton"


def test_decode_clientscript_metadata_handles_frontier_without_catalog_entry():
    payload = _build_clientscript_payload(
        instruction_count=2,
        switch_tables=[{10: 1, 20: 5}],
        body_bytes=(
            _encode_clientscript_instruction(0x1001, "int", 42)
            + b"\x30\x03"
        ),
    )

    profile = _decode_clientscript_metadata(
        payload,
        raw_opcode_types={0x1001: "int"},
        raw_opcode_catalog={},
    )

    assert profile["kind"] == "clientscript-metadata"
    assert profile["frontier_mode"] == "locked-prefix"
    assert profile["frontier_raw_opcode_hex"] == "0x3003"
    assert "frontier_candidate_label" not in profile
    assert "frontier_candidate_confidence" not in profile
    assert "frontier_candidate_stack_effect" not in profile
    assert "frontier_candidate_operand_signature" not in profile
    assert profile["frontier_instruction_sample"][0]["raw_opcode_hex"] == "0x1001"
    assert profile["cfg_mode"] == "switch-skeleton"


def test_profile_archive_file_decodes_clientscript_disassembly_with_locked_types():
    payload = _build_clientscript_payload(
        instruction_count=3,
        body_bytes=(
            _encode_clientscript_instruction(0x1001, "int", 10)
            + _encode_clientscript_instruction(0x2002, "byte", 7)
            + _encode_clientscript_instruction(0x1001, "int", 20)
        ),
    )

    profile = profile_archive_file(
        payload,
        index_name="CLIENTSCRIPTS",
        archive_key=0,
        file_id=2,
        clientscript_opcode_types={0x1001: "int", 0x2002: "byte"},
        clientscript_opcode_catalog={
            0x1001: {"mnemonic": "PUSH_INT_LITERAL", "family": "stack"},
            0x2002: {"mnemonic": "RETURN", "family": "control-flow", "confidence": 0.9},
        },
    )

    assert profile is not None
    assert profile["kind"] == "clientscript-disassembly"
    assert profile["distinct_raw_opcode_count"] == 2
    assert profile["immediate_kind_counts"] == {"int": 2, "byte": 1}
    assert profile["instruction_sample"][0]["raw_opcode_hex"] == "0x1001"
    assert profile["instruction_sample"][0]["semantic_label"] == "PUSH_INT_LITERAL"
    assert profile["instruction_sample"][0]["stack_effect_candidate"]["int_pushes"] == 1
    assert profile["instruction_sample"][0]["produced_int_expressions"][0]["value"] == 10
    assert profile["instruction_sample"][0]["int_stack_depth_after"] == 1
    assert profile["instruction_sample"][1]["immediate_value"] == 7
    assert profile["instruction_sample"][1]["semantic_label"] == "RETURN"
    assert profile["instruction_sample"][1]["int_stack_depth_before"] == 1
    assert profile["instruction_sample"][1]["int_stack_depth_after"] == 1
    assert profile["stack_tracking"]["known_effect_instruction_count"] == 3
    assert profile["stack_tracking"]["final_depths"]["int_stack"] == 2
    assert profile["disassembly_mode"] == "cache-calibrated"


def test_profile_archive_file_decodes_clientscript_disassembly_with_direct_string_immediate():
    payload = _build_clientscript_payload(
        instruction_count=2,
        body_bytes=(
            _encode_clientscript_instruction(0x3003, "string", "Hello")
            + _encode_clientscript_instruction(0x2002, "byte", 0)
        ),
    )

    profile = profile_archive_file(
        payload,
        index_name="CLIENTSCRIPTS",
        archive_key=0,
        file_id=13,
        clientscript_opcode_types={0x3003: "string", 0x2002: "byte"},
        clientscript_opcode_catalog={
            0x3003: {"mnemonic": "PUSH_CONST_STRING", "family": "stack-constant"},
            0x2002: {"mnemonic": "RETURN", "family": "control-flow", "confidence": 0.9},
        },
    )

    assert profile is not None
    assert profile["kind"] == "clientscript-disassembly"
    assert profile["immediate_kind_counts"] == {"string": 1, "byte": 1}
    assert profile["instruction_sample"][0]["semantic_label"] == "PUSH_CONST_STRING"
    assert profile["instruction_sample"][0]["produced_string_expressions"][0]["kind"] == "string-literal"
    assert profile["instruction_sample"][0]["produced_string_expressions"][0]["value"] == "Hello"
    assert profile["instruction_sample"][0]["string_stack_depth_after"] == 1
    assert profile["stack_tracking"]["final_depths"]["string_stack"] == 1


def test_clientscript_string_immediates_are_supported_but_not_part_of_default_discovery():
    assert "string" not in js5_module.CLIENTSCRIPT_IMMEDIATE_TYPES
    assert "string" in js5_module.CLIENTSCRIPT_SUPPORTED_IMMEDIATE_TYPES


def test_profile_archive_file_uses_override_immediate_kind_for_clientscript():
    payload = _build_clientscript_payload(
        instruction_count=2,
        body_bytes=(
            _encode_clientscript_instruction(0x2002, "byte", 7)
            + b"\x30\x03\x00"
        ),
    )

    profile = profile_archive_file(
        payload,
        index_name="CLIENTSCRIPTS",
        archive_key=0,
        file_id=12,
        clientscript_opcode_types={0x2002: "byte"},
        clientscript_opcode_catalog={
            0x3003: {
                "mnemonic": "SWITCH_DISPATCH_FRONTIER_CANDIDATE",
                "family": "control-flow",
                "immediate_kind": "byte",
            }
        },
    )

    assert profile is not None
    assert profile["kind"] == "clientscript-disassembly"
    assert {entry["raw_opcode_hex"] for entry in profile["raw_opcode_types_sample"]} == {"0x2002", "0x3003"}
    assert profile["instruction_sample"][1]["semantic_label"] == "SWITCH_DISPATCH_FRONTIER_CANDIDATE"


def test_profile_archive_file_builds_clientscript_cfg():
    payload = _build_clientscript_payload(
        instruction_count=5,
        body_bytes=(
            _encode_clientscript_instruction(0x3003, "int", 9)
            + _encode_clientscript_instruction(0x1001, "int", 10)
            + _encode_clientscript_instruction(0x2002, "byte", 0)
            + _encode_clientscript_instruction(0x1001, "int", 20)
            + _encode_clientscript_instruction(0x2002, "byte", 0)
        ),
    )

    profile = profile_archive_file(
        payload,
        index_name="CLIENTSCRIPTS",
        archive_key=0,
        file_id=3,
        clientscript_opcode_types={0x3003: "int", 0x1001: "int", 0x2002: "byte"},
        clientscript_opcode_catalog={
            0x3003: {
                "mnemonic": "BRANCH_IF_TRUE",
                "family": "control-flow",
                "control_flow_kind": "branch",
                "jump_base": "next_offset",
            },
            0x1001: {"mnemonic": "PUSH_INT_LITERAL", "family": "stack"},
            0x2002: {"mnemonic": "RETURN", "family": "control-flow", "control_flow_kind": "return"},
        },
    )

    assert profile is not None
    assert profile["cfg_block_count"] == 3
    assert profile["cfg_edge_count"] == 2
    assert profile["cfg_terminal_block_count"] == 2
    assert profile["cfg_unresolved_target_count"] == 0
    assert {edge["kind"] for edge in profile["cfg_edges_sample"]} == {"branch", "fallthrough"}


def test_profile_archive_file_tracks_branch_condition_expression():
    payload = _build_clientscript_payload(
        instruction_count=3,
        body_bytes=(
            _encode_clientscript_instruction(0x1001, "int", 7)
            + _encode_clientscript_instruction(0x4004, "short", -10)
            + _encode_clientscript_instruction(0x2002, "byte", 0)
        ),
    )

    profile = profile_archive_file(
        payload,
        index_name="CLIENTSCRIPTS",
        archive_key=0,
        file_id=4,
        clientscript_opcode_types={0x1001: "int", 0x4004: "short", 0x2002: "byte"},
        clientscript_opcode_catalog={
            0x1001: {"mnemonic": "PUSH_INT_LITERAL", "family": "stack"},
            0x4004: {
                "mnemonic": "JUMP_OFFSET_FRONTIER_CANDIDATE",
                "family": "control-flow",
                "control_flow_kind": "branch-candidate",
                "jump_base": "next_offset",
                "immediate_kind": "short",
            },
            0x2002: {"mnemonic": "RETURN", "family": "control-flow", "control_flow_kind": "return"},
        },
    )

    assert profile is not None
    assert profile["kind"] == "clientscript-disassembly"
    assert profile["instruction_sample"][0]["produced_int_expressions"][0]["kind"] == "int-literal"
    assert profile["instruction_sample"][0]["produced_int_expressions"][0]["value"] == 7
    assert profile["instruction_sample"][1]["consumed_int_expressions"][0]["kind"] == "int-literal"
    assert profile["instruction_sample"][1]["branch_condition_expression"]["value"] == 7
    assert profile["stack_tracking"]["minimum_required_inputs"] == {}
    assert profile["stack_tracking"]["final_expression_stacks"] == {}


def test_js5_export_profiles_clientscript_disassembly(tmp_path):
    root = tmp_path / "OpenNXT"
    target = root / "data" / "cache" / "js5-12.jcache"
    export_dir = tmp_path / "exports"
    target.parent.mkdir(parents=True, exist_ok=True)
    _write_js5_mapping(root, build=947, index_names={12: "CLIENTSCRIPTS"})
    _write_clientscript_semantics(
        root,
        build=947,
        opcodes={
            "0x1001": {"mnemonic": "PUSH_INT_LITERAL", "family": "stack"},
            "0x2002": {
                "mnemonic": "RETURN",
                "family": "control-flow",
                "confidence": 0.9,
                "control_flow_kind": "return",
            },
        },
    )

    reference_table = _build_reference_table({0: [0], 1: [0], 2: [0]})
    int_script = _build_clientscript_payload(
        instruction_count=3,
        body_bytes=(
            _encode_clientscript_instruction(0x1001, "int", 10)
            + _encode_clientscript_instruction(0x1001, "int", 20)
            + _encode_clientscript_instruction(0x1001, "int", 30)
        ),
    )
    byte_script = _build_clientscript_payload(
        instruction_count=3,
        body_bytes=(
            _encode_clientscript_instruction(0x2002, "byte", 1)
            + _encode_clientscript_instruction(0x2002, "byte", 2)
            + _encode_clientscript_instruction(0x2002, "byte", 3)
        ),
    )
    mixed_script = _build_clientscript_payload(
        instruction_count=3,
        body_bytes=(
            _encode_clientscript_instruction(0x1001, "int", 40)
            + _encode_clientscript_instruction(0x2002, "byte", 7)
            + _encode_clientscript_instruction(0x1001, "int", 50)
        ),
    )

    with sqlite3.connect(target) as connection:
        connection.execute("CREATE TABLE cache (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute("CREATE TABLE cache_index (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute(
            "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (0, _build_js5_record(int_script, compression='none', revision=11), 100, 200),
        )
        connection.execute(
            "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (1, _build_js5_record(byte_script, compression='none', revision=11), 101, 201),
        )
        connection.execute(
            "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (2, _build_js5_record(mixed_script, compression='none', revision=11), 102, 202),
        )
        connection.execute(
            "INSERT INTO cache_index (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (1, _build_js5_record(reference_table, compression='gzip'), -1, 999),
        )
        connection.commit()

    manifest = export_js5_cache(target, export_dir, tables=["cache"])
    records = manifest["tables"]["cache"]["records"]
    mixed_record = next(record for record in records if record["key"] == 2)
    file0 = mixed_record["archive_files"][0]
    disassembly_path = Path(file0["semantic_profile"]["disassembly_text_path"])
    opcode_catalog_path = Path(manifest["clientscript_opcode_catalog_path"])
    cfg_dot_path = Path(file0["semantic_profile"]["cfg_dot_path"])
    cfg_json_path = Path(file0["semantic_profile"]["cfg_json_path"])
    pseudocode_path = Path(file0["semantic_profile"]["pseudocode_text_path"])

    assert manifest["clientscript_calibration"]["locked_opcode_type_count"] >= 2
    assert manifest["summary"]["semantic_kind_counts"]["clientscript-disassembly"] >= 1
    assert manifest["summary"]["cfg_graph_count"] >= 1
    assert file0["semantic_profile"]["kind"] == "clientscript-disassembly"
    assert file0["semantic_profile"]["instruction_sample"][0]["raw_opcode_hex"] == "0x1001"
    assert file0["semantic_profile"]["instruction_sample"][0]["semantic_label"] == "PUSH_INT_LITERAL"
    assert file0["semantic_profile"]["instruction_sample"][0]["stack_effect_candidate"]["int_pushes"] == 1
    assert file0["semantic_profile"]["instruction_sample"][0]["produced_int_expressions"][0]["value"] == 40
    assert file0["semantic_profile"]["instruction_sample"][1]["semantic_label"] == "RETURN"
    assert disassembly_path.exists()
    assert opcode_catalog_path.exists()
    assert cfg_dot_path.exists()
    assert cfg_json_path.exists()
    assert pseudocode_path.exists()
    opcode_catalog = json.loads(opcode_catalog_path.read_text(encoding="utf-8"))
    push_int_entry = next(entry for entry in opcode_catalog["opcodes"] if entry["raw_opcode_hex"] == "0x1001")
    assert push_int_entry["stack_effect_candidate"]["int_pushes"] == 1
    assert "semantic=PUSH_INT_LITERAL" in disassembly_path.read_text(encoding="utf-8")
    assert "return;" in pseudocode_path.read_text(encoding="utf-8")
    assert "digraph clientscript_cfg" in cfg_dot_path.read_text(encoding="utf-8")
    assert json.loads(cfg_json_path.read_text(encoding="utf-8"))["block_count"] >= 1
    assert manifest["clientscript_calibration"]["semantic_override_build"] == 947


def test_js5_export_writes_clientscript_pseudocode_blocker_catalog(tmp_path, monkeypatch):
    root = tmp_path / "OpenNXT"
    target = root / "data" / "cache" / "js5-12.jcache"
    export_dir = tmp_path / "exports"
    target.parent.mkdir(parents=True, exist_ok=True)
    _write_js5_mapping(root, build=947, index_names={12: "CLIENTSCRIPTS"})
    _write_clientscript_semantics(root, build=947, opcodes={})

    reference_table = _build_reference_table({0: [0], 1: [0]})
    grouped_archive = _build_grouped_archive({0: b"synthetic clientscript payload"})

    def fake_profile_archive_file(
        data: bytes,
        *,
        index_name: str,
        archive_key: int,
        file_id: int,
        clientscript_opcode_types: dict[int, str] | None = None,
        clientscript_opcode_catalog: dict[int, dict[str, object]] | None = None,
    ) -> dict[str, object] | None:
        assert index_name == "CLIENTSCRIPTS"
        return {
            "kind": "clientscript-metadata",
            "parser_status": "profiled",
            "disassembly_mode": "cache-calibrated",
            "disassembly_solution_count": 0,
            "disassembly_bailed": False,
            "frontier_reason": "unknown-locked-opcode",
            "frontier_raw_opcode": 0x4004,
            "frontier_raw_opcode_hex": "0x4004",
            "frontier_offset": 6,
            "frontier_instruction_index": 1,
            "frontier_candidate_label": "STRING_FORMATTER_FRONTIER_CANDIDATE",
            "frontier_candidate_family": "string-transform-frontier",
        }

    monkeypatch.setattr(js5_module, "profile_archive_file", fake_profile_archive_file)

    with sqlite3.connect(target) as connection:
        connection.execute("CREATE TABLE cache (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute("CREATE TABLE cache_index (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute(
            "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (0, _build_js5_record(grouped_archive, compression='none', revision=11), 100, 200),
        )
        connection.execute(
            "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (1, _build_js5_record(grouped_archive, compression='none', revision=11), 101, 201),
        )
        connection.execute(
            "INSERT INTO cache_index (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (1, _build_js5_record(reference_table, compression='gzip'), -1, 999),
        )
        connection.commit()

    manifest = export_js5_cache(target, export_dir, tables=["cache"])
    blocker_path = Path(manifest["clientscript_pseudocode_blockers_path"])
    blocker_catalog = json.loads(blocker_path.read_text(encoding="utf-8"))
    blocker_entry = next(entry for entry in blocker_catalog["opcodes"] if entry["raw_opcode_hex"] == "0x4004")
    record = next(record for record in manifest["tables"]["cache"]["records"] if record["key"] == 0)
    semantic_profile = record["archive_files"][0]["semantic_profile"]

    assert blocker_path.exists()
    assert manifest["clientscript_pseudocode"]["blocked_profile_count"] == 2
    assert manifest["clientscript_pseudocode"]["ready_profile_count"] == 0
    assert blocker_catalog["blocked_profile_count"] == 2
    assert blocker_catalog["blocker_opcode_count"] >= 1
    assert blocker_entry["blocked_profile_count"] == 2
    assert semantic_profile["pseudocode_status"] == "blocked"
    assert semantic_profile["pseudocode_blocker"]["frontier_raw_opcode_hex"] == "0x4004"


def test_build_clientscript_pseudocode_profile_status_preserves_tail_diagnostics():
    status = _build_clientscript_pseudocode_profile_status(
        {
            "kind": "clientscript-metadata",
            "parser_status": "profiled",
            "disassembly_mode": "cache-calibrated",
            "disassembly_solution_count": 0,
            "disassembly_bailed": False,
            "tail_trace_status": "extra-bytes",
            "tail_instruction_count": 153,
            "tail_remaining_opcode_bytes": 5,
            "tail_last_instruction": {
                "offset": 780,
                "raw_opcode": 0x6167,
                "raw_opcode_hex": "0x6167",
                "immediate_kind": "int",
                "semantic_label": "STRING_FORMATTER_CANDIDATE",
            },
            "tail_stack_summary": {
                "prefix_operand_signature": "widget+string",
                "prefix_widget_stack_count": 1,
                "prefix_string_stack_count": 1,
            },
        },
        archive_key=3055,
        file_id=0,
    )

    assert status is not None
    assert status["blocking_kind"] == "tail-extra-bytes"
    assert status["tail_trace_status"] == "extra-bytes"
    assert status["tail_instruction_count"] == 153
    assert status["tail_remaining_opcode_bytes"] == 5
    assert status["tail_operand_signature"] == "widget+string"
    assert status["tail_last_instruction"]["raw_opcode_hex"] == "0x6167"


def test_summarize_clientscript_pseudocode_blockers_groups_tail_only_failures():
    summary = _summarize_clientscript_pseudocode_blockers(
        [
            {
                "archive_key": 3055,
                "file_id": 0,
                "status": "blocked",
                "blocking_kind": "tail-extra-bytes",
                "tail_trace_status": "extra-bytes",
                "tail_instruction_count": 150,
                "tail_remaining_opcode_bytes": 5,
                "tail_operand_signature": "widget+string",
                "tail_last_instruction": {
                    "raw_opcode": 0x6167,
                    "raw_opcode_hex": "0x6167",
                    "semantic_label": "STRING_FORMATTER_CANDIDATE",
                    "immediate_kind": "int",
                },
            },
            {
                "archive_key": 3174,
                "file_id": 0,
                "status": "blocked",
                "blocking_kind": "tail-extra-bytes",
                "tail_trace_status": "extra-bytes",
                "tail_instruction_count": 153,
                "tail_remaining_opcode_bytes": 5,
                "tail_operand_signature": "widget+string",
                "tail_last_instruction": {
                    "raw_opcode": 0x6167,
                    "raw_opcode_hex": "0x6167",
                    "semantic_label": "STRING_FORMATTER_CANDIDATE",
                    "immediate_kind": "int",
                },
            },
        ]
    )

    assert summary["blocked_profile_count"] == 2
    assert summary["blocking_kind_counts"]["tail-extra-bytes"] == 2
    assert summary["tail_status_counts"]["extra-bytes"] == 2
    assert summary["tail_last_opcode_count"] == 1
    assert summary["tail_last_opcodes"][0]["raw_opcode_hex"] == "0x6167"
    assert summary["tail_last_opcodes"][0]["blocked_profile_count"] == 2
    assert summary["blocked_profile_sample"][0]["tail_operand_signature"] == "widget+string"


def test_js5_export_writes_clientscript_string_transform_frontier_candidates(tmp_path):
    root = tmp_path / "OpenNXT"
    target = root / "data" / "cache" / "js5-12.jcache"
    export_dir = tmp_path / "exports"
    target.parent.mkdir(parents=True, exist_ok=True)
    _write_js5_mapping(root, build=947, index_names={12: "CLIENTSCRIPTS"})
    _write_clientscript_semantics(
        root,
        build=947,
        opcodes={
            "0x1001": {"mnemonic": "PUSH_INT_LITERAL", "family": "stack", "immediate_kind": "int"},
            "0x3003": {
                "mnemonic": "PUSH_CONST_STRING_CANDIDATE",
                "family": "stack-constant",
                "immediate_kind": "string",
            },
        },
    )

    reference_table = _build_reference_table({0: [0]})
    mixed_frontier_script = _build_clientscript_payload(
        instruction_count=3,
        body_bytes=(
            _encode_clientscript_instruction(0x1001, "int", 40)
            + _encode_clientscript_instruction(0x3003, "string", "Level: ")
            + b"\x40\x04\x00"
        ),
    )

    with sqlite3.connect(target) as connection:
        connection.execute("CREATE TABLE cache (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute("CREATE TABLE cache_index (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute(
            "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (0, _build_js5_record(mixed_frontier_script, compression='none', revision=11), 100, 200),
        )
        connection.execute(
            "INSERT INTO cache_index (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (1, _build_js5_record(reference_table, compression='gzip'), -1, 999),
        )
        connection.commit()

    manifest = export_js5_cache(target, export_dir, tables=["cache"])
    candidate_path = Path(manifest["clientscript_string_transform_frontier_candidates_path"])
    candidates = json.loads(candidate_path.read_text(encoding="utf-8"))
    frontier_entry = next(entry for entry in candidates["opcodes"] if entry["raw_opcode_hex"] == "0x4004")

    assert candidate_path.exists()
    assert manifest["clientscript_calibration"]["string_transform_frontier_candidates"]["frontier_opcode_count"] >= 1
    assert frontier_entry["candidate_mnemonic"] == "STRING_FORMATTER_FRONTIER_CANDIDATE"
    assert frontier_entry["prefix_operand_signature_sample"][0]["signature"] == "int+string"


def test_js5_export_writes_clientscript_string_transform_arity_candidates(tmp_path):
    root = tmp_path / "OpenNXT"
    target = root / "data" / "cache" / "js5-12.jcache"
    export_dir = tmp_path / "exports"
    target.parent.mkdir(parents=True, exist_ok=True)
    _write_js5_mapping(root, build=947, index_names={12: "CLIENTSCRIPTS"})
    _write_clientscript_semantics(
        root,
        build=947,
        opcodes={
            "0x1001": {"mnemonic": "PUSH_INT_LITERAL", "family": "stack", "immediate_kind": "int"},
            "0x3003": {
                "mnemonic": "PUSH_CONST_STRING_CANDIDATE",
                "family": "stack-constant",
                "immediate_kind": "string",
            },
        },
    )

    reference_table = _build_reference_table({0: [0], 1: [0]})
    mixed_frontier_script = _build_clientscript_payload(
        instruction_count=3,
        body_bytes=(
            _encode_clientscript_instruction(0x1001, "int", 40)
            + _encode_clientscript_instruction(0x3003, "string", "Level: ")
            + b"\x40\x04\x00"
        ),
    )

    with sqlite3.connect(target) as connection:
        connection.execute("CREATE TABLE cache (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute("CREATE TABLE cache_index (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute(
            "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (0, _build_js5_record(mixed_frontier_script, compression='none', revision=11), 100, 200),
        )
        connection.execute(
            "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (1, _build_js5_record(mixed_frontier_script, compression='none', revision=11), 101, 201),
        )
        connection.execute(
            "INSERT INTO cache_index (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (1, _build_js5_record(reference_table, compression='gzip'), -1, 999),
        )
        connection.commit()

    manifest = export_js5_cache(target, export_dir, tables=["cache"])
    candidate_path = Path(manifest["clientscript_string_transform_arity_candidates_path"])
    opcode_catalog_path = Path(manifest["clientscript_opcode_catalog_path"])
    candidates = json.loads(candidate_path.read_text(encoding="utf-8"))
    opcode_catalog = json.loads(opcode_catalog_path.read_text(encoding="utf-8"))
    frontier_entry = next(entry for entry in candidates["opcodes"] if entry["raw_opcode_hex"] == "0x4004")
    opcode_entry = next(entry for entry in opcode_catalog["opcodes"] if entry["raw_opcode_hex"] == "0x4004")

    assert candidate_path.exists()
    assert manifest["clientscript_calibration"]["string_transform_arity_candidates"]["profiled_opcode_count"] >= 1
    assert frontier_entry["candidate_arity_profile"]["candidate_mnemonic"] == "STRING_FORMATTER_CANDIDATE"
    assert frontier_entry["candidate_arity_profile"]["signature"] == "int+string"
    assert frontier_entry["candidate_arity_profile"]["stack_effect_candidate"]["string_pushes"] == 1
    assert opcode_entry["candidate_mnemonic"] == "STRING_FORMATTER_CANDIDATE"


def test_js5_export_uses_atomic_artifacts_for_manifest_and_arity_candidates(tmp_path, monkeypatch):
    root = tmp_path / "OpenNXT"
    target = root / "data" / "cache" / "js5-12.jcache"
    export_dir = tmp_path / "exports"
    target.parent.mkdir(parents=True, exist_ok=True)
    _write_js5_mapping(root, build=947, index_names={12: "CLIENTSCRIPTS"})
    _write_clientscript_semantics(
        root,
        build=947,
        opcodes={
            "0x1001": {"mnemonic": "PUSH_INT_LITERAL", "family": "stack", "immediate_kind": "int"},
            "0x3003": {
                "mnemonic": "PUSH_CONST_STRING_CANDIDATE",
                "family": "stack-constant",
                "immediate_kind": "string",
            },
        },
    )

    reference_table = _build_reference_table({0: [0], 1: [0]})
    mixed_frontier_script = _build_clientscript_payload(
        instruction_count=3,
        body_bytes=(
            _encode_clientscript_instruction(0x1001, "int", 40)
            + _encode_clientscript_instruction(0x3003, "string", "Level: ")
            + b"\x40\x04\x00"
        ),
    )

    with sqlite3.connect(target) as connection:
        connection.execute("CREATE TABLE cache (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute("CREATE TABLE cache_index (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute(
            "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (0, _build_js5_record(mixed_frontier_script, compression='none', revision=11), 100, 200),
        )
        connection.execute(
            "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (1, _build_js5_record(mixed_frontier_script, compression='none', revision=11), 101, 201),
        )
        connection.execute(
            "INSERT INTO cache_index (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (1, _build_js5_record(reference_table, compression='gzip'), -1, 999),
        )
        connection.commit()

    original_write_text = Path.write_text
    sabotaged_names = {"manifest.json", "clientscript-string-transform-arity-candidates.json"}

    def _write_zero_placeholder(self: Path, data: str, *args, **kwargs):
        if self.name in sabotaged_names:
            encoding = kwargs.get("encoding") or "utf-8"
            payload = data.encode(encoding)
            self.parent.mkdir(parents=True, exist_ok=True)
            self.write_bytes(b"\x00" * len(payload))
            return len(data)
        return original_write_text(self, data, *args, **kwargs)

    monkeypatch.setattr(Path, "write_text", _write_zero_placeholder)

    manifest = export_js5_cache(target, export_dir, tables=["cache"])
    manifest_path = export_dir / "manifest.json"
    candidate_path = Path(manifest["clientscript_string_transform_arity_candidates_path"])

    parsed_manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    parsed_candidates = json.loads(candidate_path.read_text(encoding="utf-8"))
    frontier_entry = next(entry for entry in parsed_candidates["opcodes"] if entry["raw_opcode_hex"] == "0x4004")

    assert parsed_manifest["report_version"] == "1.0"
    assert candidate_path.exists()
    assert frontier_entry["candidate_arity_profile"]["signature"] == "int+string"


def test_js5_export_reuses_clientscript_cache_dir(tmp_path, monkeypatch):
    root = tmp_path / "OpenNXT"
    target = root / "data" / "cache" / "js5-12.jcache"
    warm_export_dir = tmp_path / "exports-warm"
    reuse_export_dir = tmp_path / "exports-reuse"
    target.parent.mkdir(parents=True, exist_ok=True)
    _write_js5_mapping(root, build=947, index_names={12: "CLIENTSCRIPTS"})
    _write_clientscript_semantics(
        root,
        build=947,
        opcodes={
            "0x1001": {"mnemonic": "PUSH_INT_LITERAL", "family": "stack"},
            "0x2002": {
                "mnemonic": "RETURN",
                "family": "control-flow",
                "confidence": 0.9,
                "control_flow_kind": "return",
            },
        },
    )

    reference_table = _build_reference_table({0: [0], 1: [0]})
    int_script = _build_clientscript_payload(
        instruction_count=3,
        body_bytes=(
            _encode_clientscript_instruction(0x1001, "int", 10)
            + _encode_clientscript_instruction(0x1001, "int", 20)
            + _encode_clientscript_instruction(0x1001, "int", 30)
        ),
    )
    mixed_script = _build_clientscript_payload(
        instruction_count=3,
        body_bytes=(
            _encode_clientscript_instruction(0x1001, "int", 40)
            + _encode_clientscript_instruction(0x2002, "byte", 7)
            + _encode_clientscript_instruction(0x1001, "int", 50)
        ),
    )

    with sqlite3.connect(target) as connection:
        connection.execute("CREATE TABLE cache (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute("CREATE TABLE cache_index (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute(
            "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (0, _build_js5_record(int_script, compression='none', revision=11), 100, 200),
        )
        connection.execute(
            "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (1, _build_js5_record(mixed_script, compression='none', revision=11), 101, 201),
        )
        connection.execute(
            "INSERT INTO cache_index (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (1, _build_js5_record(reference_table, compression='gzip'), -1, 999),
        )
        connection.commit()

    warm_manifest = export_js5_cache(target, warm_export_dir, tables=["cache"])
    assert Path(warm_manifest["clientscript_opcode_catalog_path"]).exists()

    def _boom(*_args, **_kwargs):
        raise AssertionError("clientscript analysis should have been reused from cache")

    monkeypatch.setattr(js5_module, "_calibrate_clientscript_opcode_types", _boom)
    monkeypatch.setattr(js5_module, "_build_clientscript_opcode_catalog", _boom)
    monkeypatch.setattr(js5_module, "_build_clientscript_control_flow_candidates", _boom)
    monkeypatch.setattr(js5_module, "_build_clientscript_producer_candidates", _boom)
    monkeypatch.setattr(js5_module, "_resolve_clientscript_contextual_frontier_passes", _boom)
    monkeypatch.setattr(js5_module, "_build_clientscript_string_frontier_candidates", _boom)

    manifest = export_js5_cache(
        target,
        reuse_export_dir,
        tables=["cache"],
        clientscript_cache_dir=warm_export_dir,
    )
    file0 = manifest["tables"]["cache"]["records"][0]["archive_files"][0]

    assert manifest["settings"]["clientscript_cache_dir"] == str(warm_export_dir)
    assert manifest["clientscript_calibration"]["cache_mode"] == "reused"
    assert manifest["clientscript_calibration"]["cache_source"] == str(warm_export_dir)
    assert file0["semantic_profile"]["instruction_sample"][0]["semantic_label"] == "PUSH_INT_LITERAL"
    assert Path(manifest["clientscript_opcode_catalog_path"]).exists()


def test_js5_export_reuses_cached_semantic_suggestions_for_formatter_candidates(tmp_path, monkeypatch):
    root = tmp_path / "OpenNXT"
    target = root / "data" / "cache" / "js5-12.jcache"
    warm_export_dir = tmp_path / "exports-warm"
    reuse_export_dir = tmp_path / "exports-reuse"
    target.parent.mkdir(parents=True, exist_ok=True)
    _write_js5_mapping(root, build=947, index_names={12: "CLIENTSCRIPTS"})
    _write_clientscript_semantics(
        root,
        build=947,
        opcodes={
            "0x1001": {"mnemonic": "PUSH_INT_LITERAL", "family": "stack", "immediate_kind": "int"},
            "0x3003": {
                "mnemonic": "PUSH_CONST_STRING_CANDIDATE",
                "family": "stack-constant",
                "immediate_kind": "string",
            },
        },
    )

    reference_table = _build_reference_table({0: [0], 1: [0]})
    mixed_frontier_script = _build_clientscript_payload(
        instruction_count=3,
        body_bytes=(
            _encode_clientscript_instruction(0x1001, "int", 40)
            + _encode_clientscript_instruction(0x3003, "string", "Level: ")
            + b"\x40\x04\x00"
        ),
    )

    with sqlite3.connect(target) as connection:
        connection.execute("CREATE TABLE cache (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute("CREATE TABLE cache_index (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute(
            "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (0, _build_js5_record(mixed_frontier_script, compression='none', revision=11), 100, 200),
        )
        connection.execute(
            "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (1, _build_js5_record(mixed_frontier_script, compression='none', revision=11), 101, 201),
        )
        connection.execute(
            "INSERT INTO cache_index (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (1, _build_js5_record(reference_table, compression='gzip'), -1, 999),
        )
        connection.commit()

    export_js5_cache(target, warm_export_dir, tables=["cache"])
    (warm_export_dir / "clientscript-opcode-semantics.json").write_text(
        json.dumps(
            {
                "build": 947,
                "opcodes": {
                    "0x4004": {
                        "mnemonic": "STRING_FORMATTER_CANDIDATE",
                        "family": "string-transform-action",
                        "immediate_kind": "byte",
                        "confidence": 0.81,
                        "operand_signature_candidate": {
                            "target_kind": "string",
                            "signature": "int+string",
                            "min_int_inputs": 1,
                            "min_string_inputs": 1,
                            "confidence": 0.81,
                        },
                        "stack_effect_candidate": {
                            "int_pops": 1,
                            "string_pops": 1,
                            "string_pushes": 1,
                            "confidence": 0.81,
                        },
                    }
                },
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    def _boom(*_args, **_kwargs):
        raise AssertionError("clientscript analysis should have been reused from cache")

    monkeypatch.setattr(js5_module, "_calibrate_clientscript_opcode_types", _boom)
    monkeypatch.setattr(js5_module, "_build_clientscript_opcode_catalog", _boom)
    monkeypatch.setattr(js5_module, "_build_clientscript_control_flow_candidates", _boom)
    monkeypatch.setattr(js5_module, "_build_clientscript_producer_candidates", _boom)
    monkeypatch.setattr(js5_module, "_resolve_clientscript_contextual_frontier_passes", _boom)
    monkeypatch.setattr(js5_module, "_build_clientscript_string_frontier_candidates", _boom)

    manifest = export_js5_cache(
        target,
        reuse_export_dir,
        tables=["cache"],
        clientscript_cache_dir=warm_export_dir,
    )
    file0 = manifest["tables"]["cache"]["records"][0]["archive_files"][0]
    instruction_labels = [
        step.get("semantic_label")
        for step in file0["semantic_profile"]["instruction_sample"]
        if isinstance(step, dict)
    ]

    assert manifest["clientscript_calibration"]["cache_mode"] == "reused"
    assert "STRING_FORMATTER_CANDIDATE" in instruction_labels


def test_js5_export_uses_semantic_only_cache_dir_as_override_seed(tmp_path):
    root = tmp_path / "OpenNXT"
    target = root / "data" / "cache" / "js5-12.jcache"
    export_dir = tmp_path / "exports"
    semantic_seed_dir = tmp_path / "semantic-seeds"
    target.parent.mkdir(parents=True, exist_ok=True)
    semantic_seed_dir.mkdir(parents=True, exist_ok=True)
    _write_js5_mapping(root, build=947, index_names={12: "CLIENTSCRIPTS"})
    _write_clientscript_semantics(root, build=947, opcodes={})

    reference_table = _build_reference_table({0: [0], 1: [0]})
    mixed_frontier_script = _build_clientscript_payload(
        instruction_count=3,
        body_bytes=(
            _encode_clientscript_instruction(0x1001, "int", 40)
            + _encode_clientscript_instruction(0x3003, "string", "Level: ")
            + b"\x40\x04\x00"
        ),
    )

    with sqlite3.connect(target) as connection:
        connection.execute("CREATE TABLE cache (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute("CREATE TABLE cache_index (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute(
            "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (0, _build_js5_record(mixed_frontier_script, compression='none', revision=11), 100, 200),
        )
        connection.execute(
            "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (1, _build_js5_record(mixed_frontier_script, compression='none', revision=11), 101, 201),
        )
        connection.execute(
            "INSERT INTO cache_index (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (1, _build_js5_record(reference_table, compression='gzip'), -1, 999),
        )
        connection.commit()

    (semantic_seed_dir / "clientscript-opcode-semantics.json").write_text(
        json.dumps(
            {
                "build": 947,
                "source_path": str(target),
                "opcodes": {
                    "0x1001": {
                        "mnemonic": "PUSH_INT_LITERAL",
                        "family": "stack",
                        "immediate_kind": "int",
                    },
                    "0x3003": {
                        "mnemonic": "PUSH_CONST_STRING_CANDIDATE",
                        "family": "stack-constant",
                        "immediate_kind": "string",
                    },
                    "0x4004": {
                        "mnemonic": "STRING_FORMATTER_CANDIDATE",
                        "family": "string-transform-action",
                        "immediate_kind": "byte",
                        "confidence": 0.81,
                        "operand_signature_candidate": {
                            "target_kind": "string",
                            "signature": "int+string",
                            "min_int_inputs": 1,
                            "min_string_inputs": 1,
                            "confidence": 0.81,
                        },
                        "stack_effect_candidate": {
                            "int_pops": 1,
                            "string_pops": 1,
                            "string_pushes": 1,
                            "confidence": 0.81,
                        },
                    },
                },
            },
            indent=2,
        ),
        encoding="utf-8",
    )

    manifest = export_js5_cache(
        target,
        export_dir,
        tables=["cache"],
        clientscript_cache_dir=semantic_seed_dir,
    )
    file0 = manifest["tables"]["cache"]["records"][0]["archive_files"][0]
    instruction_labels = [
        step.get("semantic_label")
        for step in file0["semantic_profile"]["instruction_sample"]
        if isinstance(step, dict)
    ]

    assert manifest["clientscript_calibration"]["cache_mode"] == "rebuilt"
    assert "STRING_FORMATTER_CANDIDATE" in instruction_labels


def test_js5_export_uses_bom_semantic_seed_cache_dir_as_override_seed(tmp_path):
    root = tmp_path / "OpenNXT"
    target = root / "data" / "cache" / "js5-12.jcache"
    export_dir = tmp_path / "exports"
    semantic_seed_dir = tmp_path / "semantic-seeds"
    target.parent.mkdir(parents=True, exist_ok=True)
    semantic_seed_dir.mkdir(parents=True, exist_ok=True)
    _write_js5_mapping(root, build=947, index_names={12: "CLIENTSCRIPTS"})
    _write_clientscript_semantics(root, build=947, opcodes={})

    reference_table = _build_reference_table({0: [0], 1: [0]})
    mixed_frontier_script = _build_clientscript_payload(
        instruction_count=3,
        body_bytes=(
            _encode_clientscript_instruction(0x1001, "int", 40)
            + _encode_clientscript_instruction(0x3003, "string", "Level: ")
            + b"\x40\x04\x00"
        ),
    )

    with sqlite3.connect(target) as connection:
        connection.execute("CREATE TABLE cache (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute("CREATE TABLE cache_index (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute(
            "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (0, _build_js5_record(mixed_frontier_script, compression='none', revision=11), 100, 200),
        )
        connection.execute(
            "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (1, _build_js5_record(mixed_frontier_script, compression='none', revision=11), 101, 201),
        )
        connection.execute(
            "INSERT INTO cache_index (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (1, _build_js5_record(reference_table, compression='gzip'), -1, 999),
        )
        connection.commit()

    (semantic_seed_dir / "clientscript-opcode-semantics.json").write_text(
        json.dumps(
            {
                "build": 947,
                "source_path": str(target),
                "opcodes": {
                    "0x1001": {
                        "mnemonic": "PUSH_INT_LITERAL",
                        "family": "stack",
                        "immediate_kind": "int",
                    },
                    "0x3003": {
                        "mnemonic": "PUSH_CONST_STRING_CANDIDATE",
                        "family": "stack-constant",
                        "immediate_kind": "string",
                    },
                    "0x4004": {
                        "mnemonic": "STRING_FORMATTER_CANDIDATE",
                        "family": "string-transform-action",
                        "immediate_kind": "byte",
                        "confidence": 0.81,
                        "operand_signature_candidate": {
                            "target_kind": "string",
                            "signature": "int+string",
                            "min_int_inputs": 1,
                            "min_string_inputs": 1,
                            "confidence": 0.81,
                        },
                        "stack_effect_candidate": {
                            "int_pops": 1,
                            "string_pops": 1,
                            "string_pushes": 1,
                            "confidence": 0.81,
                        },
                    },
                },
            },
            indent=2,
        ),
        encoding="utf-8-sig",
    )

    manifest = export_js5_cache(
        target,
        export_dir,
        tables=["cache"],
        clientscript_cache_dir=semantic_seed_dir,
    )
    file0 = manifest["tables"]["cache"]["records"][0]["archive_files"][0]
    instruction_labels = [
        step.get("semantic_label")
        for step in file0["semantic_profile"]["instruction_sample"]
        if isinstance(step, dict)
    ]

    assert manifest["clientscript_calibration"]["cache_mode"] == "rebuilt"
    assert str(semantic_seed_dir) in str(
        manifest["clientscript_calibration"]["semantic_override_source"]
    )
    assert "STRING_FORMATTER_CANDIDATE" in instruction_labels


def test_js5_export_builds_switch_skeleton_cfg_for_metadata_only_script(tmp_path):
    root = tmp_path / "OpenNXT"
    target = root / "data" / "cache" / "js5-12.jcache"
    export_dir = tmp_path / "exports"
    target.parent.mkdir(parents=True, exist_ok=True)
    _write_js5_mapping(root, build=947, index_names={12: "CLIENTSCRIPTS"})

    reference_table = _build_reference_table({0: [0]})
    script_payload = _build_clientscript_payload(
        instruction_count=12,
        switch_tables=[{10: 1, 20: 5, 30: 9}],
        body_bytes=b"\x01\x02\x03\x04",
    )

    with sqlite3.connect(target) as connection:
        connection.execute("CREATE TABLE cache (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute("CREATE TABLE cache_index (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute(
            "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (0, _build_js5_record(script_payload, compression='none', revision=11), 100, 200),
        )
        connection.execute(
            "INSERT INTO cache_index (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (1, _build_js5_record(reference_table, compression='gzip'), -1, 999),
        )
        connection.commit()

    manifest = export_js5_cache(target, export_dir, tables=["cache"])
    file0 = manifest["tables"]["cache"]["records"][0]["archive_files"][0]
    cfg_dot_path = Path(file0["semantic_profile"]["cfg_dot_path"])
    cfg_json_path = Path(file0["semantic_profile"]["cfg_json_path"])

    assert file0["semantic_profile"]["cfg_mode"] == "switch-skeleton"
    assert manifest["summary"]["cfg_graph_count"] == 1
    assert cfg_dot_path.exists()
    assert cfg_json_path.exists()
    assert 'switch[0]=10' in cfg_dot_path.read_text(encoding="utf-8")
    assert json.loads(cfg_json_path.read_text(encoding="utf-8"))["block_count"] == 4


def test_js5_export_writes_clientscript_control_flow_candidates(tmp_path):
    root = tmp_path / "OpenNXT"
    target = root / "data" / "cache" / "js5-12.jcache"
    export_dir = tmp_path / "exports"
    target.parent.mkdir(parents=True, exist_ok=True)
    _write_js5_mapping(root, build=947, index_names={12: "CLIENTSCRIPTS"})

    reference_table = _build_reference_table({0: [0], 1: [0], 2: [0], 3: [0], 4: [0]})
    int_script = _build_clientscript_payload(
        instruction_count=3,
        body_bytes=(
            _encode_clientscript_instruction(0x1001, "int", 10)
            + _encode_clientscript_instruction(0x1001, "int", 20)
            + _encode_clientscript_instruction(0x1001, "int", 30)
        ),
    )
    byte_script = _build_clientscript_payload(
        instruction_count=3,
        body_bytes=(
            _encode_clientscript_instruction(0x2002, "byte", 1)
            + _encode_clientscript_instruction(0x2002, "byte", 2)
            + _encode_clientscript_instruction(0x2002, "byte", 3)
        ),
    )
    mixed_script = _build_clientscript_payload(
        instruction_count=3,
        body_bytes=(
            _encode_clientscript_instruction(0x1001, "int", 40)
            + _encode_clientscript_instruction(0x2002, "byte", 7)
            + _encode_clientscript_instruction(0x1001, "int", 50)
        ),
    )
    switch_frontier_a = _build_clientscript_payload(
        instruction_count=3,
        switch_tables=[{10: 1, 20: 5}],
        body_bytes=(
            _encode_clientscript_instruction(0x2002, "byte", 7)
            + b"\x30\x03\x00\x40\x04"
        ),
    )
    switch_frontier_b = _build_clientscript_payload(
        instruction_count=3,
        switch_tables=[{30: 1, 40: 5, 50: 9}],
        body_bytes=(
            _encode_clientscript_instruction(0x2002, "byte", 9)
            + b"\x30\x03\x01\x50\x05"
        ),
    )

    with sqlite3.connect(target) as connection:
        connection.execute("CREATE TABLE cache (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute("CREATE TABLE cache_index (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute(
            "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (0, _build_js5_record(int_script, compression='none', revision=11), 100, 200),
        )
        connection.execute(
            "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (1, _build_js5_record(byte_script, compression='none', revision=11), 101, 201),
        )
        connection.execute(
            "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (2, _build_js5_record(mixed_script, compression='none', revision=11), 102, 202),
        )
        connection.execute(
            "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (3, _build_js5_record(switch_frontier_a, compression='none', revision=11), 103, 203),
        )
        connection.execute(
            "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (4, _build_js5_record(switch_frontier_b, compression='none', revision=11), 104, 204),
        )
        connection.execute(
            "INSERT INTO cache_index (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (1, _build_js5_record(reference_table, compression='gzip'), -1, 999),
        )
        connection.commit()

    manifest = export_js5_cache(target, export_dir, tables=["cache"])
    candidate_path = Path(manifest["clientscript_control_flow_candidates_path"])
    suggestions_path = Path(manifest["clientscript_semantic_suggestions_path"])
    candidates = json.loads(candidate_path.read_text(encoding="utf-8"))
    suggestions = json.loads(suggestions_path.read_text(encoding="utf-8"))
    frontier_entry = next(entry for entry in candidates["opcodes"] if entry["raw_opcode_hex"] == "0x3003")
    frontier_profile = manifest["tables"]["cache"]["records"][3]["archive_files"][0]["semantic_profile"]

    assert candidate_path.exists()
    assert suggestions_path.exists()
    assert manifest["clientscript_calibration"]["control_flow_candidates"]["frontier_opcode_count"] >= 1
    assert frontier_entry["candidate_mnemonic"] == "CONTROL_FLOW_FRONTIER_CANDIDATE"
    assert frontier_entry["script_count"] == 2
    assert frontier_entry["switch_script_count"] == 2
    assert frontier_entry["suggested_immediate_kind"] == "byte"
    assert frontier_entry["immediate_kind_candidates"][0]["immediate_kind"] == "byte"
    assert frontier_profile["kind"] == "clientscript-metadata"
    assert frontier_profile["frontier_raw_opcode_hex"] == "0x4004"
    assert frontier_profile["frontier_instruction_sample"][1]["semantic_label"] == "CONTROL_FLOW_FRONTIER_CANDIDATE"
    assert frontier_profile["cfg_mode"] == "switch-skeleton"
    assert suggestions["opcodes"]["0x3003"]["immediate_kind"] == "byte"


def test_js5_export_surfaces_clientscript_jump_offset_candidates(tmp_path):
    root = tmp_path / "OpenNXT"
    target = root / "data" / "cache" / "js5-12.jcache"
    export_dir = tmp_path / "exports"
    target.parent.mkdir(parents=True, exist_ok=True)
    _write_js5_mapping(root, build=947, index_names={12: "CLIENTSCRIPTS"})

    reference_table = _build_reference_table({0: [0], 1: [0], 2: [0], 3: [0], 4: [0]})
    int_script = _build_clientscript_payload(
        instruction_count=3,
        body_bytes=(
            _encode_clientscript_instruction(0x1001, "int", 10)
            + _encode_clientscript_instruction(0x1001, "int", 20)
            + _encode_clientscript_instruction(0x1001, "int", 30)
        ),
    )
    byte_script = _build_clientscript_payload(
        instruction_count=3,
        body_bytes=(
            _encode_clientscript_instruction(0x2002, "byte", 1)
            + _encode_clientscript_instruction(0x2002, "byte", 2)
            + _encode_clientscript_instruction(0x2002, "byte", 3)
        ),
    )
    mixed_script = _build_clientscript_payload(
        instruction_count=3,
        body_bytes=(
            _encode_clientscript_instruction(0x1001, "int", 40)
            + _encode_clientscript_instruction(0x2002, "byte", 7)
            + _encode_clientscript_instruction(0x1001, "int", 50)
        ),
    )
    jump_frontier_a = _build_clientscript_payload(
        instruction_count=3,
        body_bytes=(
            _encode_clientscript_instruction(0x1001, "int", 7)
            + _encode_clientscript_instruction(0x4004, "short", -10)
            + _encode_clientscript_instruction(0x2002, "byte", 1)
        ),
    )
    jump_frontier_b = _build_clientscript_payload(
        instruction_count=3,
        body_bytes=(
            _encode_clientscript_instruction(0x1001, "int", 9)
            + _encode_clientscript_instruction(0x4004, "short", -10)
            + _encode_clientscript_instruction(0x2002, "byte", 2)
        ),
    )

    with sqlite3.connect(target) as connection:
        connection.execute("CREATE TABLE cache (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute("CREATE TABLE cache_index (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        for key, payload, version, crc in [
            (0, int_script, 100, 200),
            (1, byte_script, 101, 201),
            (2, mixed_script, 102, 202),
            (3, jump_frontier_a, 103, 203),
            (4, jump_frontier_b, 104, 204),
        ]:
            connection.execute(
                "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
                (key, _build_js5_record(payload, compression='none', revision=11), version, crc),
            )
        connection.execute(
            "INSERT INTO cache_index (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (1, _build_js5_record(reference_table, compression='gzip'), -1, 999),
        )
        connection.commit()

    manifest = export_js5_cache(target, export_dir, tables=["cache"])
    candidate_path = Path(manifest["clientscript_control_flow_candidates_path"])
    suggestions_path = Path(manifest["clientscript_semantic_suggestions_path"])
    candidates = json.loads(candidate_path.read_text(encoding="utf-8"))
    suggestions = json.loads(suggestions_path.read_text(encoding="utf-8"))
    frontier_entry = next(entry for entry in candidates["opcodes"] if entry["raw_opcode_hex"] == "0x4004")
    short_candidate = next(
        candidate
        for candidate in frontier_entry["immediate_kind_candidates"]
        if candidate["immediate_kind"] == "short"
    )
    frontier_profile = manifest["tables"]["cache"]["records"][3]["archive_files"][0]["semantic_profile"]

    assert candidate_path.exists()
    assert suggestions_path.exists()
    assert frontier_entry["candidate_mnemonic"] == "JUMP_OFFSET_FRONTIER_CANDIDATE"
    assert frontier_entry["suggested_immediate_kind"] == "short"
    assert short_candidate["relative_target_count"] == 2
    assert short_candidate["relative_target_instruction_boundary_count"] == 2
    assert short_candidate["relative_target_backward_count"] == 2
    assert short_candidate["relative_target_sample"][0]["target_offset"] == 0
    assert short_candidate["relative_target_sample"][0]["target_relation"] == "instruction-boundary"
    assert suggestions["opcodes"]["0x4004"]["immediate_kind"] == "short"
    assert suggestions["opcodes"]["0x4004"]["control_flow_kind"] == "branch-candidate"
    assert suggestions["opcodes"]["0x4004"]["jump_base"] == "next_offset"
    assert frontier_profile["kind"] == "clientscript-disassembly"
    assert frontier_profile["raw_opcode_types_sample"][2]["raw_opcode_hex"] == "0x4004"
    assert frontier_profile["raw_opcode_types_sample"][2]["immediate_kind"] == "short"
    assert frontier_profile["raw_opcode_types_sample"][2]["semantic_label"] == "JUMP_OFFSET_FRONTIER_CANDIDATE"
    assert frontier_profile["raw_opcode_types_sample"][2]["stack_effect_candidate"]["int_pops"] == 1
    assert frontier_profile["instruction_sample"][1]["semantic_label"] == "JUMP_OFFSET_FRONTIER_CANDIDATE"
    assert frontier_profile["instruction_sample"][1]["stack_effect_candidate"]["int_pops"] == 1
    assert frontier_profile["instruction_sample"][1]["int_stack_depth_before"] == 1
    assert frontier_profile["instruction_sample"][1]["int_stack_depth_after"] == 0
    branch_expression = frontier_profile["instruction_sample"][1]["branch_condition_expression"]
    assert branch_expression["kind"] in {"int-literal", "int-input"}
    if branch_expression["kind"] == "int-literal":
        assert frontier_profile["stack_tracking"]["minimum_required_inputs"] == {}
    else:
        assert frontier_profile["stack_tracking"]["minimum_required_inputs"] == {"int_stack": 1}
    assert frontier_profile["cfg_mode"] == "override-aware"
    assert frontier_profile["cfg_edge_count"] == 2
    assert {edge["kind"] for edge in frontier_profile["cfg_edges_sample"]} == {"branch", "fallthrough"}


def test_js5_export_infers_clientscript_producer_candidates(tmp_path):
    root = tmp_path / "OpenNXT"
    target = root / "data" / "cache" / "js5-12.jcache"
    export_dir = tmp_path / "exports"
    target.parent.mkdir(parents=True, exist_ok=True)
    _write_js5_mapping(root, build=947, index_names={12: "CLIENTSCRIPTS"})

    reference_table = _build_reference_table({0: [0], 1: [0], 2: [0], 3: [0], 4: [0]})
    int_script = _build_clientscript_payload(
        instruction_count=3,
        body_bytes=(
            _encode_clientscript_instruction(0x1001, "int", 10)
            + _encode_clientscript_instruction(0x1001, "int", 20)
            + _encode_clientscript_instruction(0x1001, "int", 30)
        ),
    )
    byte_script = _build_clientscript_payload(
        instruction_count=3,
        body_bytes=(
            _encode_clientscript_instruction(0x2002, "byte", 1)
            + _encode_clientscript_instruction(0x2002, "byte", 2)
            + _encode_clientscript_instruction(0x2002, "byte", 3)
        ),
    )
    mixed_script = _build_clientscript_payload(
        instruction_count=3,
        body_bytes=(
            _encode_clientscript_instruction(0x1001, "int", 40)
            + _encode_clientscript_instruction(0x2002, "byte", 7)
            + _encode_clientscript_instruction(0x1001, "int", 50)
        ),
    )
    jump_frontier_a = _build_clientscript_payload(
        instruction_count=3,
        body_bytes=(
            _encode_clientscript_instruction(0x1001, "int", 77)
            + _encode_clientscript_instruction(0x4004, "short", -10)
            + _encode_clientscript_instruction(0x2002, "byte", 1)
        ),
    )
    jump_frontier_b = _build_clientscript_payload(
        instruction_count=3,
        body_bytes=(
            _encode_clientscript_instruction(0x1001, "int", 99)
            + _encode_clientscript_instruction(0x4004, "short", -10)
            + _encode_clientscript_instruction(0x2002, "byte", 2)
        ),
    )

    with sqlite3.connect(target) as connection:
        connection.execute("CREATE TABLE cache (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute("CREATE TABLE cache_index (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        for key, payload, version, crc in [
            (0, int_script, 100, 200),
            (1, byte_script, 101, 201),
            (2, mixed_script, 102, 202),
            (3, jump_frontier_a, 103, 203),
            (4, jump_frontier_b, 104, 204),
        ]:
            connection.execute(
                "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
                (key, _build_js5_record(payload, compression='none', revision=11), version, crc),
            )
        connection.execute(
            "INSERT INTO cache_index (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (1, _build_js5_record(reference_table, compression='gzip'), -1, 999),
        )
        connection.commit()

    manifest = export_js5_cache(target, export_dir, tables=["cache"])
    producer_path = Path(manifest["clientscript_producer_candidates_path"])
    producer_candidates = json.loads(producer_path.read_text(encoding="utf-8"))
    producer_entry = next(entry for entry in producer_candidates["opcodes"] if entry["raw_opcode_hex"] == "0x1001")
    profile = manifest["tables"]["cache"]["records"][3]["archive_files"][0]["semantic_profile"]

    assert producer_path.exists()
    assert producer_entry["candidate_mnemonic"] == "PUSH_INT_CANDIDATE"
    assert producer_entry["control_flow_successor_count"] == 2
    assert producer_entry["branch_successor_count"] == 2
    assert producer_entry["consumer_raw_opcode_sample"][0]["raw_opcode_hex"] == "0x4004"
    assert producer_entry["trace_samples"][0]["consumer_kind"] == "branch"
    assert profile["kind"] == "clientscript-disassembly"
    assert profile["instruction_sample"][0]["semantic_label"] == "PUSH_INT_CANDIDATE"
    assert profile["instruction_sample"][0]["produced_int_expressions"][0]["value"] == 77
    assert profile["instruction_sample"][1]["branch_condition_expression"]["value"] == 77
    assert profile["stack_tracking"]["minimum_required_inputs"] == {}


def test_build_clientscript_contextual_frontier_candidates():
    target = Path(":memory:")
    calibration_script = _build_clientscript_payload(
        instruction_count=3,
        body_bytes=(
            _encode_clientscript_instruction(0x1001, "int", 10)
            + _encode_clientscript_instruction(0x1001, "int", 20)
            + _encode_clientscript_instruction(0x1001, "int", 30)
        ),
    )
    switch_frontier_a = _build_clientscript_payload(
        instruction_count=4,
        switch_tables=[{10: 1, 20: 5}],
        body_bytes=(
            _encode_clientscript_instruction(0x1001, "int", 7)
            + b"\x30\x03\x00"
            + _encode_clientscript_instruction(0x1001, "int", 77)
            + _encode_clientscript_instruction(0x9009, "int", 123)
        ),
    )
    switch_frontier_b = _build_clientscript_payload(
        instruction_count=4,
        switch_tables=[{30: 1, 40: 5, 50: 9}],
        body_bytes=(
            _encode_clientscript_instruction(0x1001, "int", 9)
            + b"\x30\x03\x01"
            + _encode_clientscript_instruction(0x1001, "int", 99)
            + _encode_clientscript_instruction(0x9009, "int", 321)
        ),
    )

    locked_opcode_types = {0x1001: "int"}
    raw_opcode_catalog = {
        0x1001: {"mnemonic": "PUSH_INT_CANDIDATE", "family": "stack", "immediate_kind": "int"},
        0x3003: {
            "mnemonic": "SWITCH_DISPATCH_FRONTIER_CANDIDATE",
            "family": "control-flow",
            "immediate_kind": "byte",
        },
    }

    with sqlite3.connect(target) as connection:
        connection.execute("CREATE TABLE cache (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        for key, payload in [
            (0, calibration_script),
            (1, switch_frontier_a),
            (2, switch_frontier_b),
        ]:
            connection.execute(
                "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
                (key, _build_js5_record(payload, compression='none', revision=11), key, key + 100),
            )
        connection.commit()

        contextual_candidates, contextual_summary = _build_clientscript_contextual_frontier_candidates(
            connection,
            locked_opcode_types=locked_opcode_types,
            raw_opcode_catalog=raw_opcode_catalog,
            include_keys=[],
            max_decoded_bytes=64 * 1024 * 1024,
            sample_limit=16,
        )

    contextual_entry = contextual_candidates[0x9009]
    assert contextual_summary["frontier_opcode_count"] >= 1
    assert contextual_entry["candidate_mnemonic"] == "INT_STATE_GETTER_CANDIDATE"
    assert contextual_entry["suggested_immediate_kind"] == "int"
    assert contextual_entry["prefix_switch_dispatch_count"] == 2
    assert contextual_entry["prefix_push_int_count"] == 2
    assert contextual_entry["previous_semantic_label_sample"][0]["label"] == "PUSH_INT_CANDIDATE"

    merged_catalog = dict(raw_opcode_catalog)
    merged_catalog[0x9009] = {
        **contextual_entry,
        "immediate_kind": contextual_entry["suggested_immediate_kind"],
    }
    profile = profile_archive_file(
        switch_frontier_a,
        index_name="CLIENTSCRIPTS",
        archive_key=0,
        file_id=0,
        clientscript_opcode_types=locked_opcode_types,
        clientscript_opcode_catalog=merged_catalog,
    )

    assert profile is not None
    assert profile["kind"] == "clientscript-disassembly"
    assert profile["instruction_sample"][3]["semantic_label"] == "INT_STATE_GETTER_CANDIDATE"
    assert profile["instruction_sample"][3]["stack_effect_candidate"]["int_pushes"] == 1
    assert profile["instruction_sample"][3]["produced_int_expressions"][0]["kind"] == "state-reference"
    assert profile["instruction_sample"][3]["produced_int_expressions"][0]["reference_id"] == 123


def test_infer_clientscript_contextual_frontier_candidate_prefers_int_over_overshoot_probe():
    entry = {
        "script_count": 1,
        "prefix_switch_dispatch_count": 1,
        "prefix_push_int_count": 1,
        "previous_push_int_count": 1,
        "immediate_kind_candidates": [
            {
                "immediate_kind": "byte",
                "valid_trace_count": 1,
                "complete_trace_count": 0,
                "improved_script_count": 1,
                "total_progress_instruction_count": 28,
                "next_frontier_trace_count": 0,
                "trace_samples": [
                    {
                        "trace_status": "extra-bytes",
                        "decoded_instruction_count": 38,
                    }
                ],
            },
            {
                "immediate_kind": "int",
                "valid_trace_count": 1,
                "complete_trace_count": 0,
                "improved_script_count": 1,
                "total_progress_instruction_count": 1,
                "next_frontier_trace_count": 1,
                "trace_samples": [
                    {
                        "trace_status": "frontier",
                        "next_frontier_raw_opcode_hex": "0x1300",
                    }
                ],
            },
        ],
    }

    inferred = _infer_clientscript_contextual_frontier_candidate(entry)

    assert inferred["candidate_mnemonic"] == "INT_STATE_GETTER_CANDIDATE"
    assert inferred["suggested_immediate_kind"] == "int"
    assert any("overshoot probe" in reason for reason in inferred["candidate_reasons"])


def test_infer_clientscript_contextual_frontier_candidate_prefers_int_over_misaligned_short_probe():
    entry = {
        "script_count": 1,
        "prefix_switch_dispatch_count": 1,
        "prefix_push_int_count": 1,
        "previous_push_int_count": 1,
        "immediate_kind_candidates": [
            {
                "immediate_kind": "short",
                "valid_trace_count": 1,
                "complete_trace_count": 0,
                "improved_script_count": 1,
                "total_progress_instruction_count": 1,
                "next_frontier_trace_count": 1,
                "relative_target_count": 1,
                "relative_target_in_bounds_count": 1,
                "relative_target_instruction_boundary_count": 0,
                "trace_samples": [
                    {
                        "trace_status": "frontier",
                        "next_frontier_raw_opcode_hex": "0x007B",
                    }
                ],
            },
            {
                "immediate_kind": "int",
                "valid_trace_count": 1,
                "complete_trace_count": 0,
                "improved_script_count": 1,
                "total_progress_instruction_count": 1,
                "next_frontier_trace_count": 1,
                "trace_samples": [
                    {
                        "trace_status": "frontier",
                        "next_frontier_raw_opcode_hex": "0x9010",
                    }
                ],
            },
        ],
    }

    inferred = _infer_clientscript_contextual_frontier_candidate(entry)

    assert inferred["candidate_mnemonic"] == "INT_STATE_GETTER_CANDIDATE"
    assert inferred["suggested_immediate_kind"] == "int"
    assert any("short in-bounds probe" in reason for reason in inferred["candidate_reasons"])


def test_build_clientscript_semantic_suggestions_includes_contextual_frontiers():
    suggestions = _build_clientscript_semantic_suggestions(
        control_flow_candidates={},
        contextual_frontier_candidates={
            0x9200: {
                "candidate_mnemonic": "INT_STATE_GETTER_CANDIDATE",
                "suggested_immediate_kind": "int",
                "family": "state-reader",
                "candidate_confidence": 0.67,
                "candidate_reasons": [
                    "Downstream frontier repeatedly appears after a known switch dispatch and integer setup sequence."
                ],
            }
        },
    )

    assert suggestions["0x9200"]["mnemonic"] == "INT_STATE_GETTER_CANDIDATE"
    assert suggestions["0x9200"]["immediate_kind"] == "int"
    assert suggestions["0x9200"]["family"] == "state-reader"
    assert suggestions["0x9200"]["confidence"] == 0.67


def test_build_clientscript_semantic_suggestions_prefers_contextual_state_reader_over_generic_control_flow():
    suggestions = _build_clientscript_semantic_suggestions(
        control_flow_candidates={
            0x1100: {
                "candidate_mnemonic": "CONTROL_FLOW_FRONTIER_CANDIDATE",
                "suggested_immediate_kind": "short",
                "family": "control-flow",
                "candidate_confidence": 0.9,
                "switch_script_count": 2,
            }
        },
        contextual_frontier_candidates={
            0x1100: {
                "candidate_mnemonic": "INT_STATE_GETTER_CANDIDATE",
                "suggested_immediate_kind": "int",
                "family": "state-reader",
                "candidate_confidence": 0.7,
                "candidate_reasons": [
                    "Downstream frontier repeatedly appears after a known switch dispatch and integer setup sequence."
                ],
            }
        },
    )

    assert suggestions["0x1100"]["mnemonic"] == "INT_STATE_GETTER_CANDIDATE"
    assert suggestions["0x1100"]["immediate_kind"] == "int"
    assert suggestions["0x1100"]["family"] == "state-reader"


def test_build_clientscript_semantic_suggestions_includes_string_frontiers():
    suggestions = _build_clientscript_semantic_suggestions(
        control_flow_candidates={},
        string_frontier_candidates={
            0x3003: {
                "candidate_mnemonic": "PUSH_CONST_STRING_CANDIDATE",
                "suggested_immediate_kind": "string",
                "family": "stack-constant",
                "candidate_confidence": 0.83,
                "script_count": 2,
                "complete_trace_count": 0,
                "candidate_reasons": [
                    "String-rich scripts decode only when this frontier is treated as a null-terminated CP1252 literal."
                ],
            }
        },
    )

    assert suggestions["0x3003"]["mnemonic"] == "PUSH_CONST_STRING_CANDIDATE"
    assert suggestions["0x3003"]["immediate_kind"] == "string"
    assert suggestions["0x3003"]["family"] == "stack-constant"
    assert suggestions["0x3003"]["confidence"] == 0.83


def test_build_clientscript_semantic_suggestions_prefers_high_confidence_string_transform_arity():
    suggestions = _build_clientscript_semantic_suggestions(
        control_flow_candidates={
            0x006A: {
                "candidate_mnemonic": "CONTROL_FLOW_FRONTIER_CANDIDATE",
                "suggested_immediate_kind": "byte",
                "suggested_immediate_kind_confidence": 0.9,
                "family": "control-flow",
                "candidate_confidence": 0.36,
                "switch_script_count": 2,
            }
        },
        string_transform_arity_candidates={
            0x006A: {
                "immediate_kind": "byte",
                "candidate_arity_profile": {
                    "candidate_mnemonic": "STRING_FORMATTER_CANDIDATE",
                    "family": "string-transform-action",
                    "signature": "string+string",
                    "confidence": 0.8,
                    "match_count": 2,
                    "notes": "Top-of-stack window repeatedly looks like two strings being merged into a new string result.",
                    "operand_signature_candidate": {
                        "target_kind": "string",
                        "signature": "string+string",
                        "min_string_inputs": 2,
                        "confidence": 0.8,
                    },
                    "stack_effect_candidate": {
                        "string_pops": 2,
                        "string_pushes": 1,
                        "confidence": 0.8,
                    },
                },
            }
        },
    )

    assert suggestions["0x006A"]["mnemonic"] == "STRING_FORMATTER_CANDIDATE"
    assert suggestions["0x006A"]["immediate_kind"] == "byte"
    assert suggestions["0x006A"]["promotion_source"] == "string-transform-arity"
    assert suggestions["0x006A"]["stack_effect_candidate"]["string_pushes"] == 1


def test_refine_clientscript_frontier_state_reader_candidate_prefers_int_with_semantic_tail():
    entry = {
        "script_count": 402,
        "switch_script_count": 0,
        "frontier_offsets_sample": [0],
        "frontier_instruction_index_sample": [0],
        "immediate_kind_candidates": [
            {
                "immediate_kind": "byte",
                "complete_trace_count": 402,
                "known_terminal_semantic_count": 0,
                "max_decoded_instruction_count": 2,
                "terminal_semantic_label_sample": [],
            },
            {
                "immediate_kind": "int",
                "complete_trace_count": 402,
                "known_terminal_semantic_count": 320,
                "max_decoded_instruction_count": 2,
                "terminal_semantic_label_sample": [
                    {"label": "TERMINATOR_CANDIDATE", "count": 180},
                    {"label": "JUMP_OFFSET_FRONTIER_CANDIDATE", "count": 100},
                    {"label": "SWITCH_DISPATCH_FRONTIER_CANDIDATE", "count": 40},
                ],
            },
        ],
    }

    _refine_clientscript_frontier_state_reader_candidate(entry)

    assert entry["candidate_mnemonic"] == "INT_STATE_GETTER_CANDIDATE"
    assert entry["suggested_immediate_kind"] == "int"
    assert entry["family"] == "state-reader"
    assert entry["candidate_confidence"] >= 0.67


def test_infer_clientscript_frontier_candidate_only_marks_switch_dispatch_at_entry():
    inferred = _infer_clientscript_frontier_candidate(
        {
            "script_count": 1,
            "switch_script_count": 1,
            "switch_case_count": 4,
            "frontier_offsets": [16],
            "frontier_instruction_indices": [3],
        }
    )

    assert inferred == {}


def test_refine_clientscript_switch_case_payload_candidate_marks_case_body_action():
    entry = {
        "script_count": 1,
        "switch_script_count": 1,
        "switch_script_ratio": 1.0,
        "switch_case_count": 29,
        "frontier_offsets_sample": [22],
        "frontier_instruction_index_sample": [4],
        "prefix_switch_dispatch_count": 1,
        "prefix_push_int_count": 1,
        "previous_push_int_count": 1,
        "previous_semantic_label_sample": [{"label": "INT_STATE_GETTER_CANDIDATE", "count": 1}],
        "immediate_kind_candidates": [
            {
                "immediate_kind": "tribyte",
                "improved_script_count": 1,
                "complete_trace_count": 0,
                "max_decoded_instruction_count": 5,
                "next_frontier_trace_count": 1,
                "relative_target_count": 0,
                "relative_target_instruction_boundary_count": 0,
            }
        ],
    }

    _refine_clientscript_switch_case_payload_candidate(entry)

    assert entry["candidate_mnemonic"] == "SWITCH_CASE_ACTION_CANDIDATE"
    assert entry["family"] == "payload-action"
    assert entry["suggested_immediate_kind"] == "tribyte"
    assert entry["candidate_confidence"] >= 0.5


def test_infer_clientscript_stack_effect_for_switch_case_payload_consumes_prepared_int():
    effect = _infer_clientscript_stack_effect(
        {
            "candidate_mnemonic": "SWITCH_CASE_ACTION_CANDIDATE",
            "previous_push_int_count": 1,
            "previous_semantic_label_sample": [{"label": "INT_STATE_GETTER_CANDIDATE", "count": 1}],
        }
    )

    assert effect is not None
    assert effect["int_pops"] == 1


def test_infer_clientscript_produced_expression_renders_widget_reference():
    expression = _infer_clientscript_produced_expression(
        {
            "semantic_label": "PUSH_INT_CANDIDATE",
            "raw_opcode_hex": "0x0000",
            "immediate_value": 300288,
        },
        stack_name="int",
        consumed_expressions=[],
        produce_index=0,
    )

    assert expression["kind"] == "widget-reference"
    assert expression["interface_id"] == 4
    assert expression["component_id"] == 38144
    assert _format_clientscript_expression(expression) == "widget[4:38144]"


def test_summarize_clientscript_prefix_stack_state_detects_int_string_mix():
    summary = _summarize_clientscript_prefix_stack_state(
        [
            {
                "raw_opcode": 0x1001,
                "raw_opcode_hex": "0x1001",
                "semantic_label": "PUSH_INT_LITERAL",
                "immediate_kind": "int",
                "immediate_value": 99,
            },
            {
                "raw_opcode": 0x3003,
                "raw_opcode_hex": "0x3003",
                "semantic_label": "PUSH_CONST_STRING_CANDIDATE",
                "immediate_kind": "string",
                "immediate_value": "Level: ",
            },
        ]
    )

    assert summary["prefix_operand_signature"] == "int+string"
    assert summary["prefix_string_result_stack_count"] == 0


def test_refine_clientscript_widget_mutator_candidate_promotes_widget_payload():
    entry = {
        "candidate_mnemonic": "SWITCH_CASE_ACTION_CANDIDATE",
        "family": "payload-action",
        "candidate_confidence": 0.62,
        "candidate_reasons": ["base reason"],
        "suggested_immediate_kind": "short",
        "prefix_widget_literal_count": 2,
        "previous_widget_literal_count": 1,
    }

    _refine_clientscript_widget_mutator_candidate(entry)

    assert entry["candidate_mnemonic"] == "WIDGET_MUTATOR_CANDIDATE"
    assert entry["family"] == "widget-action"
    assert entry["candidate_confidence"] > 0.62
    assert "widget-id literals" in " ".join(entry["candidate_reasons"])


def test_infer_clientscript_stack_effect_for_widget_mutator_consumes_widget_input():
    effect = _infer_clientscript_stack_effect(
        {
            "candidate_mnemonic": "WIDGET_MUTATOR_CANDIDATE",
            "prefix_widget_literal_count": 1,
        }
    )

    assert effect is not None
    assert effect["int_pops"] == 1


def test_infer_clientscript_widget_operand_signature_prefers_widget_plus_int():
    signature = _infer_clientscript_widget_operand_signature(
        {
            "candidate_mnemonic": "WIDGET_MUTATOR_CANDIDATE",
            "prefix_widget_literal_count": 1,
            "prefix_widget_stack_script_count": 1,
            "prefix_secondary_int_script_count": 1,
            "prefix_operand_signature_sample": [{"signature": "widget+int", "count": 2}],
        }
    )

    assert signature is not None
    assert signature["signature"] == "widget+int"
    assert signature["min_int_inputs"] == 2
    assert signature["min_string_inputs"] == 0


def test_summarize_clientscript_consumed_operand_window_detects_widget_widget():
    summary = _summarize_clientscript_consumed_operand_window(
        {
            "candidate_mnemonic": "WIDGET_MUTATOR_CANDIDATE",
            "stack_effect_candidate": {
                "int_pops": 2,
            },
            "script_samples": [
                {
                    "key": 2,
                    "prefix_int_stack_sample": [
                        {"kind": "int-literal", "value": 1811},
                        {"kind": "widget-reference", "packed_value": 984337, "interface_id": 15, "component_id": 1297},
                        {"kind": "widget-reference", "packed_value": 1121544, "interface_id": 17, "component_id": 7432},
                    ],
                    "prefix_string_stack_sample": [],
                }
            ],
        }
    )

    assert summary["consumed_operand_signature_sample"][0]["signature"] == "widget+widget"
    assert summary["consumed_secondary_int_kind_sample"][0]["kind"] == "widget"


def test_infer_clientscript_widget_operand_signature_prefers_consumed_window_signature():
    signature = _infer_clientscript_widget_operand_signature(
        {
            "candidate_mnemonic": "WIDGET_MUTATOR_CANDIDATE",
            "prefix_widget_literal_count": 1,
            "prefix_widget_stack_script_count": 1,
            "prefix_secondary_int_script_count": 1,
            "prefix_operand_signature_sample": [{"signature": "widget+int", "count": 4}],
            "consumed_operand_signature_sample": [{"signature": "widget+widget", "count": 1}],
        }
    )

    assert signature is not None
    assert signature["signature"] == "widget+widget"
    assert signature["secondary_operand_kind"] == "widget"
    assert signature["min_int_inputs"] == 2


def test_infer_clientscript_widget_operand_signature_tracks_state_secondary_operand():
    signature = _infer_clientscript_widget_operand_signature(
        {
            "candidate_mnemonic": "WIDGET_MUTATOR_CANDIDATE",
            "prefix_widget_literal_count": 1,
            "consumed_operand_signature_sample": [{"signature": "widget+state-int", "count": 2}],
        }
    )

    assert signature is not None
    assert signature["signature"] == "widget+state-int"
    assert signature["secondary_operand_kind"] == "state-int"
    assert signature["min_int_inputs"] == 2


def test_refine_clientscript_consumed_operand_payload_candidate_demotes_non_widget_window():
    entry = {
        "candidate_mnemonic": "WIDGET_MUTATOR_CANDIDATE",
        "family": "widget-action",
        "candidate_confidence": 0.72,
        "candidate_reasons": ["base reason"],
        "suggested_immediate_kind": "byte",
        "consumed_operand_signature_sample": [{"signature": "int-only", "count": 1}],
    }

    _refine_clientscript_consumed_operand_payload_candidate(entry)

    assert entry["candidate_mnemonic"] == "SWITCH_CASE_ACTION_CANDIDATE"
    assert entry["family"] == "payload-action"
    assert entry["suggested_override"]["mnemonic"] == "SWITCH_CASE_ACTION_CANDIDATE"
    assert "does not actually include a widget operand" in " ".join(entry["candidate_reasons"])


def test_refine_clientscript_consumed_operand_role_candidate_promotes_widget_link():
    entry = {
        "candidate_mnemonic": "WIDGET_MUTATOR_CANDIDATE",
        "family": "widget-action",
        "candidate_confidence": 0.72,
        "candidate_reasons": ["base reason"],
        "suggested_immediate_kind": "tribyte",
        "consumed_operand_signature_sample": [{"signature": "widget+widget", "count": 1}],
    }

    _refine_clientscript_consumed_operand_role_candidate(entry)

    assert entry["candidate_mnemonic"] == "WIDGET_LINK_MUTATOR_CANDIDATE"
    assert entry["family"] == "widget-link-action"
    assert entry["suggested_override"]["mnemonic"] == "WIDGET_LINK_MUTATOR_CANDIDATE"


def test_refine_clientscript_consumed_operand_role_candidate_promotes_widget_state():
    entry = {
        "candidate_mnemonic": "WIDGET_MUTATOR_CANDIDATE",
        "family": "widget-action",
        "candidate_confidence": 0.72,
        "candidate_reasons": ["base reason"],
        "suggested_immediate_kind": "int",
        "consumed_operand_signature_sample": [{"signature": "widget+state-int", "count": 1}],
    }

    _refine_clientscript_consumed_operand_role_candidate(entry)

    assert entry["candidate_mnemonic"] == "WIDGET_STATE_MUTATOR_CANDIDATE"
    assert entry["family"] == "widget-state-action"


def test_refine_clientscript_consumed_operand_role_candidate_promotes_widget_text():
    entry = {
        "candidate_mnemonic": "WIDGET_MUTATOR_CANDIDATE",
        "family": "widget-action",
        "candidate_confidence": 0.72,
        "candidate_reasons": ["base reason"],
        "suggested_immediate_kind": "string",
        "consumed_operand_signature_sample": [{"signature": "widget+string", "count": 1}],
    }

    _refine_clientscript_consumed_operand_role_candidate(entry)

    assert entry["candidate_mnemonic"] == "WIDGET_TEXT_MUTATOR_CANDIDATE"
    assert entry["family"] == "widget-text-action"
    assert entry["suggested_override"]["mnemonic"] == "WIDGET_TEXT_MUTATOR_CANDIDATE"


def test_refine_clientscript_consumed_operand_role_candidate_promotes_state_value_action():
    entry = {
        "candidate_mnemonic": "SWITCH_CASE_ACTION_CANDIDATE",
        "family": "payload-action",
        "candidate_confidence": 0.6,
        "candidate_reasons": ["base reason"],
        "suggested_immediate_kind": "byte",
        "consumed_operand_signature_sample": [{"signature": "int-only", "count": 1}],
        "consumed_secondary_int_kind_sample": [{"kind": "state-int", "count": 1}],
    }

    _refine_clientscript_consumed_operand_role_candidate(entry)

    assert entry["candidate_mnemonic"] == "STATE_VALUE_ACTION_CANDIDATE"
    assert entry["family"] == "state-action"
    assert entry["suggested_override"]["mnemonic"] == "STATE_VALUE_ACTION_CANDIDATE"


def test_refine_clientscript_consumed_operand_role_candidate_promotes_string_formatter():
    entry = {
        "candidate_mnemonic": "SWITCH_CASE_ACTION_CANDIDATE",
        "family": "payload-action",
        "candidate_confidence": 0.61,
        "candidate_reasons": ["base reason"],
        "suggested_immediate_kind": "string",
        "consumed_operand_signature_sample": [{"signature": "int+string", "count": 1}],
    }

    _refine_clientscript_consumed_operand_role_candidate(entry)

    assert entry["candidate_mnemonic"] == "STRING_FORMATTER_CANDIDATE"
    assert entry["family"] == "string-transform-action"
    assert entry["suggested_override"]["mnemonic"] == "STRING_FORMATTER_CANDIDATE"


def test_refine_clientscript_consumed_operand_role_candidate_promotes_string_concat_formatter():
    entry = {
        "candidate_mnemonic": "SWITCH_CASE_ACTION_CANDIDATE",
        "family": "payload-action",
        "candidate_confidence": 0.61,
        "candidate_reasons": ["base reason"],
        "suggested_immediate_kind": "string",
        "consumed_operand_signature_sample": [{"signature": "string+string", "count": 1}],
    }

    _refine_clientscript_consumed_operand_role_candidate(entry)

    assert entry["candidate_mnemonic"] == "STRING_FORMATTER_CANDIDATE"
    assert entry["family"] == "string-transform-action"
    assert entry["suggested_override"]["mnemonic"] == "STRING_FORMATTER_CANDIDATE"


def test_refine_clientscript_consumed_operand_role_candidate_promotes_string_action():
    entry = {
        "candidate_mnemonic": "SWITCH_CASE_ACTION_CANDIDATE",
        "family": "payload-action",
        "candidate_confidence": 0.61,
        "candidate_reasons": ["base reason"],
        "suggested_immediate_kind": "string",
        "consumed_operand_signature_sample": [{"signature": "string-only", "count": 1}],
    }

    _refine_clientscript_consumed_operand_role_candidate(entry)

    assert entry["candidate_mnemonic"] == "STRING_ACTION_CANDIDATE"
    assert entry["family"] == "string-action"
    assert entry["suggested_override"]["mnemonic"] == "STRING_ACTION_CANDIDATE"


def test_refine_clientscript_consumed_operand_role_candidate_promotes_string_message_action():
    entry = {
        "candidate_mnemonic": "SWITCH_CASE_ACTION_CANDIDATE",
        "family": "payload-action",
        "candidate_confidence": 0.61,
        "candidate_reasons": ["base reason"],
        "suggested_immediate_kind": "short",
        "consumed_operand_signature_sample": [{"signature": "string-only", "count": 1}],
        "consumed_operand_samples": [
            {
                "key": 15820,
                "signature": "string-only",
                "int_operands": [],
                "string_operands": [
                    {
                        "kind": "string-literal",
                        "value": "You will not be able to use Treasure Hunter Keys until competitive mode is over.",
                    }
                ],
            }
        ],
    }

    _refine_clientscript_consumed_operand_role_candidate(entry)

    assert entry["candidate_mnemonic"] == "STRING_MESSAGE_ACTION_CANDIDATE"
    assert entry["family"] == "string-message-action"
    assert entry["suggested_override"]["mnemonic"] == "STRING_MESSAGE_ACTION_CANDIDATE"


def test_refine_clientscript_consumed_operand_role_candidate_promotes_string_url_action():
    entry = {
        "candidate_mnemonic": "SWITCH_CASE_ACTION_CANDIDATE",
        "family": "payload-action",
        "candidate_confidence": 0.61,
        "candidate_reasons": ["base reason"],
        "suggested_immediate_kind": "short",
        "consumed_operand_signature_sample": [{"signature": "string-only", "count": 1}],
        "consumed_operand_samples": [
            {
                "key": 4242,
                "signature": "string-only",
                "int_operands": [],
                "string_operands": [
                    {
                        "kind": "string-literal",
                        "value": "https://oldschool.runescape.com/",
                    }
                ],
            }
        ],
    }

    _refine_clientscript_consumed_operand_role_candidate(entry)

    assert entry["candidate_mnemonic"] == "STRING_URL_ACTION_CANDIDATE"
    assert entry["family"] == "string-url-action"
    assert entry["suggested_override"]["mnemonic"] == "STRING_URL_ACTION_CANDIDATE"


def test_refine_clientscript_consumed_operand_role_candidate_upgrades_existing_string_action_to_message_subtype():
    entry = {
        "candidate_mnemonic": "STRING_ACTION_CANDIDATE",
        "family": "string-action",
        "candidate_confidence": 0.67,
        "candidate_reasons": ["base reason"],
        "suggested_immediate_kind": "int",
        "consumed_operand_signature_sample": [{"signature": "string-only", "count": 1}],
        "consumed_operand_samples": [
            {
                "key": 3376,
                "signature": "string-only",
                "int_operands": [],
                "string_operands": [
                    {
                        "kind": "string-literal",
                        "value": "You have unlocked custom presets.",
                    }
                ],
            }
        ],
    }

    _refine_clientscript_consumed_operand_role_candidate(entry)

    assert entry["candidate_mnemonic"] == "STRING_MESSAGE_ACTION_CANDIDATE"
    assert entry["family"] == "string-message-action"
    assert entry["suggested_override"]["mnemonic"] == "STRING_MESSAGE_ACTION_CANDIDATE"


def test_refine_clientscript_consumed_operand_role_candidate_keeps_low_signal_string_action_generic():
    entry = {
        "candidate_mnemonic": "SWITCH_CASE_ACTION_CANDIDATE",
        "family": "payload-action",
        "candidate_confidence": 0.61,
        "candidate_reasons": ["base reason"],
        "suggested_immediate_kind": "short",
        "consumed_operand_signature_sample": [{"signature": "string-only", "count": 1}],
        "consumed_operand_samples": [
            {
                "key": 4506,
                "signature": "string-only",
                "int_operands": [],
                "string_operands": [
                    {
                        "kind": "string-literal",
                        "value": "Z",
                    }
                ],
            }
        ],
    }

    _refine_clientscript_consumed_operand_role_candidate(entry)

    assert entry["candidate_mnemonic"] == "STRING_ACTION_CANDIDATE"
    assert entry["family"] == "string-action"


def test_refine_clientscript_string_payload_frontier_candidate_promotes_single_script_string_action():
    entry = {
        "raw_opcode": 0x0205,
        "raw_opcode_hex": "0x0205",
        "script_count": 1,
        "switch_script_count": 1,
        "prefix_operand_signature_sample": [{"signature": "string-only", "count": 1}],
        "suggested_immediate_kind": "short",
    }

    _refine_clientscript_string_payload_frontier_candidate(entry)

    assert entry["candidate_mnemonic"] == "STRING_ACTION_CANDIDATE"
    assert entry["family"] == "string-action"
    assert entry["suggested_override"]["mnemonic"] == "STRING_ACTION_CANDIDATE"
    assert entry["suggested_override"]["immediate_kind"] == "short"


def test_refine_clientscript_string_payload_frontier_candidate_breaks_formatter_probe_ties_toward_narrow_string_payload():
    entry = {
        "raw_opcode": 0x0383,
        "raw_opcode_hex": "0x0383",
        "script_count": 1,
        "switch_script_count": 1,
        "prefix_operand_signature_sample": [{"signature": "int+string", "count": 1}],
        "immediate_kind_candidates": [
            {
                "immediate_kind": "short",
                "improved_script_count": 1,
                "total_progress_instruction_count": 64,
                "next_frontier_trace_count": 1,
                "valid_trace_count": 1,
                "complete_trace_count": 0,
                "invalid_immediate_count": 0,
                "relative_target_count": 1,
                "relative_target_instruction_boundary_count": 0,
            },
            {
                "immediate_kind": "byte",
                "improved_script_count": 1,
                "total_progress_instruction_count": 64,
                "next_frontier_trace_count": 1,
                "valid_trace_count": 1,
                "complete_trace_count": 0,
                "invalid_immediate_count": 0,
                "relative_target_count": 0,
                "relative_target_instruction_boundary_count": 0,
            },
        ],
    }

    _refine_clientscript_string_payload_frontier_candidate(entry)

    assert entry["candidate_mnemonic"] == "STRING_FORMATTER_CANDIDATE"
    assert entry["family"] == "string-transform-action"
    assert entry["suggested_immediate_kind"] == "byte"
    assert entry["suggested_override"]["immediate_kind"] == "byte"


def test_refine_clientscript_string_payload_frontier_candidate_rejects_switch_immediate_for_formatter():
    entry = {
        "raw_opcode": 0x1200,
        "raw_opcode_hex": "0x1200",
        "script_count": 1,
        "switch_script_count": 1,
        "prefix_operand_signature_sample": [{"signature": "int+string", "count": 1}],
        "suggested_immediate_kind": "switch",
        "immediate_kind_candidates": [
            {
                "immediate_kind": "switch",
                "improved_script_count": 1,
                "total_progress_instruction_count": 9,
                "next_frontier_trace_count": 1,
                "valid_trace_count": 1,
                "complete_trace_count": 0,
                "invalid_immediate_count": 0,
                "relative_target_count": 0,
                "relative_target_instruction_boundary_count": 0,
            },
            {
                "immediate_kind": "byte",
                "improved_script_count": 1,
                "total_progress_instruction_count": 4,
                "next_frontier_trace_count": 1,
                "valid_trace_count": 1,
                "complete_trace_count": 0,
                "invalid_immediate_count": 0,
                "relative_target_count": 0,
                "relative_target_instruction_boundary_count": 0,
            },
        ],
    }

    _refine_clientscript_string_payload_frontier_candidate(entry)

    assert entry["candidate_mnemonic"] == "STRING_FORMATTER_CANDIDATE"
    assert entry["suggested_immediate_kind"] == "byte"
    assert entry["suggested_override"]["immediate_kind"] == "byte"


def test_infer_clientscript_stack_effect_for_widget_mutator_can_require_string():
    effect = _infer_clientscript_stack_effect(
        {
            "candidate_mnemonic": "WIDGET_MUTATOR_CANDIDATE",
            "prefix_widget_stack_script_count": 1,
            "prefix_string_operand_script_count": 1,
            "prefix_operand_signature_sample": [{"signature": "widget+string", "count": 1}],
        }
    )

    assert effect is not None
    assert effect["int_pops"] == 1
    assert effect["string_pops"] == 1


def test_infer_clientscript_stack_effect_for_string_formatter_consumes_int_and_string():
    effect = _infer_clientscript_stack_effect(
        {
            "candidate_mnemonic": "STRING_FORMATTER_CANDIDATE",
            "family": "string-transform-action",
            "prefix_string_operand_script_count": 1,
            "consumed_operand_signature_sample": [{"signature": "int+string", "count": 1}],
        }
    )

    assert effect is not None
    assert effect["int_pops"] == 1
    assert effect["string_pops"] == 1
    assert effect["string_pushes"] == 1


def test_infer_clientscript_stack_effect_for_string_concat_formatter_consumes_two_strings():
    effect = _infer_clientscript_stack_effect(
        {
            "candidate_mnemonic": "STRING_FORMATTER_CANDIDATE",
            "family": "string-transform-action",
            "prefix_string_operand_script_count": 1,
            "consumed_operand_signature_sample": [{"signature": "string+string", "count": 1}],
        }
    )

    assert effect is not None
    assert effect["string_pops"] == 2
    assert effect["string_pushes"] == 1


def test_profile_archive_file_tracks_string_formatter_result_stack():
    payload = _build_clientscript_payload(
        instruction_count=3,
        body_bytes=(
            _encode_clientscript_instruction(0x3003, "string", "Level: ")
            + _encode_clientscript_instruction(0x5005, "byte", 7)
            + _encode_clientscript_instruction(0x2002, "byte", 0)
        ),
    )

    profile = profile_archive_file(
        payload,
        index_name="CLIENTSCRIPTS",
        archive_key=0,
        file_id=15,
        clientscript_opcode_types={0x3003: "string", 0x5005: "byte", 0x2002: "byte"},
        clientscript_opcode_catalog={
            0x3003: {
                "mnemonic": "PUSH_CONST_STRING",
                "family": "stack-constant",
                "stack_effect_candidate": {
                    "string_pushes": 1,
                    "confidence": 0.95,
                    "notes": "Opcode pushes one string constant onto the string stack.",
                },
            },
            0x5005: {
                "mnemonic": "STRING_FORMATTER_CANDIDATE",
                "family": "string-transform-action",
                "stack_effect_candidate": {
                    "string_pops": 1,
                    "string_pushes": 1,
                    "confidence": 0.71,
                    "notes": "String-context payload likely consumes one string value before producing a transformed string.",
                },
            },
            0x2002: {"mnemonic": "RETURN", "family": "control-flow", "confidence": 0.9},
        },
    )

    assert profile is not None
    assert profile["kind"] == "clientscript-disassembly"
    assert profile["instruction_sample"][1]["semantic_label"] == "STRING_FORMATTER_CANDIDATE"
    assert profile["instruction_sample"][1]["stack_effect_candidate"]["string_pushes"] == 1
    assert profile["instruction_sample"][1]["consumed_string_expressions"][0]["kind"] == "string-literal"
    assert profile["instruction_sample"][1]["produced_string_expressions"][0]["kind"] == "string-result"
    assert profile["instruction_sample"][1]["string_stack_depth_after"] == 1
    assert profile["stack_tracking"]["final_depths"]["string_stack"] == 1


def test_profile_archive_file_renders_clientscript_pseudocode_for_formatter_and_widget_text():
    payload = _build_clientscript_payload(
        instruction_count=5,
        body_bytes=(
            _encode_clientscript_instruction(0x1001, "int", 99)
            + _encode_clientscript_instruction(0x3003, "string", "Welcome")
            + _encode_clientscript_instruction(0x5005, "byte", 7)
            + _encode_clientscript_instruction(0x1001, "int", 133160)
            + _encode_clientscript_instruction(0x6006, "byte", 0)
        ),
    )

    profile = profile_archive_file(
        payload,
        index_name="CLIENTSCRIPTS",
        archive_key=0,
        file_id=22,
        clientscript_opcode_types={0x1001: "int", 0x3003: "string", 0x5005: "byte", 0x6006: "byte"},
        clientscript_opcode_catalog={
            0x1001: {
                "mnemonic": "PUSH_INT_LITERAL",
                "family": "stack",
                "stack_effect_candidate": {
                    "int_pushes": 1,
                    "confidence": 0.95,
                    "notes": "Opcode pushes one integer constant onto the stack.",
                },
            },
            0x3003: {
                "mnemonic": "PUSH_CONST_STRING_CANDIDATE",
                "family": "stack-constant",
                "stack_effect_candidate": {
                    "string_pushes": 1,
                    "confidence": 0.95,
                    "notes": "Opcode pushes one string constant onto the string stack.",
                },
            },
            0x5005: {
                "mnemonic": "STRING_FORMATTER_CANDIDATE",
                "family": "string-transform-action",
                "stack_effect_candidate": {
                    "int_pops": 1,
                    "string_pops": 1,
                    "string_pushes": 1,
                    "confidence": 0.81,
                    "notes": "Formatter consumes one int and one string, then pushes a formatted string.",
                },
                "operand_signature_candidate": {
                    "target_kind": "string",
                    "signature": "int+string",
                    "min_int_inputs": 1,
                    "min_string_inputs": 1,
                    "confidence": 0.81,
                },
            },
            0x6006: {
                "mnemonic": "CONTROL_FLOW_FRONTIER_CANDIDATE",
                "candidate_mnemonic": "WIDGET_TEXT_MUTATOR_CANDIDATE",
                "family": "widget-text-action",
                "stack_effect_candidate": {
                    "int_pops": 1,
                    "string_pops": 1,
                    "confidence": 0.8,
                    "notes": "Widget text mutator consumes one widget and one string.",
                },
                "operand_signature_candidate": {
                    "target_kind": "widget",
                    "signature": "widget+string",
                    "min_int_inputs": 1,
                    "min_string_inputs": 1,
                    "confidence": 0.8,
                    "secondary_operand_kind": "string",
                },
            },
        },
    )

    assert profile is not None
    assert profile["instruction_sample"][4]["semantic_label"] == "WIDGET_TEXT_MUTATOR_CANDIDATE"
    pseudocode = profile["_pseudocode_text"]
    assert 'append_int("Welcome", 99);' in pseudocode
    assert 'set_widget_text(widget[2:2088], string_' in pseudocode


def test_infer_clientscript_stack_effect_for_state_value_action_consumes_two_ints():
    effect = _infer_clientscript_stack_effect(
        {
            "candidate_mnemonic": "STATE_VALUE_ACTION_CANDIDATE",
            "family": "state-action",
        }
    )

    assert effect is not None
    assert effect["int_pops"] == 2


def test_promote_clientscript_control_flow_candidates_includes_widget_mutator():
    promoted = _promote_clientscript_control_flow_candidates(
        {
            0xFE00: {
                "candidate_mnemonic": "WIDGET_MUTATOR_CANDIDATE",
                "switch_script_count": 1,
                "script_count": 1,
                "candidate_confidence": 0.67,
                "suggested_immediate_kind": "short",
                "family": "widget-action",
                "operand_signature_candidate": {
                    "target_kind": "widget",
                    "signature": "widget+int",
                    "min_int_inputs": 2,
                    "confidence": 0.66,
                    "notes": "Widget-targeted payload likely consumes a packed widget id plus one additional integer-like argument.",
                },
                "stack_effect_candidate": {
                    "int_pops": 2,
                    "confidence": 0.66,
                    "notes": "Widget-targeted payload likely consumes a packed widget id plus one additional integer-like argument.",
                },
            }
        }
    )

    assert promoted[0xFE00]["mnemonic"] == "WIDGET_MUTATOR_CANDIDATE"
    assert promoted[0xFE00]["immediate_kind"] == "short"
    assert promoted[0xFE00]["operand_signature_candidate"]["signature"] == "widget+int"
    assert promoted[0xFE00]["stack_effect_candidate"]["int_pops"] == 2


def test_promote_clientscript_control_flow_candidates_includes_widget_subtypes_and_state_payloads():
    promoted = _promote_clientscript_control_flow_candidates(
        {
            0x9500: {
                "candidate_mnemonic": "WIDGET_LINK_MUTATOR_CANDIDATE",
                "switch_script_count": 1,
                "script_count": 1,
                "candidate_confidence": 0.76,
                "suggested_immediate_kind": "tribyte",
                "family": "widget-link-action",
            },
            0x5E00: {
                "candidate_mnemonic": "STATE_VALUE_ACTION_CANDIDATE",
                "switch_script_count": 1,
                "script_count": 1,
                "candidate_confidence": 0.66,
                "suggested_immediate_kind": "byte",
                "family": "state-action",
            },
        }
    )

    assert promoted[0x9500]["mnemonic"] == "WIDGET_LINK_MUTATOR_CANDIDATE"
    assert promoted[0x5E00]["mnemonic"] == "STATE_VALUE_ACTION_CANDIDATE"


def test_promote_clientscript_control_flow_candidates_includes_string_payloads():
    promoted = _promote_clientscript_control_flow_candidates(
        {
            0x0502: {
                "candidate_mnemonic": "STRING_FORMATTER_CANDIDATE",
                "switch_script_count": 1,
                "script_count": 3,
                "candidate_confidence": 0.71,
                "suggested_immediate_kind": "string",
                "family": "string-transform-action",
            }
        }
    )

    assert promoted[0x0502]["mnemonic"] == "STRING_FORMATTER_CANDIDATE"
    assert promoted[0x0502]["immediate_kind"] == "string"


def test_promote_clientscript_control_flow_candidates_includes_string_message_payloads():
    promoted = _promote_clientscript_control_flow_candidates(
        {
            0x0041: {
                "candidate_mnemonic": "STRING_MESSAGE_ACTION_CANDIDATE",
                "switch_script_count": 1,
                "script_count": 1,
                "candidate_confidence": 0.72,
                "suggested_immediate_kind": "int",
                "family": "string-message-action",
            }
        }
    )

    assert promoted[0x0041]["mnemonic"] == "STRING_MESSAGE_ACTION_CANDIDATE"
    assert promoted[0x0041]["family"] == "string-message-action"


def test_build_clientscript_string_transform_frontier_candidates_detects_formatter_frontier():
    candidates, summary = _build_clientscript_string_transform_frontier_candidates(
        {
            0x4004: {
                "raw_opcode": 0x4004,
                "raw_opcode_hex": "0x4004",
                "script_count": 2,
                "key_sample": [7, 8],
                "prefix_operand_signature_sample": [{"signature": "int+string", "count": 2}],
                "script_samples": [
                    {
                        "key": 7,
                        "prefix_operand_signature": "int+string",
                        "prefix_string_stack_sample": [
                            {
                                "kind": "string-result",
                                "raw_opcode_hex": "0x5500",
                                "semantic_label": "STRING_FORMATTER_CANDIDATE",
                            }
                        ],
                    }
                ],
            }
        }
    )

    assert candidates[0x4004]["candidate_mnemonic"] == "STRING_FORMATTER_FRONTIER_CANDIDATE"
    assert candidates[0x4004]["string_result_script_count"] == 1
    assert summary["frontier_opcode_count"] == 1


def test_build_clientscript_string_transform_arity_candidates_profiles_formatter_window():
    candidates, summary = _build_clientscript_string_transform_arity_candidates(
        {
            0x4004: {
                "raw_opcode": 0x4004,
                "raw_opcode_hex": "0x4004",
                "script_count": 2,
                "string_result_script_count": 2,
                "candidate_mnemonic": "STRING_FORMATTER_FRONTIER_CANDIDATE",
                "family": "string-transform-frontier",
                "key_sample": [7, 8],
                "script_samples": [
                    {
                        "key": 7,
                        "prefix_int_stack_sample": [
                            {
                                "kind": "int-literal",
                                "value": 99,
                            }
                        ],
                        "prefix_string_stack_sample": [
                            {
                                "kind": "string-literal",
                                "value": "Level: ",
                            }
                        ],
                    },
                    {
                        "key": 8,
                        "prefix_int_stack_sample": [
                            {
                                "kind": "state-reference",
                                "reference_id": 7,
                            }
                        ],
                        "prefix_string_stack_sample": [
                            {
                                "kind": "string-result",
                                "raw_opcode_hex": "0x5500",
                            }
                        ],
                    },
                ],
            }
        }
    )

    candidate_profile = candidates[0x4004]["candidate_arity_profile"]

    assert candidate_profile["candidate_mnemonic"] == "STRING_FORMATTER_CANDIDATE"
    assert candidate_profile["signature"] == "int+string"
    assert candidate_profile["stack_effect_candidate"]["int_pops"] == 1
    assert candidate_profile["stack_effect_candidate"]["string_pops"] == 1
    assert candidate_profile["stack_effect_candidate"]["string_pushes"] == 1
    assert summary["selected_profile_count"] == 1


def test_promote_clientscript_string_frontier_candidates_includes_direct_string_push():
    promoted = _promote_clientscript_string_frontier_candidates(
        {
            0x3003: {
                "candidate_mnemonic": "PUSH_CONST_STRING_CANDIDATE",
                "candidate_confidence": 0.81,
                "suggested_immediate_kind": "string",
                "family": "stack-constant",
                "script_count": 2,
                "complete_trace_count": 0,
                "stack_effect_candidate": {
                    "string_pushes": 1,
                    "confidence": 0.95,
                    "notes": "Opcode pushes one string constant onto the string stack.",
                },
            }
        }
    )

    assert promoted[0x3003]["mnemonic"] == "PUSH_CONST_STRING_CANDIDATE"
    assert promoted[0x3003]["immediate_kind"] == "string"
    assert promoted[0x3003]["stack_effect_candidate"]["string_pushes"] == 1


def test_build_clientscript_control_flow_candidates_uses_terminal_semantics_for_state_reader():
    target = Path(":memory:")
    wrappers = [
        _build_clientscript_payload(
            instruction_count=2,
            body_bytes=(
                _encode_clientscript_instruction(0x0895, "int", 100 + key)
                + _encode_clientscript_instruction(0x0495, "byte", 0)
            ),
        )
        for key in range(40)
    ]

    with sqlite3.connect(target) as connection:
        connection.execute("CREATE TABLE cache (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        for key, payload in enumerate(wrappers):
            connection.execute(
                "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
                (key, _build_js5_record(payload, compression='none', revision=11), key, key + 100),
            )
        connection.commit()

        candidates, _summary = _build_clientscript_control_flow_candidates(
            connection,
            locked_opcode_types={0x0495: "byte"},
            semantic_overrides={},
            raw_opcode_catalog={
                0x0495: {
                    "mnemonic": "TERMINATOR_CANDIDATE",
                    "family": "control-flow",
                    "immediate_kind": "byte",
                }
            },
            include_keys=[],
            max_decoded_bytes=64 * 1024 * 1024,
            sample_limit=40,
        )

    entry = candidates[0x0895]
    int_candidate = next(
        candidate for candidate in entry["immediate_kind_candidates"] if candidate["immediate_kind"] == "int"
    )

    assert int_candidate["known_terminal_semantic_count"] == 40
    assert int_candidate["terminal_semantic_label_sample"][0]["label"] == "TERMINATOR_CANDIDATE"
    assert entry["candidate_mnemonic"] == "INT_STATE_GETTER_CANDIDATE"
    assert entry["suggested_immediate_kind"] == "int"


def test_build_clientscript_semantic_suggestions_includes_control_flow_state_reader():
    suggestions = _build_clientscript_semantic_suggestions(
        control_flow_candidates={
            0x0895: {
                "candidate_mnemonic": "INT_STATE_GETTER_CANDIDATE",
                "suggested_immediate_kind": "int",
                "family": "state-reader",
                "candidate_confidence": 0.72,
                "switch_script_count": 0,
                "candidate_reasons": ["32-bit probe repeatedly decodes into tiny complete scripts."],
            }
        }
    )

    assert suggestions["0x0895"]["mnemonic"] == "INT_STATE_GETTER_CANDIDATE"
    assert suggestions["0x0895"]["immediate_kind"] == "int"
    assert suggestions["0x0895"]["family"] == "state-reader"
    assert suggestions["0x0895"]["confidence"] == 0.72


def test_merge_clientscript_catalog_entry_prefers_specific_state_reader_over_generic_frontier():
    catalog = {
        0x1100: {
            "mnemonic": "CONTROL_FLOW_FRONTIER_CANDIDATE",
            "immediate_kind": "short",
            "family": "control-flow",
            "confidence": 0.9,
        }
    }

    _merge_clientscript_catalog_entry(
        catalog,
        0x1100,
        {
            "mnemonic": "INT_STATE_GETTER_CANDIDATE",
            "immediate_kind": "int",
            "family": "state-reader",
            "confidence": 0.7,
            "promotion_source": "contextual-frontier",
        },
    )

    assert catalog[0x1100]["mnemonic"] == "INT_STATE_GETTER_CANDIDATE"
    assert catalog[0x1100]["immediate_kind"] == "int"
    assert catalog[0x1100]["family"] == "state-reader"
    assert catalog[0x1100]["promotion_source"] == "contextual-frontier"


def test_seed_clientscript_catalog_with_semantic_overrides_adds_missing_entry():
    catalog = {
        0x035E: {
            "raw_opcode": 0x035E,
            "raw_opcode_hex": "0x035E",
            "mnemonic": "SWITCH_DISPATCH_FRONTIER_CANDIDATE",
            "immediate_kind": "tribyte",
        }
    }

    _seed_clientscript_catalog_with_semantic_overrides(
        catalog,
        {
            0x1100: {
                "mnemonic": "INT_STATE_GETTER_CANDIDATE",
                "immediate_kind": "int",
                "family": "state-reader",
                "confidence": 0.7,
            }
        },
    )

    assert 0x1100 in catalog
    assert catalog[0x1100]["raw_opcode_hex"] == "0x1100"
    assert catalog[0x1100]["mnemonic"] == "INT_STATE_GETTER_CANDIDATE"
    assert catalog[0x1100]["immediate_kind"] == "int"
    assert catalog[0x1100]["override"] is True


def test_build_clientscript_effective_semantic_suggestions_preserves_override_only_entries():
    suggestions = {
        "0x035E": {
            "mnemonic": "SWITCH_DISPATCH_FRONTIER_CANDIDATE",
            "immediate_kind": "tribyte",
            "family": "control-flow",
        }
    }

    effective = _build_clientscript_effective_semantic_suggestions(
        suggestions,
        semantic_overrides={
            0x1100: {
                "mnemonic": "INT_STATE_GETTER_CANDIDATE",
                "immediate_kind": "int",
                "family": "state-reader",
                "confidence": 0.7,
            }
        },
    )

    assert effective["0x035E"]["mnemonic"] == "SWITCH_DISPATCH_FRONTIER_CANDIDATE"
    assert effective["0x1100"]["mnemonic"] == "INT_STATE_GETTER_CANDIDATE"
    assert effective["0x1100"]["immediate_kind"] == "int"
    assert effective["0x1100"]["family"] == "state-reader"


def test_combine_clientscript_control_flow_candidates_adds_post_contextual_entries():
    combined = _combine_clientscript_control_flow_candidates(
        {
            0x0895: {
                "raw_opcode": 0x0895,
                "raw_opcode_hex": "0x0895",
                "script_count": 402,
                "switch_script_count": 0,
                "candidate_mnemonic": "INT_STATE_GETTER_CANDIDATE",
                "suggested_immediate_kind": "int",
                "family": "state-reader",
                "candidate_confidence": 0.84,
            }
        },
        {
            0x0895: {
                "raw_opcode": 0x0895,
                "raw_opcode_hex": "0x0895",
                "script_count": 401,
                "switch_script_count": 0,
            },
            0x9500: {
                "raw_opcode": 0x9500,
                "raw_opcode_hex": "0x9500",
                "script_count": 128,
                "switch_script_count": 0,
                "candidate_mnemonic": "INT_STATE_GETTER_CANDIDATE",
                "suggested_immediate_kind": "int",
                "family": "state-reader",
                "candidate_confidence": 0.61,
            },
        },
        {
            0x5E00: {
                "raw_opcode": 0x5E00,
                "raw_opcode_hex": "0x5E00",
                "script_count": 8,
                "switch_script_count": 1,
                "candidate_mnemonic": "SWITCH_CASE_ACTION_CANDIDATE",
                "suggested_immediate_kind": "short",
                "family": "payload-action",
                "candidate_confidence": 0.58,
            },
        },
        {
            0x4A00: {
                "raw_opcode": 0x4A00,
                "raw_opcode_hex": "0x4A00",
                "script_count": 6,
                "switch_script_count": 1,
                "candidate_mnemonic": "WIDGET_TEXT_MUTATOR_CANDIDATE",
                "suggested_immediate_kind": "string",
                "family": "widget-text-action",
                "candidate_confidence": 0.77,
            },
        },
    )

    assert combined[0x0895]["analysis_stage"] == "initial"
    assert combined[0x0895]["post_contextual_observed"] is True
    assert combined[0x9500]["analysis_stage"] == "post-contextual"
    assert combined[0x5E00]["analysis_stage"] == "recursive"
    assert combined[0x4A00]["analysis_stage"] == "post-string"


def test_resolve_clientscript_contextual_frontier_passes_chains_promotions(monkeypatch):
    pass_responses = [
        (
            {
                0x9009: {
                    "raw_opcode": 0x9009,
                    "raw_opcode_hex": "0x9009",
                    "candidate_mnemonic": "INT_STATE_GETTER_CANDIDATE",
                    "suggested_immediate_kind": "int",
                    "family": "state-reader",
                    "candidate_confidence": 0.67,
                    "prefix_switch_dispatch_count": 1,
                    "script_count": 1,
                }
            },
            {
                "frontier_opcode_count": 1,
                "frontier_script_count": 1,
                "catalog_sample": [],
            },
        ),
        (
            {
                0x9010: {
                    "raw_opcode": 0x9010,
                    "raw_opcode_hex": "0x9010",
                    "candidate_mnemonic": "INT_STATE_GETTER_CANDIDATE",
                    "suggested_immediate_kind": "int",
                    "family": "state-reader",
                    "candidate_confidence": 0.63,
                    "prefix_switch_dispatch_count": 1,
                    "script_count": 1,
                }
            },
            {
                "frontier_opcode_count": 1,
                "frontier_script_count": 1,
                "catalog_sample": [],
            },
        ),
        (
            {},
            {
                "frontier_opcode_count": 0,
                "frontier_script_count": 0,
                "catalog_sample": [],
            },
        ),
    ]
    seen_locked_types: list[dict[int, str]] = []

    def fake_build(*args, **kwargs):
        seen_locked_types.append(dict(kwargs["locked_opcode_types"]))
        return pass_responses.pop(0)

    monkeypatch.setattr(
        js5_module,
        "_build_clientscript_contextual_frontier_candidates",
        fake_build,
    )

    with sqlite3.connect(":memory:") as connection:
        (
            contextual_candidates,
            contextual_summary,
            promoted_contextual_frontiers,
            effective_opcode_types,
            effective_opcode_catalog,
        ) = _resolve_clientscript_contextual_frontier_passes(
            connection,
            locked_opcode_types={0x1001: "int"},
            raw_opcode_catalog={
                0x1001: {"mnemonic": "PUSH_INT_CANDIDATE", "family": "stack", "immediate_kind": "int"}
            },
            include_keys=[],
            max_decoded_bytes=64 * 1024 * 1024,
            sample_limit=16,
            max_passes=3,
        )

    assert contextual_summary["pass_count"] == 3
    assert contextual_summary["promoted_opcode_count"] == 2
    assert contextual_candidates[0x9009]["candidate_mnemonic"] == "INT_STATE_GETTER_CANDIDATE"
    assert contextual_candidates[0x9010]["candidate_mnemonic"] == "INT_STATE_GETTER_CANDIDATE"
    assert promoted_contextual_frontiers[0x9009]["mnemonic"] == "INT_STATE_GETTER_CANDIDATE"
    assert promoted_contextual_frontiers[0x9010]["mnemonic"] == "INT_STATE_GETTER_CANDIDATE"
    assert effective_opcode_types[0x9009] == "int"
    assert effective_opcode_types[0x9010] == "int"
    assert effective_opcode_catalog[0x9010]["mnemonic"] == "INT_STATE_GETTER_CANDIDATE"
    assert 0x9009 not in seen_locked_types[0]
    assert seen_locked_types[1][0x9009] == "int"


def test_js5_export_combines_post_context_control_flow_candidates(tmp_path, monkeypatch):
    root = tmp_path / "OpenNXT"
    target = root / "data" / "cache" / "js5-12.jcache"
    export_dir = tmp_path / "exports"
    target.parent.mkdir(parents=True, exist_ok=True)
    _write_js5_mapping(root, build=947, index_names={12: "CLIENTSCRIPTS"})

    reference_table = _build_reference_table({0: [0]})
    script_payload = _build_clientscript_payload(
        instruction_count=1,
        body_bytes=_encode_clientscript_instruction(0x1001, "int", 42),
    )

    with sqlite3.connect(target) as connection:
        connection.execute("CREATE TABLE cache (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute("CREATE TABLE cache_index (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute(
            "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (0, _build_js5_record(script_payload, compression='none', revision=11), 100, 200),
        )
        connection.execute(
            "INSERT INTO cache_index (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (1, _build_js5_record(reference_table, compression='gzip'), -1, 999),
        )
        connection.commit()

    control_calls: list[dict[int, str]] = []

    def fake_build_control_flow_candidates(*args, **kwargs):
        control_calls.append(dict(kwargs["locked_opcode_types"]))
        if len(control_calls) == 1:
            return (
                {
                    0x0895: {
                        "raw_opcode": 0x0895,
                        "raw_opcode_hex": "0x0895",
                        "script_count": 402,
                        "switch_script_count": 0,
                        "candidate_mnemonic": "INT_STATE_GETTER_CANDIDATE",
                        "suggested_immediate_kind": "int",
                        "family": "state-reader",
                        "candidate_confidence": 0.84,
                    }
                },
                {
                    "frontier_opcode_count": 1,
                    "frontier_script_count": 1,
                    "switch_frontier_script_count": 0,
                    "catalog_sample": [],
                },
            )

        if len(control_calls) == 2:
            return (
                {
                    0x9500: {
                        "raw_opcode": 0x9500,
                        "raw_opcode_hex": "0x9500",
                        "script_count": 128,
                        "switch_script_count": 0,
                        "candidate_mnemonic": "INT_STATE_GETTER_CANDIDATE",
                        "suggested_immediate_kind": "int",
                        "family": "state-reader",
                        "candidate_confidence": 0.61,
                    }
                },
                {
                    "frontier_opcode_count": 1,
                    "frontier_script_count": 1,
                    "switch_frontier_script_count": 0,
                    "catalog_sample": [],
                },
            )

        return (
            {
                0x5E00: {
                    "raw_opcode": 0x5E00,
                    "raw_opcode_hex": "0x5E00",
                    "script_count": 16,
                    "switch_script_count": 1,
                    "candidate_mnemonic": "SWITCH_CASE_ACTION_CANDIDATE",
                    "suggested_immediate_kind": "short",
                    "family": "payload-action",
                    "candidate_confidence": 0.58,
                }
            },
            {
                "frontier_opcode_count": 1,
                "frontier_script_count": 1,
                "switch_frontier_script_count": 0,
                "catalog_sample": [],
            },
        )

    monkeypatch.setattr(js5_module, "load_clientscript_semantic_overrides", lambda *args, **kwargs: ({}, None, None))
    monkeypatch.setattr(
        js5_module,
        "_calibrate_clientscript_opcode_types",
        lambda *args, **kwargs: ({0x1001: "int"}, {"locked_opcode_type_count": 1}),
    )
    monkeypatch.setattr(
        js5_module,
        "_build_clientscript_opcode_catalog",
        lambda *args, **kwargs: (
            {
                0x1001: {
                    "raw_opcode": 0x1001,
                    "raw_opcode_hex": "0x1001",
                    "mnemonic": "PUSH_INT_LITERAL",
                    "family": "stack",
                    "immediate_kind": "int",
                }
            },
            {"catalog_opcode_count": 1},
        ),
    )
    monkeypatch.setattr(js5_module, "_build_clientscript_control_flow_candidates", fake_build_control_flow_candidates)
    monkeypatch.setattr(
        js5_module,
        "_build_clientscript_producer_candidates",
        lambda *args, **kwargs: ({}, {"producer_opcode_count": 0, "catalog_sample": []}),
    )
    monkeypatch.setattr(
        js5_module,
        "_resolve_clientscript_contextual_frontier_passes",
        lambda *args, **kwargs: (
            {},
            {
                "frontier_opcode_count": 0,
                "promoted_opcode_count": 0,
                "pass_count": 1,
                "pass_summaries": [],
                "catalog_sample": [],
                "frontier_script_count": 0,
            },
            {},
            {0x1001: "int", 0x0895: "int"},
            {
                0x1001: {
                    "raw_opcode": 0x1001,
                    "raw_opcode_hex": "0x1001",
                    "mnemonic": "PUSH_INT_LITERAL",
                    "family": "stack",
                    "immediate_kind": "int",
                },
                0x0895: {
                    "raw_opcode": 0x0895,
                    "raw_opcode_hex": "0x0895",
                    "mnemonic": "INT_STATE_GETTER_CANDIDATE",
                    "family": "state-reader",
                    "immediate_kind": "int",
                },
            },
        ),
    )

    manifest = export_js5_cache(target, export_dir, tables=["cache"])
    control_payload = json.loads(
        Path(manifest["clientscript_control_flow_candidates_path"]).read_text(encoding="utf-8")
    )
    semantic_payload = json.loads(
        Path(manifest["clientscript_semantic_suggestions_path"]).read_text(encoding="utf-8")
    )
    control_entries = {entry["raw_opcode_hex"]: entry for entry in control_payload["opcodes"]}

    assert len(control_calls) == 4
    assert control_calls[0] == {0x1001: "int"}
    assert control_calls[1][0x0895] == "int"
    assert control_calls[2][0x9500] == "int"
    assert control_calls[3][0x5E00] == "short"
    assert control_payload["initial_frontier_opcode_count"] == 1
    assert control_payload["post_contextual_frontier_opcode_count"] == 1
    assert control_payload["recursive_frontier_opcode_count"] == 1
    assert control_payload["post_string_frontier_opcode_count"] == 1
    assert control_entries["0x0895"]["analysis_stage"] == "initial"
    assert control_entries["0x9500"]["analysis_stage"] == "post-contextual"
    assert control_entries["0x5E00"]["analysis_stage"] == "recursive"
    assert control_entries["0x5E00"]["post_string_observed"] is True
    assert semantic_payload["opcodes"]["0x9500"]["mnemonic"] == "INT_STATE_GETTER_CANDIDATE"
    assert semantic_payload["opcodes"]["0x5E00"]["mnemonic"] == "SWITCH_CASE_ACTION_CANDIDATE"
    assert (
        manifest["clientscript_calibration"]["control_flow_candidates"]["post_contextual_frontier_opcode_count"] == 1
    )
    assert manifest["clientscript_calibration"]["control_flow_candidates"]["recursive_frontier_opcode_count"] == 1
    assert manifest["clientscript_calibration"]["control_flow_candidates"]["post_string_frontier_opcode_count"] == 1
    assert manifest["clientscript_calibration"]["control_flow_candidates"]["combined_frontier_opcode_count"] == 3


def test_combine_clientscript_control_flow_candidates_merges_later_stage_promotion():
    combined = _combine_clientscript_control_flow_candidates(
        {
            0x0205: {
                "raw_opcode": 0x0205,
                "raw_opcode_hex": "0x0205",
                "script_count": 1,
                "switch_script_count": 1,
                "suggested_immediate_kind": "short",
            }
        },
        {},
        post_string_candidates={
            0x0205: {
                "raw_opcode": 0x0205,
                "raw_opcode_hex": "0x0205",
                "script_count": 1,
                "switch_script_count": 1,
                "candidate_mnemonic": "STRING_ACTION_CANDIDATE",
                "family": "string-action",
                "candidate_confidence": 0.66,
                "suggested_immediate_kind": "short",
                "suggested_override": {
                    "mnemonic": "STRING_ACTION_CANDIDATE",
                    "family": "string-action",
                    "immediate_kind": "short",
                },
            }
        },
    )

    assert combined[0x0205]["candidate_mnemonic"] == "STRING_ACTION_CANDIDATE"
    assert combined[0x0205]["analysis_stage"] == "post-string"
    assert combined[0x0205]["post_string_observed"] is True


def test_profile_archive_file_decodes_rt7_model_metadata():
    payload = _build_rt7_model_payload(
        positions=[(-10, 0, -5), (10, 5, 0), (0, 7, 12)],
        indices=[0, 1, 2],
        material_argument=42,
    )

    profile = profile_archive_file(payload, index_name="MODELS_RT7", archive_key=0, file_id=0)

    assert profile is not None
    assert profile["kind"] == "rt7-model"
    assert profile["parser_status"] == "parsed"
    assert profile["format"] == 2
    assert profile["version"] == 5
    assert profile["vertex_count"] == 3
    assert profile["total_index_count"] == 3
    assert profile["total_triangle_count"] == 1
    assert profile["material_argument_sample"] == [42]
    assert profile["bounds"]["min_x"] == -10
    assert profile["bounds"]["max_z"] == 12
    assert profile["feature_flags"]["has_vertices"] is True
    assert profile["_mesh_obj_text"].startswith("# Reverser Workbench RT7 model export")
    assert "f 1 2 3" in profile["_mesh_obj_text"]


def test_js5_export_profiles_rt7_model_metadata(tmp_path):
    root = tmp_path / "OpenNXT"
    target = root / "data" / "cache" / "js5-47.jcache"
    export_dir = tmp_path / "exports"
    target.parent.mkdir(parents=True, exist_ok=True)
    _write_js5_mapping(root, build=947, index_names={47: "MODELS_RT7"})

    reference_table = _build_reference_table({0: [0]})
    model_payload = _build_rt7_model_payload(
        positions=[(-10, 0, -5), (10, 5, 0), (0, 7, 12)],
        indices=[0, 1, 2],
        material_argument=42,
    )

    with sqlite3.connect(target) as connection:
        connection.execute("CREATE TABLE cache (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute("CREATE TABLE cache_index (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute(
            "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (0, _build_js5_record(model_payload, compression='none', revision=11), 100, 200),
        )
        connection.execute(
            "INSERT INTO cache_index (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (1, _build_js5_record(reference_table, compression='gzip'), -1, 999),
        )
        connection.commit()

    manifest = export_js5_cache(target, export_dir, tables=["cache"])
    file0 = manifest["tables"]["cache"]["records"][0]["archive_files"][0]
    mesh_obj_path = Path(file0["semantic_profile"]["mesh_obj_path"])

    assert manifest["summary"]["semantic_kind_counts"]["rt7-model"] == 1
    assert file0["semantic_profile"]["kind"] == "rt7-model"
    assert file0["semantic_profile"]["vertex_count"] == 3
    assert file0["semantic_profile"]["material_argument_sample"] == [42]
    assert mesh_obj_path.exists()
    assert "f 1 2 3" in mesh_obj_path.read_text(encoding="utf-8")


def test_profile_archive_file_decodes_mapsquare_locations():
    payload = _build_mapsquare_locations_payload(
        [
            {"loc_id": 100, "plane": 0, "x": 10, "y": 20, "type": 10, "rotation": 2},
            {
                "loc_id": 101,
                "plane": 1,
                "x": 5,
                "y": 6,
                "type": 22,
                "rotation": 1,
                "extra": {
                    "flags": 0x0E,
                    "translate_x": 12,
                    "translate_y": -3,
                    "translate_z": 44,
                },
            },
        ]
    )

    profile = profile_archive_file(payload, index_name="MAPS", archive_key=260, file_id=0)

    assert profile is not None
    assert profile["kind"] == "mapsquare-locations"
    assert profile["parser_status"] == "parsed"
    assert profile["mapsquare_x"] == 4
    assert profile["mapsquare_z"] == 2
    assert profile["placement_count"] == 2
    assert profile["unique_loc_id_count"] == 2
    assert profile["plane_counts"] == [1, 1, 0, 0]
    assert profile["translated_placement_count"] == 1
    assert profile["placement_samples"][0]["loc_id"] == 100
    assert profile["placement_samples"][1]["extra"]["translate_z"] == 44


def test_profile_archive_file_decodes_mapsquare_tiles_nxt():
    payload = _build_mapsquare_tile_nxt_payload(
        levels={
            0: {
                0: {
                    "flags": 0x13,
                    "height": 1234,
                    "water_height": 1000,
                    "underlay": 400,
                    "underlay_color": 55,
                    "overlay": 300,
                    "overlay_under": 12,
                    "shape": 1,
                    "underlay_under": 13,
                }
            },
            1: {0: {"flags": 0x01, "height": 44, "underlay": 12, "underlay_color": 7, "overlay": 0}},
        }
    )

    profile = profile_archive_file(payload, index_name="MAPS", archive_key=260, file_id=5)

    assert profile is not None
    assert profile["kind"] == "mapsquare-tiles-nxt"
    assert profile["parser_status"] == "parsed"
    assert profile["mapsquare_x"] == 4
    assert profile["mapsquare_z"] == 2
    assert profile["nonempty_tile_count"] == 2
    assert profile["overlay_tile_count"] == 1
    assert profile["underlay_tile_count"] == 2
    assert profile["level_presence"] == [1, 1, 0, 0]
    assert profile["water_tile_count"] == 1
    assert profile["overlay_under_tile_count"] == 1
    assert profile["height_range"] == {"min": 0, "max": 1234}
    assert profile["water_height_range"] == {"min": 1000, "max": 1000}
    assert profile["tile_samples"][0]["overlay_id"] == 300


def test_js5_export_profiles_mapsquare_payloads(tmp_path):
    root = tmp_path / "OpenNXT"
    target = root / "data" / "cache" / "js5-5.jcache"
    export_dir = tmp_path / "exports"
    target.parent.mkdir(parents=True, exist_ok=True)
    _write_js5_mapping(root, build=947, index_names={5: "MAPS"})

    reference_table = _build_reference_table({260: [0, 5]})
    grouped_archive = _build_grouped_archive(
        {
            0: _build_mapsquare_locations_payload(
                [{"loc_id": 100, "plane": 0, "x": 10, "y": 20, "type": 10, "rotation": 2}]
            ),
            5: _build_mapsquare_tile_nxt_payload(
                levels={
                    0: {
                        0: {
                            "flags": 0x01,
                            "height": 1234,
                            "underlay": 400,
                            "underlay_color": 55,
                            "overlay": 300,
                            "shape": 1,
                        }
                    }
                }
            ),
        }
    )

    with sqlite3.connect(target) as connection:
        connection.execute("CREATE TABLE cache (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute("CREATE TABLE cache_index (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute(
            "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (260, _build_js5_record(grouped_archive, compression='none', revision=11), 100, 200),
        )
        connection.execute(
            "INSERT INTO cache_index (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (1, _build_js5_record(reference_table, compression='gzip'), -1, 999),
        )
        connection.commit()

    manifest = export_js5_cache(target, export_dir, tables=["cache"])
    record = manifest["tables"]["cache"]["records"][0]
    profiles = {entry["file_id"]: entry["semantic_profile"] for entry in record["archive_files"]}

    assert manifest["summary"]["semantic_kind_counts"]["mapsquare-locations"] == 1
    assert manifest["summary"]["semantic_kind_counts"]["mapsquare-tiles-nxt"] == 1
    assert profiles[0]["mapsquare_x"] == 4
    assert profiles[5]["overlay_id_sample"] == [300]


def test_js5_export_enriches_mapsquare_archives_with_object_summaries(tmp_path):
    root = tmp_path / "OpenNXT"
    map_target = root / "data" / "cache" / "js5-5.jcache"
    object_target = root / "data" / "cache" / "js5-16.jcache"
    export_dir = tmp_path / "exports"
    map_target.parent.mkdir(parents=True, exist_ok=True)
    _write_js5_mapping(root, build=947, index_names={5: "MAPS", 16: "CONFIG_OBJECT"})

    map_reference_table = _build_reference_table({260: [0, 3]})
    map_archive = _build_grouped_archive(
        {
            0: _build_mapsquare_locations_payload(
                [{"loc_id": 513, "plane": 0, "x": 10, "y": 20, "type": 10, "rotation": 2}]
            ),
            3: _build_mapsquare_tile_payload(
                tiles={0: {"overlay": 200, "shape": 3, "underlay": 400, "height": 1234}},
                environment_id=77,
            ),
        }
    )
    object_reference_table = _build_reference_table({2: [1]})
    object_payload = _build_object_definition(
        name="Crate",
        actions=["Search"],
        size_x=2,
        size_y=3,
        animation_id=3206,
    )

    with sqlite3.connect(map_target) as connection:
        connection.execute("CREATE TABLE cache (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute("CREATE TABLE cache_index (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute(
            "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (260, _build_js5_record(map_archive, compression="none", revision=11), 100, 200),
        )
        connection.execute(
            "INSERT INTO cache_index (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (1, _build_js5_record(map_reference_table, compression="gzip"), -1, 999),
        )
        connection.commit()

    with sqlite3.connect(object_target) as connection:
        connection.execute("CREATE TABLE cache (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute("CREATE TABLE cache_index (KEY INTEGER PRIMARY KEY, DATA BLOB, VERSION INTEGER, CRC INTEGER)")
        connection.execute(
            "INSERT INTO cache (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (2, _build_js5_record(object_payload, compression="none", revision=5), 20, 30),
        )
        connection.execute(
            "INSERT INTO cache_index (KEY, DATA, VERSION, CRC) VALUES (?, ?, ?, ?)",
            (1, _build_js5_record(object_reference_table, compression="gzip"), -1, 777),
        )
        connection.commit()

    manifest = export_js5_cache(map_target, export_dir, tables=["cache"])
    record = manifest["tables"]["cache"]["records"][0]
    profiles = {entry["file_id"]: entry["semantic_profile"] for entry in record["archive_files"]}
    location_profile = profiles[0]
    archive_summary = record["archive_summary"]

    assert manifest["summary"]["archive_summary_count"] == 1
    assert manifest["summary"]["archive_summary_kind_counts"]["mapsquare-archive"] == 1
    assert location_profile["loc_definition_lookup_count"] == 1
    assert location_profile["loc_definition_resolved_count"] == 1
    assert location_profile["loc_definition_sample"][0]["name"] == "Crate"
    assert location_profile["placement_samples"][0]["loc_summary"]["primary_action"] == "Search"
    assert archive_summary["kind"] == "mapsquare-archive"
    assert archive_summary["mapsquare_x"] == 4
    assert archive_summary["mapsquare_z"] == 2
    assert archive_summary["file_kinds_present"] == ["locations", "tiles"]
    assert archive_summary["environment_id_sample"] == [77]
    assert archive_summary["overlay_id_sample"] == [200]
    assert archive_summary["underlay_id_sample"] == [400]
    assert archive_summary["loc_definition_sample"][0]["animation_id"] == 3206
