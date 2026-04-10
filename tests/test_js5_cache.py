from __future__ import annotations

import bz2
import gzip
import json
import lzma
import sqlite3
from pathlib import Path

from reverser.analysis.js5 import export_js5_cache, profile_archive_file
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
    script_name: str = "",
    body_bytes: bytes = b"\x00",
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
        script_name.encode("cp1252")
        + b"\x00"
        + body_bytes
        + bytes(footer)
        + bytes(switch_payload)
        + len(switch_payload).to_bytes(2, "big")
    )


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
    assert profile["script_name"] is None


def test_js5_export_profiles_clientscript_metadata(tmp_path):
    root = tmp_path / "OpenNXT"
    target = root / "data" / "cache" / "js5-12.jcache"
    export_dir = tmp_path / "exports"
    target.parent.mkdir(parents=True, exist_ok=True)
    _write_js5_mapping(root, build=947, index_names={12: "CLIENTSCRIPTS"})

    reference_table = _build_reference_table({0: [0]})
    script_payload = _build_clientscript_payload(
        instruction_count=90,
        local_int_count=8,
        int_argument_count=3,
        body_bytes=b"\x05\x11\x00\x00\x00\x00",
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

    assert manifest["summary"]["semantic_kind_counts"]["clientscript-metadata"] == 1
    assert file0["semantic_profile"]["kind"] == "clientscript-metadata"
    assert file0["semantic_profile"]["instruction_count"] == 90
    assert file0["semantic_profile"]["local_int_count"] == 8
    assert file0["semantic_profile"]["int_argument_count"] == 3
