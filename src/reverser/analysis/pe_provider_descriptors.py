from __future__ import annotations

import struct
from pathlib import Path

from reverser.analysis.pe_address_refs import find_pe_address_refs
from reverser.analysis.pe_direct_calls import PEMetadata, parse_int_literal, read_pe_metadata
from reverser.analysis.pe_function_literals import find_pe_function_literals
from reverser.analysis.pe_rtti import read_msvc_rtti_type_descriptor


def _hex(value: int) -> str:
    return f"0x{value:x}"


def _read_bytes(data: bytes, metadata: PEMetadata, va: int, count: int) -> bytes | None:
    section = metadata.section_for_va(va)
    if section is None:
        return None
    raw_offset = metadata.rva_to_offset(va - metadata.image_base)
    if raw_offset + count > len(data):
        return None
    return data[raw_offset : raw_offset + count]


def _read_qword(data: bytes, metadata: PEMetadata, va: int) -> int | None:
    raw = _read_bytes(data, metadata, va, 8)
    if raw is None:
        return None
    return struct.unpack_from("<Q", raw)[0]


def _annotate_pointer(value: int, metadata: PEMetadata) -> dict[str, object]:
    section = metadata.section_for_va(value)
    payload: dict[str, object] = {
        "value": _hex(value),
        "annotation": "non-image-value",
    }
    if value == 0:
        payload["annotation"] = "zero"
    elif section is not None:
        payload["annotation"] = "executable-target" if section.is_executable else "image-target"
        payload["target_rva"] = _hex(value - metadata.image_base)
        payload["target_section"] = section.name
        payload["target_is_executable"] = section.is_executable
    return payload


def _decode_lea_rax_rip_relative(raw: bytes, instruction_va: int) -> int | None:
    if len(raw) < 7 or raw[0:3] != b"\x48\x8d\x05":
        return None
    displacement = struct.unpack_from("<i", raw, 3)[0]
    return instruction_va + 7 + displacement


def _decode_clone_materializer(data: bytes, metadata: PEMetadata, thunk_va: int, descriptor_va: int) -> dict[str, object] | None:
    raw = _read_bytes(data, metadata, thunk_va, 22)
    if raw is None:
        return None
    descriptor_from_thunk = _decode_lea_rax_rip_relative(raw, thunk_va)
    if descriptor_from_thunk is None:
        return None
    suffix = bytes.fromhex("488902488b410848894208488bc2c3")
    if raw[7:] != suffix:
        return None
    return {
        "kind": "clone-materializer",
        "descriptor_from_thunk": _hex(descriptor_from_thunk),
        "matches_descriptor": descriptor_from_thunk == descriptor_va,
        "role": "stamp descriptor pointer, copy source payload +0x8, return output provider",
    }


def _decode_rtti_getter(data: bytes, metadata: PEMetadata, thunk_va: int, *, max_name_bytes: int) -> dict[str, object] | None:
    raw = _read_bytes(data, metadata, thunk_va, 8)
    if raw is None:
        return None
    target_va = _decode_lea_rax_rip_relative(raw, thunk_va)
    if target_va is None or raw[7] != 0xC3:
        return None
    return {
        "kind": "rtti-type-getter",
        "rtti_type_descriptor": read_msvc_rtti_type_descriptor(
            data,
            metadata,
            target_va,
            max_name_bytes=max_name_bytes,
        ),
    }


def _decode_payload_setter(data: bytes, metadata: PEMetadata, thunk_va: int) -> dict[str, object] | None:
    raw = _read_bytes(data, metadata, thunk_va, 16)
    if raw is None or raw[0:4] != b"\x48\x8b\x41\x08":
        return None
    if len(raw) >= 12 and raw[4:6] == b"\xc6\x80" and raw[11] == 0xC3:
        return {
            "kind": "payload-byte-setter",
            "payload_source": "qword ptr [RCX+0x8]",
            "field_offset": _hex(struct.unpack_from("<I", raw, 6)[0]),
            "value": raw[10],
        }
    if len(raw) >= 15 and raw[4:6] == b"\xc7\x80" and raw[14] == 0xC3:
        return {
            "kind": "payload-dword-setter",
            "payload_source": "qword ptr [RCX+0x8]",
            "field_offset": _hex(struct.unpack_from("<I", raw, 6)[0]),
            "value": struct.unpack_from("<I", raw, 10)[0],
        }
    return None


def _decode_forward_jump(data: bytes, metadata: PEMetadata, thunk_va: int) -> dict[str, object] | None:
    raw = _read_bytes(data, metadata, thunk_va, 16)
    if raw is None:
        return None

    if len(raw) >= 9 and raw[0:4] == b"\x48\x8b\x49\x08" and raw[4] == 0xE9:
        displacement = struct.unpack_from("<i", raw, 5)[0]
        return {
            "kind": "payload-forward-jump",
            "payload_source": "qword ptr [RCX+0x8]",
            "jump_target": _hex(thunk_va + 9 + displacement),
        }

    if len(raw) >= 12 and raw[0:7] == b"\x48\x8b\x12\x48\x8b\x49\x08" and raw[7] == 0xE9:
        displacement = struct.unpack_from("<i", raw, 8)[0]
        return {
            "kind": "payload-rdx-unwrap-forward-jump",
            "payload_source": "qword ptr [RCX+0x8]",
            "rdx_source": "qword ptr [RDX]",
            "jump_target": _hex(thunk_va + 12 + displacement),
        }

    if len(raw) >= 8 and raw[0:3] == b"\x48\x83\xc1" and raw[4] == 0xE9:
        displacement = struct.unpack_from("<i", raw, 5)[0]
        return {
            "kind": "rcx-add-forward-jump",
            "rcx_add": _hex(raw[3]),
            "jump_target": _hex(thunk_va + 9 + displacement),
        }

    return None


def _classify_slot(
    data: bytes,
    metadata: PEMetadata,
    *,
    descriptor_va: int,
    slot_index: int,
    slot_value: int,
    max_name_bytes: int,
) -> dict[str, object]:
    slot: dict[str, object] = {
        "slot": slot_index,
        "target": _annotate_pointer(slot_value, metadata),
    }
    if metadata.section_for_va(slot_value) is None:
        return slot

    clone = _decode_clone_materializer(data, metadata, slot_value, descriptor_va)
    if clone is not None:
        slot["thunk"] = clone
        return slot

    payload_setter = _decode_payload_setter(data, metadata, slot_value)
    if payload_setter is not None:
        slot["thunk"] = payload_setter
        return slot

    forward_jump = _decode_forward_jump(data, metadata, slot_value)
    if forward_jump is not None:
        slot["thunk"] = forward_jump
        return slot

    rtti_getter = _decode_rtti_getter(data, metadata, slot_value, max_name_bytes=max_name_bytes)
    if rtti_getter is not None:
        slot["thunk"] = rtti_getter
        return slot

    first_bytes = _read_bytes(data, metadata, slot_value, 16)
    if first_bytes is not None:
        slot["thunk"] = {
            "kind": "unclassified",
            "first_bytes": first_bytes.hex(),
        }
    return slot


def summarize_pe_provider_descriptors(
    path: str | Path,
    addresses: list[str | int],
    *,
    slot_count: int = 6,
    max_name_bytes: int = 256,
) -> dict[str, object]:
    if slot_count <= 0:
        raise ValueError("Slot count must be greater than zero.")

    target_path = Path(path)
    data = target_path.read_bytes()
    metadata = read_pe_metadata(data)
    warnings: list[str] = []
    descriptors: list[dict[str, object]] = []

    for address in addresses:
        requested_value = parse_int_literal(str(address))
        descriptor = _summarize_descriptor_at(
            data,
            metadata,
            requested_value,
            request=str(address),
            slot_count=slot_count,
            max_name_bytes=max_name_bytes,
        )
        if "warning" in descriptor:
            warnings.append(str(descriptor["warning"]))
        descriptors.append(descriptor)

    return {
        "type": "pe-provider-descriptors",
        "target": str(target_path),
        "image_base": _hex(metadata.image_base),
        "descriptors": descriptors,
        "warnings": warnings,
    }


def scan_pe_provider_descriptors(
    path: str | Path,
    *,
    section_names: list[str] | None = None,
    slot_count: int = 6,
    max_results: int = 128,
    require_rtti: bool = True,
    include_refs: bool = False,
    max_refs_per_descriptor: int = 16,
    max_name_bytes: int = 256,
) -> dict[str, object]:
    if slot_count <= 0:
        raise ValueError("Slot count must be greater than zero.")
    if max_results <= 0:
        raise ValueError("Max results must be greater than zero.")
    if max_refs_per_descriptor <= 0:
        raise ValueError("Max refs per descriptor must be greater than zero.")

    target_path = Path(path)
    data = target_path.read_bytes()
    metadata = read_pe_metadata(data)
    requested_sections = {name.lower() for name in section_names or []}
    scan_sections = [
        section
        for section in metadata.sections
        if section.raw_size > 0
        and not section.is_executable
        and (not requested_sections or section.name.lower() in requested_sections)
    ]
    descriptors: list[dict[str, object]] = []
    candidate_count = 0
    scanned_qword_count = 0

    for section in scan_sections:
        raw_start = section.raw_pointer
        raw_end = min(len(data), section.raw_pointer + section.raw_size)
        raw_cursor = raw_start
        while raw_cursor + 32 <= raw_end:
            scanned_qword_count += 1
            slot0 = struct.unpack_from("<Q", data, raw_cursor)[0]
            slot1 = struct.unpack_from("<Q", data, raw_cursor + 8)[0]
            if slot0 == 0 or slot0 != slot1:
                raw_cursor += 8
                continue

            descriptor_rva = section.virtual_address + (raw_cursor - section.raw_pointer)
            descriptor_va = metadata.image_base + descriptor_rva
            clone = _decode_clone_materializer(data, metadata, slot0, descriptor_va)
            if clone is None or not clone["matches_descriptor"]:
                raw_cursor += 8
                continue

            descriptor = _summarize_descriptor_at(
                data,
                metadata,
                descriptor_va,
                request=_hex(descriptor_va),
                slot_count=slot_count,
                max_name_bytes=max_name_bytes,
            )
            has_rtti = bool(descriptor.get("summary", {}).get("rtti_type_getter_slots"))
            if require_rtti and not has_rtti:
                raw_cursor += 8
                continue

            candidate_count += 1
            if len(descriptors) < max_results:
                descriptors.append(descriptor)
            raw_cursor += 8

    reference_payload: dict[str, object] | None = None
    if include_refs and descriptors:
        reference_payload = find_pe_address_refs(
            target_path,
            [str(descriptor["address"]) for descriptor in descriptors],
            max_hits_per_target=max_refs_per_descriptor,
        )
        refs_by_target = {entry["target_va"]: entry for entry in reference_payload["results"]}
        for descriptor in descriptors:
            descriptor["references"] = refs_by_target.get(str(descriptor["address"]))
            descriptor["reference_roles"] = _summarize_descriptor_references(descriptor)

    return {
        "type": "pe-provider-descriptor-scan",
        "target": str(target_path),
        "image_base": _hex(metadata.image_base),
        "scan": {
            "section_filter": sorted(requested_sections),
            "sections_scanned": [
                {
                    "name": section.name,
                    "virtual_address": _hex(section.virtual_address),
                    "raw_pointer": _hex(section.raw_pointer),
                    "raw_size": _hex(section.raw_size),
                }
                for section in scan_sections
            ],
            "scanned_qword_count": scanned_qword_count,
            "candidate_count": candidate_count,
            "result_count": len(descriptors),
            "max_results": max_results,
            "slot_count": slot_count,
            "require_rtti": require_rtti,
            "include_refs": include_refs,
            "max_refs_per_descriptor": max_refs_per_descriptor,
        },
        "descriptors": descriptors,
        "reference_scan": reference_payload["scan"] if reference_payload is not None else None,
        "reference_clusters": _cluster_descriptors_by_setup_function(descriptors) if reference_payload is not None else None,
        "warnings": [],
    }


def _compact_reference(hit: dict[str, object]) -> dict[str, object]:
    compact: dict[str, object] = {
        "kind": hit.get("kind"),
        "reference_va": hit.get("reference_va"),
        "reference_rva": hit.get("reference_rva"),
        "section": hit.get("section"),
    }
    if isinstance(hit.get("function"), dict):
        compact["function"] = hit["function"]
    return compact


def _clone_materializer_targets(descriptor: dict[str, object]) -> set[str]:
    targets: set[str] = set()
    for slot in descriptor.get("slots", []):
        if not isinstance(slot, dict) or not isinstance(slot.get("thunk"), dict):
            continue
        if slot["thunk"].get("kind") != "clone-materializer":
            continue
        target = slot.get("target", {})
        if isinstance(target, dict) and isinstance(target.get("value"), str):
            targets.add(target["value"].lower())
    return targets


def _summarize_descriptor_references(descriptor: dict[str, object]) -> dict[str, object]:
    clone_targets = _clone_materializer_targets(descriptor)
    roles: dict[str, object] = {
        "setup_references": [],
        "clone_materializer_references": [],
        "other_references": [],
    }
    references = descriptor.get("references")
    if not isinstance(references, dict):
        return roles

    for hit in references.get("hits", []):
        if not isinstance(hit, dict):
            continue
        compact = _compact_reference(hit)
        reference_va = str(hit.get("reference_va", "")).lower()
        if reference_va in clone_targets:
            roles["clone_materializer_references"].append(compact)
        elif isinstance(hit.get("function"), dict):
            roles["setup_references"].append(compact)
        else:
            roles["other_references"].append(compact)
    return roles


def _descriptor_cluster_entry(
    descriptor: dict[str, object],
    *,
    setup_references: list[dict[str, object]],
) -> dict[str, object]:
    summary = descriptor.get("summary", {})
    roles = descriptor.get("reference_roles", {})
    return {
        "address": descriptor.get("address"),
        "primary_decorated_name": summary.get("primary_decorated_name") if isinstance(summary, dict) else None,
        "setup_references": setup_references,
        "clone_materializer_references": roles.get("clone_materializer_references", []) if isinstance(roles, dict) else [],
        "other_references": roles.get("other_references", []) if isinstance(roles, dict) else [],
    }


def _cluster_descriptors_by_setup_function(descriptors: list[dict[str, object]]) -> dict[str, object]:
    clusters_by_start: dict[str, dict[str, object]] = {}
    descriptor_count_with_setup_refs = 0

    for descriptor in descriptors:
        roles = descriptor.get("reference_roles")
        if not isinstance(roles, dict):
            continue
        setup_references = [ref for ref in roles.get("setup_references", []) if isinstance(ref, dict)]
        if setup_references:
            descriptor_count_with_setup_refs += 1

        references_by_function: dict[str, list[dict[str, object]]] = {}
        for reference in setup_references:
            function = reference.get("function")
            if not isinstance(function, dict) or not isinstance(function.get("start_va"), str):
                continue
            references_by_function.setdefault(function["start_va"], []).append(reference)

        for function_start, grouped_refs in references_by_function.items():
            function = grouped_refs[0]["function"]
            cluster = clusters_by_start.setdefault(
                function_start,
                {
                    "kind": "setup-function",
                    "function": function,
                    "descriptor_count": 0,
                    "setup_reference_count": 0,
                    "clone_materializer_reference_count": 0,
                    "descriptors": [],
                },
            )
            entry = _descriptor_cluster_entry(descriptor, setup_references=grouped_refs)
            cluster["descriptors"].append(entry)
            cluster["descriptor_count"] += 1
            cluster["setup_reference_count"] += len(grouped_refs)
            cluster["clone_materializer_reference_count"] += len(entry["clone_materializer_references"])

    clusters = sorted(
        clusters_by_start.values(),
        key=lambda cluster: parse_int_literal(str(cluster["function"]["start_va"])),
    )
    return {
        "setup_function_cluster_count": len(clusters),
        "descriptor_count_with_setup_refs": descriptor_count_with_setup_refs,
        "descriptor_count_without_setup_refs": max(0, len(descriptors) - descriptor_count_with_setup_refs),
        "setup_function_clusters": clusters,
    }


def _literal_payload_by_function(literal_payload: dict[str, object] | None) -> dict[str, dict[str, object]]:
    if not isinstance(literal_payload, dict):
        return {}
    return {
        str(function.get("start_va")): function
        for function in literal_payload.get("functions", [])
        if isinstance(function, dict) and isinstance(function.get("start_va"), str)
    }


def _cluster_function_specs(payload: dict[str, object]) -> list[str]:
    reference_clusters = payload.get("reference_clusters")
    if not isinstance(reference_clusters, dict):
        return []
    specs: list[str] = []
    for cluster in reference_clusters.get("setup_function_clusters", []):
        if not isinstance(cluster, dict) or not isinstance(cluster.get("function"), dict):
            continue
        function = cluster["function"]
        start_va = function.get("start_va")
        end_va = function.get("end_va")
        if isinstance(start_va, str) and isinstance(end_va, str):
            specs.append(f"{start_va}:{end_va}")
    return specs


def provider_descriptor_cluster_literal_payload(
    path: str | Path,
    payload: dict[str, object],
    *,
    max_literals_per_function: int = 8,
    max_string_bytes: int = 256,
    min_string_length: int = 4,
) -> dict[str, object]:
    return find_pe_function_literals(
        path,
        _cluster_function_specs(payload),
        max_literals_per_function=max_literals_per_function,
        max_string_bytes=max_string_bytes,
        min_string_length=min_string_length,
    )


def compact_provider_descriptor_clusters(
    payload: dict[str, object],
    *,
    max_descriptors_per_cluster: int = 8,
    literal_payload: dict[str, object] | None = None,
) -> dict[str, object]:
    if max_descriptors_per_cluster <= 0:
        raise ValueError("Max descriptors per cluster must be greater than zero.")

    reference_clusters = payload.get("reference_clusters")
    literals_by_function = _literal_payload_by_function(literal_payload)
    clusters = []
    if isinstance(reference_clusters, dict):
        clusters = [
            cluster
            for cluster in reference_clusters.get("setup_function_clusters", [])
            if isinstance(cluster, dict)
        ]

    compact_clusters: list[dict[str, object]] = []
    for cluster in sorted(clusters, key=lambda item: (-int(item.get("descriptor_count", 0)), str(item.get("function", {})))):
        function = cluster.get("function", {})
        descriptors = [item for item in cluster.get("descriptors", []) if isinstance(item, dict)]
        descriptor_preview = []
        for descriptor in descriptors[:max_descriptors_per_cluster]:
            setup_references = descriptor.get("setup_references", [])
            setup_reference = setup_references[0] if setup_references and isinstance(setup_references[0], dict) else {}
            descriptor_preview.append(
                {
                    "address": descriptor.get("address"),
                    "primary_decorated_name": descriptor.get("primary_decorated_name"),
                    "setup_reference_va": setup_reference.get("reference_va"),
                    "clone_materializer_reference_count": len(descriptor.get("clone_materializer_references", [])),
                    "other_reference_count": len(descriptor.get("other_references", [])),
                }
            )
        compact_clusters.append(
            {
                "function": function,
                "literals": literals_by_function.get(str(function.get("start_va"))),
                "descriptor_count": cluster.get("descriptor_count", 0),
                "setup_reference_count": cluster.get("setup_reference_count", 0),
                "clone_materializer_reference_count": cluster.get("clone_materializer_reference_count", 0),
                "descriptor_preview_count": len(descriptor_preview),
                "descriptor_preview_truncated_count": max(0, len(descriptors) - len(descriptor_preview)),
                "descriptor_preview": descriptor_preview,
            }
        )

    scan = payload.get("scan", {}) if isinstance(payload.get("scan"), dict) else {}
    return {
        "type": "pe-provider-descriptor-clusters",
        "target": payload.get("target"),
        "image_base": payload.get("image_base"),
        "source_type": payload.get("type"),
        "scan": {
            "candidate_count": scan.get("candidate_count"),
            "result_count": scan.get("result_count"),
            "section_filter": scan.get("section_filter", []),
            "slot_count": scan.get("slot_count"),
            "require_rtti": scan.get("require_rtti"),
            "include_refs": scan.get("include_refs"),
            "max_descriptors_per_cluster": max_descriptors_per_cluster,
            "include_literals": literal_payload is not None,
        },
        "summary": {
            "setup_function_cluster_count": len(compact_clusters),
            "descriptor_count_with_setup_refs": reference_clusters.get("descriptor_count_with_setup_refs", 0)
            if isinstance(reference_clusters, dict)
            else 0,
            "descriptor_count_without_setup_refs": reference_clusters.get("descriptor_count_without_setup_refs", 0)
            if isinstance(reference_clusters, dict)
            else 0,
        },
        "clusters": compact_clusters,
    }


def provider_descriptor_cluster_rows(
    payload: dict[str, object],
    *,
    max_descriptors_per_cluster: int = 8,
    literal_payload: dict[str, object] | None = None,
) -> list[dict[str, object]]:
    compact = compact_provider_descriptor_clusters(
        payload,
        max_descriptors_per_cluster=max_descriptors_per_cluster,
        literal_payload=literal_payload,
    )
    rows: list[dict[str, object]] = []
    for cluster in compact["clusters"]:
        function = cluster.get("function", {}) if isinstance(cluster.get("function"), dict) else {}
        preview = [item for item in cluster.get("descriptor_preview", []) if isinstance(item, dict)]
        literals = cluster.get("literals", {}) if isinstance(cluster.get("literals"), dict) else {}
        literal_entries = [item for item in literals.get("literals", []) if isinstance(item, dict)]
        rows.append(
            {
                "function_start_va": function.get("start_va"),
                "function_end_va": function.get("end_va"),
                "literal_hit_count": literals.get("literal_hit_count", 0),
                "literal_count": literals.get("literal_count", 0),
                "sample_literals": ";".join(str(item.get("value")) for item in literal_entries),
                "descriptor_count": cluster.get("descriptor_count"),
                "setup_reference_count": cluster.get("setup_reference_count"),
                "clone_materializer_reference_count": cluster.get("clone_materializer_reference_count"),
                "descriptor_preview_count": cluster.get("descriptor_preview_count"),
                "descriptor_preview_truncated_count": cluster.get("descriptor_preview_truncated_count"),
                "sample_descriptors": ";".join(str(item.get("address")) for item in preview),
                "sample_setup_refs": ";".join(str(item.get("setup_reference_va")) for item in preview),
                "sample_rtti_names": ";".join(
                    str(item.get("primary_decorated_name"))
                    for item in preview
                    if item.get("primary_decorated_name")
                ),
            }
        )
    return rows


def _summarize_descriptor_at(
    data: bytes,
    metadata: PEMetadata,
    requested_value: int,
    *,
    request: str,
    slot_count: int,
    max_name_bytes: int,
) -> dict[str, object]:
    descriptor_va, descriptor_rva = metadata.normalize_va_or_rva(requested_value)
    section = metadata.section_for_rva(descriptor_rva)
    descriptor: dict[str, object] = {
        "request": request,
        "address": _hex(descriptor_va),
        "rva": _hex(descriptor_rva),
        "section": section.name if section is not None else None,
        "slot_count_requested": slot_count,
        "slots": [],
    }

    if section is None:
        message = f"{request}: address {_hex(descriptor_va)} is not mapped by a PE section"
        descriptor["error"] = message
        descriptor["warning"] = message
        return descriptor

    raw_offset = metadata.rva_to_offset(descriptor_rva)
    descriptor["raw_offset"] = _hex(raw_offset)
    available_slots = max(0, (min(len(data), section.raw_pointer + section.raw_size) - raw_offset) // 8)
    if available_slots < slot_count:
        descriptor["warning"] = f"{request}: requested {slot_count} slots but only {available_slots} fit in mapped data"

    returned_slot_count = min(slot_count, available_slots)
    slots = []
    for index in range(returned_slot_count):
        slot_va = descriptor_va + index * 8
        slot_value = _read_qword(data, metadata, slot_va)
        if slot_value is None:
            continue
        slots.append(
            _classify_slot(
                data,
                metadata,
                descriptor_va=descriptor_va,
                slot_index=index,
                slot_value=slot_value,
                max_name_bytes=max_name_bytes,
            )
        )
    descriptor["slot_count_returned"] = len(slots)
    descriptor["slots"] = slots
    descriptor["summary"] = _summarize_descriptor(slots)
    return descriptor


def _summarize_descriptor(slots: list[dict[str, object]]) -> dict[str, object]:
    clone_slots = [
        slot["slot"]
        for slot in slots
        if isinstance(slot.get("thunk"), dict) and slot["thunk"].get("kind") == "clone-materializer"
    ]
    rtti_slots = [
        slot
        for slot in slots
        if isinstance(slot.get("thunk"), dict) and slot["thunk"].get("kind") == "rtti-type-getter"
    ]
    summary: dict[str, object] = {
        "clone_materializer_slots": clone_slots,
        "has_duplicate_slot0_slot1": len(slots) >= 2 and slots[0]["target"]["value"] == slots[1]["target"]["value"],
        "rtti_type_getter_slots": [slot["slot"] for slot in rtti_slots],
    }
    if rtti_slots:
        rtti_descriptor = rtti_slots[0]["thunk"]["rtti_type_descriptor"]
        summary["primary_rtti_type_descriptor"] = rtti_descriptor.get("address")
        summary["primary_decorated_name"] = rtti_descriptor.get("decorated_name")
        parsed_name = rtti_descriptor.get("parsed_name")
        if isinstance(parsed_name, dict):
            summary["primary_parsed_name"] = parsed_name.get("name")
    return summary
