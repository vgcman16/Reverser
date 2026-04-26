from __future__ import annotations

import re
import struct
from dataclasses import dataclass
from pathlib import Path

from reverser.analysis.pe_direct_calls import PEMetadata, parse_int_literal, read_pe_metadata
from reverser.analysis.pe_function_calls import _parse_function_spec
from reverser.analysis.pe_registration_records import _normalize_address, _scan_range_instructions
from reverser.analysis.pe_runtime_functions import read_pe_runtime_functions
from reverser.analysis.pe_selector_table_dispatches import _dest_register, _operands, _register_name


def _hex(value: int) -> str:
    return f"0x{value:x}"


@dataclass(frozen=True)
class MemoryOperand:
    base: str | None
    index: str | None
    scale: int
    displacement: int


_REGISTER_RE = re.compile(r"^(?:R(?:1[0-5]|[0-9]|[A-Z]{2})(?:D|W|B)?|E(?:AX|BX|CX|DX|SI|DI|SP|BP)|[A-Z]{2})$")


def _parse_memory_operand(value: str | None) -> MemoryOperand | None:
    if value is None:
        return None
    raw = value.strip().upper().replace(" ", "")
    if not raw.startswith("[") or not raw.endswith("]"):
        return None

    base: str | None = None
    index: str | None = None
    scale = 1
    displacement = 0

    for token in re.findall(r"[+-]?[^+-]+", raw[1:-1]):
        token = token.lstrip("+")
        if "*" in token:
            register, raw_scale = token.split("*", 1)
            register = _register_name(register)
            if not _REGISTER_RE.match(register):
                return None
            index = register
            scale = int(raw_scale, 0)
            continue

        normalized = _register_name(token)
        if _REGISTER_RE.match(normalized):
            if base is None:
                base = normalized
            elif index is None:
                index = normalized
            else:
                return None
            continue

        displacement += int(token, 0)

    return MemoryOperand(base=base, index=index, scale=scale, displacement=displacement)


def _instruction_payload(instruction: dict[str, object]) -> dict[str, object]:
    return {
        "address_va": instruction["address_va"],
        "address_rva": instruction["address_rva"],
        "instruction": instruction["instruction"],
    }


def _memory_target_from_image_base(memory: MemoryOperand, image_base: int) -> int:
    if memory.base is None:
        return memory.displacement
    return image_base + memory.displacement


def _signed_32(value: int) -> int:
    return value - 0x100000000 if value & 0x80000000 else value


def _find_recent_image_base_load(
    instructions: list[dict[str, object]],
    start_index: int,
    register: str,
    image_base: int,
    max_backtrack_instructions: int,
) -> dict[str, object] | None:
    for index in range(start_index - 1, max(-1, start_index - max_backtrack_instructions - 1), -1):
        instruction = instructions[index]
        if _dest_register(instruction) != register:
            continue
        target = instruction.get("memory_target_va")
        immediate = instruction.get("immediate")
        if target is not None and parse_int_literal(str(target)) == image_base:
            return instruction
        if immediate is not None and int(immediate) == image_base:
            return instruction
    return None


def _find_recent_register_bias(
    instructions: list[dict[str, object]],
    start_index: int,
    register: str,
    max_backtrack_instructions: int,
) -> dict[str, object] | None:
    for index in range(start_index - 1, max(-1, start_index - max_backtrack_instructions - 1), -1):
        instruction = instructions[index]
        if _dest_register(instruction) != register or "immediate" not in instruction:
            continue

        immediate = int(instruction["immediate"])
        mnemonic = instruction.get("mnemonic")
        if mnemonic == "ADD":
            bias = _signed_32(immediate)
        elif mnemonic == "SUB":
            bias = -immediate
        else:
            continue

        payload = _instruction_payload(instruction)
        payload.update(
            {
                "register": register,
                "bias": bias,
                "selector_value_for_index_zero": -bias,
            }
        )
        return payload
    return None


def _find_selector_index_setup(
    instructions: list[dict[str, object]],
    start_index: int,
    selector_index_register: str,
    max_backtrack_instructions: int,
) -> dict[str, object] | None:
    for index in range(start_index - 1, max(-1, start_index - max_backtrack_instructions - 1), -1):
        instruction = instructions[index]
        if instruction.get("mnemonic") not in {"LEA", "MOV", "MOVZX", "MOVSXD", "ADD", "SUB"}:
            continue
        if _dest_register(instruction) != selector_index_register:
            continue
        _, right = _operands(instruction)
        memory = _parse_memory_operand(right)
        payload = _instruction_payload(instruction)
        if instruction.get("mnemonic") == "LEA" and memory is not None:
            payload.update(
                {
                    "source_register": memory.base,
                    "bias": memory.displacement,
                    "selector_value_for_index_zero": -memory.displacement,
                }
            )
        elif right is not None and not right.startswith("["):
            source_register = _register_name(right)
            if _REGISTER_RE.match(source_register):
                payload["source_register"] = source_register
                bias = _find_recent_register_bias(
                    instructions,
                    index,
                    source_register,
                    max_backtrack_instructions,
                )
                if bias is not None:
                    payload["bias_setup"] = bias
                    payload["bias"] = bias["bias"]
                    payload["selector_value_for_index_zero"] = bias["selector_value_for_index_zero"]
        return payload
    return None


def _find_bound_check(
    instructions: list[dict[str, object]],
    start_index: int,
    selector_index_registers: set[str],
    max_backtrack_instructions: int,
) -> dict[str, object] | None:
    for index in range(start_index - 1, max(-1, start_index - max_backtrack_instructions - 1), -1):
        instruction = instructions[index]
        if instruction.get("mnemonic") != "CMP" or "immediate" not in instruction:
            continue
        left, _ = _operands(instruction)
        if _register_name(left) not in selector_index_registers:
            continue

        branch: dict[str, object] | None = None
        for candidate in instructions[index + 1 : start_index]:
            if str(candidate.get("mnemonic", "")).startswith("J"):
                branch = _instruction_payload(candidate)
                break

        upper_bound = int(instruction["immediate"])
        payload = _instruction_payload(instruction)
        payload.update(
            {
                "bound_register": _register_name(left),
                "upper_bound": upper_bound,
                "upper_bound_hex": _hex(upper_bound),
                "inferred_index_count": upper_bound + 1,
            }
        )
        if branch is not None:
            payload["branch"] = branch
        return payload
    return None


def _find_target_table_load(
    instructions: list[dict[str, object]],
    start_index: int,
    *,
    base_register: str,
    remap_register: str,
    target_table_base_va: int,
    image_base: int,
    max_lookahead_instructions: int,
) -> tuple[int, str, MemoryOperand] | None:
    limit = min(len(instructions), start_index + 1 + max_lookahead_instructions)
    for index in range(start_index + 1, limit):
        instruction = instructions[index]
        if instruction.get("mnemonic") not in {"MOV", "MOVSXD"}:
            continue
        target_register = _dest_register(instruction)
        _, right = _operands(instruction)
        memory = _parse_memory_operand(right)
        if target_register is None or memory is None:
            continue
        if memory.base != base_register or memory.index != remap_register or memory.scale != 4:
            continue
        if _memory_target_from_image_base(memory, image_base) != target_table_base_va:
            continue
        return index, target_register, memory
    return None


def _find_resolved_branch(
    instructions: list[dict[str, object]],
    start_index: int,
    *,
    base_register: str,
    target_register: str,
    max_lookahead_instructions: int,
) -> tuple[int, int] | None:
    limit = min(len(instructions), start_index + 1 + max_lookahead_instructions)
    for add_index in range(start_index + 1, limit):
        instruction = instructions[add_index]
        left, right = _operands(instruction)
        if (
            instruction.get("mnemonic") != "ADD"
            or _register_name(left) != target_register
            or right is None
            or _register_name(right) != base_register
        ):
            continue

        for branch_index in range(add_index + 1, min(len(instructions), add_index + 5)):
            branch = instructions[branch_index]
            branch_left, _ = _operands(branch)
            if branch.get("mnemonic") in {"JMP", "CALL"} and _register_name(branch_left) == target_register:
                return add_index, branch_index
    return None


def _entry_section_payload(metadata: PEMetadata, target_rva: int) -> tuple[str | None, bool | None]:
    section = metadata.section_for_rva(target_rva)
    if section is None:
        return None, None
    return section.name, section.is_executable


def _read_remapped_entries(
    data: bytes,
    metadata: PEMetadata,
    *,
    index_table_base_va: int,
    target_table_base_va: int,
    index_count: int,
    max_entries: int,
    selector_index_setup: dict[str, object] | None,
) -> tuple[list[dict[str, object]], list[str], int]:
    warnings: list[str] = []
    entries: list[dict[str, object]] = []
    returned_count = min(index_count, max_entries)
    selector_zero_value = None
    if selector_index_setup is not None and "selector_value_for_index_zero" in selector_index_setup:
        selector_zero_value = int(selector_index_setup["selector_value_for_index_zero"])

    for selector_index in range(returned_count):
        index_entry_va = index_table_base_va + selector_index
        entry: dict[str, object] = {
            "selector_index": selector_index,
            "selector_index_hex": _hex(selector_index),
            "index_entry_va": _hex(index_entry_va),
            "index_entry_rva": _hex(index_entry_va - metadata.image_base),
        }
        if selector_zero_value is not None:
            selector_value = selector_zero_value + selector_index
            entry["selector_value"] = selector_value
            entry["selector_value_hex"] = _hex(selector_value)

        try:
            index_offset = metadata.rva_to_offset(index_entry_va - metadata.image_base)
            remap_index = data[index_offset]
            target_entry_va = target_table_base_va + remap_index * 4
            target_entry_offset = metadata.rva_to_offset(target_entry_va - metadata.image_base)
            target_rva = struct.unpack_from("<I", data, target_entry_offset)[0]
        except (IndexError, ValueError, struct.error) as exc:
            message = f"{_hex(index_entry_va)}: failed to read remapped jump-table entry: {exc}"
            entry["error"] = message
            warnings.append(message)
            entries.append(entry)
            continue

        target_va = metadata.image_base + target_rva
        target_section, target_is_executable = _entry_section_payload(metadata, target_rva)
        entry.update(
            {
                "remap_index": remap_index,
                "remap_index_hex": _hex(remap_index),
                "target_table_entry_va": _hex(target_entry_va),
                "target_table_entry_rva": _hex(target_entry_va - metadata.image_base),
                "target_rva": _hex(target_rva),
                "target_va": _hex(target_va),
                "target_section": target_section,
                "target_is_executable": target_is_executable,
            }
        )
        entries.append(entry)

    if returned_count < index_count:
        warnings.append(f"Entry output truncated from {index_count} to {returned_count} rows.")
    return entries, warnings, returned_count


def _remapped_table_from_load(
    data: bytes,
    metadata: PEMetadata,
    instructions: list[dict[str, object]],
    index: int,
    *,
    index_table_base_va: int,
    target_table_base_va: int,
    explicit_index_count: int | None,
    max_backtrack_instructions: int,
    max_lookahead_instructions: int,
    include_entries: bool,
    max_entries_per_table: int,
) -> tuple[dict[str, object], list[str]] | None:
    remap_load = instructions[index]
    remap_register = _dest_register(remap_load)
    _, remap_source = _operands(remap_load)
    remap_memory = _parse_memory_operand(remap_source)
    if remap_load.get("mnemonic") != "MOVZX" or remap_register is None or remap_memory is None:
        return None
    if remap_memory.base is None or remap_memory.index is None or remap_memory.scale != 1:
        return None

    base_load = _find_recent_image_base_load(
        instructions,
        index,
        remap_memory.base,
        metadata.image_base,
        max_backtrack_instructions,
    )
    if base_load is None:
        return None
    if _memory_target_from_image_base(remap_memory, metadata.image_base) != index_table_base_va:
        return None

    target_load = _find_target_table_load(
        instructions,
        index,
        base_register=remap_memory.base,
        remap_register=remap_register,
        target_table_base_va=target_table_base_va,
        image_base=metadata.image_base,
        max_lookahead_instructions=max_lookahead_instructions,
    )
    if target_load is None:
        return None
    target_load_index, target_register, target_memory = target_load

    resolved_branch = _find_resolved_branch(
        instructions,
        target_load_index,
        base_register=remap_memory.base,
        target_register=target_register,
        max_lookahead_instructions=max_lookahead_instructions,
    )
    if resolved_branch is None:
        return None
    add_index, branch_index = resolved_branch

    selector_index_setup = _find_selector_index_setup(
        instructions,
        index,
        remap_memory.index,
        max_backtrack_instructions,
    )
    bound_registers = {remap_memory.index}
    if selector_index_setup is not None and "source_register" in selector_index_setup:
        bound_registers.add(str(selector_index_setup["source_register"]))
    bound_check = _find_bound_check(
        instructions,
        index,
        bound_registers,
        max_backtrack_instructions,
    )
    inferred_index_count = (
        int(bound_check["inferred_index_count"])
        if bound_check is not None and "inferred_index_count" in bound_check
        else None
    )
    index_count = explicit_index_count if explicit_index_count is not None else inferred_index_count or 256

    warnings: list[str] = []
    table: dict[str, object] = {
        "index_table_base_va": _hex(index_table_base_va),
        "index_table_base_rva": _hex(index_table_base_va - metadata.image_base),
        "target_table_base_va": _hex(target_table_base_va),
        "target_table_base_rva": _hex(target_table_base_va - metadata.image_base),
        "image_base_register": remap_memory.base,
        "image_base_load": _instruction_payload(base_load),
        "selector_index_register": remap_memory.index,
        "remap_register": remap_register,
        "target_register": target_register,
        "index_table_load": _instruction_payload(remap_load),
        "target_table_load": _instruction_payload(instructions[target_load_index]),
        "target_resolve_add": _instruction_payload(instructions[add_index]),
        "dispatch_branch": _instruction_payload(instructions[branch_index]),
        "dispatch_kind": instructions[branch_index]["mnemonic"],
        "index_count": index_count,
        "index_count_source": "explicit" if explicit_index_count is not None else "bound-check" if inferred_index_count else "default",
        "memory_model": {
            "index_load_displacement": _hex(remap_memory.displacement),
            "target_load_displacement": _hex(target_memory.displacement),
            "target_entry_scale": target_memory.scale,
        },
    }
    if selector_index_setup is not None:
        table["selector_index_setup"] = selector_index_setup
    if bound_check is not None:
        table["bound_check"] = bound_check

    if include_entries:
        entries, entry_warnings, returned_count = _read_remapped_entries(
            data,
            metadata,
            index_table_base_va=index_table_base_va,
            target_table_base_va=target_table_base_va,
            index_count=index_count,
            max_entries=max_entries_per_table,
            selector_index_setup=selector_index_setup,
        )
        warnings.extend(entry_warnings)
        table["entry_count"] = returned_count
        table["truncated_entry_count"] = max(0, index_count - returned_count)
        table["unique_remap_count"] = len({entry.get("remap_index") for entry in entries if "remap_index" in entry})
        table["unique_target_count"] = len({entry.get("target_va") for entry in entries if "target_va" in entry})
        table["entries"] = entries

    return table, warnings


def find_pe_remapped_jump_tables(
    path: str | Path,
    ranges: list[str],
    *,
    index_table_base: str | int,
    target_table_base: str | int,
    index_count: int | None = None,
    max_backtrack_instructions: int = 16,
    max_lookahead_instructions: int = 32,
    max_tables_per_range: int = 32,
    include_entries: bool = True,
    max_entries_per_table: int = 256,
) -> dict[str, object]:
    if index_count is not None and index_count <= 0:
        raise ValueError("Index count must be greater than zero.")
    if max_backtrack_instructions <= 0:
        raise ValueError("Max backtrack instruction count must be greater than zero.")
    if max_lookahead_instructions <= 0:
        raise ValueError("Max lookahead instruction count must be greater than zero.")
    if max_tables_per_range <= 0:
        raise ValueError("Max tables per range must be greater than zero.")
    if max_entries_per_table <= 0:
        raise ValueError("Max entries per table must be greater than zero.")

    target_path = Path(path)
    data = target_path.read_bytes()
    metadata = read_pe_metadata(data)
    runtime_functions = read_pe_runtime_functions(data, metadata)
    index_table_base_va = _normalize_address(index_table_base, metadata)
    target_table_base_va = _normalize_address(target_table_base, metadata)
    results: list[dict[str, object]] = []
    warnings: list[str] = []
    scanned_byte_count = 0
    decoded_instruction_count = 0

    for range_spec in ranges:
        start_va, end_va = _parse_function_spec(range_spec, metadata, runtime_functions)
        instructions, warning, scanned = _scan_range_instructions(
            data,
            metadata,
            runtime_functions,
            start_va=start_va,
            end_va=end_va,
        )
        scanned_byte_count += scanned
        decoded_instruction_count += len(instructions)
        if warning is not None:
            warnings.append(f"Range {range_spec!r} {warning}.")

        tables: list[dict[str, object]] = []
        hit_count = 0
        for index, instruction in enumerate(instructions):
            if instruction.get("mnemonic") != "MOVZX":
                continue
            table_result = _remapped_table_from_load(
                data,
                metadata,
                instructions,
                index,
                index_table_base_va=index_table_base_va,
                target_table_base_va=target_table_base_va,
                explicit_index_count=index_count,
                max_backtrack_instructions=max_backtrack_instructions,
                max_lookahead_instructions=max_lookahead_instructions,
                include_entries=include_entries,
                max_entries_per_table=max_entries_per_table,
            )
            if table_result is None:
                continue
            table, table_warnings = table_result
            hit_count += 1
            warnings.extend(table_warnings)
            if len(tables) < max_tables_per_range:
                tables.append(table)

        results.append(
            {
                "request": str(range_spec),
                "start_va": _hex(start_va),
                "start_rva": _hex(start_va - metadata.image_base),
                "end_va": _hex(end_va),
                "end_rva": _hex(end_va - metadata.image_base),
                "decoded_instruction_count": len(instructions),
                "table_hit_count": hit_count,
                "table_count": len(tables),
                "truncated_table_count": max(0, hit_count - len(tables)),
                "tables": tables,
            }
        )

    return {
        "type": "pe-remapped-jump-tables",
        "target": str(target_path),
        "image_base": _hex(metadata.image_base),
        "scan": {
            "range_count": len(ranges),
            "index_table_base_va": _hex(index_table_base_va),
            "index_table_base_rva": _hex(index_table_base_va - metadata.image_base),
            "target_table_base_va": _hex(target_table_base_va),
            "target_table_base_rva": _hex(target_table_base_va - metadata.image_base),
            "index_count": index_count,
            "max_backtrack_instructions": max_backtrack_instructions,
            "max_lookahead_instructions": max_lookahead_instructions,
            "max_tables_per_range": max_tables_per_range,
            "include_entries": include_entries,
            "max_entries_per_table": max_entries_per_table,
            "runtime_function_count": len(runtime_functions),
            "decoded_instruction_count": decoded_instruction_count,
            "scanned_byte_count": scanned_byte_count,
        },
        "ranges": results,
        "warnings": warnings,
    }
