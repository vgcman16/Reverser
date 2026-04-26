from __future__ import annotations

from pathlib import Path

from reverser.analysis.pe_direct_calls import parse_int_literal, read_pe_metadata
from reverser.analysis.pe_function_calls import _parse_function_spec
from reverser.analysis.pe_registration_records import (
    _memory_target_va,
    _normalize_address,
    _scan_range_instructions,
)
from reverser.analysis.pe_runtime_functions import read_pe_runtime_functions


def _hex(value: int) -> str:
    return f"0x{value:x}"


_REGISTER_ALIASES = {
    "EAX": "RAX",
    "AX": "RAX",
    "AL": "RAX",
    "ECX": "RCX",
    "CX": "RCX",
    "CL": "RCX",
    "EDX": "RDX",
    "DX": "RDX",
    "DL": "RDX",
    "EBX": "RBX",
    "BX": "RBX",
    "BL": "RBX",
    "ESP": "RSP",
    "SP": "RSP",
    "SPL": "RSP",
    "EBP": "RBP",
    "BP": "RBP",
    "BPL": "RBP",
    "ESI": "RSI",
    "SI": "RSI",
    "SIL": "RSI",
    "EDI": "RDI",
    "DI": "RDI",
    "DIL": "RDI",
}

for _index in range(8, 16):
    _REGISTER_ALIASES[f"R{_index}D"] = f"R{_index}"
    _REGISTER_ALIASES[f"R{_index}W"] = f"R{_index}"
    _REGISTER_ALIASES[f"R{_index}B"] = f"R{_index}"


def _register_name(value: str) -> str:
    value = value.strip().upper()
    return _REGISTER_ALIASES.get(value, value)


def _operands(instruction: dict[str, object]) -> tuple[str, str | None]:
    raw = str(instruction.get("operands", ""))
    if "," not in raw:
        return raw.strip(), None
    left, right = raw.split(",", 1)
    return left.strip(), right.strip()


def _dest_register(instruction: dict[str, object]) -> str | None:
    left, _ = _operands(instruction)
    if not left or left.startswith("["):
        return None
    return _register_name(left)


def _is_register_source(instruction: dict[str, object], register: str) -> bool:
    _, right = _operands(instruction)
    return right is not None and _register_name(right) == register


def _find_selector_shift(
    instructions: list[dict[str, object]],
    start_index: int,
    selector_register: str,
    max_distance: int,
) -> int | None:
    limit = min(len(instructions), start_index + 1 + max_distance)
    for index in range(start_index + 1, limit):
        instruction = instructions[index]
        left, right = _operands(instruction)
        if (
            instruction.get("mnemonic") == "SHL"
            and _register_name(left) == selector_register
            and str(right).lower() == "0x4"
        ):
            return index
    return None


def _find_slot_add(
    instructions: list[dict[str, object]],
    start_index: int,
    selector_register: str,
    table_register: str,
    max_distance: int,
) -> int | None:
    limit = min(len(instructions), start_index + 1 + max_distance)
    for index in range(start_index + 1, limit):
        instruction = instructions[index]
        left, right = _operands(instruction)
        if (
            instruction.get("mnemonic") == "ADD"
            and _register_name(left) == selector_register
            and right is not None
            and _register_name(right) == table_register
        ):
            return index
    return None


def _find_slot_store(
    instructions: list[dict[str, object]],
    start_index: int,
    selector_register: str,
    max_distance: int,
) -> tuple[int, str] | None:
    limit = min(len(instructions), start_index + 1 + max_distance)
    for index in range(start_index + 1, limit):
        instruction = instructions[index]
        left, right = _operands(instruction)
        if (
            instruction.get("mnemonic") == "MOV"
            and left.startswith("[")
            and right is not None
            and _register_name(right) == selector_register
        ):
            return index, left
    return None


def _find_slot_reload(
    instructions: list[dict[str, object]],
    start_index: int,
    slot_operand: str,
    max_distance: int,
) -> tuple[int, str] | None:
    limit = min(len(instructions), start_index + 1 + max_distance)
    for index in range(start_index + 1, limit):
        instruction = instructions[index]
        if instruction.get("mnemonic") != "MOV":
            continue
        left, right = _operands(instruction)
        if right == slot_operand and not left.startswith("["):
            return index, _register_name(left)
    return None


def _find_handler_load(
    instructions: list[dict[str, object]],
    start_index: int,
    slot_register: str,
    max_distance: int,
) -> tuple[int, str] | None:
    limit = min(len(instructions), start_index + 1 + max_distance)
    for index in range(start_index + 1, limit):
        instruction = instructions[index]
        if instruction.get("mnemonic") != "MOV":
            continue
        left, right = _operands(instruction)
        left_register = _register_name(left)
        if left_register and right == f"[{slot_register}]":
            return index, left_register
    return None


def _find_handler_call(
    instructions: list[dict[str, object]],
    start_index: int,
    handler_register: str,
    max_distance: int,
) -> int | None:
    limit = min(len(instructions), start_index + 1 + max_distance)
    for index in range(start_index + 1, limit):
        instruction = instructions[index]
        left, _ = _operands(instruction)
        if instruction.get("mnemonic") == "CALL" and _register_name(left) == handler_register:
            return index
    return None


def _argument_setup(
    instructions: list[dict[str, object]],
    start_index: int,
    end_index: int,
) -> list[dict[str, object]]:
    arg_registers = {"RCX", "RDX", "R8", "R9"}
    setup: list[dict[str, object]] = []
    for instruction in instructions[start_index:end_index]:
        destination = _dest_register(instruction)
        if destination in arg_registers:
            setup.append(
                {
                    "address_va": instruction["address_va"],
                    "address_rva": instruction["address_rva"],
                    "register": destination,
                    "instruction": instruction["instruction"],
                }
            )
    return setup


def _slot_checks(
    instructions: list[dict[str, object]],
    start_index: int,
    end_index: int,
    slot_register: str,
) -> list[dict[str, object]]:
    checks: list[dict[str, object]] = []
    marker = f"[{slot_register}+0x8]"
    for instruction in instructions[start_index:end_index]:
        if instruction.get("mnemonic") != "CMP":
            continue
        if marker not in str(instruction.get("operands", "")):
            continue
        checks.append(
            {
                "address_va": instruction["address_va"],
                "address_rva": instruction["address_rva"],
                "instruction": instruction["instruction"],
            }
        )
    return checks


def _dispatch_from_table_ref(
    instructions: list[dict[str, object]],
    index: int,
    *,
    table_base_va: int,
    image_base: int,
    max_lookahead_instructions: int,
) -> dict[str, object] | None:
    table_ref = instructions[index]
    table_register = _dest_register(table_ref)
    if table_register is None:
        return None

    limit = min(len(instructions), index + 1 + max_lookahead_instructions)
    for selector_index in range(index + 1, limit):
        selector_load = instructions[selector_index]
        if selector_load.get("mnemonic") != "MOVZX":
            continue
        selector_register = _dest_register(selector_load)
        if selector_register is None:
            continue
        shift_index = _find_selector_shift(instructions, selector_index, selector_register, 8)
        if shift_index is None:
            continue
        add_index = _find_slot_add(instructions, shift_index, selector_register, table_register, 8)
        if add_index is None:
            continue
        store = _find_slot_store(instructions, add_index, selector_register, 12)
        if store is None:
            continue
        store_index, slot_operand = store
        reload = _find_slot_reload(instructions, store_index, slot_operand, 48)
        if reload is None:
            continue
        reload_index, slot_register = reload
        handler_load = _find_handler_load(instructions, reload_index, slot_register, 24)
        if handler_load is None:
            continue
        handler_load_index, handler_register = handler_load
        call_index = _find_handler_call(instructions, handler_load_index, handler_register, 12)
        if call_index is None:
            continue

        return {
            "table_base_va": _hex(table_base_va),
            "table_base_rva": _hex(table_base_va - image_base),
            "table_register": table_register,
            "table_ref_va": table_ref["address_va"],
            "table_ref_rva": table_ref["address_rva"],
            "selector_load_va": selector_load["address_va"],
            "selector_load_rva": selector_load["address_rva"],
            "selector_load_instruction": selector_load["instruction"],
            "selector_register": selector_register,
            "slot_stride": 16,
            "slot_shift_va": instructions[shift_index]["address_va"],
            "slot_add_va": instructions[add_index]["address_va"],
            "slot_register": selector_register,
            "slot_store_va": instructions[store_index]["address_va"],
            "slot_store_instruction": instructions[store_index]["instruction"],
            "slot_operand": slot_operand,
            "slot_reload_va": instructions[reload_index]["address_va"],
            "slot_reload_instruction": instructions[reload_index]["instruction"],
            "handler_load_va": instructions[handler_load_index]["address_va"],
            "handler_load_instruction": instructions[handler_load_index]["instruction"],
            "handler_register": handler_register,
            "dispatch_call_va": instructions[call_index]["address_va"],
            "dispatch_call_rva": instructions[call_index]["address_rva"],
            "dispatch_call_instruction": instructions[call_index]["instruction"],
            "argument_setup": _argument_setup(instructions, handler_load_index + 1, call_index),
            "slot_checks": _slot_checks(instructions, add_index + 1, handler_load_index, slot_register),
        }
    return None


def find_pe_selector_table_dispatches(
    path: str | Path,
    ranges: list[str],
    *,
    table_base: str | int,
    max_lookahead_instructions: int = 96,
    max_dispatches_per_range: int = 64,
) -> dict[str, object]:
    if max_lookahead_instructions <= 0:
        raise ValueError("Max lookahead instruction count must be greater than zero.")
    if max_dispatches_per_range <= 0:
        raise ValueError("Max dispatches per range must be greater than zero.")

    target_path = Path(path)
    data = target_path.read_bytes()
    metadata = read_pe_metadata(data)
    runtime_functions = read_pe_runtime_functions(data, metadata)
    table_base_va = _normalize_address(table_base, metadata)
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

        dispatches: list[dict[str, object]] = []
        hit_count = 0
        for index, instruction in enumerate(instructions):
            if _memory_target_va(instruction) != table_base_va:
                continue
            dispatch = _dispatch_from_table_ref(
                instructions,
                index,
                table_base_va=table_base_va,
                image_base=metadata.image_base,
                max_lookahead_instructions=max_lookahead_instructions,
            )
            if dispatch is None:
                continue
            hit_count += 1
            if len(dispatches) < max_dispatches_per_range:
                dispatches.append(dispatch)

        results.append(
            {
                "request": str(range_spec),
                "start_va": _hex(start_va),
                "start_rva": _hex(start_va - metadata.image_base),
                "end_va": _hex(end_va),
                "end_rva": _hex(end_va - metadata.image_base),
                "decoded_instruction_count": len(instructions),
                "dispatch_hit_count": hit_count,
                "dispatch_count": len(dispatches),
                "truncated_dispatch_count": max(0, hit_count - len(dispatches)),
                "dispatches": dispatches,
            }
        )

    return {
        "type": "pe-selector-table-dispatches",
        "target": str(target_path),
        "image_base": _hex(metadata.image_base),
        "scan": {
            "range_count": len(ranges),
            "table_base_va": _hex(table_base_va),
            "table_base_rva": _hex(table_base_va - metadata.image_base),
            "max_lookahead_instructions": max_lookahead_instructions,
            "max_dispatches_per_range": max_dispatches_per_range,
            "runtime_function_count": len(runtime_functions),
            "decoded_instruction_count": decoded_instruction_count,
            "scanned_byte_count": scanned_byte_count,
        },
        "ranges": results,
        "warnings": warnings,
    }
