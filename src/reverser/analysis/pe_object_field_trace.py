from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from reverser.analysis.pe_direct_calls import parse_int_literal, read_pe_metadata
from reverser.analysis.pe_field_refs import find_pe_field_refs
from reverser.analysis.pe_indirect_dispatches import (
    _normalize_register,
    _parse_memory_operand,
    _split_operands,
)
from reverser.analysis.pe_instructions import WindowSpec, _scan_window
from reverser.analysis.pe_runtime_functions import read_pe_runtime_functions


def _hex(value: int) -> str:
    return f"0x{value:x}"


_STACK_REGISTERS = {"RSP", "ESP", "SP", "RBP", "EBP", "BP"}
_VOLATILE_REGISTERS = {"RAX", "RCX", "RDX", "R8", "R9", "R10", "R11"}
_REGISTER_WRITE_MNEMONICS = {
    "ADD",
    "ADC",
    "AND",
    "IMUL",
    "LEA",
    "MOV",
    "MOVSX",
    "MOVSXD",
    "MOVZX",
    "OR",
    "SBB",
    "SUB",
    "XOR",
}


@dataclass(frozen=True)
class _Taint:
    path: tuple[int, ...]
    root_source_va: str
    root_source_instruction: str

    def to_payload(self) -> dict[str, object]:
        return {
            "path": [_hex(offset) for offset in self.path],
            "root_source_va": self.root_source_va,
            "root_source_instruction": self.root_source_instruction,
        }


def _normalize_offsets(values: list[str | int]) -> list[int]:
    normalized: list[int] = []
    seen: set[int] = set()
    for value in values:
        offset = parse_int_literal(str(value))
        if offset in seen:
            continue
        seen.add(offset)
        normalized.append(offset)
    return normalized


def _memory_parts(operand: str) -> dict[str, object] | None:
    memory = _parse_memory_operand(operand)
    if memory is None:
        return None
    if memory.get("memory_kind") not in {"base", "base-displacement"}:
        return None
    base_register = _normalize_register(memory.get("base_register"))
    if base_register is None:
        return None
    return {
        "operand": memory.get("operand"),
        "base_register": base_register,
        "displacement": int(memory.get("displacement") or 0),
        "displacement_hex": memory.get("displacement_hex") or "0x0",
    }


def _access_kind(mnemonic: str, operand_index: int) -> str:
    if mnemonic == "LEA":
        return "address"
    if operand_index == 0 and mnemonic not in {"CMP", "TEST"}:
        return "write"
    return "read"


def _root_taint_for_instruction(
    instruction: dict[str, object],
    operands: list[str],
    *,
    root_offset: int,
    exclude_stack: bool,
) -> tuple[str, _Taint] | None:
    mnemonic = str(instruction.get("mnemonic") or "").upper()
    if mnemonic != "MOV" or len(operands) < 2:
        return None

    destination = _normalize_register(operands[0])
    if destination is None:
        return None

    memory = _memory_parts(operands[1])
    if memory is None or int(memory["displacement"]) != root_offset:
        return None
    if exclude_stack and str(memory["base_register"]) in _STACK_REGISTERS:
        return None

    return destination, _Taint(
        path=(root_offset,),
        root_source_va=str(instruction.get("address_va")),
        root_source_instruction=str(instruction.get("instruction")),
    )


def _follow_taint_for_instruction(
    instruction: dict[str, object],
    operands: list[str],
    taints: dict[str, _Taint],
    *,
    follow_offsets: set[int],
) -> tuple[str, _Taint] | None:
    mnemonic = str(instruction.get("mnemonic") or "").upper()
    if mnemonic not in {"MOV", "LEA"} or len(operands) < 2:
        return None

    destination = _normalize_register(operands[0])
    if destination is None:
        return None

    memory = _memory_parts(operands[1])
    if memory is None:
        return None
    displacement = int(memory["displacement"])
    if displacement not in follow_offsets:
        return None

    base_taint = taints.get(str(memory["base_register"]))
    if base_taint is None:
        return None
    return destination, _Taint(
        path=base_taint.path + (displacement,),
        root_source_va=base_taint.root_source_va,
        root_source_instruction=base_taint.root_source_instruction,
    )


def _register_copy_taint(operands: list[str], taints: dict[str, _Taint]) -> tuple[str, _Taint] | None:
    if len(operands) < 2:
        return None
    destination = _normalize_register(operands[0])
    source = _normalize_register(operands[1])
    if destination is None or source is None or source not in taints:
        return None
    return destination, taints[source]


def _target_events_for_instruction(
    instruction: dict[str, object],
    operands: list[str],
    taints: dict[str, _Taint],
    *,
    target_offsets: set[int],
) -> list[dict[str, object]]:
    mnemonic = str(instruction.get("mnemonic") or "").upper()
    events: list[dict[str, object]] = []
    for operand_index, operand in enumerate(operands):
        memory = _memory_parts(operand)
        if memory is None:
            continue
        displacement = int(memory["displacement"])
        if displacement not in target_offsets:
            continue
        base_register = str(memory["base_register"])
        taint = taints.get(base_register)
        if taint is None:
            continue
        events.append(
            {
                "event_va": instruction.get("address_va"),
                "event_rva": instruction.get("address_rva"),
                "instruction": instruction.get("instruction"),
                "mnemonic": instruction.get("mnemonic"),
                "operands": instruction.get("operands"),
                "access": _access_kind(mnemonic, operand_index),
                "memory_operand": memory["operand"],
                "base_register": base_register,
                "target_offset": _hex(displacement),
                "taint": taint.to_payload(),
            }
        )
    return events


def _destination_register(operands: list[str]) -> str | None:
    if not operands:
        return None
    return _normalize_register(operands[0])


def _trace_function_events(
    instructions: list[dict[str, object]],
    *,
    root_offset: int,
    follow_offsets: set[int],
    target_offsets: set[int],
    exclude_stack: bool,
    max_events: int,
) -> tuple[list[dict[str, object]], int]:
    taints: dict[str, _Taint] = {}
    events: list[dict[str, object]] = []
    event_count = 0

    for instruction in instructions:
        mnemonic = str(instruction.get("mnemonic") or "").upper()
        operands = _split_operands(instruction.get("operands"))

        instruction_events = _target_events_for_instruction(
            instruction,
            operands,
            taints,
            target_offsets=target_offsets,
        )
        event_count += len(instruction_events)
        remaining = max(0, max_events - len(events))
        if remaining:
            events.extend(instruction_events[:remaining])

        new_taint = (
            _root_taint_for_instruction(
                instruction,
                operands,
                root_offset=root_offset,
                exclude_stack=exclude_stack,
            )
            or _follow_taint_for_instruction(
                instruction,
                operands,
                taints,
                follow_offsets=follow_offsets,
            )
            or (_register_copy_taint(operands, taints) if mnemonic == "MOV" else None)
        )
        if new_taint is not None:
            taints[new_taint[0]] = new_taint[1]
        else:
            destination = _destination_register(operands)
            if destination is not None and mnemonic in _REGISTER_WRITE_MNEMONICS:
                taints.pop(destination, None)

        if mnemonic == "CALL":
            for register in _VOLATILE_REGISTERS:
                taints.pop(register, None)

    return events, event_count


def _root_functions(root_refs: dict[str, object], max_functions: int) -> tuple[list[dict[str, object]], list[str]]:
    warnings: list[str] = []
    by_start: dict[str, dict[str, object]] = {}
    skipped_without_function = 0
    results = root_refs.get("results")
    if not isinstance(results, list) or not results:
        return [], ["Root field-reference scan returned no result rows."]

    hits = results[0].get("hits") if isinstance(results[0], dict) else None
    if not isinstance(hits, list):
        return [], ["Root field-reference scan returned no hits array."]

    for hit in hits:
        if not isinstance(hit, dict):
            continue
        function = hit.get("function")
        if not isinstance(function, dict):
            skipped_without_function += 1
            continue
        start_va = str(function.get("start_va"))
        existing = by_start.setdefault(
            start_va,
            {
                "start_va": start_va,
                "end_va": function.get("end_va"),
                "root_hits": [],
            },
        )
        existing["root_hits"].append(
            {
                "reference_va": hit.get("reference_va"),
                "instruction": hit.get("instruction"),
                "memory_operand": hit.get("memory_operand"),
                "base_register": hit.get("base_register"),
            }
        )

    functions = sorted(by_start.values(), key=lambda item: parse_int_literal(str(item["start_va"])))
    if skipped_without_function:
        warnings.append(f"Skipped {skipped_without_function} root hits without .pdata function attribution.")
    if len(functions) > max_functions:
        warnings.append(f"Truncated root-function scan from {len(functions)} to {max_functions} functions.")
    return functions[:max_functions], warnings


def find_pe_object_field_trace(
    path: str | Path,
    *,
    root_offset: str | int,
    follow_offsets: list[str | int],
    target_offsets: list[str | int],
    max_root_hits: int = 512,
    max_functions: int = 256,
    max_events_per_function: int = 128,
    exclude_stack: bool = True,
) -> dict[str, object]:
    target = Path(path)
    data = target.read_bytes()
    metadata = read_pe_metadata(data)
    runtime_functions = read_pe_runtime_functions(data, metadata)

    normalized_root_offset = parse_int_literal(str(root_offset))
    normalized_follow_offsets = _normalize_offsets(follow_offsets)
    normalized_target_offsets = _normalize_offsets(target_offsets)
    root_refs = find_pe_field_refs(
        target,
        [normalized_root_offset],
        max_hits_per_offset=max_root_hits,
        exclude_stack=exclude_stack,
    )
    functions, warnings = _root_functions(root_refs, max_functions)

    traced_functions: list[dict[str, object]] = []
    scanned_instruction_count = 0
    event_function_count = 0
    total_event_count = 0

    for function in functions:
        start_va = parse_int_literal(str(function["start_va"]))
        end_va = parse_int_literal(str(function["end_va"]))
        window, warning = _scan_window(
            data,
            metadata,
            runtime_functions,
            WindowSpec(request=f"{function['start_va']}..{function['end_va']}", start_va=start_va, end_va=end_va),
        )
        if warning is not None:
            warnings.append(warning)
        instructions = window.get("instructions", [])
        if not isinstance(instructions, list):
            instructions = []
        scanned_instruction_count += len(instructions)
        events, event_count = _trace_function_events(
            instructions,
            root_offset=normalized_root_offset,
            follow_offsets=set(normalized_follow_offsets),
            target_offsets=set(normalized_target_offsets),
            exclude_stack=exclude_stack,
            max_events=max_events_per_function,
        )
        if event_count:
            event_function_count += 1
            total_event_count += event_count
            traced_functions.append(
                {
                    "start_va": function["start_va"],
                    "end_va": function["end_va"],
                    "root_hits": function["root_hits"],
                    "event_count": event_count,
                    "returned_event_count": len(events),
                    "truncated_event_count": max(0, event_count - len(events)),
                    "events": events,
                }
            )

    root_result = root_refs["results"][0] if root_refs.get("results") else {}
    return {
        "type": "pe-object-field-trace",
        "target": str(target),
        "image_base": _hex(metadata.image_base),
        "scan": {
            "root_offset": _hex(normalized_root_offset),
            "follow_offsets": [_hex(offset) for offset in normalized_follow_offsets],
            "target_offsets": [_hex(offset) for offset in normalized_target_offsets],
            "exclude_stack": exclude_stack,
            "max_root_hits": max_root_hits,
            "max_functions": max_functions,
            "max_events_per_function": max_events_per_function,
            "root_hit_count": root_result.get("hit_count", 0),
            "returned_root_hit_count": root_result.get("returned_hit_count", 0),
            "root_function_count": len(functions),
            "event_function_count": event_function_count,
            "event_count": total_event_count,
            "scanned_instruction_count": scanned_instruction_count,
            "runtime_function_count": len(runtime_functions),
        },
        "functions": traced_functions,
        "warnings": warnings,
    }
