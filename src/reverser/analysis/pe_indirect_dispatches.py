from __future__ import annotations

import re
from pathlib import Path

from reverser.analysis.pe_direct_calls import parse_int_literal, read_pe_metadata
from reverser.analysis.pe_function_calls import _parse_function_spec, find_pe_function_calls
from reverser.analysis.pe_instructions import find_pe_instructions
from reverser.analysis.pe_runtime_functions import read_pe_runtime_functions


def _hex(value: int) -> str:
    return f"0x{value:x}"


_REGISTER_ALIASES = {
    "AL": "RAX",
    "AX": "RAX",
    "EAX": "RAX",
    "RAX": "RAX",
    "CL": "RCX",
    "CX": "RCX",
    "ECX": "RCX",
    "RCX": "RCX",
    "DL": "RDX",
    "DX": "RDX",
    "EDX": "RDX",
    "RDX": "RDX",
    "BL": "RBX",
    "BX": "RBX",
    "EBX": "RBX",
    "RBX": "RBX",
    "SPL": "RSP",
    "SP": "RSP",
    "ESP": "RSP",
    "RSP": "RSP",
    "BPL": "RBP",
    "BP": "RBP",
    "EBP": "RBP",
    "RBP": "RBP",
    "SIL": "RSI",
    "SI": "RSI",
    "ESI": "RSI",
    "RSI": "RSI",
    "DIL": "RDI",
    "DI": "RDI",
    "EDI": "RDI",
    "RDI": "RDI",
}

for _index in range(8, 16):
    _REGISTER_ALIASES[f"R{_index}B"] = f"R{_index}"
    _REGISTER_ALIASES[f"R{_index}W"] = f"R{_index}"
    _REGISTER_ALIASES[f"R{_index}D"] = f"R{_index}"
    _REGISTER_ALIASES[f"R{_index}"] = f"R{_index}"


_MEMORY_RE = re.compile(
    r"^(?:(?P<segment>[A-Z]+):)?\[(?P<body>[^\]]+)\]$",
    re.IGNORECASE,
)
_BASE_DISP_RE = re.compile(
    r"^(?P<base>[A-Z][A-Z0-9]*)(?P<sign>[+-])0x(?P<disp>[0-9a-f]+)$",
    re.IGNORECASE,
)
_ABS_RE = re.compile(r"^0x[0-9a-f]+$", re.IGNORECASE)


def _normalize_register(value: object) -> str | None:
    register = str(value).strip().upper()
    return _REGISTER_ALIASES.get(register)


def _split_operands(value: object) -> list[str]:
    operands = str(value or "")
    if not operands:
        return []
    return [part.strip() for part in operands.split(",")]


def _parse_memory_operand(value: str) -> dict[str, object] | None:
    raw_value = value.strip()
    match = _MEMORY_RE.match(raw_value)
    if match is None:
        return None

    body = match.group("body").strip().upper()
    segment = match.group("segment")
    payload: dict[str, object] = {
        "kind": "memory",
        "operand": raw_value,
    }
    if segment:
        payload["segment"] = segment.upper()

    if _ABS_RE.match(body):
        absolute_va = parse_int_literal(body)
        payload.update(
            {
                "memory_kind": "absolute",
                "absolute_va": _hex(absolute_va),
            }
        )
        return payload

    base = _normalize_register(body)
    if base is not None:
        payload.update(
            {
                "memory_kind": "base",
                "base_register": base,
                "displacement": 0,
                "displacement_hex": "0x0",
            }
        )
        return payload

    base_disp = _BASE_DISP_RE.match(body)
    if base_disp is not None:
        base_register = _normalize_register(base_disp.group("base"))
        if base_register is not None:
            displacement = parse_int_literal(f"0x{base_disp.group('disp')}")
            if base_disp.group("sign") == "-":
                displacement = -displacement
            payload.update(
                {
                    "memory_kind": "base-displacement",
                    "base_register": base_register,
                    "displacement": displacement,
                    "displacement_hex": _hex(displacement) if displacement >= 0 else f"-{_hex(-displacement)}",
                }
            )
            return payload

    payload.update(
        {
            "memory_kind": "complex",
            "expression": body,
        }
    )
    return payload


def _source_payload(
    instruction: dict[str, object],
    source_operand: str,
    *,
    depth: int,
) -> dict[str, object]:
    source_register = _normalize_register(source_operand)
    if source_register is not None:
        return {
            "kind": "register-copy",
            "register": source_register,
            "depth": depth,
        }

    memory = _parse_memory_operand(source_operand)
    if memory is not None:
        return {
            "kind": "memory-load",
            "memory": memory,
            "depth": depth,
        }

    if source_operand.lower().startswith("0x"):
        try:
            return {
                "kind": "immediate",
                "value": _hex(parse_int_literal(source_operand)),
                "depth": depth,
            }
        except ValueError:
            pass

    return {
        "kind": "expression",
        "expression": source_operand,
        "depth": depth,
        "instruction": instruction.get("instruction"),
    }


def _instruction_assignment_for(
    instruction: dict[str, object],
    register: str,
) -> tuple[str, str] | None:
    mnemonic = str(instruction.get("mnemonic") or "").upper()
    if mnemonic not in {"MOV", "LEA", "MOVZX", "MOVSXD"}:
        return None

    operands = _split_operands(instruction.get("operands"))
    if len(operands) < 2:
        return None

    destination = _normalize_register(operands[0])
    if destination != register:
        return None
    return mnemonic, operands[1]


def _resolve_register_origin(
    instructions: list[dict[str, object]],
    call_index: int,
    register: str,
    *,
    max_backtrack_instructions: int,
    depth: int = 0,
    seen: frozenset[str] = frozenset(),
) -> dict[str, object]:
    if depth > 3 or register in seen:
        return {
            "kind": "unresolved",
            "reason": "copy-depth-limit",
            "register": register,
            "depth": depth,
        }

    lower_bound = max(0, call_index - max_backtrack_instructions)
    for index in range(call_index - 1, lower_bound - 1, -1):
        instruction = instructions[index]
        assignment = _instruction_assignment_for(instruction, register)
        if assignment is None:
            continue

        mnemonic, source_operand = assignment
        payload = _source_payload(instruction, source_operand, depth=depth)
        payload.update(
            {
                "register": register,
                "assignment_mnemonic": mnemonic,
                "assignment_va": instruction.get("address_va"),
                "assignment_instruction": instruction.get("instruction"),
            }
        )
        if payload["kind"] == "memory-load":
            memory = payload.get("memory")
            if isinstance(memory, dict):
                base_register = _normalize_register(memory.get("base_register"))
                if base_register is not None and base_register != register:
                    payload["base_register_origin"] = _resolve_register_origin(
                        instructions,
                        index,
                        base_register,
                        max_backtrack_instructions=max_backtrack_instructions,
                        depth=depth + 1,
                        seen=seen | {register},
                    )
        if payload["kind"] == "register-copy":
            source_register = str(payload["register"])
            payload["resolved_origin"] = _resolve_register_origin(
                instructions,
                index,
                source_register,
                max_backtrack_instructions=max_backtrack_instructions,
                depth=depth + 1,
                seen=seen | {register},
            )
            payload["register"] = register
            payload["source_register"] = source_register
        return payload

    return {
        "kind": "unresolved",
        "reason": "no-static-register-assignment",
        "register": register,
        "depth": depth,
        "searched_instruction_count": call_index - lower_bound,
    }


def _call_index_by_va(instructions: list[dict[str, object]]) -> dict[str, int]:
    return {
        str(instruction.get("address_va")): index
        for index, instruction in enumerate(instructions)
        if instruction.get("address_va") is not None
    }


def _flatten_origin_chain(origin: dict[str, object]) -> list[dict[str, object]]:
    chain: list[dict[str, object]] = []

    def append_origin(node: dict[str, object]) -> None:
        step = {
            "kind": node.get("kind"),
            "register": node.get("register"),
            "depth": node.get("depth"),
            "assignment_va": node.get("assignment_va"),
            "assignment_mnemonic": node.get("assignment_mnemonic"),
            "assignment_instruction": node.get("assignment_instruction"),
        }
        for key in (
            "memory",
            "source_register",
            "value",
            "expression",
            "reason",
            "memory_va",
            "resolved_pointer_va",
            "import",
        ):
            if key in node:
                step[key] = node[key]
        chain.append({key: value for key, value in step.items() if value is not None})

        next_origin = node.get("resolved_origin") or node.get("base_register_origin")
        if isinstance(next_origin, dict):
            append_origin(next_origin)

    append_origin(origin)
    return chain


def _tail_dispatch_from_instruction(instruction: dict[str, object]) -> dict[str, object] | None:
    mnemonic = str(instruction.get("mnemonic") or "").upper()
    if mnemonic != "JMP":
        return None

    operands = _split_operands(instruction.get("operands"))
    if len(operands) != 1:
        return None

    operand = operands[0]
    register = _normalize_register(operand)
    if register is not None:
        return {
            "callsite_va": instruction.get("address_va"),
            "callsite_rva": instruction.get("address_rva"),
            "kind": "indirect-register",
            "instruction": instruction.get("instruction"),
            "raw_bytes": instruction.get("raw_bytes"),
            "register": register,
            "control_transfer": "tail-jump",
            "instruction_record": instruction,
        }

    memory = _parse_memory_operand(operand.removeprefix("qword ptr ").strip())
    if memory is None:
        return None
    memory_kind = memory.get("memory_kind")
    if memory_kind not in {"base", "base-displacement"}:
        return None

    return {
        "callsite_va": instruction.get("address_va"),
        "callsite_rva": instruction.get("address_rva"),
        "kind": "indirect-memory",
        "instruction": instruction.get("instruction"),
        "raw_bytes": instruction.get("raw_bytes"),
        "base_register": memory.get("base_register"),
        "displacement": memory.get("displacement"),
        "control_transfer": "tail-jump",
        "instruction_record": instruction,
    }


def _dispatch_payload_for_call(
    call: dict[str, object],
    instructions: list[dict[str, object]],
    call_index: int,
    *,
    max_backtrack_instructions: int,
) -> dict[str, object] | None:
    kind = str(call.get("kind") or "")
    if not kind.startswith("indirect-"):
        return None

    origin_register: str | None = None
    dispatch_slot_displacement: int | None = None
    if kind == "indirect-memory":
        origin_register = _normalize_register(call.get("base_register"))
        displacement = call.get("displacement")
        if isinstance(displacement, int):
            dispatch_slot_displacement = displacement
    elif kind == "indirect-register":
        origin_register = _normalize_register(call.get("register"))
        dispatch_slot_displacement = 0
    elif kind == "indirect-rip-memory":
        origin = {
            "kind": "rip-memory-pointer",
            "memory_va": call.get("memory_va"),
            "resolved_pointer_va": call.get("resolved_pointer_va"),
            "import": call.get("import"),
        }
        return {
            "callsite_va": call.get("callsite_va"),
            "callsite_rva": call.get("callsite_rva"),
            "kind": kind,
            "instruction": call.get("instruction"),
            "raw_bytes": call.get("raw_bytes"),
            "control_transfer": call.get("control_transfer", "call"),
            "origin": origin,
            "origin_chain": _flatten_origin_chain(origin),
            "call": call,
        }

    if origin_register is None:
        origin = {
            "kind": "unresolved",
            "reason": "no-origin-register",
        }
        return {
            "callsite_va": call.get("callsite_va"),
            "callsite_rva": call.get("callsite_rva"),
            "kind": kind,
            "instruction": call.get("instruction"),
            "raw_bytes": call.get("raw_bytes"),
            "control_transfer": call.get("control_transfer", "call"),
            "origin": origin,
            "origin_chain": _flatten_origin_chain(origin),
            "call": call,
        }

    origin = _resolve_register_origin(
        instructions,
        call_index,
        origin_register,
        max_backtrack_instructions=max_backtrack_instructions,
    )
    payload: dict[str, object] = {
        "callsite_va": call.get("callsite_va"),
        "callsite_rva": call.get("callsite_rva"),
        "kind": kind,
        "instruction": call.get("instruction"),
        "raw_bytes": call.get("raw_bytes"),
        "control_transfer": call.get("control_transfer", "call"),
        "origin_register": origin_register,
        "origin": origin,
        "origin_chain": _flatten_origin_chain(origin),
        "call": call,
    }
    if dispatch_slot_displacement is not None:
        payload["dispatch_slot_displacement"] = dispatch_slot_displacement
        payload["dispatch_slot_displacement_hex"] = (
            _hex(dispatch_slot_displacement)
            if dispatch_slot_displacement >= 0
            else f"-{_hex(-dispatch_slot_displacement)}"
        )
    return payload


def find_pe_indirect_dispatches(
    path: str | Path,
    functions: list[str],
    *,
    max_backtrack_instructions: int = 20,
    max_dispatches_per_function: int = 128,
) -> dict[str, object]:
    if max_backtrack_instructions <= 0:
        raise ValueError("Max backtrack instructions must be greater than zero.")
    if max_dispatches_per_function <= 0:
        raise ValueError("Max dispatches per function must be greater than zero.")

    target_path = Path(path)
    data = target_path.read_bytes()
    metadata = read_pe_metadata(data)
    runtime_functions = read_pe_runtime_functions(data, metadata)
    normalized_functions: list[str] = []
    for function_spec in functions:
        start_va, end_va = _parse_function_spec(function_spec, metadata, runtime_functions)
        normalized_functions.append(f"{_hex(start_va)}..{_hex(end_va)}")

    calls_payload = find_pe_function_calls(
        target_path,
        normalized_functions,
        max_calls_per_function=max(max_dispatches_per_function * 4, 128),
    )
    instructions_payload = find_pe_instructions(target_path, normalized_functions)
    instruction_windows = {
        str(window.get("request")): list(window.get("instructions") or [])
        for window in instructions_payload.get("windows", [])
    }

    results: list[dict[str, object]] = []
    dispatch_hit_count = 0
    warnings = list(calls_payload.get("warnings", [])) + list(instructions_payload.get("warnings", []))
    for function in calls_payload.get("functions", []):
        request = str(function.get("request"))
        instructions = instruction_windows.get(request, [])
        index_by_va = _call_index_by_va(instructions)
        dispatches: list[dict[str, object]] = []
        function_hit_count = 0
        for call in function.get("calls", []):
            kind = str(call.get("kind") or "")
            if not kind.startswith("indirect-"):
                continue
            function_hit_count += 1
            dispatch_hit_count += 1
            if len(dispatches) >= max_dispatches_per_function:
                continue
            call_index = index_by_va.get(str(call.get("callsite_va")))
            if call_index is None:
                dispatches.append(
                    {
                        "callsite_va": call.get("callsite_va"),
                        "callsite_rva": call.get("callsite_rva"),
                        "kind": kind,
                        "instruction": call.get("instruction"),
                        "origin": {
                            "kind": "unresolved",
                            "reason": "callsite-not-in-instruction-window",
                        },
                        "call": call,
                    }
                )
                continue
            dispatch = _dispatch_payload_for_call(
                call,
                instructions,
                call_index,
                max_backtrack_instructions=max_backtrack_instructions,
            )
            if dispatch is not None:
                dispatches.append(dispatch)

        existing_dispatch_vas = {str(dispatch.get("callsite_va")) for dispatch in dispatches}
        for instruction in instructions:
            tail_dispatch = _tail_dispatch_from_instruction(instruction)
            if tail_dispatch is None:
                continue
            if str(tail_dispatch.get("callsite_va")) in existing_dispatch_vas:
                continue
            function_hit_count += 1
            dispatch_hit_count += 1
            if len(dispatches) >= max_dispatches_per_function:
                continue
            call_index = index_by_va.get(str(tail_dispatch.get("callsite_va")))
            if call_index is None:
                dispatches.append(
                    {
                        "callsite_va": tail_dispatch.get("callsite_va"),
                        "callsite_rva": tail_dispatch.get("callsite_rva"),
                        "kind": tail_dispatch.get("kind"),
                        "instruction": tail_dispatch.get("instruction"),
                        "control_transfer": "tail-jump",
                        "origin": {
                            "kind": "unresolved",
                            "reason": "callsite-not-in-instruction-window",
                        },
                        "call": tail_dispatch,
                    }
                )
                continue
            dispatch = _dispatch_payload_for_call(
                tail_dispatch,
                instructions,
                call_index,
                max_backtrack_instructions=max_backtrack_instructions,
            )
            if dispatch is not None:
                dispatches.append(dispatch)

        results.append(
            {
                "request": request,
                "start_va": function.get("start_va"),
                "start_rva": function.get("start_rva"),
                "end_va": function.get("end_va"),
                "end_rva": function.get("end_rva"),
                "indirect_dispatch_hit_count": function_hit_count,
                "indirect_dispatch_count": len(dispatches),
                "truncated_indirect_dispatch_count": max(0, function_hit_count - len(dispatches)),
                "dispatches": dispatches,
            }
        )

    return {
        "type": "pe-indirect-dispatches",
        "target": str(target_path),
        "image_base": _hex(metadata.image_base),
        "scan": {
            "function_count": len(normalized_functions),
            "max_backtrack_instructions": max_backtrack_instructions,
            "max_dispatches_per_function": max_dispatches_per_function,
            "indirect_dispatch_hit_count": dispatch_hit_count,
        },
        "functions": results,
        "warnings": warnings,
    }
