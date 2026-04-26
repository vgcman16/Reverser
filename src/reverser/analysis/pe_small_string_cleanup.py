from __future__ import annotations

from pathlib import Path
from typing import Any

from reverser.analysis.pe_direct_calls import read_pe_metadata
from reverser.analysis.pe_function_calls import _parse_function_spec
from reverser.analysis.pe_indirect_dispatches import _normalize_register, _parse_memory_operand, _split_operands
from reverser.analysis.pe_instructions import WindowSpec, _scan_window
from reverser.analysis.pe_runtime_functions import read_pe_runtime_functions


def _hex(value: int) -> str:
    return f"0x{value:x}"


def _instruction_excerpt(instruction: dict[str, object]) -> dict[str, object]:
    keys = ("address_va", "address_rva", "raw_bytes", "length", "instruction", "mnemonic", "operands")
    return {key: instruction[key] for key in keys if key in instruction}


def _assignment(instruction: dict[str, object]) -> tuple[str, str] | None:
    if str(instruction.get("mnemonic") or "").upper() not in {"MOV", "LEA", "MOVZX", "MOVSXD"}:
        return None
    operands = _split_operands(instruction.get("operands"))
    if len(operands) < 2:
        return None
    destination = _normalize_register(operands[0])
    if destination is None:
        return None
    return destination, operands[1]


def _memory_assignment(instruction: dict[str, object], register: str) -> dict[str, object] | None:
    assignment = _assignment(instruction)
    if assignment is None:
        return None
    destination, source = assignment
    if destination != register:
        return None
    return _parse_memory_operand(source)


def _register_assignment(instruction: dict[str, object], register: str) -> str | None:
    assignment = _assignment(instruction)
    if assignment is None:
        return None
    destination, source = assignment
    if destination != register:
        return None
    return _normalize_register(source)


def _stack_memory(memory: dict[str, object] | None) -> bool:
    if not memory:
        return False
    return _normalize_register(memory.get("base_register")) in {"RSP", "RBP"}


def _find_recent_memory_load(
    instructions: list[dict[str, object]],
    call_index: int,
    register: str,
    *,
    max_backtrack_instructions: int,
) -> tuple[int, dict[str, object], dict[str, object]] | None:
    lower = max(0, call_index - max_backtrack_instructions)
    for index in range(call_index - 1, lower - 1, -1):
        memory = _memory_assignment(instructions[index], register)
        if memory is not None:
            return index, instructions[index], memory
    return None


def _find_recent_register_copy(
    instructions: list[dict[str, object]],
    call_index: int,
    register: str,
    *,
    max_backtrack_instructions: int,
) -> tuple[int, dict[str, object], str] | None:
    lower = max(0, call_index - max_backtrack_instructions)
    for index in range(call_index - 1, lower - 1, -1):
        source = _register_assignment(instructions[index], register)
        if source is not None:
            return index, instructions[index], source
    return None


def _find_sentinel_gate(
    instructions: list[dict[str, object]],
    call_index: int,
    *,
    max_backtrack_instructions: int,
) -> dict[str, object] | None:
    lower = max(0, call_index - max_backtrack_instructions)
    window = instructions[lower:call_index]
    for local_index, instruction in enumerate(window):
        mnemonic = str(instruction.get("mnemonic") or "").upper()
        operands = _split_operands(instruction.get("operands"))
        if mnemonic == "TEST" and len(operands) >= 2 and str(operands[1]).lower() == "0x80":
            memory = _parse_memory_operand(operands[0])
            if _stack_memory(memory):
                return {
                    "kind": "memory-bit-test",
                    "memory": memory,
                    "test_va": instruction.get("address_va"),
                    "test_instruction": instruction.get("instruction"),
                }
        if mnemonic != "MOVZX" or len(operands) < 2:
            continue
        memory = _parse_memory_operand(operands[1])
        if not _stack_memory(memory):
            continue
        following = window[local_index + 1 : min(len(window), local_index + 8)]
        shift = next(
            (
                item
                for item in following
                if str(item.get("mnemonic") or "").upper() in {"SHR", "SAR"}
                and "0x7" in str(item.get("operands") or "").lower()
            ),
            None,
        )
        test = next(
            (
                item
                for item in following
                if str(item.get("mnemonic") or "").upper() == "TEST"
                and "0x1" in str(item.get("operands") or "").lower()
            ),
            None,
        )
        if shift is not None and test is not None:
            return {
                "kind": "small-string-high-bit-sentinel",
                "memory": memory,
                "load_va": instruction.get("address_va"),
                "load_instruction": instruction.get("instruction"),
                "shift_va": shift.get("address_va"),
                "shift_instruction": shift.get("instruction"),
                "test_va": test.get("address_va"),
                "test_instruction": test.get("instruction"),
            }
    return None


def _has_null_test_after(
    instructions: list[dict[str, object]],
    load_index: int,
    register: str,
    call_index: int,
) -> bool:
    for instruction in instructions[load_index + 1 : min(call_index, load_index + 5)]:
        if str(instruction.get("mnemonic") or "").upper() != "TEST":
            continue
        registers = [_normalize_register(part) for part in _split_operands(instruction.get("operands"))]
        if registers.count(register) >= 2:
            return True
    return False


def _absolute_memory_load(instructions: list[dict[str, object]], call_index: int, *, max_backtrack_instructions: int) -> dict[str, object] | None:
    lower = max(0, call_index - max_backtrack_instructions)
    for index in range(call_index - 1, lower - 1, -1):
        memory = _memory_assignment(instructions[index], "RCX")
        if memory and memory.get("memory_kind") == "absolute":
            return {
                "global_va": memory.get("absolute_va"),
                "load_va": instructions[index].get("address_va"),
                "load_instruction": instructions[index].get("instruction"),
            }
    return None


def _size_sources(
    instructions: list[dict[str, object]],
    call_index: int,
    *,
    max_backtrack_instructions: int,
    start_index: int | None = None,
) -> list[dict[str, object]]:
    lower = max(0, call_index - max_backtrack_instructions)
    if start_index is not None:
        lower = max(lower, start_index)
    sources: list[dict[str, object]] = []
    for instruction in instructions[lower:call_index]:
        memory = _memory_assignment(instruction, "R8")
        if memory is None:
            continue
        sources.append(
            {
                "load_va": instruction.get("address_va"),
                "load_instruction": instruction.get("instruction"),
                "memory": memory,
            }
        )
    return sources


def _classify_score(
    *,
    sentinel: dict[str, object] | None,
    pointer: dict[str, object] | None,
    allocator: dict[str, object] | None,
    dispatch: dict[str, object] | None,
    final_pool_register: str | None,
    sizes: list[dict[str, object]],
) -> tuple[float, str]:
    score = 0.2
    if dispatch:
        score += 0.25
    if final_pool_register:
        score += 0.15
    if allocator:
        score += 0.15
    if pointer:
        score += 0.15
    if sentinel:
        score += 0.1
    if sizes:
        score += 0.1
    score = min(score, 1.0)
    if score >= 0.85:
        return score, "high"
    if score >= 0.65:
        return score, "medium"
    return score, "low"


def _cleanup_for_call(
    instructions: list[dict[str, object]],
    call_index: int,
    *,
    max_backtrack_instructions: int,
) -> dict[str, object] | None:
    call = instructions[call_index]
    call_register = _normalize_register(str(call.get("operands") or ""))
    if call_register is None:
        return None

    method_load = _find_recent_memory_load(
        instructions,
        call_index,
        call_register,
        max_backtrack_instructions=max_backtrack_instructions,
    )
    if method_load is None:
        return None
    method_index, method_instruction, method_memory = method_load
    if method_memory.get("memory_kind") not in {"base", "base-displacement"}:
        return None

    final_pool = _find_recent_register_copy(
        instructions,
        call_index,
        "RCX",
        max_backtrack_instructions=max_backtrack_instructions,
    )
    final_pool_register = final_pool[2] if final_pool else None

    pointer_load = _find_recent_memory_load(
        instructions,
        call_index,
        "RDX",
        max_backtrack_instructions=max_backtrack_instructions,
    )
    pointer_payload: dict[str, object] | None = None
    if pointer_load is not None:
        pointer_index, pointer_instruction, pointer_memory = pointer_load
        pointer_payload = {
            "register": "RDX",
            "memory": pointer_memory,
            "load_va": pointer_instruction.get("address_va"),
            "load_instruction": pointer_instruction.get("instruction"),
            "null_checked": _has_null_test_after(instructions, pointer_index, "RDX", call_index),
        }

    sentinel = _find_sentinel_gate(
        instructions,
        call_index,
        max_backtrack_instructions=max_backtrack_instructions,
    )
    allocator = _absolute_memory_load(
        instructions,
        call_index,
        max_backtrack_instructions=max_backtrack_instructions,
    )
    sizes = _size_sources(
        instructions,
        call_index,
        max_backtrack_instructions=max_backtrack_instructions,
        start_index=method_index,
    )
    dispatch = {
        "method_register": call_register,
        "method_load_va": method_instruction.get("address_va"),
        "method_load_instruction": method_instruction.get("instruction"),
        "vtable_memory": method_memory,
        "slot_displacement": method_memory.get("displacement", 0),
        "slot_displacement_hex": method_memory.get("displacement_hex", "0x0"),
    }
    if final_pool is not None:
        dispatch["final_rcx_setup_va"] = final_pool[1].get("address_va")
        dispatch["final_rcx_setup_instruction"] = final_pool[1].get("instruction")
        dispatch["pool_register"] = final_pool_register

    score, confidence = _classify_score(
        sentinel=sentinel,
        pointer=pointer_payload,
        allocator=allocator,
        dispatch=dispatch,
        final_pool_register=final_pool_register,
        sizes=sizes,
    )
    if confidence == "low":
        return None

    evidence_lower = max(0, call_index - min(max_backtrack_instructions, 18))
    return {
        "classification": "small-string-heap-cleanup",
        "confidence": confidence,
        "confidence_score": round(score, 2),
        "callsite_va": call.get("address_va"),
        "callsite_rva": call.get("address_rva"),
        "instruction": call.get("instruction"),
        "call_register": call_register,
        "released_pointer": pointer_payload,
        "sentinel_gate": sentinel,
        "allocator_service": allocator,
        "dispatch": dispatch,
        "size_sources": sizes,
        "evidence": [_instruction_excerpt(item) for item in instructions[evidence_lower : call_index + 1]],
    }


def find_pe_small_string_cleanup(
    path: str | Path,
    functions: list[str] | tuple[str, ...],
    *,
    call_registers: list[str] | tuple[str, ...] = ("R10",),
    max_backtrack_instructions: int = 32,
    max_cleanups_per_function: int = 128,
) -> dict[str, object]:
    """Find stack small-string heap-cleanup dispatches through allocator vtable calls."""

    target_path = Path(path)
    data = target_path.read_bytes()
    metadata = read_pe_metadata(data)
    runtime_functions = read_pe_runtime_functions(data, metadata)
    requested_call_registers = tuple(
        register
        for register in (_normalize_register(item) for item in call_registers)
        if register is not None
    ) or ("R10",)

    warnings: list[str] = []
    results: list[dict[str, object]] = []
    cleanup_hit_count = 0
    decoded_instruction_count = 0
    for function_spec in functions:
        try:
            start_va, end_va = _parse_function_spec(str(function_spec), metadata, runtime_functions)
        except ValueError as exc:
            warnings.append(str(exc))
            continue
        window, warning = _scan_window(
            data,
            metadata,
            runtime_functions,
            WindowSpec(request=str(function_spec), start_va=start_va, end_va=end_va),
        )
        if warning is not None:
            warnings.append(warning)
        instructions = [item for item in window.get("instructions", []) if isinstance(item, dict)]
        decoded_instruction_count += int(window.get("decoded_instruction_count", 0))
        cleanups: list[dict[str, object]] = []
        function_candidate_count = 0
        function_cleanup_hit_count = 0
        for index, instruction in enumerate(instructions):
            if str(instruction.get("mnemonic") or "").upper() != "CALL":
                continue
            call_register = _normalize_register(str(instruction.get("operands") or ""))
            if call_register not in requested_call_registers:
                continue
            function_candidate_count += 1
            cleanup = _cleanup_for_call(
                instructions,
                index,
                max_backtrack_instructions=max_backtrack_instructions,
            )
            if cleanup is None:
                continue
            function_cleanup_hit_count += 1
            cleanup_hit_count += 1
            if len(cleanups) < max_cleanups_per_function:
                cleanups.append(cleanup)
        results.append(
            {
                "request": str(function_spec),
                "start_va": _hex(start_va),
                "start_rva": _hex(start_va - metadata.image_base),
                "end_va": _hex(end_va),
                "end_rva": _hex(end_va - metadata.image_base),
                "decoded_instruction_count": int(window.get("decoded_instruction_count", 0)),
                "candidate_call_count": function_candidate_count,
                "cleanup_hit_count": function_cleanup_hit_count,
                "cleanup_count": len(cleanups),
                "truncated_cleanup_count": max(0, function_cleanup_hit_count - len(cleanups)),
                "cleanups": cleanups,
            }
        )

    return {
        "type": "pe-small-string-cleanup",
        "target": str(target_path),
        "image_base": _hex(metadata.image_base),
        "scan": {
            "function_count": len(results),
            "runtime_function_count": len(runtime_functions),
            "decoded_instruction_count": decoded_instruction_count,
            "call_registers": list(requested_call_registers),
            "max_backtrack_instructions": max_backtrack_instructions,
            "cleanup_hit_count": cleanup_hit_count,
            "cleanup_count": sum(len(item["cleanups"]) for item in results),
        },
        "functions": results,
        "warnings": warnings,
    }
