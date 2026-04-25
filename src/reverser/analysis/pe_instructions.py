from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path

from reverser.analysis.pe_direct_calls import PEMetadata, PESection, parse_int_literal, read_pe_metadata
from reverser.analysis.pe_function_calls import (
    _call_at,
    _runtime_payload_for_va,
)
from reverser.analysis.pe_runtime_functions import read_pe_runtime_functions


def _hex(value: int) -> str:
    return f"0x{value:x}"


_REG8 = (
    "AL",
    "CL",
    "DL",
    "BL",
    "SPL",
    "BPL",
    "SIL",
    "DIL",
    "R8B",
    "R9B",
    "R10B",
    "R11B",
    "R12B",
    "R13B",
    "R14B",
    "R15B",
)

_REG16 = (
    "AX",
    "CX",
    "DX",
    "BX",
    "SP",
    "BP",
    "SI",
    "DI",
    "R8W",
    "R9W",
    "R10W",
    "R11W",
    "R12W",
    "R13W",
    "R14W",
    "R15W",
)

_REG32 = (
    "EAX",
    "ECX",
    "EDX",
    "EBX",
    "ESP",
    "EBP",
    "ESI",
    "EDI",
    "R8D",
    "R9D",
    "R10D",
    "R11D",
    "R12D",
    "R13D",
    "R14D",
    "R15D",
)

_REG64 = (
    "RAX",
    "RCX",
    "RDX",
    "RBX",
    "RSP",
    "RBP",
    "RSI",
    "RDI",
    "R8",
    "R9",
    "R10",
    "R11",
    "R12",
    "R13",
    "R14",
    "R15",
)

_XMM = tuple(f"XMM{index}" for index in range(16))

_JCC_NAMES = {
    0x0: "JO",
    0x1: "JNO",
    0x2: "JC",
    0x3: "JNC",
    0x4: "JZ",
    0x5: "JNZ",
    0x6: "JBE",
    0x7: "JA",
    0x8: "JS",
    0x9: "JNS",
    0xA: "JP",
    0xB: "JNP",
    0xC: "JL",
    0xD: "JGE",
    0xE: "JLE",
    0xF: "JG",
}

_GROUP1_MNEMONICS = {
    0x0: "ADD",
    0x1: "OR",
    0x2: "ADC",
    0x3: "SBB",
    0x4: "AND",
    0x5: "SUB",
    0x6: "XOR",
    0x7: "CMP",
}


@dataclass(frozen=True)
class WindowSpec:
    request: str
    start_va: int
    instruction_count: int | None = None
    end_va: int | None = None


@dataclass(frozen=True)
class Prefixes:
    start: int
    opcode_offset: int
    rex: int | None
    lock: bool
    repeat: str | None
    operand16: bool
    segment: str | None
    raw: bytes

    @property
    def rex_w(self) -> int:
        return 1 if self.rex is not None and self.rex & 0x8 else 0

    @property
    def rex_r(self) -> int:
        return 0x8 if self.rex is not None and self.rex & 0x4 else 0

    @property
    def rex_x(self) -> int:
        return 0x8 if self.rex is not None and self.rex & 0x2 else 0

    @property
    def rex_b(self) -> int:
        return 0x8 if self.rex is not None and self.rex & 0x1 else 0


@dataclass(frozen=True)
class ModRMOperand:
    reg: int
    rm: int
    mod: int
    rm_operand: str
    reg_operand: str
    operand_length: int
    displacement: int | None = None
    memory_target_va: int | None = None


def _parse_window_spec(value: str, metadata: PEMetadata) -> WindowSpec:
    raw_value = str(value)
    if ".." in raw_value:
        start_raw, end_raw = raw_value.split("..", 1)
        start_va, _ = metadata.normalize_va_or_rva(parse_int_literal(start_raw))
        end_va, _ = metadata.normalize_va_or_rva(parse_int_literal(end_raw))
        if end_va <= start_va:
            raise ValueError(f"Window end must be greater than start: {value!r}.")
        return WindowSpec(request=raw_value, start_va=start_va, end_va=end_va)

    if ":" in raw_value:
        start_raw, count_raw = raw_value.split(":", 1)
        start_va, _ = metadata.normalize_va_or_rva(parse_int_literal(start_raw))
        count = parse_int_literal(count_raw)
        if count <= 0:
            raise ValueError(f"Instruction count must be greater than zero: {value!r}.")
        return WindowSpec(request=raw_value, start_va=start_va, instruction_count=count)

    start_va, _ = metadata.normalize_va_or_rva(parse_int_literal(raw_value))
    return WindowSpec(request=raw_value, start_va=start_va, instruction_count=32)


def _register(index: int, size: int) -> str:
    if size == 128:
        return _XMM[index]
    if size == 8:
        return _REG8[index]
    if size == 16:
        return _REG16[index]
    if size == 32:
        return _REG32[index]
    return _REG64[index]


def _operand_size(prefixes: Prefixes) -> int:
    if prefixes.rex_w:
        return 64
    if prefixes.operand16:
        return 16
    return 32


def _full_width_immediate_size(operand_size: int) -> int:
    return 2 if operand_size == 16 else 4


def _signed_hex(value: int) -> str:
    if value < 0:
        return f"-0x{-value:x}"
    return f"0x{value:x}"


def _format_displacement(value: int) -> str:
    if value < 0:
        return f"-0x{-value:x}"
    return f"+0x{value:x}"


def _read_prefixes(data: bytes, cursor: int) -> Prefixes:
    offset = cursor
    rex: int | None = None
    lock = False
    repeat: str | None = None
    operand16 = False
    segment: str | None = None
    while offset < len(data):
        byte = data[offset]
        if byte == 0xF0:
            lock = True
            offset += 1
            continue
        if byte == 0x66:
            operand16 = True
            offset += 1
            continue
        if byte in (0x2E, 0x36, 0x3E, 0x26, 0x64, 0x65):
            segment = {
                0x2E: "CS",
                0x36: "SS",
                0x3E: "DS",
                0x26: "ES",
                0x64: "FS",
                0x65: "GS",
            }[byte]
            offset += 1
            continue
        if byte in (0xF2, 0xF3):
            repeat = "REPNE" if byte == 0xF2 else "REP"
            offset += 1
            continue
        if byte == 0x67:
            offset += 1
            continue
        if 0x40 <= byte <= 0x4F:
            rex = byte
            offset += 1
            continue
        break
    return Prefixes(
        start=cursor,
        opcode_offset=offset,
        rex=rex,
        lock=lock,
        repeat=repeat,
        operand16=operand16,
        segment=segment,
        raw=data[cursor:offset],
    )


def _format_memory(
    *,
    base: str | None,
    index: str | None,
    scale: int,
    displacement: int,
    absolute_va: int | None = None,
    segment: str | None = None,
) -> str:
    prefix = f"{segment}:" if segment is not None else ""
    if absolute_va is not None:
        return f"{prefix}[{_hex(absolute_va)}]"

    parts: list[str] = []
    if base is not None:
        parts.append(base)
    if index is not None:
        parts.append(index if scale == 1 else f"{index}*0x{scale:x}")

    if not parts:
        return f"{prefix}[{_signed_hex(displacement)}]"

    text = "+".join(parts)
    if displacement:
        text += _format_displacement(displacement)
    return f"{prefix}[{text}]"


def _parse_modrm(
    data: bytes,
    *,
    prefixes: Prefixes,
    opcode_offset: int,
    operand_start: int,
    instruction_va: int,
    rm_size: int,
    reg_size: int | None = None,
    rip_relative_base_adjust: int = 0,
) -> ModRMOperand | None:
    if operand_start >= len(data):
        return None

    reg_size = rm_size if reg_size is None else reg_size
    modrm = data[operand_start]
    mod = (modrm >> 6) & 0x3
    reg = ((modrm >> 3) & 0x7) + prefixes.rex_r
    rm = (modrm & 0x7) + prefixes.rex_b
    offset = operand_start + 1
    displacement: int | None = None
    memory_target_va: int | None = None

    if mod == 0x3:
        return ModRMOperand(
            reg=reg,
            rm=rm,
            mod=mod,
            rm_operand=_register(rm, rm_size),
            reg_operand=_register(reg, reg_size),
            operand_length=offset - operand_start,
        )

    base: str | None = None
    index: str | None = None
    scale = 1
    absolute_va: int | None = None
    rm_low = modrm & 0x7
    if rm_low == 0x4:
        if offset >= len(data):
            return None
        sib = data[offset]
        offset += 1
        scale = 1 << ((sib >> 6) & 0x3)
        index_low = (sib >> 3) & 0x7
        base_low = sib & 0x7
        if index_low != 0x4:
            index = _register(index_low + prefixes.rex_x, 64)
        if not (mod == 0 and base_low == 0x5):
            base = _register(base_low + prefixes.rex_b, 64)
    elif not (mod == 0 and rm_low == 0x5):
        base = _register(rm, 64)

    if mod == 0 and rm_low == 0x5 and base is None:
        if offset + 4 > len(data):
            return None
        displacement = struct.unpack_from("<i", data, offset)[0]
        offset += 4
        memory_target_va = instruction_va + (offset - prefixes.start) + rip_relative_base_adjust + displacement
        absolute_va = memory_target_va
    elif mod == 0 and rm_low == 0x4 and base is None:
        if offset + 4 > len(data):
            return None
        displacement = struct.unpack_from("<i", data, offset)[0]
        offset += 4
    elif mod == 1:
        if offset + 1 > len(data):
            return None
        displacement = struct.unpack_from("<b", data, offset)[0]
        offset += 1
    elif mod == 2:
        if offset + 4 > len(data):
            return None
        displacement = struct.unpack_from("<i", data, offset)[0]
        offset += 4
    else:
        displacement = 0

    memory = _format_memory(
        base=base,
        index=index,
        scale=scale,
        displacement=displacement or 0,
        absolute_va=absolute_va,
        segment=prefixes.segment,
    )
    return ModRMOperand(
        reg=reg,
        rm=rm,
        mod=mod,
        rm_operand=memory,
        reg_operand=_register(reg, reg_size),
        operand_length=offset - operand_start,
        displacement=displacement,
        memory_target_va=memory_target_va,
    )


def _instruction_payload(
    *,
    data: bytes,
    section: PESection,
    raw_start: int,
    cursor: int,
    length: int,
    mnemonic: str,
    operands: str = "",
    kind: str = "decoded",
    extra: dict[str, object] | None = None,
) -> dict[str, object]:
    rva = section.virtual_address + (cursor - raw_start)
    va = rva + extra.pop("_image_base") if extra and "_image_base" in extra else None
    if va is None:
        raise ValueError("Internal instruction payload requires _image_base in extra.")
    instruction = mnemonic if not operands else f"{mnemonic} {operands}"
    payload: dict[str, object] = {
        "address_va": _hex(va),
        "address_rva": _hex(rva),
        "section": section.name,
        "raw_offset": _hex(cursor),
        "raw_bytes": data[cursor : cursor + length].hex(),
        "length": length,
        "mnemonic": mnemonic,
        "operands": operands,
        "instruction": instruction,
        "kind": kind,
    }
    if extra:
        payload.update(extra)
    return payload


def _decode_modrm_instruction(
    data: bytes,
    *,
    metadata: PEMetadata,
    runtime_functions: list[object],
    section: PESection,
    raw_start: int,
    cursor: int,
    prefixes: Prefixes,
    opcode: int,
    mnemonic: str,
    operand_order: str,
    rm_size: int,
    reg_size: int | None = None,
    kind: str = "decoded",
) -> dict[str, object] | None:
    instruction_va = metadata.image_base + section.virtual_address + (cursor - raw_start)
    parsed = _parse_modrm(
        data,
        prefixes=prefixes,
        opcode_offset=prefixes.opcode_offset,
        operand_start=prefixes.opcode_offset + 1,
        instruction_va=instruction_va,
        rm_size=rm_size,
        reg_size=reg_size,
    )
    if parsed is None:
        return None

    length = prefixes.opcode_offset - cursor + 1 + parsed.operand_length
    if operand_order == "rm,reg":
        operands = f"{parsed.rm_operand}, {parsed.reg_operand}"
    else:
        operands = f"{parsed.reg_operand}, {parsed.rm_operand}"
    extra: dict[str, object] = {"_image_base": metadata.image_base}
    if parsed.memory_target_va is not None:
        extra["memory_target_va"] = _hex(parsed.memory_target_va)
        extra["memory_target_rva"] = _hex(parsed.memory_target_va - metadata.image_base)
    return _instruction_payload(
        data=data,
        section=section,
        raw_start=raw_start,
        cursor=cursor,
        length=length,
        mnemonic=mnemonic,
        operands=operands,
        kind=kind,
        extra=extra,
    )


def _branch_payload(
    data: bytes,
    *,
    metadata: PEMetadata,
    runtime_functions: list[object],
    section: PESection,
    raw_start: int,
    cursor: int,
    length: int,
    mnemonic: str,
    rel: int,
    conditional: bool,
) -> dict[str, object]:
    instruction_va = metadata.image_base + section.virtual_address + (cursor - raw_start)
    target_va = instruction_va + length + rel
    extra: dict[str, object] = {
        "_image_base": metadata.image_base,
        "target_va": _hex(target_va),
        "target_rva": _hex(target_va - metadata.image_base) if target_va >= metadata.image_base else None,
        "target_section": section.name if section.contains_rva(target_va - metadata.image_base) else None,
        "relative_offset": rel,
        "branch_kind": "conditional" if conditional else "unconditional",
    }
    target_function = _runtime_payload_for_va(metadata, runtime_functions, target_va)
    if target_function is not None:
        extra["target_function"] = target_function
    return _instruction_payload(
        data=data,
        section=section,
        raw_start=raw_start,
        cursor=cursor,
        length=length,
        mnemonic=mnemonic,
        operands=_hex(target_va),
        kind="branch",
        extra=extra,
    )


def _decode_instruction_at(
    data: bytes,
    metadata: PEMetadata,
    runtime_functions: list[object],
    section: PESection,
    raw_start: int,
    cursor: int,
    raw_end: int,
) -> dict[str, object]:
    instruction_va = metadata.image_base + section.virtual_address + (cursor - raw_start)
    call = _call_at(data, metadata, runtime_functions, section, raw_start, cursor)
    if call is not None:
        length = int(call["instruction_length"])
        call_kind = call.pop("kind", None)
        payload = {
            "address_va": call.pop("callsite_va"),
            "address_rva": call.pop("callsite_rva"),
            "section": call.pop("section"),
            "raw_offset": call.pop("raw_offset"),
            "raw_bytes": call.pop("raw_bytes"),
            "length": length,
            "mnemonic": "CALL",
            "operands": str(call.get("instruction", "CALL")).split(" ", 1)[1] if " " in str(call.get("instruction", "")) else "",
            "instruction": call.pop("instruction"),
            "kind": "call",
        }
        if call_kind is not None:
            payload["call_kind"] = call_kind
        payload.update(call)
        return payload

    prefixes = _read_prefixes(data, cursor)
    opcode_offset = prefixes.opcode_offset
    if opcode_offset >= raw_end:
        return _instruction_payload(
            data=data,
            section=section,
            raw_start=raw_start,
            cursor=cursor,
            length=1,
            mnemonic="DB",
            operands=_hex(data[cursor]),
            kind="unknown",
            extra={"_image_base": metadata.image_base},
        )

    opcode = data[opcode_offset]
    prefix_len = opcode_offset - cursor
    size = _operand_size(prefixes)

    if opcode == 0x90:
        return _instruction_payload(
            data=data,
            section=section,
            raw_start=raw_start,
            cursor=cursor,
            length=prefix_len + 1,
            mnemonic="NOP",
            extra={"_image_base": metadata.image_base},
        )
    if opcode == 0xCC:
        return _instruction_payload(
            data=data,
            section=section,
            raw_start=raw_start,
            cursor=cursor,
            length=prefix_len + 1,
            mnemonic="INT3",
            extra={"_image_base": metadata.image_base},
        )
    if opcode == 0xCD and opcode_offset + 2 <= raw_end:
        immediate = data[opcode_offset + 1]
        return _instruction_payload(
            data=data,
            section=section,
            raw_start=raw_start,
            cursor=cursor,
            length=prefix_len + 2,
            mnemonic="INT",
            operands=_hex(immediate),
            extra={"_image_base": metadata.image_base, "immediate": immediate},
        )
    if opcode == 0xC3:
        return _instruction_payload(
            data=data,
            section=section,
            raw_start=raw_start,
            cursor=cursor,
            length=prefix_len + 1,
            mnemonic="RET",
            kind="return",
            extra={"_image_base": metadata.image_base},
        )
    if opcode in (0xAA, 0xAB):
        if opcode == 0xAA:
            mnemonic = "STOSB"
        elif size == 16:
            mnemonic = "STOSW"
        elif size == 64:
            mnemonic = "STOSQ"
        else:
            mnemonic = "STOSD"
        extra: dict[str, object] = {"_image_base": metadata.image_base}
        if prefixes.repeat is not None:
            extra["repeat_prefix"] = prefixes.repeat
        payload = _instruction_payload(
            data=data,
            section=section,
            raw_start=raw_start,
            cursor=cursor,
            length=prefix_len + 1,
            mnemonic=mnemonic,
            extra=extra,
        )
        if prefixes.repeat is not None:
            payload["instruction"] = f"{prefixes.repeat} {mnemonic}"
        return payload
    if opcode in (0x98, 0x99):
        if opcode == 0x98:
            mnemonic = "CDQE" if prefixes.rex_w else ("CBW" if prefixes.operand16 else "CWDE")
        else:
            mnemonic = "CQO" if prefixes.rex_w else ("CWD" if prefixes.operand16 else "CDQ")
        return _instruction_payload(
            data=data,
            section=section,
            raw_start=raw_start,
            cursor=cursor,
            length=prefix_len + 1,
            mnemonic=mnemonic,
            extra={"_image_base": metadata.image_base},
        )
    if opcode == 0xC2 and opcode_offset + 3 <= raw_end:
        imm = struct.unpack_from("<H", data, opcode_offset + 1)[0]
        return _instruction_payload(
            data=data,
            section=section,
            raw_start=raw_start,
            cursor=cursor,
            length=prefix_len + 3,
            mnemonic="RET",
            operands=_hex(imm),
            kind="return",
            extra={"_image_base": metadata.image_base, "immediate": imm},
        )
    if 0x50 <= opcode <= 0x57:
        register = _register((opcode - 0x50) + prefixes.rex_b, 64)
        return _instruction_payload(
            data=data,
            section=section,
            raw_start=raw_start,
            cursor=cursor,
            length=prefix_len + 1,
            mnemonic="PUSH",
            operands=register,
            extra={"_image_base": metadata.image_base, "register": register},
        )
    if 0x58 <= opcode <= 0x5F:
        register = _register((opcode - 0x58) + prefixes.rex_b, 64)
        return _instruction_payload(
            data=data,
            section=section,
            raw_start=raw_start,
            cursor=cursor,
            length=prefix_len + 1,
            mnemonic="POP",
            operands=register,
            extra={"_image_base": metadata.image_base, "register": register},
        )
    if 0xB0 <= opcode <= 0xB7 and opcode_offset + 2 <= raw_end:
        register = _register((opcode - 0xB0) + prefixes.rex_b, 8)
        immediate = data[opcode_offset + 1]
        return _instruction_payload(
            data=data,
            section=section,
            raw_start=raw_start,
            cursor=cursor,
            length=prefix_len + 2,
            mnemonic="MOV",
            operands=f"{register}, {_hex(immediate)}",
            extra={"_image_base": metadata.image_base, "register": register, "immediate": immediate},
        )
    if 0xB8 <= opcode <= 0xBF:
        register = _register((opcode - 0xB8) + prefixes.rex_b, 64 if prefixes.rex_w else 32)
        imm_size = 8 if prefixes.rex_w else 4
        if opcode_offset + 1 + imm_size <= raw_end:
            fmt = "<Q" if imm_size == 8 else "<I"
            immediate = struct.unpack_from(fmt, data, opcode_offset + 1)[0]
            return _instruction_payload(
                data=data,
                section=section,
                raw_start=raw_start,
                cursor=cursor,
                length=prefix_len + 1 + imm_size,
                mnemonic="MOV",
                operands=f"{register}, {_hex(immediate)}",
                extra={"_image_base": metadata.image_base, "register": register, "immediate": immediate},
            )

    if opcode in (0xA8, 0xA9):
        register = _register(0, 64 if prefixes.rex_w else 32) if opcode == 0xA9 else "AL"
        imm_size = 4 if opcode == 0xA9 else 1
        if opcode_offset + 1 + imm_size <= raw_end:
            immediate = int.from_bytes(data[opcode_offset + 1 : opcode_offset + 1 + imm_size], "little")
            return _instruction_payload(
                data=data,
                section=section,
                raw_start=raw_start,
                cursor=cursor,
                length=prefix_len + 1 + imm_size,
                mnemonic="TEST",
                operands=f"{register}, {_hex(immediate)}",
                extra={"_image_base": metadata.image_base, "register": register, "immediate": immediate},
            )

    if opcode in (0xE9, 0xEB):
        if opcode == 0xE9 and opcode_offset + 5 <= raw_end:
            return _branch_payload(
                data,
                metadata=metadata,
                runtime_functions=runtime_functions,
                section=section,
                raw_start=raw_start,
                cursor=cursor,
                length=prefix_len + 5,
                mnemonic="JMP",
                rel=struct.unpack_from("<i", data, opcode_offset + 1)[0],
                conditional=False,
            )
        if opcode == 0xEB and opcode_offset + 2 <= raw_end:
            return _branch_payload(
                data,
                metadata=metadata,
                runtime_functions=runtime_functions,
                section=section,
                raw_start=raw_start,
                cursor=cursor,
                length=prefix_len + 2,
                mnemonic="JMP",
                rel=struct.unpack_from("<b", data, opcode_offset + 1)[0],
                conditional=False,
            )
    if 0x70 <= opcode <= 0x7F and opcode_offset + 2 <= raw_end:
        return _branch_payload(
            data,
            metadata=metadata,
            runtime_functions=runtime_functions,
            section=section,
            raw_start=raw_start,
            cursor=cursor,
            length=prefix_len + 2,
            mnemonic=_JCC_NAMES[opcode & 0xF],
            rel=struct.unpack_from("<b", data, opcode_offset + 1)[0],
            conditional=True,
        )
    if opcode == 0x0F and opcode_offset + 2 <= raw_end:
        opcode2 = data[opcode_offset + 1]
        if 0x80 <= opcode2 <= 0x8F and opcode_offset + 6 <= raw_end:
            return _branch_payload(
                data,
                metadata=metadata,
                runtime_functions=runtime_functions,
                section=section,
                raw_start=raw_start,
                cursor=cursor,
                length=prefix_len + 6,
                mnemonic=_JCC_NAMES[opcode2 & 0xF],
                rel=struct.unpack_from("<i", data, opcode_offset + 2)[0],
                conditional=True,
            )
        if 0x40 <= opcode2 <= 0x4F:
            parsed = _parse_modrm(
                data,
                prefixes=prefixes,
                opcode_offset=opcode_offset,
                operand_start=opcode_offset + 2,
                instruction_va=instruction_va,
                rm_size=size,
                reg_size=size,
            )
            if parsed is not None:
                return _instruction_payload(
                    data=data,
                    section=section,
                    raw_start=raw_start,
                    cursor=cursor,
                    length=prefix_len + 2 + parsed.operand_length,
                    mnemonic=f"CMOV{_JCC_NAMES[opcode2 & 0xF][1:]}",
                    operands=f"{parsed.reg_operand}, {parsed.rm_operand}",
                    extra={"_image_base": metadata.image_base},
                )
        if 0x90 <= opcode2 <= 0x9F:
            parsed = _parse_modrm(
                data,
                prefixes=prefixes,
                opcode_offset=opcode_offset,
                operand_start=opcode_offset + 2,
                instruction_va=instruction_va,
                rm_size=8,
            )
            if parsed is not None:
                return _instruction_payload(
                    data=data,
                    section=section,
                    raw_start=raw_start,
                    cursor=cursor,
                    length=prefix_len + 2 + parsed.operand_length,
                    mnemonic=f"SET{_JCC_NAMES[opcode2 & 0xF][1:]}",
                    operands=parsed.rm_operand,
                    extra={"_image_base": metadata.image_base},
                )
        if opcode2 == 0x1F:
            parsed = _parse_modrm(
                data,
                prefixes=prefixes,
                opcode_offset=opcode_offset,
                operand_start=opcode_offset + 2,
                instruction_va=instruction_va,
                rm_size=64,
            )
            if parsed is not None:
                return _instruction_payload(
                    data=data,
                    section=section,
                    raw_start=raw_start,
                    cursor=cursor,
                    length=prefix_len + 2 + parsed.operand_length,
                    mnemonic="NOP",
                    operands=parsed.rm_operand,
                    extra={"_image_base": metadata.image_base},
                )
        if opcode2 == 0xC1:
            parsed = _parse_modrm(
                data,
                prefixes=prefixes,
                opcode_offset=opcode_offset,
                operand_start=opcode_offset + 2,
                instruction_va=instruction_va,
                rm_size=size,
            )
            if parsed is not None:
                mnemonic = "XADD.LOCK" if prefixes.lock else "XADD"
                return _instruction_payload(
                    data=data,
                    section=section,
                    raw_start=raw_start,
                    cursor=cursor,
                    length=prefix_len + 2 + parsed.operand_length,
                    mnemonic=mnemonic,
                    operands=f"{parsed.rm_operand}, {parsed.reg_operand}",
                    extra={"_image_base": metadata.image_base},
                )
        if opcode2 in (0xB0, 0xB1):
            cmpxchg_size = 8 if opcode2 == 0xB0 else size
            parsed = _parse_modrm(
                data,
                prefixes=prefixes,
                opcode_offset=opcode_offset,
                operand_start=opcode_offset + 2,
                instruction_va=instruction_va,
                rm_size=cmpxchg_size,
                reg_size=cmpxchg_size,
            )
            if parsed is not None:
                mnemonic = "CMPXCHG.LOCK" if prefixes.lock else "CMPXCHG"
                extra: dict[str, object] = {"_image_base": metadata.image_base}
                if parsed.memory_target_va is not None:
                    extra["memory_target_va"] = _hex(parsed.memory_target_va)
                    extra["memory_target_rva"] = _hex(parsed.memory_target_va - metadata.image_base)
                return _instruction_payload(
                    data=data,
                    section=section,
                    raw_start=raw_start,
                    cursor=cursor,
                    length=prefix_len + 2 + parsed.operand_length,
                    mnemonic=mnemonic,
                    operands=f"{parsed.rm_operand}, {parsed.reg_operand}",
                    extra=extra,
                )
        bit_test_decoders = {
            0xA3: "BT",
            0xAB: "BTS",
            0xB3: "BTR",
            0xBB: "BTC",
        }
        if opcode2 in bit_test_decoders:
            parsed = _parse_modrm(
                data,
                prefixes=prefixes,
                opcode_offset=opcode_offset,
                operand_start=opcode_offset + 2,
                instruction_va=instruction_va,
                rm_size=size,
                reg_size=size,
            )
            if parsed is not None:
                return _instruction_payload(
                    data=data,
                    section=section,
                    raw_start=raw_start,
                    cursor=cursor,
                    length=prefix_len + 2 + parsed.operand_length,
                    mnemonic=bit_test_decoders[opcode2],
                    operands=f"{parsed.rm_operand}, {parsed.reg_operand}",
                    extra={"_image_base": metadata.image_base},
                )
        if opcode2 == 0xAF:
            parsed = _parse_modrm(
                data,
                prefixes=prefixes,
                opcode_offset=opcode_offset,
                operand_start=opcode_offset + 2,
                instruction_va=instruction_va,
                rm_size=size,
                reg_size=size,
            )
            if parsed is not None:
                return _instruction_payload(
                    data=data,
                    section=section,
                    raw_start=raw_start,
                    cursor=cursor,
                    length=prefix_len + 2 + parsed.operand_length,
                    mnemonic="IMUL",
                    operands=f"{parsed.reg_operand}, {parsed.rm_operand}",
                    extra={"_image_base": metadata.image_base},
                )
        if opcode2 == 0x2C and prefixes.repeat in ("REP", "REPNE"):
            parsed = _parse_modrm(
                data,
                prefixes=prefixes,
                opcode_offset=opcode_offset,
                operand_start=opcode_offset + 2,
                instruction_va=instruction_va,
                rm_size=128,
                reg_size=64 if prefixes.rex_w else size,
            )
            if parsed is not None:
                extra: dict[str, object] = {"_image_base": metadata.image_base}
                if parsed.memory_target_va is not None:
                    extra["memory_target_va"] = _hex(parsed.memory_target_va)
                    extra["memory_target_rva"] = _hex(parsed.memory_target_va - metadata.image_base)
                mnemonic = "CVTTSS2SI" if prefixes.repeat == "REP" else "CVTTSD2SI"
                return _instruction_payload(
                    data=data,
                    section=section,
                    raw_start=raw_start,
                    cursor=cursor,
                    length=prefix_len + 2 + parsed.operand_length,
                    mnemonic=mnemonic,
                    operands=f"{parsed.reg_operand}, {parsed.rm_operand}",
                    extra=extra,
                )
        if opcode2 == 0x59 and prefixes.repeat in ("REP", "REPNE"):
            parsed = _parse_modrm(
                data,
                prefixes=prefixes,
                opcode_offset=opcode_offset,
                operand_start=opcode_offset + 2,
                instruction_va=instruction_va,
                rm_size=128,
                reg_size=128,
            )
            if parsed is not None:
                extra: dict[str, object] = {"_image_base": metadata.image_base}
                if parsed.memory_target_va is not None:
                    extra["memory_target_va"] = _hex(parsed.memory_target_va)
                    extra["memory_target_rva"] = _hex(parsed.memory_target_va - metadata.image_base)
                mnemonic = "MULSS" if prefixes.repeat == "REP" else "MULSD"
                return _instruction_payload(
                    data=data,
                    section=section,
                    raw_start=raw_start,
                    cursor=cursor,
                    length=prefix_len + 2 + parsed.operand_length,
                    mnemonic=mnemonic,
                    operands=f"{parsed.reg_operand}, {parsed.rm_operand}",
                    extra=extra,
                )
        if opcode2 in (0x6E, 0x7E) and prefixes.operand16:
            rm_size = 64 if prefixes.rex_w else 32
            parsed = _parse_modrm(
                data,
                prefixes=prefixes,
                opcode_offset=opcode_offset,
                operand_start=opcode_offset + 2,
                instruction_va=instruction_va,
                rm_size=rm_size,
                reg_size=128,
            )
            if parsed is not None:
                mnemonic = "MOVQ" if prefixes.rex_w else "MOVD"
                operands = (
                    f"{parsed.reg_operand}, {parsed.rm_operand}"
                    if opcode2 == 0x6E
                    else f"{parsed.rm_operand}, {parsed.reg_operand}"
                )
                extra: dict[str, object] = {"_image_base": metadata.image_base}
                if parsed.memory_target_va is not None:
                    extra["memory_target_va"] = _hex(parsed.memory_target_va)
                    extra["memory_target_rva"] = _hex(parsed.memory_target_va - metadata.image_base)
                return _instruction_payload(
                    data=data,
                    section=section,
                    raw_start=raw_start,
                    cursor=cursor,
                    length=prefix_len + 2 + parsed.operand_length,
                    mnemonic=mnemonic,
                    operands=operands,
                    extra=extra,
                )
        if opcode2 in (0x10, 0x11, 0x28, 0x29, 0x2E, 0x2F, 0x57, 0x58, 0x5B, 0x6F, 0x7F, 0xB6, 0xB7, 0xBE, 0xBF):
            if opcode2 in (0x10, 0x11):
                if prefixes.repeat == "REP":
                    mnemonic = "MOVSS"
                elif prefixes.repeat == "REPNE":
                    mnemonic = "MOVSD"
                else:
                    mnemonic = "MOVUPS"
                rm_size = 128
                reg_size = 128
                order = "reg,rm" if opcode2 == 0x10 else "rm,reg"
            elif opcode2 in (0x28, 0x29):
                mnemonic = "MOVAPS"
                rm_size = 128
                reg_size = 128
                order = "reg,rm" if opcode2 == 0x28 else "rm,reg"
            elif opcode2 in (0x2E, 0x2F):
                mnemonic = "UCOMISS" if opcode2 == 0x2E else "COMISS"
                rm_size = 128
                reg_size = 128
                order = "reg,rm"
            elif opcode2 == 0x57:
                mnemonic = "XORPS"
                rm_size = 128
                reg_size = 128
                order = "reg,rm"
            elif opcode2 == 0x58:
                if prefixes.repeat == "REP":
                    mnemonic = "ADDSS"
                elif prefixes.repeat == "REPNE":
                    mnemonic = "ADDSD"
                else:
                    mnemonic = "ADDPS"
                rm_size = 128
                reg_size = 128
                order = "reg,rm"
            elif opcode2 == 0x5B:
                mnemonic = "CVTDQ2PS"
                rm_size = 128
                reg_size = 128
                order = "reg,rm"
            elif opcode2 in (0x6F, 0x7F):
                mnemonic = "MOVDQA"
                rm_size = 128
                reg_size = 128
                order = "reg,rm" if opcode2 == 0x6F else "rm,reg"
            elif opcode2 in (0xB6, 0xB7):
                mnemonic = "MOVZX"
                rm_size = 8 if opcode2 == 0xB6 else 16
                reg_size = size
                order = "reg,rm"
            else:
                mnemonic = "MOVSX"
                rm_size = 8 if opcode2 == 0xBE else 16
                reg_size = size
                order = "reg,rm"
            parsed = _parse_modrm(
                data,
                prefixes=prefixes,
                opcode_offset=opcode_offset,
                operand_start=opcode_offset + 2,
                instruction_va=instruction_va,
                rm_size=rm_size,
                reg_size=reg_size,
            )
            if parsed is not None:
                operands = (
                    f"{parsed.reg_operand}, {parsed.rm_operand}"
                    if order == "reg,rm"
                    else f"{parsed.rm_operand}, {parsed.reg_operand}"
                )
                extra: dict[str, object] = {"_image_base": metadata.image_base}
                if parsed.memory_target_va is not None:
                    extra["memory_target_va"] = _hex(parsed.memory_target_va)
                    extra["memory_target_rva"] = _hex(parsed.memory_target_va - metadata.image_base)
                return _instruction_payload(
                    data=data,
                    section=section,
                    raw_start=raw_start,
                    cursor=cursor,
                    length=prefix_len + 2 + parsed.operand_length,
                    mnemonic=mnemonic,
                    operands=operands,
                    extra=extra,
                )

    accumulator_imm8_decoders = {
        0x04: "ADD",
        0x0C: "OR",
        0x14: "ADC",
        0x1C: "SBB",
        0x24: "AND",
        0x2C: "SUB",
        0x34: "XOR",
        0x3C: "CMP",
    }
    if opcode in accumulator_imm8_decoders and opcode_offset + 2 <= raw_end:
        immediate = data[opcode_offset + 1]
        return _instruction_payload(
            data=data,
            section=section,
            raw_start=raw_start,
            cursor=cursor,
            length=prefix_len + 2,
            mnemonic=accumulator_imm8_decoders[opcode],
            operands=f"AL, {_hex(immediate)}",
            extra={"_image_base": metadata.image_base, "immediate": immediate},
        )

    accumulator_imm_decoders = {
        0x05: "ADD",
        0x0D: "OR",
        0x15: "ADC",
        0x1D: "SBB",
        0x25: "AND",
        0x2D: "SUB",
        0x35: "XOR",
        0x3D: "CMP",
    }
    if opcode in accumulator_imm_decoders:
        imm_size = 2 if prefixes.operand16 else 4
        if opcode_offset + 1 + imm_size <= raw_end:
            immediate = int.from_bytes(data[opcode_offset + 1 : opcode_offset + 1 + imm_size], "little", signed=False)
            register = _register(0, size)
            return _instruction_payload(
                data=data,
                section=section,
                raw_start=raw_start,
                cursor=cursor,
                length=prefix_len + 1 + imm_size,
                mnemonic=accumulator_imm_decoders[opcode],
                operands=f"{register}, {_hex(immediate)}",
                extra={"_image_base": metadata.image_base, "immediate": immediate},
            )

    modrm_decoders = {
        0x01: ("ADD", "rm,reg"),
        0x03: ("ADD", "reg,rm"),
        0x09: ("OR", "rm,reg"),
        0x0B: ("OR", "reg,rm"),
        0x11: ("ADC", "rm,reg"),
        0x13: ("ADC", "reg,rm"),
        0x19: ("SBB", "rm,reg"),
        0x1B: ("SBB", "reg,rm"),
        0x21: ("AND", "rm,reg"),
        0x23: ("AND", "reg,rm"),
        0x29: ("SUB", "rm,reg"),
        0x2B: ("SUB", "reg,rm"),
        0x31: ("XOR", "rm,reg"),
        0x33: ("XOR", "reg,rm"),
        0x39: ("CMP", "rm,reg"),
        0x3B: ("CMP", "reg,rm"),
        0x85: ("TEST", "rm,reg"),
        0x87: ("XCHG", "rm,reg"),
        0x89: ("MOV", "rm,reg"),
        0x8B: ("MOV", "reg,rm"),
        0x8D: ("LEA", "reg,rm"),
    }
    if opcode in modrm_decoders:
        mnemonic, order = modrm_decoders[opcode]
        decoded = _decode_modrm_instruction(
            data,
            metadata=metadata,
            runtime_functions=runtime_functions,
            section=section,
            raw_start=raw_start,
            cursor=cursor,
            prefixes=prefixes,
            opcode=opcode,
            mnemonic=mnemonic,
            operand_order=order,
            rm_size=size,
            reg_size=size,
        )
        if decoded is not None:
            return decoded

    if opcode == 0x63:
        decoded = _decode_modrm_instruction(
            data,
            metadata=metadata,
            runtime_functions=runtime_functions,
            section=section,
            raw_start=raw_start,
            cursor=cursor,
            prefixes=prefixes,
            opcode=opcode,
            mnemonic="MOVSXD",
            operand_order="reg,rm",
            rm_size=32,
            reg_size=64 if prefixes.rex_w else size,
        )
        if decoded is not None:
            return decoded

    if opcode in (0x69, 0x6B):
        imm_size = 4 if opcode == 0x69 else 1
        parsed = _parse_modrm(
            data,
            prefixes=prefixes,
            opcode_offset=opcode_offset,
            operand_start=opcode_offset + 1,
            instruction_va=instruction_va,
            rm_size=size,
            reg_size=size,
            rip_relative_base_adjust=imm_size,
        )
        if parsed is not None:
            imm_offset = opcode_offset + 1 + parsed.operand_length
            if imm_offset + imm_size <= raw_end:
                immediate = (
                    struct.unpack_from("<i", data, imm_offset)[0]
                    if imm_size == 4
                    else struct.unpack_from("<b", data, imm_offset)[0]
                )
                extra: dict[str, object] = {"_image_base": metadata.image_base, "immediate": immediate}
                if parsed.memory_target_va is not None:
                    extra["memory_target_va"] = _hex(parsed.memory_target_va)
                    extra["memory_target_rva"] = _hex(parsed.memory_target_va - metadata.image_base)
                return _instruction_payload(
                    data=data,
                    section=section,
                    raw_start=raw_start,
                    cursor=cursor,
                    length=prefix_len + 1 + parsed.operand_length + imm_size,
                    mnemonic="IMUL",
                    operands=f"{parsed.reg_operand}, {parsed.rm_operand}, {_signed_hex(immediate)}",
                    extra=extra,
                )

    byte_modrm_decoders = {
        0x00: ("ADD", "rm,reg"),
        0x02: ("ADD", "reg,rm"),
        0x08: ("OR", "rm,reg"),
        0x0A: ("OR", "reg,rm"),
        0x10: ("ADC", "rm,reg"),
        0x12: ("ADC", "reg,rm"),
        0x18: ("SBB", "rm,reg"),
        0x1A: ("SBB", "reg,rm"),
        0x20: ("AND", "rm,reg"),
        0x22: ("AND", "reg,rm"),
        0x28: ("SUB", "rm,reg"),
        0x2A: ("SUB", "reg,rm"),
        0x30: ("XOR", "rm,reg"),
        0x32: ("XOR", "reg,rm"),
        0x38: ("CMP", "rm,reg"),
        0x3A: ("CMP", "reg,rm"),
        0x86: ("XCHG", "rm,reg"),
        0x88: ("MOV", "rm,reg"),
        0x8A: ("MOV", "reg,rm"),
    }
    if opcode in byte_modrm_decoders:
        mnemonic, order = byte_modrm_decoders[opcode]
        decoded = _decode_modrm_instruction(
            data,
            metadata=metadata,
            runtime_functions=runtime_functions,
            section=section,
            raw_start=raw_start,
            cursor=cursor,
            prefixes=prefixes,
            opcode=opcode,
            mnemonic=mnemonic,
            operand_order=order,
            rm_size=8,
            reg_size=8,
        )
        if decoded is not None:
            return decoded

    if opcode == 0x84:
        decoded = _decode_modrm_instruction(
            data,
            metadata=metadata,
            runtime_functions=runtime_functions,
            section=section,
            raw_start=raw_start,
            cursor=cursor,
            prefixes=prefixes,
            opcode=opcode,
            mnemonic="TEST",
            operand_order="rm,reg",
            rm_size=8,
            reg_size=8,
        )
        if decoded is not None:
            return decoded

    if opcode in (0x80, 0x81, 0x83, 0xC6, 0xC7):
        rm_size = 8 if opcode in (0x80, 0xC6) else size
        imm_size = 1 if opcode in (0x80, 0x83, 0xC6) else _full_width_immediate_size(size)
        parsed = _parse_modrm(
            data,
            prefixes=prefixes,
            opcode_offset=opcode_offset,
            operand_start=opcode_offset + 1,
            instruction_va=instruction_va,
            rm_size=rm_size,
            rip_relative_base_adjust=imm_size,
        )
        if parsed is not None:
            imm_offset = opcode_offset + 1 + parsed.operand_length
            if imm_offset + imm_size <= raw_end:
                immediate = (
                    struct.unpack_from("<b", data, imm_offset)[0]
                    if imm_size == 1 and opcode == 0x83
                    else int.from_bytes(data[imm_offset : imm_offset + imm_size], "little", signed=False)
                )
                if opcode in (0xC6, 0xC7):
                    mnemonic = "MOV"
                else:
                    mnemonic = _GROUP1_MNEMONICS.get(parsed.reg, "GRP1")
                extra: dict[str, object] = {"_image_base": metadata.image_base, "immediate": immediate}
                if parsed.memory_target_va is not None:
                    extra["memory_target_va"] = _hex(parsed.memory_target_va)
                    extra["memory_target_rva"] = _hex(parsed.memory_target_va - metadata.image_base)
                return _instruction_payload(
                    data=data,
                    section=section,
                    raw_start=raw_start,
                    cursor=cursor,
                    length=prefix_len + 1 + parsed.operand_length + imm_size,
                    mnemonic=mnemonic,
                    operands=f"{parsed.rm_operand}, {_signed_hex(immediate)}" if immediate < 0 else f"{parsed.rm_operand}, {_hex(immediate)}",
                    extra=extra,
                )

    if opcode in (0xF6, 0xF7):
        rm_size = 8 if opcode == 0xF6 else size
        parsed = _parse_modrm(
            data,
            prefixes=prefixes,
            opcode_offset=opcode_offset,
            operand_start=opcode_offset + 1,
            instruction_va=instruction_va,
            rm_size=rm_size,
        )
        if parsed is not None:
            group = parsed.reg & 0x7
            if group in (0x0, 0x1):
                imm_offset = opcode_offset + 1 + parsed.operand_length
                imm_size = 1 if opcode == 0xF6 else _full_width_immediate_size(size)
                if imm_offset + imm_size <= raw_end:
                    immediate = int.from_bytes(data[imm_offset : imm_offset + imm_size], "little", signed=False)
                    return _instruction_payload(
                        data=data,
                        section=section,
                        raw_start=raw_start,
                        cursor=cursor,
                        length=prefix_len + 1 + parsed.operand_length + imm_size,
                        mnemonic="TEST",
                        operands=f"{parsed.rm_operand}, {_hex(immediate)}",
                        extra={"_image_base": metadata.image_base, "immediate": immediate},
                    )
            mnemonic = {
                0x2: "NOT",
                0x3: "NEG",
                0x4: "MUL",
                0x5: "IMUL",
                0x6: "DIV",
                0x7: "IDIV",
            }.get(group)
            if mnemonic is not None:
                return _instruction_payload(
                    data=data,
                    section=section,
                    raw_start=raw_start,
                    cursor=cursor,
                    length=prefix_len + 1 + parsed.operand_length,
                    mnemonic=mnemonic,
                    operands=parsed.rm_operand,
                    extra={"_image_base": metadata.image_base},
                )

    if opcode in (0xC0, 0xC1, 0xD0, 0xD1, 0xD2, 0xD3):
        rm_size = 8 if opcode in (0xC0, 0xD0, 0xD2) else size
        parsed = _parse_modrm(
            data,
            prefixes=prefixes,
            opcode_offset=opcode_offset,
            operand_start=opcode_offset + 1,
            instruction_va=instruction_va,
            rm_size=rm_size,
        )
        if parsed is not None:
            mnemonic = {
                0x0: "ROL",
                0x1: "ROR",
                0x2: "RCL",
                0x3: "RCR",
                0x4: "SHL",
                0x5: "SHR",
                0x7: "SAR",
            }.get(parsed.reg & 0x7, "SHIFT")
            if opcode in (0xC0, 0xC1):
                imm_offset = opcode_offset + 1 + parsed.operand_length
                if imm_offset + 1 <= raw_end:
                    immediate = data[imm_offset]
                    return _instruction_payload(
                        data=data,
                        section=section,
                        raw_start=raw_start,
                        cursor=cursor,
                        length=prefix_len + 1 + parsed.operand_length + 1,
                        mnemonic=mnemonic,
                        operands=f"{parsed.rm_operand}, {_hex(immediate)}",
                        extra={"_image_base": metadata.image_base, "immediate": immediate},
                    )
            count_operand = "1" if opcode in (0xD0, 0xD1) else "CL"
            return _instruction_payload(
                data=data,
                section=section,
                raw_start=raw_start,
                cursor=cursor,
                length=prefix_len + 1 + parsed.operand_length,
                mnemonic=mnemonic,
                operands=f"{parsed.rm_operand}, {count_operand}",
                extra={"_image_base": metadata.image_base},
            )

    if opcode == 0xFE:
        parsed = _parse_modrm(
            data,
            prefixes=prefixes,
            opcode_offset=opcode_offset,
            operand_start=opcode_offset + 1,
            instruction_va=instruction_va,
            rm_size=8,
        )
        if parsed is not None:
            mnemonic = {0x0: "INC", 0x1: "DEC"}.get(parsed.reg & 0x7)
            if mnemonic is not None:
                if prefixes.lock and parsed.mod != 0x3:
                    mnemonic = f"{mnemonic}.LOCK"
                return _instruction_payload(
                    data=data,
                    section=section,
                    raw_start=raw_start,
                    cursor=cursor,
                    length=prefix_len + 1 + parsed.operand_length,
                    mnemonic=mnemonic,
                    operands=parsed.rm_operand,
                    extra={"_image_base": metadata.image_base},
                )

    if opcode == 0xFF:
        parsed = _parse_modrm(
            data,
            prefixes=prefixes,
            opcode_offset=opcode_offset,
            operand_start=opcode_offset + 1,
            instruction_va=instruction_va,
            rm_size=size,
        )
        if parsed is not None:
            group = parsed.reg & 0x7
            mnemonic = {0x0: "INC", 0x1: "DEC", 0x4: "JMP", 0x6: "PUSH"}.get(group)
            if mnemonic is not None:
                if prefixes.lock and mnemonic in ("INC", "DEC") and parsed.mod != 0x3:
                    mnemonic = f"{mnemonic}.LOCK"
                if mnemonic in ("JMP", "PUSH") and size != 64:
                    parsed64 = _parse_modrm(
                        data,
                        prefixes=prefixes,
                        opcode_offset=opcode_offset,
                        operand_start=opcode_offset + 1,
                        instruction_va=instruction_va,
                        rm_size=64,
                    )
                    if parsed64 is not None:
                        parsed = parsed64
                kind = "branch" if mnemonic == "JMP" else "decoded"
                return _instruction_payload(
                    data=data,
                    section=section,
                    raw_start=raw_start,
                    cursor=cursor,
                    length=prefix_len + 1 + parsed.operand_length,
                    mnemonic=mnemonic,
                    operands=parsed.rm_operand,
                    kind=kind,
                    extra={"_image_base": metadata.image_base},
                )

    return _instruction_payload(
        data=data,
        section=section,
        raw_start=raw_start,
        cursor=cursor,
        length=1,
        mnemonic="DB",
        operands=_hex(data[cursor]),
        kind="unknown",
        extra={"_image_base": metadata.image_base},
    )


def _scan_window(
    data: bytes,
    metadata: PEMetadata,
    runtime_functions: list[object],
    spec: WindowSpec,
) -> tuple[dict[str, object], str | None]:
    section = metadata.section_for_va(spec.start_va)
    if section is None:
        return (
            {
                "request": spec.request,
                "start_va": _hex(spec.start_va),
                "start_rva": _hex(spec.start_va - metadata.image_base),
                "instructions": [],
                "decoded_instruction_count": 0,
                "decoded_byte_count": 0,
                "stopped_reason": "unmapped-start",
            },
            f"Window {spec.request!r} starts outside mapped PE sections.",
        )

    start_offset = metadata.rva_to_offset(spec.start_va - metadata.image_base)
    section_raw_end = min(len(data), section.raw_pointer + section.scan_size)
    requested_end_offset = section_raw_end
    if spec.end_va is not None:
        end_section = metadata.section_for_va(spec.end_va - 1)
        if end_section is None or end_section.name != section.name:
            requested_end_offset = section_raw_end
        else:
            requested_end_offset = metadata.rva_to_offset(spec.end_va - metadata.image_base - 1) + 1

    containing = _runtime_payload_for_va(metadata, runtime_functions, spec.start_va)
    instructions: list[dict[str, object]] = []
    cursor = start_offset
    stopped_reason = "instruction-count"
    while cursor < requested_end_offset:
        if spec.instruction_count is not None and len(instructions) >= spec.instruction_count:
            break
        instruction = _decode_instruction_at(data, metadata, runtime_functions, section, section.raw_pointer, cursor, requested_end_offset)
        length = max(1, int(instruction["length"]))
        instructions.append(instruction)
        cursor += length
        if spec.end_va is not None and cursor >= requested_end_offset:
            stopped_reason = "end-address"
            break
        if cursor >= section_raw_end:
            stopped_reason = "section-end"
            break

    decoded_bytes = 0
    if instructions:
        first_offset = int(str(instructions[0]["raw_offset"]), 0)
        last = instructions[-1]
        decoded_bytes = int(str(last["raw_offset"]), 0) + int(last["length"]) - first_offset

    payload: dict[str, object] = {
        "request": spec.request,
        "start_va": _hex(spec.start_va),
        "start_rva": _hex(spec.start_va - metadata.image_base),
        "section": section.name,
        "decoded_instruction_count": len(instructions),
        "decoded_byte_count": decoded_bytes,
        "stopped_reason": stopped_reason,
        "instructions": instructions,
    }
    if spec.instruction_count is not None:
        payload["requested_instruction_count"] = spec.instruction_count
    if spec.end_va is not None:
        payload["end_va"] = _hex(spec.end_va)
        payload["end_rva"] = _hex(spec.end_va - metadata.image_base)
    if containing is not None:
        payload["containing_function"] = containing
    return payload, None


def find_pe_instructions(path: str | Path, windows: list[str]) -> dict[str, object]:
    target_path = Path(path)
    data = target_path.read_bytes()
    metadata = read_pe_metadata(data)
    runtime_functions = read_pe_runtime_functions(data, metadata)
    specs = [_parse_window_spec(window, metadata) for window in windows]

    results: list[dict[str, object]] = []
    warnings: list[str] = []
    decoded_instruction_count = 0
    decoded_byte_count = 0
    for spec in specs:
        window, warning = _scan_window(data, metadata, runtime_functions, spec)
        results.append(window)
        if warning is not None:
            warnings.append(warning)
        decoded_instruction_count += int(window.get("decoded_instruction_count", 0))
        decoded_byte_count += int(window.get("decoded_byte_count", 0))

    return {
        "type": "pe-instructions",
        "target": str(target_path),
        "image_base": _hex(metadata.image_base),
        "scan": {
            "window_count": len(specs),
            "decoded_instruction_count": decoded_instruction_count,
            "decoded_byte_count": decoded_byte_count,
            "runtime_function_count": len(runtime_functions),
        },
        "windows": results,
        "warnings": warnings,
    }
