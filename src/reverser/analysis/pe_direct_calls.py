from __future__ import annotations

import struct
from dataclasses import dataclass
from pathlib import Path


IMAGE_SCN_MEM_EXECUTE = 0x20000000


@dataclass(frozen=True)
class PESection:
    name: str
    virtual_address: int
    virtual_size: int
    raw_pointer: int
    raw_size: int
    characteristics: int

    @property
    def scan_size(self) -> int:
        return min(self.raw_size, max(self.virtual_size, self.raw_size))

    @property
    def is_executable(self) -> bool:
        return bool(self.characteristics & IMAGE_SCN_MEM_EXECUTE)

    def contains_rva(self, rva: int) -> bool:
        span_size = max(self.virtual_size, self.raw_size)
        return self.virtual_address <= rva < self.virtual_address + span_size

    def rva_to_offset(self, rva: int) -> int:
        if not self.contains_rva(rva):
            raise ValueError(f"RVA {_hex(rva)} is not in section {self.name}.")
        delta = rva - self.virtual_address
        if delta >= self.raw_size:
            raise ValueError(f"RVA {_hex(rva)} is in virtual-only data for section {self.name}.")
        return self.raw_pointer + delta


@dataclass(frozen=True)
class PEMetadata:
    image_base: int
    sections: tuple[PESection, ...]

    def normalize_va_or_rva(self, value: int) -> tuple[int, int]:
        if value >= self.image_base:
            return value, value - self.image_base
        return self.image_base + value, value

    def section_for_rva(self, rva: int) -> PESection | None:
        for section in self.sections:
            if section.contains_rva(rva):
                return section
        return None

    def section_for_va(self, va: int) -> PESection | None:
        if va < self.image_base:
            return None
        return self.section_for_rva(va - self.image_base)

    def rva_to_offset(self, rva: int) -> int:
        section = self.section_for_rva(rva)
        if section is None:
            raise ValueError(f"RVA {_hex(rva)} is not mapped by any section.")
        return section.rva_to_offset(rva)


def parse_int_literal(value: str) -> int:
    return int(str(value), 0)


def read_pe_metadata(data: bytes) -> PEMetadata:
    if len(data) < 0x100 or data[:2] != b"MZ":
        raise ValueError("Target is not a PE file.")

    pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    if pe_offset + 4 > len(data) or data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
        raise ValueError("Target begins with MZ but has no valid PE signature.")

    coff_offset = pe_offset + 4
    _, section_count, _, _, _, optional_header_size, _ = struct.unpack_from("<HHIIIHH", data, coff_offset)
    optional_offset = coff_offset + 20
    magic = struct.unpack_from("<H", data, optional_offset)[0]
    is_pe32_plus = magic == 0x20B
    image_base = struct.unpack_from("<Q" if is_pe32_plus else "<I", data, optional_offset + 24)[0]

    section_offset = optional_offset + optional_header_size
    sections: list[PESection] = []
    for index in range(section_count):
        start = section_offset + index * 40
        if start + 40 > len(data):
            break
        raw_name = data[start : start + 8]
        name = raw_name.split(b"\x00", 1)[0].decode("ascii", errors="replace") or f"section-{index}"
        (
            virtual_size,
            virtual_address,
            raw_size,
            raw_pointer,
            _,
            _,
            _,
            _,
            characteristics,
        ) = struct.unpack_from("<IIIIIIHHI", data, start + 8)
        sections.append(
            PESection(
                name=name,
                virtual_address=virtual_address,
                virtual_size=virtual_size,
                raw_pointer=raw_pointer,
                raw_size=raw_size,
                characteristics=characteristics,
            )
        )

    return PEMetadata(image_base=image_base, sections=tuple(sections))


def _normalize_target(value: int, image_base: int) -> tuple[int, int]:
    if value >= image_base:
        return value, value - image_base
    return image_base + value, value


def _hex(value: int) -> str:
    return f"0x{value:x}"


def find_pe_direct_calls(path: str | Path, targets: list[str | int]) -> dict[str, object]:
    from reverser.analysis.pe_runtime_functions import (
        function_for_rva,
        read_pe_runtime_functions,
        runtime_function_to_dict,
    )

    target_path = Path(path)
    data = target_path.read_bytes()
    metadata = read_pe_metadata(data)
    normalized_targets = [_normalize_target(parse_int_literal(str(target)), metadata.image_base) for target in targets]
    target_by_va = {va: rva for va, rva in normalized_targets}
    calls_by_target: dict[int, list[dict[str, object]]] = {va: [] for va, _ in normalized_targets}
    direct_call_count = 0
    runtime_functions = read_pe_runtime_functions(data, metadata)

    executable_sections = [section for section in metadata.sections if section.is_executable and section.raw_size > 0]
    for section in executable_sections:
        raw_start = section.raw_pointer
        raw_end = min(len(data), raw_start + section.scan_size)
        cursor = raw_start
        while cursor + 5 <= raw_end:
            if data[cursor] != 0xE8:
                cursor += 1
                continue

            direct_call_count += 1
            rel32 = struct.unpack_from("<i", data, cursor + 1)[0]
            call_rva = section.virtual_address + (cursor - raw_start)
            call_va = metadata.image_base + call_rva
            target_va = call_va + 5 + rel32
            if target_va in target_by_va:
                call: dict[str, object] = {
                    "callsite_va": _hex(call_va),
                    "callsite_rva": _hex(call_rva),
                    "target_va": _hex(target_va),
                    "target_rva": _hex(target_by_va[target_va]),
                    "rel32": rel32,
                    "section": section.name,
                    "raw_offset": _hex(cursor),
                    "instruction": f"CALL {_hex(target_va)}",
                }
                function = function_for_rva(runtime_functions, call_rva)
                if function is not None:
                    call["function"] = runtime_function_to_dict(function, metadata)
                calls_by_target[target_va].append(call)
            cursor += 1

    return {
        "type": "pe-direct-calls",
        "target": str(target_path),
        "image_base": _hex(metadata.image_base),
        "scan": {
            "executable_section_count": len(executable_sections),
            "direct_call_opcode_count": direct_call_count,
            "runtime_function_count": len(runtime_functions),
            "executable_sections": [
                {
                    "name": section.name,
                    "virtual_address": _hex(section.virtual_address),
                    "virtual_size": _hex(section.virtual_size),
                    "raw_pointer": _hex(section.raw_pointer),
                    "raw_size": _hex(section.raw_size),
                }
                for section in executable_sections
            ],
        },
        "results": [
            {
                "target_va": _hex(va),
                "target_rva": _hex(rva),
                "hit_count": len(calls_by_target[va]),
                "calls": calls_by_target[va],
            }
            for va, rva in normalized_targets
        ],
    }
