from __future__ import annotations

import math
import struct
from pathlib import Path

from reverser.analysis.analyzers.base import Analyzer
from reverser.models import AnalysisReport


MACHINE_TYPES = {
    0x14C: "x86",
    0x8664: "x64",
    0x1C0: "arm",
    0xAA64: "arm64",
}

SUBSYSTEMS = {
    1: "native",
    2: "windows-gui",
    3: "windows-cui",
    5: "os2-cui",
    7: "posix-cui",
    9: "windows-ce-gui",
    10: "efi-app",
}


def _section_entropy(section_bytes: bytes) -> float:
    if not section_bytes:
        return 0.0
    counts = [0] * 256
    for byte in section_bytes:
        counts[byte] += 1
    total = len(section_bytes)
    entropy = 0.0
    for count in counts:
        if count:
            probability = count / total
            entropy -= probability * math.log2(probability)
    return entropy


def _rva_to_offset(sections: list[dict[str, int | str]], rva: int) -> int | None:
    for section in sections:
        virtual_address = int(section["virtual_address"])
        virtual_size = max(int(section["virtual_size"]), int(section["raw_size"]))
        if virtual_address <= rva < virtual_address + virtual_size:
            return int(section["raw_pointer"]) + (rva - virtual_address)
    return None


def _read_c_string(data: bytes, offset: int | None) -> str:
    if offset is None or offset >= len(data):
        return "<invalid>"
    end = data.find(b"\x00", offset)
    if end == -1:
        end = len(data)
    return data[offset:end].decode("ascii", errors="replace")


class PEAnalyzer(Analyzer):
    name = "portable-executable"

    def supports(self, target: Path) -> bool:
        return target.is_file() and target.read_bytes()[:2] == b"MZ"

    def analyze(self, target: Path, report: AnalysisReport) -> None:
        data = target.read_bytes()
        if len(data) < 0x100:
            report.warn("PE file is too small for full header parsing.")
            return

        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
        if data[pe_offset : pe_offset + 4] != b"PE\x00\x00":
            report.warn("Target begins with MZ but does not contain a valid PE header.")
            return

        coff_offset = pe_offset + 4
        machine, section_count, timestamp, _, _, optional_header_size, characteristics = struct.unpack_from(
            "<HHIIIHH", data, coff_offset
        )

        optional_offset = coff_offset + 20
        magic = struct.unpack_from("<H", data, optional_offset)[0]
        is_pe32_plus = magic == 0x20B
        entry_point = struct.unpack_from("<I", data, optional_offset + 16)[0]
        image_base = struct.unpack_from("<Q" if is_pe32_plus else "<I", data, optional_offset + 24)[0]
        subsystem = struct.unpack_from("<H", data, optional_offset + 68)[0]
        number_of_rva_and_sizes = struct.unpack_from("<I", data, optional_offset + (108 if is_pe32_plus else 92))[0]
        directory_offset = optional_offset + (112 if is_pe32_plus else 96)

        data_directories = []
        for index in range(min(number_of_rva_and_sizes, 16)):
            rva, size = struct.unpack_from("<II", data, directory_offset + index * 8)
            data_directories.append({"index": index, "rva": rva, "size": size})

        section_offset = optional_offset + optional_header_size
        sections: list[dict[str, int | str | float]] = []
        for index in range(section_count):
            start = section_offset + index * 40
            raw_name = data[start : start + 8]
            name = raw_name.split(b"\x00", 1)[0].decode("ascii", errors="ignore")
            (
                virtual_size,
                virtual_address,
                raw_size,
                raw_pointer,
                _,
                _,
                _,
                _,
                characteristics_bits,
            ) = struct.unpack_from("<IIIIIIHHI", data, start + 8)
            section_bytes = data[raw_pointer : raw_pointer + raw_size]
            sections.append(
                {
                    "name": name or f"section-{index}",
                    "virtual_size": virtual_size,
                    "virtual_address": virtual_address,
                    "raw_size": raw_size,
                    "raw_pointer": raw_pointer,
                    "characteristics": characteristics_bits,
                    "entropy": round(_section_entropy(section_bytes), 4),
                }
            )

        imports = self._parse_imports(data, sections, data_directories, is_pe32_plus)
        report.add_section(
            "pe",
            {
                "machine": MACHINE_TYPES.get(machine, hex(machine)),
                "section_count": section_count,
                "timestamp": timestamp,
                "optional_header_size": optional_header_size,
                "characteristics": hex(characteristics),
                "format": "pe32+" if is_pe32_plus else "pe32",
                "entry_point_rva": hex(entry_point),
                "image_base": hex(image_base),
                "subsystem": SUBSYSTEMS.get(subsystem, str(subsystem)),
                "imports": imports,
                "sections": sections,
            },
        )

        if imports:
            high_signal = [item for item in imports if item["dll"].lower() in {"ws2_32.dll", "wininet.dll", "advapi32.dll"}]
            if high_signal:
                report.add_finding(
                    "pe",
                    "Interesting Windows imports",
                    "The PE imports networking or security-sensitive Windows APIs.",
                    severity="medium",
                    imports=high_signal,
                )

    def _parse_imports(
        self,
        data: bytes,
        sections: list[dict[str, int | str | float]],
        directories: list[dict[str, int]],
        is_pe32_plus: bool,
    ) -> list[dict[str, object]]:
        if len(directories) < 2:
            return []

        import_directory = directories[1]
        if not import_directory["rva"]:
            return []

        descriptor_offset = _rva_to_offset(sections, import_directory["rva"])
        if descriptor_offset is None:
            return []

        imports: list[dict[str, object]] = []
        cursor = descriptor_offset
        step = 8 if is_pe32_plus else 4
        ordinal_flag = 1 << (63 if is_pe32_plus else 31)

        while cursor + 20 <= len(data):
            original_first_thunk, _, _, name_rva, first_thunk = struct.unpack_from("<IIIII", data, cursor)
            if not any((original_first_thunk, name_rva, first_thunk)):
                break

            name_offset = _rva_to_offset(sections, name_rva)
            dll_name = _read_c_string(data, name_offset) if name_offset is not None else "<unknown>"
            thunk_rva = original_first_thunk or first_thunk
            thunk_offset = _rva_to_offset(sections, thunk_rva)

            functions: list[str] = []
            if thunk_offset is not None:
                for index in range(128):
                    item_offset = thunk_offset + index * step
                    if item_offset + step > len(data):
                        break
                    value = struct.unpack_from("<Q" if is_pe32_plus else "<I", data, item_offset)[0]
                    if value == 0:
                        break
                    if value & ordinal_flag:
                        functions.append(f"ordinal:{value & 0xFFFF}")
                        continue
                    hint_name_offset = _rva_to_offset(sections, int(value))
                    if hint_name_offset is not None:
                        functions.append(_read_c_string(data, hint_name_offset + 2))

            imports.append({"dll": dll_name, "functions": functions[:40], "function_count": len(functions)})
            cursor += 20

        return imports
