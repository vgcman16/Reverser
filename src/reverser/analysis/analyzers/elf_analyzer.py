from __future__ import annotations

import struct
from pathlib import Path

from reverser.analysis.analyzers.base import Analyzer
from reverser.models import AnalysisReport


ELF_TYPES = {
    0: "none",
    1: "relocatable",
    2: "executable",
    3: "shared-object",
    4: "core",
}
ELF_MACHINES = {
    0x03: "x86",
    0x3E: "x64",
    0x28: "arm",
    0xB7: "arm64",
}
ELF_OSABI = {
    0: "system-v",
    3: "linux",
    6: "solaris",
    9: "freebsd",
}


class ELFAnalyzer(Analyzer):
    name = "elf"

    def supports(self, target: Path) -> bool:
        if not target.is_file():
            return False
        with target.open("rb") as handle:
            return handle.read(4) == b"\x7fELF"

    def analyze(self, target: Path, report: AnalysisReport) -> None:
        data = target.read_bytes()
        elf_class = data[4]
        elf_data = data[5]
        endian = "<" if elf_data == 1 else ">"

        if elf_class == 1:
            header = struct.unpack_from(f"{endian}HHIIIIIHHHHHH", data, 16)
            entry_point = header[3]
            program_header_offset = header[4]
            section_header_offset = header[5]
            program_header_count = header[9]
            section_header_count = header[11]
            section_name_index = header[12]
        else:
            header = struct.unpack_from(f"{endian}HHIQQQIHHHHHH", data, 16)
            entry_point = header[3]
            program_header_offset = header[4]
            section_header_offset = header[5]
            program_header_count = header[9]
            section_header_count = header[11]
            section_name_index = header[12]

        section_names = self._parse_section_names(
            data,
            elf_class=elf_class,
            endian=endian,
            section_header_offset=section_header_offset,
            section_header_count=section_header_count,
            section_name_index=section_name_index,
        )

        report.add_section(
            "elf",
            {
                "class": "elf64" if elf_class == 2 else "elf32",
                "endianness": "little" if elf_data == 1 else "big",
                "osabi": ELF_OSABI.get(data[7], str(data[7])),
                "type": ELF_TYPES.get(header[0], str(header[0])),
                "machine": ELF_MACHINES.get(header[1], hex(header[1])),
                "entry_point": hex(entry_point),
                "program_header_offset": program_header_offset,
                "section_header_offset": section_header_offset,
                "program_header_count": program_header_count,
                "section_header_count": section_header_count,
                "sections": section_names,
            },
        )

    def _parse_section_names(
        self,
        data: bytes,
        *,
        elf_class: int,
        endian: str,
        section_header_offset: int,
        section_header_count: int,
        section_name_index: int,
    ) -> list[dict[str, object]]:
        if section_header_count <= 0 or section_name_index <= 0:
            return []

        if elf_class == 1:
            entry_size = 40
            section_format = f"{endian}IIIIIIIIII"
            offset_index = 4
            size_index = 5
        else:
            entry_size = 64
            section_format = f"{endian}IIQQQQIIQQ"
            offset_index = 4
            size_index = 5

        string_section_offset = section_header_offset + section_name_index * entry_size
        if string_section_offset + entry_size > len(data):
            return []

        string_section = struct.unpack_from(section_format, data, string_section_offset)
        string_table_offset = int(string_section[offset_index])
        string_table_size = int(string_section[size_index])
        string_table = data[string_table_offset : string_table_offset + string_table_size]

        sections: list[dict[str, object]] = []
        for index in range(min(section_header_count, 40)):
            offset = section_header_offset + index * entry_size
            if offset + entry_size > len(data):
                break
            entry = struct.unpack_from(section_format, data, offset)
            name_offset = int(entry[0])
            name = self._read_string(string_table, name_offset)
            sections.append({"index": index, "name": name or f"section-{index}"})

        return sections

    @staticmethod
    def _read_string(string_table: bytes, offset: int) -> str:
        if offset >= len(string_table):
            return ""
        end = string_table.find(b"\x00", offset)
        if end == -1:
            end = len(string_table)
        return string_table[offset:end].decode("utf-8", errors="replace")
