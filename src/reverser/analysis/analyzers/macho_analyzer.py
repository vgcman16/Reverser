from __future__ import annotations

import struct
from pathlib import Path

from reverser.analysis.analyzers.base import Analyzer
from reverser.models import AnalysisReport


MAGIC_TABLE = {
    0xFEEDFACE: ("mach-o-32", ">"),
    0xCEFAEDFE: ("mach-o-32", "<"),
    0xFEEDFACF: ("mach-o-64", ">"),
    0xCFFAEDFE: ("mach-o-64", "<"),
}
CPU_TYPES = {
    7: "x86",
    12: "arm",
    18: "ppc",
    0x01000007: "x64",
    0x0100000C: "arm64",
}
FILE_TYPES = {
    1: "object",
    2: "executable",
    3: "fvmlib",
    4: "core",
    5: "preload",
    6: "dylib",
    7: "dylinker",
    8: "bundle",
}
LOAD_COMMANDS = {
    0x1: "segment",
    0x2: "symtab",
    0x19: "segment_64",
    0x1B: "uuid",
    0x24: "version_min_macosx",
    0x32: "build_version",
    0x80000022: "dyld_info_only",
    0x80000028: "main",
}


class MachOAnalyzer(Analyzer):
    name = "mach-o"

    def supports(self, target: Path) -> bool:
        if not target.is_file():
            return False
        with target.open("rb") as handle:
            header = handle.read(4)
        if len(header) < 4:
            return False
        magic = struct.unpack(">I", header)[0]
        return magic in MAGIC_TABLE

    def analyze(self, target: Path, report: AnalysisReport) -> None:
        data = target.read_bytes()
        magic = struct.unpack_from(">I", data, 0)[0]
        format_name, endian = MAGIC_TABLE[magic]
        is_64 = format_name.endswith("64")

        if is_64:
            cpu_type, cpu_subtype, file_type, ncmds, sizeofcmds, flags, reserved = struct.unpack_from(
                f"{endian}iiiiiii", data, 4
            )
            header_size = 32
        else:
            cpu_type, cpu_subtype, file_type, ncmds, sizeofcmds, flags = struct.unpack_from(
                f"{endian}iiiiii", data, 4
            )
            reserved = None
            header_size = 28

        load_commands = []
        cursor = header_size
        for _ in range(min(max(ncmds, 0), 20)):
            if cursor + 8 > len(data):
                break
            cmd, cmdsize = struct.unpack_from(f"{endian}II", data, cursor)
            load_commands.append(
                {
                    "command": LOAD_COMMANDS.get(cmd, hex(cmd)),
                    "size": cmdsize,
                }
            )
            if cmdsize <= 0:
                break
            cursor += cmdsize

        report.add_section(
            "macho",
            {
                "format": format_name,
                "endianness": "little" if endian == "<" else "big",
                "cpu_type": CPU_TYPES.get(cpu_type, hex(cpu_type)),
                "cpu_subtype": cpu_subtype,
                "file_type": FILE_TYPES.get(file_type, str(file_type)),
                "load_command_count": ncmds,
                "load_command_bytes": sizeofcmds,
                "flags": hex(flags),
                "reserved": reserved,
                "load_commands": load_commands,
            },
        )
