from __future__ import annotations

import struct
import zlib
from pathlib import Path


NETDRAGON_MAGIC = b"NetDragonDatPkg\x00"


def build_netdragon_pair(
    root: Path,
    *,
    stem: str = "data",
    entries: list[tuple[str, bytes]] | None = None,
) -> tuple[Path, Path]:
    payload_entries = entries or [
        ("data/demo.txt", b"hello from netdragon"),
        ("data/image.dds", b"DDS " + b"\x00" * 124),
    ]

    common_header = NETDRAGON_MAGIC + struct.pack("<IIII", 1000, 0, 1, 3)
    table = bytearray()
    payload = bytearray(common_header)
    offset = len(common_header)

    for relative_path, decoded_bytes in payload_entries:
        path_bytes = relative_path.encode("ascii")
        stored_bytes = zlib.compress(decoded_bytes)
        table.extend(
            bytes([len(path_bytes)])
            + path_bytes
            + struct.pack(
                "<HIIIII",
                1,
                len(decoded_bytes),
                len(stored_bytes),
                len(stored_bytes),
                len(decoded_bytes),
                offset,
            )
        )
        payload.extend(stored_bytes)
        offset += len(stored_bytes)

    tpd_path = root / f"{stem}.tpd"
    tpi_path = root / f"{stem}.tpi"
    tpd_path.write_bytes(bytes(payload))
    tpi_path.write_bytes(common_header + struct.pack("<IIII", 0x30, len(payload_entries), len(table), 0) + bytes(table))
    return tpi_path, tpd_path
