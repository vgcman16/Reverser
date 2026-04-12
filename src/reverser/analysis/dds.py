from __future__ import annotations

from pathlib import Path


DDS_MAGIC = b"DDS "
DDS_HEADER_SIZE = 128


def parse_dds_file(path: Path) -> dict[str, object]:
    return parse_dds_bytes(path.read_bytes(), path=path)


def parse_dds_bytes(data: bytes, *, path: Path | None = None) -> dict[str, object]:
    if len(data) < DDS_HEADER_SIZE or not data.startswith(DDS_MAGIC):
        raise ValueError("Not a DDS texture.")

    fourcc_raw = data[84:88]
    dxgi_format = int.from_bytes(data[128:132], "little") if fourcc_raw == b"DX10" and len(data) >= 148 else None

    return {
        "format": "dds",
        "resource_kind": "texture",
        "path": str(path) if path else None,
        "file_size_bytes": len(data),
        "header_size": int.from_bytes(data[4:8], "little"),
        "flags": int.from_bytes(data[8:12], "little"),
        "height": int.from_bytes(data[12:16], "little"),
        "width": int.from_bytes(data[16:20], "little"),
        "pitch_or_linear_size": int.from_bytes(data[20:24], "little"),
        "depth": int.from_bytes(data[24:28], "little"),
        "mipmap_count": int.from_bytes(data[28:32], "little"),
        "pixel_format_size": int.from_bytes(data[76:80], "little"),
        "pixel_format_flags": int.from_bytes(data[80:84], "little"),
        "fourcc": _decode_fourcc(fourcc_raw),
        "rgb_bit_count": int.from_bytes(data[88:92], "little"),
        "caps": int.from_bytes(data[108:112], "little"),
        "caps2": int.from_bytes(data[112:116], "little"),
        "dxgi_format": dxgi_format,
        "header_head_hex": data[:64].hex(),
    }


def _decode_fourcc(raw: bytes) -> str | None:
    if raw == b"\x00\x00\x00\x00":
        return None

    if all(32 <= byte < 127 for byte in raw):
        return raw.decode("ascii", errors="replace").rstrip()

    return raw.hex()
