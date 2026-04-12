from __future__ import annotations

import shutil
import subprocess
import tarfile
import zipfile
from pathlib import Path

from reverser.analysis.analyzers.base import Analyzer
from reverser.models import AnalysisReport

try:
    import py7zr
    from py7zr.compressor import SupportedMethods
    from py7zr.exceptions import Bad7zFile, PasswordRequired
except ImportError:  # pragma: no cover - exercised by runtime fallback behavior
    py7zr = None
    SupportedMethods = None
    Bad7zFile = ValueError
    PasswordRequired = ValueError


ARCHIVE_EXTENSIONS = {".zip", ".tar", ".gz", ".tgz", ".bz2", ".tbz", ".xz", ".txz", ".7z"}
SEVEN_ZIP_MAGIC = b"7z\xbc\xaf\x27\x1c"
SEVEN_ZIP_CLI_CANDIDATES = ("7z", "7za", "7zr")
MAX_MEMBER_SAMPLE = 50
METHOD_NAMES_BY_ID = {
    method["id"]: str(method["name"])
    for method in (SupportedMethods.methods if SupportedMethods is not None else [])
}


def looks_like_7z_archive(path: Path) -> bool:
    try:
        with path.open("rb") as handle:
            return handle.read(len(SEVEN_ZIP_MAGIC)) == SEVEN_ZIP_MAGIC
    except OSError:
        return False


def _find_7z_cli() -> str | None:
    for candidate in SEVEN_ZIP_CLI_CANDIDATES:
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    return None


def _parse_7z_int(raw_value: str | None) -> int | None:
    if raw_value is None:
        return None
    try:
        return int(raw_value)
    except ValueError:
        return None


def _parse_7z_listing(output: str) -> list[dict[str, object]]:
    entries: list[dict[str, object]] = []
    current: dict[str, str] = {}
    in_entries = False

    for raw_line in output.splitlines():
        line = raw_line.strip()
        if not in_entries:
            if line.startswith("----------"):
                in_entries = True
            continue

        if not line:
            if current:
                path = current.get("Path")
                if path:
                    attributes = current.get("Attributes", "")
                    is_directory = current.get("Folder") == "+" or attributes.startswith("D")
                    entries.append(
                        {
                            "path": path,
                            "size_bytes": _parse_7z_int(current.get("Size")),
                            "packed_size_bytes": _parse_7z_int(current.get("Packed Size")),
                            "is_directory": is_directory,
                            "encrypted": current.get("Encrypted") == "+",
                            "method": current.get("Method"),
                        }
                    )
                current = {}
            continue

        if "=" not in line:
            continue

        key, value = line.split("=", 1)
        current[key.strip()] = value.strip()

    if current:
        path = current.get("Path")
        if path:
            attributes = current.get("Attributes", "")
            is_directory = current.get("Folder") == "+" or attributes.startswith("D")
            entries.append(
                {
                    "path": path,
                    "size_bytes": _parse_7z_int(current.get("Size")),
                    "packed_size_bytes": _parse_7z_int(current.get("Packed Size")),
                    "is_directory": is_directory,
                    "encrypted": current.get("Encrypted") == "+",
                    "method": current.get("Method"),
                }
            )

    return entries


def _method_name(method_id: bytes | None) -> str | None:
    if method_id is None:
        return None
    return METHOD_NAMES_BY_ID.get(method_id, method_id.hex())


def _payload_base() -> dict[str, object]:
    return {
        "type": "7z",
        "listing_status": "header-only",
        "member_count": None,
        "file_count": None,
        "directory_count": None,
        "members": [],
        "total_uncompressed_bytes": None,
        "listing_tool": None,
        "encrypted": None,
    }


def _py7zr_member_payload(entry: object) -> dict[str, object]:
    creation_time = getattr(entry, "creationtime", None)
    return {
        "path": getattr(entry, "filename", None),
        "size_bytes": getattr(entry, "uncompressed", None),
        "packed_size_bytes": getattr(entry, "compressed", None),
        "is_directory": bool(getattr(entry, "is_directory", False)),
        "crc32": getattr(entry, "crc32", None),
        "creation_time": creation_time.isoformat() if creation_time is not None else None,
    }


def _py7zr_coder_stack(coders: object) -> list[dict[str, object]]:
    if not isinstance(coders, list):
        return []

    payload: list[dict[str, object]] = []
    for coder in coders:
        if not isinstance(coder, dict):
            continue
        method_id = coder.get("method")
        payload.append(
            {
                "method_id": method_id.hex() if isinstance(method_id, bytes) else None,
                "method_name": _method_name(method_id if isinstance(method_id, bytes) else None),
                "numinstreams": coder.get("numinstreams"),
                "numoutstreams": coder.get("numoutstreams"),
            }
        )
    return payload


def _summarize_7z_archive_with_py7zr(target: Path) -> dict[str, object] | None:
    if py7zr is None:
        return None

    payload = _payload_base()
    payload["listing_tool"] = "py7zr"

    try:
        with py7zr.SevenZipFile(target, mode="r") as archive:
            entries = [_py7zr_member_payload(entry) for entry in archive.list()]
    except PasswordRequired as exc:
        payload["listing_status"] = "password-required"
        payload["encrypted"] = True
        payload["coder_stack"] = _py7zr_coder_stack(exc.args[0] if exc.args else None)
        return payload
    except Bad7zFile as exc:
        payload["listing_status"] = "invalid"
        payload["error"] = str(exc)
        return payload
    except Exception as exc:
        payload["listing_status"] = "error"
        payload["error"] = str(exc)
        return payload

    payload["listing_status"] = "listed"
    payload["encrypted"] = False
    payload["member_count"] = len(entries)
    payload["file_count"] = sum(1 for item in entries if not item["is_directory"])
    payload["directory_count"] = sum(1 for item in entries if item["is_directory"])
    payload["total_uncompressed_bytes"] = sum(
        int(item["size_bytes"])
        for item in entries
        if isinstance(item.get("size_bytes"), int) and not item["is_directory"]
    )
    payload["members"] = entries[:MAX_MEMBER_SAMPLE]
    return payload


def _summarize_7z_archive(target: Path) -> dict[str, object]:
    py7zr_payload = _summarize_7z_archive_with_py7zr(target)
    if py7zr_payload is not None and py7zr_payload.get("listing_status") in {"listed", "password-required"}:
        return py7zr_payload

    payload = py7zr_payload or _payload_base()

    cli = _find_7z_cli()
    if not cli:
        return payload

    completed = subprocess.run(
        [cli, "l", "-slt", str(target)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=60,
        check=False,
    )
    payload["listing_tool"] = cli

    entries = _parse_7z_listing(completed.stdout)
    if completed.returncode not in {0, 1} and not entries:
        payload["listing_status"] = "cli-error"
        error_text = completed.stderr.strip() or completed.stdout.strip()
        payload["error"] = error_text[:500] if error_text else f"7z exited with code {completed.returncode}"
        return payload

    payload["listing_status"] = "listed"
    payload["encrypted"] = any(bool(item.get("encrypted")) for item in entries)
    payload["member_count"] = len(entries)
    payload["file_count"] = sum(1 for item in entries if not item["is_directory"])
    payload["directory_count"] = sum(1 for item in entries if item["is_directory"])
    payload["total_uncompressed_bytes"] = sum(
        int(item["size_bytes"])
        for item in entries
        if isinstance(item.get("size_bytes"), int) and not item["is_directory"]
    )
    payload["members"] = entries[:MAX_MEMBER_SAMPLE]
    return payload


class ArchiveAnalyzer(Analyzer):
    name = "archive"

    def supports(self, target: Path) -> bool:
        return target.is_file() and (
            zipfile.is_zipfile(target)
            or looks_like_7z_archive(target)
            or tarfile.is_tarfile(target)
            or target.suffix.lower() in ARCHIVE_EXTENSIONS
        )

    def analyze(self, target: Path, report: AnalysisReport) -> None:
        if zipfile.is_zipfile(target):
            with zipfile.ZipFile(target) as archive:
                members = archive.infolist()
                report.add_section(
                    "archive",
                    {
                        "type": "zip",
                        "member_count": len(members),
                        "members": [member.filename for member in members[:50]],
                        "total_uncompressed_bytes": sum(member.file_size for member in members),
                    },
                )
            return

        if looks_like_7z_archive(target):
            payload = _summarize_7z_archive(target)
            report.add_section("archive", payload)
            if payload.get("listing_status") == "cli-error":
                report.warn(f"7z archive detected but member listing failed for {target.name}.")
            if payload.get("listing_status") == "password-required":
                report.add_finding(
                    "archive",
                    "Encrypted 7z archive detected",
                    "The archive header requires a password before members can be enumerated or extracted.",
                    severity="info",
                    listing_status=payload["listing_status"],
                    coder_stack=payload.get("coder_stack", []),
                )
            return

        if tarfile.is_tarfile(target):
            with tarfile.open(target) as archive:
                members = archive.getmembers()
                report.add_section(
                    "archive",
                    {
                        "type": "tar",
                        "member_count": len(members),
                        "members": [member.name for member in members[:50]],
                        "total_uncompressed_bytes": sum(member.size for member in members),
                    },
                )
            return

        if target.suffix.lower() == ".7z":
            report.add_section(
                "archive",
                {
                    "type": "7z",
                    "listing_status": "unreadable",
                    "member_count": None,
                    "members": [],
                    "total_uncompressed_bytes": None,
                },
            )
