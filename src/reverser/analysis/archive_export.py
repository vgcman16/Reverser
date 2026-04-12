from __future__ import annotations

import json
import tarfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path

from reverser import __version__
from reverser.analysis.analyzers.archive_analyzer import looks_like_7z_archive

try:
    import py7zr
    from py7zr.exceptions import Bad7zFile, PasswordRequired
except ImportError:  # pragma: no cover - runtime dependency guard
    py7zr = None
    Bad7zFile = ValueError
    PasswordRequired = ValueError


def export_archive(
    source: str | Path,
    output_dir: str | Path,
    *,
    password: str | None = None,
) -> dict[str, object]:
    target = Path(source).expanduser().resolve()
    if not target.exists():
        raise FileNotFoundError(f"Target does not exist: {target}")
    if not target.is_file():
        raise IsADirectoryError(f"Archive export expects a file target: {target}")

    destination = Path(output_dir).expanduser().resolve()
    destination.mkdir(parents=True, exist_ok=True)
    manifest_path = destination / "manifest.json"

    if zipfile.is_zipfile(target):
        manifest = _export_zip_archive(target, destination, password_supplied=password is not None)
    elif looks_like_7z_archive(target):
        manifest = _export_7z_archive(target, destination, password=password)
    elif tarfile.is_tarfile(target):
        manifest = _export_tar_archive(target, destination, password_supplied=password is not None)
    else:
        raise ValueError(f"Unsupported archive format: {target}")

    manifest["manifest_path"] = str(manifest_path)
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return manifest


def _manifest_header(
    *,
    target: Path,
    destination: Path,
    archive_type: str,
    password_supplied: bool,
    password_mode: str,
) -> dict[str, object]:
    return {
        "report_version": "1.0",
        "tool": {
            "name": "reverser-workbench",
            "version": __version__,
        },
        "generated_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "source_path": str(target),
        "export_root": str(destination),
        "archive_type": archive_type,
        "settings": {
            "password_supplied": password_supplied,
            "password_mode": password_mode,
        },
        "summary": {},
        "warnings": [],
        "members": [],
    }


def _safe_relative_archive_path(raw_path: str) -> Path:
    normalized = raw_path.replace("\\", "/").lstrip("/")
    candidate = Path(normalized)
    safe_parts = [part for part in candidate.parts if part not in {"", ".", ".."}]
    if not safe_parts:
        return Path("unnamed.bin")
    return Path(*safe_parts)


def _is_safe_archive_member(raw_path: str) -> bool:
    normalized = raw_path.replace("\\", "/")
    candidate = Path(normalized)
    if candidate.is_absolute():
        return False
    return all(part not in {"", ".", ".."} for part in candidate.parts)


def _export_zip_archive(target: Path, destination: Path, *, password_supplied: bool) -> dict[str, object]:
    manifest = _manifest_header(
        target=target,
        destination=destination,
        archive_type="zip",
        password_supplied=password_supplied,
        password_mode="ignored",
    )
    members: list[dict[str, object]] = []
    extracted_count = 0

    with zipfile.ZipFile(target) as archive:
        archive_members = archive.infolist()
        unsafe_members = [member.filename for member in archive_members if not _is_safe_archive_member(member.filename)]
        if unsafe_members:
            manifest["summary"] = {
                "extraction_status": "unsafe-member-paths",
                "member_count": len(archive_members),
                "exported_member_count": 0,
            }
            manifest["warnings"].append("Archive contains unsafe member paths; extraction aborted.")
            manifest["unsafe_members"] = unsafe_members[:25]
            return manifest

        for member in archive_members:
            safe_relative = _safe_relative_archive_path(member.filename)
            output_path = destination / safe_relative
            member_payload = {
                "path": member.filename,
                "output_path": str(output_path),
                "size_bytes": member.file_size,
                "compressed_size_bytes": member.compress_size,
                "is_directory": member.is_dir(),
            }

            if member.is_dir():
                output_path.mkdir(parents=True, exist_ok=True)
                member_payload["status"] = "directory"
            else:
                output_path.parent.mkdir(parents=True, exist_ok=True)
                with archive.open(member) as handle:
                    output_path.write_bytes(handle.read())
                member_payload["status"] = "extracted"
                extracted_count += 1

            members.append(member_payload)

    manifest["summary"] = {
        "extraction_status": "extracted",
        "member_count": len(archive_members),
        "exported_member_count": extracted_count,
    }
    manifest["members"] = members
    return manifest


def _export_tar_archive(target: Path, destination: Path, *, password_supplied: bool) -> dict[str, object]:
    manifest = _manifest_header(
        target=target,
        destination=destination,
        archive_type="tar",
        password_supplied=password_supplied,
        password_mode="ignored",
    )
    members: list[dict[str, object]] = []
    extracted_count = 0

    with tarfile.open(target) as archive:
        archive_members = archive.getmembers()
        unsafe_members = [member.name for member in archive_members if not _is_safe_archive_member(member.name)]
        if unsafe_members:
            manifest["summary"] = {
                "extraction_status": "unsafe-member-paths",
                "member_count": len(archive_members),
                "exported_member_count": 0,
            }
            manifest["warnings"].append("Archive contains unsafe member paths; extraction aborted.")
            manifest["unsafe_members"] = unsafe_members[:25]
            return manifest

        for member in archive_members:
            safe_relative = _safe_relative_archive_path(member.name)
            output_path = destination / safe_relative
            member_payload = {
                "path": member.name,
                "output_path": str(output_path),
                "size_bytes": member.size,
                "is_directory": member.isdir(),
            }

            if member.isdir():
                output_path.mkdir(parents=True, exist_ok=True)
                member_payload["status"] = "directory"
            else:
                extracted = archive.extractfile(member)
                if extracted is None:
                    member_payload["status"] = "skipped"
                    members.append(member_payload)
                    continue
                output_path.parent.mkdir(parents=True, exist_ok=True)
                output_path.write_bytes(extracted.read())
                member_payload["status"] = "extracted"
                extracted_count += 1

            members.append(member_payload)

    manifest["summary"] = {
        "extraction_status": "extracted",
        "member_count": len(archive_members),
        "exported_member_count": extracted_count,
    }
    manifest["members"] = members
    return manifest


def _export_7z_archive(target: Path, destination: Path, *, password: str | None) -> dict[str, object]:
    manifest = _manifest_header(
        target=target,
        destination=destination,
        archive_type="7z",
        password_supplied=password is not None,
        password_mode="supplied" if password is not None else "none",
    )

    if py7zr is None:
        manifest["summary"] = {
            "extraction_status": "missing-dependency",
            "member_count": 0,
            "exported_member_count": 0,
        }
        manifest["warnings"].append("py7zr is not installed, so 7z extraction is unavailable.")
        return manifest

    try:
        with py7zr.SevenZipFile(target, mode="r", password=password) as archive:
            entries = list(archive.list())
            names = [str(getattr(entry, "filename", "")) for entry in entries]
            unsafe_members = [name for name in names if not _is_safe_archive_member(name)]
            if unsafe_members:
                manifest["summary"] = {
                    "extraction_status": "unsafe-member-paths",
                    "member_count": len(names),
                    "exported_member_count": 0,
                }
                manifest["warnings"].append("Archive contains unsafe member paths; extraction aborted.")
                manifest["unsafe_members"] = unsafe_members[:25]
                return manifest

            archive.reset()
            archive.extractall(path=destination)
    except PasswordRequired as exc:
        manifest["summary"] = {
            "extraction_status": "password-required",
            "member_count": 0,
            "exported_member_count": 0,
        }
        manifest["encrypted"] = True
        if exc.args and isinstance(exc.args[0], list):
            manifest["coder_stack"] = [
                {
                    "method_id": coder.get("method").hex() if isinstance(coder, dict) and isinstance(coder.get("method"), bytes) else None,
                    "numinstreams": coder.get("numinstreams") if isinstance(coder, dict) else None,
                    "numoutstreams": coder.get("numoutstreams") if isinstance(coder, dict) else None,
                }
                for coder in exc.args[0]
                if isinstance(coder, dict)
            ]
        return manifest
    except Bad7zFile as exc:
        manifest["summary"] = {
            "extraction_status": "invalid-archive",
            "member_count": 0,
            "exported_member_count": 0,
        }
        manifest["warnings"].append(str(exc))
        return manifest
    except Exception as exc:
        manifest["summary"] = {
            "extraction_status": "invalid-password-or-archive",
            "member_count": 0,
            "exported_member_count": 0,
        }
        manifest["warnings"].append(str(exc))
        return manifest

    members: list[dict[str, object]] = []
    extracted_count = 0
    for entry in entries:
        raw_path = str(getattr(entry, "filename", ""))
        safe_relative = _safe_relative_archive_path(raw_path)
        is_directory = bool(getattr(entry, "is_directory", False))
        member_payload = {
            "path": raw_path,
            "output_path": str(destination / safe_relative),
            "size_bytes": getattr(entry, "uncompressed", None),
            "compressed_size_bytes": getattr(entry, "compressed", None),
            "is_directory": is_directory,
            "status": "directory" if is_directory else "extracted",
        }
        if not is_directory:
            extracted_count += 1
        members.append(member_payload)

    manifest["summary"] = {
        "extraction_status": "extracted",
        "member_count": len(entries),
        "exported_member_count": extracted_count,
    }
    manifest["encrypted"] = password is not None
    manifest["members"] = members
    return manifest
