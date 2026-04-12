from __future__ import annotations

import hashlib
import math
import mimetypes
from collections import Counter
from pathlib import Path

from reverser.analysis.analyzers.base import Analyzer
from reverser.models import AnalysisReport


EXECUTABLE_HINT_EXTENSIONS = {".exe", ".dll", ".sys", ".drv"}
PACKED_EXECUTABLE_ENTROPY = 7.2
DEFAULT_MAX_HASH_BYTES = 256 * 1024 * 1024
DEFAULT_MAX_ENTROPY_BYTES = 256 * 1024 * 1024
DEFAULT_SAMPLE_WINDOW_BYTES = 8 * 1024 * 1024
SAMPLING_SEGMENTS = 3
SIGNATURES: tuple[tuple[bytes, str], ...] = (
    (b"MZ", "portable-executable"),
    (b"\x7fELF", "elf"),
    (b"\xfe\xed\xfa\xce", "mach-o-32"),
    (b"\xfe\xed\xfa\xcf", "mach-o-64"),
    (b"\xcf\xfa\xed\xfe", "mach-o-64-reversed"),
    (b"SQLite format 3\x00", "sqlite"),
    (b"PK\x03\x04", "zip"),
    (b"7z\xbc\xaf\x27\x1c", "7zip"),
    (b"Rar!\x1a\x07\x00", "rar"),
    (b"Rar!\x1a\x07\x01\x00", "rar5"),
    (b"UnityFS", "unityfs-bundle"),
    (b"UnityWeb", "unity-web"),
    (b"NetDragonDatPkg\x00", "netdragon-datpkg"),
    (b"MAXFILE C3 00001", "conquer-c3"),
    (b"PUZZLE2\x00", "conquer-pul"),
    (b"TqTerrain\x00", "conquer-pux"),
    (b"DDS ", "dds"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"%PDF-", "pdf"),
)


def _signature_name(header: bytes) -> str | None:
    for marker, label in SIGNATURES:
        if header.startswith(marker):
            return label
    return None


def _compute_hashes(path: Path) -> dict[str, str]:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def _hash_chunks(chunks: list[tuple[int, bytes]]) -> dict[str, str]:
    md5 = hashlib.md5()
    sha1 = hashlib.sha1()
    sha256 = hashlib.sha256()

    for offset, chunk in chunks:
        offset_bytes = offset.to_bytes(8, "big", signed=False)
        md5.update(offset_bytes)
        md5.update(chunk)
        sha1.update(offset_bytes)
        sha1.update(chunk)
        sha256.update(offset_bytes)
        sha256.update(chunk)

    return {
        "md5": md5.hexdigest(),
        "sha1": sha1.hexdigest(),
        "sha256": sha256.hexdigest(),
    }


def _byte_entropy(path: Path) -> float:
    counts = [0] * 256
    total = 0

    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            total += len(chunk)
            for byte in chunk:
                counts[byte] += 1

    if total == 0:
        return 0.0

    entropy = 0.0
    for count in counts:
        if count:
            probability = count / total
            entropy -= probability * math.log2(probability)
    return round(entropy, 4)


def _entropy_from_bytes(chunks: list[bytes]) -> float:
    counts = [0] * 256
    total = 0

    for chunk in chunks:
        total += len(chunk)
        for byte in chunk:
            counts[byte] += 1

    if total == 0:
        return 0.0

    entropy = 0.0
    for count in counts:
        if count:
            probability = count / total
            entropy -= probability * math.log2(probability)
    return round(entropy, 4)


def _sample_file_chunks(path: Path, budget_bytes: int) -> list[tuple[int, bytes]]:
    total_size = path.stat().st_size
    if total_size == 0:
        return [(0, b"")]
    if total_size <= budget_bytes:
        return [(0, path.read_bytes())]

    window_bytes = max(1, budget_bytes // SAMPLING_SEGMENTS)
    middle_offset = max(0, (total_size // 2) - (window_bytes // 2))
    tail_offset = max(0, total_size - window_bytes)
    offsets = list(dict.fromkeys([0, middle_offset, tail_offset]))

    chunks: list[tuple[int, bytes]] = []
    with path.open("rb") as handle:
        for offset in offsets:
            handle.seek(offset)
            chunk = handle.read(min(window_bytes, total_size - offset))
            chunks.append((offset, chunk))
    return chunks


def _directory_summary(path: Path) -> dict[str, object]:
    total_bytes = 0
    file_count = 0
    extensions: Counter[str] = Counter()
    largest_files: list[tuple[int, str]] = []

    for child in path.rglob("*"):
        if child.is_file():
            file_count += 1
            size = child.stat().st_size
            total_bytes += size
            extensions[child.suffix.lower() or "<none>"] += 1
            largest_files.append((size, str(child.relative_to(path))))

    largest_files.sort(reverse=True)
    return {
        "file_count": file_count,
        "total_bytes": total_bytes,
        "top_extensions": [
            {"extension": ext, "count": count}
            for ext, count in extensions.most_common(10)
        ],
        "largest_files": [
            {"path": relative_path, "size_bytes": size}
            for size, relative_path in largest_files[:10]
        ],
    }


class FileIdentityAnalyzer(Analyzer):
    name = "file-identity"

    def __init__(
        self,
        *,
        max_hash_bytes: int = DEFAULT_MAX_HASH_BYTES,
        max_entropy_bytes: int = DEFAULT_MAX_ENTROPY_BYTES,
        sample_window_bytes: int = DEFAULT_SAMPLE_WINDOW_BYTES,
    ) -> None:
        self.max_hash_bytes = max_hash_bytes
        self.max_entropy_bytes = max_entropy_bytes
        self.sample_window_bytes = sample_window_bytes

    def analyze(self, target: Path, report: AnalysisReport) -> None:
        if target.is_dir():
            report.add_section(
                "identity",
                {
                    "mime_guess": "inode/directory",
                    "signature": "directory",
                    **_directory_summary(target),
                },
            )
            return

        with target.open("rb") as handle:
            header = handle.read(64)

        size_bytes = target.stat().st_size
        mime_guess, _ = mimetypes.guess_type(target.name)
        signature = _signature_name(header) or "unknown"
        payload = {
            "mime_guess": mime_guess or "application/octet-stream",
            "signature": signature,
            "hashes": {},
            "sampled_hashes": {},
            "hash_strategy": "full",
            "entropy_strategy": "full",
            "probable_packed_executable": False,
        }

        if size_bytes <= self.max_hash_bytes:
            payload["hashes"] = _compute_hashes(target)
        else:
            sampled_chunks = _sample_file_chunks(target, self.sample_window_bytes)
            payload["sampled_hashes"] = _hash_chunks(sampled_chunks)
            payload["hash_strategy"] = "sampled"
            payload["hash_sampled_bytes"] = sum(len(chunk) for _, chunk in sampled_chunks)
            payload["hash_sample_window_bytes"] = self.sample_window_bytes

        if size_bytes <= self.max_entropy_bytes:
            entropy = _byte_entropy(target)
        else:
            entropy_chunks = _sample_file_chunks(target, self.sample_window_bytes)
            entropy = _entropy_from_bytes([chunk for _, chunk in entropy_chunks])
            payload["entropy_strategy"] = "sampled"
            payload["entropy_sampled_bytes"] = sum(len(chunk) for _, chunk in entropy_chunks)
            payload["entropy_sample_window_bytes"] = self.sample_window_bytes

        probable_packed_executable = (
            signature == "unknown"
            and target.suffix.lower() in EXECUTABLE_HINT_EXTENSIONS
            and entropy >= PACKED_EXECUTABLE_ENTROPY
        )
        payload["entropy"] = entropy
        payload["probable_packed_executable"] = probable_packed_executable
        report.add_section("identity", payload)

        if probable_packed_executable:
            report.add_finding(
                "identity",
                "Opaque executable-like file",
                "Executable-like file has an unknown signature and very high entropy, which may indicate packing, encryption, or wrapper-managed content.",
                severity="low",
                entropy=entropy,
                extension=target.suffix.lower(),
                mime_guess=payload["mime_guess"],
            )
