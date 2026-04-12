from __future__ import annotations

from pathlib import Path

from reverser.analysis.analyzers.archive_analyzer import looks_like_7z_archive
from reverser.analysis.analyzers.base import Analyzer
from reverser.models import AnalysisReport


SCRIPT_ARCHIVE_NAMES = {"script.dat", "pcscript.dat"}
MAX_SAMPLE_ITEMS = 25


def _relative_posix(path: Path, base: Path) -> str:
    return str(path.relative_to(base)).replace("\\", "/")


def _find_conquer_install_root(target: Path) -> Path | None:
    search_start = target if target.is_dir() else target.parent

    for candidate in [search_start, *search_start.parents]:
        if (candidate / "ini" / "luacfg").is_dir():
            return candidate
        if candidate.name.lower() == "luacfg" and candidate.parent.name.lower() == "ini":
            return candidate.parent.parent

    return None


def _luacfg_dir_for(root: Path) -> Path:
    return root / "ini" / "luacfg"


def _ini_dir_for(root: Path) -> Path:
    return root / "ini"


def _is_luacfg_dat(path: Path, *, install_root: Path) -> bool:
    luacfg_dir = _luacfg_dir_for(install_root)
    return path.is_file() and path.suffix.lower() == ".dat" and path.is_relative_to(luacfg_dir)


def _is_plaintext_ini_lua(path: Path, *, install_root: Path) -> bool:
    ini_dir = _ini_dir_for(install_root)
    luacfg_dir = _luacfg_dir_for(install_root)
    return (
        path.is_file()
        and path.suffix.lower() == ".lua"
        and path.is_relative_to(ini_dir)
        and not path.is_relative_to(luacfg_dir)
    )


def _mirror_lua_path(dat_path: Path, *, install_root: Path) -> Path:
    relative = dat_path.relative_to(_luacfg_dir_for(install_root)).with_suffix(".lua")
    return _ini_dir_for(install_root) / relative


def _mirror_dat_path(lua_path: Path, *, install_root: Path) -> Path:
    relative = lua_path.relative_to(_ini_dir_for(install_root)).with_suffix(".dat")
    return _luacfg_dir_for(install_root) / relative


def _resource_payload(target: Path, *, install_root: Path) -> dict[str, object] | None:
    if _is_luacfg_dat(target, install_root=install_root):
        mirror = _mirror_lua_path(target, install_root=install_root)
        return {
            "format": "conquer-online-resource",
            "scope": "file",
            "resource_kind": "luacfg-dat",
            "install_root": str(install_root),
            "relative_path": _relative_posix(target, install_root),
            "plaintext_mirror_exists": mirror.exists(),
            "plaintext_mirror_relative_path": _relative_posix(mirror, install_root),
            "size_bytes": target.stat().st_size,
        }

    if _is_plaintext_ini_lua(target, install_root=install_root):
        mirror = _mirror_dat_path(target, install_root=install_root)
        return {
            "format": "conquer-online-resource",
            "scope": "file",
            "resource_kind": "plaintext-lua",
            "install_root": str(install_root),
            "relative_path": _relative_posix(target, install_root),
            "paired_dat_exists": mirror.exists(),
            "paired_dat_relative_path": _relative_posix(mirror, install_root),
            "size_bytes": target.stat().st_size,
        }

    if target.is_file() and target.name.lower() in SCRIPT_ARCHIVE_NAMES:
        return {
            "format": "conquer-online-resource",
            "scope": "file",
            "resource_kind": "script-archive",
            "install_root": str(install_root),
            "relative_path": _relative_posix(target, install_root),
            "looks_like_7z_archive": looks_like_7z_archive(target),
            "size_bytes": target.stat().st_size,
        }

    return None


def _directory_payload(target: Path, *, install_root: Path) -> dict[str, object]:
    luacfg_dir = _luacfg_dir_for(install_root)
    ini_dir = _ini_dir_for(install_root)

    dat_files = sorted(path for path in luacfg_dir.rglob("*.dat") if path.is_file())
    lua_files = sorted(path for path in ini_dir.rglob("*.lua") if path.is_file() and not path.is_relative_to(luacfg_dir))

    dat_map = {_relative_posix(path.with_suffix(""), luacfg_dir).lower(): path for path in dat_files}
    lua_map = {_relative_posix(path.with_suffix(""), ini_dir).lower(): path for path in lua_files}

    mirrored_keys = sorted(dat_map.keys() & lua_map.keys())
    dat_only_keys = sorted(dat_map.keys() - lua_map.keys())
    lua_only_keys = sorted(lua_map.keys() - dat_map.keys())

    script_archives: list[dict[str, object]] = []
    for name in sorted(SCRIPT_ARCHIVE_NAMES):
        candidate = install_root / name
        if candidate.is_file():
            script_archives.append(
                {
                    "relative_path": _relative_posix(candidate, install_root),
                    "size_bytes": candidate.stat().st_size,
                    "looks_like_7z_archive": looks_like_7z_archive(candidate),
                }
            )

    return {
        "format": "conquer-online-resource",
        "scope": "install",
        "install_root": str(install_root),
        "analyzed_path": str(target),
        "luacfg_dir": str(luacfg_dir),
        "luacfg_dat_count": len(dat_files),
        "plaintext_lua_count": len(lua_files),
        "mirrored_pair_count": len(mirrored_keys),
        "dat_only_count": len(dat_only_keys),
        "lua_only_count": len(lua_only_keys),
        "mirrored_sample": mirrored_keys[:MAX_SAMPLE_ITEMS],
        "dat_only_sample": dat_only_keys[:MAX_SAMPLE_ITEMS],
        "lua_only_sample": lua_only_keys[:MAX_SAMPLE_ITEMS],
        "script_archives": script_archives,
    }


class ConquerResourceAnalyzer(Analyzer):
    name = "conquer-resource"

    def supports(self, target: Path) -> bool:
        install_root = _find_conquer_install_root(target)
        if install_root is None:
            return False
        if target.is_dir():
            return True
        return _resource_payload(target, install_root=install_root) is not None

    def analyze(self, target: Path, report: AnalysisReport) -> None:
        install_root = _find_conquer_install_root(target)
        if install_root is None:
            return

        if target.is_dir():
            payload = _directory_payload(target, install_root=install_root)
            report.add_section("conquer_resource", payload)
            report.add_finding(
                "game",
                "Conquer luacfg resources detected",
                "The target includes Conquer Online plaintext Lua resources, encrypted luacfg `.dat` counterparts, or script archives.",
                severity="info",
                mirrored_pair_count=payload["mirrored_pair_count"],
                dat_only_count=payload["dat_only_count"],
                lua_only_count=payload["lua_only_count"],
                script_archive_count=len(payload["script_archives"]),
            )
            return

        payload = _resource_payload(target, install_root=install_root)
        if payload is None:
            return

        report.add_section("conquer_resource", payload)

        if payload["resource_kind"] == "luacfg-dat":
            report.add_finding(
                "game",
                "Conquer encrypted Lua/config resource detected",
                "This file sits under `ini/luacfg` and matches the Conquer Online encrypted or packaged config/Lua resource pattern.",
                severity="info",
                plaintext_mirror_exists=payload["plaintext_mirror_exists"],
                plaintext_mirror_relative_path=payload["plaintext_mirror_relative_path"],
            )
        elif payload["resource_kind"] == "script-archive":
            report.add_finding(
                "game",
                "Conquer script archive detected",
                "This file matches a known Conquer Online script archive path and may wrap content as a 7z-backed package.",
                severity="info",
                looks_like_7z_archive=payload["looks_like_7z_archive"],
            )
