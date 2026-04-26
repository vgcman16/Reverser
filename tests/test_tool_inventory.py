from __future__ import annotations

import os
import stat
from pathlib import Path

from reverser.analysis.tool_inventory import build_external_tool_inventory


def _write_fake_command(root: Path, name: str) -> None:
    path = root / name
    path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IEXEC)


def test_external_tool_inventory_uses_hackingtool_reverse_engineering_catalog():
    payload = build_external_tool_inventory(profile="win64-pe", path_env="", include_common_paths=False)

    names = {tool["name"] for tool in payload["tools"]}
    ida = next(tool for tool in payload["tools"] if tool["name"] == "IDA Free / IDA Pro")
    ghidra = next(tool for tool in payload["tools"] if tool["name"] == "Ghidra")
    jadx = next(tool for tool in payload["tools"] if tool["name"] == "JadX")

    assert payload["type"] == "external-tool-inventory"
    assert payload["source"]["mode"] == "read-only-catalog-reference"
    assert {"IDA Free / IDA Pro", "Ghidra", "Radare2", "JadX", "Androguard", "Apk2Gold"} <= names
    assert ida["recommended_for_profile"] is True
    assert ghidra["recommended_for_profile"] is True
    assert jadx["recommended_for_profile"] is False
    assert payload["scan"]["tool_count"] == 6
    assert payload["scan"]["common_path_detection"] is False


def test_external_tool_inventory_detects_available_commands(tmp_path: Path):
    _write_fake_command(tmp_path, "r2")
    _write_fake_command(tmp_path, "r2.exe")
    _write_fake_command(tmp_path, "jadx")
    _write_fake_command(tmp_path, "jadx.exe")

    payload = build_external_tool_inventory(profile="all", path_env=str(tmp_path), include_common_paths=False)
    radare2 = next(tool for tool in payload["tools"] if tool["name"] == "Radare2")
    jadx = next(tool for tool in payload["tools"] if tool["name"] == "JadX")

    assert radare2["available"] is True
    assert any(command["command"] == "r2" and command["available"] for command in radare2["commands"])
    assert jadx["available"] is True
    assert payload["scan"]["recommended_available_tool_count"] == 2


def test_external_tool_inventory_accepts_windows_exe_commands(tmp_path: Path):
    _write_fake_command(tmp_path, "analyzeHeadless")
    _write_fake_command(tmp_path, "analyzeHeadless.exe")
    path_env = str(tmp_path)
    if os.name == "nt":
        os.environ.setdefault("PATHEXT", ".COM;.EXE;.BAT;.CMD")

    payload = build_external_tool_inventory(profile="win64", path_env=path_env, include_common_paths=False)
    ghidra = next(tool for tool in payload["tools"] if tool["name"] == "Ghidra")

    assert payload["profile"] == "win64-pe"
    assert ghidra["available"] is True


def test_external_tool_inventory_detects_ida_command(tmp_path: Path):
    _write_fake_command(tmp_path, "ida")
    _write_fake_command(tmp_path, "ida.exe")

    payload = build_external_tool_inventory(profile="win64-pe", path_env=str(tmp_path), include_common_paths=False)
    ida = next(tool for tool in payload["tools"] if tool["name"] == "IDA Free / IDA Pro")

    assert ida["available"] is True
    assert ida["recommended_for_profile"] is True
    assert any(command["command"] == "ida" and command["available"] for command in ida["commands"])
