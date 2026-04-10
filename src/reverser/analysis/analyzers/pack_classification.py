from __future__ import annotations

import re
from pathlib import Path


CHROMIUM_PAK_NAMES = {
    "resources.pak",
    "chrome_100_percent.pak",
    "chrome_200_percent.pak",
}
UNREAL_PAK_PATTERN = re.compile(r"^pakchunk\d+.*\.pak$", re.IGNORECASE)


def is_chromium_resource_pack(path: Path) -> bool:
    name = path.name.lower()
    parent_name = path.parent.name.lower()
    return name in CHROMIUM_PAK_NAMES or parent_name == "locales"


def looks_like_unreal_pak(path: Path) -> bool:
    if is_chromium_resource_pack(path):
        return False

    if UNREAL_PAK_PATTERN.match(path.name.lower()):
        return True

    parts = {part.lower() for part in path.parts}
    return "content" in parts and "paks" in parts
