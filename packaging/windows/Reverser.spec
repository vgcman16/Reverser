# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the Windows Reverser GUI executable."""

from pathlib import Path


try:
    REPO_ROOT = Path(SPECPATH).resolve().parents[1]
except NameError:
    REPO_ROOT = Path(__file__).resolve().parents[2]

SRC_DIR = REPO_ROOT / "src"

a = Analysis(
    [str(SRC_DIR / "reverser" / "app.py")],
    pathex=[str(SRC_DIR)],
    binaries=[],
    datas=[],
    hiddenimports=[
        "PySide6.QtCore",
        "PySide6.QtGui",
        "PySide6.QtWidgets",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="Reverser",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
