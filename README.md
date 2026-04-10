# Reverser Workbench

Reverser Workbench is a Windows-first drag-and-drop software analysis tool for
authorized binaries, game installations, archives, and asset containers. It is
designed for inspection, triage, interoperability research, incident response,
permitted modding workflows, and internal software forensics.

This project intentionally does **not** implement DRM bypass, cracking, license
evasion, anti-cheat tampering, or unauthorized extraction of proprietary
content.

## What it does today

- Drag-and-drop desktop UI for files or directories
- Headless CLI with deterministic JSON on stdout for AI and automation
- Identity pass with hashes, entropy, MIME guesses, signatures, and directory stats
- String extraction for ASCII and UTF-16LE content
- ZIP and TAR archive inventory
- Portable Executable (PE) header and section inspection
- Game and engine fingerprinting for Unity, Unreal, Godot, Source-family, and common containers
- JSON and Markdown report export
- Modular analyzer architecture so new formats can be added safely

## Quickstart

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -U pip
python -m pip install -e .[dev]
pytest
reverser analyze C:\Path\To\Target.exe
```

Install the GUI extra when you want the desktop application:

```powershell
python -m pip install -e .[dev,gui]
reverser-gui
```

## AI and automation

The CLI is intentionally headless-first:

- `reverser analyze <target>` prints a stable JSON report to stdout
- `--json-out` writes a machine-readable artifact to disk
- `--md-out` writes a human-readable incident or triage report
- The GUI and CLI share the same analysis engine, so results stay aligned

## Planned next steps

- Richer PE import and export reconstruction
- Plugin adapters for external tools such as Ghidra or radare2
- Symbol browsing, diffing, and richer resource decoding
- IOC matching, YARA integration, and signed rule packs
- Signed release pipeline and packaged Windows installers
