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
- Recursive batch scan mode with JSON index and NDJSON exports
- Structured diff mode for reports, scan indexes, or raw targets
- Local JSON API for automation and agent workflows
- Persistent local SQLite catalog for ingest, search, and reuse across investigations
- Identity pass with hashes, entropy, MIME guesses, signatures, and directory stats
- String extraction for ASCII and UTF-16LE content
- IOC/rule pass for IPs, emails, secret-like strings, and high-entropy PE sections
- ZIP and TAR archive inventory
- Portable Executable (PE) header and section inspection
- ELF header and section inventory for Linux binaries
- Mach-O header and load-command inventory for macOS binaries
- SQLite schema and table inspection
- RuneScape/OpenNXT JS5 `.jcache` analysis with archive IDs, local index-name mapping, and compression summaries
- Game and engine fingerprinting for Unity, Unreal, Godot, Source-family, and common containers
- Directory inventory with entrypoint and container discovery
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
- `reverser scan <folder>` prints a stable scan index for large directories
- `--json-out` writes a machine-readable artifact to disk
- `--md-out` writes a human-readable incident or triage report
- `--index-json` and `--index-ndjson` export batch-scan artifacts
- `reverser diff <base> <head>` compares reports, scan indexes, or raw paths
- `reverser api` runs a localhost-only JSON API
- `reverser catalog-ingest` stores reports or raw targets in a reusable local catalog
- `reverser catalog-search` queries the catalog by signature, engine, tag, path, or hash
- `--csv-out` on scan and catalog search produces flat CSV for spreadsheets and BI tools
- `reverser schema --kind report|scan-index|diff|catalog-search|catalog-ingests` exposes the data contracts
- `reverser analyzers` lists the built-in analysis pipeline
- The GUI and CLI share the same analysis engine, so results stay aligned
- Scan indexes now carry JS5 fields such as `js5_archive_id`, `js5_index_name`, and `js5_store_kind` when applicable

## JS5 cache example

```powershell
reverser analyze C:\Path\To\js5-17.jcache --stdout-format pretty
```

This reports:

- SQLite schema and row counts
- JS5 archive ID and store family
- Optional local archive-name labels from nearby `data\prot\*\generated\shared\js5-archive-resolution.json`
- Compression distribution across cache rows
- Parsed sample record headers with decoded-size checks

## Batch scan example

```powershell
reverser scan C:\Games\Example `
  --reports-dir reports\example `
  --index-json reports\example-index.json `
  --index-ndjson reports\example-index.ndjson `
  --include-markdown `
  --stdout-format pretty
```

## Diff example

```powershell
reverser diff C:\Games\BuildA C:\Games\BuildB --stdout-format pretty
reverser diff reports\build-a-index.json reports\build-b-index.json --json-out reports\build-diff.json
```

## Local API

The local API binds to `127.0.0.1` by default so it is only reachable from the
same machine.

```powershell
reverser api --port 8765
```

Examples:

- `GET /health`
- `GET /analyzers`
- `GET /schema/report`
- `GET /schema/scan-index`
- `GET /schema/diff`
- `GET /schema/catalog-search`
- `GET /schema/catalog-ingests`
- `POST /analyze` with `{"target":"C:\\Path\\To\\file.exe"}`
- `POST /scan` with `{"target":"C:\\Games\\Example","max_files":500,"workers":6}`
- `POST /diff` with `{"base":"reports\\old.json","head":"reports\\new.json"}`
- `POST /catalog/ingest` with `{"source":"C:\\Games\\Example"}`
- `POST /catalog/search` with `{"signature":"portable-executable","limit":25}`

## Local catalog

The catalog is a local SQLite database at `.reverser/catalog.sqlite3` by default.
It lets the tool remember previous scans so you can search across investigations.

```powershell
reverser catalog-init
reverser catalog-ingest C:\Games\Example
reverser catalog-search --signature portable-executable --min-findings 1
reverser catalog-ingests --limit 10
reverser catalog-stats
```

## Planned next steps

- Richer PE import and export reconstruction
- Plugin adapters for external tools such as Ghidra or radare2
- Symbol browsing, diffing, and richer resource decoding
- IOC matching, YARA integration, and signed rule packs
- Signed release pipeline and packaged Windows installers
