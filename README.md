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
- ZIP, TAR, and 7z archive inventory, including encrypted/password-required 7z detection for disguised payloads such as Conquer `script.dat`
- Portable Executable (PE) header and section inspection
- ELF header and section inventory for Linux binaries
- Mach-O header and load-command inventory for macOS binaries
- NetDragon `.tpi/.tpd` package analysis for Conquer Online-era installs, including full index parsing, method profiling, and decode probes
- NetDragon export mode for materializing decoded package contents with a JSON manifest
- Conquer Online `ini/luacfg` resource mapping with mirrored `.lua` versus encrypted `.dat` coverage summaries
- Conquer animation analysis for plaintext `.ani` descriptor files under `ani\`
- Conquer client executable-chain analysis for `Conquer.exe`, `play.exe`, patchers, launchers, and top-level DLL component stacks
- Conquer C3 analysis for loose `.c3` assets plus `ini\3dmotion.ini` / `ini\3DEffectObj.ini` reference tables resolved against `c3.tpi` and `c31.tpi`
- Conquer map analysis for `.7z` map archives, `.DMap` headers, and plaintext `.OtherData` sidecars
- Conquer puzzle/terrain analysis for `map\puzzle\*.pul` and `map\PuzzleSave\*.pux` assets referenced by `.DMap` headers
- SQLite schema and table inspection
- RuneScape/OpenNXT JS5 `.jcache` analysis with archive IDs, local index-name mapping, and compression summaries
- JS5 export mode for decoded cache rows, manifest generation, and AI-friendly archive extraction
- Reference-table-aware JS5 archive splitting with per-file payload export when grouped archives are present
- Semantic JS5 config profiling for enum, struct, param, varbit, and generic var-definition payloads
- Partial semantic profiling for RuneScape `CONFIG_ITEM`, `CONFIG_NPC`, and `CONFIG_OBJECT` payload families
- Sprite archive decoding for `SPRITES` and preview PNG generation during JS5 export
- Clientscript metadata decoding for `CLIENTSCRIPTS`, including instruction counts, locals/args, and switch tables
- RT7 model metadata decoding for `MODELS_RT7`, including bounds, render groups, triangle counts, and OBJ sidecar export during JS5 export
- Mapsquare profiling for `MAPS`, including coordinates, location placement summaries, legacy tile summaries, NXT tile summaries, and environment blobs
- JS5 cache-directory inventory for runtime cache folders with mapped archive names and largest-archive ranking
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
- `reverser js5-export <cache> <outdir>` materializes decoded JS5 rows and prints a manifest to stdout
- `reverser netdragon-export <package> <outdir>` materializes decoded NetDragon package rows and prints a manifest to stdout
- `reverser archive-export <archive> <outdir>` extracts ZIP, TAR, and 7z archives, with optional password prompt/env input for authorized access
- `reverser conquer-map-export <target> <outdir>` bulk-extracts openable Conquer map archives with DMap and `.OtherData` metadata
- `reverser api` runs a localhost-only JSON API
- `reverser catalog-ingest` stores reports or raw targets in a reusable local catalog
- `reverser catalog-search` queries the catalog by signature, engine, tag, path, or hash
- `--csv-out` on scan and catalog search produces flat CSV for spreadsheets and BI tools
- `reverser schema --kind report|scan-index|diff|catalog-search|catalog-ingests|js5-manifest` exposes the data contracts
- `reverser analyzers` lists the built-in analysis pipeline
- The GUI and CLI share the same analysis engine, so results stay aligned
- Scan indexes now carry JS5 fields such as `js5_archive_id`, `js5_index_name`, and `js5_store_kind` when applicable
- Oversized JS5 and SQLite artifacts are admitted to scans as metadata targets instead of being dropped by size caps
- Very large files switch to sampled identity digests and sampled entropy automatically so headless analysis stays responsive
- JS5 export manifests now include grouped `archive_files` plus semantic profiles for known config payload families
- Item, NPC, and object config exports surface names, actions, models, params, and common render/resize metadata when the opcode stream matches a known layout
- Sprite exports surface sprite-sheet metadata such as frame counts, frame sizes, palette size, alpha usage, and a generated PNG preview path
- Clientscript exports surface script body/footer sizes, instruction counts, int/string/long local and argument counts, and sampled switch-case tables
- RT7 model exports surface mesh bounds, render samples, material arguments, and a generated `.mesh.obj` path when geometry stays within safe export limits
- Mapsquare exports surface archive coordinates plus per-subfile summaries for location placements, tile flags, heights, overlays, and NXT terrain grids

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

Directory example:

```powershell
reverser analyze C:\Path\To\data\cache --stdout-format pretty
reverser scan C:\Path\To\data\cache --max-files 10 --stdout-format pretty
```

This surfaces:

- Archive inventory with mapped JS5 index names when available
- Largest runtime caches first during scans
- Sampled hashes for multi-GB caches instead of empty or skipped analysis

Export example:

```powershell
reverser js5-export C:\Path\To\js5-47.jcache reports\models-rt7 `
  --table cache `
  --limit 25 `
  --stdout-format pretty
```

This writes:

- `manifest.json` with per-record compression, revision, CRC, and output paths
- decoded `.payload.bin` files for rows that can be decompressed
- split `file-<id>.bin` payloads when reference-table metadata is available for grouped archives
- semantic summaries for exported enum, struct, param, varbit, var-definition, item, NPC, object, sprite, clientscript, RT7 model, and mapsquare payloads when recognized
- preview `.png` files for decoded sprite archives when the payload format matches the Jagex sprite container layout
- `.mesh.obj` files for decoded RT7 models when the mesh is small enough for safe sidecar export
- semantic kind counts in the manifest summary so headless agents can quickly see what was decoded
- optional raw `.container.bin` files when `--include-container` is used

## NetDragon package example

```powershell
reverser analyze C:\Games\Conquer\data.tpi --stdout-format pretty
reverser netdragon-export C:\Games\Conquer\data.tpi reports\conquer-data --limit 25 --stdout-format pretty
```

This surfaces:

- `NetDragonDatPkg` header metadata, full entry counts, root folders, and extension breakdowns
- package method counts, decode probes, and paired `.tpd`/`.tpi` detection
- decoded output files with the original relative paths plus a `manifest.json` for automation
- Conquer `ini/luacfg` mirror coverage, dat-only resource samples, and known script archive discovery when you analyze the install root
- Conquer client startup-chain and support-library summaries, including launcher stubs, patcher roles, DLL stack grouping, likely dynamic-load components, and binary dependency-graph/hotspot views around the Windows client
- Conquer C3 reference coverage from `3dmotion.ini` and `3DEffectObj.ini`, including duplicate reference hot spots, package resolution counts, cross-file overlap, and sampled resolved `top_tag` / `object_name` metadata from `c3.tpi` / `c31.tpi`
- Conquer C3 role hints and namespace coverage, including `camera` / `motion` / `mesh-or-model` / `particle` top-tag labels, family-level and branch-level resolution ratios, and package family inventories for `c3.tpi` and `c31.tpi`
- validated alias-promoted C3 coverage for stale numeric motion families, including effective post-alias coverage ratios, highest alias-gain family and branch samples, plus residual family and branch queues for the still-missing references
- residual C3 branch package profiles for the worst remaining gaps, including sampled top tags, structural roles, chunk signatures, unknown chunk-tag inventories, per-tag size/co-occurrence profiles, parent/preceding/following known-tag context, `between-...-and-...` sequence hints, cautious attachment-role hints such as mesh-to-motion control, particle postlude bulk-float, or mesh postlude bulk-float families, grouped unknown-tag archetypes that collapse many raw tags into recurring semantic buckets, install-wide residual archetype rollups that show which semantic buckets recur across branches, clustered unknown subformats, cautious shape-based subformat labels, and object-name/path samples so branches like `effect/flash`, `effect/weapon`, or `effect/other` can be characterized even when many referenced filenames are still missing
- password-required 7z classification for `script.dat` and `pcscript.dat`, including visible coder-stack metadata when the archive header is encrypted
- Conquer map summaries such as archive counts, paired `.OtherData` sidecars, DMap version values, embedded puzzle asset paths, inferred grid sizes, and resolved `.pul` / `.pux` / `.ani` dependency chains when present on disk
- Conquer `.ani` summaries such as section counts, frame-path counts, puzzle section coverage, and first-frame path roots
- resolved frame samples from `.ani` manifests, including whether referenced `DDS` textures are present on disk
- missing-frame directory diagnostics for `.ani` manifests, including nearest real parents, likely replacement directories, filename-overlap validation, grouped stale-path clusters, validated-cluster views, sequence-offset alias recovery when frame numbering shifted between legacy and canonical directories, conservative handling for generic-only overlaps such as `1.dds` or `pic000.dds`, and post-alias residual-gap queues for the still-unresolved families
- Puzzle and terrain summaries such as `.pul` animation references, `.pux` puzzle-label counts, and resolved asset metadata attached to DMap reports when the install root is available

## Archive export example

```powershell
reverser archive-export C:\Games\Conquer\script.dat reports\script --password-prompt --stdout-format pretty
```

This writes:

- extracted archive members into the output directory when a valid password is supplied
- a `manifest.json` even when extraction stops at `password-required`
- safe-path guards so archives with traversal-style member names are rejected instead of extracted

## Conquer map export example

```powershell
reverser conquer-map-export "C:\Games\Conquer" reports\conquer-maps --limit 25 --stdout-format pretty
```

This writes:

- extracted `.DMap` payloads into per-archive folders
- copied `.OtherData` sidecars when present
- a `manifest.json` with parsed DMap header fields plus resolved `.pul` / `.pux` asset metadata when those references exist on disk

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
- `GET /schema/js5-manifest`
- `POST /analyze` with `{"target":"C:\\Path\\To\\file.exe"}`
- `POST /scan` with `{"target":"C:\\Games\\Example","max_files":500,"workers":6}`
- `POST /diff` with `{"base":"reports\\old.json","head":"reports\\new.json"}`
- `POST /js5/export` with `{"target":"C:\\Path\\To\\js5-47.jcache","output_dir":"reports\\models-rt7","tables":["cache"],"limit":25}`
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
- Deeper RT7 model decoding for normals, UV semantics, and material reconstruction, plus richer mapsquare/environment interpretation and fuller clientscript instruction decoding
- IOC matching, YARA integration, and signed rule packs
- Signed release pipeline and packaged Windows installers
