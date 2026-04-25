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
- ZIP, TAR, and 7z archive inventory, including encrypted/password-required 7z detection
- Portable Executable (PE) header and section inspection
- ELF header and section inventory for Linux binaries
- Mach-O header and load-command inventory for macOS binaries
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
- `reverser external-target-index <root>` indexes external-target artifact trails for ongoing reverse-engineering work
- `reverser external-tool-inventory --profile win64-pe` detects trusted local reverse-engineering tools from a curated read-only external catalog reference; it does not run third-party installers
- `reverser pe-direct-calls <pe> <target...>` scans executable PE sections for raw x86/x64 `CALL rel32` sites to exact VA/RVA targets, with `.pdata` caller attribution when available
- `reverser pe-callsite-registers <pe> <target...>` recovers simple static register setup such as `RCX` callback pointers before direct callsites to wrapper functions
- `reverser pe-address-refs <pe> <target...>` scans PE data qwords and common x64 RIP-relative code operands, including immediate memory stores, for references to exact VA/RVA targets, with `.pdata` function attribution when available
- `reverser pe-function-literals <pe> <start:end...>` scans PE function ranges for string literals reached by RIP-relative or MOVABS operands
- `reverser pe-function-calls <pe> <start:end...>` lists recognized direct and common indirect call instructions inside PE function ranges, with `.pdata` target attribution when available
- `reverser pe-indirect-dispatches <pe> <start:end...>` annotates indirect callsites with simple backtracked register/object-field origins, useful for vtable-style service dispatches such as `CALL [RAX+0x20]`
- `reverser pe-instructions <pe> <start:count|start..end...>` decodes lightweight x64 instruction windows with call/branch target annotation and raw-byte fallback for unsupported opcodes
- `reverser pe-runtime-functions <pe> <address...>` maps VA/RVA addresses to `.pdata` runtime-function ranges and neighboring entries
- `reverser pe-read-qwords <pe> <address[:count]...>` reads mapped PE qword rows from VA/RVA addresses and annotates image-section or executable targets
- `reverser pe-read-strings <pe> <address[:byte_count]...>` reads ASCII and UTF-16LE C strings from exact mapped PE VA/RVA addresses
- `reverser pe-vtable-slots <pe> <address[:count]...>` reads PE vtable slots and annotates executable targets with `.pdata` function ownership
- `reverser pe-rtti-type-descriptors <pe> <address...>` reads MSVC RTTI TypeDescriptor rows and extracts decorated plus lightly parsed type names
- `reverser pe-provider-descriptors <pe> <address...>` summarizes provider descriptor rows, clone/materializer thunks, and RTTI getter slots
- `reverser pe-provider-descriptor-scan <pe>` scans non-executable PE sections for provider descriptor rows whose clone/materializer slot points back to the row; `--include-refs` adds setup-function clusters and `--cluster-json-out`/`--cluster-csv-out` writes compact worklists, optionally with `--cluster-include-literals`
- `scripts/GhidraDumpWindowsPy.py` is a workspace-local headless Ghidra helper for exact instruction windows such as `0x140020522:70` or `0x140020540:120:12` during external-target reversing
- `scripts/GhidraReadCStringPy.py` reads exact-address C strings such as `0x140B5E03C` or `0x140B69720:128` during quick no-analysis literal recovery
- `scripts/GhidraFindRefsPy.py` attempts raw-reference plus operand-level xref triage for exact addresses when a full analyzed project is not warranted; on `-noanalysis` imports, run a targeted `GhidraDumpWindowsPy.py` window first so operand scans have decoded instructions to inspect
- `scripts/GhidraFindScalarBytesPy.py` scans executable blocks, or all memory with `--all`, for little-endian scalar byte patterns such as struct offsets like `0x19C80` when raw xrefs are unavailable
- `scripts/GhidraReadQwordsPy.py` reads exact-address little-endian qword tables such as `0x140BA0630:16` or `0x140C41920:4` and annotates executable targets plus inline ASCII literals during quick no-analysis vftable and descriptor recovery
- `scripts/GhidraReadPdataPy.py` decodes Windows x64 `.pdata` `RUNTIME_FUNCTION` entries so unwind metadata references are not mistaken for real callsites or dispatch tables
- `scripts/GhidraWin64StackArgsPy.py` tracks simple Win64 function-entry `RSP`/`RBP` offsets and labels stack references such as shadow space versus `stack-arg5+`
- `scripts/GhidraCallsiteArgsPy.py` emits immediate Win64 callsite argument setup candidates for exact `CALL` addresses, including register args and outgoing stack slots
- `reverser js5-export <cache> <outdir>` materializes decoded JS5 rows and prints a manifest to stdout
- `reverser js5-pseudocode-blockers <export>` summarizes ready-versus-blocked clientscript pseudocode status from an existing JS5 export manifest
- `reverser archive-export <archive> <outdir>` extracts ZIP, TAR, and 7z archives, with optional password prompt/env input for authorized access
- `reverser api` runs a localhost-only JSON API
- `reverser catalog-ingest` stores reports or raw targets in a reusable local catalog
- `reverser catalog-search` queries the catalog by signature, engine, tag, path, or hash
- `--csv-out` on scan and catalog search produces flat CSV for spreadsheets and BI tools
- `reverser schema --list` enumerates available schema kinds and API paths for agents
- `reverser schema --kind <kind>` prints any registered response or request contract, for example `report`, `external-target-index`, `external-tool-inventory`, `pe-direct-calls`, `pe-callsite-registers`, `pe-address-refs`, `pe-function-literals`, `pe-function-calls`, `pe-indirect-dispatches`, `pe-instructions`, `pe-runtime-functions`, `pe-qwords`, `pe-strings`, `pe-vtable-slots`, `pe-rtti-type-descriptors`, `pe-provider-descriptors`, `pe-provider-descriptor-scan`, `pe-provider-descriptor-clusters`, `js5-manifest`, `analyze-request`, or `js5-opcode-probe-request`
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
- `clientscript-pseudocode-blockers.json` when clientscript exports include ready or blocked pseudocode status snapshots
- preview `.png` files for decoded sprite archives when the payload format matches the Jagex sprite container layout
- `.mesh.obj` files for decoded RT7 models when the mesh is small enough for safe sidecar export
- semantic kind counts in the manifest summary so headless agents can quickly see what was decoded
- optional raw `.container.bin` files when `--include-container` is used

Blocker triage example:

```powershell
reverser js5-pseudocode-blockers reports\models-rt7 --stdout-format pretty
```

## Archive export example

```powershell
reverser archive-export C:\Investigations\sample.7z reports\archive --password-prompt --stdout-format pretty
```

This writes:

- extracted archive members into the output directory when a valid password is supplied
- a `manifest.json` even when extraction stops at `password-required`
- safe-path guards so archives with traversal-style member names are rejected instead of extracted

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
- `GET /schema`
- `GET /schema/report`
- `GET /schema/scan-index`
- `GET /schema/diff`
- `GET /schema/catalog-search`
- `GET /schema/catalog-ingests`
- `GET /schema/external-tool-inventory`
- `GET /schema/pe-address-refs`
- `GET /schema/pe-function-literals`
- `GET /schema/pe-function-calls`
- `GET /schema/pe-indirect-dispatches`
- `GET /schema/pe-runtime-functions`
- `GET /schema/pe-qwords`
- `GET /schema/pe-strings`
- `GET /schema/pe-vtable-slots`
- `GET /schema/pe-rtti-type-descriptors`
- `GET /schema/pe-provider-descriptors`
- `GET /schema/pe-provider-descriptor-scan`
- `GET /schema/pe-provider-descriptor-clusters`
- `GET /schema/js5-manifest`
- `GET /schema/js5-opcode-probe`
- `GET /schema/js5-opcode-interior-probe`
- `GET /schema/js5-opcode-subtypes`
- `GET /schema/js5-branch-clusters`
- `GET /schema/js5-pseudocode-blockers`
- `GET /schema/analyze-request` and `GET /schema/js5-opcode-probe-request` expose representative POST body contracts; `GET /schema` lists the full request and response registry
- `POST /analyze` with `{"target":"C:\\Path\\To\\file.exe"}`
- `POST /scan` with `{"target":"C:\\Games\\Example","max_files":500,"workers":6}`
- `POST /diff` with `{"base":"reports\\old.json","head":"reports\\new.json"}`
- `POST /js5/export` with `{"target":"C:\\Path\\To\\js5-47.jcache","output_dir":"reports\\models-rt7","tables":["cache"],"limit":25}`
- `POST /js5/opcode-probe` with `{"source":"reports\\models-rt7\\manifest.json","opcode":317,"table":"cache","key":5,"file_id":0,"max_hits":16}`
- `POST /js5/opcode-interior-probe` with `{"source":"reports\\models-rt7\\manifest.json","opcode":317,"table":"cache","keys":[5,7],"ready_only":true,"max_hits":16}`
- `POST /js5/opcode-subtypes` with `{"source":"reports\\models-rt7\\manifest.json","opcode":317,"table":"cache","key":5,"file_id":0,"max_hits":16}`
- `POST /js5/branch-clusters` with `{"source":"reports\\models-rt7\\manifest.json","opcode":317,"table":"cache","key":5,"file_id":0,"max_hits":16}`
- `POST /js5/pseudocode-blockers` with `{"source":"reports\\models-rt7\\manifest.json","max_sample":12}`
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
