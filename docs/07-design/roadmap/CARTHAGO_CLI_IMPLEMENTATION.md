# CARTHAGO CLI — CLI-001

2026-11-13 · SOURCE CANDIDATE — UNVERIFIED · Tests authored, not executed by the publishing environment.

The owner authorized initial CLI development. This implementation is an isolated,
read-only companion, not a headless detection engine. It targets .NET 8 with no
WPF dependency. The existing CSA snapshot/archive implementation is source-linked
rather than duplicated; a shared portable library is a future extraction.

## Commands

Run from the repository root with the .NET 8 SDK (or compatible SDK):

```powershell
dotnet build Carthago.Cli/Carthago.Cli.csproj -c Release
dotnet run --project Carthago.Cli -c Release -- --help
dotnet run --project Carthago.Cli -c Release -- status --json
dotnet run --project Carthago.Cli -c Release -- capabilities
dotnet run --project Carthago.Cli -c Release -- session inspect ./session.csa --json
dotnet test Carthago.Cli.Tests/Carthago.Cli.Tests.csproj -c Release
```

Publish separately from WPF if desired:

```powershell
dotnet publish Carthago.Cli/Carthago.Cli.csproj -c Release -r win-x64 --self-contained false
```

Use linux-x64 for a Linux candidate; neither platform is verified by this commit.
The executable is named carthago (carthago.exe on Windows).

## Contract

- JSON schemaVersion 1; stdout contains a single successful response. Errors go
  to stderr, as a single JSON object when the trailing --json option is supplied.
- Exit 0 success, 2 usage, 3 data/runtime error, 130 cancelled.
- status describes the CLI process only; live engine health is unavailable.
- Session inspection uses CSA v1 inventory/hash/count checks and outputs only
  the fixed category names and counts. Archive hashes do not authenticate the
  producer. Imported sessions never become trusted events. Empty categories
  mean zero stored rows, not zero detections in the real world.
- Inherits existing CSA limits (256 MiB per category / 512 MiB total declared
  content); the shared reader materializes the snapshot, so large-archive
  memory and performance need dedicated validation before production use.
- No capture, network listeners, sensor control, configuration changes, or
  automatic discovery of live databases. No raw rows, arbitrary metadata or
  exception paths are emitted. No new external dependencies for the CLI.

## Next gates

1. CLI-002: versioned read-only DTOs and authenticated local IPC threat model;
   audit existing live status/health and rule catalog access boundaries.
2. CLI-003: read-only live status/rules and sensor health; distinguish unavailable
   sources, stale data and zero counts; add positive/negative/privacy tests.
3. CLI-004: bounded events/incidents queries with filtering and pagination.
4. CLI-005: headless engine lifecycle, platform capture providers and explicit
   permissions, only after runtime design review and Windows/Linux validation.

The WPF application and its unavailable CLI companion placeholder remain unchanged.
See [future architecture](CARTHAGO_CLI_AVALONIA_FUTURE_ARCHITECTURE.md).

## CLI-002 — opt-in Windows local read endpoint

SOURCE CANDIDATE — UNVERIFIED. New portable Carthago.Contracts project; fixed
v1 binary frames (18-byte request, 39-byte response), correlation ID, command
allowlist, bounded counts, timestamps, no identity claims from the wire.
Windows named pipe uses a protected current-user SID DACL, first-instance
creation and PIPE_REJECT_REMOTE_CLIENTS; client uses CurrentUserOnly and local
"." server name. One request per connection, five-second I/O deadlines; a one-byte client acknowledgment prevents disconnect from discarding unread responses.
Same-account processes are inside the trust boundary: this is not signed
application attestation or protection against a compromised same-user process.

Explicitly enable the WPF listener (ordinary startup remains unchanged):

```powershell
dotnet run --project Carthago/Carthago.csproj -c Release -- --enable-cli-ipc
# In a separate terminal, same account and elevation:
dotnet run --project Carthago.Cli -c Release -- engine status --json
dotnet run --project Carthago.Cli -c Release -- rules summary --json
```

Host reachability is not capture or engine health. Rule summary reads
RuleCatalog.All (default registered catalog, not all available content packs);
enabled-by-default and planned counts may overlap. Validation and live
configuration state are not assessed. A disconnected or unavailable source
returns error 3, not zero counts. Linux live queries return unsupported_platform.
Offline commands retain their existing semantics. No sensor/control or event
ingestion operation is exposed. The existing health Snapshot method consumes
capture-drop deltas, so it is deliberately not used for a read-only CLI query.

Tests: protocol round trip, bad version/opcode/length, impossible counts,
correlation mismatch, unavailable source, CLI projection, and Windows loopback
candidate. Before promoting: run Windows build and tests, verify same-account
success, different-user/elevation rejection, remote SMB rejection, timeout,
restart, pipe squatting and concurrent requests on real Windows. No runtime
tests executed by publishing environment. Linux offline build also remains
unverified.

## CLI-003A — offline catalog and qualification-ledger queries

SOURCE CANDIDATE — UNVERIFIED. No changes to live IPC or WPF. Uses existing
CSA v1 Rules rows and the explicitly supplied qualification resume ledger.

```powershell
dotnet run --project Carthago.Cli -c Release -- rules list ./session.csa --offset 0 --limit 25 --json
dotnet run --project Carthago.Cli -c Release -- rules show ./session.csa R001 --json
dotnet run --project Carthago.Cli -c Release -- rules quality ./docs/rules/RULE_QUALIFICATION_RESUME_LEDGER.md --json
```

Catalog rows are imported and untrusted; only fixed metadata fields are
projected. Numeric ordering, duplicate rejection, page size 1–100, default 50,
missing metadata remains null. Existing archive integrity/size checks apply;
the reader still materializes the archive, so pagination bounds output, not
archive memory. No evidence, descriptions or arbitrary metadata are emitted.
Catalog counts are stored rows, not live registered/active/validated rules.

The ledger command reads at most 4 MiB / 10,000 rows and recognizes the
specific seven-column markdown table. It counts exact audit-pending labels,
explicit producer-blocked labels and other/unclassified rows; no execution,
coverage or validation inference. It rejects malformed or duplicate rows.
The historical ledger is provisional, not a complete rule inventory.
A future machine-readable, pinned-SHA execution manifest is required for
actual qualification counts. Live catalog pagination and sensor health remain
CLI-003B; no false claim of their implementation. Tests authored, unexecuted.
