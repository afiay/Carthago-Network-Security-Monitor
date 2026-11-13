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

## CLI-003B — live catalog and heartbeat queries

SOURCE CANDIDATE — UNVERIFIED. Adds separate v2 Windows pipe, using the same
current-user local-only security boundary as v1. Both opt in with
--enable-cli-ipc. No change to v1 framing or offline commands. v2 uses a
4-byte big-endian length prefix, strict bounded JSON (1 KiB request, 128 KiB
response), correlation IDs, allowlisted queries, typed responses, bounded
pages (1–100), five-second I/O deadlines and acknowledgment. Synchronous catalog construction/validation is not preemptible; it runs on the background listener task. No mutation.

```powershell
dotnet run --project Carthago/Carthago.csproj -c Release -- --enable-cli-ipc
# Second terminal, same Windows user/elevation:
dotnet run --project Carthago.Cli -c Release -- rules list --live --offset 0 --limit 25 --json
dotnet run --project Carthago.Cli -c Release -- rules show R001 --live --json
dotnet run --project Carthago.Cli -c Release -- rules validate --json
dotnet run --project Carthago.Cli -c Release -- sensors list --json
dotnet run --project Carthago.Cli -c Release -- sensors health --json
```

Rules use RuleCatalog.All, numeric core rule ordering, registered/default
metadata only. Catalog validation invokes RuleCatalog.Validate, returning
error count and exit 3 for a failed structural check; not detection accuracy
or rule qualification. No active config assertion.

Sensor queries read the existing CommonApplicationData/Carthago/sensors
heartbeat journal files for the current UTC date plus six previous dates.
Each file is bounded to 1 MiB, records to 8192 characters and unique IDs to
10,000. Latest timestamp wins regardless of file order. Missing journals,
malformed records (including duplicate JSON fields) or size/permission errors return unavailable, not zero.
Fresh means at most five minutes old, future means more than 30 seconds
ahead of observation, otherwise stale. This is unverified journal freshness,
not authenticated telemetry or runtime liveness. Only safe sensor IDs,
timestamps and freshness labels are projected. No active probes or control.
A future timestamp can mask earlier heartbeats and must be treated as
untrusted, not healthy. Older files outside the window are not inspected.

Authored portable protocol, CLI, heartbeat projection and Windows loopback
tests; no execution in publishing environment. Verify actual Windows
builds, pipe lifecycle and account/remote restrictions before promotion.

## CLI-004A — offline investigation queries

SOURCE CANDIDATE — UNVERIFIED. Six read-only forms query existing CSA v1
Alerts, Incidents, Traffic and Hosts categories. No live journal or engine
query in this increment; no new IPC surface. Explicit file path required.

```powershell
dotnet run --project Carthago.Cli -c Release -- alerts list ./session.csa --severity high --limit 25 --json
dotnet run --project Carthago.Cli -c Release -- alerts show ./session.csa <event-id> --json
dotnet run --project Carthago.Cli -c Release -- incidents list ./session.csa --json
dotnet run --project Carthago.Cli -c Release -- incidents show ./session.csa <incident-id> --json
dotnet run --project Carthago.Cli -c Release -- events list ./session.csa --source-ip 192.168.1.10 --json
dotnet run --project Carthago.Cli -c Release -- hosts list ./session.csa --json
```

List options: offset >= 0, limit 1–100 (default 50), exact canonical source
IP, exact severity for alerts/incidents only (info/low/medium/high/critical).
Pages preserve stored row order, not chronological order. Show accepts N/D
GUIDs; duplicate alert/incident IDs or conflicting incident aliases fail
closed. Missing/invalid mandatory identity rows and non-IP host labels are
counted as omitted. Missing optional fields remain null. Traffic display
timestamps are not converted to UTC; only explicit UTC event/incident/host
fields are used. Fixed enum/identifier/IP/numeric projections omit arbitrary
descriptions, payload, analyst notes, process names and evidence. IPs and
identifiers are still sensitive operational metadata. Archive integrity is
not authentication. Output explicitly describes retained snapshot coverage,
not a full capture or complete journal. Pagination bounds output but the
existing CSA reader materializes all categories; memory gate remains open.
Tests authored, no execution. Live journal/incident queries are CLI-004B.

## CLI-004B — bounded live investigation

SOURCE CANDIDATE — UNVERIFIED. Separate v3 local pipe; v1/v2 unchanged.
Same user, local-only, opt-in, five-second I/O deadline, strict bounded JSON
and correlation validation. Shared portable projection also serves offline
CSA commands. Syntax: alerts/incidents list|show --live [ID or filters],
events/hosts list --live [filters]. No tail/streaming yet.

Alerts: current UTC date journal via DetectionJournal.Current.GetJournalPath,
8 MiB / 20,000 rows / 128 Ki characters per row; incomplete or malformed
journal unavailable. No previous-day lookup, no full history, no signature
verification; journal contents are persisted records, not proof of live
capture or authenticated detections. Camel-case journal and Pascal-case CSA
fields accepted, ambiguous case-duplicate fields rejected. Incidents: up to
1,000 cache entries using existing GetRecentIncidents ordering. Traffic:
retained UI rows, no inferred UTC timestamp. Hosts: current observed-host
table, at most 10,000 entries, no online assertion. UI projections run on
dispatcher at background priority; no mutation. Missing source is not zero.
Pagination is bounded, not an immutable cross-query snapshot; cache changes
may change ordering/counts between pages. Synchronous cache clone and
dispatcher projection are not preemptible; cancellation checked per row.
Runtime tests and native pipe verification still required. No Actions run.

## CLI-004C — historical journal windows and polling tail

SOURCE CANDIDATE — UNVERIFIED. Adds optional V3 request filter fields
journalDate (YYYY-MM-DD UTC) or sinceMinutes (1–1440), mutually exclusive,
live alerts list only. Null fields omitted on wire for existing V3 commands.
Old V3 hosts reject new fields; update both host and CLI. Server resolves
relative windows using its observation clock. Half-open [start,end) UTC
range; relative window may span at most two daily journals. Each uses
existing 8 MiB/20,000-record cap. Any missing required day, malformed
record, invalid identity or missing explicit UTC timestamp fails closed.
No implicit historical coverage or signature claim. Future calendar dates
are rejected. Pages preserve day then file order, not timestamp order.

```powershell
dotnet run --project Carthago.Cli -c Release -- alerts list --live --date 2026-11-12 --json
dotnet run --project Carthago.Cli -c Release -- alerts list --live --since 1h --severity high --json
dotnet run --project Carthago.Cli -c Release -- alerts tail --live --severity high --json
```

Tail replays the current UTC day's matching rows from the beginning, then
polls every two seconds, 100 rows per page with one-row overlap and bounded
20,000 emitted IDs. JSON is NDJSON, one record per line, stdout only; errors
go to stderr, Ctrl+C returns 130. Stops on unavailable/malformed source,
cursor mismatch, count shrink, duplicate IDs, capacity or UTC date change.
Restart replays the current day, so consumers must deduplicate across
restarts. Overlap detects some shifts/truncation but cannot prove immutable
prefix, losslessness, atomic snapshots or cross-midnight delivery. No
automatic retry, durable checkpoint or push subscription. Relative windows
are recalculated each request; use fixed date for more stable paging.
Tests authored, unexecuted; Windows and .NET validation pending.

## CLI-005A — Windows foreground headless monitor

SOURCE CANDIDATE — UNVERIFIED. New Carthago.Monitor Windows console project
references existing WPF engine assembly; no Application/window or message
pump is started. Actual TrafficCaptureService Npcap path shares session
initialization with desktop. Headless mode bypasses UI delivery queue and
dispatcher callbacks, retains packet parsing/local enrichment/rule evaluation
and existing mandatory detection journal. Remote WHOIS/reputation/VPN
classification and external sinks/analytics host are not started. No
threat-feed initialization, active sensors, ETW or Linux capture yet.

```powershell
dotnet run --project Carthago.Monitor -c Release -- capture interfaces --json
dotnet run --project Carthago.Monitor -c Release -- monitor start --interface '<exact Npcap ID>' --filter 'tcp' --json
```

Foreground only: Ctrl+C stops, returns 130; startup or shutdown failure
returns 3. Explicit exact interface; BPF filter fails closed if rejected.
No automatic device selection. Status defaults to every five seconds,
1–60 seconds configurable. Counters are actual pipeline totals, not
proof of lossless capture, sustained liveness or detection accuracy.
Legacy engine stdout is suppressed during monitor run; journal preserved.
Existing error logs may still contain operational details. Close desktop
first; foreground mutex only protects same-session foreground instances.
Existing synchronous native start/stop may block; ten-second worker wait
does not bound native stop. Cancellation can discard queued enrichment;
not a drain or no-loss guarantee. No service manager, persistent daemon,
remote stop, IPC or automatic restart in this increment. Tests authored,
not executed. Windows Npcap permissions, real device start/filter/stop,
journal creation, desktop regression and worker shutdown require tests.

## CLI-005B — headless IPC and explicit stop authorization

SOURCE CANDIDATE — UNVERIFIED. Foreground monitor --enable-cli-ipc reserves
existing V1/V2/V3 read endpoints and a separate V4 monitor lifecycle pipe
before capture starts. Same current-user SID, local-only, first-instance
security boundary; no application identity attestation. V1/V2 reuse desktop
providers; V3 uses same journal reader, non-alert queries unavailable (no
headless analytics/traffic/host cache). Desktop V4 is not exposed. If any
default endpoint is occupied, startup fails closed; close desktop first.
An unexpected endpoint exit requests monitor shutdown. No remote network IPC.

```powershell
dotnet run --project Carthago.Monitor -c Release -- monitor start --interface '<exact Npcap ID>' --enable-cli-ipc --allow-cli-stop
# Other terminal, same user/elevation:
dotnet run --project Carthago.Cli -c Release -- monitor status --json
dotnet run --project Carthago.Cli -c Release -- engine health --json
dotnet run --project Carthago.Cli -c Release -- alerts list --live --json
dotnet run --project Carthago.Cli -c Release -- monitor stop
```

Stop is disabled by default and requires both launch flags. A stop request
targets a nonempty per-process session GUID; CLI resolves status once if
--session GUID not supplied. Server commits cancellation only after valid
response acknowledgment. Acceptance is not proof of shutdown; client
disconnect or native blocking can prevent completion. No process kill,
arbitrary commands, service manager, restart or remote start. Status
returns lifecycle and most recent sampled counters (nullable before
sampling), sample time and observation time, no inferred health/accuracy.
Stop and Ctrl+C use the existing cancellation/disposal path (exit 130 if
successful cancellation, 3 on failure). Existing desktop capture without
IPC is not excluded by pipe ownership. Tests authored, Windows validation
and native capture still pending.

## CLI-005C1 — Windows SCM service host

SOURCE CANDIDATE — UNVERIFIED. New service run/validate commands in
Carthago.Monitor, ServiceBase integration via System.ServiceProcess.ServiceController
8.0.0. Config is explicit, absolute path, UTF-8 JSON <=16 KiB, strict
schema/version and fields. Service uses same foreground Npcap adapter and
rule/journal path; no desktop UI, external sinks, remote IP enrichment,
foreground IPC or CLI stop. SCM owns lifecycle, not a privileged pipe.
Service runs with the configured Windows account; do not use LocalSystem
by default. See service deployment guide for prerequisites and commands.

Startup waits for adapter confirmation (30s, plus bounded cleanup wait);
SCM pending wait hint requested. Stop cancels worker and waits 20s;
native start/stop may block and cancellation can discard pending records.
Stop timeout/failure is not a successful shutdown. Unexpected worker exit
after startup terminates the dedicated service process with exit 3 for SCM
failure handling; recovery policy is operator-controlled, not auto-installed.
Service startup uses deployment directory for bundled resources; existing
preferences and journal directories resolve under service identity. No
durable status snapshot, cross-account query, installer or recovery policy
automation yet. Tests authored, not executed; build, SCM and real Npcap
qualification still required.

## CLI-005C2 — SCM commands and durable service sample

SOURCE CANDIDATE — UNVERIFIED. Fixed local CarthagoMonitor SCM name;
CLI service status/start/stop/health/doctor, native SCM authorization
(minimum access per operation), no elevation or arbitrary service names.
Start/stop poll up to 30 seconds for SCM confirmation, cancellation
returns 130 without rolling back an already requested transition.
Service sample written atomically to CommonApplicationData/Carthago/
ServiceStatus/monitor.json at configured interval; preprovision directory
with service-write/admin-control and intended operator-read ACLs.
Write failure fails the monitoring worker. Schema/size/identity checks,
PID + actual process start time, 120s freshness, future timestamps reject;
SCM state rechecked after read. A fresh sample is not continuous capture
health, lossless capture, journal delivery or detection accuracy proof.
Stale/invalid/missing/mismatched/unreadable sample not exposed as current.
SCM status independent of sample; health/doctor exit 3 if no fresh sample.
No install/recovery automation, capture validation or Windows tests run.

## CLI-005C3A — deployment preflight and observed-scope qualification

SOURCE CANDIDATE — UNVERIFIED. Read-only preflight checks deployment,
runtime, Npcap registration, exact interface/config, SCM ImagePath,
non-LocalSystem identity, broad-write ACL screening and input hashes.
Explicit lifecycle opt-in requires stopped service and exclusive capture/
permissions confirmation. Start, check matching fresh samples and actual
capture/parse counter movement, stop, inspect bounded same-day journal
append, restart and confirm new session, finally stop. No traffic injection,
installation, ACL mutation, recovery policy change or service process kill.
Journal is shared, not session-attributed; no detection is inconclusive.
RequireJournalEvidence requires observed append and detection counter delta.
Manual restart is not crash recovery. Windows execution pending.

## CLI-005C3B — cooperative machine-wide capture reservation

SOURCE CANDIDATE — UNVERIFIED. Shared TrafficCaptureService reserves a
Windows Global named mutex object before Npcap or ETW startup. Ownership
is object existence (exclusive creation), not thread-affine mutex wait;
handle closes on confirmed native cleanup, process exit or crash.
Authenticated users can open existing object with SYNCHRONIZE only;
SYSTEM/admin full access. Existing object or access failure rejects startup.
Native stop/close/detach failures retain handle in process-lifetime
quarantine; no restart in that process. ETW cleanup errors tracked.
Reservation covers cooperative desktop/foreground/service capture paths,
not arbitrary third-party or older builds, not all independent sensors,
not pending enrichment/rule evaluation or authenticated owner identity.
Named object squatting can deny startup; no security-boundary claim.
Windows cross-process/session/account, crash release, actual native
startup/stop and desktop regressions remain unverified.

## CLI-005C3C — measured pipeline assessment

SOURCE CANDIDATE — UNVERIFIED. Headless adapter adds native Started,
last packet UTC, queue depth/capacity, live/configured worker tasks,
worker faults/fallbacks, evaluation count and process-lifetime journal
failure/persisted/rule failure counters. Health read is non-destructive.
Foreground V4 Health request returns extended counters; old Status/Stop
requests omit extension. Service snapshot schema 2 includes pipeline;
reader accepts schema 1 (unknown assessment) and schema 2. Update CLI
and service together; old readers reject schema 2. Engine health is
foreground only; service health is SCM/process-bound. Fixed policy:
120s sample age, 30s recent packet window, 80% queue pressure, 10% lifetime
parse error ratio with >=20 attempts. Fail on native not started,
zero worker tasks or any lifetime journal failure; degrade on worker
exit/fault, fallback, rule failure, queue pressure or parse ratio.
Historical failures latch until process restart; no recovery inference.
Idle is not proof of native source health; healthy means observed
pipeline with no measured degradation, not losslessness/accuracy.
Journal not exercised if no persisted event; external sink delivery
not assessed. Samples are non-atomic across counters. Tests authored,
Windows/runtime verification pending.
