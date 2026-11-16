# Enrichment Phase 16.1 — focused Windows qualification

Parent: `af7d218642ebfcb4d2257ade26a310a343ce6c1c`; tree: `b67a68d8dbb87ef3de24e5a87c2dc3b489ff6e06`. Reviewed root verify-local.ps1, Windows test project, worker health source/tests, test inventory and development ledger. The existing full verification runner remains unchanged; this companion is intentionally scoped to enrichment and asset/communication tests.

Run from a clean Windows checkout:

```powershell
git switch feature/carthago-reliability-hardening
git pull --ff-only origin feature/carthago-reliability-hardening
.\verify-enrichment.ps1 -SelfTest
.\verify-enrichment.ps1 -LiveOutput
```

Each run uses a unique build-verify/enrichment directory, records exact HEAD, Release test-project build (including app reference), filters, exit codes, TRX counters and JSON summary. Zero tests, skipped tests, missing/malformed TRX, failures or source changes cannot qualify. The two groups are selected from existing test classes; counts are measured, not assumed. SelfTest checks four synthetic TRX outcomes and missing evidence. No native capture, visual or performance qualification is performed; these remain explicitly not-run. No tests or PowerShell execution occurred during authoring. Windows owner execution pending. The JSON qualified flag refers only to these focused tests, not overall enrichment completion.

Next: review actual Windows evidence and extend the runtime sampling protocol with a local process sampler and explicit session/backend metadata; retain native capture and visual checks as separate gates.

## Phase 16.2 — read-only runtime sampling

Run after starting the desired capture and warming up for five minutes. Supply the actual application PID (Get-Process), backend and remote enrichment configuration. Example: ` .\\measure-enrichment-runtime.ps1 -TargetProcessId 1234 -Backend Npcap -RemoteEnrichment Disabled -DurationMinutes 30 `. Use 120 minutes for the extended run. `-SelfTest` exercises four CPU arithmetic fixtures. CSV samples include monotonic elapsed time, UTC, private bytes, working set, thread count, cumulative CPU and normalized CPU percent (first sample blank). JSON records declared configuration, checkout HEAD (not proof of binary provenance), process start identity and completion or failure. Process exit/reuse is not a successful run. No capture is started or stopped; record dashboard counters and shutdown separately. No performance thresholds or runtime passes claimed.


## Phase 16.3 — aggregate application counter snapshots

During the runtime sampler, open Monitoring Health and click Copy aggregate counters (JSON) at the beginning, every five minutes, and at the end. Save each clipboard value to a separate local JSON file. Match processId and processStartedUtc to runtime.json and sampledUtc to samples.csv; do not combine different process identities. Snapshot time is the UI refresh time, not clipboard time. Service-lifetime counters may span capture restarts; registry gauges are current/last session and must not be differenced across sessions. Export contains only selected aggregate counters, no packet payloads or checkpoint diagnostic text. Missing snapshots remain null; absent provider rows are omitted. No automatic polling or file writes added. UI and Windows test execution pending.


## Phase 16.4 — runtime evidence correlation

Run ` .\analyze-enrichment-runtime.ps1 -SelfTest ` then ` .\analyze-enrichment-runtime.ps1 -RuntimeDirectory <runtime-dir> -HealthPaths <first.json>,<second.json> `. Supply snapshots in chronological order within the process sampling window. Output JSON reports measured CPU, private memory change and per-interval publication/fallback/worker elapsed metrics; null means unavailable. No performance acceptance, binary provenance or native capture accuracy is inferred. Four synthetic fixtures authored; execution pending. Registry gauges and provider/checkpoint deltas are not analyzed in this increment.

### Provider interval evidence (Phase 16.5a)

The analyzer reports per-provider outcome deltas, cache-hit deltas, success share and mean elapsed milliseconds. The denominator includes all five terminal outcomes, including cancellation; cache hits are separate path events. Missing provider rows are omitted and zero outcomes yield null ratios. Counter decreases reject the evidence. Run `./analyze-enrichment-runtime.ps1 -SelfTest` (seven fixtures). Windows execution remains pending.


### Phase 16.5b — GeoIP and checkpoint intervals

City and ASN completed database attempts are derived separately from found/not-found/failed deltas. Cache eligible requests are derived from positive/negative hits and misses, not database attempts; occupancy is an ending gauge, not a delta. Checkpoint writes and failures are independent of the ending diagnostic flag, which is not a warning count. Missing snapshots yield null; decreasing lifetime counters reject. Session registry deltas remain unavailable without session identity. Five additional synthetic fixtures authored (twelve total); execution pending. Run `./analyze-enrichment-runtime.ps1 -SelfTest`.


### Phase 16.5c — invariant runtime evidence

Sampler writes floating-point CSV values using invariant round-trip formatting. Analyzer parses decimal strings with invariant Float style (no grouping), rejects boolean and nonfinite values, and accepts typed UTC/offset timestamps returned by newer PowerShell JSON readers. Offsetless strings and unspecified DateTime values reject. Added Swedish-culture decimal and malformed-value fixtures; run both sampler and analyzer -SelfTest in Windows PowerShell 5.1 and PowerShell 7. Existing locale-dependent CSV evidence may require recollection. Execution pending.


### Phase 16.6a — Registry identity

Aggregate schema 1 adds optional `storage.registrySessionId`, the GUID of the current/last observed-asset registry, captured under the lifecycle lock with its capacity snapshots. This is registry identity, not proof of active capture. The analyzer emits registry rejection deltas only when both snapshots have the same nonempty GUID; legacy, missing or changed identities yield null. Ending counts and limits are gauges. Same-registry rejection decreases reject evidence. Run `analyze-enrichment-runtime.ps1 -SelfTest` and the `EnrichmentHealthPresentationTests` group; Windows execution pending.


### Phase 16.6b — Registry lifecycle token presence

Schema 1 storage adds nullable `registryRunPresent`, sampled under the same lifecycle lock as registry identity and capacity. True means a non-cancelled run token exists, not that native capture is delivering packets; false includes initial/stopped retained registries; null means unavailable. Registry rejection deltas remain registry-scoped, including retained final counters. Three export theory cases authored; Windows execution pending. Run `dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --filter FullyQualifiedName~EnrichmentHealthPresentationTests`.


### Phase 16.6c — Analyzer repair and lifecycle integration

Removed a duplicated trailing script fragment and repaired the unterminated timestamp regex in the live analyzer. Same-registry intervals expose nullable fromRunPresent/toRunPresent without inferring native capture activity. Three full Analyze JSON-roundtrip scenarios cover retained stopped registry, replacement and missing lifecycle flag; Windows execution pending. Run `./analyze-enrichment-runtime.ps1 -SelfTest` in Windows PowerShell 5.1 and PowerShell 7. Production lifecycle concurrency remains pending.
