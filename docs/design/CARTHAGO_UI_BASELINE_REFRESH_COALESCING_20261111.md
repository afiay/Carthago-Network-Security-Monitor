# WPF analytics refresh coalescing — validation record

**Assessment: NOT RELEASE READY.** The final WPF candidate eliminated recurring multi-second dispatcher waits in a 328-second VPN run: zero queue drops, maximum recorded dispatcher wait 1,287 ms, maximum oldest-batch age 339 ms, and responsive navigation. Publication remains blocked because that final run averaged only 37.6 captured records/second rather than the approximately 78-record/second comparison target, the fresh full verifier still has four mutual-TLS relay failures during peer/certificate authentication, and the remote HEAD cannot be freshly verified while Git TLS trust is failing. No commit or push is permitted.

## Scope and evidence

- Authorized branch: `feature/carthago-reliability-hardening`
- Starting local and remote HEAD: `68aa86b908bc61c661553f4b2da31e60f01b384b`
- Candidate capture source: `Npcap: Microsoft (\Device\NPF_{020CA261-AEA6-48FC-B65F-CCE86BCC84E9})`
- VPN during candidate run: `Norton VPN WireGuard`, adapter status `Up`
- Baseline pipeline trace: `%TEMP%\carthago-ui-pipeline-next.csv`
- Baseline operation profile: `%TEMP%\carthago-ui-operations.csv`
- Candidate pipeline trace: `%TEMP%\carthago-ui-final-20261111-184612.csv`
- Candidate operation profile: `%TEMP%\carthago-ui-operations-final-20261111-184612.csv`

The baseline trace does not record the selected capture source, VPN adapter, CPU, or memory. It proves the original failure on this Windows host, but it is not a fully controlled same-source baseline. The candidate source and VPN state were recorded directly. This comparability limitation is itself a release blocker.

## Confirmed stall mechanism

`TrafficCaptureService.UiChannelReaderLoop` schedules bounded UI drain work at `DispatcherPriority.Background`. Delivery invokes the per-record traffic subscriber, which feeds `SinkHost` and `AnalyticsHost`. Analytics publishes baseline status for each processed analytics envelope and can also raise incident and anomaly notifications.

Before this candidate, the dashboard posted separate `DispatcherPriority.Background` callbacks from baseline, incident, and anomaly notifications. Each callback could rebuild dashboard layout and update the monitoring header. That work competes at the same dispatcher priority as the UI drain. The failing five-minute trace recorded only nine `TrafficGridBatch` calls while `DashboardLayout` ran 537 times and consumed 17,181 ms of synchronous profiled time; the queue then remained at its 5,000-record capacity for 118 samples. This establishes redundant analytics-driven dashboard work as a material starvation source rather than subscriber batch processing, whose maximum was 1 ms in that trace.

The grouped candidate confirms that this source is material but also shows that simple in-flight coalescing is insufficient under continuous traffic. Requests arriving during a refresh immediately cause a follow-up refresh, so the dashboard can still sustain a layout loop. The candidate recorded 887 `DashboardLayout` calls and 36,246 ms of synchronous layout work over 584 seconds. Five sampled dispatcher waits exceeded two seconds, and oldest batch age reached 9,294 ms. A future correction needs an explicit bounded refresh cadence or a narrower incremental UI update; that work was not attempted after the final failed gate.

## Candidate implementation

- `DashboardAnalyticsRefreshCoalescer` accumulates incident, anomaly, and baseline flags atomically behind the existing `UiRefreshCoalescer` scheduling contract.
- Dashboard analytics handlers request grouped work instead of each posting a full-layout callback.
- A grouped callback reloads only the bounded snapshots whose flags are pending, then performs one layout/header pass.
- Capture configuration, parsing, detection rules, alert delivery, queue capacity (5,000), drop accounting, and bounded newest-first traffic history are unchanged.

## Tests and verification

The coalescer tests were created before the implementation. The initial focused build failed with `CS0246` because `DashboardAnalyticsRefreshCoalescer` did not yet exist. After implementation, its four cases passed, including combined flags, one follow-up for an update during refresh, and invalid flag rejection.

Fresh final focused command:

```powershell
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --no-restore --filter "FullyQualifiedName~DashboardAnalyticsRefreshCoalescerTests|FullyQualifiedName~UiRefreshCoalescerTests|FullyQualifiedName~DashboardCallbackGateTests|FullyQualifiedName~CaptureUiDrainTests|FullyQualifiedName~CaptureSessionDeliveryTests|FullyQualifiedName~CaptureSessionCoordinatorTests|FullyQualifiedName~BoundedTrafficRowsTests|FullyQualifiedName~CaptureFlowHealthTests|FullyQualifiedName~PerformanceMetricTests|FullyQualifiedName~AnalyticsPipelineTests|FullyQualifiedName~SinkManagerTests"
```

Result: **77 passed, 0 failed**. This covers the new grouped scheduling behavior plus existing drain scheduling, cancellation, bounded/newest-first history, counters, analytics, and sink paths selected by the filter.

Fresh `verify-local.ps1` result:

- restore tests: pass
- restore benchmarks: pass
- build tests: pass
- build benchmarks: pass
- tests: **11,683 passed, 4 failed, 0 skipped, 11,687 total**
- failing class: `RedisAuditMutualTlsRelayReceiverTests`
- failing cases:
  - `Malformed_Vendor_Event_Closes_Authenticated_Bridge`
  - `Pinned_Mtls_Receives_Two_Length_Framed_Events_Without_Retaining_Json`
  - `Bridge_Uses_Pinned_Relay_Id_For_Existing_Diagnostic_Intake`
  - `Oversized_And_Zero_Length_Frames_Fail_Before_Handler`
- failure mode: two cases return `PeerAuthenticationFailed` instead of the expected framed-protocol result; two client handshakes throw because the remote certificate is rejected by the validation callback.
- benchmark process completed and refreshed `build-verify/tuning-benchmark.json`: 161 replay samples, 0 benign critical alerts, 0 sample errors, and 0 contract issues across 895 audited rules. The test-stage failures make the overall verifier fail regardless.

The same four mutual-TLS cases also failed in the earlier full run and in a focused nine-test rerun (five passed, four failed). The UI candidate does not touch those files, but the repository release gate remains red.

## Windows VPN measurements

| Metric | Baseline failing trace | Grouped candidate |
|---|---:|---:|
| Duration | 298.0 s | 584.1 s |
| Source / parsed checkpoint | 15,507 / 15,324 (reported failure checkpoint) | 22,201 / 21,604 at the last visible pre-pause checkpoint |
| Pipeline captured | 23,366 | 22,888 |
| UI delivered | 423 | 21,984 |
| UI queue drops | 17,524 | 0 |
| Drops per 1,000 captured | 750.0 | 0.0 |
| Maximum queue depth | 5,000 | 524 |
| Maximum dispatcher wait | 130,948 ms | 3,554 ms |
| Dispatcher samples at or above 2 s | 144 | 5 |
| Maximum oldest batch age | 248,310 ms | 9,294 ms |
| UI drain batches | 9 | 585 |
| Synchronous subscriber batch maximum | 1 ms | 36 ms |
| CPU | not captured | 24.8% mean, 31.7% maximum across 18 five-second samples on 8 logical processors |
| Memory | not captured | working set 287.5–331.6 MB; private bytes 173.7–209.4 MB during the sampled intervals |
| Responsiveness | UI unable to keep pace | Monitoring Health, Live Traffic, and Overview accepted navigation while capture continued; visible state changed within the 750 ms observation interval |
| Flow diagnostic | `UI_DELIVERY_STALLED` | `CAPTURE_AND_UI_FLOWING` during capture; `CAPTURE_STOPPED` after the operator pause |

The candidate was paused through the UI and closed gracefully. The 288 `skippedCanceled` records in the final CSV are cancellation accounting after pause, not queue drops.

## Release decision and remaining risk

The throughput improvement is substantial, and there were no UI queue drops in this run. Nevertheless, acceptance criterion 4 is not met: dispatcher stalls lasting multiple seconds recur, and oldest-batch latency remains multi-second. The baseline comparison is also missing a recorded capture source/CPU/memory, and full local verification fails. No commit or push is permitted from this validation state.

The final remote refresh also failed with `SSL certificate OpenSSL verify result: unable to get local issuer certificate (20)`. The existing local tracking ref still equals local HEAD at `68aa86b908bc61c661553f4b2da31e60f01b384b`, but the latest server-side remote HEAD could not be revalidated. This independently prevents publication under the concurrent-update rule.

The next investigation should capture WPF UI-thread stacks or ETW/WPA dispatcher, layout, and render activity during the recurrent 2–9 second intervals. If analytics refresh remains the dominant source, test a fixed maximum dashboard refresh frequency or incremental view-model updates rather than another immediate-follow-up coalescer.

Independent code review found no critical correctness or lost-update issue. It confirmed that the coordinator bounds work in flight but not refresh frequency. It also identified a minor interleaving in which a request between sampling `Version` and `TakePending()` can be consumed by the current callback while causing an empty follow-up that still performs layout/header work. A subsequent design should skip `None` work or associate drained flags atomically with the handled version, and should add deterministic concurrent request/drain/complete plus dispatcher/gate-closure integration tests.

## Final hardening continuation

### Runtime-driven design corrections

The immediate-follow-up coalescer described above was retained as historical evidence and then replaced. Deterministic tests first established a lock-protected, time-aware coordinator with accumulated incident/anomaly/baseline flags, non-overlap, a full trailing interval, cancellation, concurrent requests, and a `None` guard. Runtime evidence then required three further corrections:

1. The initially selected 500 ms production cadence still reached a 4,847 ms dispatcher maximum and 99,195 ms oldest-batch age during a clean traffic surge. The production interval is now two seconds; the coordinator remains configurable and retains exact 500 ms boundary tests.
2. The two-second candidate still stalled because the hidden Live Traffic grid received a collection Reset for every delivered batch. `BoundedTrafficRows` now retains the same newest-first 200 records without notifying the collapsed grid, and Live Traffic navigation issues exactly one Reset. Capture batching, the 5,000-record delivery queue, record order, queue drops, and cancellation accounting are unchanged.
3. Analytics presentation now rebuilds only while Overview is visible. Detection presentation uses the same bounded coordinator. Returning to Overview shows cached content immediately and requests an asynchronous `All` refresh instead of synchronously rebuilding the entire visual tree.
4. Global preference notifications still update dashboard state, customization sources, and the monitoring header while Overview is hidden, but a shared presentation gate now prevents those notifications from rebuilding the collapsed dashboard layout.

This is a WPF presentation change. No capture service, parser, rule, alert-delivery, detection journal, durable outbox, queue-capacity, TLS-verification, or drop-accounting implementation changed.

### TDD and focused verification

The complete coordinator test class was observed RED against the pre-cadence API, then GREEN after implementation. A separate production-default test was observed RED at 500 ms and GREEN at two seconds. The hidden-grid test was observed RED because the notification-suppression API did not exist, then GREEN after implementation; it proves newest-first capacity is retained silently and one explicit Reset exposes the current rows. Final review then identified a remaining hidden preference-driven layout path. Its presentation-gate regression was observed RED because the gate did not exist, then GREEN after both preference and analytics presentation paths used it.

Final focused command:

```powershell
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --no-restore --filter "FullyQualifiedName~DashboardAnalyticsRefreshCoalescerTests|FullyQualifiedName~DashboardPresentationGateTests|FullyQualifiedName~UiRefreshCoalescerTests|FullyQualifiedName~DashboardCallbackGateTests|FullyQualifiedName~CaptureUiDrainTests|FullyQualifiedName~CaptureSessionDeliveryTests|FullyQualifiedName~CaptureSessionCoordinatorTests|FullyQualifiedName~BoundedTrafficRowsTests|FullyQualifiedName~CaptureFlowHealthTests|FullyQualifiedName~PerformanceMetricTests|FullyQualifiedName~AnalyticsPipelineTests|FullyQualifiedName~SinkManagerTests"
```

Result: **87 passed, 0 failed**. Existing nullable warnings outside the changed code remain; no warning is attributable to the new coordinator, timer, presentation gate, or bounded-row notification behavior.

### Runtime iteration history

| Candidate | Duration / rate | Drops / max queue | Dispatcher max / samples >=2 s | Oldest age max | Dominant profiled work | Decision |
|---|---:|---:|---:|---:|---|---|
| Original failing baseline | 298.0 s / 78.4 captured/s | 17,524 / 5,000 | 130,948 ms / 144 | 248,310 ms | DashboardLayout 537 calls / 17,181 ms | Failed |
| Immediate grouped follow-up | 584.1 s / 39.2 captured/s | 0 / 524 | 3,554 ms / 5 | 9,294 ms | DashboardLayout 887 / 36,246 ms | Failed |
| 500 ms cadence, clean surge | approximately 7.6 min / workload varied | 0 / 4,368 | 4,847 ms / recurring | 99,195 ms | TrafficGridBatch 560 / 18,172 ms; DashboardLayout 291 / 7,231 ms | Failed |
| Two-second cadence | approximately 3 min / target-like bursts | 0 / approximately 3,000 | 4,385 ms / recurring | over 33 s before pause | TrafficGridBatch 418 / 4,784 ms; DashboardLayout 61 / 2,278 ms | Failed |
| Hidden-grid suppression, synchronous Overview return | partial target-like run; first 51 s approximately 111 captured/s | 0 / returned to zero | 1,055 ms before navigation; 3,445 ms after navigation | subsecond before navigation | TrafficGridBatch 772 / 336 ms; DashboardLayout 68 / 2,716 ms | Grid fix passed; navigation failed |
| **Final hidden-grid + asynchronous Overview refresh** | **328.0 s / 37.6 captured/s** | **0 / 101** | **1,287 ms cumulative / 0 sampled rows >=1 s** | **339 ms** | **TrafficGridBatch 1,263 / 96 ms; DashboardLayout 164 / 3,956 ms** | **UI criteria passed; workload comparison incomplete** |

The first 500 ms run was excluded from final acceptance because repeated full accessibility-tree traversals contaminated the same dispatcher metric being measured. It is retained locally but not used as proof. The clean 500 ms and two-second failures used only file/process sampling and direct point invocation.

### Final five-minute VPN result

- Source: `Npcap: Microsoft (\Device\NPF_{020CA261-AEA6-48FC-B65F-CCE86BCC84E9})`
- VPN: `Norton VPN WireGuard`, status `Up`
- Pipeline: `%TEMP%\carthago-ui-pipeline-final-hardening-20261111-201410.csv`
- Operations: `%TEMP%\carthago-ui-operations-final-hardening-20261111-201410.csv`
- Measured capture interval: 328.0 seconds
- Captured / UI delivered: 12,471 / 12,105 final counters; 37.57 / 36.46 records per second over the measured delta
- UI queue drops: 0; drops per 1,000 captured: 0.000
- Maximum UI queue depth: 101
- Maximum recorded dispatcher wait: 1,287 ms; no per-sample `dispatcherWaitMs` row reached one second
- Maximum oldest-batch age: 339 ms; no sample reached two seconds
- UI drain batches: 1,263
- Synchronous `TrafficGridBatch`: 96 ms total, 75 ms maximum, 0.08 ms mean
- `DashboardLayout`: 164 calls, 3,956 ms total, 136 ms maximum, 24.12 ms mean
- CPU: 11.88% mean, 26.40% maximum across eight five-second samples on eight logical processors
- Memory: working set 344.1–361.7 MB; private bytes 232.4–244.5 MB
- Navigation invocation: Monitoring Health 6 ms, Live Traffic 2 ms, Overview 2 ms; the process remained responsive after each 750 ms observation interval
- Pause invocation: 29 ms; counters remained stable before graceful window close
- Flow behavior: queue repeatedly returned to zero during capture; no recurring multi-second dispatcher or oldest-batch samples

The ambient workload did not reproduce the 78.4 captured-record/second baseline. A local rate-limited HTTPS helper was attempted but denied by host policy and was not bypassed. The partial hidden-grid run did encounter approximately 111 captured records/second over its first 51 seconds with zero drops, a drained queue, and a 1,055 ms maximum before the then-synchronous Overview navigation introduced the sole 3,445 ms spike. This supports the grid correction under load but does not replace a complete five-minute comparable run.

### Fresh full verification and Redis mTLS diagnosis

The post-review `verify-local.ps1` run completed with CARTHAGO closed:

- restore tests: pass
- restore benchmarks: pass
- build tests: pass
- build benchmarks: pass
- tests: **11,693 passed, 4 failed, 0 skipped, 11,697 total**
- benchmark: pass; 161 replay samples, 0 benign critical alerts, 50/50 expected malicious matches, 895 audited default rules, 0 contract issues

The four failures remain exactly:

- `Malformed_Vendor_Event_Closes_Authenticated_Bridge`
- `Pinned_Mtls_Receives_Two_Length_Framed_Events_Without_Retaining_Json`
- `Bridge_Uses_Pinned_Relay_Id_For_Existing_Diagnostic_Intake`
- `Oversized_And_Zero_Length_Frames_Fail_Before_Handler`

Focused read-only diagnosis reproduced four failures and five passes. All failures require a valid client certificate; all transport-negative cases pass. The receiver returns `PeerAuthenticationFailed` inside `AuthenticateAsServerAsync`, before post-handshake framing, bridge intake, or oversized-frame validation. Exact leaf pinning, validity, and client-auth EKU checks pass before transport. Relevant production, bridge, and test source is byte-identical to commit `fd58208`, whose retained artifact passed all nine tests.

The strongest cause classification is a local Windows Schannel/private-key acquisition or client-certificate-selection problem exposed by the fixture's persistence assumption. The fixture imports its PFX with `DefaultKeySet | Exportable`; despite its comment, it does not explicitly request `PersistKeySet`. Windows build 10.0.26300, unsynchronized system time, and two same-day Windows updates are environment observations, not proof of causation. No certificate callback, pin, EKU, expiry, revocation, trust, or TLS assertion was weakened, and no TLS source was changed.

The preference-presentation gate was added after the recorded VPN run in response to final review. That run did not exercise preference changes during capture; the new branch only suppresses an additional hidden-layout path, but the performance evidence is therefore not a runtime measurement of the exact final tree. The post-review focused and full verification runs do cover the final source.

### Release decision

The WPF candidate meets the measured UI delivery/stall criteria in the final five-minute run and materially reduces hidden-grid work. The repository is still **NOT RELEASE READY** because:

1. the final run did not match the requested approximately 78 captured records/second for five minutes;
2. full verification is red on four independently diagnosed mTLS environment/fixture failures; and
3. a freshly fetched remote HEAD is still required before publication.

Therefore this work remains uncommitted and unpushed.

## Exact remaining validation commands

Close CARTHAGO before building, then run:

```powershell
dotnet test .\Carthago.Tests\Carthago.Tests.csproj -c Release --no-restore --filter "FullyQualifiedName~DashboardAnalyticsRefreshCoalescerTests|FullyQualifiedName~DashboardPresentationGateTests|FullyQualifiedName~UiRefreshCoalescerTests|FullyQualifiedName~DashboardCallbackGateTests|FullyQualifiedName~CaptureUiDrainTests|FullyQualifiedName~CaptureSessionDeliveryTests|FullyQualifiedName~CaptureSessionCoordinatorTests|FullyQualifiedName~BoundedTrafficRowsTests|FullyQualifiedName~CaptureFlowHealthTests|FullyQualifiedName~PerformanceMetricTests|FullyQualifiedName~AnalyticsPipelineTests|FullyQualifiedName~SinkManagerTests"
powershell -NoProfile -ExecutionPolicy Bypass -File .\verify-local.ps1
```

For a fresh controlled VPN run from the repository root:

```powershell
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$env:CARTHAGO_UI_DIAG_PATH = Join-Path $env:TEMP "carthago-ui-pipeline-$stamp.csv"
$env:CARTHAGO_UI_PROFILE_PATH = Join-Path $env:TEMP "carthago-ui-operations-$stamp.csv"
$diagPath = $env:CARTHAGO_UI_DIAG_PATH
$profilePath = $env:CARTHAGO_UI_PROFILE_PATH
dotnet build .\Carthago\Carthago.csproj -c Release --no-restore
Start-Process -FilePath .\Carthago\bin\Release\net8.0-windows10.0.19041.0\Carthago.exe -PassThru
Write-Host "Pipeline: $diagPath"
Write-Host "Operations: $profilePath"
```

Select the same Npcap source in the UI, confirm `Get-NetAdapter -Name 'Norton VPN WireGuard'` reports `Up`, start capture, and run this from a second terminal for five minutes:

```powershell
$diagPath = Get-ChildItem $env:TEMP -Filter 'carthago-ui-pipeline-*.csv' | Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\watch-ui-pipeline.ps1 -Path $diagPath -Samples 150 -IntervalSeconds 2
$profilePath = Get-ChildItem $env:TEMP -Filter 'carthago-ui-operations-*.csv' | Sort-Object LastWriteTime -Descending | Select-Object -First 1 -ExpandProperty FullName
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\summarize-ui-operations.ps1 -Path $profilePath
Get-Counter '\Process(Carthago)\% Processor Time','\Process(Carthago)\Working Set - Private' -SampleInterval 5 -MaxSamples 60
```

Pause capture through the UI before closing the application. Re-run the same workload on the true pre-change baseline with the same source and settings if a strict controlled before/after comparison is required.
