# Carthago anomaly-first validation

## Build

Run from the repository root:

```powershell
dotnet restore DOTNET.sln
dotnet build DOTNET.sln
dotnet test DOTNET.sln --no-build
```

## Start the app

Launch the WPF client from the repository root:

```powershell
dotnet run --project Carthago\Carthago.csproj
```

The default view should open on the anomaly-first dashboard, not the raw traffic table.

To reveal the developer demo section outside debug builds, launch with:

```powershell
dotnet run --project Carthago\Carthago.csproj -- --demo-mode
```

## Verify the empty state

1. Start the app without feeding traffic.
2. Confirm the dashboard can show the minimal empty state:
   - `Your dashboard is empty`
   - `Enable sections or add widgets from Settings to build your security workspace.`
3. Confirm the empty state exposes actions for adding a widget, opening Settings, or applying a recommended layout.
4. Open `Anomalies` and `Incident Queue` from the sidebar and confirm both views show intentional empty cards rather than empty grids.

## Verify baseline learning

1. Start monitoring and let a single normal host generate repeated, ordinary outbound traffic for a few windows.
2. Confirm the dashboard and `Anomalies` page show baseline confidence as `Low` first.
3. Confirm the message says more observations are needed before strong anomaly scoring is available.
4. After several windows, confirm confidence advances and novelty signals begin appearing only when behavior actually changes.

## ML.NET anomaly scoring v1

ML.NET anomaly scoring adds a second, lightweight behavior signal based on recent per-host feature windows.

It does:

- aggregate 5-minute host windows
- score unusual outbound bytes, destination fan-out, rule-hit spikes, novelty bursts, and threat-intel concentration
- add `ML-assisted` supporting evidence to incidents and risk reasons

It does not:

- replace deterministic rules or baseline logic
- decide final severity by itself
- require the optional LLM summarizer

Operational notes:

1. Short history stays quiet and should not crash or spam anomalies.
2. ML scoring can be disabled in code if a conservative rollout is preferred.
3. ML-only signals should not create Critical incidents on their own.

## Trigger or simulate an incident

Use the deterministic developer demo scenario from the app or the test suite.

In the app:

1. Open `Settings`
2. Scroll to `Developer Demo Mode`
3. Click `Simulate compromised laptop`
4. Confirm the app returns to the dashboard and highlights one correlated incident for `192.168.1.44`

From tests:

```powershell
dotnet test DOTNET.sln --no-build --filter AnalyticsHost_DemoScenario_Creates_Single_HighRisk_Incident
```

That scenario uses `AttackRunner.BuildCompromisedLaptopScenario()` and simulates:

1. Normal host traffic.
2. A DNS spike.
3. A new external destination.
4. A new ASN / country.
5. An unusual destination port.
6. High outbound volume.
7. A reputation hit.

Expected result:

- one incident for the host
- title similar to `Suspicious outbound behavior from 192.168.x.x`
- correlated detections and anomalies on the same incident
- non-empty evidence, risk reasons, recommended actions, and summary
- optional `ML-assisted anomaly score: xx/100` risk reason when enough history exists
- a demo confirmation message naming `Suspicious outbound behavior from 192.168.1.44`

## Analyst feedback and false-positive reduction

Incident details now include local analyst feedback actions:

- `Confirm suspicious`
- `Mark expected`
- `Mark false positive`
- `Suppress similar`
- `Trust destination for this host`
- `Trust port for this host`
- `Trust process for this host`
- `Save note`

Validation steps:

1. Run the demo incident.
2. Open the incident details from the dashboard or `Incident Queue`.
3. Click `Mark expected`.
4. Confirm the feedback state changes and the detail view shows a reason like:
   - `Risk reduced: similar behavior marked expected by analyst.`
5. Click `Clear demo data`.
6. Run the demo again.
7. Confirm the new incident for the same host shows a reduced score or feedback-applied reasons.
8. Repeat with `Confirm suspicious` and confirm future similar incidents include:
   - `Risk increased: similar behavior previously confirmed suspicious.`

Operational notes:

1. Suppression lasts 7 days in this v1 implementation.
2. Suppression and trust rules stay local and persist on disk.
3. Threat-intel and critical evidence are not silently hidden even when a pattern was previously trusted or suppressed.
4. Feedback adjusts scoring explainably; it does not delete evidence or raw telemetry.

## Incident timeline / attack story

Every incident can now include a time-ordered story built from correlated telemetry and analyst actions.

Timeline item types include:

- `Detection`
- `Anomaly`
- `MlSignal`
- `RiskChange`
- `Feedback`
- `Suppression`
- `TrustRule`
- `Summary`
- `StatusChange`
- `RecommendedAction`
- `DemoStep`

Validation steps:

1. Run the demo incident.
2. Open the incident details.
3. Confirm the `Incident timeline / attack story` section is present.
4. Confirm the story is ordered by time.
5. Confirm it includes detections, anomalies, and at least one risk-change entry.
6. If ML has enough history, confirm an `ML-assisted` item appears.
7. Mark the incident expected or false positive and confirm an analyst-feedback item appears in the story.
8. Confirm the timeline remains bounded and readable instead of repeating identical items.

Use during investigation:

1. Start at the earliest story item to see what happened first.
2. Look for `Risk change` entries to understand why severity increased or decreased.
3. Review `Analyst feedback`, `Suppression`, and `Trust rule` items to understand why the current score differs from the original demo run.

## Confirm incident correlation

1. Open the dashboard or `Incident Queue`.
2. Confirm the demo behavior creates one host-centric incident rather than many separate cards.
3. Confirm `OccurrenceCount` increases as related detections or anomalies are added.
4. Confirm evidence, related anomalies, and related detections do not contain obvious duplicates.

## Confirm risk scoring

1. Select the incident in the dashboard or `Incident Queue`.
2. Confirm the risk score is between 0 and 100.
3. Confirm the severity band matches the score:
   - `0-30 Low`
   - `31-60 Medium`
   - `61-80 High`
   - `81-100 Critical`
4. Confirm the investigation panel shows human-readable risk reasons.
5. If ML had enough history, confirm the risk reasons mention that it is `ML-assisted` supporting evidence rather than a final verdict.

## Confirm recommended actions

1. Select an incident with DNS, outbound-volume, or threat-intel evidence.
2. Confirm the action list is non-empty.
3. Confirm the actions are investigative and practical, not vague and not auto-blocking by default.

## Export or copy incident details

From `Incident Queue`, select the incident and confirm:

1. `Copy summary` copies the incident summary text.
2. `Copy JSON export` copies a structured export including timestamps, category, and evidence.
3. `Copy markdown report` copies a demo-friendly markdown incident report.
4. Analyst feedback state, suppression state, feedback reasons, notes, and timeline items appear in the export.

## Confirm statistics customization

1. Open the dashboard.
2. Add a `Statistics card`.
3. Change the selected metric.
4. Change the selected time window.
5. Restart the app and confirm the card keeps the selected metric and time window.

## Confirm raw traffic is still available

Use the left navigation:

- `Raw Traffic` for `TrafficRecord` rows
- `Raw Detections` for `DetectionEvent` rows
- `Sink Delivery` for sink emissions and sink failures
- `Cisco Tools` for live Cisco syslog if configured

These are the Advanced / Forensics surfaces. The main dashboard should remain anomaly-first.
The developer demo injects analytics-layer data only, so these raw views continue to show real capture and sink telemetry rather than fake packet rows.

## Confirm LLM is optional

By default, LLM summaries are disabled and the app uses deterministic fallback summaries.

Optional Ollama mode can be enabled with:

```powershell
$env:CARTHAGO_ENABLE_OLLAMA = "true"
$env:CARTHAGO_OLLAMA_URL = "http://127.0.0.1:11434"
$env:CARTHAGO_OLLAMA_MODEL = "qwen2.5:7b"
```

Validation points:

1. Run without these variables and confirm incidents still receive summaries.
2. Point the URL at an invalid endpoint and confirm incident creation, scoring, and actions still work.
3. Confirm the UI remains responsive and the fallback summary appears instead of a crash.

## Known limitations

- `dotnet build` still reports package compatibility `NU1701` warnings for `SkiaSharp.Views.WPF` and `SnmpSharpNet` on `net8.0-windows`.
- Full WPF binding/runtime verification still depends on launching the app on a machine with desktop UI support.
- The developer demo path is intentionally hidden unless running a debug build or launching with `--demo-mode`.
- Demo data is injected into the analytics host, not the live packet-capture driver, so raw packet tables do not show synthetic packets.
- ML.NET anomaly scoring uses recent host windows only, so it can remain silent when history is short or highly uniform.
- Analyst feedback is host-pattern oriented and local-only in this pass. It reduces repeated noise but is not a replacement for analyst review or deterministic threat evidence.
- Suppressed incidents are de-emphasized through risk reduction rather than fully removed from stored history.

## Minimal dashboard validation

The anomaly-first pipeline remains the primary source of dashboard information, but the main view is now settings-driven.

Validation points:

1. The dashboard can be empty by default.
2. Incidents, anomalies, statistics, recommended actions, and advanced shortcuts appear only when the user enables the corresponding section or applies a preset.
3. Statistics are calculated from existing incident, anomaly, baseline, and detection snapshots.
4. Raw traffic and raw detections remain available from Advanced / Forensics navigation but are not displayed by default.
5. Demo mode creates the same correlated high-risk incident, but the demo controls appear only when demo mode is enabled.

## UI validation addition: serious anomaly workspace

The anomaly-first validation flow should also verify the redesigned Anomalies page:

- The timeline should show compact anomaly cards rather than raw detection rows.
- The selected anomaly should open in a structured Signal Details panel.
- The risk score and severity should be visible without dominating the rest of the evidence.
- Reasons, rule IDs, tags, investigation guidance, and linked-incident context should remain available in the details panel.
- Filtering/searching should not break selection or the empty state.
- Advanced/raw telemetry should remain available through the existing navigation, not embedded into the anomaly timeline.


## Grouped anomaly timeline

The anomaly workspace now collapses similar anomaly signals by category, source host, destination, protocol, and port. This prevents repeated ML/baseline windows from overwhelming the analyst while preserving the latest signal details, grouped occurrence count, exportable evidence, and raw/advanced telemetry access.

ML-assisted anomaly evidence is shown in a readable form: model name, confidence, score, top feature drivers, and analysis window appear as evidence chips. Raw feature values remain available under Raw feature values for deeper review.
