# Carthago demo scenario

## What the demo shows

The demo simulates a compromised laptop that shifts from normal outbound activity into suspicious behavior that should be grouped into one investigation instead of many disconnected alerts.

Primary story:

1. Normal host activity from `192.168.1.44`
2. DNS spike
3. New external destination
4. New ASN / country
5. Unusual destination port
6. High outbound traffic
7. Threat-intel / reputation hit
8. One correlated incident with evidence, related anomalies, related detections, risk score, and actions

## Incident timeline / attack story

The demo incident now also builds a clear attack story instead of only showing a flat list of alerts.

The story should include:

1. the simulated demo start
2. DNS-related detection and anomaly activity
3. destination novelty and geography changes
4. unusual port and outbound-volume changes
5. threat-intel or reputation context
6. risk increases as evidence accumulates
7. recommended-action generation
8. analyst feedback items if you mark the incident expected, false positive, or suspicious

## Run the app

From the repository root:

```powershell
dotnet restore DOTNET.sln
dotnet build DOTNET.sln
dotnet run --project Carthago\Carthago.csproj -- --demo-mode
```

In debug builds, the demo section is visible automatically. In other builds, pass `--demo-mode`.

## Trigger the demo incident

1. Open `Settings`
2. Scroll to `Developer Demo Mode`
3. Click `Simulate compromised laptop`

The app will generate labeled demo anomaly and detection data through the analytics host, then return to the anomaly-first dashboard.
The confirmation banner should read:

- `Demo incident generated: Suspicious outbound behavior from 192.168.1.44`

## Analyst feedback and false-positive reduction

The demo now also proves the local analyst feedback loop.

Available feedback actions in the incident detail view:

- `Confirm suspicious`
- `Mark expected`
- `Mark false positive`
- `Suppress similar`
- `Trust destination for this host`
- `Trust port for this host`
- `Trust process for this host` when process data exists
- `Save note`

What they do:

- expected / false-positive feedback lowers future similar risk with an explainable reason
- confirmed-suspicious feedback increases future similar risk with an explainable reason
- suppression lowers visibility for a similar pattern for 7 days, but threat-intel and critical evidence stay visible
- trust actions reduce novelty-driven risk for the same host and destination / port / process
- notes stay local and are attached to the incident detail view

Suggested demo walkthrough:

1. Run `Simulate compromised laptop`
2. Open the incident details
3. Click `Mark expected` or `Mark false positive`
4. Click `Clear demo data`
5. Run `Simulate compromised laptop` again
6. Confirm the new incident shows a lower score or a feedback reason such as:
   - `Risk reduced: similar behavior marked expected by analyst.`

## ML.NET anomaly scoring v1

The demo now also feeds enough normal per-host history into the analytics pipeline for ML-assisted scoring to participate when recent behavior becomes unusual.

What it does:

- builds short per-host feature windows
- uses ML.NET time-series spike detection to look for unusual outbound bytes, destination fan-out, rule-hit spikes, and similar host changes
- adds a supporting `ML-assisted` anomaly when the score is meaningful

What it does not do:

- it does not replace deterministic rules
- it does not replace baseline learning
- it does not decide final severity on its own
- it does not require the LLM path

If ML history is too short, the demo still works and the deterministic anomaly-first story remains intact.

## What should appear on the dashboard

You should see:

- one main incident titled `Suspicious outbound behavior from 192.168.1.44`
- risk score in the High or Critical range
- the host and destination surfaced clearly
- evidence and risk reasons in the investigation panel
- related anomalies and related detections in the incident details
- optional `ML-assisted` supporting evidence and risk reasons if enough history was available
- updated KPI cards and anomaly timeline entries

The incident should remain tagged as simulated demo data.

## How to inspect the incident

From the dashboard:

1. Select the incident card in the investigation queue
2. Review the summary, evidence, risk reasons, actions, related anomalies, and related detections

Or open `Incident Queue` from the sidebar for the full incident page. You can also copy:

- summary
- JSON export
- markdown report

The detail view also shows:

- current analyst feedback state
- suppression state if active
- feedback-applied reasons
- analyst note text
- incident timeline / attack story

The timeline helps answer:

- what happened first
- what happened next
- when risk increased
- whether ML-assisted evidence appeared
- which analyst actions changed the score

## Raw / advanced data access

Raw and forensic views stay available from the sidebar:

- `Raw Traffic`
- `Raw Detections`
- `Sink Delivery`
- `Cisco Tools`

The demo mode does not replace those views and does not make raw telemetry the default experience.

## Clear demo data

Use `Settings -> Developer Demo Mode -> Clear demo data`.

This removes tagged demo incidents, demo anomalies, and demo-tagged feedback only. It does not wipe user settings, live sink configuration, or non-demo incidents.
The confirmation banner should read:

- `Demo data cleared`

## Export behavior

`Copy JSON export` and `Copy markdown report` now include timeline items so you can share the full incident story, not just the final score and evidence list.

## Known limitations

- Demo data is injected at the analytics host layer, not the live capture driver, so raw capture grids are not polluted with fake packets.
- The feature is intentionally hidden unless running a debug build or launching with `--demo-mode`.
- Remaining build warnings are package compatibility `NU1701` warnings for `SkiaSharp.Views.WPF` and `SnmpSharpNet`.
- ML.NET anomaly scoring is supporting evidence only and may stay quiet when recent history is too short or too uniform.
- Feedback is local-only and rule-based in this pass; it is not a separate ML model and does not auto-block traffic.

## What this proves

This demo proves the anomaly-first product flow works end to end:

- correlated anomalies and detections
- explainable risk scoring
- useful recommended actions
- optional LLM summaries with deterministic fallback
- anomaly-first dashboard presentation instead of a raw packet table

## Minimal dashboard integration

The compromised-laptop demo integrates with the modular dashboard system.

When demo mode is enabled, the widget registry exposes the **Demo controls** widget and the **Demo View** preset. The widget can generate the existing compromised-laptop scenario for `192.168.1.44`, clear only labeled demo data, and keep the incident queue focused on one correlated high-risk incident instead of many fragmented alerts.

When demo mode is disabled, the Demo Controls widget and Demo View preset are hidden. No demo UI is forced onto the main dashboard.

## Demo UI note

When Carthago is started with `--demo-mode`, the compromised-laptop scenario should now appear in a cleaner anomaly workspace. The expected behavior is still the same: the demo should produce one clear correlated high-risk incident and related anomaly evidence, but the visual presentation should be calmer, more serious, and easier to explain during a demo.


## Grouped anomaly timeline

The anomaly workspace now collapses similar anomaly signals by category, source host, destination, protocol, and port. This prevents repeated ML/baseline windows from overwhelming the analyst while preserving the latest signal details, grouped occurrence count, exportable evidence, and raw/advanced telemetry access.

ML-assisted anomaly evidence is shown in a readable form: model name, confidence, score, top feature drivers, and analysis window appear as evidence chips. Raw feature values remain available under Raw feature values for deeper review.
