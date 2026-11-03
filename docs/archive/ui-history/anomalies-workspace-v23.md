## Anomalies Workspace v23

### Purpose
The Anomalies page is the behavior-triage and anomaly-investigation workspace for Carthago. It is intentionally different from the Dashboard:

- Dashboard answers: what matters across the system right now
- Anomalies answers: which anomaly matters, why it triggered, how it differs from baseline, and what the analyst should do next

### Layout
The page body keeps the existing Carthago shell and renders three workspace bands:

1. A compact anomaly KPI strip
2. A split main workspace:
   - left: dense anomaly triage queue with filters and pagination
   - right: selected anomaly investigation cockpit
3. A lower analyst band:
   - entity behavior history
   - baseline drift and peer group comparison
   - analyst actions and shortcuts

The page uses page-level scrolling only. The queue itself is paged to about seven visible rows so it does not rely on an inner vertical scrollbar.

### Data Projection Approach
The page keeps the existing anomaly and incident runtime path from `SinkHost.Analytics` and projects it in `Views/AnomaliesPage.xaml.cs`.

Current projections include:

- KPI counts from recent anomalies and linked incidents
- grouped anomaly queue rows from recent anomaly signals
- linked incident context from recent incidents
- baseline comparison text derived from peer-normal anomaly patterns
- model explanation from structured anomaly reasons, related rule IDs, ML feature keys, and incident correlation
- lower panels from host-level and peer-level anomaly aggregations

No production values are hardcoded. Demo-only content still depends on the existing `--demo-mode` runtime path.

### Empty State Behavior
The page handles empty or partial runtime states explicitly:

- No anomalies:
  `No anomaly signals yet. Start monitoring or run demo mode to populate behavior signals.`
- No selected anomaly:
  `Select an anomaly to inspect baseline comparison, model signals, and recommended actions.`
- No baseline:
  `Baseline still learning. Not enough historical traffic to compare this host against normal behavior.`
- No linked incident:
  the investigation panel shows the honest standalone state and the incident action routes to the live incident queue flow when available

### Actions and Routing
The page routes to real existing views where possible:

- Pivot to Host -> Host Integrity, with Analytics fallback if needed
- Query detections -> Raw Detections
- Search in Raw Traffic / Open Raw Traffic -> Raw Traffic
- Escalate to Incident -> Incident Queue when no related incident exists
- View Related Incident -> Incidents workspace when correlation exists
- Create Detection Rule -> Settings / Detection Rules shell destination
- Export Evidence Pack -> copies structured anomaly evidence JSON

If a direct feature is not implemented, the page shows an honest status message instead of pretending the action succeeded.

### Validation Notes
Validated in this pass:

- `dotnet build .\Carthago.sln --no-restore`
- `dotnet test ..\DOTNET.sln --no-build`
- `dotnet run --project .\Carthago.csproj --no-build --no-restore`
- `dotnet run --project .\Carthago.csproj --no-build --no-restore -- --demo-mode`

In the Codex sandbox, app startup logs still show the known network and local-store environment restrictions:

- threat-feed SSL/network access is blocked here
- `%LocalAppData%\Carthago\analytics.db` is not writable here

Those are sandbox limitations, not compile failures in the anomalies workspace itself.
