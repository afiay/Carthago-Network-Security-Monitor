## Incidents and Incident Queue Workspaces v24

### Purpose Split
The incidents-related workspaces now follow a clearer page-purpose split:

- Incident Queue = triage and case prioritization
- Incidents = full case investigation and response workflow

This avoids the previous state where both shell destinations rendered through the same page and felt too similar.

### Incident Queue
The queue is now routed to the dedicated `IncidentQueuePage`.

The page emphasizes:

- compact queue KPIs
- severity, status, owner, and text filters
- a dense, paged triage table
- a selected-incident snapshot on the right
- lower panels for timeline, affected hosts, and response checklist

The queue intentionally stays compact and operational. It answers:

`Which cases need attention first, and what does the triage snapshot look like right now?`

### Incidents
The incidents workspace remains the richer case-investigation surface.

The page emphasizes:

- incident-focused KPI strip
- curated case list on the left
- a full incident investigation cockpit on the right
- analyst note entry
- feedback and trust actions
- related anomalies, affected hosts, timeline, and checklist

It answers:

`What happened in this case, what evidence supports it, and what response decision should the analyst take?`

### Layout Notes
- The queue uses explicit paging instead of relying on a dominant inner queue scrollbar
- The incidents page uses page-level scrolling so the lower investigation content is not clipped
- Long host, destination, and incident values are kept readable with ellipsis and tooltips instead of vertical wrapping

### Routing
The queue now routes through `IncidentQueuePage`, while `OpenIncidentWorkspace(...)` continues to route to `IncidentsPage`.

Additional navigation helpers were added in `MainWindow.Navigation.cs` so page actions can open:

- Raw Traffic
- Raw Detections
- Anomalies
- Host Integrity
- Incidents

### Validation Notes
Validated in this pass:

- `dotnet test DOTNET.sln --no-build`
- isolated no-restore build outputs:
  - `dotnet build .\Carthago\Carthago.csproj --no-restore -p:UseAppHost=false -o .\build-verify\carthago`
  - `dotnet build .\Carthago.Tests\Carthago.Tests.csproj --no-restore -p:UseAppHost=false -o .\build-verify\tests`
- startup smoke check from alternate output:
  - `dotnet .\build-verify\carthago\Carthago.dll -- --demo-mode`

Local `bin\Debug` validation was blocked only because a running `Carthago.exe` already held the default debug output files open.
