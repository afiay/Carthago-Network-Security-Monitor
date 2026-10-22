## Carthago Page Purpose Rules

Each major page should answer a different analyst question. The goal is to avoid turning every screen into the same dashboard with different data.

- Dashboard = overview
- Anomalies = behavior triage and model explanation
- Incidents = case investigation and response workflow
- Incident Queue = triage and case prioritization
- Threat Feed = IOC intelligence and feed matching
- Raw Traffic = packet and flow forensics
- Raw Detections = rule-hit inspection
- Settings = configuration and governance

## Design System Notes

- Keep the shell consistent across pages: sidebar, top monitoring bar, footer, and global workspace chrome stay shared
- Page bodies should use the shared dark SOC palette from `Views/Theme.xaml`
- Default pages should stay compact and serious, with advanced evidence one click away instead of always expanded
- Long technical values should favor `TextWrapping="NoWrap"`, `TextTrimming="CharacterEllipsis"`, and tooltips instead of vertical wrapping
- Main pages should prefer page-level scroll over competing nested scroll regions when dense tables are already paged

## v23 Anomalies Alignment

The anomalies workspace follows the page-purpose rule by focusing on:

- dense triage queue
- selected anomaly investigation
- baseline comparison
- model explanation
- analyst shortcuts to deeper evidence

It intentionally does not mirror the dashboard's whole-system overview layout.

## v24 Incidents Alignment

The incidents-related pages now follow the same page-purpose rule more explicitly:

- `Incident Queue` is the operational board for triage, filtering, paging, and case prioritization
- `Incidents` is the case workspace for evidence review, analyst note-taking, related anomalies, timeline, and response decisions

That keeps the workflow progression clearer:

1. Triage in the queue
2. Open the full incident workspace
3. Route into deeper evidence pages only when needed
