# Threat Feed Workspace

The Threat Feed page is a focused IOC and reputation-match workspace for Carthago.

It uses real detection events already flowing through the application and projects them into threat-match rows when evidence indicates an IOC, reputation hit, suspicious infrastructure, suspicious domain, Tor/evasion endpoint, C2 wording, malware wording, phishing wording, or high/critical severity signal.

The page intentionally does not fake external feed delivery. When no real feed-related evidence exists, it shows a clean empty state.

## Main sections

- KPI cards for active matches, high-confidence indicators, blocked/suppressed count, recent indicators, and feed health.
- Threat Feed Matches list with severity, score, indicator, feed source, confidence, and time.
- Threat Match Details panel with selected IOC context.
- Evidence / Observations section.
- Tags and related rule IDs.
- Recommended actions.
- Feed-source and IOC-type summary panels.
- Raw/Advanced shortcuts for deeper investigation.

## Blocking behavior

The Block Indicator button is disabled until a real blocking or suppression workflow is connected. This avoids presenting fake containment functionality.

## Data model

The page is backed by `DetectionEvent` data and related `Incident` context from the existing analytics host. It is a presentation projection, not a separate duplicated detection pipeline.
