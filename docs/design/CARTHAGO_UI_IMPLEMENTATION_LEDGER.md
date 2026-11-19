

## GA ENRICHMENT UI — Monitoring Health operational sections

**2026-11-19 · SOURCE CANDIDATE — UNVERIFIED.** Baseline branch HEAD `882bd36c393376b1d8fc61b4592320aa7e60822d`, authoritative commit TREE `6bdb23946004e8248e5aca6ced2de9829e2662ef`. The existing Monitoring Health page already contained capture diagnostics, provider outcomes, and aggregate export. This increment gives the existing enrichment measurements dedicated sections for queue/worker operations, publication and evidence coverage, session storage/checkpoints, and GeoIP/process diagnostics. The existing provider grid, aggregate JSON export, summary text, and snapshot lifecycle remain in place.

**Data boundaries:** all displayed values are reused from the current `EnrichmentHealthPresentation` accounting helpers. Queue depth is an instantaneous gauge; fallback, worker, coverage, registry rejection, and checkpoint counters retain their existing service-lifetime or session-lifetime scopes. Process TCP socket ownership and UDP local binding remain distinct denominators; ETW publication is explicitly distinguished from packet evidence. TLS capacity rejection is session-scoped. No new source events, denominators, detector evidence, or confidence claims are introduced.

**Ownership:** `Carthago/Services/EnrichmentHealthPresentation.cs`, `Carthago/Views/MonitoringHealthPage.xaml`, `Carthago/Views/MonitoringHealthPage.xaml.cs`, `Carthago.Tests/EnrichmentHealthPresentationTests.cs`, and the validation ledgers. No detection rules, capture producers, enrichment admission, shared telemetry contracts, or qualification workflows changed.

**Unexecuted acceptance:** focused xUnit, WPF build/render, scroll/keyboard/screen-reader review, narrow-width layout, Windows runtime, and sustained-performance checks remain pending. **Next UI/enrichment gate:** build and run the focused presentation tests, then verify the new sections against a live Windows capture session without treating observational coverage as protocol recall or qualified detection evidence.
