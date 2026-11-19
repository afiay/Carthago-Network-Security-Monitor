

## GA ENRICHMENT UI — Monitoring Health operational sections

**2026-11-19 · SOURCE CANDIDATE — UNVERIFIED.** Baseline branch HEAD `882bd36c393376b1d8fc61b4592320aa7e60822d`, authoritative commit TREE `6bdb23946004e8248e5aca6ced2de9829e2662ef`. The existing Monitoring Health page already contained capture diagnostics, provider outcomes, and aggregate export. This increment gives the existing enrichment measurements dedicated sections for queue/worker operations, publication and evidence coverage, session storage/checkpoints, and GeoIP/process diagnostics. The existing provider grid, aggregate JSON export, summary text, and snapshot lifecycle remain in place.

**Data boundaries:** all displayed values are reused from the current `EnrichmentHealthPresentation` accounting helpers. Queue depth is an instantaneous gauge; fallback, worker, coverage, registry rejection, and checkpoint counters retain their existing service-lifetime or session-lifetime scopes. Process TCP socket ownership and UDP local binding remain distinct denominators; ETW publication is explicitly distinguished from packet evidence. TLS capacity rejection is session-scoped. No new source events, denominators, detector evidence, or confidence claims are introduced.

**Ownership:** `Carthago/Services/EnrichmentHealthPresentation.cs`, `Carthago/Views/MonitoringHealthPage.xaml`, `Carthago/Views/MonitoringHealthPage.xaml.cs`, `Carthago.Tests/EnrichmentHealthPresentationTests.cs`, and the validation ledgers. No detection rules, capture producers, enrichment admission, shared telemetry contracts, or qualification workflows changed.

**Unexecuted acceptance:** focused xUnit, WPF build/render, scroll/keyboard/screen-reader review, narrow-width layout, Windows runtime, and sustained-performance checks remain pending. **Next UI/enrichment gate:** build and run the focused presentation tests, then verify the new sections against a live Windows capture session without treating observational coverage as protocol recall or qualified detection evidence.

## 2026-11-19 — GA ENRICHMENT UI: responsive diagnostics card matrix

**Source baseline:** `feature/carthago-reliability-hardening` HEAD `cb1209ec7ae0e54692b7f146d4ff7ed92ad4f065`; actual parent TREE `a4396bf650a727398012c8e56f531c195c0ad854`. **Before:** queue/worker, publication/evidence, session storage/checkpoints, and GeoIP/process diagnostics were four vertically stacked cards. **After:** the same four read-only cards sit in a two-column operational matrix, with a single-column fallback below 680 DIPs of available page width; a compact operational-detail heading and scope caption make the grouping explicit.

**Approved-reference mapping:** exact Library image `libfile_b0a34361560c8191b641e432b3e6b15c` (visually inspected): reuse its navy/graphite surfaces, thin blue card borders, restrained cyan section labels, and compact grouping. The reference's demo-data badges, example telemetry, and overview composition are not copied.

**Responsive behavior:** two equal columns at 680 DIPs and above; one column below 680 DIPs. The breakpoint uses the page-local available width, not the physical display resolution. Existing vertical scrolling and wrapped diagnostic text remain in place. The 1024–1099 compact range should retain two columns when the content area is at least 680 DIPs; narrower content collapses to one.

**Ownership:** `Carthago/Views/MonitoringHealthPage.xaml`, its code-behind, and this design ledger only. `EnrichmentHealthPresentation.cs`, `Views/Theme.xaml`, and `App.xaml` were inspected as read-only dependencies. No ViewModel, service, engine, model, capture, telemetry, security, rule, shared API, or project file changed. Existing text element names, presentation-helper values, counter scopes, provider rows, and aggregate-only export remain unchanged.

**Static risks:** the WPF `SizeChanged` handler may perform one additional layout pass when the initial column count is corrected; long diagnostic strings can make paired row heights tall; the provider DataGrid retains its existing fixed 160-DIP height and column behavior. No runtime layout or accessibility claim is made.

**Unexecuted acceptance:** no build, test, CI, capture, or render was run. Still required on Windows: inspect at display widths >=1440, 1100–1439, 1024–1099, and below 1024; verify page-local breakpoint behavior, text wrapping, vertical scroll reachability, DataGrid horizontal access, keyboard navigation, screen-reader names, and live snapshot refresh without changing metric provenance.

**Next GA:** Windows visual and accessibility acceptance for the responsive diagnostics matrix, followed by review of the provider DataGrid's narrow-width access.
