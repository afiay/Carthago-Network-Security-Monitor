# Reliability and Evidence Hardening

## Purpose

Make Carthago's stored findings recoverable, distinguish capture failure from a quiet network,
quantify detection quality, and measure sustained resource usage before integrating a second
security control plane.

## Principles

- Preserve legacy LiteDB and JSON/journal data; never silently discard an unreadable database.
- Keep capture, detection, presentation, and external trust integrations independently operable.
- Make failures observable, without turning recoverable conditions into process crashes.
- Report detection quality against declared labels and denominators, not only a pass count.
- Run deterministic, offline performance probes before comparing live capture results.
- Never grant an optional integration enforcement authority by default.
- Do not rename existing APIs or change the project's licensing or authorship.

## Delivery stages

1. **Data integrity.** Fail closed if a damaged database cannot be preserved; provide explicit
   persistence outcomes to callers; verify reopening and compatibility with existing files.
2. **Monitoring reliability.** Make capture-to-UI delivery diagnostics distinguish zero traffic,
   queue drops, stale UI, and processing failures. Preserve session isolation.
3. **Detection quality.** Add precision, recall, and F1 measurements using deterministic benign
   and malicious replay labels; document what the dataset does not prove.
4. **Performance.** Introduce reproducible throughput, allocation, and queue-pressure tests that
   run without administrator privileges or external network traffic.
5. **GenesisMesh evaluation.** Document an optional read-only trust-adapter boundary; only an
   explicit later authorization may enable external policy changes or revocation.

## Considered approaches

- **Incremental hardening (selected):** retain existing capture and persistence architecture,
  prove each changed behavior independently, and preserve legacy file formats.
- **Full persistence and capture rewrite:** simplifies some contracts but introduces high
  migration and availability risk before existing failure modes are measured.
- **Telemetry-only audit:** lowest risk, but leaves known data-loss and status-reporting gaps.

## Validation

- Unit tests for failure paths, existing-data reopening, and read/write compatibility.
- Windows Release build and full test suite on a Windows host for WPF-dependent coverage.
- Portable deterministic probes for platform-neutral scoring, policies, and persistence.
- No claim of production readiness from passing unit tests alone: a Windows live-capture soak
  and restart exercise are separate acceptance checks.

## Integration boundaries

The proposed GenesisMesh connection is an explicitly enabled outbound, read-only enrichment
adapter. Credentials are external to source control, responses have timeouts and bounded size,
and unavailable trust data cannot block capture or override Carthago's own observations.
