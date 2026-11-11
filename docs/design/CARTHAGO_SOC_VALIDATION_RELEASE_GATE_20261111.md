# CARTHAGO SOC workspace — Validation and release gate (V1)

Status: **NOT READY FOR VERIFIED RELEASE** — source checks only; no Windows runtime results yet.

Scope: SOC-01 through SOC-20 in the existing WPF application, on
`feature/carthago-reliability-hardening`. This does not certify the independent
detection-rule expansion, GA rule accuracy, or the separate UI-design automation.

## Gate and evidence

| Gate | Required evidence | V1 result | Release disposition |
| --- | --- | --- | --- |
| G0 Source identity | Exact working branch, clean worktree, HEAD aligned with local origin tracking ref, source SHA recorded and unchanged across test run | Enforced by Windows script but not yet executed; remote can still advance independently | Pending candidate execution |
| G1 Static WPF structure | XML parse for every application XAML; event bindings resolve to application partial class code | 23/23 XAML documents parsed; 300/300 inspected WPF event bindings resolved | Source checks passed, not WPF compilation |
| G2 Release build | Windows `net8.0-windows` WPF project and test assembly restore/build without errors | Not run: current Linux execution environment has no `dotnet` command | Blocked pending Windows execution |
| G3 Focused SOC tests | Source-authored NetworkInvestigation, IncidentTimeline, and IncidentDetectionLinkVm xUnit groups pass; preserve and inspect nonempty TRX | Not run | Blocked pending Windows execution |
| G4 Full regression | Existing `verify-local.ps1` / complete xUnit suite, investigation/export/accuracy regressions reviewed | Not run in this phase | Required before release claim |
| G5 Manual WPF acceptance | Rendered layout, focus/keyboard behavior, same-window navigation, search and retained evidence inspectors | Not run | Required before release claim |
| G6 Live operational checks | Capture source status, Npcap/ETW drop counters, representative packet and detection flow, export content/redaction | Not run | Required before release claim |

The portable G1 structure check can be repeated with `python scripts/verify-soc-static.py`.
It is an XML/source-handler check, not a WPF compilation or a substitute for G2.

## Reproducible Windows execution

From the repository root after a clean fast-forward pull:

```powershell
git pull --ff-only origin feature/carthago-reliability-hardening
powershell -NoProfile -ExecutionPolicy Bypass -File .\scripts\verify-soc-workspace.ps1
```

The script runs restore, Release build and selected SOC tests **locally**. It
does not run GitHub Actions, start packet capture or change application settings.
It rejects a dirty/wrong branch, a mismatched local tracking SHA, and source
changes during execution; it also rejects missing/empty TRX, skipped/failed tests, or missing SOC test
groups. It saves source SHA, SDK version, logs, and xUnit TRX under an ignored,
timestamped `TestResults/soc-workspace-*` folder. A green script is only gates G0/G2/G3;
it is not final operational acceptance.

Run the complete pre-existing verifier separately after G2/G3:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\verify-local.ps1
```

## Manual acceptance matrix (Windows)

1. **Monitoring health:** Confirm disabled/paused/active source labels, last-analysis freshness, Npcap parse errors, ETW drops and UI queue drops are independently labeled; no counter is presented as a guaranteed complete sample.
2. **Investigation:** Open from Overview, Live Traffic and Incidents. Search exact IP, `port:443`, `event:<recorded-event-id>`, recorded DNS QNAME, and general text. Confirm retained-only scope, no inferred incident membership, and same-window navigation.
3. **Evidence:** Verify selection provenance, multi-field highlighting, missing values displayed as `Not recorded`, and no unapproved raw evidence. On a true exact event-ID reference, confirm case links use recorded event IDs only.
4. **Navigation and accessibility:** Check session Back/Forward, saved queries, row Previous/Next at first/last boundaries, Alt+Up/Down in each grid, unmodified arrow keys, tab order, keyboard focus, screen reader names and contrast.
5. **Analytics and map:** Verify time ranges on historical samples, local/reserved address exclusion from public geolocation markers, source-bound marker pivots and plausible chart redraw performance.
6. **Triage and export:** Verify incident selection, timeline category/time filtering, exact evidence pivots, local file dialog, scope confirmation, Excel sheet content, unknown process/country and redaction.

## Stop conditions

- Any WPF build failure, failing focused or full test, crash, missing major navigation route, incorrect case link, unapproved sensitive evidence display, or incorrect export classification keeps the candidate **NO-GO**.
- Missing hardware-dependent capture evidence is **not tested**, not a pass. Record interface, privilege and sensor availability before interpreting drops.
- The rules/accuracy stream and the GA visual redesign may advance the same branch. Recheck SHA before all test runs, compare it after, and do not transplant a pass result from another commit.

## Outcome

SOC features are implemented as *source candidates*, but the verification gate
has **not** been passed. Run the Windows checks, collect TRX/build logs and
manual acceptance results, then review failures and promote one pinned commit.
