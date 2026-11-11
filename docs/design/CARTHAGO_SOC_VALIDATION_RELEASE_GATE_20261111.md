# CARTHAGO SOC workspace — Validation and release gate (V1)

Status: **LOCAL AUTOMATED GATES PASSED; OPERATIONAL RELEASE STILL PENDING**.
Windows results were reported by the owner on 2026-11-11. The full local
verifier passed at source commit `d65321f29c144b7e2068d1124f20d91e42f7a5f7`;
manual WPF and live capture acceptance remain outstanding.

Scope: SOC-01 through SOC-20 in the existing WPF application, on
`feature/carthago-reliability-hardening`. This does not certify the independent
detection-rule expansion, GA rule accuracy, or the separate UI-design automation.

## Gate and evidence

| Gate | Required evidence | V1 result | Release disposition |
| --- | --- | --- | --- |
| G0 Source identity | Exact working branch, clean worktree, HEAD aligned with local origin tracking ref, source SHA recorded and unchanged across test run | Owner pulled `d65321f` by fast-forward before the full verifier; a separate pinned run of the SOC verification script was reported earlier at a prior SHA | Reconfirm pinned SHA for final acceptance |
| G1 Static WPF structure | XML parse for every application XAML; event bindings resolve to application partial class code | 23/23 XAML documents parsed; 300/300 inspected WPF event bindings resolved | Source checks passed, not WPF compilation |
| G2 Release build | Windows `net8.0-windows` WPF project and test assembly restore/build without errors | Windows Release restore/build passed in focused SOC and full local runs; nullable compiler warnings remain | Passed with warnings at `d65321f` |
| G3 Focused SOC tests | Source-authored NetworkInvestigation, IncidentTimeline, and IncidentDetectionLinkVm xUnit groups pass; preserve and inspect nonempty TRX | Earlier owner-reported focused SOC run: 69/69 passed on prior source SHA | Passed at earlier SHA; repeat on release candidate |
| G4 Full regression | Existing `verify-local.ps1` / complete xUnit suite, investigation/export/accuracy regressions reviewed | Owner-reported 2026-11-11 13:57–14:00 Stockholm: restore, builds, full tests and benchmark all passed at `d65321f` | Passed on this pinned candidate |
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

## 2026-11-11 regression remediation and evidence

The first full local verification run on `245bcce` reported 15 failures in
11,676 executed tests (11,661 passed); the build and replay benchmark passed.
The failures were corrected directly on the existing branch in three guarded,
non-force updates, with Windows reruns after each correction:

| Commit | Change | Evidence boundary |
| --- | --- | --- |
| `39cce5866b50910caafa5b28c54c27f264ef9d24` | Admit typed HTTP PUT for the R740 upload-shaped predicate without changing other HTTP rules; recognize the `nc` process for R714 without lowering the general process-name filter | Focused R706–R715 and R736–R745 tests: 84/87 passed; only R738/R742/R743 recovery remained |
| `d0c3b6945a31652a1a952de82d6414d6877c4275` | Redact output host labels for R788/R799/R805 and remove the R714 nullable warning | Focused R786–R795 and R796–R805 tests: 84/84 passed |
| `d65321f29c144b7e2068d1124f20d91e42f7a5f7` | Restart the completed cadence window at its first subsequent observation; preserve packet IDs, order, intervals, sizes, and thresholds | Full `verify-local.ps1`: all stages PASS, including tests and benchmark |

The cadence reset applies to the previously failing R738, R742, R743, R753,
R761, R785, R849 and R889 sequences. No detector thresholds were relaxed.
Windows console evidence is owner-reported; the complete logs/TRX were not
ingested into this document and no claim of independent reproducibility is made.

The full verifier reported 895 registered rules, zero catalog contract issues,
161 labeled replay samples and zero benign *critical* alerts. Its synthetic
recognition funnel reported 50/50 raw recognition per policy profile, while
only 1–2 of those 50 were eligible for simulated alerts under the selected
profiles. Those are **policy eligibility metrics**, not production detection
recall. The catalog also reported 838 rules without explicit controls; the
successful regression run does not establish equivalent per-rule accuracy.

## Outcome

The local automated verification gate has passed on `d65321f`. The full SOC
release remains **NO-GO** pending G5 manual WPF acceptance, G6 operational
capture/export checks, and final source-identity confirmation. Preserve the
Windows logs/TRX with the pinned SHA before release promotion.
