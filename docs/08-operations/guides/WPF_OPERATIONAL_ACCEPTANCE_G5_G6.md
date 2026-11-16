# CARTHAGO WPF — owner-operated G5/G6 acceptance (source-pinned V1)

**Disposition: NOT EXECUTED / NO-GO until original Windows GUI and capture evidence are supplied.** This is a real WPF user acceptance process, not an automated synthetic SOC test. The separate SOC classifier/completion bug is **closed**, with 70/70 SOC unit tests passed and matching original artifacts on the 2026-11-16 Windows run. **Do not rerun that successful verification just to perform this workflow.**

Source branch: `feature/carthago-reliability-hardening`. Any newer commit creates a **new** candidate; do not copy acceptance from an earlier source SHA.

## Source-only contract preflight (does not open WPF)

Run the new offline Python contract before relying on the acceptance scripts:

```powershell
python .\scripts\test-wpf-historical-acceptance-contracts.py
```

It checks safe default NO-GO, accepted hashed observations, refusal of unsafe evidence paths, source SHA changes, 42-TRX exact-link count and historical log proximity behavior using synthetic fixtures. It does **not** run the Windows app, perform detector tests or create capture traffic. **The authoring session has not executed this new contract**; record the actual Windows output before trusting the toolchain.

## How to operate the acceptance workflow

From an interactive Windows session in the CARTHAGO repository, after saving local edits and doing a safe fast-forward:

```powershell
git fetch origin
git pull --ff-only origin feature/carthago-reliability-hardening
git status --short

python .\scripts\wpf-operational-acceptance.py init --output-root .\TestResults
```

The tool verifies the exact clean branch and tracking SHA, and creates **one new folder** named `TestResults/wpf-g5-g6-<UTC>-<ID>/` containing `run-info.json`, an editable `responses.json` with **16 not_run items** and an `evidence/` directory. The tool does **not** launch WPF, start capture, rerun the SOC verifier, alter detection configuration or claim any PASS.

Launch the actual Windows WPF application in your usual approved non-production setup. For opt-in aggregate dispatcher/queue diagnostics, start it in a dedicated terminal with unique paths for this run:

```powershell
$env:CARTHAGO_UI_DIAG_PATH = Join-Path $env:TEMP 'carthago-g5-g6-ui-pipeline.csv'
$env:CARTHAGO_UI_PROFILE_PATH = Join-Path $env:TEMP 'carthago-g5-g6-ui-operations.csv'
dotnet run --project .\Carthago\Carthago.csproj -c Release
```

Diagnostics are **source instrumentation**, not automatic proof of correct UI rendering. Use `scripts/watch-ui-pipeline.ps1` and `scripts/summarize-ui-operations.ps1` as diagnostic aids and retain their outputs. If external dependencies or traffic are unavailable, mark that case **blocked**, not passed. Use traffic on a network/lab you administer or are authorized to test. Do not send raw personal traffic or credentials in screenshots or logs.

While the actual application is running, work through the matrix below. For **each case** edit the matching row in `responses.json`:

- `status`: one of `not_run`, `pass`, `fail`, `blocked`. Never turn missing evidence into a pass.
- `notes`: a factual observation with at least 15 characters for a pass; mention what happened and any deviation.
- `observedAtUtc`: real observation timestamp, e.g. `2026-11-16T21:25:00Z`.
- `evidence`: at least one **relative path** for a pass, such as `evidence/G5-02-navigation-redacted.png` or `evidence/G6-04-process.csv`; each file must actually exist in the run folder, be nonempty and at most 20 MiB. Use images, diagnostic CSV or redacted local observations. Do not fabricate evidence files.

After all observations, end the application normally. On the **same unchanged clean checkout**, evaluate the saved record:

```powershell
python .\scripts\wpf-operational-acceptance.py assess `
    --run-dir '.\TestResults\wpf-g5-g6-<YOUR-RUN-FOLDER>'
```

This produces a **new immutable** `assessment-<UTC>-<ID>.json` on each invocation; a NO-GO assessment never overwrites earlier evidence, so the operator can add observations and assess again. It hashes each evidence file and returns `NO_GO` until **all 16 required manual cases** have complete, source-consistent, real submitted observations. A complete `CANDIDATE_ONLY` outcome is still operator-submitted evidence, **not independent proof** that the WPF rendered correctly, and **not** detection-rule accuracy or full release approval. Exit code 2 indicates NO-GO; 3 indicates malformed/unsafe input.

## G5 manual visual/navigation checks

| ID | Exercise on the actual application | Required observed result |
| --- | --- | --- |
| G5-01 | Start and inspect full window at native scale and resized size | No crash, misleading placeholder metrics, clipped headings or missing controls |
| G5-02 | Overview → Monitoring Health → Live Traffic → Detection Coverage, then return | Same MainWindow, retained navigation context, no blank or detached destination |
| G5-03 | With capture disabled, paused, idle and later active | Source/queue/parser labels distinguish unavailable from zero, paused from failure, session counters from network-wide data |
| G5-04 | Network Investigation: exact IP, `port:443`, DNS QNAME and `event:<known-id>` | Search stays within retained data; no implied incident or host identity |
| G5-05 | Selected incident timeline → recorded event link → evidence inspector | Correct exact ID, only stored fields, missing values explicitly unknown, no fake provenance |
| G5-06 | Tab/Shift+Tab, Alt+Up/Down, row first/last, Back/Forward, focus and assistive names | Keyboard navigation works; no trap, skipped control or misleading selection |
| G5-07 | Analytics time filters and map selection; selected private/local IP | Historical charts redraw; private IP never gets a fabricated public marker |
| G5-08 | Incidents/Analytics/session export with consent and local dialog | Export scope, Excel sheets, unknown process/country and redaction match actually retained records |
| G5-09 | Active sensors UI for disabled/unconfigured/unavailable and authorized running sensor | Status is not hard-coded green/zero; missing observations are not silently reported as healthy |
| G5-10 | Settings, resize, minimize/restore, cross-page return during activity | Layout stable, responsive and accessible; no observed multi-second dispatcher stall |

## G6 live operational checks (same pinned source)

| ID | Exercise | Required observed result |
| --- | --- | --- |
| G6-01 | Identify ETW/Npcap backend, selected interface and actual privilege/capabilities | A source is genuinely available; missing Npcap or permission is **blocked**, not a fake PASS |
| G6-02 | Bounded, authorized traffic → source → parser/detection → UI; observe counters | Retained traffic is observed, UI-delivered and drop counters can be reconciled; no invented visibility |
| G6-03 | Compare Monitoring Health with opt-in `CARTHAGO_UI_DIAG_PATH` and a saved CSA | Queue depth, oldest wait, dispatcher lag, capture drops, parsing errors have consistent scope |
| G6-04 | Observe actual WPF process under same 15-minute lab workload | Record CPU, private memory, responsiveness, sampled drop/error deltas, resource trend and load notes; absence of measurement is NO-GO |
| G6-05 | Stop capture, exit WPF gracefully, relaunch, revisit recorded incidents | No stale session conflation, unintended loss or duplicate incident/baseline identity |
| G6-06 | Export original session/CSA and report from selected evidence during workload | Actual scope and identifiers match, redaction preserved; process/country never invented |

**G6 does not authorize destructive or adversarial testing outside a controlled lab.** Do not claim broad network visibility from a single capture interface, nor production detection recall from generated traffic.

## Integrity, scope and stop conditions

The assessment script binds the **source at initialization** to a full Git SHA and matching local origin tracking ref, checks that Git remains clean/unchanged at assessment, rejects unknown check IDs/statuses, accepts no evidence outside the run's `evidence/` subtree, rejects symlinks, and records SHA-256 hashes of local evidence. It **never** overwrites an earlier `assessment.json`.

A crash, incorrect incident link, sensitive export leak, failed accessibility path, capture visibility problem or unsafe reporting is **NO-GO**. A missing device/capture driver is also **NO-GO for full G5+G6 acceptance**, even if other cases pass. Capture diagnostic results cannot substitute for manual visual screenshots or vice versa.

**Status at authoring:** workflow and acceptance contract authored only; **0/16 manual cases executed by this author**. Windows WPF GUI operations and G5/G6 human observations require the owner to perform them on the actual PC. There is no reported new source-pinned G5/G6 result yet.

References within CARTHAGO: [SOC workspace release gate](../../design/CARTHAGO_SOC_VALIDATION_RELEASE_GATE_20261111.md), [SOC integration](../../design/CARTHAGO_SOC_WORKSPACE_INTEGRATION.md), [performance acceptance](../../06-development/engineering/performance-acceptance.md), [closed SOC verifier defect](../../05-detection-quality/SOC_VERIFIER_BUG_CLOSURE_20261116.md).
