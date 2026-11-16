# SOC verifier classification/completion defect — CLOSED (2026-11-16)

**Disposition:** **CLOSED — corrected and owner-runtime verified** for the SOC workspace verifier defect where all filtered tests passed but the post-test TRX classifier rejected a method-scoped SOC test and refused the source-pinned completion report. This disposition applies **only** to the verifier defect, not broader Windows operational acceptance, field detection accuracy or manual WPF checks.

**Repository:** `afiay/Carthago-Network-Security-Monitor`  
**Branch:** `feature/carthago-reliability-hardening`  
**Executed source SHA (from uploaded completion report):** `971892ef4d18e18cbb2d8317c23c0ada64c2dc19`  
**Source validation:** The named commit exists; its `verify-soc-workspace.ps1` performs the final Git checkout check before publishing the report; `SocWorkspaceCompletion.psm1` classifies each original TRX test by an unambiguous class or method SOC marker, verifies exact group partition and refuses unrelated/multiple matches.

## Original failure and corrected behavior

Original owner run: Release build succeeded with nine xUnit1026 theory warnings; 70/70 SOC tests passed; legacy **class-only** evidence validator then threw `SOC TRX has an unrelated or overlapping test group`. **No successful completion report** was produced for that aborted run.

Correction: Include `TestMethod.name` when the declaring class does not itself contain any SOC filter marker. The original VSTest filter `FullyQualifiedName~NetworkInvestigation|FullyQualifiedName~IncidentTimeline|FullyQualifiedName~IncidentDetectionLinkVm` can match the method name. The corrected validator still requires a unique group, one-to-one result-to-definition identity, exclusively passing outcomes and matching totals. It records `methodScopedCases` in the saved report.

## Owner-run acceptance proof

The owner ran the corrected code on Windows and supplied the full successful console transcript plus the new `completion.json`:

| Acceptance condition | Evidence and outcome |
| --- | --- |
| Offline contract suite | **27/27 assertions PASS** |
| Historical failed-run TRX reparse | 70/70 PASS; 29 NetworkInvestigation, 36 IncidentTimeline, 5 IncidentDetectionLinkVm; **5 method-scoped** cases |
| New verification restore | PASS |
| New Release build | **PASS**, 0 errors; **9 xUnit1026 warnings** (separate quality cleanup) |
| New SOC TRX execution | **70/70 PASS**, 0 failed/skipped |
| Verifier completion | **`SOURCE BUILD AND SOC TEST STAGES PASSED`** printed *after* report publication |
| Unique new run | `TestResults/soc-workspace-20261116-201947-13980-fc218b2a` |
| Completion file status | `SyntheticSocPassed`, schema `soc-workspace-final-provenance-v1` |
| Reported executed SHA | `971892ef4d18e18cbb2d8317c23c0ada64c2dc19` before/after and local/remote (all five SHA fields identical) |
| Reported original TRX | run ID `36333bc5-2f34-472e-9e8c-0afbe7463041`; SHA-256 `121f68fc32e94d42f4ccc8a424f2a34582cba797cbb904e123b8c8dd4cefe1af` |
| New TRX group partition | 29 NetworkInvestigation, 36 IncidentTimeline, 5 IncidentDetectionLinkVm; 5 method-scoped |
| Saved stage statuses | sdk-version, restore, build-release, soc-tests: **4/4 zero exit codes**, log SHA-256 entries present |
| Runtime interval | 2026-11-16 20:19:47.7302204Z — 20:21:17.0540568Z; TRX inside interval |
| Uploaded `completion.json` original SHA-256 | `577edf65e6be209e1908600ea94a9af22b189ea56f8938afaaf84e371d6ac252` (2,935 bytes) |
| Completion schema independent review | **PASS**: verified JSON structure, 5 matching SHAs, execution times, report counters and all three SOC groups |
| Deployment, manual WPF, field accuracy or formal rule admission | **Not established**; `manualWpfValidated=false`, `fieldAccuracyQualified=false`, `evidenceAdmitted=false` |

The completion file is an owner-supplied runner-generated report, **not an external cryptographic attestation**. Its recorded original TRX and stage-log SHA-256 digests have not yet been independently recomputed from the original corresponding files in this review.

## Follow-up separated from CLOSED bug

1. **Independent original-artifact integrity: COMPLETED — owner Windows execution.** The owner ran `scripts/verify-soc-completion-artifacts.ps1 -RunDirectory '.\TestResults\soc-workspace-20261116-201947-13980-fc218b2a'` and supplied the exact resulting console JSON: `status=all-original-artifact-hashes-matched`. It verified the original source SHA file, TRX GUID/hash/counters/groups and all four original stage-log SHA-256 values against `completion.json`, without rebuilding, rerunning detector tests or capturing traffic. Retain the original bundle and terminal output as local proof. This is owner-run byte verification reported to the auditor, not a claim the original sibling files were separately uploaded here.
2. **Rule test warnings:** Nine xUnit1026 unused `name` parameter warnings in R988–R990 and R995–R1000. Separate rule-test hygiene work, preserving theory-case coverage and semantics.
3. **SOC operational acceptance:** Manual WPF UI/navigation/export/accessibility and physical/capture path evidence remain pending; not part of this defect.

## Evidence cohort boundary

The successful **new** 2026-11-16 SOC TRX is **not** part of the frozen 359-artifact / 42-TRX historical recovery cohort. That separate inventory stays **6/42 runner-report-linked, 36 without runner links**. The original 2026-11-11 SOC source-file-correlated run remains historically unlinked; do not retroactively attach this new completion report. No rule or benchmark was promoted by this closure.

**Disposition basis:** Reproduction, narrow fix, 27 offline contract assertions, actual corrected Windows end-to-end test pass, final report publication, and independent inspection of the uploaded completion JSON. No open GitHub issue matching this defect was present at closure inspection; this Markdown file is the authoritative **engineering defect closure record**, not a claim that an issue was programmatically closed.


## Final owner-run artifact verification — PASS (2026-11-16)

The owner executed the dedicated **read-only** `scripts/verify-soc-completion-artifacts.ps1` against the **new** run `TestResults/soc-workspace-20261116-201947-13980-fc218b2a/`, after rerunning the offline contract (27 assertions PASS). The terminal result reports `status=all-original-artifact-hashes-matched`:

| Field from Windows checker | Verified reported result |
| --- | --- |
| `sourceSha` | `971892ef4d18e18cbb2d8317c23c0ada64c2dc19` |
| `trxRunId` | `36333bc5-2f34-472e-9e8c-0afbe7463041` |
| `trxSha256` | `121f68fc32e94d42f4ccc8a424f2a34582cba797cbb904e123b8c8dd4cefe1af` |
| `completionSha256` | `577edf65e6be209e1908600ea94a9af22b189ea56f8938afaaf84e371d6ac252` |
| Original TRX | 70 executed, 70 passed, 5 method-scoped |
| `sdk-version`, `restore`, `build-release`, `soc-tests` logs | `sha256-matched` for each |
| `fieldQualified`, `evidenceAdmitted` | `false`, `false` |
| `verifierTestsExecuted` | 0 |

This closes the *separately tracked independent original-file hash-check follow-up* as **owner-executed PASS**. The local original files were hashed by the Windows utility; their bytes were not separately uploaded to this conversation. The frozen historical 42-TRX reconciliation remains **6 source-run-linked, 36 unlinked**, because the new source-pinned SOC run is not in that historical cohort. Manual WPF operational acceptance and detection accuracy remain **pending**. The nine xUnit1026 warnings remain a separate issue. No rules, benchmark thresholds, or original evidence files were changed by this documentation.
