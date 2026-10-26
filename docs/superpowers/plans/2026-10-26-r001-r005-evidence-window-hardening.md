# R001–R005 Evidence-Window Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Close concrete R001–R005 accuracy-gate gaps without promoting rules, changing confidence floors, or advancing to R006.

**Architecture:** Preserve the existing five legacy rule adapters and their public contracts. Strengthen R002's stateful evidence accounting so the packet, byte, and SYN/ACK tests all use one bounded observation window; keep the five-rule verification gate extensible beyond its initial 25 test cases.

**Tech Stack:** C#/.NET 8, xUnit, PowerShell.

**Spec:** `docs/RULE_BATCH_001-005.md` and the five-rule continuation handoff.

## Global Constraints

- Stay on `feature/carthago-reliability-hardening`; check remote HEAD before publication and never force-push.
- Preserve R102/R118/R163 confidence floors and all Shadow, Disabled, and approval safeguards.
- Do not claim Windows, replay, or holdout verification without corresponding passing evidence.
- R001–R005 must pass before starting R006–R010.

## Review Focus

- Out-of-order future-dated R002 records must not preload current evidence.
- Continuous low-rate R002 traffic must not retain old byte or SYN totals beyond the packet window.
- High-rate benign SYN/ACK traffic must not accumulate unbounded per-flow memory.
- Independent R002 sources and target services must remain isolated under concurrency.
- The acceptance gate must allow more than five meaningful advanced scenarios per rule.

---

### Task 1: R002 aligned bounded evidence windows

**Files:**
- Modify: `Carthago.Tests/R002AdvancedAccuracyBatchTests.cs`
- Modify: `Carthago/Engine/RuleEngine.Detectors.cs`
- Modify: `Carthago/Engine/RuleEngine.Replay.cs`
- Modify: `Carthago/Engine/RuleEngine.Core.cs` if state cleanup needs adjustment.

**Interfaces:** Preserve `R002_FloodDosRule.EvaluateAsync` and `DetectionEvent` output. Use internal per-flow evidence buckets to aggregate packets, bytes, SYN and ACK within one consistent window; omit future and expired observations.

- [ ] Add two regression tests: future timestamp contamination, stale byte accumulation under continuous trickle.
- [ ] Run the focused R002 tests and witness their expected failures on baseline logic.
- [ ] Make the smallest bounded, concurrency-safe state change that passes those tests.
- [ ] Add benign high-volume, late-packet, and state-reset tests if gaps remain.
- [ ] Run focused R002 tests and all legacy R001–R005 tests; document unavailable platform gates.

### Task 2: Acceptance script supports more than the minimum 25 scenarios

**Files:**
- Modify: `scripts/verify-first-rule-batch.ps1`
- Modify: `docs/RULE_BATCH_001-005.md`

**Interfaces:** Preserve existing PowerShell entry point, TRX output, and failure handling.

- [ ] Demonstrate current exact-25 check blocks any sixth advanced case.
- [ ] Require at least 25 passing advanced cases, with non-passing tests still failing the gate.
- [ ] Run PowerShell validation if available; otherwise explicitly mark Windows execution pending.

### Task 3: Final batch audit and handoff

**Files:**
- Modify: `docs/RULE_BATCH_001-005.md`

- [ ] Review all five rule implementations and the existing 25+ advanced tests independently.
- [ ] Run all available local verification and inspect exit codes.
- [ ] Verify git diff and remote branch SHA before commit/push; do not overwrite concurrent changes.
- [ ] Provide the exact Windows command and leave batch unapproved until passing logs return.
