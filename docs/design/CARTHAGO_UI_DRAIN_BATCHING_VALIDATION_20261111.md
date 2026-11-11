# CARTHAGO UI drain batching: operational validation

## Scope

- The capture-to-dispatcher channel retains its 5,000-item bound, 100-record drain batches, and existing drop semantics.
- MainWindow receives successful traffic records once per batch for dashboard counters and the 200-row traffic grid. The grid emits one collection reset for each batch instead of one insert/remove notification per record.
- Other `TrafficRecordReceived` subscribers, the detection/rule pipeline, alert delivery, and capture configuration are untouched.
- Monitoring Health now reports cumulative UI drain batch count, last/max dispatcher batch duration, and lifetime UI queue drops. These are diagnostics, not evidence of live alert delivery.

## Known baseline (2026-11-11 VPN recording)

The operator-supplied CSA recorded 12,265 captured packets, 12,082 parsed records, and **6,008 UI queue drops**. This is a single baseline observation, not a controlled before/after measurement. The recording includes 200 retained UI rows, of which 180 were tagged `wireguardtun`.

## Matched Windows validation (pending)

1. Pull the updated feature branch and run `powershell -NoProfile -ExecutionPolicy Bypass -File .\verify-local.ps1` from the repository root.
2. Open Monitoring Health and record queue drops and UI batches at the start of the workload; record the same values at the end. Use **delta drops**, not lifetime totals.
3. Replay/produce the **same VPN traffic workload**, capture adapter, traffic duration, packet count or rate, process load, and UI navigation as the baseline. Export a new CSA and XLSX.
4. Compare captured, parsed, UI-delivered, queue-dropped, elapsed seconds, and UI batch last/max duration. Do not infer an improvement from two runs with different traffic rates or conditions.
5. Check that detections and alerts, including their timestamps/IDs, match baseline expectations. Verify the 200-row newest-first grid remains usable, and no source or capture settings changed.

Release gate stays **unverified** until the Windows build/tests and matched-workload comparison pass. A reduction in UI queue drops without preserved alerts and detection is not release readiness.
