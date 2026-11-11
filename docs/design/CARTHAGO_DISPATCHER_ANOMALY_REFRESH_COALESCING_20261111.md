# Dashboard anomaly refresh coalescing — source candidate

## Observation

During the operator's VPN run, the capture/UI queue grew from 320 to approximately 900 records, with dispatcher scheduling delays reaching 27,055 ms and the oldest pending batch exceeding 73 seconds. Subscriber processing reported zero milliseconds at the diagnostic's resolution. This localizes the delay to dispatcher scheduling but does not identify every competing UI operation.

## Candidate addressed

`MainWindow.DashboardAnomalyObserved` posted a separate `DispatcherPriority.Background` callback for every anomaly. Each callback refreshed the anomaly list and rebuilt the dashboard layout. During a burst, this creates redundant dispatcher work.

The new `UiRefreshCoalescer` bounds this source to one scheduled callback and, when an update arrives during a refresh, one follow-up callback. The refreshed view still reads the current analytics snapshot. No anomaly signals, capture records, detections, or alerts are suppressed or changed at the source.

## Validation required

1. Run `verify-local.ps1` on the Windows host; source-only inspection is not compilation.
2. Capture the same VPN workload and compare `queueDepth`, `dispatcherWaitMs`, `oldestBatchWaitMs`, `queueDrops`, and `uiDelivered` using `watch-ui-pipeline.ps1`.
3. Confirm anomaly and incident counts and details remain accessible after bursts; leave monitoring source and capture profile unchanged.
4. If the scheduling delay persists, profile chart, map, and layout work before modifying further UI paths. Do not promote to release on a single zero-drop observation.
