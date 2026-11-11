# SPDX-License-Identifier: MIT
# Read-only live observer of opt-in CARTHAGO UI pipeline diagnostics.
[CmdletBinding()]
param(
    [string]$Path = (Join-Path $env:TEMP 'carthago-ui-diag.csv'),
    [int]$Samples = 30,
    [int]$IntervalSeconds = 2
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
if ($Samples -lt 1 -or $Samples -gt 3600) { throw 'Samples must be 1..3600.' }
if ($IntervalSeconds -lt 1 -or $IntervalSeconds -gt 300) { throw 'IntervalSeconds must be 1..300.' }

Write-Host "Watching $Path"
Write-Host 'QueueDepth, age, dispatcher delay, and subscriber duration are sampled diagnostics; the CSV has cumulative counters.'
for ($i = 1; $i -le $Samples; $i++) {
    if (Test-Path -LiteralPath $Path) {
        $rows = @(Import-Csv -LiteralPath $Path)
        if ($rows.Count -gt 0) {
            $last = $rows[$rows.Count - 1]
            Write-Host ('{0} depth={1} captured={2} delivered={3} drops={4} batches={5} oldestMs={6} dispatcherMs={7} maxDispatcherMs={8} subscriberMs={9} skippedCanceled={10}' -f `
                $last.timestampUtc, $last.queueDepth, $last.captured, $last.uiDelivered, $last.queueDrops, `
                $last.batches, $last.oldestBatchWaitMs, $last.dispatcherWaitMs, `
                $last.maxDispatcherWaitMs, $last.subscriberBatchMs, $last.skippedCanceled)
        } else { Write-Host 'CSV exists, waiting for first sample.' }
    } else { Write-Host 'Waiting for diagnostics CSV; start CARTHAGO with CARTHAGO_UI_DIAG_PATH set.' }
    if ($i -lt $Samples) { Start-Sleep -Seconds $IntervalSeconds }
}
