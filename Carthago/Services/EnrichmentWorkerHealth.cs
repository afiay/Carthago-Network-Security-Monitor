// SPDX-License-Identifier: MIT
using System;

namespace Carthago.Services;

public sealed record EnrichmentWorkerSnapshot(long Started, long Returned, long Cancelled, long Faulted,
    long Skipped, long WaitTotalMs, long WaitMaxMs, long ElapsedTotalMs, long ElapsedMaxMs);

// One coherent snapshot per service lifetime; no packet retention.
internal sealed class EnrichmentWorkerHealth
{
    private readonly object _gate = new();
    private long _started, _returned, _cancelled, _faulted, _skipped, _wait, _waitMax, _elapsed, _elapsedMax;
    internal void SkipCancelled() { lock (_gate) _skipped++; }
    internal void Start(long waitMs)
    {
        lock (_gate)
        {
            _started++;
            _wait += Math.Max(0, waitMs);
            _waitMax = Math.Max(_waitMax, waitMs);
        }
    }
    internal void End(bool returned, bool cancelled, long elapsedMs)
    {
        lock (_gate)
        {
            if (cancelled) _cancelled++;
            else if (returned) _returned++;
            else _faulted++;
            _elapsed += Math.Max(0, elapsedMs);
            _elapsedMax = Math.Max(_elapsedMax, elapsedMs);
        }
    }
    internal EnrichmentWorkerSnapshot Snapshot()
    {
        lock (_gate) return new(_started, _returned, _cancelled, _faulted, _skipped, _wait, _waitMax, _elapsed, _elapsedMax);
    }
}
