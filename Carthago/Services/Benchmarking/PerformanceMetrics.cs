// SPDX-License-Identifier: MIT
using System;
using System.Diagnostics;

namespace Carthago.Services.Benchmarking
{
    /// <summary>
    /// Process-wide counters combined with capture-session counters at one instant.
    /// Compare snapshots from the same process and capture session only.
    /// </summary>
    public sealed record PerformanceCounterSnapshot(
        DateTimeOffset TimestampUtc,
        long Captured,
        long Displayed,
        long Dropped,
        long ManagedAllocatedBytes,
        TimeSpan ProcessCpuTime,
        long WorkingSetBytes)
    {
        public static PerformanceCounterSnapshot Capture(long captured, long displayed, long dropped)
        {
            using var process = Process.GetCurrentProcess();
            return new PerformanceCounterSnapshot(DateTimeOffset.UtcNow, captured, displayed, dropped,
                GC.GetTotalAllocatedBytes(precise: false), process.TotalProcessorTime, process.WorkingSet64);
        }
    }

    public sealed record PerformanceMetricSummary
    {
        public TimeSpan Duration { get; init; }
        public long Captured { get; init; }
        public long Displayed { get; init; }
        public long Dropped { get; init; }
        public long ManagedAllocationBytes { get; init; }
        public long WorkingSetDeltaBytes { get; init; }
        public double? CapturedPerSecond { get; init; }
        public double? DisplayedPerSecond { get; init; }
        public double? DropRate { get; init; }
        public double? CpuCoreEquivalents { get; init; }

        public static PerformanceMetricSummary Between(PerformanceCounterSnapshot before, PerformanceCounterSnapshot after)
        {
            ArgumentNullException.ThrowIfNull(before);
            ArgumentNullException.ThrowIfNull(after);

            var duration = after.TimestampUtc - before.TimestampUtc;
            var captured = after.Captured - before.Captured;
            var displayed = after.Displayed - before.Displayed;
            var dropped = after.Dropped - before.Dropped;
            var allocations = after.ManagedAllocatedBytes - before.ManagedAllocatedBytes;
            var cpu = after.ProcessCpuTime - before.ProcessCpuTime;
            if (duration < TimeSpan.Zero || captured < 0 || displayed < 0 || dropped < 0
                || allocations < 0 || cpu < TimeSpan.Zero || dropped > captured)
                throw new ArgumentException("Snapshots must be ordered and come from the same unreset process and capture session.");

            var seconds = duration.TotalSeconds;
            return new PerformanceMetricSummary
            {
                Duration = duration,
                Captured = captured,
                Displayed = displayed,
                Dropped = dropped,
                ManagedAllocationBytes = allocations,
                WorkingSetDeltaBytes = after.WorkingSetBytes - before.WorkingSetBytes,
                CapturedPerSecond = seconds > 0 ? captured / seconds : null,
                DisplayedPerSecond = seconds > 0 ? displayed / seconds : null,
                DropRate = captured > 0 ? (double)dropped / captured : null,
                CpuCoreEquivalents = seconds > 0 ? cpu.TotalSeconds / seconds : null
            };
        }
    }
}
