using System;
using Carthago.Services.Benchmarking;
using Xunit;

namespace Carthago.Tests;

public sealed class PerformanceMetricTests
{
    [Fact]
    public void SustainedWindowCalculatesThroughputDropsAndCpuCores()
    {
        var now = new DateTimeOffset(2026, 10, 25, 17, 0, 0, TimeSpan.Zero);
        var before = new PerformanceCounterSnapshot(now, 100, 90, 10, 1_000_000,
            TimeSpan.FromSeconds(50), 100_000_000);
        var after = new PerformanceCounterSnapshot(now.AddSeconds(20), 500, 450, 50, 9_192_000,
            TimeSpan.FromSeconds(55), 101_048_576);

        var result = PerformanceMetricSummary.Between(before, after);

        Assert.Equal(400, result.Captured);
        Assert.Equal(360, result.Displayed);
        Assert.Equal(40, result.Dropped);
        Assert.Equal(20.0, result.CapturedPerSecond);
        Assert.Equal(18.0, result.DisplayedPerSecond);
        Assert.Equal(0.1, result.DropRate!.Value, precision: 8);
        Assert.Equal(0.25, result.CpuCoreEquivalents);
        Assert.Equal(8_192_000, result.ManagedAllocationBytes);
        Assert.Equal(1_048_576, result.WorkingSetDeltaBytes);
    }

    [Fact]
    public void ZeroDurationOrNoTrafficNeverProducesNonFiniteRates()
    {
        var now = DateTimeOffset.UtcNow;
        var same = new PerformanceCounterSnapshot(now, 0, 0, 0, 0, TimeSpan.Zero, 0);

        var result = PerformanceMetricSummary.Between(same, same);

        Assert.Null(result.CapturedPerSecond);
        Assert.Null(result.DisplayedPerSecond);
        Assert.Null(result.DropRate);
        Assert.Null(result.CpuCoreEquivalents);
    }

    [Fact]
    public void ResetOrDifferentCaptureSessionsCannotCreateNegativeThroughput()
    {
        var now = DateTimeOffset.UtcNow;
        var before = new PerformanceCounterSnapshot(now, 100, 90, 10, 1_000,
            TimeSpan.FromSeconds(10), 8_000);
        var reset = new PerformanceCounterSnapshot(now.AddSeconds(5), 4, 3, 0, 1_100,
            TimeSpan.FromSeconds(11), 8_000);

        Assert.Throws<ArgumentException>(() => PerformanceMetricSummary.Between(before, reset));
    }
}
