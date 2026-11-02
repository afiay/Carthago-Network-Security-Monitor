// SPDX-License-Identifier: MIT
// R437 audit sink quality gate — SOURCE CANDIDATE — UNVERIFIED.
// Synthetic counter values; no Redis Software metrics scrape is performed.
using System;
using Carthago.Services.TrustedAudit;
using Xunit;

namespace Carthago.Tests;

public sealed class RedisAuditSinkMetricsHealthTests
{
    private static readonly DateTimeOffset Origin =
        new(2026, 11, 2, 18, 0, 0, TimeSpan.Zero);

    private static RedisAuditSinkMetricsSnapshot Sample(int second,
        long sent = 100, long dropped = 0, long disconnectLoss = 0,
        long exhausted = 0, long pending = 0)
        => new(Origin.AddSeconds(second), sent, dropped,
            disconnectLoss, exhausted, pending);

    [Fact]
    public void Baseline_And_Monotonic_No_Drop_Still_Cannot_Prove_Completeness()
    {
        var monitor = new RedisAuditSinkMetricsHealthMonitor();
        var first = monitor.Observe("operator-redis", Sample(0), Origin);
        Assert.Equal(RedisAuditSinkHealthStatus.BaselineOnly, first.Status);
        Assert.False(first.CompleteCommandAuditProven);
        Assert.False(first.AuditDeliveryAuthenticated);

        var next = monitor.Observe("operator-redis",
            Sample(10, sent: 110), Origin.AddSeconds(10));
        Assert.Equal(RedisAuditSinkHealthStatus.NoObservedLossDelta, next.Status);
        Assert.False(next.AlertPermitted);
        Assert.False(next.CompleteCommandAuditProven);
    }

    [Theory]
    [InlineData(1, 0, 0)]
    [InlineData(0, 1, 0)]
    [InlineData(0, 0, 1)]
    public void Any_Drop_Disconnect_Loss_Or_Exhaustion_Poisons_The_Source(
        int dropped, int disconnectLoss, int exhausted)
    {
        var monitor = new RedisAuditSinkMetricsHealthMonitor();
        monitor.Observe("operator-redis", Sample(0), Origin);
        var loss = monitor.Observe("operator-redis",
            Sample(10, 105, dropped, disconnectLoss, exhausted),
            Origin.AddSeconds(10));
        Assert.Equal(RedisAuditSinkHealthStatus.LossCounterIncrease, loss.Status);
        Assert.False(loss.AlertPermitted);

        var later = monitor.Observe("operator-redis",
            Sample(20, 120, dropped, disconnectLoss, exhausted),
            Origin.AddSeconds(20));
        Assert.Equal(RedisAuditSinkHealthStatus.PreviouslyCompromised,
            later.Status);
    }

    [Fact]
    public void Backlog_Is_Not_Mistaken_For_Confirmed_Delivery()
    {
        var monitor = new RedisAuditSinkMetricsHealthMonitor();
        monitor.Observe("operator-redis", Sample(0), Origin);
        var backlog = monitor.Observe("operator-redis",
            Sample(10, sent: 110, pending: 128), Origin.AddSeconds(10));
        Assert.Equal(RedisAuditSinkHealthStatus.PendingBacklog, backlog.Status);
        Assert.False(backlog.CompleteCommandAuditProven);

        var drained = monitor.Observe("operator-redis",
            Sample(20, sent: 120, pending: 0), Origin.AddSeconds(20));
        Assert.Equal(RedisAuditSinkHealthStatus.NoObservedLossDelta,
            drained.Status);
        Assert.False(drained.AuditDeliveryAuthenticated);
    }

    [Fact]
    public void Stale_Future_NonUtc_Invalid_And_Missing_Values_Fail_Closed()
    {
        var monitor = new RedisAuditSinkMetricsHealthMonitor();
        Assert.Equal(RedisAuditSinkHealthStatus.InvalidSourceOrSnapshot,
            monitor.Observe(null, Sample(0), Origin).Status);
        Assert.Equal(RedisAuditSinkHealthStatus.InvalidSourceOrSnapshot,
            monitor.Observe("operator-redis", null, Origin).Status);
        Assert.Equal(RedisAuditSinkHealthStatus.InvalidSourceOrSnapshot,
            monitor.Observe("operator-redis",
                Sample(0, dropped: -1), Origin).Status);
        Assert.Equal(RedisAuditSinkHealthStatus.StaleOrNonUtcSample,
            monitor.Observe("operator-redis", Sample(0),
                Origin.AddMinutes(3)).Status);
        Assert.Equal(RedisAuditSinkHealthStatus.StaleOrNonUtcSample,
            monitor.Observe("operator-redis", Sample(31),
                Origin).Status);
        Assert.Equal(RedisAuditSinkHealthStatus.StaleOrNonUtcSample,
            monitor.Observe("operator-redis", Sample(0),
                Origin.ToOffset(TimeSpan.FromHours(1))).Status);
    }

    [Fact]
    public void Counter_Reset_And_Out_Of_Order_Samples_Remain_Compromised()
    {
        var monitor = new RedisAuditSinkMetricsHealthMonitor();
        monitor.Observe("operator-redis", Sample(0, sent: 120), Origin);
        Assert.Equal(RedisAuditSinkHealthStatus.CounterResetOrStaleOrder,
            monitor.Observe("operator-redis",
                Sample(10, sent: 100), Origin.AddSeconds(10)).Status);
        Assert.Equal(RedisAuditSinkHealthStatus.PreviouslyCompromised,
            monitor.Observe("operator-redis",
                Sample(20, sent: 200), Origin.AddSeconds(20)).Status);

        var independent = new RedisAuditSinkMetricsHealthMonitor();
        independent.Observe("operator-redis", Sample(0), Origin);
        Assert.Equal(RedisAuditSinkHealthStatus.CounterResetOrStaleOrder,
            independent.Observe("operator-redis",
                Sample(0), Origin).Status);
    }

    [Fact]
    public void Source_Identity_Isolation_And_Bounded_Storage()
    {
        var monitor = new RedisAuditSinkMetricsHealthMonitor();
        for (var i = 0; i < 64; i++)
            Assert.Equal(RedisAuditSinkHealthStatus.BaselineOnly,
                monitor.Observe("redis-" + i, Sample(0), Origin).Status);
        Assert.Equal(RedisAuditSinkHealthStatus.TrackingCapacityExceeded,
            monitor.Observe("redis-64", Sample(0), Origin).Status);
    }
}
