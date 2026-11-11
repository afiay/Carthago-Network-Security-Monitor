using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

public class DashboardAnalyticsRefreshCoalescerTests
{
    [Fact]
    public void ProductionCadenceLeavesTwoSecondsBetweenFullDashboardRefreshes()
    {
        var time = new ManualTimeProvider();
        var refresh = new DashboardAnalyticsRefreshCoalescer(
            DashboardAnalyticsRefreshCoalescer.DefaultMinimumInterval,
            time);
        Assert.True(refresh.Request(DashboardAnalyticsRefreshKind.All));

        time.Advance(TimeSpan.FromMilliseconds(1999));
        Assert.False(refresh.TryBeginRefresh(out _, out var retryAfter));
        Assert.Equal(TimeSpan.FromMilliseconds(1), retryAfter);

        time.Advance(TimeSpan.FromMilliseconds(1));
        Assert.True(refresh.TryBeginRefresh(out var pending, out _));
        Assert.Equal(DashboardAnalyticsRefreshKind.All, pending);
        Assert.False(refresh.CompleteRefresh());
    }

    [Fact]
    public void ContinuousBurstArmsOneRefreshAndCombinesAllKinds()
    {
        var time = new ManualTimeProvider();
        var refresh = new DashboardAnalyticsRefreshCoalescer(TimeSpan.FromMilliseconds(500), time);

        Assert.True(refresh.Request(DashboardAnalyticsRefreshKind.Incidents));
        for (var i = 0; i < 100; i++)
        {
            Assert.False(refresh.Request(DashboardAnalyticsRefreshKind.Anomalies));
            Assert.False(refresh.Request(DashboardAnalyticsRefreshKind.Baseline));
        }

        Assert.Equal(TimeSpan.FromMilliseconds(500), refresh.GetDelayUntilNextRefresh());
        time.Advance(TimeSpan.FromMilliseconds(500));
        Assert.True(refresh.TryBeginRefresh(out var pending, out var retryAfter));
        Assert.Equal(DashboardAnalyticsRefreshKind.All, pending);
        Assert.Equal(TimeSpan.Zero, retryAfter);
        Assert.False(refresh.CompleteRefresh());
    }

    [Fact]
    public void RefreshCannotBeginBeforeMinimumInterval()
    {
        var time = new ManualTimeProvider();
        var refresh = new DashboardAnalyticsRefreshCoalescer(TimeSpan.FromMilliseconds(500), time);
        Assert.True(refresh.Request(DashboardAnalyticsRefreshKind.Baseline));

        Assert.False(refresh.TryBeginRefresh(out _, out var initialRetry));
        Assert.Equal(TimeSpan.FromMilliseconds(500), initialRetry);

        time.Advance(TimeSpan.FromMilliseconds(499));
        Assert.False(refresh.TryBeginRefresh(out _, out var finalRetry));
        Assert.Equal(TimeSpan.FromMilliseconds(1), finalRetry);

        time.Advance(TimeSpan.FromMilliseconds(1));
        Assert.True(refresh.TryBeginRefresh(out var pending, out var retryAfter));
        Assert.Equal(DashboardAnalyticsRefreshKind.Baseline, pending);
        Assert.Equal(TimeSpan.Zero, retryAfter);
        Assert.False(refresh.CompleteRefresh());
    }

    [Fact]
    public void UpdateDuringRefreshRunsOnceAfterFullTrailingInterval()
    {
        var time = new ManualTimeProvider();
        var refresh = new DashboardAnalyticsRefreshCoalescer(TimeSpan.FromMilliseconds(500), time);
        Assert.True(refresh.Request(DashboardAnalyticsRefreshKind.Incidents));
        time.Advance(TimeSpan.FromMilliseconds(500));
        Assert.True(refresh.TryBeginRefresh(out var first, out _));
        Assert.Equal(DashboardAnalyticsRefreshKind.Incidents, first);

        Assert.False(refresh.Request(DashboardAnalyticsRefreshKind.Baseline));
        Assert.True(refresh.CompleteRefresh());
        Assert.False(refresh.TryBeginRefresh(out _, out var retryAfter));
        Assert.Equal(TimeSpan.FromMilliseconds(500), retryAfter);

        time.Advance(TimeSpan.FromMilliseconds(500));
        Assert.True(refresh.TryBeginRefresh(out var trailing, out _));
        Assert.Equal(DashboardAnalyticsRefreshKind.Baseline, trailing);
        Assert.False(refresh.CompleteRefresh());
    }

    [Fact]
    public void OverlappingRefreshCannotBegin()
    {
        var time = new ManualTimeProvider();
        var refresh = new DashboardAnalyticsRefreshCoalescer(TimeSpan.FromMilliseconds(500), time);
        Assert.True(refresh.Request(DashboardAnalyticsRefreshKind.Anomalies));
        time.Advance(TimeSpan.FromMilliseconds(500));
        Assert.True(refresh.TryBeginRefresh(out _, out _));

        Assert.False(refresh.TryBeginRefresh(out var overlapping, out var retryAfter));
        Assert.Equal(DashboardAnalyticsRefreshKind.None, overlapping);
        Assert.Equal(TimeSpan.Zero, retryAfter);
        Assert.False(refresh.CompleteRefresh());
    }

    [Fact]
    public void ConcurrentNotificationsScheduleOnceWithoutLosingKinds()
    {
        var time = new ManualTimeProvider();
        var refresh = new DashboardAnalyticsRefreshCoalescer(TimeSpan.FromMilliseconds(500), time);
        var scheduled = 0;

        Parallel.For(0, 3000, index =>
        {
            var kind = (index % 3) switch
            {
                0 => DashboardAnalyticsRefreshKind.Incidents,
                1 => DashboardAnalyticsRefreshKind.Anomalies,
                _ => DashboardAnalyticsRefreshKind.Baseline
            };
            if (refresh.Request(kind))
                Interlocked.Increment(ref scheduled);
        });

        Assert.Equal(1, scheduled);
        time.Advance(TimeSpan.FromMilliseconds(500));
        Assert.True(refresh.TryBeginRefresh(out var pending, out _));
        Assert.Equal(DashboardAnalyticsRefreshKind.All, pending);
        Assert.False(refresh.CompleteRefresh());
    }

    [Fact]
    public void CancelPreventsScheduledAndFutureWork()
    {
        var time = new ManualTimeProvider();
        var refresh = new DashboardAnalyticsRefreshCoalescer(TimeSpan.FromMilliseconds(500), time);
        Assert.True(refresh.Request(DashboardAnalyticsRefreshKind.Incidents));

        refresh.Cancel();
        time.Advance(TimeSpan.FromMilliseconds(500));

        Assert.False(refresh.TryBeginRefresh(out var pending, out var retryAfter));
        Assert.Equal(DashboardAnalyticsRefreshKind.None, pending);
        Assert.Equal(TimeSpan.Zero, retryAfter);
        Assert.False(refresh.Request(DashboardAnalyticsRefreshKind.Baseline));
    }

    [Fact]
    public void CancelDuringRefreshSuppressesTrailingWork()
    {
        var time = new ManualTimeProvider();
        var refresh = new DashboardAnalyticsRefreshCoalescer(TimeSpan.FromMilliseconds(500), time);
        Assert.True(refresh.Request(DashboardAnalyticsRefreshKind.Incidents));
        time.Advance(TimeSpan.FromMilliseconds(500));
        Assert.True(refresh.TryBeginRefresh(out _, out _));
        Assert.False(refresh.Request(DashboardAnalyticsRefreshKind.Baseline));

        refresh.Cancel();

        Assert.False(refresh.CompleteRefresh());
        Assert.False(refresh.Request(DashboardAnalyticsRefreshKind.Anomalies));
    }

    [Fact]
    public void RejectsInvalidCadenceConfiguration()
    {
        var time = new ManualTimeProvider();

        Assert.Throws<ArgumentOutOfRangeException>(() =>
            new DashboardAnalyticsRefreshCoalescer(TimeSpan.Zero, time));
        Assert.Throws<ArgumentNullException>(() =>
            new DashboardAnalyticsRefreshCoalescer(TimeSpan.FromMilliseconds(500), null!));
    }

    [Theory]
    [InlineData(DashboardAnalyticsRefreshKind.None)]
    [InlineData((DashboardAnalyticsRefreshKind)8)]
    public void RejectsEmptyOrUnknownWork(DashboardAnalyticsRefreshKind kind)
    {
        var refresh = new DashboardAnalyticsRefreshCoalescer();

        Assert.Throws<ArgumentOutOfRangeException>(() => refresh.Request(kind));
    }

    private sealed class ManualTimeProvider : TimeProvider
    {
        private long _timestamp;

        public override long TimestampFrequency => TimeSpan.TicksPerSecond;

        public override long GetTimestamp() => Interlocked.Read(ref _timestamp);

        public void Advance(TimeSpan elapsed)
            => Interlocked.Add(ref _timestamp, elapsed.Ticks);
    }
}
