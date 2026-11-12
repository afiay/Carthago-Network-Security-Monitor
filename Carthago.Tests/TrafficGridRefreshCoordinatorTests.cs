using System;
using System.Collections.Specialized;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

public class TrafficGridRefreshCoordinatorTests
{
    [Fact]
    public void VisibleBurstCoalescesThousandsOfRowsIntoOneNotification()
    {
        var gate = new TrafficGridRefreshCoordinator();
        var rows = new BoundedTrafficRows<int>();
        var resets = 0;
        rows.CollectionChanged += (_, e) =>
        {
            Assert.Equal(NotifyCollectionChangedAction.Reset, e.Action);
            resets++;
        };

        Assert.Equal(TimeSpan.FromMilliseconds(250), TrafficGridRefreshCoordinator.RefreshInterval);
        var schedules = 0;
        for (var i = 0; i < 1000; i++)
        {
            rows.PrependBatch(new[] { i }, 200, notifyCollectionChanged: false);
            if (gate.Request(visible: true))
                schedules++;
        }

        Assert.Equal(1, schedules);
        Assert.Equal(0, resets);
        Assert.Empty(rows);
        var retained = rows.GetRetainedSnapshot();
        Assert.Equal(200, retained.Count);
        Assert.Equal(999, retained[0]);
        Assert.Equal(800, retained[199]);

        Assert.True(gate.OnTimer(visible: true));
        rows.NotifyReset();
        Assert.Equal(1, resets);
        Assert.Equal(200, rows.Count);
        Assert.Equal(999, rows[0]);
        Assert.Equal(800, rows[199]);
        Assert.False(gate.OnTimer(visible: true));

        Assert.True(gate.Request(visible: true));
        Assert.True(gate.OnTimer(visible: true));
    }

    [Fact]
    public void HiddenTrafficKeepsNewestSnapshotUntilOneNavigationRefresh()
    {
        var gate = new TrafficGridRefreshCoordinator();
        var rows = new BoundedTrafficRows<int>();
        var resets = 0;
        rows.CollectionChanged += (_, _) => resets++;

        for (var i = 0; i < 1000; i++)
        {
            rows.PrependBatch(new[] { i }, 200, notifyCollectionChanged: false);
            Assert.False(gate.Request(visible: false));
        }

        Assert.Equal(0, resets);
        Assert.Empty(rows);
        var retained = rows.GetRetainedSnapshot();
        Assert.Equal(999, retained[0]);
        Assert.Equal(800, retained[199]);
        Assert.True(gate.Show());
        rows.NotifyReset();
        Assert.Equal(1, resets);
        Assert.Equal(200, rows.Count);
    }

    [Fact]
    public void NavigatingAwayCancelsPendingTimerWithoutLosingLatestRows()
    {
        var gate = new TrafficGridRefreshCoordinator();
        Assert.True(gate.Request(visible: true));
        gate.Hide();
        Assert.False(gate.OnTimer(visible: false));
        Assert.False(gate.Request(visible: false));
        Assert.True(gate.Show());
        Assert.False(gate.OnTimer(visible: true));
        Assert.True(gate.Request(visible: true));
        Assert.True(gate.OnTimer(visible: true));
    }

    [Fact]
    public void TimerFiredAfterGridBecomesHiddenDoesNotInvalidate()
    {
        var gate = new TrafficGridRefreshCoordinator();
        Assert.True(gate.Request(visible: true));
        Assert.False(gate.OnTimer(visible: false));
        Assert.True(gate.Show());
        Assert.True(gate.Request(visible: true));
        Assert.True(gate.OnTimer(visible: true));
    }

    [Fact]
    public void IdleTimerDoesNotInvalidateAndShutdownSuppressesUpdates()
    {
        var gate = new TrafficGridRefreshCoordinator();
        Assert.False(gate.OnTimer(visible: true));
        Assert.True(gate.Request(visible: true));
        gate.Stop();
        Assert.False(gate.OnTimer(visible: true));
        Assert.False(gate.Request(visible: true));
        Assert.False(gate.Show());
    }
}
