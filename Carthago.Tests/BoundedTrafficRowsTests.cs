using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

public class BoundedTrafficRowsTests
{
    [Fact]
    public void BurstsKeepNewestRowsAndNotifyOnlyOncePerBatch()
    {
        var rows = new BoundedTrafficRows<int>();
        var resets = 0;
        rows.CollectionChanged += (_, e) =>
        {
            Assert.Equal(NotifyCollectionChangedAction.Reset, e.Action);
            resets++;
        };

        rows.PrependBatch(new[] { 1, 2, 3 }, 4);
        rows.PrependBatch(new[] { 4, 5, 6 }, 4);

        Assert.Equal(new[] { 6, 5, 4, 3 }, rows);
        Assert.Equal(2, resets);
    }

    [Fact]
    public void EmptyBatchDoesNotInvalidateGridAndInvalidCapacityIsRejected()
    {
        var rows = new BoundedTrafficRows<int>();
        var notifications = 0;
        rows.CollectionChanged += (_, _) => notifications++;
        rows.PrependBatch(Array.Empty<int>(), 200);
        Assert.Equal(0, notifications);
        Assert.Throws<ArgumentOutOfRangeException>(() => rows.PrependBatch(new[] { 1 }, 0));
    }

    [Fact]
    public void OversizedInputRemainsStrictlyBounded()
    {
        var rows = new BoundedTrafficRows<int>();
        rows.PrependBatch(new[] { 1, 2, 3, 4, 5 }, 2);
        Assert.Equal(new[] { 5, 4 }, rows);
    }

    [Fact]
    public void HiddenGridStagesNewestRowsUntilOneExplicitInvalidation()
    {
        var rows = new BoundedTrafficRows<int>();
        var notifications = 0;
        rows.CollectionChanged += (_, e) =>
        {
            Assert.Equal(NotifyCollectionChangedAction.Reset, e.Action);
            notifications++;
        };

        rows.PrependBatch(new[] { 1, 2, 3 }, 4, notifyCollectionChanged: false);
        rows.PrependBatch(new[] { 4, 5, 6 }, 4, notifyCollectionChanged: false);

        Assert.Empty(rows);
        Assert.Equal(new[] { 6, 5, 4, 3 }, rows.GetRetainedSnapshot());
        Assert.Equal(0, notifications);

        rows.NotifyReset();

        Assert.Equal(1, notifications);
        Assert.Equal(new[] { 6, 5, 4, 3 }, rows);
    }

    [Fact]
    public void DeferredBatchCannotChangePublishedItemsBeforeItsResetEvent()
    {
        var rows = new BoundedTrafficRows<int>();
        var resetCounts = new List<int>();
        rows.CollectionChanged += (_, e) =>
        {
            Assert.Equal(NotifyCollectionChangedAction.Reset, e.Action);
            resetCounts.Add(rows.Count);
        };
        rows.PrependBatch(new[] { 1, 2, 3, 4, 5, 6, 7, 8, 9 }, 200);

        rows.PrependBatch(new[] { 10 }, 200, notifyCollectionChanged: false);

        // WPF's generator has received events accounting for nine items, so
        // the published collection must also remain at nine until Reset.
        Assert.Equal(9, rows.Count);
        Assert.Equal(new[] { 9, 8, 7, 6, 5, 4, 3, 2, 1 }, rows);
        Assert.Equal(new[] { 10, 9, 8, 7, 6, 5, 4, 3, 2, 1 }, rows.GetRetainedSnapshot());
        Assert.Equal(new[] { 9 }, resetCounts);

        rows.NotifyReset();

        Assert.Equal(10, rows.Count);
        Assert.Equal(10, rows[0]);
        Assert.Equal(new[] { 9, 10 }, resetCounts);
    }
}
