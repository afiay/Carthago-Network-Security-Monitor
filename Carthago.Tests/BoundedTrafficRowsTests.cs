using System;
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
    public void HiddenGridRetainsNewestRowsUntilOneExplicitInvalidation()
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

        Assert.Equal(new[] { 6, 5, 4, 3 }, rows);
        Assert.Equal(0, notifications);

        rows.NotifyReset();

        Assert.Equal(1, notifications);
        Assert.Equal(new[] { 6, 5, 4, 3 }, rows);
    }
}
