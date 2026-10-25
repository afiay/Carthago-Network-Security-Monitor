using System;
using System.Threading;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

public class CaptureSessionDeliveryTests
{
    [Fact]
    public void PendingRecordFromStoppedSessionIsNotDelivered()
    {
        using var previousSession = new CancellationTokenSource();
        var pending = new CaptureSessionRecord<string>("previous-session", previousSession.Token);
        previousSession.Cancel();

        string? received = null;
        Assert.False(pending.TryDeliver(value => received = value));
        Assert.Null(received);
    }

    [Fact]
    public void RecordFromCurrentSessionIsDelivered()
    {
        using var currentSession = new CancellationTokenSource();
        var pending = new CaptureSessionRecord<string>("current-session", currentSession.Token);

        string? received = null;
        Assert.True(pending.TryDeliver(value => received = value));
        Assert.Equal("current-session", received);
    }
}
