using System;
using System.Threading;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

public class CaptureSessionDiagnosticTimestampTests
{
    [Fact]
    public void QueuedRecordHasUtcEnqueueTimestamp()
    {
        var before = DateTime.UtcNow.Ticks;
        var item = new CaptureSessionRecord<int>(42, CancellationToken.None);
        var after = DateTime.UtcNow.Ticks;
        Assert.InRange(item.EnqueuedUtcTicks, before, after);
    }
}
