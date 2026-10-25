using System;
using System.Collections.Generic;
using System.Threading;
using System.Threading.Channels;
using System.Threading.Tasks;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

public class CaptureUiDrainTests
{
    [Fact]
    public async Task ReportsReaderFaultAfterDeliveringAvailableRecords()
    {
        var channel = Channel.CreateUnbounded<int>();
        var seen = new List<int>();
        await channel.Writer.WriteAsync(12);
        channel.Writer.TryComplete(new InvalidOperationException("queue reader failed"));

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() =>
            CaptureUiDrain.RunAsync(channel.Reader, 100,
                batch => { seen.AddRange(batch); return Task.CompletedTask; }, CancellationToken.None));

        Assert.Equal("queue reader failed", error.Message);
        Assert.Equal(new[] { 12 }, seen);
    }

    [Fact]
    public async Task NormalCancellationIsNotReportedAsFault()
    {
        var channel = Channel.CreateUnbounded<int>();
        using var cancellation = new CancellationTokenSource();
        cancellation.Cancel();
        await CaptureUiDrain.RunAsync(channel.Reader, 100,
            _ => Task.CompletedTask, cancellation.Token);
    }
}
