using System.Collections.Concurrent;
using System.Diagnostics;
using Carthago.Models;
using Carthago.Sinks;

namespace Carthago.Tests;

public sealed class SinkManagerTests
{
    [Fact]
    public async Task EnqueueAsync_Routes_Event_To_All_Sinks()
    {
        var sinkA = new RecordingSink();
        var sinkB = new RecordingSink();
        using var manager = new SinkManager(new IDetectionSink[] { sinkA, sinkB }, TestOptions);

        await manager.EnqueueAsync(CreateEvent());

        await AssertEventuallyAsync(
            () => sinkA.Events.Count == 1 && sinkB.Events.Count == 1,
            "Expected both sinks to receive the enqueued event.");
    }

    [Fact]
    public async Task Failing_Sink_Does_Not_Block_Healthy_Sinks()
    {
        var healthySink = new RecordingSink();
        var failedEvents = 0;
        using var manager = new SinkManager(new IDetectionSink[] { new FailingSink(), healthySink }, TestOptions);
        manager.SinkFailed += (_, __) => Interlocked.Increment(ref failedEvents);

        await manager.EnqueueAsync(CreateEvent());

        await AssertEventuallyAsync(
            () => healthySink.Events.Count == 1 && Volatile.Read(ref failedEvents) == 1,
            "Expected the healthy sink to receive the event even when another sink fails.");
    }

    private static readonly SinkManagerOptions TestOptions = new()
    {
        MaxBatchWindow = TimeSpan.FromMilliseconds(10),
        PerAttemptTimeout = TimeSpan.FromMilliseconds(250),
        MaxRetries = 0,
        BreakerTripFailures = 1
    };

    private static DetectionEvent CreateEvent() =>
        new()
        {
            Timestamp = DateTime.UtcNow,
            RuleId = "RTEST",
            Description = "test event",
            SourceIp = "10.0.0.1",
            DestinationIp = "10.0.0.2",
            DestinationPort = 443,
            Protocol = "TCP",
            Severity = SeverityLevel.Medium,
            Count = 1,
            WindowSeconds = 5
        };

    private static async Task AssertEventuallyAsync(Func<bool> condition, string message, int timeoutMs = 3000)
    {
        var sw = Stopwatch.StartNew();
        while (sw.ElapsedMilliseconds < timeoutMs)
        {
            if (condition()) return;
            await Task.Delay(25);
        }

        Assert.True(condition(), message);
    }

    private sealed class RecordingSink : IDetectionSink
    {
        public ConcurrentQueue<DetectionEvent> Events { get; } = new();

        public Task EmitAsync(DetectionEvent evt, CancellationToken ct = default)
        {
            Events.Enqueue(evt);
            return Task.CompletedTask;
        }

        public void Dispose()
        {
        }
    }

    private sealed class FailingSink : IDetectionSink
    {
        public Task EmitAsync(DetectionEvent evt, CancellationToken ct = default)
            => Task.FromException(new InvalidOperationException("sink failure"));

        public void Dispose()
        {
        }
    }
}
