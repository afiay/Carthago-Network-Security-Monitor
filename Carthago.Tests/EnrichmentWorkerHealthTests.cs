using Carthago.Services;

namespace Carthago.Tests;

public sealed class EnrichmentWorkerHealthTests
{
    [Fact]
    public void Outcomes_And_Wait_Use_Separate_Denominators()
    {
        var h = new EnrichmentWorkerHealth();
        h.SkipCancelled();
        h.Start(4); h.End(true, false, 20);
        h.Start(10); h.End(true, true, 30);
        h.Start(6); h.End(false, false, 40);
        h.Start(8);
        var s = h.Snapshot();
        Assert.Equal(4L, s.Started);
        Assert.Equal(1L, s.Returned);
        Assert.Equal(1L, s.Cancelled);
        Assert.Equal(1L, s.Faulted);
        Assert.Equal(1L, s.Skipped);
        Assert.Equal(28L, s.WaitTotalMs);
        Assert.Equal(10L, s.WaitMaxMs);
        Assert.Equal(90L, s.ElapsedTotalMs);
        Assert.Equal(40L, s.ElapsedMaxMs);
        var display = EnrichmentHealthPresentation.WorkerSummary(s);
        Assert.Contains("7.0 / 10", display);
        Assert.Contains("30.0 / 40", display);
    }
    [Fact]
    public void Worker_Summary_Separates_InFlight_From_Completed_And_Skipped()
    {
        var h = new EnrichmentWorkerHealth();
        h.SkipCancelled();
        h.Start(4); h.End(true, false, 20);
        h.Start(8);
        var active = EnrichmentHealthPresentation.WorkerSummary(h.Snapshot());
        Assert.Contains("in flight at snapshot: 1", active);
        Assert.Contains("started workers: 2", active);
        Assert.Contains("completed workers: 1", active);
        Assert.Contains("6.0 / 8", active);
        Assert.Contains("20.0 / 20", active);
        h.End(false, false, 30);
        var drained = EnrichmentHealthPresentation.WorkerSummary(h.Snapshot());
        Assert.Contains("in flight at snapshot: 0", drained);
        Assert.Contains("completed workers: 2", drained);
        Assert.Contains("25.0 / 30", drained);
        var empty = EnrichmentHealthPresentation.WorkerSummary(new EnrichmentWorkerHealth().Snapshot());
        Assert.Contains("in flight at snapshot: 0", empty);
        Assert.Contains("started workers: 0", empty);
        Assert.Contains("completed workers: 0", empty);
        Assert.Contains("—", empty);
    }

    [Fact]
    public void Worker_Durations_Clamp_Negative_Values_Without_Changing_Outcome_Denominators()
    {
        var health = new EnrichmentWorkerHealth();
        health.Start(-100);
        health.End(true, false, -200);
        health.Start(12);
        health.End(true, true, 15);
        health.Start(-1);
        health.End(false, false, -1);

        var snapshot = health.Snapshot();
        Assert.Equal(3L, snapshot.Started);
        Assert.Equal(1L, snapshot.Returned);
        Assert.Equal(1L, snapshot.Cancelled);
        Assert.Equal(1L, snapshot.Faulted);
        Assert.Equal(12L, snapshot.WaitTotalMs);
        Assert.Equal(12L, snapshot.WaitMaxMs);
        Assert.Equal(15L, snapshot.ElapsedTotalMs);
        Assert.Equal(15L, snapshot.ElapsedMaxMs);
        var summary = EnrichmentHealthPresentation.WorkerSummary(snapshot);
        Assert.Contains("started workers: 3", summary);
        Assert.Contains("completed workers: 3", summary);
        Assert.Contains("4.0 / 12", summary);
        Assert.Contains("5.0 / 15", summary);
        Assert.Contains("in flight at snapshot: 0", summary);
    }

    [Fact]
    public async System.Threading.Tasks.Task Worker_Snapshot_During_Concurrent_InFlight_Work_Reconciles_After_Drain()
    {
        const int workers = 16;
        var health = new EnrichmentWorkerHealth();
        using var started = new System.Threading.CountdownEvent(workers);
        using var release = new System.Threading.ManualResetEventSlim(false);
        var tasks = System.Linq.Enumerable.Range(0, workers).Select(i =>
            System.Threading.Tasks.Task.Factory.StartNew(() =>
            {
                health.Start(i + 1);
                started.Signal();
                release.Wait();
                health.End(i % 2 == 0, false, 2 * (i + 1));
            }, System.Threading.CancellationToken.None,
                System.Threading.Tasks.TaskCreationOptions.LongRunning,
                System.Threading.Tasks.TaskScheduler.Default)).ToArray();
        try
        {
            Assert.True(started.Wait(System.TimeSpan.FromSeconds(15)), "All workers must reach the in-flight barrier");
            var inFlight = health.Snapshot();
            Assert.Equal(workers, inFlight.Started);
            Assert.Equal(0L, inFlight.Returned + inFlight.Cancelled + inFlight.Faulted);
            Assert.Equal(136L, inFlight.WaitTotalMs);
            Assert.Equal(16L, inFlight.WaitMaxMs);
            Assert.Equal(0L, inFlight.ElapsedTotalMs);
            Assert.Contains("in flight at snapshot: 16", EnrichmentHealthPresentation.WorkerSummary(inFlight));
        }
        finally
        {
            release.Set();
            await System.Threading.Tasks.Task.WhenAll(tasks).WaitAsync(System.TimeSpan.FromSeconds(15));
        }
        var drained = health.Snapshot();
        Assert.Equal(workers, drained.Started);
        Assert.Equal(8L, drained.Returned);
        Assert.Equal(8L, drained.Faulted);
        Assert.Equal(0L, drained.Cancelled);
        Assert.Equal(272L, drained.ElapsedTotalMs);
        Assert.Equal(32L, drained.ElapsedMaxMs);
        Assert.Contains("in flight at snapshot: 0", EnrichmentHealthPresentation.WorkerSummary(drained));
    }

    [Fact]
    public void Worker_Summary_Flags_Overcompleted_Accounting_Without_Inventing_InFlight_Work()
    {
        // Deliberately invalid synthetic snapshot: this is an observability guard,
        // not evidence that a production worker has over-completed.
        var invalid = new EnrichmentWorkerSnapshot(1, 1, 1, 0, 0, 5, 5, 10, 10);
        var summary = EnrichmentHealthPresentation.WorkerSummary(invalid);
        Assert.Contains("in flight at snapshot: 0", summary);
        Assert.Contains("WARNING: completed outcomes exceed started workers by 1", summary);
        Assert.Contains("completed workers: 2", summary);

        var valid = new EnrichmentWorkerHealth();
        valid.Start(2);
        valid.End(true, false, 3);
        Assert.DoesNotContain("WARNING:", EnrichmentHealthPresentation.WorkerSummary(valid.Snapshot()));
    }

    [Theory]
    [InlineData(-1, 0, 0, 0, 0, 0, 0, 0, 0)]
    [InlineData(1, -1, 0, 0, 0, 0, 0, 0, 0)]
    [InlineData(1, 0, 0, 0, -1, 0, 0, 0, 0)]
    [InlineData(1, 0, 0, 0, 0, -1, 0, 0, 0)]
    [InlineData(1, 0, 0, 0, 0, 0, 0, -1, 0)]
    public void Worker_Summary_Flags_Negative_Counters_Without_Rewriting_Snapshot(
        long started, long returned, long cancelled, long faulted, long skipped,
        long waitTotal, long waitMax, long elapsedTotal, long elapsedMax)
    {
        var snapshot = new EnrichmentWorkerSnapshot(started, returned, cancelled, faulted,
            skipped, waitTotal, waitMax, elapsedTotal, elapsedMax);
        var summary = EnrichmentHealthPresentation.WorkerSummary(snapshot);
        Assert.Contains("WARNING: negative worker counters or durations", summary);
        Assert.Contains("-1", summary);
    }

    [Fact]
    public void Detached_Work_Return_Is_Cancelled_Even_Before_Token_Signal()
    {
        using var oldRun = new System.Threading.CancellationTokenSource();
        using var newRun = new System.Threading.CancellationTokenSource();
        var h = new EnrichmentWorkerHealth();
        h.Start(1);
        TrafficCaptureService.RecordEnrichmentWorkerEnd(h, null, oldRun.Token, true, 2);
        Assert.False(oldRun.IsCancellationRequested);
        h.Start(3);
        TrafficCaptureService.RecordEnrichmentWorkerEnd(h, newRun.Token, oldRun.Token, true, 4);
        h.Start(5);
        TrafficCaptureService.RecordEnrichmentWorkerEnd(h, newRun.Token, newRun.Token, true, 6);
        h.Start(7);
        TrafficCaptureService.RecordEnrichmentWorkerEnd(h, newRun.Token, newRun.Token, false, 8);
        newRun.Cancel();
        h.Start(9);
        TrafficCaptureService.RecordEnrichmentWorkerEnd(h, newRun.Token, newRun.Token, true, 10);
        var snapshot = h.Snapshot();
        Assert.Equal(5L, snapshot.Started);
        Assert.Equal(3L, snapshot.Cancelled);
        Assert.Equal(1L, snapshot.Returned);
        Assert.Equal(1L, snapshot.Faulted);
        Assert.Equal(30L, snapshot.ElapsedTotalMs);
    }

    [Fact]
    public void Empty_And_Missing_Metrics_Are_Not_Success()
    {
        Assert.Contains("unavailable", EnrichmentHealthPresentation.WorkerSummary(null));
        Assert.Contains("—", EnrichmentHealthPresentation.WorkerSummary(new EnrichmentWorkerHealth().Snapshot()));
    }
    [Fact]
    public void Sustained_Concurrent_Worker_Accounting_Reconciles_Exactly()
    {
        const int batches = 32, perBatch = 128;
        var h = new EnrichmentWorkerHealth();
        using var run = new System.Threading.CancellationTokenSource();
        using var detached = new System.Threading.CancellationTokenSource();
        for (int batch = 0; batch < batches; batch++)
        {
            System.Threading.Tasks.Parallel.For(0, perBatch, i =>
            {
                if (i % 4 == 0) { h.SkipCancelled(); return; }
                h.Start(2);
                TrafficCaptureService.RecordEnrichmentWorkerEnd(h, run.Token,
                    i % 4 == 2 ? detached.Token : run.Token, i % 4 != 3, 5);
                var interim = h.Snapshot();
                Assert.InRange(interim.Returned + interim.Cancelled + interim.Faulted, 0L, interim.Started);
            });
            var snapshot = h.Snapshot();
            long each = (batch + 1) * (perBatch / 4);
            Assert.Equal(each, snapshot.Returned);
            Assert.Equal(each, snapshot.Cancelled);
            Assert.Equal(each, snapshot.Faulted);
            Assert.Equal(each, snapshot.Skipped);
            Assert.Equal(each * 3, snapshot.Started);
            Assert.Equal(each * 6, snapshot.WaitTotalMs);
            Assert.Equal(each * 15, snapshot.ElapsedTotalMs);
            Assert.Equal(2L, snapshot.WaitMaxMs);
            Assert.Equal(5L, snapshot.ElapsedMaxMs);
        }
    }

    [Fact]
    public async System.Threading.Tasks.Task Worker_Drain_Continues_After_Item_Fault_Without_Retry()
    {
        var channel = System.Threading.Channels.Channel.CreateBounded<int>(3);
        Assert.True(channel.Writer.TryWrite(1));
        Assert.True(channel.Writer.TryWrite(2));
        Assert.True(channel.Writer.TryWrite(3));
        channel.Writer.Complete();
        var seen = new System.Collections.Generic.List<int>();
        var errors = new System.Collections.Generic.List<System.Exception>();
        await TrafficCaptureService.DrainEnrichmentItemsAsync(channel.Reader, item =>
        {
            seen.Add(item);
            if (item == 1) throw new System.InvalidOperationException("item fault");
            if (item == 2) throw new System.OperationCanceledException("item cancellation");
            return System.Threading.Tasks.Task.CompletedTask;
        }, errors.Add, System.Threading.CancellationToken.None);
        Assert.Equal(new[] { 1, 2, 3 }, seen);
        Assert.Collection(errors,
            ex => Assert.IsType<System.InvalidOperationException>(ex),
            ex => Assert.IsType<System.OperationCanceledException>(ex));
    }

    [Fact]
    public async System.Threading.Tasks.Task Worker_Drain_Stops_On_Service_Cancellation()
    {
        using var stop = new System.Threading.CancellationTokenSource();
        var channel = System.Threading.Channels.Channel.CreateBounded<int>(2);
        Assert.True(channel.Writer.TryWrite(1));
        Assert.True(channel.Writer.TryWrite(2));
        channel.Writer.Complete();
        var seen = new System.Collections.Generic.List<int>();
        var errors = new System.Collections.Generic.List<System.Exception>();
        await Assert.ThrowsAnyAsync<System.OperationCanceledException>(() =>
            TrafficCaptureService.DrainEnrichmentItemsAsync(channel.Reader, item =>
            {
                seen.Add(item);
                stop.Cancel();
                stop.Token.ThrowIfCancellationRequested();
                return System.Threading.Tasks.Task.CompletedTask;
            }, errors.Add, stop.Token));
        Assert.Equal(new[] { 1 }, seen);
        Assert.Empty(errors);
    }
}
