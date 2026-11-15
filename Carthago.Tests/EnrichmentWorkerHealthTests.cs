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
}
