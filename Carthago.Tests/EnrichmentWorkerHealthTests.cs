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
    public void Empty_And_Missing_Metrics_Are_Not_Success()
    {
        Assert.Contains("unavailable", EnrichmentHealthPresentation.WorkerSummary(null));
        Assert.Contains("—", EnrichmentHealthPresentation.WorkerSummary(new EnrichmentWorkerHealth().Snapshot()));
    }
}
