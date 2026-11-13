using System.Collections.Generic;
using System.Linq;
using Carthago.Services;

namespace Carthago.Tests;

public sealed class EnrichmentHealthPresentationTests
{
    [Fact]
    public void Missing_Snapshot_Does_Not_Invent_Provider_Health()
    {
        Assert.Empty(EnrichmentHealthPresentation.Build(null).Providers);
    }
    [Fact]
    public void Zero_Outcomes_Does_Not_Imply_Healthy()
    {
        var display = EnrichmentHealthPresentation.Build(new TrafficCaptureService.StatsSnapshot());
        Assert.Equal(3, display.Providers.Count);
        Assert.All(display.Providers, p => { Assert.Equal("—", p.SuccessShare); Assert.Equal("—", p.Latency); });
    }
    [Fact]
    public void Cache_Hits_Do_Not_Inflate_Outcome_Denominator()
    {
        var stats = new TrafficCaptureService.StatsSnapshot
        {
            EnrichmentProviders = new Dictionary<string, EnrichmentProviderSnapshot>
            {
                ["whois"] = new(2, 1, 0, 1, 0, 2, 40, 20)
            }
        };
        var row = EnrichmentHealthPresentation.Build(stats).Providers.Single(p => p.Provider == "whois");
        Assert.Equal(50.0, double.Parse(row.SuccessShare.Replace("%", "").Trim(), System.Globalization.CultureInfo.InvariantCulture));
        Assert.Equal("10.0 / 20", row.Latency);
        Assert.Equal(2L, row.CacheHits);
    }
    [Fact]
    public void Cancellation_Remains_A_Distinct_Outcome()
    {
        var stats = new TrafficCaptureService.StatsSnapshot
        {
            EnrichmentProviders = new Dictionary<string, EnrichmentProviderSnapshot>
            {
                ["reputation"] = new(1, 0, 0, 0, 1, 0, 10, 7)
            }
        };
        var row = EnrichmentHealthPresentation.Build(stats).Providers.Single(p => p.Provider == "reputation");
        Assert.Equal(1L, row.Cancelled);
        Assert.Equal(50.0, double.Parse(row.SuccessShare.Replace("%", "").Trim(), System.Globalization.CultureInfo.InvariantCulture));
    }
}
