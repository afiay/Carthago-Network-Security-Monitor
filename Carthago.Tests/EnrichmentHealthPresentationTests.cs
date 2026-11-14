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
    public void Geo_Database_States_Are_Independent_And_Not_Lookup_Outcomes()
    {
        var stats = new TrafficCaptureService.StatsSnapshot
        {
            GeoCityDatabaseStatus = Carthago.Services.Geo.GeoIpService.DatabaseAvailability.Missing,
            GeoAsnDatabaseStatus = Carthago.Services.Geo.GeoIpService.DatabaseAvailability.Ready
        };
        var display = EnrichmentHealthPresentation.Build(stats);
        Assert.Contains("City Missing; ASN Ready", display.Summary);
        Assert.Contains("not a successful lookup", display.Summary);
        Assert.Contains("City unknown; ASN unknown", EnrichmentHealthPresentation.Build(new TrafficCaptureService.StatsSnapshot()).Summary);
        Assert.Contains("City Unavailable; ASN unknown", EnrichmentHealthPresentation.Build(new TrafficCaptureService.StatsSnapshot
        {
            GeoCityDatabaseStatus = Carthago.Services.Geo.GeoIpService.DatabaseAvailability.Unavailable
        }).Summary);
    }

    [Fact]
    public void Geo_Lookup_Health_Uses_Independent_Completed_Attempts()
    {
        var stats = new TrafficCaptureService.StatsSnapshot
        {
            GeoCityLookupHealth = new(2, 1, 1),
            GeoAsnLookupHealth = new(0, 0, 0)
        };
        var summary = EnrichmentHealthPresentation.Build(stats).Summary;
        Assert.Contains("service lifetime", summary);
        Assert.Contains("City: 4 attempts, 2 found, 1 not found, 1 failed", summary);
        Assert.Contains("ASN: 0 attempts, 0 found, 0 not found, 0 failed (failure share —)", summary);
        Assert.Contains("25", summary);
        Assert.Contains("City unknown; ASN unknown", EnrichmentHealthPresentation.Build(new TrafficCaptureService.StatsSnapshot()).Summary);
        Assert.Contains("Records found do not imply usable field coverage", summary);
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

    [Fact]
    public void Geo_Cache_Requests_Are_Separate_From_Database_Attempts()
    {
        var stats = new TrafficCaptureService.StatsSnapshot
        {
            GeoCacheHealth = new(3, 1, 4, 1, 2, 2, 8),
            GeoCityLookupHealth = new(1, 2, 0)
        };
        var summary = EnrichmentHealthPresentation.Build(stats).Summary;
        Assert.Contains("8 eligible requests, 3 positive hits, 1 negative hits, 4 misses", summary);
        Assert.Contains("City: 3 attempts", summary);
        Assert.Contains("retained entries: 2/8", summary);
        Assert.Contains("GeoIP cache metrics unavailable", EnrichmentHealthPresentation.Build(new TrafficCaptureService.StatsSnapshot()).Summary);
    }

    [Fact]
    public void Native_Process_Summary_Separates_Candidates_And_Empty_Buckets()
    {
        var stats = new TrafficCaptureService.StatsSnapshot
        {
            NativeProcessLookups = new WindowsProcessResolver.ProcessLookupMetrics.Snapshot[]
            {
                new(2, 1, 1, System.Diagnostics.Stopwatch.Frequency), default,
                new(1, 0, 1, 0), default
            }
        };
        var summary = EnrichmentHealthPresentation.Build(stats).Summary;
        Assert.Contains("TCP/IPv4: 2 completed, 1 resolved, 1 unresolved, mean ms 500.0", summary);
        Assert.Contains("TCP/IPv6: 0 completed, 0 resolved, 0 unresolved, mean ms —", summary);
        Assert.Contains("UDP/IPv4: 1 completed, 0 resolved, 1 unresolved, mean ms 0.0", summary);
        Assert.Contains("not packets", summary);
        Assert.Contains("Native process lookup metrics unavailable", EnrichmentHealthPresentation.Build(new TrafficCaptureService.StatsSnapshot()).Summary);
    }
}
