using System.Collections.Generic;
using System.Linq;
using Carthago.Services;

namespace Carthago.Tests;

public sealed class EnrichmentHealthPresentationTests
{
    [Fact]
    public void Aggregate_Export_Preserves_Counters_And_Omits_Diagnostic_Text()
    {
        var stats = new TrafficCaptureService.StatsSnapshot
        {
            RegistrySessionId = System.Guid.Parse("12345678-1234-1234-1234-123456789abc"),
            EnrichmentCoverage = new(10, 5, 2, 1, 0, 4, 2, 1, 3),
            EnrichmentProviders = new Dictionary<string, EnrichmentProviderSnapshot>
            {
                ["whois"] = new(2, 1, 0, 1, 0, 2, 40, 20)
            },
            EnrichmentStorage = new(new(0, 32, 0), new(0, 32, 0),
                new(33, 1, "private-path-marker"))
        };
        var time = System.DateTimeOffset.Parse("2026-11-15T12:00:00Z");
        var json = EnrichmentHealthPresentation.ExportCounters(stats, time, 42, time.AddMinutes(-1));
        using var doc = System.Text.Json.JsonDocument.Parse(json);
        var root = doc.RootElement;
        Assert.Equal(1, root.GetProperty("schemaVersion").GetInt32());
        Assert.Equal(42, root.GetProperty("processId").GetInt32());
        Assert.Equal(time, root.GetProperty("sampledUtc").GetDateTimeOffset());
        Assert.Equal(10, root.GetProperty("coverage").GetProperty("Published").GetInt64());
        Assert.Equal(2, root.GetProperty("providers").GetProperty("whois").GetProperty("CacheHits").GetInt64());
        Assert.True(root.GetProperty("storage").GetProperty("checkpointDiagnosticPresent").GetBoolean());
        Assert.Equal(stats.RegistrySessionId.Value, root.GetProperty("storage").GetProperty("registrySessionId").GetGuid());
        Assert.DoesNotContain("private-path-marker", json);
        Assert.Equal(System.Text.Json.JsonValueKind.Null, root.GetProperty("workers").ValueKind);
    }

    [Fact]
    public void Aggregate_Export_Excludes_Unrecognized_Providers_And_Diagnostic_Payloads()
    {
        const string secret = "sensitive-endpoint-and-provider-diagnostic";
        var stats = new TrafficCaptureService.StatsSnapshot
        {
            EnrichmentProviders = new Dictionary<string, EnrichmentProviderSnapshot>
            {
                ["whois"] = new(1, 0, 0, 0, 0, 0, 5, 5),
                [secret] = new(1, 0, 0, 0, 0, 0, 5, 5)
            },
            EnrichmentStorage = new(new(1, 32, 0), new(2, 32, 1),
                new(1, 1, secret))
        };
        var now = System.DateTimeOffset.Parse("2026-11-17T05:00:00Z");
        var json = EnrichmentHealthPresentation.ExportCounters(stats, now, 42, now);
        using var doc = System.Text.Json.JsonDocument.Parse(json);
        var providers = doc.RootElement.GetProperty("providers");
        Assert.Equal(1, providers.EnumerateObject().Count());
        Assert.Equal(1, providers.GetProperty("whois").GetProperty("Success").GetInt64());
        Assert.False(providers.TryGetProperty(secret, out _));
        Assert.DoesNotContain(secret, json);
        var storage = doc.RootElement.GetProperty("storage");
        Assert.Equal(1, storage.GetProperty("checkpointFailures").GetInt64());
        Assert.True(storage.GetProperty("checkpointDiagnosticPresent").GetBoolean());
        Assert.Equal(1, storage.GetProperty("destinations").GetProperty("Rejected").GetInt64());
    }

    [Fact]
    public void Aggregate_Export_Without_Registry_Identity_Does_Not_Invent_One()
    {
        var stats = new TrafficCaptureService.StatsSnapshot { EnrichmentStorage = new(new(0, 32, 0), new(0, 32, 0), new(0, 0, null)) };
        using var doc = System.Text.Json.JsonDocument.Parse(EnrichmentHealthPresentation.ExportCounters(stats, System.DateTimeOffset.UtcNow, 42, System.DateTimeOffset.UtcNow));
        Assert.Equal(System.Text.Json.JsonValueKind.Null, doc.RootElement.GetProperty("storage").GetProperty("registrySessionId").ValueKind);
    }

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    [InlineData(null)]
    public void Aggregate_Export_Preserves_Registry_Run_Presence(bool? present)
    {
        var stats = new TrafficCaptureService.StatsSnapshot
        {
            RegistrySessionId = System.Guid.NewGuid(), RegistryRunPresent = present,
            EnrichmentStorage = new(new(0, 32, 0), new(0, 32, 0), new(0, 0, null))
        };
        var now = System.DateTimeOffset.UtcNow;
        using var doc = System.Text.Json.JsonDocument.Parse(EnrichmentHealthPresentation.ExportCounters(stats, now, 42, now));
        var storage = doc.RootElement.GetProperty("storage");
        Assert.Equal(stats.RegistrySessionId.Value, storage.GetProperty("registrySessionId").GetGuid());
        var value = storage.GetProperty("registryRunPresent");
        if (present.HasValue) Assert.Equal(present.Value, value.GetBoolean());
        else Assert.Equal(System.Text.Json.JsonValueKind.Null, value.ValueKind);
    }

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
        Assert.Equal("10.0 / 20 ms (4 outcomes)", row.Latency);
        Assert.Equal(2L, row.CacheHits);
    }
    [Fact]
    public void Provider_Latency_Uses_Completed_Outcomes_Not_Cache_Hits_Or_Published_Records()
    {
        var stats = new TrafficCaptureService.StatsSnapshot
        {
            EnrichmentCoverage = new(100, 0, 0, 0, 0, 0, 0, 0, 0),
            EnrichmentProviders = new Dictionary<string, EnrichmentProviderSnapshot>
            {
                ["whois"] = new(1, 0, 0, 1, 1, 50, 90, 60)
            }
        };
        var row = EnrichmentHealthPresentation.Build(stats).Providers.Single(p => p.Provider == "whois");
        Assert.Equal("33.3%", row.SuccessShare);
        Assert.Equal("30.0 / 60 ms (3 outcomes)", row.Latency);
        Assert.Equal(50L, row.CacheHits);
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
        Assert.Contains("hit share 50.0% of 8 eligible requests", summary);
        Assert.Contains("City: 3 attempts", summary);
        Assert.Contains("retained entries: 2/8", summary);
        Assert.Contains("GeoIP cache metrics unavailable", EnrichmentHealthPresentation.Build(new TrafficCaptureService.StatsSnapshot()).Summary);
    }

    [Fact]
    public void Metadata_Cache_Summary_Uses_Probe_Denominator_And_Distinguishes_Missing()
    {
        var summary = EnrichmentHealthPresentation.Build(new TrafficCaptureService.StatsSnapshot
        {
            ProcessMetadataCache = new(1, 2, 3, 1, 1)
        }).Summary;
        Assert.Contains("8 completed, 1 absent, 2 expired, 3 owner mismatch, 1 identity mismatch, 1 reused", summary);
        Assert.Contains((1.0 / 8).ToString("P1", System.Globalization.CultureInfo.InvariantCulture), summary);
        Assert.Contains("not packets or avoided native ownership scans", summary);
        Assert.Contains("fresh ownership remains required", summary);
        Assert.Contains("reuse share —", EnrichmentHealthPresentation.Build(new TrafficCaptureService.StatsSnapshot
        {
            ProcessMetadataCache = new(0, 0, 0, 0, 0)
        }).Summary);
        Assert.Contains("TCP metadata-cache metrics unavailable", EnrichmentHealthPresentation.Build(new TrafficCaptureService.StatsSnapshot()).Summary);
    }

    [Fact]
    public void Metadata_Cache_Capacity_Is_Independent_Of_Probe_Outcomes()
    {
        var summary = EnrichmentHealthPresentation.Build(new TrafficCaptureService.StatsSnapshot
        {
            ProcessMetadataCacheCapacity = (3, 17)
        }).Summary;
        Assert.Contains($"retained entries: 3/{WindowsProcessResolver.MaxCacheEntries}", summary);
        Assert.Contains("capacity evictions (process lifetime): 17", summary);
        Assert.Contains("Retained entries may be expired", summary);
        Assert.Contains("exclude explicit clear and invalidation", summary);
        Assert.Contains("TCP metadata-cache metrics unavailable", summary);
        Assert.Contains("capacity evictions (process lifetime): 0", EnrichmentHealthPresentation.Build(new TrafficCaptureService.StatsSnapshot { ProcessMetadataCacheCapacity = (0, 0) }).Summary);
        Assert.Contains("TCP metadata-cache capacity metrics unavailable", EnrichmentHealthPresentation.Build(new TrafficCaptureService.StatsSnapshot()).Summary);
    }

    [Fact]
    public void Native_Process_Summary_Separates_Candidates_And_Empty_Buckets()
    {
        var stats = new TrafficCaptureService.StatsSnapshot
        {
            NativeProcessLookups = new WindowsProcessResolver.ProcessLookupMetrics.Snapshot[]
            {
                new(2, 1, 1, System.Diagnostics.Stopwatch.Frequency, 1, 3),
                new(0, 0, 0, 0, 2, 2),
                new(1, 0, 1, 0), default
            }
        };
        var summary = EnrichmentHealthPresentation.Build(stats).Summary;
        Assert.Contains("TCP/IPv4: 2 completed, 1 resolved, 1 unresolved, mean ms 500.0, 1 active, 3 peak active", summary);
        Assert.Contains("TCP/IPv6: 0 completed, 0 resolved, 0 unresolved, mean ms —, 2 active, 2 peak active", summary);
        Assert.Contains("UDP/IPv4: 1 completed, 0 resolved, 1 unresolved, mean ms 0.0", summary);
        Assert.Contains("not packets", summary);
        Assert.Contains("bucket peaks must not be summed", summary);
        Assert.Contains("UDP/IPv6: 0 completed, 0 resolved, 0 unresolved, mean ms —, 0 active, 0 peak active", summary);
        Assert.Contains("Native process lookup metrics unavailable", EnrichmentHealthPresentation.Build(new TrafficCaptureService.StatsSnapshot()).Summary);
    }
    [Fact]
    public void Tls_Capacity_Summary_Distinguishes_Closed_And_Missing_Session()
    {
        var summary = EnrichmentHealthPresentation.Build(new TrafficCaptureService.StatsSnapshot
        {
            TlsCapacity = (5, 3, 7)
        }).Summary;
        Assert.Contains("open: 2; closed: 3", summary);
        Assert.Contains("capacity-rejected SYN attempts (session lifetime): 7", summary);
        Assert.Contains("not a count of live connections", summary);
        Assert.Contains("open: 0; closed: 0", EnrichmentHealthPresentation.Build(new TrafficCaptureService.StatsSnapshot { TlsCapacity = (0, 0, 0) }).Summary);
        Assert.Contains("TLS capacity metrics unavailable (no capture session)", EnrichmentHealthPresentation.Build(new TrafficCaptureService.StatsSnapshot()).Summary);
    }
    [Fact]
    public void Storage_Summary_Distinguishes_Persisted_Checkpoint_Warning()
    {
        var stats = new TrafficCaptureService.StatsSnapshot
        {
            EnrichmentStorage = new(new(0, 32, 0), new(0, 32, 0),
                new(33, 0, "Checkpoint persisted; retention cleanup failed: denied"))
        };
        var summary = EnrichmentHealthPresentation.Build(stats).Summary;
        Assert.Contains("Checkpoint writes: 33, failures: 0", summary);
        Assert.Contains("Checkpoint diagnostic present (details withheld; inspect restricted local logs).", summary);
        Assert.DoesNotContain("Checkpoint persisted; retention cleanup failed: denied", summary);
        Assert.DoesNotContain("Last save error", summary);
        stats = new TrafficCaptureService.StatsSnapshot
        {
            EnrichmentStorage = new(new(0, 32, 0), new(0, 32, 0), new(34, 0, null))
        };
        Assert.Contains("No checkpoint diagnostic reported", EnrichmentHealthPresentation.Build(stats).Summary);
    }
    [Fact]
    public void Geo_Cache_Zero_Eligible_Requests_Has_No_Hit_Rate()
    {
        var summary = EnrichmentHealthPresentation.Build(new TrafficCaptureService.StatsSnapshot
        {
            GeoCacheHealth = new(0, 0, 0, 0, 0, 0, 8)
        }).Summary;
        Assert.Contains("0 eligible requests", summary);
        Assert.Contains("hit share — of 0 eligible requests", summary);
    }

    [Fact]
    public void Worker_Summary_Without_Snapshot_Does_Not_Invent_Denominators()
    {
        Assert.Equal("Worker metrics unavailable.", EnrichmentHealthPresentation.WorkerSummary(null));
    }

}
