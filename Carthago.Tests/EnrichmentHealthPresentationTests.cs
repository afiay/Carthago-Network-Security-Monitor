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
    public void Aggregate_Export_Preserves_Exact_GeoIp_Lifetime_Totals()
    {
        var stats = new TrafficCaptureService.StatsSnapshot
        {
            GeoCityLookupHealth = new(long.MaxValue, 0, long.MaxValue),
            GeoCacheHealth = new(long.MaxValue, long.MaxValue, 0, 0, 0, 0, 32)
        };
        var sampled = System.DateTimeOffset.Parse("2026-11-18T10:00:00Z");
        using var doc = System.Text.Json.JsonDocument.Parse(
            EnrichmentHealthPresentation.ExportCounters(stats, sampled, 42, sampled));
        var root = doc.RootElement;
        var city = root.GetProperty("geoCity");
        Assert.Equal(18446744073709551614m, city.GetProperty("AttemptsExact").GetDecimal());
        Assert.True(city.GetProperty("AttemptsOverflowed").GetBoolean());
        Assert.Equal(long.MaxValue, city.GetProperty("Attempts").GetInt64());
        var cache = root.GetProperty("geoCache");
        Assert.Equal(18446744073709551614m, cache.GetProperty("RequestsExact").GetDecimal());
        Assert.True(cache.GetProperty("RequestsOverflowed").GetBoolean());
        Assert.Equal(long.MaxValue, cache.GetProperty("Requests").GetInt64());
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

    [Theory]
    [InlineData(-1, 0, 0)]
    [InlineData(0, -1, 0)]
    [InlineData(0, 0, -1)]
    public void Invalid_Provider_Counters_Are_Flagged_Without_Hiding_Raw_Evidence(
        long success, long cacheHits, long elapsed)
    {
        var stats = new TrafficCaptureService.StatsSnapshot
        {
            EnrichmentProviders = new Dictionary<string, EnrichmentProviderSnapshot>
            {
                ["whois"] = new(success, 0, 0, 0, 0, cacheHits, elapsed, 0)
            }
        };
        var display = EnrichmentHealthPresentation.Build(stats);
        Assert.Contains("WARNING: invalid provider outcome, cache-path or latency counters", display.Summary);
        Assert.Equal(success, display.Providers.Single(p => p.Provider == "whois").Success);
        Assert.Equal(cacheHits, display.Providers.Single(p => p.Provider == "whois").CacheHits);
        Assert.DoesNotContain("WARNING: invalid provider outcome", EnrichmentHealthPresentation.Build(
            new TrafficCaptureService.StatsSnapshot()).Summary);
    }

    [Fact]
    public void Negative_Provider_Outcome_Does_Not_Display_Misleading_Success_Percentage()
    {
        var stats = new TrafficCaptureService.StatsSnapshot
        {
            EnrichmentProviders = new Dictionary<string, EnrichmentProviderSnapshot>
            {
                ["whois"] = new(5, -1, 0, 0, 0, 0, 10, 10)
            }
        };
        var display = EnrichmentHealthPresentation.Build(stats);
        Assert.Equal("—", display.Providers.Single(p => p.Provider == "whois").SuccessShare);
        Assert.Contains("WARNING: invalid provider outcome", display.Summary);
        Assert.Equal(-1L, display.Providers.Single(p => p.Provider == "whois").Unavailable);
    }

    [Theory]
    [InlineData(0, 0, 5, 5)]
    [InlineData(0, 0, 0, 5)]
    [InlineData(1, 0, 1, 2)]
    public void Provider_Latency_Inconsistency_Is_Flagged_Without_Fabricating_Outcomes(
        long success, long unavailable, long elapsed, long maxElapsed)
    {
        var stats = new TrafficCaptureService.StatsSnapshot
        {
            EnrichmentProviders = new Dictionary<string, EnrichmentProviderSnapshot>
            {
                ["whois"] = new(success, unavailable, 0, 0, 0, 0, elapsed, maxElapsed)
            }
        };
        var display = EnrichmentHealthPresentation.Build(stats);
        Assert.Contains("WARNING: invalid provider outcome, cache-path or latency counters", display.Summary);
        var row = display.Providers.Single(p => p.Provider == "whois");
        Assert.Equal(success, row.Success);
        Assert.Equal(success == 0 ? "—" : "100.0%", row.SuccessShare);
    }

    [Fact]
    public void Provider_Outcome_Denominator_Does_Not_Overflow_Long_Lifetime_Counters()
    {
        var stats = new TrafficCaptureService.StatsSnapshot
        {
            EnrichmentProviders = new Dictionary<string, EnrichmentProviderSnapshot>
            {
                ["whois"] = new(long.MaxValue, long.MaxValue, 0, 0, 0, 0, 0, 0)
            }
        };
        var display = EnrichmentHealthPresentation.Build(stats);
        var whois = display.Providers.Single(p => p.Provider == "whois");
        Assert.Equal("50.0%", whois.SuccessShare);
        Assert.Contains("outcomes)", whois.Latency);
        Assert.DoesNotContain("WARNING: invalid provider outcome", display.Summary);
    }

    [Fact]
    public void Cache_Only_Provider_Activity_Does_Not_Create_Outcome_Or_Latency_Samples()
    {
        // Cache path activity is not an attempted provider lookup. In particular,
        // an empty outcome population must never produce a 0% success rate.
        var stats = new TrafficCaptureService.StatsSnapshot
        {
            EnrichmentCoverage = new(250, 0, 0, 0, 0, 0, 0, 0, 0),
            EnrichmentProviders = new Dictionary<string, EnrichmentProviderSnapshot>
            {
                ["whois"] = new(0, 0, 0, 0, 0, 75, 0, 0),
                ["reputation"] = new(0, 0, 0, 0, 0, 0, 0, 0)
            }
        };
        var display = EnrichmentHealthPresentation.Build(stats);
        var whois = display.Providers.Single(p => p.Provider == "whois");
        Assert.Equal(75L, whois.CacheHits);
        Assert.Equal("—", whois.SuccessShare);
        Assert.Equal("—", whois.Latency);
        Assert.Equal(0L, whois.Success + whois.Unavailable + whois.Failed + whois.TimedOut + whois.Cancelled);
        Assert.Contains("Cache hits are lookup-path events, not additional outcomes", display.Summary);
        var reputation = display.Providers.Single(p => p.Provider == "reputation");
        Assert.Equal("—", reputation.SuccessShare);
        Assert.Equal("—", reputation.Latency);
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
    public void Geo_Lookup_Failure_Share_Uses_Exact_Overflowing_Attempt_Population()
    {
        var stats = new TrafficCaptureService.StatsSnapshot
        {
            GeoCityLookupHealth = new(long.MaxValue, 0, long.MaxValue)
        };
        var summary = EnrichmentHealthPresentation.Build(stats).Summary;
        Assert.Contains("City: 18446744073709551614 attempts", summary);
        Assert.Contains("failure share 50.0%", summary);
        Assert.Contains("WARNING: GeoIP lookup outcome counters invalid or exceed Int64", summary);
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
        Assert.Contains("8 accounted eligible requests (reported Int64 total 8), 3 positive hits, 1 negative hits, 4 misses", summary);
        Assert.Contains("hit share 50.0% of 8 accounted eligible requests", summary);
        Assert.Contains("City: 3 attempts", summary);
        Assert.Contains("retained entries: 2/8", summary);
        Assert.Contains("GeoIP cache metrics unavailable", EnrichmentHealthPresentation.Build(new TrafficCaptureService.StatsSnapshot()).Summary);
    }

    [Theory]
    [InlineData(3, 1, 4, 1, 2, 2, 8, false)]
    [InlineData(3, 1, 4, 1, 2, 9, 8, true)]
    [InlineData(-1, 1, 4, 1, 2, 2, 8, true)]
    [InlineData(long.MaxValue, long.MaxValue, 0, 0, 0, 0, 8, true)]
    public void Geo_Cache_Flags_Invalid_Counters_Without_Clamping(
        long positive, long negative, long misses, long expired, long evicted,
        int occupancy, int capacity, bool warning)
    {
        var stats = new TrafficCaptureService.StatsSnapshot
        {
            GeoCacheHealth = new(positive, negative, misses, expired, evicted, occupancy, capacity)
        };
        var summary = EnrichmentHealthPresentation.Build(stats).Summary;
        Assert.Equal(warning, summary.Contains("WARNING: GeoIP cache request-path or capacity counters inconsistent"));
        Assert.Contains($"{positive} positive hits", summary);
        Assert.Contains($"retained entries: {occupancy}/{capacity}", summary);
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
    public void Metadata_Cache_Overflow_Uses_Exact_Probe_Population()
    {
        var summary = EnrichmentHealthPresentation.ProcessMetadataCacheSummary(
            new WindowsProcessResolver.MetadataCacheMetrics.Snapshot(
                long.MaxValue, 0, 0, 0, long.MaxValue));
        Assert.Contains("18446744073709551614 completed", summary);
        Assert.Contains("reuse share —", summary);
        Assert.Contains("WARNING: TCP metadata-cache outcome counters invalid or exceed Int64", summary);
    }

    [Fact]
    public void Metadata_Cache_Negative_Outcome_Does_Not_Publish_Reuse_Rate()
    {
        var summary = EnrichmentHealthPresentation.ProcessMetadataCacheSummary(
            new WindowsProcessResolver.MetadataCacheMetrics.Snapshot(-1, 0, 0, 0, 3));
        Assert.Contains("2 completed", summary);
        Assert.Contains("-1 absent", summary);
        Assert.Contains("reuse share —", summary);
        Assert.Contains("WARNING: TCP metadata-cache outcome counters invalid", summary);
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

    [Theory]
    [InlineData(-1, 0L)]
    [InlineData(0, -1L)]
    [InlineData(int.MaxValue, 0L)]
    public void Metadata_Cache_Invalid_Capacity_Counters_Are_Flagged(int count, long evictions)
    {
        var summary = EnrichmentHealthPresentation.ProcessMetadataCacheCapacitySummary((count, evictions));
        Assert.Contains("WARNING: TCP metadata-cache capacity counters inconsistent", summary);
        Assert.Contains($"retained entries: {count}/{WindowsProcessResolver.MaxCacheEntries}", summary);
        Assert.Contains($"capacity evictions (process lifetime): {evictions}", summary);
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
    [Theory]
    [InlineData(-1, 0, 0)]
    [InlineData(2, -1, 0)]
    [InlineData(2, 3, 0)]
    [InlineData(2, 1, -1)]
    public void Tls_Invalid_Capacity_Gauges_Do_Not_Fabricate_Open_Connections(
        int retained, int closed, long rejected)
    {
        var summary = EnrichmentHealthPresentation.TlsCapacitySummary((retained, closed, rejected));
        Assert.Contains("WARNING: TLS retained, closed or capacity rejection counters inconsistent", summary);
        Assert.Contains("open: —", summary);
        Assert.Contains($"closed: {closed:N0}", summary);
        Assert.Contains($"capacity-rejected SYN attempts (session lifetime): {rejected:N0}", summary);
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
    public void Geo_Cache_Hit_Rate_Widens_Lifetime_Counters()
    {
        // Two individually valid lifetime hit counters exceed Int64 when combined.
        // The denominator is the full eligible request population, not DB attempts.
        var summary = EnrichmentHealthPresentation.Build(new TrafficCaptureService.StatsSnapshot
        {
            GeoCacheHealth = new(long.MaxValue, long.MaxValue, 0, 0, 0, 0, 8)
        }).Summary;
        Assert.Contains("hit share 100.0%", summary);
        Assert.Contains("18446744073709551614 accounted eligible requests", summary);
        Assert.Contains("WARNING: GeoIP cache request-path or capacity counters inconsistent", summary);
    }

    [Fact]
    public void Geo_Cache_Zero_Eligible_Requests_Has_No_Hit_Rate()
    {
        var summary = EnrichmentHealthPresentation.Build(new TrafficCaptureService.StatsSnapshot
        {
            GeoCacheHealth = new(0, 0, 0, 0, 0, 0, 8)
        }).Summary;
        Assert.Contains("0 accounted eligible requests", summary);
        Assert.Contains("hit share — of 0 accounted eligible requests", summary);
    }

    [Theory]
    [InlineData(1, 1, 0, 0, 0, 5, 6, 8, 4)]
    [InlineData(0, 0, 0, 0, 0, 5, 5, 0, 0)]
    [InlineData(1, 0, 0, 0, 0, 0, 0, 3, 3)]
    public void Worker_Summary_Suppresses_Inconsistent_Duration_Means(
        long started, long returned, long cancelled, long faulted, long skipped,
        long waitTotal, long waitMax, long elapsedTotal, long elapsedMax)
    {
        var snapshot = new EnrichmentWorkerSnapshot(started, returned, cancelled, faulted,
            skipped, waitTotal, waitMax, elapsedTotal, elapsedMax);
        var summary = EnrichmentHealthPresentation.WorkerSummary(snapshot);
        Assert.Contains("WARNING: invalid worker counters or duration accounting", summary);
        if (waitMax > waitTotal || started == 0)
            Assert.Contains("Queue wait mean/max ms (started workers: " + started + "): —", summary);
        if (elapsedMax > elapsedTotal || returned + cancelled + faulted == 0)
            Assert.Contains("worker elapsed mean/max ms (completed workers: ", summary);
    }

    [Fact]
    public void Worker_Summary_Without_Snapshot_Does_Not_Invent_Denominators()
    {
        Assert.Equal("Worker metrics unavailable.", EnrichmentHealthPresentation.WorkerSummary(null));
    }

    [Fact]
    public void Process_Coverage_Uses_Eligible_Record_Denominator_Not_All_Publications()
    {
        var stats = new TrafficCaptureService.StatsSnapshot
        {
            EnrichmentCoverage = new(100, 40, 20, 10, 5, 8, 3, 2, 7)
        };
        var summary = EnrichmentHealthPresentation.Build(stats).Summary;
        Assert.Contains("Local TCP/UDP records sampled after process stage: 8", summary);
        Assert.Contains("TCP socket ownership: 3/8 eligible", summary);
        Assert.Contains("UDP binding only: 2/8 eligible", summary);
        Assert.Contains("subset of published records", summary);
        Assert.DoesNotContain("TCP socket ownership: 3/100", summary);
    }

    [Fact]
    public void Evidence_Coverage_Flags_Negative_Counters_Without_Clamping_Them()
    {
        var negativePublished = new TrafficCaptureService.StatsSnapshot
        {
            EnrichmentCoverage = new(-1, 0, 0, 0, 0, 0, 0, 0, 0)
        };
        var negativeDns = new TrafficCaptureService.StatsSnapshot
        {
            EnrichmentCoverage = new(10, 0, 0, -1, 0, 0, 0, 0, 0)
        };
        var negativeProcess = new TrafficCaptureService.StatsSnapshot
        {
            EnrichmentCoverage = new(10, 0, 0, 0, 0, 5, -1, 0, 0)
        };
        foreach (var stats in new[] { negativePublished, negativeDns, negativeProcess })
        {
            var summary = EnrichmentHealthPresentation.Build(stats).Summary;
            Assert.Contains("WARNING: evidence coverage counters are negative or exceed", summary);
            Assert.Contains("-1", summary);
        }
    }

    [Fact]
    public void Evidence_Coverage_Flags_Impossible_Publication_And_Process_Denominators()
    {
        var valid = new TrafficCaptureService.StatsSnapshot
        {
            EnrichmentCoverage = new(100, 40, 20, 10, 5, 8, 3, 2, 7)
        };
        Assert.DoesNotContain("WARNING: evidence coverage counters", EnrichmentHealthPresentation.Build(valid).Summary);

        var impossiblePublication = new TrafficCaptureService.StatsSnapshot
        {
            EnrichmentCoverage = new(10, 11, 2, 1, 0, 4, 2, 1, 3)
        };
        Assert.Contains("WARNING: evidence coverage counters are negative or exceed", EnrichmentHealthPresentation.Build(impossiblePublication).Summary);

        var impossibleProcess = new TrafficCaptureService.StatsSnapshot
        {
            EnrichmentCoverage = new(100, 40, 20, 10, 5, 8, 9, 2, 7)
        };
        Assert.Contains("WARNING: evidence coverage counters are negative or exceed", EnrichmentHealthPresentation.Build(impossibleProcess).Summary);

        var empty = new TrafficCaptureService.StatsSnapshot
        {
            EnrichmentCoverage = new(0, 0, 0, 0, 0, 0, 0, 0, 0)
        };
        Assert.DoesNotContain("WARNING: evidence coverage counters", EnrichmentHealthPresentation.Build(empty).Summary);
    }


    [Theory]
    [InlineData(1, 0, 0, 0, 0, -1, 0)]
    [InlineData(1, 0, 0, 0, 0, 5, -1)]
    [InlineData(1, 0, 0, 0, 0, 5, 6)]
    [InlineData(1, -1, 0, 0, 0, 5, 5)]
    public void Invalid_Provider_Accounting_Does_Not_Publish_Latency_Average(
        long success, long unavailable, long failed, long timedOut, long cancelled,
        long elapsedMs, long maxElapsedMs)
    {
        var stats = new TrafficCaptureService.StatsSnapshot
        {
            EnrichmentProviders = new Dictionary<string, EnrichmentProviderSnapshot>
            {
                ["whois"] = new(success, unavailable, failed, timedOut, cancelled, 0, elapsedMs, maxElapsedMs)
            }
        };
        var display = EnrichmentHealthPresentation.Build(stats);
        var provider = display.Providers.Single(p => p.Provider == "whois");
        Assert.Equal("—", provider.Latency);
        Assert.Contains("WARNING: invalid provider outcome, cache-path or latency counters", display.Summary);
    }


    [Theory]
    [InlineData(1, 2, 0, 0)]
    [InlineData(-1, 0, 0, 0)]
    [InlineData(1, -1, 0, 0)]
    public void Worker_Invalid_Lifecycle_Does_Not_Fabricate_InFlight_Count(
        long started, long returned, long cancelled, long faulted)
    {
        var summary = EnrichmentHealthPresentation.WorkerSummary(
            new EnrichmentWorkerSnapshot(started, returned, cancelled, faulted, 0, 0, 0, 0, 0));
        Assert.Contains("in flight at snapshot: —;", summary);
        Assert.Contains("WARNING:", summary);
        Assert.Contains($"{returned} returned", summary);
    }

    [Fact]
    public void Worker_Valid_Lifecycle_Reports_Exact_InFlight_Count()
    {
        var summary = EnrichmentHealthPresentation.WorkerSummary(
            new EnrichmentWorkerSnapshot(5, 2, 1, 0, 0, 0, 0, 0, 0));
        Assert.Contains("in flight at snapshot: 2;", summary);
        Assert.DoesNotContain("WARNING: completed outcomes exceed started workers", summary);
    }

    [Fact]
    public void Worker_Completed_Exceeding_Started_Does_Not_Report_Elapsed_Mean()
    {
        // An impossible lifecycle denominator must not yield a plausible average.
        // Preserve the raw elapsed maximum and outcome counters for diagnostics.
        var summary = EnrichmentHealthPresentation.WorkerSummary(
            new EnrichmentWorkerSnapshot(1, 2, 0, 0, 0, 10, 10, 40, 30));
        Assert.Contains("WARNING: completed outcomes exceed started workers by 1", summary);
        Assert.Contains("worker elapsed mean/max ms (completed workers: 2): — / 30", summary);
        Assert.Contains("2 returned", summary);
    }

    [Fact]
    public void Worker_Negative_Outcome_Does_Not_Publish_Plausible_Duration_Means()
    {
        // A negative returned count can leave a positive derived completed total.
        // Neither queue wait nor elapsed averages should appear valid in that state.
        var summary = EnrichmentHealthPresentation.WorkerSummary(
            new EnrichmentWorkerSnapshot(3, -1, 2, 0, 0, 12, 8, 20, 10));
        Assert.Contains("in flight at snapshot: —;", summary);
        Assert.Contains("Queue wait mean/max ms (started workers: 3): — / 8", summary);
        Assert.Contains("worker elapsed mean/max ms (completed workers: 1): — / 10", summary);
        Assert.Contains("WARNING: invalid worker counters", summary);
    }

    [Theory]
    [InlineData(2, 2, 1, 100, 0, 0)]
    [InlineData(2, -1, 3, 100, 0, 0)]
    [InlineData(1, 1, 0, -1, 0, 0)]
    [InlineData(0, 0, 0, 10, 0, 0)]
    [InlineData(1, 1, 0, 10, 2, 1)]
    public void Native_Process_Invalid_Candidate_Accounting_Suppresses_Mean(
        long completed, long resolved, long unresolved, long elapsedTicks, long active, long peak)
    {
        var summary = EnrichmentHealthPresentation.NativeProcessSummary(new[]
        {
            new WindowsProcessResolver.ProcessLookupMetrics.Snapshot(
                completed, resolved, unresolved, elapsedTicks, active, peak),
            default(WindowsProcessResolver.ProcessLookupMetrics.Snapshot),
            default(WindowsProcessResolver.ProcessLookupMetrics.Snapshot),
            default(WindowsProcessResolver.ProcessLookupMetrics.Snapshot)
        });
        Assert.Contains("WARNING: native process candidate lookup accounting inconsistent", summary);
        Assert.Contains($"TCP/IPv4: {completed} completed, {resolved} resolved, {unresolved} unresolved, mean ms —", summary);
        Assert.Contains($"{active} active, {peak} peak active", summary);
    }

    [Fact]
    public void Native_Process_Active_Without_Completed_Is_Not_Invalid()
    {
        var summary = EnrichmentHealthPresentation.NativeProcessSummary(new[]
        {
            new WindowsProcessResolver.ProcessLookupMetrics.Snapshot(0, 0, 0, 0, 1, 1),
            default(WindowsProcessResolver.ProcessLookupMetrics.Snapshot),
            default(WindowsProcessResolver.ProcessLookupMetrics.Snapshot),
            default(WindowsProcessResolver.ProcessLookupMetrics.Snapshot)
        });
        Assert.Contains("TCP/IPv4: 0 completed, 0 resolved, 0 unresolved, mean ms —, 1 active, 1 peak active", summary);
        Assert.DoesNotContain("WARNING: native process candidate lookup accounting inconsistent", summary);
    }

}
