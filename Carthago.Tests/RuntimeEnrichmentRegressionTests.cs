using System;
using System.IO;
using System.Net;
using Carthago.Models;
using Carthago.Services;
using Carthago.Services.Geo;

namespace Carthago.Tests;

public sealed class RuntimeEnrichmentRegressionTests
{
    [Theory]
    [InlineData("TCP", true, false)]
    [InlineData("UDP", false, true)]
    public void Etw_Event_Record_Preserves_Event_Time_Without_Packet_Evidence(
        string protocol, bool tcp, bool udp)
    {
        var observed = new DateTime(2026, 1, 2, 3, 4, 5, DateTimeKind.Utc);
        var record = Carthago.Capture.EtwCapture.CreateEventRecord(
            protocol, "192.168.1.10", "8.8.8.8", 53000, 443, observed);
        Assert.Equal(observed.ToString("o"), record.Timestamp);
        Assert.Equal(protocol, record.Protocol);
        Assert.Equal(tcp, record.IsTcp);
        Assert.Equal(udp, record.IsUdp);
        Assert.Equal("192.168.1.10", record.Source);
        Assert.Equal("8.8.8.8", record.Destination);
        Assert.Equal(53000, record.SourcePort);
        Assert.Equal(443, record.DestinationPort);
        Assert.Equal("ETW", record.CaptureBackend);
        Assert.Equal("InterfaceNotProvided", record.CaptureInterfaceEvidence);
        Assert.Null(record.CaptureInterfaceId);
        Assert.Null(record.TcpFlags);
        Assert.Null(record.L4Len);
        Assert.Null(record.DnsCorrelationEvidence);
        Assert.Null(record.TlsCorrelationEvidence);
        Assert.Null(record.ProcessAttribution);
    }

    [Fact]
    public void Geo_Lookup_Health_Counts_Completed_Attempts_Independently()
    {
        var city = new GeoIpService.LookupHealthCounter();
        var asn = new GeoIpService.LookupHealthCounter();
        System.Threading.Tasks.Parallel.For(0, 1000, _ =>
        {
            city.Record(GeoIpService.LookupOutcome.Found);
            city.Record(GeoIpService.LookupOutcome.NotFound);
            city.Record(GeoIpService.LookupOutcome.Failed);
            asn.Record(GeoIpService.LookupOutcome.Found);
            asn.Record(GeoIpService.LookupOutcome.NotAttempted);
        });
        Assert.Equal(new GeoIpService.LookupHealthSnapshot(1000, 1000, 1000), city.Snapshot());
        Assert.Equal(3000L, city.Snapshot().Attempts);
        Assert.Equal(new GeoIpService.LookupHealthSnapshot(1000, 0, 0), asn.Snapshot());
        Assert.Equal(1000L, asn.Snapshot().Attempts);
    }

    [Theory]
    [InlineData("GeoLite2-City", true, true)]
    [InlineData("GeoIP2-City", true, true)]
    [InlineData("GeoLite2-ASN", false, true)]
    [InlineData("GeoIP2-ASN", false, true)]
    [InlineData("GeoLite2-City", false, false)]
    [InlineData("GeoLite2-ASN", true, false)]
    [InlineData("GeoLite2-Country", true, false)]
    [InlineData(null, false, false)]
    public void Geo_Database_Edition_Must_Match_Reader_Role(string? type, bool city, bool expected)
    {
        Assert.Equal(expected, GeoIpService.IsExpectedDatabaseType(type, city));
    }

    [Fact]
    public void Geo_Database_Status_Separates_Missing_And_Unreadable_Files()
    {
        var root = Path.Combine(Path.GetTempPath(), "carthago-geo-" + Guid.NewGuid().ToString("N"));
        try
        {
            Directory.CreateDirectory(Path.Combine(root, "Data"));
            using (var missing = new GeoIpService(root))
            {
                Assert.Equal(GeoIpService.DatabaseAvailability.Missing, missing.CityDatabaseStatus);
                Assert.Equal(GeoIpService.DatabaseAvailability.Missing, missing.AsnDatabaseStatus);
                Assert.Null(missing.Lookup("8.8.8.8"));
                Assert.Null(missing.Lookup("192.168.1.1"));
                Assert.Equal(0L, missing.CityLookupHealth.Attempts);
                Assert.Equal(0L, missing.AsnLookupHealth.Attempts);
                var missingOutcome = missing.LookupWithOutcomes("8.8.8.8");
                Assert.Null(missingOutcome.Info);
                Assert.Equal(GeoIpService.LookupOutcome.NotAttempted, missingOutcome.City);
                Assert.Equal(GeoIpService.LookupOutcome.NotAttempted, missingOutcome.Asn);
            }

            File.WriteAllText(Path.Combine(root, "Data", "GeoLite2-City.mmdb"), "not a database");
            using var invalid = new GeoIpService(root);
            Assert.Equal(GeoIpService.DatabaseAvailability.Unavailable, invalid.CityDatabaseStatus);
            Assert.Equal(GeoIpService.DatabaseAvailability.Missing, invalid.AsnDatabaseStatus);
            Assert.False(invalid.IsCityDbAvailable);
            Assert.False(invalid.IsAsnDbAvailable);
            Assert.Null(invalid.Lookup("8.8.8.8"));
            var outcome = invalid.LookupWithOutcomes("8.8.8.8");
            Assert.Equal(GeoIpService.LookupOutcome.NotAttempted, outcome.City);
            Assert.Equal(GeoIpService.LookupOutcome.NotAttempted, outcome.Asn);
        }
        finally { Directory.Delete(root, true); }
    }

    [Fact]
    public void WindowsProcessResolver_Accepts_Wildcard_Local_Bindings()
    {
        Assert.True(WindowsProcessResolver.AddressMatchesForTests("192.168.1.153", IPAddress.Any));
        Assert.True(WindowsProcessResolver.AddressMatchesForTests("2001:db8::1", IPAddress.IPv6Any));
        Assert.False(WindowsProcessResolver.AddressMatchesForTests(
            "192.168.1.153", IPAddress.Parse("192.168.1.200")));
    }

    [Fact]
    public void GeoEnrichment_Populates_Source_And_Destination_Record_Fields()
    {
        var record = new TrafficRecord();

        TrafficRecordGeoEnrichment.ApplySource(record, new GeoIpService.GeoInfo
        {
            CountryName = "Sweden",
            CountryIso2 = "SE",
            Latitude = 59.3293,
            Longitude = 18.0686
        });
        TrafficRecordGeoEnrichment.ApplyDestination(record, new GeoIpService.GeoInfo
        {
            CountryName = "United States",
            CountryIso2 = "US",
            Latitude = 37.751,
            Longitude = -97.822
        });

        Assert.Equal("Sweden", record.SrcCountry);
        Assert.Equal("SE", record.SrcCountryIso2);
        Assert.Equal(59.3293, record.SrcLat);
        Assert.Equal(18.0686, record.SrcLon);
        Assert.Equal("United States", record.DstCountry);
        Assert.Equal("US", record.DstCountryIso2);
        Assert.Equal(37.751, record.DstLat);
        Assert.Equal(-97.822, record.DstLon);
    }

    [Fact]
    public void GeoEnrichment_Preserves_Asn_Without_Coordinates()
    {
        var geo = GeoIpService.CreateResult(null, null, null, null, null, 64500, "Example Network");
        Assert.NotNull(geo);
        var record = new TrafficRecord();
        TrafficRecordGeoEnrichment.ApplySource(record, geo!);
        Assert.Equal(64500L, record.SrcAsn);
        Assert.Equal("Example Network", record.SrcAsnOrganization);
        Assert.Null(record.SrcLat);
        Assert.Null(record.SrcLon);
        Assert.Null(record.WhoisASN);
        Assert.Null(record.DstAsn);
    }

    [Fact]
    public void GeoEnrichment_Preserves_Country_And_City_Without_Coordinates()
    {
        var geo = GeoIpService.CreateResult("Sweden", "SE", "Stockholm", null, null, null, null);
        Assert.NotNull(geo);
        var record = new TrafficRecord();
        TrafficRecordGeoEnrichment.ApplyDestination(record, geo!);
        Assert.Equal("Stockholm", record.DstCity);
        Assert.Equal("Sweden", record.DstCountry);
        Assert.Equal("SE", record.DstCountryIso2);
        Assert.Null(record.DstLat);
        Assert.Null(record.DstLon);
        Assert.Null(record.SrcCity);
    }

    [Fact]
    public void GeoEnrichment_Rejects_Missing_Or_Invalid_Coordinates_Without_Fabricating_A_Point()
    {
        Assert.Null(GeoIpService.CreateResult(null, null, null, null, null, null, null));
        Assert.Null(GeoIpService.CreateResult(null, null, null, 59, null, null, null));
        var geo = GeoIpService.CreateResult("Sweden", "SE", null, 91, 18, null, null);
        Assert.NotNull(geo);
        Assert.Null(geo!.Latitude);
        Assert.Null(geo.Longitude);
        var zero = GeoIpService.CreateResult(null, null, null, 0, 0, null, null);
        Assert.NotNull(zero);
        Assert.Equal(0d, zero!.Latitude);
        Assert.Equal(0d, zero.Longitude);
    }

    [Fact]
    public void GeoEnrichment_Does_Not_Overwrite_Existing_Record_Values()
    {
        var record = new TrafficRecord
        {
            SrcAsn = 64501,
            SrcAsnOrganization = "Existing network",
            SrcCity = "Existing city",
            SrcCountry = "Existing",
            SrcCountryIso2 = "EX",
            SrcLat = 1,
            SrcLon = 2
        };

        TrafficRecordGeoEnrichment.ApplySource(record, new GeoIpService.GeoInfo
        {
            Asn = 64502,
            AsnOrganization = "Replacement network",
            CityName = "Replacement city",
            CountryName = "Replacement",
            CountryIso2 = "RP",
            Latitude = 3,
            Longitude = 4
        });

        Assert.Equal(64501L, record.SrcAsn);
        Assert.Equal("Existing network", record.SrcAsnOrganization);
        Assert.Equal("Existing city", record.SrcCity);
        Assert.Equal("Existing", record.SrcCountry);
        Assert.Equal("EX", record.SrcCountryIso2);
        Assert.Equal(1, record.SrcLat);
        Assert.Equal(2, record.SrcLon);
    }

    [Fact]
    public void Process_Observation_Age_Is_Bounded_Using_Monotonic_Time()
    {
        long start = System.Diagnostics.Stopwatch.Frequency * 10;
        long second = System.Diagnostics.Stopwatch.Frequency;
        Assert.True(TrafficCaptureService.IsProcessObservationFresh(start, start));
        Assert.True(TrafficCaptureService.IsProcessObservationFresh(start, start + second * 2));
        Assert.False(TrafficCaptureService.IsProcessObservationFresh(start, start + second * 3));
        Assert.False(TrafficCaptureService.IsProcessObservationFresh(start, start - 1));
    }

    [Fact]
    public void Enrichment_Run_Admission_Rejects_Stopped_And_Replaced_Sessions()
    {
        using var first = new System.Threading.CancellationTokenSource();
        using var second = new System.Threading.CancellationTokenSource();
        Assert.True(TrafficCaptureService.IsCurrentEnrichmentRun(first.Token, first.Token));
        Assert.False(TrafficCaptureService.IsCurrentEnrichmentRun(null, first.Token));
        Assert.False(TrafficCaptureService.IsCurrentEnrichmentRun(second.Token, first.Token));
        first.Cancel();
        Assert.False(TrafficCaptureService.IsCurrentEnrichmentRun(first.Token, first.Token));
        Assert.True(TrafficCaptureService.IsCurrentEnrichmentRun(second.Token, second.Token));
    }

    [Fact]
    public void Detached_Run_Is_Rejected_Before_Cancellation_Is_Signalled()
    {
        using var oldRun = new System.Threading.CancellationTokenSource();
        using var newRun = new System.Threading.CancellationTokenSource();
        // Stop detaches the run under the lifecycle lock before cancelling it.
        Assert.False(oldRun.IsCancellationRequested);
        Assert.False(TrafficCaptureService.IsCurrentEnrichmentRun(null, oldRun.Token));
        Assert.False(TrafficCaptureService.IsCurrentEnrichmentRun(newRun.Token, oldRun.Token));
        Assert.True(TrafficCaptureService.IsCurrentEnrichmentRun(newRun.Token, newRun.Token));
    }
    [Fact]
    public void Session_Health_Separates_Stopped_And_New_Tls_State_From_Checkpoints()
    {
        var registry = new ObservedAssetRegistry();
        var checkpoints = new CheckpointHealthSnapshot(3, 1, "test");
        var active = TrafficCaptureService.SnapshotSessionHealth(registry, new TlsConnectionEnrichment(), checkpoints);
        Assert.NotNull(active.Tls);
        Assert.Equal(0, active.Tls!.Value.Retained);
        var stopped = TrafficCaptureService.SnapshotSessionHealth(registry, null, checkpoints);
        Assert.Null(stopped.Tls);
        Assert.Equal(active.Storage, stopped.Storage);
        var next = TrafficCaptureService.SnapshotSessionHealth(new ObservedAssetRegistry(), new TlsConnectionEnrichment(), checkpoints);
        Assert.NotNull(next.Tls);
        Assert.Equal(0L, next.Tls!.Value.CapacityRejections);
        Assert.Equal(checkpoints, next.Storage.Checkpoints);
    }

    [Fact]
    public void Publication_Registry_Admission_Rejects_Detached_Work_Before_Cancellation()
    {
        using var oldRun = new System.Threading.CancellationTokenSource();
        using var newRun = new System.Threading.CancellationTokenSource();
        var registry = new ObservedAssetRegistry();
        var record = new TrafficRecord
        {
            Source = "192.168.1.10", Destination = "8.8.8.8",
            IsTcp = true, TcpFlags = 2, SourcePort = 50000, DestinationPort = 443,
            SrcIsLocalHost = true, DstIsLocalHost = false,
            CaptureInterfaceEvidence = "WindowsInterfaceGuid",
            CaptureInterfaceId = Guid.NewGuid().ToString("D")
        };
        var now = DateTimeOffset.UtcNow;
        Assert.True(TrafficCaptureService.IsCurrentEnrichmentRun(oldRun.Token, oldRun.Token));
        // Correlation may have started before detachment; final admission must recheck.
        Assert.False(TrafficCaptureService.TryObservePublishedAssets(null, oldRun.Token, registry, record, now));
        Assert.False(TrafficCaptureService.TryObservePublishedAssets(newRun.Token, oldRun.Token, registry, record, now));
        Assert.Empty(registry.Snapshot());
        Assert.Empty(registry.Communications.Snapshot());
        Assert.True(TrafficCaptureService.TryObservePublishedAssets(newRun.Token, newRun.Token, registry, record, now));
        Assert.Single(registry.Snapshot());
        Assert.Single(registry.Communications.Snapshot());
        newRun.Cancel();
        Assert.False(TrafficCaptureService.TryObservePublishedAssets(newRun.Token, newRun.Token, registry, record, now));
        Assert.Equal(1L, Assert.Single(registry.Snapshot()).Observations);
        Assert.Equal(1L, Assert.Single(registry.Communications.Snapshot()).Observations);
    }

    [Fact]
    public void Sealed_Session_Rejects_Delayed_Communication_Metadata()
    {
        var oldRegistry = new ObservedAssetRegistry();
        var newRegistry = new ObservedAssetRegistry();
        var record = new TrafficRecord
        {
            Source = "192.168.1.10", Destination = "8.8.8.8",
            IsTcp = true, TcpFlags = 2, SourcePort = 50000, DestinationPort = 443,
            SrcIsLocalHost = true, DstIsLocalHost = false,
            CaptureInterfaceEvidence = "WindowsInterfaceGuid",
            CaptureInterfaceId = Guid.NewGuid().ToString("D"),
            ProcessId = 123, ProcessName = "first", ProcessAttribution = "TcpSocketTable",
            DstAsn = 64500, DstCountryIso2 = "SE"
        };
        var now = DateTimeOffset.UtcNow;
        oldRegistry.Communications.Observe(record, now);
        oldRegistry.Communications.AddMetadata(record);
        oldRegistry.Seal();

        record.ProcessName = "late";
        record.DstAsn = 64501;
        record.DstCountryIso2 = "US";
        oldRegistry.Communications.AddMetadata(record);
        oldRegistry.Communications.Observe(record, now.AddSeconds(1));
        // Metadata alone must not create a row in the replacement session.
        newRegistry.Communications.AddMetadata(record);
        Assert.Empty(newRegistry.Communications.Snapshot());

        var frozen = Assert.Single(oldRegistry.Communications.Snapshot());
        Assert.Equal(1L, frozen.Observations);
        Assert.Equal(now, frozen.LastSeenUtc);
        Assert.Equal(new[] { "first" }, frozen.Processes);
        Assert.Equal(new[] { "64500" }, frozen.Asns);
        Assert.Equal(new[] { "SE" }, frozen.Countries);

        newRegistry.Communications.Observe(record, now.AddSeconds(1));
        newRegistry.Communications.AddMetadata(record);
        var fresh = Assert.Single(newRegistry.Communications.Snapshot());
        Assert.Equal(new[] { "late" }, fresh.Processes);
        Assert.Equal(new[] { "64501" }, fresh.Asns);
        Assert.Equal(new[] { "US" }, fresh.Countries);
    }
}
