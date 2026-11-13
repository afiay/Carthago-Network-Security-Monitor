using System;
using System.IO;
using System.Net;
using Carthago.Models;
using Carthago.Services;
using Carthago.Services.Geo;

namespace Carthago.Tests;

public sealed class RuntimeEnrichmentRegressionTests
{
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
}
