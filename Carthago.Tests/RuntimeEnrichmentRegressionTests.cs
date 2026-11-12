using System.Net;
using Carthago.Models;
using Carthago.Services;
using Carthago.Services.Geo;

namespace Carthago.Tests;

public sealed class RuntimeEnrichmentRegressionTests
{
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
}
