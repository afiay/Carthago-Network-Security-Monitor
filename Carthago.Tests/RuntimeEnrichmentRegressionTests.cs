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
    public void GeoEnrichment_Does_Not_Overwrite_Existing_Record_Values()
    {
        var record = new TrafficRecord
        {
            SrcCountry = "Existing",
            SrcCountryIso2 = "EX",
            SrcLat = 1,
            SrcLon = 2
        };

        TrafficRecordGeoEnrichment.ApplySource(record, new GeoIpService.GeoInfo
        {
            CountryName = "Replacement",
            CountryIso2 = "RP",
            Latitude = 3,
            Longitude = 4
        });

        Assert.Equal("Existing", record.SrcCountry);
        Assert.Equal("EX", record.SrcCountryIso2);
        Assert.Equal(1, record.SrcLat);
        Assert.Equal(2, record.SrcLon);
    }
}
