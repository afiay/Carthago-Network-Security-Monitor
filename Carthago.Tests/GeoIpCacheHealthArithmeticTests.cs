using Carthago.Services.Geo;

namespace Carthago.Tests;

public sealed class GeoIpCacheHealthArithmeticTests
{
    [Fact]
    public void Cache_Requests_Use_Exact_Total_And_Saturate_Legacy_Int64()
    {
        var snapshot = new GeoIpService.CacheHealthSnapshot(
            long.MaxValue, long.MaxValue, 1, 0, 0, 0, 4096);

        Assert.Equal((decimal)long.MaxValue * 2 + 1, snapshot.RequestsExact);
        Assert.True(snapshot.RequestsOverflowed);
        Assert.Equal(long.MaxValue, snapshot.Requests);
    }

    [Fact]
    public void Cache_Requests_Preserve_Ordinary_Counts()
    {
        var snapshot = new GeoIpService.CacheHealthSnapshot(7, 3, 2, 0, 0, 4, 4096);

        Assert.Equal(12m, snapshot.RequestsExact);
        Assert.False(snapshot.RequestsOverflowed);
        Assert.Equal(12L, snapshot.Requests);
    }
    [Fact]
    public void Cache_Health_Json_Exports_Exact_Request_Total_And_Overflow_Indicator()
    {
        var snapshot = new GeoIpService.CacheHealthSnapshot(
            long.MaxValue, long.MaxValue, 1, 0, 0, 0, 4096);

        using var document = System.Text.Json.JsonDocument.Parse(
            System.Text.Json.JsonSerializer.Serialize(snapshot));
        var root = document.RootElement;

        Assert.Equal((decimal)long.MaxValue * 2 + 1,
            root.GetProperty("RequestsExact").GetDecimal());
        Assert.True(root.GetProperty("RequestsOverflowed").GetBoolean());
        Assert.Equal(long.MaxValue, root.GetProperty("Requests").GetInt64());
        Assert.Equal(long.MaxValue, root.GetProperty("PositiveHits").GetInt64());
        Assert.Equal(long.MaxValue, root.GetProperty("NegativeHits").GetInt64());
    }


    [Fact]
    public void Cache_Health_Json_Preserves_Ordinary_Request_Accounting()
    {
        var snapshot = new GeoIpService.CacheHealthSnapshot(7, 3, 2, 0, 0, 4, 4096);

        using var document = System.Text.Json.JsonDocument.Parse(
            System.Text.Json.JsonSerializer.Serialize(snapshot));
        var root = document.RootElement;

        Assert.Equal(12m, root.GetProperty("RequestsExact").GetDecimal());
        Assert.False(root.GetProperty("RequestsOverflowed").GetBoolean());
        Assert.Equal(12L, root.GetProperty("Requests").GetInt64());
        Assert.Equal(7L, root.GetProperty("PositiveHits").GetInt64());
        Assert.Equal(3L, root.GetProperty("NegativeHits").GetInt64());
        Assert.Equal(2L, root.GetProperty("Misses").GetInt64());
    }

    [Fact]
    public void Lookup_Attempts_Use_Exact_Total_And_Saturate_Legacy_Int64()
    {
        var snapshot = new GeoIpService.LookupHealthSnapshot(long.MaxValue, long.MaxValue, 1);

        Assert.Equal((decimal)long.MaxValue * 2 + 1, snapshot.AttemptsExact);
        Assert.True(snapshot.AttemptsOverflowed);
        Assert.Equal(long.MaxValue, snapshot.Attempts);
    }

    [Fact]
    public void Lookup_Attempts_Preserve_Ordinary_Counts_And_Json_Provenance()
    {
        var snapshot = new GeoIpService.LookupHealthSnapshot(7, 3, 2);

        Assert.Equal(12m, snapshot.AttemptsExact);
        Assert.False(snapshot.AttemptsOverflowed);
        Assert.Equal(12L, snapshot.Attempts);

        using var document = System.Text.Json.JsonDocument.Parse(
            System.Text.Json.JsonSerializer.Serialize(
                new GeoIpService.LookupHealthSnapshot(long.MaxValue, long.MaxValue, 1)));
        var root = document.RootElement;
        Assert.Equal((decimal)long.MaxValue * 2 + 1, root.GetProperty("AttemptsExact").GetDecimal());
        Assert.True(root.GetProperty("AttemptsOverflowed").GetBoolean());
        Assert.Equal(long.MaxValue, root.GetProperty("Attempts").GetInt64());
    }
}
