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
}
