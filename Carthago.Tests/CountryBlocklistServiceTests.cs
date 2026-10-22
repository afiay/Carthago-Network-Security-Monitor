using Carthago.Services;
using Carthago.Tests.TestInfrastructure;

namespace Carthago.Tests;

public sealed class CountryBlocklistServiceTests
{
    [Fact]
    public void Add_Remove_And_Set_Persist_Blocklist()
    {
        using var isolation = new PreferencesIsolation();
        var service = new CountryBlocklistService();

        service.Set(new[] { "se", "US", "se" });
        PreferencesService.Load();
        Assert.Equal(new[] { "SE", "US" }, PreferencesService.Current.BlockedCountries.OrderBy(x => x).ToArray());

        service.Add("no");
        PreferencesService.Load();
        Assert.Equal(new[] { "NO", "SE", "US" }, PreferencesService.Current.BlockedCountries.OrderBy(x => x).ToArray());

        service.Remove("us");
        PreferencesService.Load();

        var current = PreferencesService.Current;
        Assert.Equal(new[] { "NO", "SE" }, current.BlockedCountries.OrderBy(x => x).ToArray());
        Assert.True(service.IsBlockedIso2("se"));
        Assert.False(service.IsBlockedIso2("us"));
    }
}
