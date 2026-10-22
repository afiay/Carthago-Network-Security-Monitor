using Carthago.Models;
using Carthago.Services;
using Carthago.Tests.TestInfrastructure;

namespace Carthago.Tests;

public sealed class PreferencesServiceTests
{
    [Fact]
    public void Update_Preserves_Unrelated_Settings()
    {
        using var isolation = new PreferencesIsolation();

        PreferencesService.Update(p =>
        {
            p.EnableFileSink = true;
            p.FileSinkDirectory = @"C:\logs\carthago";
            p.EnableWebhook = true;
            p.WebhookUrl = "https://example.test/webhook";
            p.EnableCountryBlocking = true;
            p.CountryBlockApplyTo = CountryBlockApplyTo.Destination;
            p.BlockedCountries = new HashSet<string>(new[] { "SE", "NO" }, StringComparer.OrdinalIgnoreCase);
        });

        PreferencesService.Update(p =>
        {
            p.EnableElastic = true;
            p.ElasticBaseUrl = "https://elastic.example";
            p.ElasticIndex = "detections";
        });

        PreferencesService.Load();
        var current = PreferencesService.Current;

        Assert.True(current.EnableFileSink);
        Assert.Equal(@"C:\logs\carthago", current.FileSinkDirectory);
        Assert.True(current.EnableWebhook);
        Assert.Equal("https://example.test/webhook", current.WebhookUrl);
        Assert.True(current.EnableCountryBlocking);
        Assert.Equal(CountryBlockApplyTo.Destination, current.CountryBlockApplyTo);
        Assert.Equal(new[] { "NO", "SE" }, current.BlockedCountries.OrderBy(x => x).ToArray());
        Assert.True(current.EnableElastic);
        Assert.Equal("https://elastic.example", current.ElasticBaseUrl);
        Assert.Equal("detections", current.ElasticIndex);
    }
}
