using Carthago.Services;

namespace Carthago.Tests;

public sealed class PortServiceResolverTests
{
    [Fact]
    public async Task InitializeAsync_Loads_Bundled_Iana_Registry_Without_Requiring_Refresh()
    {
        await PortServiceResolver.InitializeAsync();

        Assert.True(PortServiceResolver.TryGetServiceInfo(21, "TCP", out var info));
        Assert.Equal("ftp", info.Name);
        Assert.StartsWith("IANA", info.Source);
    }

    [Fact]
    public void Mutable_Port_Data_Lives_Under_Per_User_LocalAppData()
    {
        string expected = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
            "Carthago", "Data", "IANA");

        Assert.Equal(
            Path.GetFullPath(expected),
            Path.GetFullPath(PortServiceResolver.WritableDataDirectoryForTests));
        Assert.Equal(
            Path.Combine(AppContext.BaseDirectory, "service-names-port-numbers.csv"),
            PortServiceResolver.BundledCsvPathForTests);
    }

    [Fact]
    public void TryGetServiceInfo_Uses_Deterministic_Fallback_For_Unknown_Port()
    {
        var resolved = PortServiceResolver.TryGetServiceInfo(65000, "UDP", out var info);

        Assert.True(resolved);
        Assert.Equal("ephemeral/dynamic", info.Name);
        Assert.Equal("Heuristic", info.Source);
        Assert.Equal("UDP", info.Protocol);
    }
}
