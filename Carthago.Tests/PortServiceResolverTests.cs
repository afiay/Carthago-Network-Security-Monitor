using Carthago.Services;

namespace Carthago.Tests;

public sealed class PortServiceResolverTests
{
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
