using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

public class WindowsLanArpResolverTests
{
    [Fact]
    public void NativeAddressPreservesNetworkOrderBytes()
    {
        var bytes = new byte[] { 192, 168, 1, 42 };
        Assert.Equal(bytes, BitConverter.GetBytes(WindowsLanArpResolver.ToNativeAddress(new IPAddress(bytes))));
        Assert.Throws<ArgumentException>(() => WindowsLanArpResolver.ToNativeAddress(IPAddress.IPv6Loopback));
    }

    [Fact]
    public void MacFormatterRejectsInvalidAndGroupAddresses()
    {
        Assert.Equal("02:11:22:33:44:55",
            WindowsLanArpResolver.FormatMac(new byte[] { 2, 17, 34, 51, 68, 85, 0, 0 }, 6));
        Assert.Null(WindowsLanArpResolver.FormatMac(new byte[8], 6));
        Assert.Null(WindowsLanArpResolver.FormatMac(new byte[] { 1, 17, 34, 51, 68, 85 }, 6));
        Assert.Null(WindowsLanArpResolver.FormatMac(new byte[8], 0));
    }

    [Fact]
    public async Task ResolvesMissingPeersUsingSelectedInterfaceWithoutProbingOtherSubnets()
    {
        var own = IPAddress.Parse("192.168.1.130");
        var adapters = new[] { new LocalLanInterface("Wi-Fi", own, IPAddress.Parse("255.255.255.128")) };
        var peer = IPAddress.Parse("192.168.1.131");
        var cached = IPAddress.Parse("192.168.1.132");
        var result = await WindowsLanArpResolver.ResolveAsync(adapters,
            new[] { own, peer, cached, IPAddress.Parse("192.168.1.128"), IPAddress.Parse("192.168.2.20") },
            new[] { cached.ToString() }, CancellationToken.None,
            (destination, source) =>
            {
                Assert.Equal(own, source);
                Assert.Equal(peer, destination);
                return "02:11:22:33:44:55";
            });
        Assert.Single(result);
        Assert.Equal("02:11:22:33:44:55", result[peer.ToString()]);
    }

    [Fact]
    public async Task NativeArpEvidenceMakesPeerSelectableWithoutIcmp()
    {
        var own = IPAddress.Parse("192.168.1.10");
        var peer = IPAddress.Parse("192.168.1.42");
        var adapters = new[] { new LocalLanInterface("Wi-Fi", own, IPAddress.Parse("255.255.255.0")) };
        var found = await WindowsLanArpResolver.ResolveAsync(adapters, new[] { peer },
            Array.Empty<string>(), CancellationToken.None, (_, _) => "02:11:22:33:44:55");
        var rows = LanCaptureDiscovery.BuildPeers(new LocalLanScanResult(found, Array.Empty<string>(), 1));
        Assert.Single(rows);
        Assert.Equal(peer, rows[0].Address);
    }

}
