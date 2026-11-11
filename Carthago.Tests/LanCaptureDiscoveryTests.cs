using System;
using System.Collections.Generic;
using System.Net;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

public class LanCaptureDiscoveryTests
{
    [Fact]
    public void ExplicitHostScopeCombinesRatherThanReplacesConfiguredFilter()
    {
        var ip = IPAddress.Parse("192.168.1.42");
        Assert.Equal("ip host 192.168.1.42", LanCaptureDiscovery.ComposeFilter(null, ip));
        Assert.Equal("(tcp or udp) and (ip host 192.168.1.42)",
            LanCaptureDiscovery.ComposeFilter(" tcp or udp ", ip));
    }

    [Fact]
    public void AdapterOnlyCapturePreservesConfiguredFilter()
    {
        Assert.Equal("tcp port 443", LanCaptureDiscovery.ComposeFilter("tcp port 443", null));
        Assert.Equal("", LanCaptureDiscovery.ComposeFilter(null, null));
    }

    [Theory]
    [InlineData("8.8.8.8")]
    [InlineData("127.0.0.1")]
    [InlineData("fe80::12")]
    public void UnsupportedScopesCannotCreateCaptureFilter(string address)
        => Assert.Throws<ArgumentException>(() =>
            LanCaptureDiscovery.ComposeFilter(null, IPAddress.Parse(address)));

    [Fact]
    public void LabelsUseResolvedNameOrIpWithoutInventingIdentity()
    {
        var peer = new LanCapturePeer(IPAddress.Parse("192.168.1.42"), "02:11:22:33:44:55", null, "Cached");
        Assert.Equal("Npcap: LAN 192.168.1.42 via Wi-Fi", LanCaptureDiscovery.FormatLabel(peer, "Wi-Fi"));
        Assert.Equal("Npcap: LAN My-iPhone.local (192.168.1.42) via Wi-Fi",
            LanCaptureDiscovery.FormatLabel(peer with { HostName = "My-iPhone.local." }, "Wi-Fi"));
        Assert.Null(LanCaptureDiscovery.NormalizeHostName("192.168.1.42"));
    }

    [Fact]
    public void OnlyScopedNeighborEvidenceProducesSelectablePeers()
    {
        var result = new LocalLanScanResult(
            new Dictionary<string, string> {
                ["192.168.1.42"] = "02:11:22:33:44:55",
                ["192.168.1.43"] = "02:11:22:33:44:56",
                ["8.8.8.8"] = "02:11:22:33:44:57"
            },
            new[] { "192.168.1.42", "192.168.1.99" }, 254);
        var peers = LanCaptureDiscovery.BuildPeers(result);
        Assert.Equal(2, peers.Count);
        Assert.Contains(peers, p => p.Address.ToString() == "192.168.1.42" && p.Evidence.Contains("ICMP"));
        Assert.Contains(peers, p => p.Address.ToString() == "192.168.1.43" && p.Evidence.Contains("unconfirmed"));
        Assert.DoesNotContain(peers, p => p.Address.ToString() == "192.168.1.99");
    }

    [Fact]
    public void NpcapGuidCanBeUsedToFindTheWindowsInterface()
    {
        var expected = Guid.Parse("1aa3c21b-2840-45cc-b855-62ea63bf9282");
        Assert.Equal(expected, CaptureDeviceLabelFormatter.ParseDeviceGuid(
            @"\Device\NPF_{1aa3c21b-2840-45cc-b855-62ea63bf9282}"));
        Assert.Null(CaptureDeviceLabelFormatter.ParseDeviceGuid("NPF_Loopback"));
    }
}
