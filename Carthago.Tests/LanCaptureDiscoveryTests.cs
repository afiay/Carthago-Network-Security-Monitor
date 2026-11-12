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
        Assert.Equal("(ip host 192.168.1.42) or (arp host 192.168.1.42)",
            LanCaptureDiscovery.ComposeFilter(null, ip));
        Assert.Equal("(tcp or udp) and ((ip host 192.168.1.42) or (arp host 192.168.1.42))",
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
    public void LabelsDescribeDiscoveredPeersAsLocalVisibilityFilters()
    {
        var peer = new LanCapturePeer(IPAddress.Parse("192.168.1.42"), "02:11:22:33:44:55", null, "Cached");
        Assert.Equal("LAN host filter: 192.168.1.42 · Wi-Fi · visible-to-PC",
            LanCaptureDiscovery.FormatLabel(peer, "Wi-Fi"));
        Assert.Equal("LAN host filter: My-iPhone.local (192.168.1.42) · Wi-Fi · visible-to-PC",
            LanCaptureDiscovery.FormatLabel(peer with { HostName = "My-iPhone.local." }, "Wi-Fi"));
        Assert.Equal("LAN gateway filter: 192.168.1.42 · Wi-Fi · visible-to-PC",
            LanCaptureDiscovery.FormatLabel(peer, "Wi-Fi", isGateway: true));
        Assert.Null(LanCaptureDiscovery.NormalizeHostName("192.168.1.42"));
    }

    [Fact]
    public void VisibilityNoticeExplainsWhyAReachablePhoneCanHaveNoCapturedTraffic()
    {
        var notice = LanCaptureDiscovery.FormatVisibilityNotice(IPAddress.Parse("192.168.1.42"));

        Assert.Contains("192.168.1.42", notice);
        Assert.Contains("not a remote sensor", notice, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("phone-to-Internet", notice, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("gateway", notice, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("mirror", notice, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void KnownSleepingPhoneCanBeAddedOnlyInsideTheSelectedAdapterScope()
    {
        var adapter = new LocalLanInterface("Wi-Fi", IPAddress.Parse("192.168.1.153"),
            IPAddress.Parse("255.255.255.0"));

        Assert.True(LanCaptureDiscovery.TryParseManualTarget(
            "192.168.1.123", adapter, out var phone, out var error));
        Assert.Equal(IPAddress.Parse("192.168.1.123"), phone);
        Assert.Null(error);

        foreach (var invalid in new[]
                 {
                     "123", "192.168.2.123", "192.168.1.153",
                     "192.168.1.0", "192.168.1.255", "8.8.8.8", "fe80::123"
                 })
        {
            Assert.False(LanCaptureDiscovery.TryParseManualTarget(
                invalid, adapter, out _, out var invalidError));
            Assert.False(string.IsNullOrWhiteSpace(invalidError));
        }
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
    public void DirectArpEvidenceIsDistinguishedFromAStaleCachedNeighbor()
    {
        var result = new LocalLanScanResult(
            new Dictionary<string, string> {
                ["192.168.1.42"] = "02:11:22:33:44:55",
                ["192.168.1.43"] = "02:11:22:33:44:56"
            },
            Array.Empty<string>(), 254,
            new[] { "192.168.1.42" });

        var peers = LanCaptureDiscovery.BuildPeers(result);

        Assert.Contains(peers, peer => peer.Address.ToString() == "192.168.1.42" &&
            peer.Evidence == "Direct ARP response");
        Assert.Contains(peers, peer => peer.Address.ToString() == "192.168.1.43" &&
            peer.Evidence == "Neighbor cache (unconfirmed)");
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
