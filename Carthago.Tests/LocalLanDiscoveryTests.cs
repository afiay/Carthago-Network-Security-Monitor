using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Carthago.Services;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public class LocalLanDiscoveryTests
{
    [Fact]
    public void TargetsRemainInsideActualSubnetAndExcludeOurOwnAddress()
    {
        var adapters = new[] { new LocalLanInterface(
            "Wi-Fi", IPAddress.Parse("192.168.1.130"), IPAddress.Parse("255.255.255.128")) };
        var peers = LocalLanDiscovery.PlanProbeTargets(adapters);
        Assert.Equal(125, peers.Count); // .129-.254 except .130
        Assert.DoesNotContain(IPAddress.Parse("192.168.1.128"), peers); // network
        Assert.DoesNotContain(IPAddress.Parse("192.168.1.255"), peers); // broadcast
        Assert.DoesNotContain(IPAddress.Parse("192.168.1.130"), peers); // own IP
        Assert.DoesNotContain(IPAddress.Parse("192.168.1.120"), peers); // other subnet
        Assert.Contains(IPAddress.Parse("192.168.1.129"), peers);
        Assert.Contains(IPAddress.Parse("192.168.1.253"), peers);
    }

    [Fact]
    public void SubnetNetworkAndBroadcastAreNotProbedOnNarrowSubnets()
    {
        var quarterSubnet = new[] { new LocalLanInterface(
            "Wi-Fi", IPAddress.Parse("192.168.1.166"), IPAddress.Parse("255.255.255.192")) };
        var quarterPeers = LocalLanDiscovery.PlanProbeTargets(quarterSubnet);
        Assert.Equal(61, quarterPeers.Count); // .129-.190, excluding .166
        Assert.DoesNotContain(IPAddress.Parse("192.168.1.128"), quarterPeers);
        Assert.DoesNotContain(IPAddress.Parse("192.168.1.191"), quarterPeers);
        Assert.DoesNotContain(IPAddress.Parse("192.168.1.166"), quarterPeers);
        Assert.Contains(IPAddress.Parse("192.168.1.190"), quarterPeers);

        var tinySubnet = new[] { new LocalLanInterface(
            "Ethernet", IPAddress.Parse("192.168.1.45"), IPAddress.Parse("255.255.255.252")) };
        var tinyPeers = LocalLanDiscovery.PlanProbeTargets(tinySubnet);
        Assert.Single(tinyPeers);
        Assert.Equal(IPAddress.Parse("192.168.1.46"), tinyPeers[0]);
    }

    [Fact]
    public void BroadPrivateSubnetIsLimitedToCurrent24AndMaximum()
    {
        var adapters = new[] { new LocalLanInterface(
            "Wi-Fi", IPAddress.Parse("10.22.33.4"), IPAddress.Parse("255.255.0.0")) };
        var peers = LocalLanDiscovery.PlanProbeTargets(adapters, 40);
        Assert.Equal(40, peers.Count);
        Assert.All(peers, ip => Assert.StartsWith("10.22.33.", ip.ToString()));
        Assert.DoesNotContain(IPAddress.Parse("10.22.33.4"), peers);
    }

    [Fact]
    public void PublicOrLoopbackInterfacesAreNotProbed()
    {
        var adapters = new[] {
            new LocalLanInterface("Public", IPAddress.Parse("8.8.8.8"), IPAddress.Parse("255.255.255.0")),
            new LocalLanInterface("Loop", IPAddress.Parse("127.0.0.1"), IPAddress.Parse("255.0.0.0"))
        };
        Assert.Empty(LocalLanDiscovery.PlanProbeTargets(adapters));
    }

    [Fact]
    public void ArpParserIgnoresMulticastAndBroadcastEntries()
    {
        const string sample = "  192.168.1.42   02-22-33-44-55-66 dynamic\n" +
                              "  224.0.0.22    01-00-5e-00-00-16 static\n" +
                              "  192.168.1.255 ff-ff-ff-ff-ff-ff static\n";
        var macs = LocalLanDiscovery.ParseArpOutput(sample);
        Assert.Single(macs);
        Assert.Equal("02:22:33:44:55:66", macs["192.168.1.42"]);
    }

    [Fact]
    public void NeighborCacheAloneMustNotClaimDeviceIsOnline()
    {
        var rows = LocalLanDiscovery.Merge(Array.Empty<TrafficRecord>(),
            new Dictionary<string, string> { ["192.168.1.42"] = "02:22:33:44:55:66" },
            Array.Empty<string>());
        Assert.Single(rows);
        Assert.Equal("Cached neighbor (unconfirmed)", rows[0].State);
    }

    [Fact]
    public void RespondingDeviceAndObservedTrafficMergeWithoutDuplicates()
    {
        var traffic = new[] { new TrafficRecord
        {
            Source = "192.168.1.42",
            Destination = "8.8.8.8",
            MacSource = "02:22:33:44:55:66"
        } };
        var rows = LocalLanDiscovery.Merge(traffic,
            new Dictionary<string, string> { ["192.168.1.42"] = "02:22:33:44:55:66" },
            new[] { "192.168.1.42" });
        Assert.Single(rows);
        Assert.Equal("Responded to ICMP", rows[0].State);
        Assert.Contains("Captured packets", rows[0].Evidence);
        Assert.Contains("Windows neighbor cache", rows[0].Evidence);
    }

    [Fact]
    public void LocalIPv6TrafficIsRecognizedWithoutInventingScanResults()
    {
        var traffic = new[] { new TrafficRecord { Source = "fe80::abc", Destination = "fd00::cafe" } };
        var rows = LocalLanDiscovery.Merge(traffic, null, null);
        Assert.Equal(2, rows.Count);
        Assert.All(rows, row => Assert.Equal("Traffic observed", row.State));
    }

    [Fact]
    public void NoInferenceFromPublicTrafficOrEmptyInputs()
    {
        var traffic = new[] { new TrafficRecord { Source = "8.8.8.8", Destination = "1.1.1.1" } };
        Assert.Empty(LocalLanDiscovery.Merge(traffic, null, null));
        Assert.Throws<ArgumentOutOfRangeException>(() =>
            LocalLanDiscovery.PlanProbeTargets(Array.Empty<LocalLanInterface>(), 0));
    }
}
