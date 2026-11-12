using System;
using System.Linq;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Tests;

public sealed class ObservedAssetRegistryTests
{
    private static readonly DateTimeOffset Now = new(2026, 11, 13, 0, 0, 0, TimeSpan.Zero);
    private const string Adapter = "12345678-1234-1234-1234-123456789abc";
    private static TrafficRecord Arp(string source = "192.168.1.10", string mac = "02:11:22:33:44:55",
        string adapter = Adapter) => new()
    {
        Protocol = "ARP", Source = source, Destination = "192.168.1.99",
        MacSource = mac, MacDestination = "FF:FF:FF:FF:FF:FF",
        CaptureInterfaceId = adapter, CaptureInterfaceEvidence = "WindowsInterfaceGuid",
        ArpSenderMacMatchesFrame = true
    };
    private static TrafficRecord Local() => new()
    {
        IsTcp = true, TcpFlags = 0x12, Source = "192.168.1.10", Destination = "8.8.8.8",
        SourcePort = 443, DestinationPort = 50000, SrcIsLocalHost = true,
        MacDestination = "02:11:22:33:44:55", CaptureBackend = "ETW"
    };

    [Fact]
    public void Same_Scoped_Mac_Retains_Multiple_Claims_And_Times()
    {
        var registry = new ObservedAssetRegistry();
        registry.Observe(Arp(), Now);
        registry.Observe(Arp("192.168.1.20", "02-11-22-33-44-55"), Now.AddSeconds(2));
        var asset = Assert.Single(registry.Snapshot());
        Assert.Equal("192.168.1.10; 192.168.1.20", asset.Addresses);
        Assert.Equal(2L, asset.Observations);
        Assert.NotEqual(asset.FirstSeenUtc, asset.LastSeenUtc);
        Assert.DoesNotContain("192.168.1.99", asset.Addresses);
    }

    [Fact]
    public void Conflicting_Macs_And_Interfaces_Are_Not_Merged()
    {
        var registry = new ObservedAssetRegistry();
        registry.Observe(Arp(), Now);
        registry.Observe(Arp(mac: "02:11:22:33:44:66"), Now);
        registry.Observe(Arp(adapter: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"), Now);
        Assert.Equal(3, registry.Snapshot().Count);
    }

    [Fact]
    public void Invalid_Unscoped_Or_Inconsistent_Arp_Claims_Are_Rejected()
    {
        var registry = new ObservedAssetRegistry();
        registry.Observe(Arp(mac: "FF:FF:FF:FF:FF:FF"), Now);
        registry.Observe(Arp(source: "0.0.0.0"), Now);
        var unscoped = Arp(); unscoped.CaptureInterfaceEvidence = "Unresolved";
        registry.Observe(unscoped, Now);
        var mismatch = Arp(); mismatch.ArpSenderMacMatchesFrame = false;
        registry.Observe(mismatch, Now);
        Assert.Empty(registry.Snapshot());
    }

    [Fact]
    public void Local_Host_Uses_Only_Own_Ip_And_SynAck_Service()
    {
        var registry = new ObservedAssetRegistry();
        registry.Observe(Local(), Now);
        var row = Assert.Single(registry.Snapshot());
        Assert.Equal("Local host IP", row.Evidence);
        Assert.Equal("192.168.1.10", row.Addresses);
        Assert.Null(row.Mac);
        Assert.Equal("443", row.Services);
        var syn = Local(); syn.TcpFlags = 2; syn.SourcePort = 12345;
        registry.Observe(syn, Now);
        Assert.Equal("443", Assert.Single(registry.Snapshot()).Services);
    }

    [Fact]
    public void Routed_Remote_Ips_And_Ordinary_Private_Peers_Do_Not_Become_Mac_Assets()
    {
        var registry = new ObservedAssetRegistry();
        var record = Local(); record.SrcIsLocalHost = false;
        registry.Observe(record, Now);
        record.Source = "192.168.1.20";
        registry.Observe(record, Now);
        Assert.Empty(registry.Snapshot());
    }

    [Fact]
    public void Session_And_Capacity_Are_Bounded()
    {
        var registry = new ObservedAssetRegistry();
        for (int i = 0; i < 2100; i++)
            registry.Observe(Arp(mac: $"02:11:22:33:{i >> 8:X2}:{i & 255:X2}"), Now);
        Assert.Equal(2048, registry.Snapshot().Count);
        Assert.Empty(new ObservedAssetRegistry().Snapshot());
    }
}
