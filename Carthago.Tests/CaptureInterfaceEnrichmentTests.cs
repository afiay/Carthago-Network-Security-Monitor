using System;
using System.Net.NetworkInformation;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Tests;

public sealed class CaptureInterfaceEnrichmentTests
{
    private const string Id = "12345678-1234-1234-1234-123456789abc";
    private const string Device = @"\Device\NPF_{12345678-1234-1234-1234-123456789abc}";

    [Fact]
    public void Guid_Match_Provides_Adapter_Context_Without_Changing_Process_Or_Remote_Vpn()
    {
        var context = CaptureInterfaceEnrichment.Resolve(Device, "Generic", new[]
        {
            new CaptureInterfaceDescriptor(Id, "My tunnel", "WireGuard Tunnel", NetworkInterfaceType.Tunnel)
        });
        var record = new TrafficRecord { ProcessName = "chrome", ProcessId = 42, IsVpn = false };
        CaptureInterfaceEnrichment.Apply(record, context);
        Assert.Equal("Npcap", record.CaptureBackend);
        Assert.Equal(Id, record.CaptureInterfaceId);
        Assert.Equal("My tunnel", record.CaptureInterfaceName);
        Assert.Equal("WireGuard", record.CaptureTunnelHint);
        Assert.Equal("WindowsInterfaceGuid", record.CaptureInterfaceEvidence);
        Assert.Equal("chrome", record.ProcessName);
        Assert.Equal(42, record.ProcessId);
        Assert.False(record.IsVpn);
    }

    [Fact]
    public void Unmatched_Description_Does_Not_Assert_Tunnel_Identity()
    {
        var context = CaptureInterfaceEnrichment.Resolve(Device, "WireGuard Tunnel", Array.Empty<CaptureInterfaceDescriptor>());
        Assert.Equal("Unresolved", context.Evidence);
        Assert.Null(context.Name);
        Assert.Null(context.TunnelHint);
    }

    [Fact]
    public void Etw_Does_Not_Invent_A_Capture_Interface()
    {
        var record = new TrafficRecord();
        CaptureInterfaceEnrichment.Apply(record, CaptureInterfaceContext.Etw);
        Assert.Equal("ETW", record.CaptureBackend);
        Assert.Equal("InterfaceNotProvided", record.CaptureInterfaceEvidence);
        Assert.Null(record.CaptureInterfaceId);
        Assert.Null(record.CaptureTunnelHint);
    }

    [Fact]
    public void Loopback_Uses_Explicit_Npcap_Identifier()
    {
        var context = CaptureInterfaceEnrichment.Resolve(@"\Device\NPF_Loopback", null, Array.Empty<CaptureInterfaceDescriptor>());
        Assert.Equal("Loopback", context.InterfaceType);
        Assert.Equal("NpcapLoopbackDevice", context.Evidence);
        Assert.Null(context.TunnelHint);
    }

    [Theory]
    [InlineData("Wintun Userspace Tunnel", NetworkInterfaceType.Ethernet, "Wintun")]
    [InlineData("TAP-Windows Adapter V9", NetworkInterfaceType.Ethernet, "OpenVPNOrTap")]
    [InlineData("Other", NetworkInterfaceType.Tunnel, "GenericTunnel")]
    [InlineData("Other", NetworkInterfaceType.Ppp, "PPP")]
    [InlineData("Physical Ethernet", NetworkInterfaceType.Ethernet, null)]
    public void Tunnel_Hints_Are_Conservative(string description, NetworkInterfaceType type, string? expected)
        => Assert.Equal(expected, CaptureInterfaceEnrichment.TunnelHint(description, type));
}
