// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.NetworkInformation;
using Carthago.Models;

namespace Carthago.Services;

internal sealed record CaptureInterfaceContext(string Backend, string? Id, string? Name,
    string? InterfaceType, string? TunnelHint, string Evidence)
{
    internal static readonly CaptureInterfaceContext Etw = new("ETW", null, null, null, null, "InterfaceNotProvided");
    internal static readonly CaptureInterfaceContext UnknownNpcap = new("Npcap", null, null, null, null, "Unresolved");
}

internal sealed record CaptureInterfaceDescriptor(string Id, string Name, string Description, NetworkInterfaceType Type);

internal static class CaptureInterfaceEnrichment
{
    internal static CaptureInterfaceContext Resolve(string? deviceName, string? description)
    {
        try
        {
            var adapters = NetworkInterface.GetAllNetworkInterfaces().Select(nic =>
                new CaptureInterfaceDescriptor(nic.Id, nic.Name, nic.Description, nic.NetworkInterfaceType));
            return Resolve(deviceName, description, adapters);
        }
        catch { return Resolve(deviceName, description, Array.Empty<CaptureInterfaceDescriptor>()); }
    }

    internal static CaptureInterfaceContext Resolve(string? deviceName, string? description,
        IEnumerable<CaptureInterfaceDescriptor> adapters)
    {
        var guid = CaptureDeviceLabelFormatter.ParseDeviceGuid(deviceName);
        if (guid.HasValue)
        {
            foreach (var adapter in adapters)
            {
                if (!Guid.TryParse(adapter.Id, out var id) || id != guid.Value) continue;
                return new("Npcap", adapter.Id, adapter.Name, adapter.Type.ToString(),
                    TunnelHint(adapter.Description, adapter.Type), "WindowsInterfaceGuid");
            }
        }

        if (string.Equals(deviceName, @"\Device\NPF_Loopback", StringComparison.OrdinalIgnoreCase)
            || string.Equals(deviceName, "NPF_Loopback", StringComparison.OrdinalIgnoreCase))
            return new("Npcap", deviceName, "Loopback", "Loopback", null, "NpcapLoopbackDevice");

        // A description without a GUID match is not verified Windows identity.
        return new("Npcap", deviceName, null, null, null, "Unresolved");
    }

    internal static string? TunnelHint(string? description, NetworkInterfaceType type)
    {
        // Driver description is a hint, not proof that any specific flow is tunneled.
        if (description?.Contains("WireGuard", StringComparison.OrdinalIgnoreCase) == true)
            return "WireGuard";
        if (description?.Contains("Wintun", StringComparison.OrdinalIgnoreCase) == true)
            return "Wintun";
        if (description?.Contains("OpenVPN", StringComparison.OrdinalIgnoreCase) == true
            || description?.Contains("TAP-Windows", StringComparison.OrdinalIgnoreCase) == true)
            return "OpenVPNOrTap";
        if (type == NetworkInterfaceType.Tunnel) return "GenericTunnel";
        if (type == NetworkInterfaceType.Ppp) return "PPP";
        return null;
    }

    internal static void Apply(TrafficRecord record, CaptureInterfaceContext context)
    {
        record.CaptureBackend = context.Backend;
        record.CaptureInterfaceId = context.Id;
        record.CaptureInterfaceName = context.Name;
        record.CaptureInterfaceType = context.InterfaceType;
        record.CaptureTunnelHint = context.TunnelHint;
        record.CaptureInterfaceEvidence = context.Evidence;
    }
}
