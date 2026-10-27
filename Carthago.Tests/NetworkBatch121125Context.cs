// SPDX-License-Identifier: MIT
using System;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Tests;

internal static class NetworkBatch121125Context
{
    private static readonly DateTime Origin = DateTime.UtcNow.AddMinutes(-10);

    internal static RuleEvaluationContext At(TrafficRecord r, int seconds = 0)
        => new(r, Sensitivity.Balanced, Origin.AddSeconds(seconds));

    internal static TrafficRecord Bacnet() => new()
    {
        Source = "10.121.1.10", Destination = "255.255.255.255",
        IpVersion = 4, Protocol = "BACnet", ApplicationProtocol = "BACnet",
        ApplicationService = "BACnet", IsUdp = true, SourcePort = 47808,
        DestinationPort = 47808, ProcessName = "python.exe", Info = "BACnet Who-Is request"
    };

    internal static TrafficRecord Coap() => new()
    {
        Source = "10.122.1.10", Destination = "198.51.100.122",
        IpVersion = 4, Protocol = "UDP", ApplicationProtocol = "CoAP",
        ApplicationService = "CoAP", IsUdp = true, SourcePort = 53000,
        DestinationPort = 5683, ProcessName = "sensor.exe", Info = "CoAP request"
    };

    internal static TrafficRecord Zigbee() => new()
    {
        Source = "10.122.1.11", Destination = "198.51.100.123",
        IpVersion = 4, Protocol = "TCP", ApplicationProtocol = "HTTPS",
        ApplicationService = "HTTPS", IsTcp = true, SourcePort = 53001,
        DestinationPort = 443, ProcessName = "gatewayd.exe", Info = "zigbee2mqtt gateway cloud sync"
    };

    internal static TrafficRecord Vpn() => new()
    {
        Source = "10.123.1.10", Destination = "198.51.100.124",
        IpVersion = 4, Protocol = "HTTPS", ApplicationProtocol = "HTTPS",
        ApplicationService = "HTTPS", IsTcp = true, SourcePort = 53000,
        DestinationPort = 443, HttpHost = "vpn.example.com", HttpMethod = "GET",
        HttpUri = "/remote/login", Info = "VPN portal login SAML"
    };

    internal static TrafficRecord Rdp() => new()
    {
        Source = "10.124.1.10", Destination = "198.51.100.124",
        IpVersion = 4, Protocol = "TCP", ApplicationProtocol = "TCP",
        ApplicationService = "RDP", IsTcp = true, SourcePort = 53000,
        DestinationPort = 3389, ProcessName = "mstsc.exe", Info = "RDP session"
    };

    internal static TrafficRecord Winrm() => new()
    {
        Source = "10.125.1.10", Destination = "198.51.100.125",
        IpVersion = 4, Protocol = "TCP", ApplicationProtocol = "TCP",
        ApplicationService = "WSMAN", IsTcp = true, SourcePort = 53000,
        DestinationPort = 5986, ProcessName = "pwsh.exe", Info = "WinRM remote session"
    };
}
