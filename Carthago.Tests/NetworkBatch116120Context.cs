// SPDX-License-Identifier: MIT
using System;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Tests;

// Deliberately isolated test identities: no live traffic, secrets or holdout inputs.
internal static class NetworkBatch116120Context
{
    private static readonly DateTime Origin = DateTime.UtcNow.AddMinutes(-40);

    internal static string Source()
    {
        var bytes = Guid.NewGuid().ToByteArray();
        return $"10.116.{bytes[0]}.{Math.Max(1, (int)bytes[1])}";
    }

    internal static RuleEvaluationContext Context(TrafficRecord record, int seconds = 0)
        => new(record, Sensitivity.Balanced, Origin.AddSeconds(seconds));

    internal static TrafficRecord Ssdp(string source, string destination = "198.51.100.40")
        => new()
        {
            Source = source, Destination = destination, IpVersion = 4,
            Protocol = "UDP", ApplicationProtocol = "UDP", ApplicationService = "SSDP",
            IsUdp = true, IsTcp = false, SourcePort = 55000, DestinationPort = 1900,
            Length = 400, L4Len = 360, ProcessName = "svchost.exe",
            Info = "M-SEARCH * HTTP/1.1 ssdp:discover"
        };

    internal static TrafficRecord Telnet(string source, string destination = "10.40.1.60")
        => new()
        {
            Source = source, Destination = destination, IpVersion = 4,
            Protocol = "TCP", ApplicationProtocol = "TCP", ApplicationService = "Telnet",
            IsTcp = true, IsUdp = false, SourcePort = 53000, DestinationPort = 23,
            Length = 200, L4Len = 150, ProcessName = "putty.exe",
            Info = "camera telnet login: admin password:"
        };

    internal static TrafficRecord Basic(string source)
        => new()
        {
            Source = source, Destination = "10.40.1.70", IpVersion = 4,
            Protocol = "HTTP", ApplicationProtocol = "HTTP", ApplicationService = "HTTP",
            IsTcp = true, SourcePort = 53000, DestinationPort = 8080,
            HttpHost = "camera.internal.local", HttpMethod = "GET", HttpUri = "/admin",
            HttpRequestHeaders = "Authorization: Basic YWRtaW46YWRtaW4=",
            ProcessName = "curl.exe", Info = "camera management request"
        };

    internal static TrafficRecord Camera(string source, string destination = "198.51.100.70")
        => new()
        {
            Source = source, Destination = destination, IpVersion = 4,
            Protocol = "TCP", ApplicationProtocol = "TCP", ApplicationService = "HTTPS",
            IsTcp = true, SourcePort = 53000, DestinationPort = 443,
            ProcessName = "camera.exe", Info = "camera onvif heartbeat", Length = 1200
        };

    internal static TrafficRecord Modbus(string source = "10.20.0.10", string destination = "10.30.0.20")
        => new()
        {
            Source = source, Destination = destination, IpVersion = 4,
            Protocol = "Modbus", ApplicationProtocol = "Modbus", ApplicationService = "Modbus",
            IsTcp = true, SourcePort = 53000, DestinationPort = 502,
            ProcessName = "plc.exe", Info = "modbus write multiple registers function 16"
        };
}
