// SPDX-License-Identifier: MIT
using System;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Tests;

internal static class Ipv6Batch066070Context
{
    internal static readonly DateTime T0 = DateTime.UtcNow.AddMinutes(-10);
    internal static RuleEvaluationContext Packet(int second, string source = "fe80::1",
        string destination = "ff02::1", int version = 6, string protocol = "ICMPv6",
        ushort? icmp = 0x8600, string? ttl = "255",
        string? mac = "00:11:22:33:44:55", string? info = null,
        string? application = null, int? sourcePort = null, int? destinationPort = null)
        => new(new TrafficRecord
        {
            Source = source, Destination = destination, IpVersion = version,
            Protocol = protocol, IcmpTypeCode = icmp, TTL = ttl, MacSource = mac,
            Info = info, ApplicationProtocol = application,
            SourcePort = sourcePort, DestinationPort = destinationPort
        }, Sensitivity.Balanced, T0.AddSeconds(second));

    internal static RuleEvaluationContext Country(int second, string? country,
        string source = "10.66.0.10", string destination = "8.8.8.8",
        string? whois = null, string? info = null)
        => new(new TrafficRecord
        {
            Source = source, Destination = destination, IpVersion = 4,
            Protocol = "TCP", TcpFlags = 2, SourcePort = 50000, DestinationPort = 443,
            DstCountryIso2 = country, WhoisCountry = whois, Info = info
        }, Sensitivity.Balanced, T0.AddSeconds(second));
}
