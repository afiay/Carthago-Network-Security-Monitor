// SPDX-License-Identifier: MIT
using System;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Tests;

// Static test fixtures only; these do not claim live packet or independent PCAP provenance.
internal static class NetworkBatch141145Context
{
    internal static readonly DateTime Origin = new(2026, 10, 27, 12, 0, 0, DateTimeKind.Utc);
    internal static readonly DateTime Issued = new(2026, 10, 1, 0, 0, 0, DateTimeKind.Utc);
    internal static readonly DateTime Expires = new(2026, 10, 12, 0, 0, 0, DateTimeKind.Utc);

    internal static RuleEvaluationContext At(TrafficRecord record, int seconds = 0)
        => new(record, Sensitivity.Balanced, Origin.AddSeconds(seconds));

    internal static TrafficRecord Tls()
        => new()
        {
            Source = "10.141.0.10",
            Destination = "198.51.100.141",
            IpVersion = 4,
            SourcePort = 51414,
            DestinationPort = 443,
            Protocol = "TLS",
            ApplicationProtocol = "TLS",
            ApplicationService = "HTTPS",
            IsTcp = true,
            Sni = "edge.example.test",
            TlsVersion = "TLS 1.2",
            Ja4 = "ja4-unique-client",
            CertSubject = "CN=unrelated.other.test",
            CertValidFrom = Issued,
            CertValidTo = Expires,
            ProcessName = "sensor-agent.exe",
            Info = "typed handshake metadata"
        };

    internal static TrafficRecord Wildcard()
    {
        var record = Tls();
        record.DestinationPort = 5986;
        record.CertSubject = "CN=*.example.test";
        return record;
    }

    internal static TrafficRecord LongValidity()
    {
        var record = Tls();
        record.CertValidFrom = new DateTime(2020, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        record.CertValidTo = new DateTime(2030, 1, 1, 0, 0, 0, DateTimeKind.Utc);
        return record;
    }

    internal static void AsUdp(TrafficRecord record)
    {
        record.IsTcp = false;
        record.IsUdp = true;
        record.Protocol = "UDP";
    }
}
