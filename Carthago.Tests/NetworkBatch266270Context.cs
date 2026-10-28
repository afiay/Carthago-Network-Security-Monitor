// SPDX-License-Identifier: MIT
using System;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Tests;
internal static class NetworkBatch266270Context
{
    internal static readonly DateTime Origin = new(2026, 10, 28, 15, 0, 0, DateTimeKind.Utc);
    internal static RuleEvaluationContext At(TrafficRecord r, double seconds = 0)
        => new(r, Sensitivity.Balanced, Origin.AddSeconds(seconds));
    internal static TrafficRecord Sample(int rule)
    {
        var r = new TrafficRecord {
            Id = Guid.NewGuid(), Source = "10.61.0.10", Destination = "198.51.100.61",
            IpVersion = 4, SourcePort = 50000, DestinationPort = 8080,
            Protocol = "TCP", IsTcp = true, ProcessId = 4100,
            ProcessName = "rarerunner.exe", Info = ""
        };
        if (rule == 267) r.ProcessName = "scvhost.exe";
        if (rule == 268) {
            r.ProcessName = "python.exe"; r.ApplicationProtocol = "HTTP";
            r.HttpMethod = "GET"; r.HttpHost = "telemetry.example.net"; r.HttpUri = "/health";
        }
        if (rule == 269) {
            r.Source = "8.8.8.8"; r.Destination = "10.61.0.10";
            r.IsTcp = false; r.IsUdp = true; r.Protocol = "UDP";
            r.SourcePort = 53; r.DestinationPort = 54000;
            r.ApplicationProtocol = "DNS"; r.DnsIsResponse = true;
            r.DnsQname = "definitionupdates.microsoft.com";
            r.DnsQtype = "A"; r.DnsRcode = "SERVFAIL";
            r.ProcessName = null; r.ProcessId = 0;
        }
        if (rule == 270) r.Info = "CarThago pipeline tampered, journal deleted";
        return r;
    }
    internal static TrafficRecord Copy(TrafficRecord r) => new() {
        Id = Guid.NewGuid(), Source = r.Source, Destination = r.Destination,
        IpVersion = r.IpVersion, SourcePort = r.SourcePort, DestinationPort = r.DestinationPort,
        Protocol = r.Protocol, IsTcp = r.IsTcp, IsUdp = r.IsUdp, IsQuic = r.IsQuic,
        ProcessName = r.ProcessName, ProcessId = r.ProcessId, Info = r.Info,
        ApplicationProtocol = r.ApplicationProtocol, ApplicationService = r.ApplicationService,
        HttpMethod = r.HttpMethod, HttpHost = r.HttpHost, HttpUri = r.HttpUri,
        TlsVersion = r.TlsVersion, Sni = r.Sni, DnsQname = r.DnsQname,
        DnsQtype = r.DnsQtype, DnsRcode = r.DnsRcode, DnsIsResponse = r.DnsIsResponse,
        IcmpTypeCode = r.IcmpTypeCode
    };
}
