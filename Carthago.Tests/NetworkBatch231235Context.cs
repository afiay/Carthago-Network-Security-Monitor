// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Tests;
internal static class NetworkBatch231235Context
{
    private static int _source = 20;
    internal static readonly DateTime Origin = new(2026, 10, 28, 6, 30, 0, DateTimeKind.Utc);
    internal static RuleEvaluationContext At(TrafficRecord r, int seconds = 0)
        => new(r, Sensitivity.Balanced, Origin.AddSeconds(seconds));
    internal static TrafficRecord Sample(int rule)
    {
        var n = Interlocked.Increment(ref _source);
        var r = new TrafficRecord
        {
            Id = Guid.NewGuid(), Source = "10.231.0." + n,
            Destination = rule == 231 ? "224.0.1.187" : rule == 232 ? "224.0.0.251"
                : rule == 233 ? "10.233.1.20" : rule == 234 ? "198.51.100.234" : "239.255.255.250",
            SourcePort = 51000, DestinationPort = rule == 231 ? 5683 : rule == 232 ? 5353
                : rule == 233 ? 631 : rule == 234 ? 554 : 3702,
            Protocol = rule is 233 or 234 ? "TCP" : "UDP",
            IsTcp = rule is 233 or 234, IsUdp = rule is 231 or 232 or 235,
            ApplicationProtocol = rule == 231 ? "coap.discovery" : rule == 232 ? "mDNS"
                : rule == 233 ? "HTTP" : rule == 234 ? "rtsp.play" : "onvif.wsdiscovery.probe",
            ApplicationService = rule == 232 ? "mDNS" : null,
            Length = 300, L4Len = 200, Info = "",
            DnsQname = rule == 232 ? "_http._tcp.local" : null,
            DnsQtype = rule == 232 ? "PTR" : null,
            DnsIsResponse = false,
            HttpMethod = rule == 233 ? "GET" : null,
            HttpUri = rule == 233 ? "/admin/settings" : null,
            ProcessName = rule == 235 ? "python.exe" : null
        };
        return r;
    }
}
