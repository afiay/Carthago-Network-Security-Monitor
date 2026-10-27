// SPDX-License-Identifier: MIT
using System;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Tests;
internal static class NetworkBatch096100Context
{
    // Past UTC timestamps keep the existing ValidTime gate deterministic.
    internal static readonly DateTime Origin = DateTime.UtcNow.AddMinutes(-30);

    internal static RuleEvaluationContext Dns(
        int seconds, string qname, string source = "10.96.0.10",
        string destination = "8.8.8.8", string qtype = "A",
        bool response = false, string? answers = null, int? ttl = null)
    {
        var record = new TrafficRecord
        {
            Source = source, Destination = destination, IpVersion = 4,
            Protocol = "DNS", ApplicationProtocol = "DNS", ApplicationService = "DNS",
            IsUdp = true, SourcePort = 53000, DestinationPort = 53,
            DnsQname = qname, DnsQtype = qtype, DnsIsResponse = response,
            DnsAnswers = answers, DnsTtl = ttl, DnsRcode = "NOERROR",
            Length = 128
        };
        return new RuleEvaluationContext(record, Sensitivity.Balanced, Origin.AddSeconds(seconds));
    }

    internal static string UniqueRoot()
        => "batch" + Guid.NewGuid().ToString("N")[..10] + ".example";
}
