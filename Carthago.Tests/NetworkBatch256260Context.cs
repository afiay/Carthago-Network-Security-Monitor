// SPDX-License-Identifier: MIT
using System;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Tests;
internal static class NetworkBatch256260Context
{
    internal static readonly DateTime Origin = new(2026, 10, 28, 12, 0, 0, DateTimeKind.Utc);
    internal static RuleEvaluationContext At(TrafficRecord r, double seconds = 0)
        => new(r, Sensitivity.Balanced, Origin.AddSeconds(seconds));

    internal static TrafficRecord Sample(int rule)
    {
        var r = new TrafficRecord {
            Id = Guid.NewGuid(), Source = "10.56.0.10", Destination = "10.56.0.20",
            SourcePort = 50000, DestinationPort = 8080, IpVersion = 4,
            Protocol = "TCP", IsTcp = true, ApplicationProtocol = "HTTP",
            HttpMethod = "PUT", HttpHost = "staging.internal.example",
            HttpUri = "/collect/source_backup.tar.gz",
            HttpRequestHeaders = "Host: staging.internal.example\nContent-Length: 4096",
            ProcessName = "curl.exe", Length = 512, L4Len = 400, Info = ""
        };
        if (rule == 257) {
            r.Source = "10.57.0.10"; r.Destination = "198.51.100.57";
            r.HttpHost = "upload.example"; r.HttpUri = "/api/upload";
            r.HttpRequestHeaders = "Host: upload.example\nContent-Length: 4096";
            r.ProcessName = "mimikatz.exe";
        }
        if (rule == 258 || rule == 259 || rule == 260) {
            r.Source = "10." + rule + ".0.10";
            r.Destination = "198.51.100." + (rule - 200);
            r.HttpMethod = null; r.HttpHost = null; r.HttpUri = null;
            r.HttpRequestHeaders = null; r.ApplicationProtocol = null;
            r.ProcessName = null; r.DestinationPort = 443;
        }
        if (rule == 258) {
            r.Protocol = "ICMP"; r.IsTcp = false;
            r.SourcePort = null; r.DestinationPort = null;
            r.IcmpTypeCode = 0x0303;
        }
        if (rule == 259) r.TcpFlags = 0x14;
        if (rule == 260) {
            r.TcpFlags = 0x02; r.Ja4T = "t13d_1_1_1";
        }
        return r;
    }
}
