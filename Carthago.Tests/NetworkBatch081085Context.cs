// SPDX-License-Identifier: MIT
using System;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Tests;

internal static class NetworkBatch081085Context
{
    internal static readonly DateTime T0 = DateTime.UtcNow.AddMinutes(-15);

    internal static RuleEvaluationContext AsRep(int sec, string? service = "AS_REP_NO_PREAUTH",
        string kdc = "10.81.1.10", string client = "10.81.0.10", string protocol = "UDP",
        Guid? id = null, string? info = null)
    {
        var r = new TrafficRecord {
            Id = id ?? Guid.NewGuid(), Source = kdc, Destination = client,
            IpVersion = 4, Protocol = protocol, IsUdp = protocol == "UDP",
            IsTcp = protocol == "TCP", TcpFlags = protocol == "TCP" ? (ushort)0x18 : null,
            SourcePort = 88, DestinationPort = 52000,
            ApplicationProtocol = "KERBEROS", ApplicationService = service, Info = info
        };
        return new RuleEvaluationContext(r, Sensitivity.Balanced, T0.AddSeconds(sec));
    }

    internal static RuleEvaluationContext Ntlm(int sec, string? service = "RELAY_CORROBORATED",
        string source = "10.82.0.10", string target = "10.82.1.10", int port = 445,
        Guid? id = null, string? info = null)
    {
        var r = new TrafficRecord {
            Id = id ?? Guid.NewGuid(), Source = source, Destination = target,
            IpVersion = 4, Protocol = "TCP", IsTcp = true, TcpFlags = 0x18,
            SourcePort = 52000, DestinationPort = port,
            ApplicationProtocol = "NTLM", ApplicationService = service, Info = info
        };
        return new RuleEvaluationContext(r, Sensitivity.Balanced, T0.AddSeconds(sec));
    }

    internal static RuleEvaluationContext NameService(int sec, string protocol = "LLMNR",
        string? service = "CONFLICTING_RESPONSE", string source = "10.83.0.10",
        string target = "10.83.0.20", Guid? id = null, string? info = null)
    {
        var port = protocol == "NBNS" ? 137 : 5355;
        var r = new TrafficRecord {
            Id = id ?? Guid.NewGuid(), Source = source, Destination = target,
            IpVersion = 4, Protocol = "UDP", IsUdp = true,
            SourcePort = port, DestinationPort = port,
            ApplicationProtocol = protocol, ApplicationService = service,
            DnsIsResponse = true, DnsQname = "printer.internal", DnsAnswers = "10.83.0.50",
            Info = info
        };
        return new RuleEvaluationContext(r, Sensitivity.Balanced, T0.AddSeconds(sec));
    }

    internal static RuleEvaluationContext Http(int sec, string uri = "/",
        string? headers = null, string? userAgent = null, string? info = null,
        Guid? id = null, string source = "10.84.0.10", string target = "10.84.1.10")
    {
        var r = new TrafficRecord {
            Id = id ?? Guid.NewGuid(), Source = source, Destination = target,
            IpVersion = 4, Protocol = "TCP", IsTcp = true, TcpFlags = 0x18,
            SourcePort = 52000, DestinationPort = 80, Length = 256,
            HttpMethod = "GET", HttpHost = "app.example.test", HttpUri = uri,
            HttpRequestHeaders = headers, HttpUserAgent = userAgent, Info = info
        };
        return new RuleEvaluationContext(r, Sensitivity.Balanced, T0.AddSeconds(sec));
    }
}
