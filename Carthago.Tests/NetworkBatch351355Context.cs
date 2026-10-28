// SPDX-License-Identifier: MIT
// CANDIDATE — UNVERIFIED. Synthetic unit contexts are not live capture provenance.
using System;
using System.Reflection;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Tests;

internal static class NetworkBatch351355Context
{
    private static readonly DateTime Origin = new(2026, 10, 29, 0, 0, 0, DateTimeKind.Utc);

    internal static TrafficRecord Http() => new()
    {
        Id = Guid.NewGuid(), Source = "10.61.0.10", Destination = "8.8.8.8",
        IpVersion = 4, Protocol = "TCP", IsTcp = true, IsUdp = false,
        SourcePort = 51234, DestinationPort = 80,
        ApplicationProtocol = "HTTP", HttpMethod = "GET",
        HttpUri = "/repos/example", HttpHost = "api.github.com", Info = ""
    };

    internal static TrafficRecord Ntlm()
    {
        var record = Http();
        record.HttpHost = null; record.HttpMethod = null; record.HttpUri = null;
        record.ApplicationProtocol = "NTLM"; record.ApplicationService = "SMB";
        record.DestinationPort = 445; record.Info = "NTLM challenge response";
        return record;
    }

    internal static TrafficRecord NameResolution()
    {
        var record = Ntlm();
        record.Protocol = "UDP"; record.IsTcp = false; record.IsUdp = true;
        record.ApplicationProtocol = "LLMNR"; record.ApplicationService = "LLMNR";
        record.DestinationPort = 5355; record.ProcessName = "/opt/Responder.py";
        record.Info = "LLMNR name query poisoning";
        return record;
    }

    internal static TrafficRecord Jenkins()
    {
        var record = Http();
        record.Source = "8.8.8.8"; record.Destination = "10.61.0.10";
        record.HttpHost = "jenkins.internal"; record.HttpUri = "/script";
        record.Info = "Jenkins script console probe";
        return record;
    }

    internal static RuleEvaluationContext At(TrafficRecord record, int seconds = 0)
        => new(record, Sensitivity.Balanced, Origin.AddSeconds(seconds));

    // Tests only: emulate the internal result of an HTTP payload parser.
    // This is NOT evidence that PacketHandler observed a real token.
    internal static void SyntheticParserFlag(TrafficRecord record, string propertyName)
    {
        var property = typeof(TrafficRecord).GetProperty(propertyName, BindingFlags.Instance | BindingFlags.Public)
            ?? throw new InvalidOperationException("Missing parser-owned observation flag: " + propertyName);
        var setter = property.GetSetMethod(nonPublic: true)
            ?? throw new InvalidOperationException("Missing parser-owned flag setter: " + propertyName);
        setter.Invoke(record, new object[] { true });
    }
}
