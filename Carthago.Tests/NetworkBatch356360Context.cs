// SPDX-License-Identifier: MIT
// CANDIDATE — UNVERIFIED. Synthetic records do not establish field provenance.
using System;
using System.Reflection;
using System.Threading;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Tests;

internal static class NetworkBatch356360Context
{
    private static int _sequence;
    private static readonly DateTime Origin = new(2026, 10, 29, 0, 0, 0, DateTimeKind.Utc);

    internal static TrafficRecord Http(string host, string uri, string method = "GET", bool inbound = false)
    {
        var n = Interlocked.Increment(ref _sequence);
        return new TrafficRecord
        {
            Id = Guid.NewGuid(),
            Source = inbound ? "8.8.8.8" : $"10.61.{n / 200}.{n % 200 + 1}",
            Destination = inbound ? "10.61.0.10" : "8.8.8.8",
            IpVersion = 4, Protocol = "TCP", IsTcp = true, IsUdp = false,
            SourcePort = 50123, DestinationPort = 80,
            ApplicationProtocol = "HTTP", HttpMethod = method, HttpUri = uri,
            HttpHost = host, Info = ""
        };
    }

    internal static RuleEvaluationContext At(TrafficRecord record, int seconds = 0)
        => new(record, Sensitivity.Balanced, Origin.AddSeconds(seconds));

    // Only emulate an internal parser observation in synthetic unit tests.
    internal static void ParserFlag(TrafficRecord record, string name)
    {
        var property = typeof(TrafficRecord).GetProperty(name, BindingFlags.Instance | BindingFlags.Public)
            ?? throw new InvalidOperationException("Missing parser flag: " + name);
        var setter = property.GetSetMethod(nonPublic: true)
            ?? throw new InvalidOperationException("Missing internal setter: " + name);
        setter.Invoke(record, new object[] { true });
    }
}
