// SPDX-License-Identifier: MIT
// CANDIDATE — UNVERIFIED. Synthetic parser flags are not independent captures.
using System;
using System.Reflection;
using System.Threading;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Tests;

internal static class NetworkBatch361370Context
{
    private static int _sequence;
    private static readonly DateTime Epoch = new(2026, 10, 30, 0, 0, 0, DateTimeKind.Utc);

    internal static TrafficRecord Http(string host, string uri, string method = "GET")
    {
        var n = Interlocked.Increment(ref _sequence);
        return new TrafficRecord
        {
            Id = Guid.NewGuid(),
            Source = $"10.91.{n / 200}.{n % 200 + 1}",
            Destination = "8.8.8.8",
            IpVersion = 4, Protocol = "TCP", IsTcp = true, IsUdp = false,
            SourcePort = 50431, DestinationPort = 80,
            ApplicationProtocol = "HTTP", HttpMethod = method, HttpUri = uri,
            HttpHost = host, Info = ""
        };
    }

    internal static TrafficRecord NewPacket(TrafficRecord original)
    {
        var copy = Http(original.HttpHost!, original.HttpUri!, original.HttpMethod!);
        copy.Source = original.Source;
        copy.Destination = original.Destination;
        copy.HttpRequestHeaders = original.HttpRequestHeaders;
        if (original.HttpAwsListSecretsRequestObserved) Flag(copy, nameof(TrafficRecord.HttpAwsListSecretsRequestObserved));
        if (original.HttpVaultTokenPatternObserved) Flag(copy, nameof(TrafficRecord.HttpVaultTokenPatternObserved));
        if (original.HttpTerraformTokenPatternObserved) Flag(copy, nameof(TrafficRecord.HttpTerraformTokenPatternObserved));
        if (original.HttpNpmTokenPatternObserved) Flag(copy, nameof(TrafficRecord.HttpNpmTokenPatternObserved));
        if (original.HttpPyPiUploadAuthorizationObserved) Flag(copy, nameof(TrafficRecord.HttpPyPiUploadAuthorizationObserved));
        return copy;
    }

    internal static RuleEvaluationContext At(TrafficRecord r, int second = 0)
        => new(r, Sensitivity.Balanced, Epoch.AddSeconds(second));

    internal static void Flag(TrafficRecord record, string name)
    {
        var property = typeof(TrafficRecord).GetProperty(name, BindingFlags.Public | BindingFlags.Instance)
            ?? throw new InvalidOperationException("Unknown parser flag: " + name);
        var setter = property.GetSetMethod(nonPublic: true)
            ?? throw new InvalidOperationException("Parser flag must have an internal setter: " + name);
        setter.Invoke(record, new object[] { true });
    }
}
