// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.AssetInventory;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

/// <summary>
/// Guards the benign-traffic exclusions without disabling genuine asset-inventory detections.
/// The R063 positive uses a unique destination because its distinct-source window is shared.
/// </summary>
public sealed class AssetInventoryNoiseRegressionTests
{
    private static readonly DateTime BaseTime = new(2026, 10, 26, 10, 0, 0, DateTimeKind.Utc);

    [Theory]
    [InlineData("DNS", null)]
    [InlineData("UDP", "DNS")]
    public async Task R061_Does_Not_Classify_Normal_Public_Resolver_Lookups_As_Sensitive_Host_Egress(
        string protocol, string? applicationProtocol)
    {
        var rule = new R061_SensitiveHostCommunicatingExternallyRule();
        var result = await rule.EvaluateAsync(Context(new TrafficRecord
        {
            Source = "10.120.1.18",
            Destination = "1.1.1.1",
            Protocol = protocol,
            ApplicationProtocol = applicationProtocol,
            DestinationPort = 53,
            DnsQname = "assets.example.org",
            DnsQtype = "A"
        }));

        Assert.False(result.Matched);
        Assert.Empty(result.Events);
    }

    [Fact]
    public async Task R061_Still_Detects_Sensitive_Service_Communicating_Externally()
    {
        var rule = new R061_SensitiveHostCommunicatingExternallyRule();
        var result = await rule.EvaluateAsync(Context(new TrafficRecord
        {
            Source = "10.120.1.30",
            SourcePort = 1433,
            Destination = "8.8.8.8",
            DestinationPort = 443,
            Protocol = "TCP",
            ApplicationProtocol = "TLS",
            Info = "SQL Server outbound network connection"
        }));

        Assert.True(result.Matched);
        Assert.Contains(result.Events, e => e.RuleId == "R061");
    }

    [Theory]
    [InlineData("169.254.169.254")]
    [InlineData("fe80::a9fe:a9fe")]
    public async Task R063_Ignores_LinkLocal_Metadata_Services_Regardless_Of_Source_Count(string destination)
    {
        var rule = new R063_WorkstationActingLikeServerRule();
        for (var index = 1; index <= 6; index++)
        {
            var result = await rule.EvaluateAsync(Context(new TrafficRecord
            {
                Source = $"10.121.1.{index}",
                Destination = destination,
                DestinationPort = 80,
                Protocol = "TCP",
                ApplicationProtocol = "HTTP",
                HttpMethod = "GET",
                HttpHost = destination,
                HttpUri = "/latest/meta-data/iam/security-credentials/test",
                ProcessName = "cloud-init"
            }, BaseTime.AddSeconds(index)));

            Assert.False(result.Matched);
            Assert.Empty(result.Events);
        }
    }

    [Fact]
    public async Task R063_Still_Detects_Unrecognized_Internal_Server_After_Five_Distinct_Sources()
    {
        var rule = new R063_WorkstationActingLikeServerRule();
        for (var index = 1; index <= 5; index++)
        {
            var result = await rule.EvaluateAsync(Context(new TrafficRecord
            {
                Source = $"10.122.1.{index}",
                Destination = "10.254.219.88",
                DestinationPort = 8443,
                Protocol = "TCP",
                ApplicationProtocol = "HTTPS",
                Info = "Inbound connection to unrecognized internal service"
            }, BaseTime.AddSeconds(index)));

            if (index < 5)
            {
                Assert.False(result.Matched);
                continue;
            }

            Assert.True(result.Matched);
            Assert.Contains(result.Events, e => e.RuleId == "R063");
        }
    }

    private static RuleEvaluationContext Context(TrafficRecord record, DateTime? timestamp = null)
        => new(record, Sensitivity.Balanced, timestamp ?? BaseTime);
}
