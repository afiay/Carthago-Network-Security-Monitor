// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Existing;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

/// <summary>R005 batch gate: five observed-service and attribution edge cases.</summary>
[Collection("Legacy rules R001-R005 isolated")]
public sealed class R005AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R005_SuspiciousProtocolRule _rule = new();
    private static readonly DateTime Origin = new(2026, 10, 26, 15, 0, 0, DateTimeKind.Utc);
    public R005AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();

    private static TrafficRecord Packet(string? service = "TELNET",
        string protocol = "TCP", int? port = 23,
        string source = "10.255.1.1", string dest = "10.255.2.1")
        => new() { Source = source, Destination = dest, DestinationPort = port,
            SourcePort = 56000, ApplicationService = service,
            Protocol = protocol, Info = "Observed synthetic service telemetry." };

    private async Task<RuleEvaluationResult> See(TrafficRecord record, int seconds = 0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(
            record, Sensitivity.Balanced, Origin.AddSeconds(seconds)));

    [Fact]
    public async Task Whitespace_And_Case_Normalized_Observed_Service_Is_Not_Silently_Lost()
    {
        var telnet = await See(Packet(service: "  telnet  "));
        Assert.True(telnet.Matched);
        Assert.Equal("R005", Assert.Single(telnet.Events).RuleId);
    }

    [Fact]
    public async Task Insecure_Service_Names_In_Untrusted_Info_Do_Not_Overrule_Transport()
    {
        var record = Packet(service: "HTTPS", protocol: "TCP", port: 443);
        record.Info = "Documentation discusses TELNET FTP SMB SNMP exposures";
        Assert.False((await See(record)).Matched);
        Assert.False((await See(Packet(service: "FTP", protocol: "UDP", port: 21))).Matched);
    }

    [Fact]
    public async Task Snmp_On_Udp_Or_Tcp_Is_Recognized_With_Attributed_Endpoint()
    {
        var udp = await See(Packet("SNMP", "UDP", 161, source: "10.255.1.11"));
        var tcp = await See(Packet("SNMP", "TCP", 161, source: "10.255.1.12"), 1);
        Assert.True(udp.Matched);
        Assert.True(tcp.Matched);
        Assert.Equal("UDP", Assert.Single(udp.Events).Protocol);
        Assert.Equal("TCP", Assert.Single(tcp.Events).Protocol);
    }

    [Fact]
    public async Task Invalid_And_Missing_Service_EndPoints_Do_Not_Manufacture_A_Finding()
    {
        foreach (int? port in new int?[] { null, -1, 0, 65536, int.MaxValue })
            Assert.False((await See(Packet(port: port))).Matched);
        var missingSource = Packet();
        missingSource.Source = " ";
        Assert.False((await See(missingSource)).Matched);
        var missingDestination = Packet();
        missingDestination.Destination = null;
        Assert.False((await See(missingDestination)).Matched);
    }

    [Fact]
    public async Task Dedupe_Applies_To_Flow_Not_Every_Independent_Service_Endpoint()
    {
        var first = await See(Packet("TELNET", "TCP", 23));
        Assert.True(first.Matched);
        Assert.Empty((await See(Packet("TELNET", "TCP", 23), 1)).Events);
        var distinctService = await See(Packet("TELNET", "TCP", 2323), 2);
        Assert.True(distinctService.Matched);
        Assert.Equal(2323, Assert.Single(distinctService.Events).DestinationPort);
    }
}
