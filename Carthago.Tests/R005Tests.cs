// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Existing;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

[Collection("Legacy rules R001-R005 isolated")]
public sealed class R005Tests : IDisposable
{
    private static readonly DateTime T0 = new(2026, 10, 26, 15, 0, 0, DateTimeKind.Utc);
    private readonly R005_SuspiciousProtocolRule _rule = new();
    public R005Tests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();

    private static TrafficRecord Packet(
        string service = "TELNET", string protocol = "TCP", int port = 23,
        string source = "10.245.0.10", string destination = "10.245.1.10")
        => new()
        {
            Source = source, Destination = destination,
            DestinationPort = port, SourcePort = 56000,
            ApplicationService = service, Protocol = protocol,
            Length = 180, Info = "Synthetic protocol identification from captured traffic."
        };

    private async Task<RuleEvaluationResult> Evaluate(TrafficRecord record, int seconds = 0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(
            record, Sensitivity.Balanced, T0.AddSeconds(seconds)));

    [Theory]
    [InlineData("TELNET", "TCP", 23)]
    [InlineData("FTP", "TCP", 21)]
    [InlineData("SMB", "TCP", 445)]
    [InlineData("SNMP", "UDP", 161)]
    public async Task Observed_Insecure_Application_Protocols_Are_Raw_Candidates(
        string service, string transport, int port)
    {
        var result = await Evaluate(Packet(service, transport, port));
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.Equal("R005", evt.RuleId);
        Assert.Equal("10.245.0.10", evt.SourceIp);
        Assert.Equal("10.245.1.10", evt.DestinationIp);
        // This is an exposure candidate, NOT proof of adversarial behavior.
        Assert.Equal(SeverityLevel.Medium, evt.Severity);
    }

    [Fact]
    public async Task Normal_Https_Ssh_Dns_And_Quic_Do_Not_Match_The_Insecure_Protocol_Set()
    {
        foreach (var (service, protocol, port) in new[]
        {
            ("HTTPS", "TCP", 443),
            ("SSH", "TCP", 22),
            ("DNS", "UDP", 53),
            ("QUIC", "UDP", 443)
        })
            Assert.False((await Evaluate(Packet(service, protocol, port))).Matched);
    }

    [Fact]
    public async Task Words_About_Insecure_Protocols_In_A_Log_Dont_Count_As_Observed_Protocol()
    {
        var record = Packet("HTTPS", "TCP", 443);
        record.Info = "A security wiki page mentions telnet ftp smb snmp, but this flow is HTTPS.";
        Assert.False((await Evaluate(record)).Matched);
    }

    [Fact]
    public async Task Sparse_Records_Without_Traffic_Attribution_Are_Not_Detections()
    {
        var noSource = Packet();
        noSource.Source = null;
        Assert.False((await Evaluate(noSource)).Matched);

        var noDest = Packet();
        noDest.Destination = null;
        Assert.False((await Evaluate(noDest)).Matched);

        var noPort = Packet();
        noPort.DestinationPort = null;
        Assert.False((await Evaluate(noPort)).Matched);
    }

    [Fact]
    public async Task Duplicate_Flow_Observations_Are_Debounced_Without_Losing_Initial_Observation()
    {
        var first = await Evaluate(Packet("TELNET", "TCP", 23));
        Assert.True(first.Matched);
        var second = await Evaluate(Packet("TELNET", "TCP", 23), 1);
        Assert.Empty(second.Events);
    }

    [Fact]
    public async Task An_Independent_Source_Is_Not_Suppressed_By_Another_Source_Using_Same_Protocol()
    {
        Assert.True((await Evaluate(Packet(source: "10.245.0.40"))).Matched);
        var second = await Evaluate(Packet(source: "10.245.0.41"), 1);
        Assert.True(second.Matched);
        Assert.Equal("10.245.0.41", Assert.Single(second.Events).SourceIp);
    }
}
