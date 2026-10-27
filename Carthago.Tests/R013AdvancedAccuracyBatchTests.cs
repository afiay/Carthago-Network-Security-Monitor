// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Existing;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

/// <summary>R013: transport evidence and registered service-port disagreement.</summary>
[Collection("Legacy rules R011-R015 isolated")]
public sealed class R013AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R013_UncommonPortsServicePortAnomalyRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 5, 0, 0, DateTimeKind.Utc);
    public R013AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();

    private static TrafficRecord Flow(string source = "10.13.0.1", int port = 3306,
        string protocol = "TCP", string? service = "SSH", string flags = "SYN")
        => new() { Source = source, Destination = "10.13.0.2", DestinationPort = port,
            Protocol = protocol, ApplicationService = service, Flags = flags, Length = 100 };

    private async Task<RuleEvaluationResult> See(TrafficRecord r, int second = 0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(r, Sensitivity.Balanced, T0.AddSeconds(second)));

    [Fact]
    public async Task Initial_Tcp_Syn_With_Mysql_Port_Ssh_Classification_Is_An_Anomaly_Candidate()
    {
        var evt = Assert.Single((await See(Flow())).Events);
        Assert.Equal("R013", evt.RuleId);
        Assert.Equal(3306, evt.DestinationPort);
        Assert.Equal(SeverityLevel.Medium, evt.Severity);
        Assert.Contains("classification mismatch", evt.Description);
    }

    [Fact]
    public async Task Tcp_SynAck_And_Ack_Are_Not_Initial_Service_Probes()
    {
        foreach (var flags in new[] { "SYN,ACK", "ACK", "RST", "FIN", "" })
            Assert.False((await See(Flow(flags: flags))).Matched);
        var numericSynAck = Flow(); numericSynAck.TcpFlags = 0x12;
        Assert.False((await See(numericSynAck)).Matched);
        var numericSyn = Flow(); numericSyn.TcpFlags = 0x02;
        Assert.True((await See(numericSyn)).Matched);
    }

    [Fact]
    public async Task Udp_Payload_Length_Alone_Is_Not_A_Service_Identification()
    {
        var record = Flow(protocol: "UDP", service: null, flags: "");
        record.Length = 2000;
        Assert.False((await See(record)).Matched);
    }

    [Fact]
    public async Task Explicit_Udp_Service_Mismatch_Produces_A_Review_Candidate()
    {
        var record = Flow(protocol: "UDP", service: "SSH", flags: "");
        var evt = Assert.Single((await See(record)).Events);
        Assert.Equal("UDP", evt.Protocol);
        Assert.Equal(3306, evt.DestinationPort);
    }

    [Fact]
    public async Task Registered_Service_On_Expected_Port_Is_Not_Anomalous()
    {
        var record = Flow(service: "mysql");
        Assert.False((await See(record)).Matched);
    }

    [Fact]
    public async Task Invalid_Attribution_Transport_Or_Port_Cannot_Create_Candidate()
    {
        var badSource = Flow(); badSource.Source = "not-an-ip";
        var badDest = Flow(); badDest.Destination = null;
        var badProto = Flow(protocol: "ICMP");
        var badPort = Flow(port: 65536);
        var privileged = Flow(port: 443);
        foreach (var record in new[] { badSource, badDest, badProto, badPort, privileged })
            Assert.False((await See(record)).Matched);
    }

    [Fact]
    public async Task Ephemeral_Unclassified_Tcp_And_Allowlisted_Service_Ports_Are_Not_Alerted()
    {
        Assert.False((await See(Flow(port: 60000, service: null))).Matched);
        Assert.False((await See(Flow(port: 5353))).Matched);
    }

    [Fact]
    public async Task Untrusted_Service_Labels_Are_Not_Echoed_Into_Alerts()
    {
        const string marker = "do-not-log-this-secret";
        var evt = Assert.Single((await See(Flow(service: "SSH " + marker))).Events);
        Assert.DoesNotContain(marker, evt.Description, StringComparison.Ordinal);
    }

    [Fact]
    public async Task Cooldown_Is_Per_Source_Destination_Service_Not_Global()
    {
        Assert.True((await See(Flow())).Matched);
        var repeated = await See(Flow(), 1);
        Assert.True(repeated.Suppressed);
        Assert.Empty(repeated.Events);
        var other = await See(Flow(source: "10.13.0.3"), 1);
        Assert.Equal("10.13.0.3", Assert.Single(other.Events).SourceIp);
    }
}
