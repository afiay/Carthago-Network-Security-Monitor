// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Existing;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

/// <summary>R020: private-source TCP SMTP egress to a routable destination with allowlist.</summary>
[Collection("Legacy rules R011-R015 isolated")]
public sealed class R020AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R020_OutboundSmtpDirectToInternetRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 3, 0, 0, DateTimeKind.Utc);
    public R020AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();

    private static TrafficRecord Flow(string source = "10.20.0.2", string destination = "8.8.8.8",
        string protocol = "TCP", int port = 25, string flags = "SYN")
        => new() { Source = source, Destination = destination, Protocol = protocol,
            DestinationPort = port, Flags = flags, Length = 64 };

    private async Task<RuleEvaluationResult> See(TrafficRecord r, int second = 0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(r, Sensitivity.Balanced, T0.AddSeconds(second)));

    [Fact]
    public async Task Private_Host_Syn_To_Public_Port25_Produces_Attributed_Egress_Candidate()
    {
        var evt = Assert.Single((await See(Flow())).Events);
        Assert.Equal("R020", evt.RuleId);
        Assert.Equal("10.20.0.2", evt.SourceIp);
        Assert.Equal("8.8.8.8", evt.DestinationIp);
        Assert.Equal(25, evt.DestinationPort);
        Assert.Equal(SeverityLevel.High, evt.Severity);
    }

    [Fact]
    public async Task Configured_Approved_Smtp_Source_Remains_Excluded()
    {
        Assert.False((await See(Flow(source: "10.0.0.10"))).Matched);
    }

    [Fact]
    public async Task Udp_Port25_And_Reverse_Tcp_Flags_Are_Not_Outbound_Smtp_Connects()
    {
        Assert.False((await See(Flow(protocol: "UDP"))).Matched);
        foreach (var flags in new[] { "ACK", "SYN,ACK", "RST", "FIN", "" })
            Assert.False((await See(Flow(flags: flags))).Matched);
        var synAck = Flow(); synAck.TcpFlags = 0x12;
        Assert.False((await See(synAck)).Matched);
    }

    [Fact]
    public async Task Explicit_Observed_Smtp_Service_Is_Evidence_Without_An_Initial_Syn()
    {
        var r = Flow(flags: "ACK");
        r.ApplicationService = "SMTP";
        Assert.Equal("R020", Assert.Single((await See(r)).Events).RuleId);
    }

    [Fact]
    public async Task Untrusted_Info_Containing_Smtp_Does_Not_Manufacture_Protocol_Evidence()
    {
        var r = Flow(flags: "");
        r.Info = "Documentation: SMTP port 25 is open";
        Assert.False((await See(r)).Matched);
    }

    [Fact]
    public async Task Private_Loopback_Linklocal_And_Documentation_Destinations_Are_Excluded()
    {
        foreach (var destination in new[] { "10.1.0.1", "127.0.0.1", "169.254.1.1",
            "192.0.2.10", "198.51.100.10", "203.0.113.10", "224.0.0.1" })
            Assert.False((await See(Flow(destination: destination))).Matched);
    }

    [Fact]
    public async Task External_Or_Malformed_Source_Is_Not_A_Private_Host_Egress()
    {
        foreach (var source in new[] { "8.8.8.8", "127.0.0.1", "not-an-ip", "169.254.1.2" })
            Assert.False((await See(Flow(source: source))).Matched);
        var missing = Flow(); missing.Source = null;
        Assert.False((await See(missing)).Matched);
    }

    [Fact]
    public async Task Submission_And_Implicit_Tls_Ports_Are_Not_Direct_Port25_Detections()
    {
        Assert.False((await See(Flow(port: 587))).Matched);
        Assert.False((await See(Flow(port: 465))).Matched);
        var zero = Flow(); zero.Length = 0;
        Assert.False((await See(zero)).Matched);
    }

    [Fact]
    public async Task Cooldown_Is_Per_Source_Destination_And_Does_Not_Leak_Smtp_Content()
    {
        var first = Flow(); first.Info = "SMTP AUTH PLAIN SECRET_SHOULD_NOT_LOG";
        var evt = Assert.Single((await See(first)).Events);
        Assert.DoesNotContain("SECRET_SHOULD_NOT_LOG", evt.Description);
        var duplicate = await See(first, 1);
        Assert.True(duplicate.Suppressed);
        Assert.Empty(duplicate.Events);
        Assert.Equal("9.9.9.9", Assert.Single((await See(Flow(destination: "9.9.9.9"), 1)).Events).DestinationIp);
    }
}
