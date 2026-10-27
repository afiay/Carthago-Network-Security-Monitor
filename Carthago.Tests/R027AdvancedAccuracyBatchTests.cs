// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Existing;
using Carthago.Models;
using Carthago.Services;
using Xunit;
namespace Carthago.Tests;

[Collection("Legacy rules R011-R015 isolated")]
public sealed class R027AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R027_AdminServiceEgressRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 4, 0, 0, DateTimeKind.Utc);
    public R027AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();
    private async Task<RuleEvaluationResult> See(TrafficRecord r, int sec = 0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(r, Sensitivity.Balanced, T0.AddSeconds(sec)));
    private static TrafficRecord Flow(int port = 22, string src = "10.27.0.2",
        string dst = "8.8.8.8", string flags = "SYN", string protocol = "TCP")
        => new() { Source = src, Destination = dst, DestinationPort = port,
            Protocol = protocol, Flags = flags, Length = 72 };
    [Fact] public async Task Ssh_And_Rdp_Connections_Are_Attributed()
    {
        var e = Assert.Single((await See(Flow())).Events);
        Assert.Equal("R027", e.RuleId); Assert.Equal("10.27.0.2", e.SourceIp);
        Assert.Equal(SeverityLevel.Medium, e.Severity);
        Assert.Equal(3389, Assert.Single((await See(Flow(port: 3389))).Events).DestinationPort);
    }

    [Fact] public async Task Ftp_Telnet_And_Winrm_Are_Eligible_Admin_Services()
    {
        foreach (int p in new[] { 21, 23, 5985, 5986 })
            Assert.Equal(p, Assert.Single((await See(Flow(port: p))).Events).DestinationPort);
    }

    [Fact] public async Task Mail_Auth_Ports_Are_Not_Administrative_Egress()
    {
        foreach (int p in new[] { 25, 110, 143, 465, 993, 995 })
            Assert.False((await See(Flow(port: p))).Matched);
    }

    [Fact] public async Task Invalid_Private_And_External_Attribution_Is_Rejected()
    {
        foreach (var dst in new[] { "10.0.0.1", "127.0.0.1", "192.0.2.1", "bad" })
            Assert.False((await See(Flow(dst: dst))).Matched);
        foreach (var src in new[] { "8.8.8.8", "169.254.1.1", "bad" })
            Assert.False((await See(Flow(src: src))).Matched);
    }

    [Fact] public async Task Udp_Ack_SynAck_And_Mismatched_Service_Are_Excluded()
    {
        Assert.False((await See(Flow(protocol: "UDP"))).Matched);
        foreach (var flags in new[] { "ACK", "SYN,ACK", "FIN", "" })
            Assert.False((await See(Flow(flags: flags))).Matched);
        var ack = Flow(); ack.TcpFlags = 0x12; Assert.False((await See(ack)).Matched);
        var mismatch = Flow(); mismatch.ApplicationService = "RDP";
        Assert.False((await See(mismatch)).Matched);
    }

    [Fact] public async Task Structured_Ssh_Service_And_Numeric_Syn_Provide_Connection_Evidence()
    {
        var service = Flow(flags: "ACK"); service.ApplicationService = "SSH";
        Assert.Equal("R027", Assert.Single((await See(service)).Events).RuleId);
        var syn = Flow(port: 3389, flags: ""); syn.TcpFlags = 0x02;
        Assert.Equal(3389, Assert.Single((await See(syn)).Events).DestinationPort);
    }

    [Fact] public async Task Empty_Packet_And_Invalid_Port_Are_Rejected()
    {
        var r = Flow(); r.Length = 0; Assert.False((await See(r)).Matched);
        Assert.False((await See(Flow(port: 65536))).Matched);
    }

    [Fact] public async Task Cooldown_Is_Per_Port_And_Destination_Without_Payload_Leak()
    {
        var r = Flow(); r.Info = "password SECRET";
        var e = Assert.Single((await See(r)).Events);
        Assert.DoesNotContain("SECRET", e.Description);
        Assert.True((await See(r, 1)).Suppressed);
        Assert.Equal(3389, Assert.Single((await See(Flow(port: 3389), 1)).Events).DestinationPort);
        Assert.Equal("9.9.9.9", Assert.Single((await See(Flow(dst: "9.9.9.9"), 1)).Events).DestinationIp);
    }
}
