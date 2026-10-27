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
public sealed class R026AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R026_SmbRpcToInternetRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 4, 0, 0, DateTimeKind.Utc);
    public R026AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();
    private async Task<RuleEvaluationResult> See(TrafficRecord r, int sec = 0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(r, Sensitivity.Balanced, T0.AddSeconds(sec)));
    private static TrafficRecord Flow(string src = "10.26.0.2", string dst = "8.8.8.8",
        int port = 445, string protocol = "TCP", string flags = "SYN")
        => new() { Source = src, Destination = dst, DestinationPort = port,
            Protocol = protocol, Flags = flags, Length = 72 };
    [Fact] public async Task Public_Smb_Syn_Emits_High_Severity_Attributed_Event()
    {
        var e = Assert.Single((await See(Flow())).Events);
        Assert.Equal("R026", e.RuleId); Assert.Equal("10.26.0.2", e.SourceIp);
        Assert.Equal("8.8.8.8", e.DestinationIp); Assert.Equal(445, e.DestinationPort);
        Assert.Equal(SeverityLevel.High, e.Severity);
    }

    [Fact] public async Task Netbios139_And_Numeric_Syn_Are_Eligible()
    {
        var r = Flow(port: 139, flags: ""); r.TcpFlags = 0x02;
        Assert.Equal(139, Assert.Single((await See(r)).Events).DestinationPort);
    }

    [Fact] public async Task Private_Documentation_Cgn_Multicast_And_Invalid_Destinations_Are_Excluded()
    {
        foreach (var dst in new[] { "10.1.0.1", "127.0.0.1", "192.0.2.1",
            "198.51.100.2", "203.0.113.3", "100.64.0.1", "224.0.0.1", "bad" })
            Assert.False((await See(Flow(dst: dst))).Matched);
    }

    [Fact] public async Task Public_Loopback_LinkLocal_And_Unknown_Sources_Are_Not_Private_Egress()
    {
        foreach (var src in new[] { "8.8.8.8", "127.0.0.1", "169.254.1.1", "bad" })
            Assert.False((await See(Flow(src: src))).Matched);
        var r = Flow(); r.Source = null; Assert.False((await See(r)).Matched);
    }

    [Fact] public async Task Udp_Reverse_Flags_And_Contradictory_Classification_Are_Not_Smb()
    {
        Assert.False((await See(Flow(protocol: "UDP"))).Matched);
        foreach (var flags in new[] { "ACK", "SYN,ACK", "RST", "" })
            Assert.False((await See(Flow(flags: flags))).Matched);
        var ack = Flow(); ack.TcpFlags = 0x12; Assert.False((await See(ack)).Matched);
        var mismatch = Flow(); mismatch.ApplicationService = "HTTP";
        Assert.False((await See(mismatch)).Matched);
    }

    [Fact] public async Task Structured_Smb_Classification_Corroborates_Established_Connection()
    {
        var r = Flow(flags: "ACK"); r.ApplicationService = "SMB";
        Assert.Equal("R026", Assert.Single((await See(r)).Events).RuleId);
    }

    [Fact] public async Task Rpc135_Invalid_Port_And_Empty_Packet_Are_Not_Port445_Evidence()
    {
        Assert.False((await See(Flow(port: 135))).Matched);
        Assert.False((await See(Flow(port: 65536))).Matched);
        var r = Flow(); r.Length = 0; Assert.False((await See(r)).Matched);
    }

    [Fact] public async Task Cooldown_Separates_Destinations_And_Protects_Payload()
    {
        var r = Flow(); r.Info = "SMB password SECRET";
        var e = Assert.Single((await See(r)).Events);
        Assert.DoesNotContain("SECRET", e.Description);
        Assert.True((await See(r, 1)).Suppressed);
        Assert.Equal("9.9.9.9", Assert.Single((await See(Flow(dst: "9.9.9.9"), 1)).Events).DestinationIp);
    }
}
