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
public sealed class R028AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R028_DirectExternalDnsRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 4, 0, 0, DateTimeKind.Utc);
    public R028AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();
    private async Task<RuleEvaluationResult> See(TrafficRecord r, int sec = 0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(r, Sensitivity.Balanced, T0.AddSeconds(sec)));
    private static TrafficRecord Query(string src = "10.28.0.2", string dst = "8.8.8.8",
        string protocol = "UDP", int port = 53)
        => new() { Source = src, Destination = dst, Protocol = protocol,
            DestinationPort = port, DnsQname = "example.org", DnsQtype = "A", Length = 88 };
    [Fact] public async Task Attributed_Public_Resolver_Query_Is_Detected()
    {
        var e = Assert.Single((await See(Query())).Events);
        Assert.Equal("R028", e.RuleId); Assert.Equal("10.28.0.2", e.SourceIp);
        Assert.Equal("8.8.8.8", e.DestinationIp); Assert.Equal(53, e.DestinationPort);
    }

    [Fact] public async Task Responses_And_Reverse_Flows_Are_Not_Direct_Queries()
    {
        var response = Query(); response.DnsIsResponse = true;
        Assert.False((await See(response)).Matched);
        Assert.False((await See(Query(src: "8.8.8.8", dst: "10.28.0.2"))).Matched);
    }

    [Fact] public async Task Private_Documentation_Multicast_And_Malformed_Resolvers_Are_Excluded()
    {
        foreach (var dst in new[] { "10.0.0.53", "127.0.0.1", "192.0.2.53",
            "203.0.113.53", "224.0.0.53", "bad" })
            Assert.False((await See(Query(dst: dst))).Matched);
    }

    [Fact] public async Task Public_LinkLocal_And_Missing_Sources_Are_Not_Attributed_Clients()
    {
        foreach (var src in new[] { "8.8.8.8", "169.254.2.3", "127.0.0.1", "bad" })
            Assert.False((await See(Query(src: src))).Matched);
        var r = Query(); r.Source = null; Assert.False((await See(r)).Matched);
    }

    [Fact] public async Task Port_Only_Udp_And_Untrusted_Info_Cannot_Claim_Observed_Query()
    {
        var r = Query(); r.DnsQname = null; r.Info = "DNS query for example.org";
        Assert.False((await See(r)).Matched);
        r.DnsQname = " "; Assert.False((await See(r)).Matched);
    }

    [Fact] public async Task Structured_Tcp_Dns_Is_Recognized_But_Tcp_Port_Only_Is_Not()
    {
        var tcp = Query(protocol: "TCP"); tcp.ApplicationService = "DNS";
        Assert.Equal("TCP", Assert.Single((await See(tcp)).Events).Protocol);
        Assert.False((await See(Query(dst: "9.9.9.9", protocol: "TCP"))).Matched);
    }

    [Fact] public async Task Wrong_Port_Contradictory_Service_Quic_And_Empty_Record_Are_Rejected()
    {
        Assert.False((await See(Query(port: 853))).Matched);
        var mismatch = Query(); mismatch.ApplicationService = "HTTP";
        Assert.False((await See(mismatch)).Matched);
        var quic = Query(); quic.IsQuic = true; Assert.False((await See(quic)).Matched);
        var empty = Query(); empty.Length = 0; Assert.False((await See(empty)).Matched);
    }

    [Fact] public async Task Cooldown_Is_Per_Resolver_And_Does_Not_Expose_Dns_Name()
    {
        var r = Query(); r.DnsQname = "private.secret.example.org";
        var e = Assert.Single((await See(r)).Events);
        Assert.DoesNotContain("private.secret.example.org", e.Description);
        Assert.True((await See(r, 1)).Suppressed);
        Assert.Equal("9.9.9.9", Assert.Single((await See(Query(dst: "9.9.9.9"), 1)).Events).DestinationIp);
    }
}
