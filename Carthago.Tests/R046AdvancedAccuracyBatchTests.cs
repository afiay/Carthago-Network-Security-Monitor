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
public sealed class R046AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R046_UnauthorizedVpnProtocolEgressRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 8, 0, 0, DateTimeKind.Utc);
    public R046AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();
    private async Task<RuleEvaluationResult> See(TrafficRecord r, int sec = 0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(r, Sensitivity.Balanced, T0.AddSeconds(sec)));
    private static TrafficRecord Vpn(int port = 51820, string destination = "8.8.8.8")
        => new() { Source = "10.46.0.2", Destination = destination, Protocol = "UDP",
            DestinationPort = port, IsVpn = true, Length = 220 };

    [Fact] public async Task WireGuard_Classified_Egress_Matches_With_Attribution()
    {
        var e = Assert.Single((await See(Vpn())).Events);
        Assert.Equal("R046", e.RuleId);
        Assert.Equal(51820, e.DestinationPort);
        Assert.Equal("8.8.8.8", e.DestinationIp);
    }
    [Fact] public async Task Structured_Ipsec_Classification_Matches_Without_IsVpn()
    {
        var r = Vpn(4500); r.IsVpn = null; r.ApplicationService = "IPsec";
        Assert.True((await See(r)).Matched);
    }
    [Fact] public async Task Port_Only_And_Udp443_Quic_Are_Not_Vpn_Evidence()
    {
        var r = Vpn(443); r.IsVpn = null; r.ApplicationService = "QUIC";
        Assert.False((await See(r)).Matched);
        r = Vpn(); r.IsVpn = null;
        Assert.False((await See(r)).Matched);
    }
    [Fact] public async Task Explicit_NonVpn_Overrides_Contradictory_Classification()
    {
        var r = Vpn(); r.IsVpn = false; r.ApplicationService = "WireGuard";
        Assert.False((await See(r)).Matched);
    }
    [Fact] public async Task Tcp_Invalid_Port_And_Nonpublic_Destination_Are_Excluded()
    {
        var r = Vpn(); r.Protocol = "TCP"; Assert.False((await See(r)).Matched);
        r = Vpn(9999); Assert.False((await See(r)).Matched);
        r = Vpn(destination: "203.0.113.9"); Assert.False((await See(r)).Matched);
        r = Vpn(); r.Source = "bad"; Assert.False((await See(r)).Matched);
    }
    [Fact] public async Task Duplicate_And_OutOfOrder_Observations_Do_Not_Consume_Budget()
    {
        Assert.True((await See(Vpn())).Matched);
        Assert.False((await See(Vpn())).Matched);
        Assert.False((await See(Vpn(), -1)).Matched);
        Assert.True((await See(Vpn(), 1)).Suppressed);
    }
    [Fact] public async Task Original_Three_Observations_Per_Minute_Budget_Remains()
    {
        Assert.True((await See(Vpn())).Matched);
        Assert.True((await See(Vpn(), 1)).Suppressed);
        Assert.True((await See(Vpn(), 2)).Suppressed);
        Assert.False((await See(Vpn(), 3)).Matched);
    }
}