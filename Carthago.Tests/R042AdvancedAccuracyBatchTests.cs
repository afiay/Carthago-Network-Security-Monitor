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
public sealed class R042AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R042_UncommonQuicAlpnRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 7, 0, 0, DateTimeKind.Utc);
    public R042AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();
    private async Task<RuleEvaluationResult> See(TrafficRecord r, int seconds=0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(r, Sensitivity.Balanced, T0.AddSeconds(seconds)));

    private static TrafficRecord Quic(string alpn="custom-quic/1",string src="10.42.0.2",string dst="8.8.8.8")
        => new() {Source=src,Destination=dst,Protocol="QUIC",IsQuic=true,DestinationPort=443,
            QuicAlpn=alpn,Length=230};
    [Fact] public async Task First_Validated_Uncommon_Alpn_Observation_Matches_Without_Leaking_Value()
    {
        var e=Assert.Single((await See(Quic())).Events);
        Assert.Equal("R042",e.RuleId); Assert.Equal(1,e.Count);
        Assert.DoesNotContain("custom-quic",e.Description);
    }
    [Fact] public async Task Standard_Http3_And_Hq_Alpns_Are_Benign()
    {
        foreach(string a in new[]{"h3","h3-29","hq-29","http/3"})
            Assert.False((await See(Quic(a))).Matched);
    }
    [Fact] public async Task Alpn_Field_Alone_Cannot_Impersonate_Quic()
    {
        var r=Quic(); r.IsQuic=false; r.Protocol="HTTP";
        Assert.False((await See(r)).Matched);
        r.Protocol="TCP"; Assert.False((await See(r)).Matched);
    }
    [Fact] public async Task Malformed_Alpn_Endpoints_And_Zero_Length_Are_Rejected()
    {
        foreach(string a in new[]{"bad alpn","x\nsecret",new string('x',65)})
            Assert.False((await See(Quic(a))).Matched);
        foreach(string dst in new[]{"192.0.2.2","10.0.0.2","bad"})
            Assert.False((await See(Quic(dst:dst))).Matched);
        var r=Quic();r.Length=0;Assert.False((await See(r)).Matched);
    }
    [Fact] public async Task Duplicate_Timestamp_Does_Not_Consume_Rarity_Quota()
    {
        Assert.True((await See(Quic())).Matched);
        for(int i=0;i<10;i++) Assert.False((await See(Quic())).Matched);
        Assert.True((await See(Quic(src:"10.42.0.3"),1)).Matched);
        Assert.True((await See(Quic(src:"10.42.0.4"),2)).Matched);
        Assert.False((await See(Quic(src:"10.42.0.5"),3)).Matched);
    }
    [Fact] public async Task Rarity_Expires_After_Six_Hours_And_Old_Timestamps_Are_Rejected()
    {
        Assert.True((await See(Quic())).Matched);
        Assert.False((await See(Quic(src:"10.42.0.3"),-1)).Matched);
        var e=Assert.Single((await See(Quic(src:"10.42.0.4"),6*3600+1)).Events);
        Assert.Equal(1,e.Count);
    }
}
