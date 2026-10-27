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
public sealed class R043AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R043_SniHttpHostMismatchRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 7, 0, 0, DateTimeKind.Utc);
    public R043AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();
    private async Task<RuleEvaluationResult> See(TrafficRecord r, int seconds=0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(r, Sensitivity.Balanced, T0.AddSeconds(seconds)));

    private static TrafficRecord Tls(string sni="api.example.org",int srcPort=51443)
        => new(){Source="10.43.0.2",Destination="8.8.8.8",Protocol="TLS",SourcePort=srcPort,
            DestinationPort=443,Sni=sni,Length=180};
    private static TrafficRecord Http(string host="other.example.net",int srcPort=51443)
        => new(){Source="10.43.0.2",Destination="8.8.8.8",Protocol="HTTP",SourcePort=srcPort,
            DestinationPort=443,HttpMethod="GET",HttpHost=host,Length=210};
    [Fact] public async Task Same_Flow_Corroborated_Sni_Host_Mismatch_Matches_Without_Leaking_Hosts()
    {
        Assert.False((await See(Tls())).Matched);
        var e=Assert.Single((await See(Http(),1)).Events);
        Assert.Equal("R043",e.RuleId);
        Assert.DoesNotContain("api.example.org",e.Description);
        Assert.DoesNotContain("other.example.net",e.Description);
    }
    [Fact] public async Task Matching_Registrable_Domain_Does_Not_Trigger()
    {
        await See(Tls());
        Assert.False((await See(Http("web.example.org"),1)).Matched);
    }
    [Fact] public async Task Unrelated_Source_Ports_Cannot_Reuse_An_Other_Flows_Sni()
    {
        await See(Tls(srcPort:51000));
        Assert.False((await See(Http(srcPort:51001),1)).Matched);
    }
    [Fact] public async Task Port_443_Without_Tls_Classification_Does_Not_Seed_Correlation()
    {
        var r=Tls();r.Protocol="TCP";
        Assert.False((await See(r)).Matched);
        Assert.False((await See(Http(),1)).Matched);
    }
    [Fact] public async Task Stale_Out_Of_Order_And_Missing_Port_Evidence_Is_Excluded()
    {
        await See(Tls());
        Assert.False((await See(Http(),-1)).Matched);
        Assert.False((await See(Http(),121)).Matched);
        var missing=Http();missing.SourcePort=null;
        Assert.False((await See(missing,1)).Matched);
    }
    [Fact] public async Task Contradictory_Host_Header_And_Field_Cannot_Trigger()
    {
        await See(Tls());
        var r=Http();r.HttpRequestHeaders="Host: contradiction.example.com\r\n";
        Assert.False((await See(r,1)).Matched);
        r=Http();r.HttpHost="bad\r\nHost: secret";
        Assert.False((await See(r,2)).Matched);
    }
    [Fact] public async Task Info_Prose_And_Connect_Tunnels_Cannot_Trigger()
    {
        await See(Tls());
        var r=Http();r.HttpMethod=null;r.Info="GET / HTTP/1.1\r\nHost: other.example.net\r\n";
        Assert.False((await See(r,1)).Matched);
        r=Http();r.HttpMethod="CONNECT";
        Assert.False((await See(r,2)).Matched);
    }
}
