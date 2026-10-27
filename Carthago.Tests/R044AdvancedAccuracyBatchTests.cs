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
public sealed class R044AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R044_UnusualHttpMethodsToInternetRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 7, 0, 0, DateTimeKind.Utc);
    public R044AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();
    private async Task<RuleEvaluationResult> See(TrafficRecord r, int seconds=0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(r, Sensitivity.Balanced, T0.AddSeconds(seconds)));

    private static TrafficRecord Http(string method="TRACE",string src="10.44.0.2",string dst="8.8.8.8",int port=80)
        => new(){Source=src,Destination=dst,Protocol="HTTP",DestinationPort=port,
            HttpMethod=method,Length=250};
    [Fact] public async Task Structured_Trace_To_Public_Host_Matches()
    {
        var e=Assert.Single((await See(Http())).Events);
        Assert.Equal("R044",e.RuleId);Assert.Contains("TRACE",e.Description);
    }
    [Fact] public async Task Other_Unusual_Recognized_Method_Matches()
    {
        var e=Assert.Single((await See(Http("PROPFIND"))).Events);
        Assert.Equal("R044",e.RuleId);
    }
    [Fact] public async Task Ordinary_Http_Methods_Are_Excluded()
    {
        foreach(string method in new[]{"GET","POST","PUT","DELETE","OPTIONS"})
            Assert.False((await See(Http(method))).Matched);
    }
    [Fact] public async Task Proxy_Connect_Is_Excluded_But_Direct_Connect_Is_Not()
    {
        Assert.False((await See(Http("CONNECT",port:8080))).Matched);
        Assert.True((await See(Http("CONNECT",port:443)).Matched));
    }
    [Fact] public async Task Info_Text_And_Contradictory_Protocol_Are_Not_Trusted()
    {
        var r=Http();r.HttpMethod=null;r.Info="TRACE / HTTP/1.1";
        Assert.False((await See(r)).Matched);
        r=Http();r.Protocol="DNS";
        Assert.False((await See(r)).Matched);
        r=Http();r.ApplicationService="SMTP";
        Assert.False((await See(r)).Matched);
    }
    [Fact] public async Task Internal_Reserved_Invalid_And_Empty_Traffic_Is_Excluded()
    {
        foreach(string dst in new[]{"10.0.0.2","192.0.2.2","bad"})
            Assert.False((await See(Http(dst:dst))).Matched);
        Assert.False((await See(Http(src:"8.8.4.4"))).Matched);
        var r=Http();r.Length=0;Assert.False((await See(r)).Matched);
    }
    [Fact] public async Task Same_Flow_Repeats_Are_Suppressed()
    {
        Assert.True((await See(Http())).Matched);
        Assert.True((await See(Http(),1)).Suppressed);
    }
}
