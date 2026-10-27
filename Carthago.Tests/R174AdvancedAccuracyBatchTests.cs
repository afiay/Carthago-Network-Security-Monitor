// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R174AdvancedAccuracyBatchTests
{
    private static TrafficRecord Dav()
    {
        var r=NetworkBatch166175Context.Http("/webdav/","PROPFIND");
        r.HttpRequestHeaders+="\r\nDepth: infinity";
        return r;
    }
    [Fact] public async Task Deep_Webdav_Propfind_Qualifies()
    {
        var r=Dav();Assert.True((await new R174_WebdavMethodAbuseRule().EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);
    }
    [Fact] public async Task Caldav_Discovery_Is_Benign()
    {
        var r=Dav();r.HttpUri="/.well-known/caldav";r.HttpRequestHeaders=r.HttpRequestHeaders!.Replace("infinity","1");Assert.False((await new R174_WebdavMethodAbuseRule().EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);
    }
    [Fact] public async Task Shallow_Propfind_Is_Not_Abusive_Probe()
    {
        var r=Dav();r.HttpRequestHeaders=r.HttpRequestHeaders!.Replace("infinity","1");Assert.False((await new R174_WebdavMethodAbuseRule().EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);
    }
    [Fact] public async Task Ordinary_Get_Is_Not_Webdav_Abuse()
    {
        var r=Dav();r.HttpMethod="GET";Assert.False((await new R174_WebdavMethodAbuseRule().EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);
    }
    [Fact] public async Task Udp_Contradiction_Is_Not_Webdav()
    {
        var r=Dav();r.IsTcp=false;r.IsUdp=true;Assert.False((await new R174_WebdavMethodAbuseRule().EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);
    }
    [Fact] public async Task Conflicting_Authority_Is_Rejected()
    {
        var r=Dav();r.HttpRequestHeaders="Host: wrong.example\r\nDepth: infinity";Assert.False((await new R174_WebdavMethodAbuseRule().EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);
    }
    [Fact] public async Task Replayed_Dav_Request_Cannot_Realert()
    {
        var r=Dav();var rule=new R174_WebdavMethodAbuseRule();Assert.True((await rule.EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch166175Context.At(r,2))).Matched);
    }
    [Fact] public async Task Dav_Resource_And_Query_Are_Redacted()
    {
        var r=Dav();r.HttpUri="/webdav/SECRET174?token=HIDDEN174";var x=await new R174_WebdavMethodAbuseRule().EvaluateAsync(NetworkBatch166175Context.At(r));Assert.True(x.Matched);Assert.DoesNotContain(Assert.Single(x.Events).StructuredEvidence!.Items,i=>i.Value.Contains("SECRET174",StringComparison.Ordinal)||i.Value.Contains("HIDDEN174",StringComparison.Ordinal));
    }
    [Fact] public async Task Webdav_Prefix_In_Unrelated_Path_Is_Not_Abuse()
    {
        var r=Dav();r.HttpUri="/webdavlike";
        Assert.False((await new R174_WebdavMethodAbuseRule().EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);
    }
    [Fact] public void Runtime_Policy_And_Confidence_Floor_Are_Preserved()
    {
        var p=new R174_WebdavMethodAbuseRule().PrecisionProfile;
        Assert.Equal(74,p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Shadow,p.DefaultMode);
    }
}
