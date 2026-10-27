// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R176AdvancedAccuracyBatchTests
{
    [Fact] public async Task Forwarded_Private_Loopback_Target_Qualifies()
    {
        var r=NetworkBatch176185Context.Http("/");r.HttpRequestHeaders+="\r\nX-Forwarded-Host: 127.0.0.1";Assert.True((await new R176_HostHeaderInjectionIndicatorRule().EvaluateAsync(NetworkBatch176185Context.At(r))).Matched);
    }
    [Fact] public async Task Normal_Proxy_Forwarding_Is_Benign()
    {
        var r=NetworkBatch176185Context.Http("/");r.HttpRequestHeaders+="\r\nX-Forwarded-Host: web.internal.local";Assert.False((await new R176_HostHeaderInjectionIndicatorRule().EvaluateAsync(NetworkBatch176185Context.At(r))).Matched);
    }
    [Fact] public async Task Sensitive_Rewrite_Target_Qualifies()
    {
        var r=NetworkBatch176185Context.Http("/");r.HttpRequestHeaders+="\r\nX-Rewrite-URL: /admin/config";Assert.True((await new R176_HostHeaderInjectionIndicatorRule().EvaluateAsync(NetworkBatch176185Context.At(r))).Matched);
    }
    [Fact] public async Task Contradictory_Observed_Host_Is_Rejected()
    {
        var r=NetworkBatch176185Context.Http("/");r.HttpRequestHeaders="Host: other.internal.local\r\nX-Forwarded-Host: 127.0.0.1";Assert.False((await new R176_HostHeaderInjectionIndicatorRule().EvaluateAsync(NetworkBatch176185Context.At(r))).Matched);
    }
    [Fact] public async Task Info_Only_Header_Claim_Is_Not_Proof()
    {
        var r=NetworkBatch176185Context.Http("/");r.Info="X-Forwarded-Host: 127.0.0.1";Assert.False((await new R176_HostHeaderInjectionIndicatorRule().EvaluateAsync(NetworkBatch176185Context.At(r))).Matched);
    }
    [Fact] public async Task Udp_Contradiction_Rejected()
    {
        var r=NetworkBatch176185Context.Http("/");r.HttpRequestHeaders+="\r\nX-Forwarded-Host: 127.0.0.1";r.IsTcp=false;r.IsUdp=true;Assert.False((await new R176_HostHeaderInjectionIndicatorRule().EvaluateAsync(NetworkBatch176185Context.At(r))).Matched);
    }
    [Fact] public async Task Duplicate_Id_Does_Not_Match_Again()
    {
        var r=NetworkBatch176185Context.Http("/");r.HttpRequestHeaders+="\r\nX-Forwarded-Host: 127.0.0.1";var rule=new R176_HostHeaderInjectionIndicatorRule();Assert.True((await rule.EvaluateAsync(NetworkBatch176185Context.At(r))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch176185Context.At(r,1))).Matched);
    }
    [Fact] public async Task Forwarded_Host_And_Query_Are_Not_Emitted()
    {
        var r=NetworkBatch176185Context.Http("/?token=SECRET176");r.HttpRequestHeaders+="\r\nX-Forwarded-Host: SECRET176.internal";var x=await new R176_HostHeaderInjectionIndicatorRule().EvaluateAsync(NetworkBatch176185Context.At(r));Assert.True(x.Matched);Assert.DoesNotContain(Assert.Single(x.Events).StructuredEvidence!.Items,i=>i.Value.Contains("SECRET176",StringComparison.Ordinal));
    }
    [Fact] public void Default_Mode_And_Confidence_Floor_Are_Preserved()
    {
        var p=new R176_HostHeaderInjectionIndicatorRule().PrecisionProfile;
        Assert.Equal(74,p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Shadow,p.DefaultMode);
    }
}
