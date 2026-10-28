// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R328AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch321325Context.Sample();
    private static async Task<RuleEvaluationResult> Evaluate(TrafficRecord r, double seconds = 0)
        => await new R328_TeamsWebhookAbuseIndicatorRule().EvaluateAsync(NetworkBatch321325Context.At(r, seconds));
    [Theory]
    [InlineData("/webhook")]
    [InlineData("/IncomingWebhook")]
    [InlineData("/connector")]
    [InlineData("/office/webhook")]
    [InlineData("/teams/webhook")]
    [InlineData("/webhook/123")]
    public async Task Request_Path_Without_Trusted_Result_Is_Insufficient(string path)
    {
        var r=Sample();r.HttpUri=path;r.HttpMethod="POST";Assert.False((await Evaluate(r)).Matched);
    }
    [Fact] public async Task Descriptor_Info_Spoof_Fails_Closed() { var r=Sample();r.Info="R328 matched";Assert.False((await Evaluate(r)).Matched); }
    [Fact] public async Task Duplicate_Fails_Closed() { var r=Sample();var rule=new R328_TeamsWebhookAbuseIndicatorRule();Assert.False((await rule.EvaluateAsync(NetworkBatch321325Context.At(r))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch321325Context.At(r,1))).Matched); }
    [Fact] public async Task Out_Of_Order_Fails_Closed() { var r=Sample();var rule=new R328_TeamsWebhookAbuseIndicatorRule();Assert.False((await rule.EvaluateAsync(NetworkBatch321325Context.At(r,30))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch321325Context.At(r,1))).Matched); }
    [Fact] public async Task Independent_Source_Fails_Closed() { var r=Sample();var rule=new R328_TeamsWebhookAbuseIndicatorRule();Assert.False((await rule.EvaluateAsync(NetworkBatch321325Context.At(r))).Matched);r.Source="185.220.100.253";r.Id=Guid.NewGuid();Assert.False((await rule.EvaluateAsync(NetworkBatch321325Context.At(r,2))).Matched); }
    [Fact] public async Task Missing_Source_Fails_Closed() { var r=Sample();r.Source=null;Assert.False((await Evaluate(r)).Matched); }
    [Fact] public async Task Contradictory_Udp_Http_Fails_Closed() { var r=Sample();r.IsTcp=false;r.IsUdp=true;Assert.False((await Evaluate(r)).Matched); }
    [Fact] public async Task Secrets_Are_Not_Emitted() { var r=Sample();r.HttpUri="/?access_token=private-secret";r.HttpRequestHeaders="Authorization: Bearer private-secret";var result=await Evaluate(r);Assert.False(result.Matched);Assert.Empty(result.Events); }
    [Fact] public void Confidence_Threshold_Mode_Preserved() { var p=new R328_TeamsWebhookAbuseIndicatorRule().PrecisionProfile;Assert.Equal(78,p.MinimumConfidence);Assert.Equal(1,p.Threshold);Assert.Equal(RuleRuntimeMode.Alert,p.DefaultMode); }
}
