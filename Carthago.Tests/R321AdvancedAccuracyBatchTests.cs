// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R321AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch321325Context.Sample();
    private static async Task<RuleEvaluationResult> Evaluate(TrafficRecord r, double seconds = 0)
        => await new R321_GmailAPIBulkMessageReadRule().EvaluateAsync(NetworkBatch321325Context.At(r, seconds));
    private static async Task<bool> Hit(TrafficRecord r, double seconds = 0)
        => (await Evaluate(r, seconds)).Matched;
    [Fact] public async Task Apparent_Evidence_1_Is_Not_Verified_Outcome() { var r=Sample();r.HttpHost="gmail.googleapis.com";Assert.False(await Hit(r)); }
    [Fact] public async Task Apparent_Evidence_2_Is_Not_Verified_Outcome() { var r=Sample();r.HttpUri="/gmail/v1/users/me/messages";Assert.False(await Hit(r)); }
    [Fact] public async Task Apparent_Evidence_3_Is_Not_Verified_Outcome() { var r=Sample();r.HttpUri="/gmail/v1/users/me/messages/id";Assert.False(await Hit(r)); }
    [Fact] public async Task Apparent_Evidence_4_Is_Not_Verified_Outcome() { var r=Sample();r.HttpMethod="POST";r.HttpUri="/gmail/v1/users/me/messages/batchModify";Assert.False(await Hit(r)); }
    [Fact] public async Task Apparent_Evidence_5_Is_Not_Verified_Outcome() { var r=Sample();r.Info="R321 bulk read succeeded";Assert.False(await Hit(r)); }
    [Fact] public async Task Apparent_Evidence_6_Is_Not_Verified_Outcome() { var r=Sample();r.Sni="gmail.googleapis.com";r.ApplicationProtocol="TLS";Assert.False(await Hit(r)); }
    [Fact] public async Task Descriptor_Info_Spoof_Is_Not_Trusted() { var r=Sample();r.Info="R321 confirmed";Assert.False(await Hit(r)); }
    [Fact] public async Task Duplicate_Packet_Cannot_Accumulate_Outcome() { var r=Sample();var rule=new R321_GmailAPIBulkMessageReadRule();Assert.False((await rule.EvaluateAsync(NetworkBatch321325Context.At(r))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch321325Context.At(r,1))).Matched); }
    [Fact] public async Task Out_Of_Order_Cannot_Accumulate_Outcome() { var r=Sample();var rule=new R321_GmailAPIBulkMessageReadRule();Assert.False((await rule.EvaluateAsync(NetworkBatch321325Context.At(r,30))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch321325Context.At(r,1))).Matched); }
    [Fact] public async Task Independent_Source_Cannot_Borrow_Outcome() { var r=Sample();var rule=new R321_GmailAPIBulkMessageReadRule();Assert.False((await rule.EvaluateAsync(NetworkBatch321325Context.At(r))).Matched);r.Source="185.220.100.253";r.Id=Guid.NewGuid();Assert.False((await rule.EvaluateAsync(NetworkBatch321325Context.At(r,2))).Matched); }
    [Fact] public async Task Missing_Source_Fails_Closed() { var r=Sample();r.Source=null;Assert.False(await Hit(r)); }
    [Fact] public async Task Contradictory_Udp_Http_Fails_Closed() { var r=Sample();r.IsTcp=false;r.IsUdp=true;Assert.False(await Hit(r)); }
    [Fact] public async Task Sensitive_Headers_And_Query_Are_Not_Emitted() { var r=Sample();r.HttpUri="/?access_token=private-secret";r.HttpRequestHeaders="Authorization: Bearer private-secret";var result=await Evaluate(r);Assert.False(result.Matched);Assert.Empty(result.Events); }
    [Fact] public void Confidence_Threshold_And_Alert_Mode_Are_Unchanged() { var p=new R321_GmailAPIBulkMessageReadRule().PrecisionProfile;Assert.Equal(78,p.MinimumConfidence);Assert.Equal(5,p.Threshold);Assert.Equal(RuleRuntimeMode.Alert,p.DefaultMode); }
}
