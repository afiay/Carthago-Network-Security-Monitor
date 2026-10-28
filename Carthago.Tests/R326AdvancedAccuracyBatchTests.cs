// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R326AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch321325Context.Sample();
    private static async Task<RuleEvaluationResult> Evaluate(TrafficRecord r, double seconds = 0)
        => await new R326_DMARCSPFDKIMReconQueryBurstRule().EvaluateAsync(NetworkBatch321325Context.At(r, seconds));
    [Theory]
    [InlineData("_dmarc.example.net")]
    [InlineData("selector1._domainkey.example.net")]
    [InlineData("spf.example.net")]
    [InlineData("mail.example.net")]
    [InlineData("example.net")]
    [InlineData("_domainkey.example.net")]
    public async Task Dns_Indicator_Without_Trusted_Attribution_Is_Insufficient(string label)
    {
        var r=Sample();r.Info=label;r.ApplicationProtocol="DNS";r.IsTcp=false;r.IsUdp=true;r.Protocol="UDP";r.DestinationPort=53;
        Assert.False((await Evaluate(r)).Matched);
    }
    [Fact] public async Task Descriptor_Info_Spoof_Fails_Closed() { var r=Sample();r.Info="R326 matched";Assert.False((await Evaluate(r)).Matched); }
    [Fact] public async Task Duplicate_Fails_Closed() { var r=Sample();var rule=new R326_DMARCSPFDKIMReconQueryBurstRule();Assert.False((await rule.EvaluateAsync(NetworkBatch321325Context.At(r))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch321325Context.At(r,1))).Matched); }
    [Fact] public async Task Out_Of_Order_Fails_Closed() { var r=Sample();var rule=new R326_DMARCSPFDKIMReconQueryBurstRule();Assert.False((await rule.EvaluateAsync(NetworkBatch321325Context.At(r,30))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch321325Context.At(r,1))).Matched); }
    [Fact] public async Task Independent_Source_Fails_Closed() { var r=Sample();var rule=new R326_DMARCSPFDKIMReconQueryBurstRule();Assert.False((await rule.EvaluateAsync(NetworkBatch321325Context.At(r))).Matched);r.Source="185.220.100.253";r.Id=Guid.NewGuid();Assert.False((await rule.EvaluateAsync(NetworkBatch321325Context.At(r,2))).Matched); }
    [Fact] public async Task Missing_Source_Fails_Closed() { var r=Sample();r.Source=null;Assert.False((await Evaluate(r)).Matched); }
    [Fact] public async Task Contradictory_Udp_Http_Fails_Closed() { var r=Sample();r.IsTcp=false;r.IsUdp=true;Assert.False((await Evaluate(r)).Matched); }
    [Fact] public async Task Secrets_Are_Not_Emitted() { var r=Sample();r.HttpUri="/?access_token=private-secret";r.HttpRequestHeaders="Authorization: Bearer private-secret";var result=await Evaluate(r);Assert.False(result.Matched);Assert.Empty(result.Events); }
    [Fact] public void Confidence_Threshold_Mode_Preserved() { var p=new R326_DMARCSPFDKIMReconQueryBurstRule().PrecisionProfile;Assert.Equal(74,p.MinimumConfidence);Assert.Equal(5,p.Threshold);Assert.Equal(RuleRuntimeMode.Alert,p.DefaultMode); }
}
