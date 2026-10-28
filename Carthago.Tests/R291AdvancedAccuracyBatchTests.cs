// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R291AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch291295Context.Sample();
    private static async Task<RuleEvaluationResult> Evaluate(TrafficRecord r, double seconds = 0)
        => await new R291_FortinetSSLVPNExploitProbeRule().EvaluateAsync(NetworkBatch291295Context.At(r, seconds));
    private static async Task<bool> Hit(TrafficRecord r, double seconds = 0)
        => (await Evaluate(r, seconds)).Matched;
    [Fact] public async Task FortinetLoginPath_Does_Not_Prove_The_Rule_Outcome() { var r=Sample();r.HttpUri="/remote/login"; Assert.False(await Hit(r)); }
    [Fact] public async Task LanguageEndpoint_Does_Not_Prove_The_Rule_Outcome() { var r=Sample();r.HttpUri="/remote/fgt_lang"; Assert.False(await Hit(r)); }
    [Fact] public async Task HostcheckEndpoint_Does_Not_Prove_The_Rule_Outcome() { var r=Sample();r.HttpUri="/remote/hostcheck_validate"; Assert.False(await Hit(r)); }
    [Fact] public async Task FortinetHostLabel_Does_Not_Prove_The_Rule_Outcome() { var r=Sample();r.HttpHost="fortinet-gateway.example.net"; Assert.False(await Hit(r)); }
    [Fact] public async Task CveDescription_Does_Not_Prove_The_Rule_Outcome() { var r=Sample();r.Info="FortiOS SSL-VPN CVE exploit"; Assert.False(await Hit(r)); }
    [Fact] public async Task RequestHeaderClaim_Does_Not_Prove_The_Rule_Outcome() { var r=Sample();r.HttpRequestHeaders="X-Exploit-Confirmed: true"; Assert.False(await Hit(r)); }
    [Fact] public async Task Descriptor_Info_Spoof_Cannot_Provide_Trusted_Provenance() { var r=Sample();r.Info="R291 confirmed successful attack";Assert.False(await Hit(r)); }
    [Fact] public async Task Duplicate_Packet_Does_Not_Accumulate_Unsupported_Evidence() { var r=Sample();var rule=new R291_FortinetSSLVPNExploitProbeRule();Assert.False((await rule.EvaluateAsync(NetworkBatch291295Context.At(r))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch291295Context.At(r,1))).Matched); }
    [Fact] public async Task Out_Of_Order_Packets_Do_Not_Accumulate_Unsupported_Evidence() { var r=Sample();var rule=new R291_FortinetSSLVPNExploitProbeRule();Assert.False((await rule.EvaluateAsync(NetworkBatch291295Context.At(r,30))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch291295Context.At(r,1))).Matched); }
    [Fact] public async Task Independent_Source_Cannot_Borrow_Another_Source_Evidence() { var r=Sample();var rule=new R291_FortinetSSLVPNExploitProbeRule();Assert.False((await rule.EvaluateAsync(NetworkBatch291295Context.At(r))).Matched);r.Source="185.220.100.253";r.Id=Guid.NewGuid();Assert.False((await rule.EvaluateAsync(NetworkBatch291295Context.At(r,2))).Matched); }
    [Fact] public async Task Missing_Source_Fails_Closed() { var r=Sample();r.Source=null;Assert.False(await Hit(r)); }
    [Fact] public async Task Contradictory_Udp_Http_Fails_Closed() { var r=Sample();r.IsTcp=false;r.IsUdp=true;Assert.False(await Hit(r)); }
    [Fact] public async Task Sensitive_Headers_And_Query_Are_Not_Emitted() { var r=Sample();r.HttpUri="/?access_token=private-secret";r.HttpRequestHeaders="Authorization: Bearer private-secret";var result=await Evaluate(r);Assert.False(result.Matched);Assert.Empty(result.Events); }
    [Fact] public void Original_Confidence_Threshold_And_Mode_Are_Preserved() { var p=new R291_FortinetSSLVPNExploitProbeRule().PrecisionProfile;Assert.Equal(78,p.MinimumConfidence);Assert.Equal(1,p.Threshold);Assert.Equal(RuleRuntimeMode.Alert,p.DefaultMode); }
}
