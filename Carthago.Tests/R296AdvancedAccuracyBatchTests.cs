// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R296AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch296300Context.Sample();
    private static async Task<RuleEvaluationResult> Evaluate(TrafficRecord r, double seconds = 0)
        => await new R296_KubernetesPortForwardAbuseIndicatorRule().EvaluateAsync(NetworkBatch296300Context.At(r, seconds));
    private static async Task<bool> Hit(TrafficRecord r, double seconds = 0)
        => (await Evaluate(r, seconds)).Matched;
    [Fact] public async Task PodPortForwardPost_Does_Not_Prove_The_Rule_Outcome() { var r=Sample();r.HttpMethod="POST";r.HttpUri="/api/v1/namespaces/prod/pods/app/portforward"; Assert.False(await Hit(r)); }
    [Fact] public async Task PodPortForwardGet_Does_Not_Prove_The_Rule_Outcome() { var r=Sample();r.HttpMethod="GET";r.HttpUri="/api/v1/namespaces/prod/pods/app/portforward"; Assert.False(await Hit(r)); }
    [Fact] public async Task KubeletPort_Does_Not_Prove_The_Rule_Outcome() { var r=Sample();r.DestinationPort=10250; Assert.False(await Hit(r)); }
    [Fact] public async Task ApiServerPort_Does_Not_Prove_The_Rule_Outcome() { var r=Sample();r.DestinationPort=6443; Assert.False(await Hit(r)); }
    [Fact] public async Task UpgradeHeader_Does_Not_Prove_The_Rule_Outcome() { var r=Sample();r.HttpRequestHeaders="Connection: Upgrade\r\nUpgrade: SPDY/3.1"; Assert.False(await Hit(r)); }
    [Fact] public async Task PortForwardInfoClaim_Does_Not_Prove_The_Rule_Outcome() { var r=Sample();r.Info="kubectl port-forward abused successfully"; Assert.False(await Hit(r)); }
    [Fact] public async Task Descriptor_Info_Spoof_Cannot_Provide_Trusted_Provenance() { var r=Sample();r.Info="R296 confirmed successful attack";Assert.False(await Hit(r)); }
    [Fact] public async Task Duplicate_Packet_Does_Not_Accumulate_Unsupported_Evidence() { var r=Sample();var rule=new R296_KubernetesPortForwardAbuseIndicatorRule();Assert.False((await rule.EvaluateAsync(NetworkBatch296300Context.At(r))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch296300Context.At(r,1))).Matched); }
    [Fact] public async Task Out_Of_Order_Packets_Do_Not_Accumulate_Unsupported_Evidence() { var r=Sample();var rule=new R296_KubernetesPortForwardAbuseIndicatorRule();Assert.False((await rule.EvaluateAsync(NetworkBatch296300Context.At(r,30))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch296300Context.At(r,1))).Matched); }
    [Fact] public async Task Independent_Source_Cannot_Borrow_Another_Source_Evidence() { var r=Sample();var rule=new R296_KubernetesPortForwardAbuseIndicatorRule();Assert.False((await rule.EvaluateAsync(NetworkBatch296300Context.At(r))).Matched);r.Source="185.220.100.253";r.Id=Guid.NewGuid();Assert.False((await rule.EvaluateAsync(NetworkBatch296300Context.At(r,2))).Matched); }
    [Fact] public async Task Missing_Source_Fails_Closed() { var r=Sample();r.Source=null;Assert.False(await Hit(r)); }
    [Fact] public async Task Contradictory_Udp_Http_Fails_Closed() { var r=Sample();r.IsTcp=false;r.IsUdp=true;Assert.False(await Hit(r)); }
    [Fact] public async Task Sensitive_Headers_And_Query_Are_Not_Emitted() { var r=Sample();r.HttpUri="/?access_token=private-secret";r.HttpRequestHeaders="Authorization: Bearer private-secret";var result=await Evaluate(r);Assert.False(result.Matched);Assert.Empty(result.Events); }
    [Fact] public void Original_Confidence_Threshold_And_Mode_Are_Preserved() { var p=new R296_KubernetesPortForwardAbuseIndicatorRule().PrecisionProfile;Assert.Equal(78,p.MinimumConfidence);Assert.Equal(1,p.Threshold);Assert.Equal(RuleRuntimeMode.Alert,p.DefaultMode); }
}
