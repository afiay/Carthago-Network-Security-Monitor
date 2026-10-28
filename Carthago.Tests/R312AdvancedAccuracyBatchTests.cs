// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R312AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch311315Context.Sample();
    private static async Task<RuleEvaluationResult> Evaluate(TrafficRecord r, double seconds = 0)
        => await new R312_KubernetesNetworkPolicyBypassIndicatorRule().EvaluateAsync(NetworkBatch311315Context.At(r, seconds));
    private static async Task<bool> Hit(TrafficRecord r, double seconds = 0)
        => (await Evaluate(r, seconds)).Matched;
    [Fact] public async Task Pod_To_Pod_Flow_Is_Not_Policy_Bypass() { var r=Sample();r.Source="10.61.0.22";r.Destination="10.61.0.23";Assert.False(await Hit(r)); }
    [Fact] public async Task Different_Subnet_Is_Not_Approved_Segment() { var r=Sample();r.Source="10.61.0.22";r.Destination="10.62.0.23";Assert.False(await Hit(r)); }
    [Fact] public async Task Direct_Pod_IP_Is_Not_Enforcement_Result() { var r=Sample();r.Destination="10.61.0.23";r.DestinationPort=8080;Assert.False(await Hit(r)); }
    [Fact] public async Task Cni_Deny_Label_In_Info_Is_Untrusted() { var r=Sample();r.Info="CNI DENY bypassed by pod";Assert.False(await Hit(r)); }
    [Fact] public async Task Kubernetes_Hostname_Is_Not_Policy_Inventory() { var r=Sample();r.HttpHost="kubernetes.default.svc";Assert.False(await Hit(r)); }
    [Fact] public async Task Repeated_Flow_Without_Decisions_Cannot_Match() { var r=Sample();r.Info="allowed despite deny";r.Length=1024;Assert.False(await Hit(r)); }
    [Fact] public async Task Descriptor_Info_Spoof_Cannot_Provide_Trusted_Provenance() { var r=Sample();r.Info="R312 confirmed successful attack";Assert.False(await Hit(r)); }
    [Fact] public async Task Duplicate_Packet_Does_Not_Accumulate_Unsupported_Evidence() { var r=Sample();var rule=new R312_KubernetesNetworkPolicyBypassIndicatorRule();Assert.False((await rule.EvaluateAsync(NetworkBatch311315Context.At(r))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch311315Context.At(r,1))).Matched); }
    [Fact] public async Task Out_Of_Order_Packets_Do_Not_Accumulate_Unsupported_Evidence() { var r=Sample();var rule=new R312_KubernetesNetworkPolicyBypassIndicatorRule();Assert.False((await rule.EvaluateAsync(NetworkBatch311315Context.At(r,30))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch311315Context.At(r,1))).Matched); }
    [Fact] public async Task Independent_Source_Cannot_Borrow_Another_Source_Evidence() { var r=Sample();var rule=new R312_KubernetesNetworkPolicyBypassIndicatorRule();Assert.False((await rule.EvaluateAsync(NetworkBatch311315Context.At(r))).Matched);r.Source="185.220.100.253";r.Id=Guid.NewGuid();Assert.False((await rule.EvaluateAsync(NetworkBatch311315Context.At(r,2))).Matched); }
    [Fact] public async Task Missing_Source_Fails_Closed() { var r=Sample();r.Source=null;Assert.False(await Hit(r)); }
    [Fact] public async Task Contradictory_Udp_Http_Fails_Closed() { var r=Sample();r.IsTcp=false;r.IsUdp=true;Assert.False(await Hit(r)); }
    [Fact] public async Task Sensitive_Headers_And_Query_Are_Not_Emitted() { var r=Sample();r.HttpUri="/?access_token=private-secret";r.HttpRequestHeaders="Authorization: Bearer private-secret";var result=await Evaluate(r);Assert.False(result.Matched);Assert.Empty(result.Events); }
    [Fact] public void Original_Confidence_Threshold_And_Mode_Are_Preserved() { var p=new R312_KubernetesNetworkPolicyBypassIndicatorRule().PrecisionProfile;Assert.Equal(78,p.MinimumConfidence);Assert.Equal(3,p.Threshold);Assert.Equal(RuleRuntimeMode.Alert,p.DefaultMode); }
}
