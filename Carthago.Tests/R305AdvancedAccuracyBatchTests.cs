// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R305AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch301305Context.Sample();
    private static async Task<RuleEvaluationResult> Evaluate(TrafficRecord r, double seconds = 0)
        => await new R305_ImageRegistryPushFromWorkstationRule().EvaluateAsync(NetworkBatch301305Context.At(r, seconds));
    private static async Task<bool> Hit(TrafficRecord r, double seconds = 0)
        => (await Evaluate(r, seconds)).Matched;
    [Fact] public async Task BlobUploadPatch_Does_Not_Prove_The_Rule_Outcome() { var r=Sample();r.HttpMethod="PATCH";r.HttpUri="/v2/app/blobs/uploads/abc";Assert.False(await Hit(r)); }
    [Fact] public async Task ManifestPut_Does_Not_Prove_The_Rule_Outcome() { var r=Sample();r.HttpMethod="PUT";r.HttpUri="/v2/app/manifests/latest";Assert.False(await Hit(r)); }
    [Fact] public async Task UploadPost_Does_Not_Prove_The_Rule_Outcome() { var r=Sample();r.HttpMethod="POST";r.HttpUri="/v2/app/blobs/uploads/";Assert.False(await Hit(r)); }
    [Fact] public async Task RegistryHostOnly_Does_Not_Prove_The_Rule_Outcome() { var r=Sample();r.HttpHost="registry.example.net";Assert.False(await Hit(r)); }
    [Fact] public async Task WorkstationProcessClaim_Does_Not_Prove_The_Rule_Outcome() { var r=Sample();r.ProcessName="docker.exe";r.ProcessId=421;Assert.False(await Hit(r)); }
    [Fact] public async Task PushInfoClaim_Does_Not_Prove_The_Rule_Outcome() { var r=Sample();r.Info="workstation pushed image successfully";Assert.False(await Hit(r)); }
    [Fact] public async Task Descriptor_Info_Spoof_Cannot_Provide_Trusted_Provenance() { var r=Sample();r.Info="R305 confirmed successful attack";Assert.False(await Hit(r)); }
    [Fact] public async Task Duplicate_Packet_Does_Not_Accumulate_Unsupported_Evidence() { var r=Sample();var rule=new R305_ImageRegistryPushFromWorkstationRule();Assert.False((await rule.EvaluateAsync(NetworkBatch301305Context.At(r))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch301305Context.At(r,1))).Matched); }
    [Fact] public async Task Out_Of_Order_Packets_Do_Not_Accumulate_Unsupported_Evidence() { var r=Sample();var rule=new R305_ImageRegistryPushFromWorkstationRule();Assert.False((await rule.EvaluateAsync(NetworkBatch301305Context.At(r,30))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch301305Context.At(r,1))).Matched); }
    [Fact] public async Task Independent_Source_Cannot_Borrow_Another_Source_Evidence() { var r=Sample();var rule=new R305_ImageRegistryPushFromWorkstationRule();Assert.False((await rule.EvaluateAsync(NetworkBatch301305Context.At(r))).Matched);r.Source="185.220.100.253";r.Id=Guid.NewGuid();Assert.False((await rule.EvaluateAsync(NetworkBatch301305Context.At(r,2))).Matched); }
    [Fact] public async Task Missing_Source_Fails_Closed() { var r=Sample();r.Source=null;Assert.False(await Hit(r)); }
    [Fact] public async Task Contradictory_Udp_Http_Fails_Closed() { var r=Sample();r.IsTcp=false;r.IsUdp=true;Assert.False(await Hit(r)); }
    [Fact] public async Task Sensitive_Headers_And_Query_Are_Not_Emitted() { var r=Sample();r.HttpUri="/?access_token=private-secret";r.HttpRequestHeaders="Authorization: Bearer private-secret";var result=await Evaluate(r);Assert.False(result.Matched);Assert.Empty(result.Events); }
    [Fact] public void Original_Confidence_Threshold_And_Mode_Are_Preserved() { var p=new R305_ImageRegistryPushFromWorkstationRule().PrecisionProfile;Assert.Equal(78,p.MinimumConfidence);Assert.Equal(1,p.Threshold);Assert.Equal(RuleRuntimeMode.Alert,p.DefaultMode); }
}
