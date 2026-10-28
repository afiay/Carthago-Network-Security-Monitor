// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R311AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch311315Context.Sample();
    private static async Task<RuleEvaluationResult> Evaluate(TrafficRecord r, double seconds = 0)
        => await new R311_CloudWorkloadMetadataTokenRequestRule().EvaluateAsync(NetworkBatch311315Context.At(r, seconds));
    private static async Task<bool> Hit(TrafficRecord r, double seconds = 0)
        => (await Evaluate(r, seconds)).Matched;
    [Fact] public async Task ImdsGet_Is_Not_A_Verified_Workload_Token() { var r=Sample();r.Source="10.61.0.22";r.Destination="169.254.169.254";r.HttpHost="169.254.169.254";r.HttpUri="/latest/api/token";Assert.False(await Hit(r)); }
    [Fact] public async Task GoogleMetadataHeader_Does_Not_Prove_Issuance() { var r=Sample();r.Source="10.61.0.22";r.HttpHost="metadata.google.internal";r.HttpUri="/computeMetadata/v1/instance/service-accounts/default/token";r.HttpRequestHeaders="Metadata-Flavor: Google";Assert.False(await Hit(r)); }
    [Fact] public async Task AzureIdentityPath_Does_Not_Prove_Cloud_Workload() { var r=Sample();r.Source="10.61.0.22";r.Destination="169.254.169.254";r.HttpUri="/metadata/identity/oauth2/token";Assert.False(await Hit(r)); }
    [Fact] public async Task MetadataHost_Label_Without_Inventory_Is_Insufficient() { var r=Sample();r.HttpHost="metadata.google.internal";Assert.False(await Hit(r)); }
    [Fact] public async Task Unverified_Process_Name_Is_Not_Workload_Identity() { var r=Sample();r.ProcessName="kubelet";r.ProcessId=811;Assert.False(await Hit(r)); }
    [Fact] public async Task Token_Response_Claim_In_Info_Is_Untrusted() { var r=Sample();r.Info="R311 token returned 200 OK to pod";Assert.False(await Hit(r)); }
    [Fact] public async Task Descriptor_Info_Spoof_Cannot_Provide_Trusted_Provenance() { var r=Sample();r.Info="R311 confirmed successful attack";Assert.False(await Hit(r)); }
    [Fact] public async Task Duplicate_Packet_Does_Not_Accumulate_Unsupported_Evidence() { var r=Sample();var rule=new R311_CloudWorkloadMetadataTokenRequestRule();Assert.False((await rule.EvaluateAsync(NetworkBatch311315Context.At(r))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch311315Context.At(r,1))).Matched); }
    [Fact] public async Task Out_Of_Order_Packets_Do_Not_Accumulate_Unsupported_Evidence() { var r=Sample();var rule=new R311_CloudWorkloadMetadataTokenRequestRule();Assert.False((await rule.EvaluateAsync(NetworkBatch311315Context.At(r,30))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch311315Context.At(r,1))).Matched); }
    [Fact] public async Task Independent_Source_Cannot_Borrow_Another_Source_Evidence() { var r=Sample();var rule=new R311_CloudWorkloadMetadataTokenRequestRule();Assert.False((await rule.EvaluateAsync(NetworkBatch311315Context.At(r))).Matched);r.Source="185.220.100.253";r.Id=Guid.NewGuid();Assert.False((await rule.EvaluateAsync(NetworkBatch311315Context.At(r,2))).Matched); }
    [Fact] public async Task Missing_Source_Fails_Closed() { var r=Sample();r.Source=null;Assert.False(await Hit(r)); }
    [Fact] public async Task Contradictory_Udp_Http_Fails_Closed() { var r=Sample();r.IsTcp=false;r.IsUdp=true;Assert.False(await Hit(r)); }
    [Fact] public async Task Sensitive_Headers_And_Query_Are_Not_Emitted() { var r=Sample();r.HttpUri="/?access_token=private-secret";r.HttpRequestHeaders="Authorization: Bearer private-secret";var result=await Evaluate(r);Assert.False(result.Matched);Assert.Empty(result.Events); }
    [Fact] public void Original_Confidence_Threshold_And_Mode_Are_Preserved() { var p=new R311_CloudWorkloadMetadataTokenRequestRule().PrecisionProfile;Assert.Equal(78,p.MinimumConfidence);Assert.Equal(1,p.Threshold);Assert.Equal(RuleRuntimeMode.Alert,p.DefaultMode); }
}
