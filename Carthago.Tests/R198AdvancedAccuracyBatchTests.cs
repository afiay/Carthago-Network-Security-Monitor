// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R198AdvancedAccuracyBatchTests
{
    private static TrafficRecord M() => NetworkBatch196200Context.Imds("aws");
    private static async Task<bool> Hit(TrafficRecord r) => (await new R198_AwsMetadataCredentialRetrievalRule().EvaluateAsync(NetworkBatch196200Context.At(r))).Matched;
    [Fact] public async Task Typed_Imds_Credential_Request_Qualifies() => Assert.True(await Hit(M()));
    [Fact] public async Task Nearby_Benign_Metadata_Route_Does_Not_Qualify()
    {
        var r = M(); r.HttpUri = "/latest/dynamic/instance-identity/document";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Host_Spoof_On_External_Destination_Cannot_Prove_Imds()
    {
        var r = M(); r.Destination = "8.8.8.8";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Contradictory_Host_Header_Is_Rejected()
    {
        var r = M(); r.HttpRequestHeaders = "Host: attacker.example.net";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Missing_Required_Attribution_Is_Not_Proof()
    {
        var r = M(); r.HttpRequestHeaders = ""; r.HttpHost = "attacker.example.net";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Packet_Info_Claim_Cannot_Replace_Parsed_Http_Method()
    {
        var r = M(); r.HttpMethod = null; r.Info = "metadata credential retrieval successful";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Approved_Guest_Agent_Activity_Remains_Suppressed()
    {
        var r = M(); r.ProcessName = "cloud-init";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Contradictory_Tls_Transport_Is_Not_Cleartext_Imds()
    {
        var r = M(); r.Protocol = "HTTPS"; r.ApplicationProtocol = "HTTPS";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Duplicate_Packet_Id_Is_Rejected()
    {
        var rule = new R198_AwsMetadataCredentialRetrievalRule(); var r = M();
        Assert.True((await rule.EvaluateAsync(NetworkBatch196200Context.At(r))).Matched);
        Assert.False((await rule.EvaluateAsync(NetworkBatch196200Context.At(r, 1))).Matched);
    }
    [Fact] public async Task Out_Of_Order_Observation_Is_Not_Second_Event()
    {
        var rule = new R198_AwsMetadataCredentialRetrievalRule();
        Assert.True((await rule.EvaluateAsync(NetworkBatch196200Context.At(M(), 10))).Matched);
        Assert.False((await rule.EvaluateAsync(NetworkBatch196200Context.At(M(), 5))).Matched);
    }
    [Fact] public async Task Aws_Imds_Token_Endpoint_Alone_Is_Not_Credential_Retrieval()
    {
        var r = M(); r.HttpUri = "/latest/api/token"; r.HttpMethod = "PUT";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Sensitive_Imds_Request_Path_Is_Redacted()
    {
        var x = await new R198_AwsMetadataCredentialRetrievalRule().EvaluateAsync(NetworkBatch196200Context.At(M()));
        Assert.True(x.Matched);
        Assert.DoesNotContain(Assert.Single(x.Events).StructuredEvidence!.Items,
            e => e.Value.Contains("role-a", StringComparison.Ordinal));
    }
    [Fact] public void Existing_Alert_And_Confidence_Floor_Remain()
    {
        var profile = new R198_AwsMetadataCredentialRetrievalRule().PrecisionProfile;
        Assert.Equal(88, profile.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Alert, profile.DefaultMode);
    }
}
