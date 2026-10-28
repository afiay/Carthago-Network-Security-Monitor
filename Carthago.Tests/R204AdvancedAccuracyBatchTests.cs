// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R204AdvancedAccuracyBatchTests
{
    private static TrafficRecord S() => NetworkBatch201205Context.State();
    private static async Task<bool> Hit(TrafficRecord r) => (await new R204_TerraformStateFileAccessRule().EvaluateAsync(NetworkBatch201205Context.At(r))).Matched;
    [Fact] public async Task Direct_External_Tfstate_Request_Qualifies() => Assert.True(await Hit(S()));
    [Fact] public async Task Terraform_Documentation_Route_Excluded()
    {
        var r = S(); r.HttpUri = "/docs/terraform.tfstate";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Query_Only_Tfstate_Mention_Not_File_Path()
    {
        var r = S(); r.HttpUri = "/search?q=terraform.tfstate";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Internal_Destination_Not_External_State_Transfer()
    {
        var r = S(); r.Destination = "10.201.0.20";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Untrusted_Info_Claim_Not_Parsed_State_Request()
    {
        var r = S(); r.HttpUri = "/health"; r.Info = "download terraform.tfstate";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Duplicate_Packet_Id_Rejected()
    {
        var rule = new R204_TerraformStateFileAccessRule(); var r = S();
        Assert.True((await rule.EvaluateAsync(NetworkBatch201205Context.At(r))).Matched);
        Assert.False((await rule.EvaluateAsync(NetworkBatch201205Context.At(r, 1))).Matched);
    }
    [Fact] public async Task Out_Of_Order_State_Request_Rejected()
    {
        var rule = new R204_TerraformStateFileAccessRule();
        Assert.True((await rule.EvaluateAsync(NetworkBatch201205Context.At(S(), 10))).Matched);
        Assert.False((await rule.EvaluateAsync(NetworkBatch201205Context.At(S(), 5))).Matched);
    }
    [Fact] public async Task State_Path_And_Host_Are_Redacted()
    {
        var x = await new R204_TerraformStateFileAccessRule().EvaluateAsync(NetworkBatch201205Context.At(S()));
        Assert.True(x.Matched);
        var evt = Assert.Single(x.Events);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items,
            e => e.Value.Contains("terraform.tfstate", StringComparison.Ordinal) || e.Value.Contains("state.external.example", StringComparison.Ordinal));
        Assert.Equal("[REDACTED]", evt.DestinationHost);
        Assert.DoesNotContain("state.external.example", evt.Evidence ?? "", StringComparison.Ordinal);
    }
    [Fact] public void Alert_And_Confidence_Floor_Unchanged()
    {
        var p = new R204_TerraformStateFileAccessRule().PrecisionProfile;
        Assert.Equal(82, p.MinimumConfidence); Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
