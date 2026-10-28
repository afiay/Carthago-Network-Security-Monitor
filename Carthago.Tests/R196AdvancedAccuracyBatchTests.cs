// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R196AdvancedAccuracyBatchTests
{
    private static TrafficRecord Nx(int i) => NetworkBatch196200Context.Nx($"host.example{i}.com");
    [Fact] public async Task Ten_Independent_Nxdomain_Roots_Qualify()
    {
        var rule = new R196_NxdomainUniqueRootSpikeRule();
        for (var i = 0; i < 9; i++) Assert.False((await rule.EvaluateAsync(NetworkBatch196200Context.At(Nx(i), i))).Matched);
        Assert.True((await rule.EvaluateAsync(NetworkBatch196200Context.At(Nx(9), 9))).Matched);
    }
    [Fact] public async Task Repeated_Subdomains_Of_Single_Root_Are_Not_Ten_Roots()
    {
        var rule = new R196_NxdomainUniqueRootSpikeRule();
        for (var i = 0; i < 12; i++)
            Assert.False((await rule.EvaluateAsync(NetworkBatch196200Context.At(NetworkBatch196200Context.Nx($"host{i}.example.com"), i))).Matched);
    }
    [Fact] public async Task Query_With_Nxdomain_Text_Cannot_Impersonate_Response()
    {
        var r = Nx(1); r.DnsIsResponse = false; r.Info = "NXDOMAIN";
        Assert.False((await new R196_NxdomainUniqueRootSpikeRule().EvaluateAsync(NetworkBatch196200Context.At(r))).Matched);
    }
    [Fact] public async Task Http_Metadata_Contradiction_Is_Rejected()
    {
        var r = Nx(1); r.HttpMethod = "GET";
        Assert.False((await new R196_NxdomainUniqueRootSpikeRule().EvaluateAsync(NetworkBatch196200Context.At(r))).Matched);
    }
    [Fact] public async Task Duplicate_Id_Cannot_Reach_Threshold()
    {
        var rule = new R196_NxdomainUniqueRootSpikeRule(); var r = Nx(1);
        for (var i = 0; i < 15; i++)
            Assert.False((await rule.EvaluateAsync(NetworkBatch196200Context.At(r, i))).Matched);
    }
    [Fact] public async Task Distinct_Client_Windows_Do_Not_Combine()
    {
        var rule = new R196_NxdomainUniqueRootSpikeRule();
        for (var i = 0; i < 9; i++) Assert.False((await rule.EvaluateAsync(NetworkBatch196200Context.At(Nx(i), i))).Matched);
        var other = Nx(9); other.Destination = "10.196.0.99";
        Assert.False((await rule.EvaluateAsync(NetworkBatch196200Context.At(other, 9))).Matched);
    }
    [Fact] public async Task Distinct_Resolver_Windows_Do_Not_Combine()
    {
        var rule = new R196_NxdomainUniqueRootSpikeRule();
        for (var i = 0; i < 9; i++) Assert.False((await rule.EvaluateAsync(NetworkBatch196200Context.At(Nx(i), i))).Matched);
        var other = Nx(9); other.Source = "1.1.1.1";
        Assert.False((await rule.EvaluateAsync(NetworkBatch196200Context.At(other, 9))).Matched);
    }
    [Fact] public async Task Out_Of_Order_Response_Does_Not_Advance_Window()
    {
        var rule = new R196_NxdomainUniqueRootSpikeRule();
        Assert.False((await rule.EvaluateAsync(NetworkBatch196200Context.At(Nx(0), 10))).Matched);
        Assert.False((await rule.EvaluateAsync(NetworkBatch196200Context.At(Nx(1), 5))).Matched);
    }
    [Fact] public async Task Root_Identifier_Is_Redacted()
    {
        var rule = new R196_NxdomainUniqueRootSpikeRule();
        Carthago.Engine.Rules.RuleEvaluationResult? last = null;
        for (var i = 0; i < 10; i++) last = await rule.EvaluateAsync(NetworkBatch196200Context.At(Nx(i), i));
        Assert.True(last!.Matched);
        Assert.DoesNotContain(Assert.Single(last.Events).StructuredEvidence!.Items, e => e.Value.Contains("example9", StringComparison.Ordinal));
    }
    [Fact] public void Existing_Shadow_And_Confidence_Floor_Remain()
    {
        var p = new R196_NxdomainUniqueRootSpikeRule().PrecisionProfile;
        Assert.Equal(74, p.MinimumConfidence); Assert.Equal(RuleRuntimeMode.Shadow, p.DefaultMode);
    }
}
