// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R186AdvancedAccuracyBatchTests
{
    private static RuleEvaluationContext At(TrafficRecord r, int seconds = 0) => NetworkBatch186195Context.At(r, seconds);
    private static TrafficRecord Q(string name, string type = "A") => NetworkBatch186195Context.Query(name, type);

    [Fact] public async Task Eight_Distinct_Caa_Roots_Qualify()
    {
        var rule = new R186_DnsCaaRecordProbingBurstRule();
        for (var i = 0; i < 7; i++) Assert.False((await rule.EvaluateAsync(At(Q($"pki.example{i}.org","CAA"),i))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Q("pki.example7.org","CAA"),7))).Matched);
    }
    [Fact] public async Task Isolated_Caa_Query_Is_Not_A_Burst()
        => Assert.False((await new R186_DnsCaaRecordProbingBurstRule().EvaluateAsync(At(Q("pki.example.org","CAA")))).Matched);
    [Fact] public async Task Repeated_Roots_Do_Not_Advance_Distinct_Count()
    {
        var rule = new R186_DnsCaaRecordProbingBurstRule();
        for (var i = 0; i < 10; i++) Assert.False((await rule.EvaluateAsync(At(Q($"sub{i}.example.org","CAA"),i))).Matched);
    }
    [Fact] public async Task Txt_Queries_Are_Not_Caa_Probes()
    {
        var rule = new R186_DnsCaaRecordProbingBurstRule();
        for (var i = 0; i < 9; i++) Assert.False((await rule.EvaluateAsync(At(Q($"pki.example{i}.org","TXT"),i))).Matched);
    }
    [Fact] public async Task Duplicate_Packet_Id_Cannot_Reach_Threshold()
    {
        var rule = new R186_DnsCaaRecordProbingBurstRule(); var r = Q("pki.example.org","CAA");
        for (var i = 0; i < 10; i++) Assert.False((await rule.EvaluateAsync(At(r,i))).Matched);
    }
    [Fact] public async Task Different_Resolvers_Do_Not_Pool_Counts()
    {
        var rule = new R186_DnsCaaRecordProbingBurstRule();
        for (var i = 0; i < 7; i++) Assert.False((await rule.EvaluateAsync(At(Q($"pki.example{i}.org","CAA"),i))).Matched);
        var r = Q("pki.example7.org","CAA"); r.Destination = "1.1.1.1";
        Assert.False((await rule.EvaluateAsync(At(r,8))).Matched);
    }
    [Fact] public async Task Contradictory_Http_Metadata_Rejected()
    {
        var r = Q("pki.example.org","CAA"); r.HttpMethod = "GET";
        Assert.False((await new R186_DnsCaaRecordProbingBurstRule().EvaluateAsync(At(r))).Matched);
    }
    [Fact] public async Task Out_Of_Order_Caa_Observation_Not_Countable()
    {
        var rule = new R186_DnsCaaRecordProbingBurstRule();
        Assert.False((await rule.EvaluateAsync(At(Q("pki.example0.org","CAA"),10))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Q("pki.example1.org","CAA"),5))).Matched);
    }
    [Fact] public async Task Private_Query_Label_Not_Persisted()
    {
        var rule = new R186_DnsCaaRecordProbingBurstRule(); RuleEvaluationResult? last = null;
        for (var i = 0; i < 8; i++) last = await rule.EvaluateAsync(At(Q($"secret186.example{i}.org","CAA"),i));
        Assert.True(last!.Matched);
        Assert.DoesNotContain(Assert.Single(last.Events).StructuredEvidence!.Items, e => e.Value.Contains("secret186", StringComparison.Ordinal));
    }
    [Fact] public void Confidence_And_Shadow_Preserved()
    {
        var p = new R186_DnsCaaRecordProbingBurstRule().PrecisionProfile;
        Assert.Equal(68,p.MinimumConfidence); Assert.Equal(RuleRuntimeMode.Shadow,p.DefaultMode);
    }
}
