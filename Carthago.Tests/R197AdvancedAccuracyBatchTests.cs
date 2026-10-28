// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R197AdvancedAccuracyBatchTests
{
    private static TrafficRecord P(string answers = "10.10.0.9", int? ttl = 1) => NetworkBatch196200Context.Private(answers, ttl);
    private static async Task<bool> Hit(TrafficRecord r) => (await new R197_DnsRebindingPrivateIpAnswerRule().EvaluateAsync(NetworkBatch196200Context.At(r))).Matched;
    [Fact] public async Task Parsed_Private_Low_Ttl_Response_Qualifies() => Assert.True(await Hit(P()));
    [Fact] public async Task Ordinary_Split_Horizon_Private_High_Ttl_Is_Not_Rebinding()
        => Assert.False(await Hit(P(ttl: 3600)));
    [Fact] public async Task Mixed_Public_Private_Answers_Qualify_Without_Low_Ttl()
        => Assert.True(await Hit(P("8.8.8.8,10.10.0.9", 3600)));
    [Fact] public async Task Loopback_Answer_Qualifies_Without_Parsed_Ttl()
        => Assert.True(await Hit(P("127.0.0.1", null)));
    [Fact] public async Task No_Parsed_Answers_Cannot_Be_Inferred_From_Info()
    {
        var r = P(); r.DnsAnswers = null; r.Info = "A 10.10.0.9 TTL 1";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Query_Not_Response_Is_Not_Rebinding()
    {
        var r = P(); r.DnsIsResponse = false;
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Contradictory_Http_Metadata_Rejected()
    {
        var r = P(); r.HttpMethod = "GET";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Duplicate_Packet_Id_Does_Not_Produce_Second_Candidate()
    {
        var rule = new R197_DnsRebindingPrivateIpAnswerRule(); var r = P();
        Assert.True((await rule.EvaluateAsync(NetworkBatch196200Context.At(r))).Matched);
        Assert.False((await rule.EvaluateAsync(NetworkBatch196200Context.At(r, 1))).Matched);
    }
    [Fact] public async Task Sensitive_Name_And_Private_Ip_Are_Redacted()
    {
        var x = await new R197_DnsRebindingPrivateIpAnswerRule().EvaluateAsync(NetworkBatch196200Context.At(P()));
        Assert.True(x.Matched);
        Assert.DoesNotContain(Assert.Single(x.Events).StructuredEvidence!.Items, e =>
            e.Value.Contains("secret197", StringComparison.Ordinal) || e.Value.Contains("10.10.0.9", StringComparison.Ordinal));
    }
    [Fact] public void Existing_Alert_And_Confidence_Floor_Remain()
    {
        var p = new R197_DnsRebindingPrivateIpAnswerRule().PrecisionProfile;
        Assert.Equal(82, p.MinimumConfidence); Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
