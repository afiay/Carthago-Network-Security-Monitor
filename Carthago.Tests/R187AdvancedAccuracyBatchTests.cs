// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R187AdvancedAccuracyBatchTests
{
    private static RuleEvaluationContext At(TrafficRecord r, int seconds = 0) => NetworkBatch186195Context.At(r, seconds);
    private static TrafficRecord Q(string name, string type = "A") => NetworkBatch186195Context.Query(name, type);

    [Fact] public async Task Typed_Null_Query_Qualifies()
        => Assert.True((await new R187_DnsNullQueryUsageRule().EvaluateAsync(At(Q("unusual.example.org","NULL")))).Matched);
    [Fact] public async Task Txt_Query_Is_Benign()
        => Assert.False((await new R187_DnsNullQueryUsageRule().EvaluateAsync(At(Q("unusual.example.org","TXT")))).Matched);
    [Fact] public async Task Info_Only_Null_Claim_Rejected()
    {
        var r=Q("normal.example.org","A"); r.Info="NULL unusual.example.org";
        Assert.False((await new R187_DnsNullQueryUsageRule().EvaluateAsync(At(r))).Matched);
    }
    [Fact] public async Task Dns_Response_Not_An_Outgoing_Query()
    {
        var r=Q("unusual.example.org","NULL"); r.DnsIsResponse=true;
        Assert.False((await new R187_DnsNullQueryUsageRule().EvaluateAsync(At(r))).Matched);
    }
    [Fact] public async Task Replayed_Packet_Id_Does_Not_Duplicate()
    {
        var rule=new R187_DnsNullQueryUsageRule(); var r=Q("unusual.example.org","NULL");
        Assert.True((await rule.EvaluateAsync(At(r))).Matched);
        Assert.False((await rule.EvaluateAsync(At(r,1))).Matched);
    }
    [Fact] public async Task Autodiscover_Validation_Query_Remains_Suppressed()
        => Assert.False((await new R187_DnsNullQueryUsageRule().EvaluateAsync(At(Q("autodiscover.example.org","NULL")))).Matched);
    [Fact] public async Task Http_Contradiction_Rejected()
    {
        var r=Q("unusual.example.org","NULL"); r.HttpUri="/null";
        Assert.False((await new R187_DnsNullQueryUsageRule().EvaluateAsync(At(r))).Matched);
    }
    [Fact] public async Task No_Transport_Attribution_Rejected()
    {
        var r=Q("unusual.example.org","NULL"); r.IsUdp=false;
        Assert.False((await new R187_DnsNullQueryUsageRule().EvaluateAsync(At(r))).Matched);
    }
    [Fact] public async Task Null_Query_Identifier_Redacted()
    {
        var x=await new R187_DnsNullQueryUsageRule().EvaluateAsync(At(Q("secret187.example.org","NULL")));
        Assert.True(x.Matched);
        Assert.DoesNotContain(Assert.Single(x.Events).StructuredEvidence!.Items,e=>e.Value.Contains("secret187",StringComparison.Ordinal));
    }
    [Fact] public void Confidence_And_Shadow_Preserved()
    {
        var p=new R187_DnsNullQueryUsageRule().PrecisionProfile;
        Assert.Equal(72,p.MinimumConfidence); Assert.Equal(RuleRuntimeMode.Shadow,p.DefaultMode);
    }
}
