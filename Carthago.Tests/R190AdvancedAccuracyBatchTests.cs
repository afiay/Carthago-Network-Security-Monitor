// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R190AdvancedAccuracyBatchTests
{
    private static RuleEvaluationContext At(TrafficRecord r, int seconds = 0) => NetworkBatch186195Context.At(r, seconds);
    private static TrafficRecord Q(string name, string type = "A") => NetworkBatch186195Context.Query(name, type);

    private static TrafficRecord R(string name="secret190.example.org",int ttl=0) => NetworkBatch186195Context.Response(name,ttl);
    [Fact] public async Task Six_Independent_Short_Ttl_Responses_Qualify()
    {
        var rule=new R190_DnsShortTtlBurstRule();
        for(var i=0;i<5;i++)Assert.False((await rule.EvaluateAsync(At(R(),i))).Matched);
        Assert.True((await rule.EvaluateAsync(At(R(),5))).Matched);
    }
    [Fact] public async Task High_Ttl_Response_Is_Benign()
        => Assert.False((await new R190_DnsShortTtlBurstRule().EvaluateAsync(At(R(ttl:300)))).Matched);
    [Fact] public async Task Query_Cannot_Claim_Answer_Ttl()
    {
        var r=R();r.DnsIsResponse=false;
        Assert.False((await new R190_DnsShortTtlBurstRule().EvaluateAsync(At(r))).Matched);
    }
    [Fact] public async Task Wrong_Source_Port_Rejected()
    {
        var r=R();r.SourcePort=53000;
        Assert.False((await new R190_DnsShortTtlBurstRule().EvaluateAsync(At(r))).Matched);
    }
    [Fact] public async Task Duplicate_Packet_Id_Does_Not_Advance()
    {
        var rule=new R190_DnsShortTtlBurstRule();var r=R();
        for(var i=0;i<8;i++)Assert.False((await rule.EvaluateAsync(At(r,i))).Matched);
    }
    [Fact] public async Task Different_Client_Does_Not_Pool_Counts()
    {
        var rule=new R190_DnsShortTtlBurstRule();
        for(var i=0;i<5;i++)Assert.False((await rule.EvaluateAsync(At(R(),i))).Matched);
        var r=R();r.Destination="10.186.0.11";
        Assert.False((await rule.EvaluateAsync(At(r,5))).Matched);
    }
    [Fact] public async Task Out_Of_Order_Response_Ignored()
    {
        var rule=new R190_DnsShortTtlBurstRule();
        Assert.False((await rule.EvaluateAsync(At(R(),10))).Matched);
        Assert.False((await rule.EvaluateAsync(At(R(),5))).Matched);
    }
    [Fact] public async Task Missing_Parsed_Ttl_Is_Not_Proof()
    {
        var r=R();r.DnsTtl=null;r.Info="TTL=0";
        Assert.False((await new R190_DnsShortTtlBurstRule().EvaluateAsync(At(r))).Matched);
    }
    [Fact] public async Task Sensitive_Query_Redacted()
    {
        var rule=new R190_DnsShortTtlBurstRule();RuleEvaluationResult? last=null;
        for(var i=0;i<6;i++)last=await rule.EvaluateAsync(At(R(),i));
        Assert.True(last!.Matched);
        Assert.DoesNotContain(Assert.Single(last.Events).StructuredEvidence!.Items,e=>e.Value.Contains("secret190",StringComparison.Ordinal));
    }
    [Fact] public void Confidence_And_Shadow_Preserved()
    {
        var p=new R190_DnsShortTtlBurstRule().PrecisionProfile;
        Assert.Equal(72,p.MinimumConfidence);Assert.Equal(RuleRuntimeMode.Shadow,p.DefaultMode);
    }
}
