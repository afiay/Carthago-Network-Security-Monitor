// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R193AdvancedAccuracyBatchTests
{
    private static RuleEvaluationContext At(TrafficRecord r, int seconds = 0) => NetworkBatch186195Context.At(r, seconds);
    private static TrafficRecord Q(string name, string type = "A") => NetworkBatch186195Context.Query(name, type);

    [Fact] public async Task Registered_Lookalike_Label_Is_Candidate()
        => Assert.True((await new R193_CloudBrandLookalikeDomainRule().EvaluateAsync(At(Q("micros0ft.dev")))).Matched);
    [Fact] public async Task Legitimate_Vendor_Domain_Is_Benign()
        => Assert.False((await new R193_CloudBrandLookalikeDomainRule().EvaluateAsync(At(Q("microsoft.com")))).Matched);
    [Fact] public async Task Brand_Token_Only_In_Subdomain_Is_Not_Registered_Impersonation()
        => Assert.False((await new R193_CloudBrandLookalikeDomainRule().EvaluateAsync(At(Q("micros0ft.example.org")))).Matched);
    [Fact] public async Task Partial_Lookalike_Substring_Is_Not_Exact_Label()
        => Assert.False((await new R193_CloudBrandLookalikeDomainRule().EvaluateAsync(At(Q("micros0ft-portal.net")))).Matched);
    [Fact] public async Task Info_Only_Brand_Claim_Not_Proof()
    {
        var r=Q("example.org");r.Info="micros0ft.dev";
        Assert.False((await new R193_CloudBrandLookalikeDomainRule().EvaluateAsync(At(r))).Matched);
    }
    [Fact] public async Task Dns_Response_Not_First_Seen_Query()
    {
        var r=Q("g00gle.cloud");r.DnsIsResponse=true;
        Assert.False((await new R193_CloudBrandLookalikeDomainRule().EvaluateAsync(At(r))).Matched);
    }
    [Fact] public async Task Duplicate_Record_Rejected()
    {
        var rule=new R193_CloudBrandLookalikeDomainRule();var r=Q("amaz0n.online");
        Assert.True((await rule.EvaluateAsync(At(r))).Matched);
        Assert.False((await rule.EvaluateAsync(At(r,1))).Matched);
    }
    [Fact] public async Task Contradictory_Http_Transport_Rejected()
    {
        var r=Q("cloudfl4re.net");r.HttpMethod="GET";
        Assert.False((await new R193_CloudBrandLookalikeDomainRule().EvaluateAsync(At(r))).Matched);
    }
    [Fact] public async Task Sensitive_Domain_Label_Redacted()
    {
        var x=await new R193_CloudBrandLookalikeDomainRule().EvaluateAsync(At(Q("paypai.info")));
        Assert.True(x.Matched);
        Assert.DoesNotContain(Assert.Single(x.Events).StructuredEvidence!.Items,e=>e.Value.Contains("paypai",StringComparison.Ordinal));
    }
    [Fact] public void Shadow_And_Floor_Preserved()
    {
        var p=new R193_CloudBrandLookalikeDomainRule().PrecisionProfile;
        Assert.Equal(74,p.MinimumConfidence);Assert.Equal(RuleRuntimeMode.Shadow,p.DefaultMode);
    }
}
