// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R192AdvancedAccuracyBatchTests
{
    private static RuleEvaluationContext At(TrafficRecord r, int seconds = 0) => NetworkBatch186195Context.At(r, seconds);
    private static TrafficRecord Q(string name, string type = "A") => NetworkBatch186195Context.Query(name, type);

    [Fact] public async Task First_Seen_Valid_Punycode_Registrable_Label_Is_Candidate()
        => Assert.True((await new R192_PunycodeHomographDomainRule().EvaluateAsync(At(Q("xn--bcher-kva.cloud")))).Matched);
    [Fact] public async Task Punycode_CcTld_Is_Not_Candidate()
        => Assert.False((await new R192_PunycodeHomographDomainRule().EvaluateAsync(At(Q("example.xn--p1ai")))).Matched);
    [Fact] public async Task Punycode_Only_In_Subdomain_Is_Not_Registrable_Impersonation()
        => Assert.False((await new R192_PunycodeHomographDomainRule().EvaluateAsync(At(Q("xn--bcher-kva.example.com")))).Matched);
    [Fact] public async Task Invalid_Punycode_Label_Rejected()
        => Assert.False((await new R192_PunycodeHomographDomainRule().EvaluateAsync(At(Q("xn--a.com")))).Matched);
    [Fact] public async Task Packet_Info_Only_Punycode_Not_Proof()
    {
        var r=Q("example.org");r.Info="xn--bcher-kva.com";
        Assert.False((await new R192_PunycodeHomographDomainRule().EvaluateAsync(At(r))).Matched);
    }
    [Fact] public async Task Dns_Response_Not_New_Query()
    {
        var r=Q("xn--bcher-kva.dev");r.DnsIsResponse=true;
        Assert.False((await new R192_PunycodeHomographDomainRule().EvaluateAsync(At(r))).Matched);
    }
    [Fact] public async Task Duplicate_Packet_Rejected()
    {
        var rule=new R192_PunycodeHomographDomainRule();var r=Q("xn--bcher-kva.online");
        Assert.True((await rule.EvaluateAsync(At(r))).Matched);
        Assert.False((await rule.EvaluateAsync(At(r,1))).Matched);
    }
    [Fact] public async Task Contradictory_Http_Metadata_Rejected()
    {
        var r=Q("xn--bcher-kva.info");r.HttpUri="/";
        Assert.False((await new R192_PunycodeHomographDomainRule().EvaluateAsync(At(r))).Matched);
    }
    [Fact] public async Task Punycode_Identifier_Redacted()
    {
        var x=await new R192_PunycodeHomographDomainRule().EvaluateAsync(At(Q("xn--bcher-kva.biz")));
        Assert.True(x.Matched);
        Assert.DoesNotContain(Assert.Single(x.Events).StructuredEvidence!.Items,e=>e.Value.Contains("xn--bcher-kva",StringComparison.Ordinal));
    }
    [Fact] public void Shadow_And_Floor_Preserved()
    {
        var p=new R192_PunycodeHomographDomainRule().PrecisionProfile;
        Assert.Equal(72,p.MinimumConfidence);Assert.Equal(RuleRuntimeMode.Shadow,p.DefaultMode);
    }
}
