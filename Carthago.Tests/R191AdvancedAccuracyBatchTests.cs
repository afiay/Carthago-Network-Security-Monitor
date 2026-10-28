// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R191AdvancedAccuracyBatchTests
{
    private static RuleEvaluationContext At(TrafficRecord r, int seconds = 0) => NetworkBatch186195Context.At(r, seconds);
    private static TrafficRecord Q(string name, string type = "A") => NetworkBatch186195Context.Query(name, type);

    private const string Dga = "bcdfrghjklmnptvxyz.net";
    [Fact] public async Task Typed_Consonant_Heavy_Domain_Is_Candidate()
        => Assert.True((await new R191_ConsonantHeavyDgaDomainRule().EvaluateAsync(At(Q(Dga)))).Matched);
    [Fact] public async Task Human_Readable_Domain_Is_Benign()
        => Assert.False((await new R191_ConsonantHeavyDgaDomainRule().EvaluateAsync(At(Q("customerportal.net")))).Matched);
    [Fact] public async Task Known_Telemetry_Root_Suppressed()
        => Assert.False((await new R191_ConsonantHeavyDgaDomainRule().EvaluateAsync(At(Q("bcdfrghjklmnptvxyz.microsoft.com")))).Matched);
    [Fact] public async Task Info_Only_Dga_Claim_Not_Proof()
    {
        var r=Q("normal.example.org");r.Info=Dga;
        Assert.False((await new R191_ConsonantHeavyDgaDomainRule().EvaluateAsync(At(r))).Matched);
    }
    [Fact] public async Task Dns_Response_Not_Outbound_Query()
    {
        var r=Q(Dga);r.DnsIsResponse=true;
        Assert.False((await new R191_ConsonantHeavyDgaDomainRule().EvaluateAsync(At(r))).Matched);
    }
    [Fact] public async Task Duplicate_Record_Rejected()
    {
        var rule=new R191_ConsonantHeavyDgaDomainRule();var r=Q(Dga);
        Assert.True((await rule.EvaluateAsync(At(r))).Matched);
        Assert.False((await rule.EvaluateAsync(At(r,1))).Matched);
    }
    [Fact] public async Task Contradictory_Http_Metadata_Rejected()
    {
        var r=Q(Dga);r.HttpMethod="GET";
        Assert.False((await new R191_ConsonantHeavyDgaDomainRule().EvaluateAsync(At(r))).Matched);
    }
    [Fact] public async Task No_Dns_Transport_Rejected()
    {
        var r=Q(Dga);r.IsUdp=false;
        Assert.False((await new R191_ConsonantHeavyDgaDomainRule().EvaluateAsync(At(r))).Matched);
    }
    [Fact] public async Task Sensitive_Dga_Label_Redacted()
    {
        var x=await new R191_ConsonantHeavyDgaDomainRule().EvaluateAsync(At(Q("bcdfrghjklmnptvxyz.cloud")));
        Assert.True(x.Matched);
        Assert.DoesNotContain(Assert.Single(x.Events).StructuredEvidence!.Items,e=>e.Value.Contains("bcdfrghjklmnptvxyz",StringComparison.Ordinal));
    }
    [Fact] public void Shadow_And_Floor_Preserved()
    {
        var p=new R191_ConsonantHeavyDgaDomainRule().PrecisionProfile;
        Assert.Equal(74,p.MinimumConfidence);Assert.Equal(RuleRuntimeMode.Shadow,p.DefaultMode);
    }
}
