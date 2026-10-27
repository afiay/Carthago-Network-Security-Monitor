// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R180AdvancedAccuracyBatchTests
{
    [Fact] public async Task Long_HighEntropy_Risky_Tld_Qualifies()
    {
        Assert.True((await new R180_DnsQueryToHighRiskTldRule().EvaluateAsync(NetworkBatch176185Context.At(NetworkBatch176185Context.Dns("a7c9e2d4f8b1c6.xyz")))).Matched);
    }
    [Fact] public async Task Short_Legitimate_Risky_Tld_Suppressed()
    {
        Assert.False((await new R180_DnsQueryToHighRiskTldRule().EvaluateAsync(NetworkBatch176185Context.At(NetworkBatch176185Context.Dns("docs.xyz")))).Matched);
    }
    [Fact] public async Task NonRisk_Tld_Suppressed()
    {
        Assert.False((await new R180_DnsQueryToHighRiskTldRule().EvaluateAsync(NetworkBatch176185Context.At(NetworkBatch176185Context.Dns("a7c9e2d4f8b1c6.example")))).Matched);
    }
    [Fact] public async Task Info_Only_Tld_Claim_Not_Proof()
    {
        var r=NetworkBatch176185Context.Dns("www.example.org");r.Info="a7c9e2d4f8b1c6.xyz";Assert.False((await new R180_DnsQueryToHighRiskTldRule().EvaluateAsync(NetworkBatch176185Context.At(r))).Matched);
    }
    [Fact] public async Task Dns_Response_Not_First_Seen_Query()
    {
        var r=NetworkBatch176185Context.Dns("a7c9e2d4f8b1c6.xyz");r.DnsIsResponse=true;Assert.False((await new R180_DnsQueryToHighRiskTldRule().EvaluateAsync(NetworkBatch176185Context.At(r))).Matched);
    }
    [Fact] public async Task Contradictory_Http_Transport_Rejected()
    {
        var r=NetworkBatch176185Context.Dns("a7c9e2d4f8b1c6.xyz");r.HttpMethod="GET";Assert.False((await new R180_DnsQueryToHighRiskTldRule().EvaluateAsync(NetworkBatch176185Context.At(r))).Matched);
    }
    [Fact] public async Task Duplicate_Dns_Record_Rejected()
    {
        var r=NetworkBatch176185Context.Dns("a7c9e2d4f8b1c6.xyz");var rule=new R180_DnsQueryToHighRiskTldRule();Assert.True((await rule.EvaluateAsync(NetworkBatch176185Context.At(r))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch176185Context.At(r,1))).Matched);
    }
    [Fact] public async Task Sensitive_Label_Is_Redacted()
    {
        var r=NetworkBatch176185Context.Dns("secret180a7c9e2d4f8b1c6.xyz");var x=await new R180_DnsQueryToHighRiskTldRule().EvaluateAsync(NetworkBatch176185Context.At(r));Assert.True(x.Matched);Assert.DoesNotContain(Assert.Single(x.Events).StructuredEvidence!.Items,i=>i.Value.Contains("secret180",StringComparison.Ordinal));
    }
    [Fact] public void Default_Mode_And_Confidence_Floor_Are_Preserved()
    {
        var p=new R180_DnsQueryToHighRiskTldRule().PrecisionProfile;
        Assert.Equal(68,p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Shadow,p.DefaultMode);
    }
}
