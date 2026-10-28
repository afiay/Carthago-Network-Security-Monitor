// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R185AdvancedAccuracyBatchTests
{
    [Fact] public async Task Known_Oast_Root_Qualifies()
    {
        Assert.True((await new R185_CanaryOrMetadataDomainProbeRule().EvaluateAsync(NetworkBatch176185Context.At(NetworkBatch176185Context.Dns("probe.canarytokens.com")))).Matched);
    }
    [Fact] public async Task Metadata_Service_Root_Qualifies()
    {
        Assert.True((await new R185_CanaryOrMetadataDomainProbeRule().EvaluateAsync(NetworkBatch176185Context.At(NetworkBatch176185Context.Dns("metadata.google.internal")))).Matched);
    }
    [Fact] public async Task Lookalike_Suffix_Is_Benign()
    {
        Assert.False((await new R185_CanaryOrMetadataDomainProbeRule().EvaluateAsync(NetworkBatch176185Context.At(NetworkBatch176185Context.Dns("canarytokens.com.attacker.example")))).Matched);
    }
    [Fact] public async Task Info_Only_Canary_Claim_Not_Proof()
    {
        var r=NetworkBatch176185Context.Dns("www.example.org");r.Info="probe.canarytokens.com";Assert.False((await new R185_CanaryOrMetadataDomainProbeRule().EvaluateAsync(NetworkBatch176185Context.At(r))).Matched);
    }
    [Fact] public async Task Response_Is_Not_Query()
    {
        var r=NetworkBatch176185Context.Dns("probe.canarytokens.com");r.DnsIsResponse=true;Assert.False((await new R185_CanaryOrMetadataDomainProbeRule().EvaluateAsync(NetworkBatch176185Context.At(r))).Matched);
    }
    [Fact] public async Task Duplicate_Packet_Id_Rejected()
    {
        var r=NetworkBatch176185Context.Dns("probe.canarytokens.com");var rule=new R185_CanaryOrMetadataDomainProbeRule();Assert.True((await rule.EvaluateAsync(NetworkBatch176185Context.At(r))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch176185Context.At(r,1))).Matched);
    }
    [Fact] public async Task Canary_Identifier_Redacted()
    {
        var r=NetworkBatch176185Context.Dns("secret185.canarytokens.com");var x=await new R185_CanaryOrMetadataDomainProbeRule().EvaluateAsync(NetworkBatch176185Context.At(r));Assert.True(x.Matched);Assert.DoesNotContain(Assert.Single(x.Events).StructuredEvidence!.Items,i=>i.Value.Contains("secret185",StringComparison.Ordinal));
    }
    [Fact] public void Runtime_Policy_And_Floor_Preserved()
    {
        var p=new R185_CanaryOrMetadataDomainProbeRule().PrecisionProfile;
        Assert.Equal(68,p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Shadow,p.DefaultMode);
    }
}
