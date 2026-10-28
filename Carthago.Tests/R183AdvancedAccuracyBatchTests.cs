// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R183AdvancedAccuracyBatchTests
{
    private static TrafficRecord Random(int i)
        => NetworkBatch176185Context.Dns($"secret183ab12cd34ef56{i:D2}.example.org","DNSKEY");
    [Fact] public async Task Eight_Distinct_Dnssec_Names_Qualify()
    {
        var rule=new R183_DnssecRandomSubdomainSpikeRule();RuleEvaluationResult? last=null;for(int i=0;i<8;i++){last=await rule.EvaluateAsync(NetworkBatch176185Context.At(Random(i),i));if(i<7)Assert.False(last.Matched);}Assert.True(last!.Matched);
    }
    [Fact] public async Task Apex_Dnskey_Is_Benign()
    {
        Assert.False((await new R183_DnssecRandomSubdomainSpikeRule().EvaluateAsync(NetworkBatch176185Context.At(NetworkBatch176185Context.Dns("example.org","DNSKEY")))).Matched);
    }
    [Fact] public async Task Repeated_Name_Not_Distinct()
    {
        var rule=new R183_DnssecRandomSubdomainSpikeRule();for(int i=0;i<9;i++)Assert.False((await rule.EvaluateAsync(NetworkBatch176185Context.At(Random(0),i))).Matched);
    }
    [Fact] public async Task Non_Dnssec_Qtype_Not_Counted()
    {
        var rule=new R183_DnssecRandomSubdomainSpikeRule();for(int i=0;i<8;i++){var r=Random(i);r.DnsQtype="A";Assert.False((await rule.EvaluateAsync(NetworkBatch176185Context.At(r,i))).Matched);}
    }
    [Fact] public async Task Different_Source_Isolated()
    {
        var rule=new R183_DnssecRandomSubdomainSpikeRule();for(int i=0;i<7;i++)Assert.False((await rule.EvaluateAsync(NetworkBatch176185Context.At(Random(i),i))).Matched);var r=Random(8);r.Source="10.176.0.11";Assert.False((await rule.EvaluateAsync(NetworkBatch176185Context.At(r,8))).Matched);
    }
    [Fact] public async Task Out_Of_Order_Ignored()
    {
        var rule=new R183_DnssecRandomSubdomainSpikeRule();Assert.False((await rule.EvaluateAsync(NetworkBatch176185Context.At(Random(0),10))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch176185Context.At(Random(1),5))).Matched);
    }
    [Fact] public async Task Random_Label_Redacted()
    {
        var rule=new R183_DnssecRandomSubdomainSpikeRule();RuleEvaluationResult? last=null;for(int i=0;i<8;i++)last=await rule.EvaluateAsync(NetworkBatch176185Context.At(Random(i),i));Assert.True(last!.Matched);Assert.DoesNotContain(Assert.Single(last.Events).StructuredEvidence!.Items,x=>x.Value.Contains("secret183",StringComparison.Ordinal));
    }
    [Fact] public void Runtime_Policy_And_Floor_Preserved()
    {
        var p=new R183_DnssecRandomSubdomainSpikeRule().PrecisionProfile;
        Assert.Equal(74,p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Shadow,p.DefaultMode);
    }
}
