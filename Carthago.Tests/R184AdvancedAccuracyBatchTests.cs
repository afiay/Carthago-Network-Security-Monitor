// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R184AdvancedAccuracyBatchTests
{
    private static TrafficRecord Ptr(int i)
        => NetworkBatch176185Context.Dns($"{i+1}.2.0.192.in-addr.arpa","PTR");
    [Fact] public async Task Ten_Distinct_External_Ptr_Qualify()
    {
        var rule=new R184_ExternalReverseDnsEnumerationRule();RuleEvaluationResult? last=null;for(int i=0;i<10;i++){last=await rule.EvaluateAsync(NetworkBatch176185Context.At(Ptr(i),i));if(i<9)Assert.False(last.Matched);}Assert.True(last!.Matched);
    }
    [Fact] public async Task Isolated_Ptr_Is_Benign()
    {
        Assert.False((await new R184_ExternalReverseDnsEnumerationRule().EvaluateAsync(NetworkBatch176185Context.At(Ptr(1)))).Matched);
    }
    [Fact] public async Task Internal_Resolver_Not_External()
    {
        var rule=new R184_ExternalReverseDnsEnumerationRule();for(int i=0;i<10;i++){var r=Ptr(i);r.Destination="10.176.0.53";Assert.False((await rule.EvaluateAsync(NetworkBatch176185Context.At(r,i))).Matched);}
    }
    [Fact] public async Task Non_Ptr_Qtype_Not_Countable()
    {
        var rule=new R184_ExternalReverseDnsEnumerationRule();for(int i=0;i<10;i++){var r=Ptr(i);r.DnsQtype="A";Assert.False((await rule.EvaluateAsync(NetworkBatch176185Context.At(r,i))).Matched);}
    }
    [Fact] public async Task Duplicate_Name_Not_Distinct()
    {
        var rule=new R184_ExternalReverseDnsEnumerationRule();for(int i=0;i<11;i++)Assert.False((await rule.EvaluateAsync(NetworkBatch176185Context.At(Ptr(0),i))).Matched);
    }
    [Fact] public async Task Different_Source_Not_Combined()
    {
        var rule=new R184_ExternalReverseDnsEnumerationRule();for(int i=0;i<9;i++)Assert.False((await rule.EvaluateAsync(NetworkBatch176185Context.At(Ptr(i),i))).Matched);var r=Ptr(9);r.Source="10.176.0.11";Assert.False((await rule.EvaluateAsync(NetworkBatch176185Context.At(r,9))).Matched);
    }
    [Fact] public async Task Reverse_Name_Redacted()
    {
        var rule=new R184_ExternalReverseDnsEnumerationRule();RuleEvaluationResult? last=null;for(int i=0;i<10;i++)last=await rule.EvaluateAsync(NetworkBatch176185Context.At(Ptr(i),i));Assert.True(last!.Matched);Assert.DoesNotContain(Assert.Single(last.Events).StructuredEvidence!.Items,x=>x.Value.Contains("in-addr.arpa",StringComparison.Ordinal));
    }
    [Fact] public void Runtime_Policy_And_Floor_Preserved()
    {
        var p=new R184_ExternalReverseDnsEnumerationRule().PrecisionProfile;
        Assert.Equal(74,p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Shadow,p.DefaultMode);
    }
}
