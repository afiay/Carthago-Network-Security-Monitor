// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R181AdvancedAccuracyBatchTests
{
    [Fact] public async Task Five_Independent_Any_Questions_Qualify()
    {
        var rule=new R181_ExcessiveDnsAnyQueriesRule();for(int i=0;i<4;i++)Assert.False((await rule.EvaluateAsync(NetworkBatch176185Context.At(NetworkBatch176185Context.Dns("zone.example.org","ANY"),i))).Matched);Assert.True((await rule.EvaluateAsync(NetworkBatch176185Context.At(NetworkBatch176185Context.Dns("zone.example.org","ANY"),4))).Matched);
    }
    [Fact] public async Task Single_Any_Is_Benign()
    {
        Assert.False((await new R181_ExcessiveDnsAnyQueriesRule().EvaluateAsync(NetworkBatch176185Context.At(NetworkBatch176185Context.Dns("zone.example.org","ANY")))).Matched);
    }
    [Fact] public async Task Other_Qtypes_Do_Not_Contribute()
    {
        var rule=new R181_ExcessiveDnsAnyQueriesRule();for(int i=0;i<5;i++)Assert.False((await rule.EvaluateAsync(NetworkBatch176185Context.At(NetworkBatch176185Context.Dns("zone.example.org","A"),i))).Matched);
    }
    [Fact] public async Task Duplicate_Packet_Id_Does_Not_Advance()
    {
        var rule=new R181_ExcessiveDnsAnyQueriesRule();var r=NetworkBatch176185Context.Dns("zone.example.org","ANY");for(int i=0;i<6;i++)Assert.False((await rule.EvaluateAsync(NetworkBatch176185Context.At(r,i))).Matched);
    }
    [Fact] public async Task Different_Source_Stays_Isolated()
    {
        var rule=new R181_ExcessiveDnsAnyQueriesRule();for(int i=0;i<4;i++)Assert.False((await rule.EvaluateAsync(NetworkBatch176185Context.At(NetworkBatch176185Context.Dns("zone.example.org","ANY"),i))).Matched);var r=NetworkBatch176185Context.Dns("zone.example.org","ANY");r.Source="10.176.0.11";Assert.False((await rule.EvaluateAsync(NetworkBatch176185Context.At(r,5))).Matched);
    }
    [Fact] public async Task Out_Of_Order_Observation_Rejected()
    {
        var rule=new R181_ExcessiveDnsAnyQueriesRule();Assert.False((await rule.EvaluateAsync(NetworkBatch176185Context.At(NetworkBatch176185Context.Dns("zone.example.org","ANY"),10))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch176185Context.At(NetworkBatch176185Context.Dns("zone.example.org","ANY"),5))).Matched);
    }
    [Fact] public async Task Sensitive_Query_Is_Redacted()
    {
        var rule=new R181_ExcessiveDnsAnyQueriesRule();RuleEvaluationResult? last=null;for(int i=0;i<5;i++)last=await rule.EvaluateAsync(NetworkBatch176185Context.At(NetworkBatch176185Context.Dns("secret181.example.org","ANY"),i));Assert.True(last!.Matched);Assert.DoesNotContain(Assert.Single(last.Events).StructuredEvidence!.Items,x=>x.Value.Contains("secret181",StringComparison.Ordinal));
    }
    [Fact] public void Runtime_Policy_And_Floor_Preserved()
    {
        var p=new R181_ExcessiveDnsAnyQueriesRule().PrecisionProfile;
        Assert.Equal(72,p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Shadow,p.DefaultMode);
    }
}
