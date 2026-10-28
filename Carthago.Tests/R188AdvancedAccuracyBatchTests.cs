// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R188AdvancedAccuracyBatchTests
{
    private static RuleEvaluationContext At(TrafficRecord r, int seconds = 0) => NetworkBatch186195Context.At(r, seconds);
    private static TrafficRecord Q(string name, string type = "A") => NetworkBatch186195Context.Query(name, type);

    private static string[] Names = { "_ldap._tcp.corp.local", "_kerberos._tcp.corp.local", "_gc._tcp.corp.local" };
    [Fact] public async Task Three_Distinct_Ad_Service_Queries_Qualify()
    {
        var rule=new R188_ActiveDirectorySrvEnumerationRule();
        Assert.False((await rule.EvaluateAsync(At(Q(Names[0],"SRV")))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Q(Names[1],"SRV"),1))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Q(Names[2],"SRV"),2))).Matched);
    }
    [Fact] public async Task Routine_Single_Ad_Service_Lookup_Is_Benign()
        => Assert.False((await new R188_ActiveDirectorySrvEnumerationRule().EvaluateAsync(At(Q(Names[0],"SRV")))).Matched);
    [Fact] public async Task NonSrv_Ad_Names_Do_Not_Advance()
    {
        var rule=new R188_ActiveDirectorySrvEnumerationRule();
        foreach(var name in Names) Assert.False((await rule.EvaluateAsync(At(Q(name,"A")))).Matched);
    }
    [Fact] public async Task Repeated_Service_Name_Does_Not_Advance()
    {
        var rule=new R188_ActiveDirectorySrvEnumerationRule();
        for(var i=0;i<5;i++) Assert.False((await rule.EvaluateAsync(At(Q(Names[0],"SRV"),i))).Matched);
    }
    [Fact] public async Task Source_Isolation_Prevents_Pooled_Burst()
    {
        var rule=new R188_ActiveDirectorySrvEnumerationRule();
        Assert.False((await rule.EvaluateAsync(At(Q(Names[0],"SRV")))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Q(Names[1],"SRV"),1))).Matched);
        var r=Q(Names[2],"SRV");r.Source="10.186.0.11";
        Assert.False((await rule.EvaluateAsync(At(r,2))).Matched);
    }
    [Fact] public async Task Resolver_Isolation_Prevents_Pooled_Burst()
    {
        var rule=new R188_ActiveDirectorySrvEnumerationRule();
        Assert.False((await rule.EvaluateAsync(At(Q(Names[0],"SRV")))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Q(Names[1],"SRV"),1))).Matched);
        var r=Q(Names[2],"SRV");r.Destination="1.1.1.1";
        Assert.False((await rule.EvaluateAsync(At(r,2))).Matched);
    }
    [Fact] public async Task Http_Contradiction_Rejected()
    {
        var r=Q(Names[0],"SRV");r.HttpMethod="POST";
        Assert.False((await new R188_ActiveDirectorySrvEnumerationRule().EvaluateAsync(At(r))).Matched);
    }
    [Fact] public async Task Out_Of_Order_Observation_Rejected()
    {
        var rule=new R188_ActiveDirectorySrvEnumerationRule();
        Assert.False((await rule.EvaluateAsync(At(Q(Names[0],"SRV"),10))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Q(Names[1],"SRV"),5))).Matched);
    }
    [Fact] public async Task Ad_Domain_Names_Redacted()
    {
        var rule=new R188_ActiveDirectorySrvEnumerationRule();RuleEvaluationResult? last=null;
        foreach(var name in Names) last=await rule.EvaluateAsync(At(Q(name.Replace("corp.local","secret188.local"),"SRV"),Array.IndexOf(Names,name)));
        Assert.True(last!.Matched);
        Assert.DoesNotContain(Assert.Single(last.Events).StructuredEvidence!.Items,e=>e.Value.Contains("secret188",StringComparison.Ordinal));
    }
    [Fact] public void Confidence_And_Shadow_Preserved()
    {
        var p=new R188_ActiveDirectorySrvEnumerationRule().PrecisionProfile;
        Assert.Equal(72,p.MinimumConfidence);Assert.Equal(RuleRuntimeMode.Shadow,p.DefaultMode);
    }
}
