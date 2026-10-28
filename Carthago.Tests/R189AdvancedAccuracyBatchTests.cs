// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R189AdvancedAccuracyBatchTests
{
    private static RuleEvaluationContext At(TrafficRecord r, int seconds = 0) => NetworkBatch186195Context.At(r, seconds);
    private static TrafficRecord Q(string name, string type = "A") => NetworkBatch186195Context.Query(name, type);

    [Fact] public async Task Internal_Ad_Srv_Query_To_Public_Resolver_Qualifies()
        => Assert.True((await new R189_AdSrvQueryToExternalResolverRule().EvaluateAsync(At(Q("_ldap._tcp.corp.local","SRV")))).Matched);
    [Fact] public async Task Public_Srv_Service_Does_Not_Leak_Ad_Namespace()
        => Assert.False((await new R189_AdSrvQueryToExternalResolverRule().EvaluateAsync(At(Q("_sip._tcp.example.org","SRV")))).Matched);
    [Fact] public async Task Internal_Resolver_Does_Not_Cross_Boundary()
    {
        var r=Q("_ldap._tcp.corp.local","SRV");r.Destination="10.186.0.53";
        Assert.False((await new R189_AdSrvQueryToExternalResolverRule().EvaluateAsync(At(r))).Matched);
    }
    [Fact] public async Task NonSrv_Query_Cannot_Claim_Ad_Leak()
        => Assert.False((await new R189_AdSrvQueryToExternalResolverRule().EvaluateAsync(At(Q("_ldap._tcp.corp.local","A")))).Matched);
    [Fact] public async Task Info_Only_Ad_Claim_Not_Proof()
    {
        var r=Q("example.org","A");r.Info="_ldap._tcp.corp.local SRV";
        Assert.False((await new R189_AdSrvQueryToExternalResolverRule().EvaluateAsync(At(r))).Matched);
    }
    [Fact] public async Task Duplicate_Record_Rejected()
    {
        var r=Q("_ldap._tcp.corp.local","SRV");var rule=new R189_AdSrvQueryToExternalResolverRule();
        Assert.True((await rule.EvaluateAsync(At(r))).Matched);
        Assert.False((await rule.EvaluateAsync(At(r,1))).Matched);
    }
    [Fact] public async Task Contradictory_Http_Transport_Rejected()
    {
        var r=Q("_ldap._tcp.corp.local","SRV");r.HttpUri="/dns-query";
        Assert.False((await new R189_AdSrvQueryToExternalResolverRule().EvaluateAsync(At(r))).Matched);
    }
    [Fact] public async Task External_Source_Not_Internal_Leak()
    {
        var r=Q("_ldap._tcp.corp.local","SRV");r.Source="9.9.9.9";
        Assert.False((await new R189_AdSrvQueryToExternalResolverRule().EvaluateAsync(At(r))).Matched);
    }
    [Fact] public async Task Internal_Namespace_Redacted()
    {
        var x=await new R189_AdSrvQueryToExternalResolverRule().EvaluateAsync(At(Q("_ldap._tcp.secret189.local","SRV")));
        Assert.True(x.Matched);
        Assert.DoesNotContain(Assert.Single(x.Events).StructuredEvidence!.Items,e=>e.Value.Contains("secret189",StringComparison.Ordinal));
    }
    [Fact] public void Alert_Mode_And_Floor_Preserved()
    {
        var p=new R189_AdSrvQueryToExternalResolverRule().PrecisionProfile;
        Assert.Equal(84,p.MinimumConfidence);Assert.Equal(RuleRuntimeMode.Alert,p.DefaultMode);
    }
}
