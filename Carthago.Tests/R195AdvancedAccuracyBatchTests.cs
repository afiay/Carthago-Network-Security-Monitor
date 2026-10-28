// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R195AdvancedAccuracyBatchTests
{
    private static RuleEvaluationContext At(TrafficRecord r, int seconds = 0) => NetworkBatch186195Context.At(r, seconds);
    private static TrafficRecord Q(string name, string type = "A") => NetworkBatch186195Context.Query(name, type);

    private static TrafficRecord Dot(string host="resolver.example.net")=>NetworkBatch186195Context.Dot(host);
    [Fact] public async Task Parsed_Tls_On_853_To_Unapproved_Host_Qualifies()
        => Assert.True((await new R195_DnsOverTlsToUnapprovedResolverRule().EvaluateAsync(At(Dot()))).Matched);
    [Fact] public async Task Approved_Public_Dot_Host_Suppressed()
        => Assert.False((await new R195_DnsOverTlsToUnapprovedResolverRule().EvaluateAsync(At(Dot("dns.google")))).Matched);
    [Fact] public async Task Ordinary_Tls_On_443_Is_Not_Dot()
    {
        var r=Dot();r.DestinationPort=443;
        Assert.False((await new R195_DnsOverTlsToUnapprovedResolverRule().EvaluateAsync(At(r))).Matched);
    }
    [Fact] public async Task Port_853_Without_Tls_Handshake_Is_Not_Proof()
    {
        var r=Dot();r.Sni=null;r.TlsVersion=null;
        Assert.False((await new R195_DnsOverTlsToUnapprovedResolverRule().EvaluateAsync(At(r))).Matched);
    }
    [Fact] public async Task Udp_On_853_Is_Not_Tls()
    {
        var r=Dot();r.IsTcp=false;r.IsUdp=true;
        Assert.False((await new R195_DnsOverTlsToUnapprovedResolverRule().EvaluateAsync(At(r))).Matched);
    }
    [Fact] public async Task Contradictory_Http_Metadata_Rejected()
    {
        var r=Dot();r.HttpMethod="GET";
        Assert.False((await new R195_DnsOverTlsToUnapprovedResolverRule().EvaluateAsync(At(r))).Matched);
    }
    [Fact] public async Task Internal_Destination_Not_Unapproved_External_Resolver()
    {
        var r=Dot();r.Destination="10.186.0.53";
        Assert.False((await new R195_DnsOverTlsToUnapprovedResolverRule().EvaluateAsync(At(r))).Matched);
    }
    [Fact] public async Task Duplicate_Packet_Id_Rejected()
    {
        var rule=new R195_DnsOverTlsToUnapprovedResolverRule();var r=Dot();
        Assert.True((await rule.EvaluateAsync(At(r))).Matched);
        Assert.False((await rule.EvaluateAsync(At(r,1))).Matched);
    }
    [Fact] public async Task Sensitive_Sni_Redacted()
    {
        var x=await new R195_DnsOverTlsToUnapprovedResolverRule().EvaluateAsync(At(Dot("secret195.example.net")));
        Assert.True(x.Matched);
        Assert.DoesNotContain(Assert.Single(x.Events).StructuredEvidence!.Items,e=>e.Value.Contains("secret195",StringComparison.Ordinal));
    }
    [Fact] public void Alert_And_Floor_Preserved()
    {
        var p=new R195_DnsOverTlsToUnapprovedResolverRule().PrecisionProfile;
        Assert.Equal(80,p.MinimumConfidence);Assert.Equal(RuleRuntimeMode.Alert,p.DefaultMode);
    }
}
