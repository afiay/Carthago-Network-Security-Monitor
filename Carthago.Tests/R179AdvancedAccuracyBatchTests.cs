// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R179AdvancedAccuracyBatchTests
{
    [Fact] public async Task Literal_Onion_Dns_Leak_Qualifies()
    {
        Assert.True((await new R179_DnsQueryForTorOnionGatewayRule().EvaluateAsync(NetworkBatch176185Context.At(NetworkBatch176185Context.Dns("abc123.onion")))).Matched);
    }
    [Fact] public async Task Gateway_Root_Qualifies()
    {
        Assert.True((await new R179_DnsQueryForTorOnionGatewayRule().EvaluateAsync(NetworkBatch176185Context.At(NetworkBatch176185Context.Dns("hidden.onion.to")))).Matched);
    }
    [Fact] public async Task Ordinary_Onion_Brand_Is_Benign()
    {
        Assert.False((await new R179_DnsQueryForTorOnionGatewayRule().EvaluateAsync(NetworkBatch176185Context.At(NetworkBatch176185Context.Dns("onion-news.example.org")))).Matched);
    }
    [Fact] public async Task Gateway_Lookalike_Suffix_Is_Rejected()
    {
        Assert.False((await new R179_DnsQueryForTorOnionGatewayRule().EvaluateAsync(NetworkBatch176185Context.At(NetworkBatch176185Context.Dns("onion.to.example.org")))).Matched);
    }
    [Fact] public async Task Info_Only_Onion_Not_Proof()
    {
        var r=NetworkBatch176185Context.Dns("www.example.org");r.Info="abc.onion";Assert.False((await new R179_DnsQueryForTorOnionGatewayRule().EvaluateAsync(NetworkBatch176185Context.At(r))).Matched);
    }
    [Fact] public async Task Udp_Tcp_Contradiction_Rejected()
    {
        var r=NetworkBatch176185Context.Dns("abc123.onion");r.IsTcp=true;Assert.False((await new R179_DnsQueryForTorOnionGatewayRule().EvaluateAsync(NetworkBatch176185Context.At(r))).Matched);
    }
    [Fact] public async Task Duplicate_Query_Id_Rejected()
    {
        var r=NetworkBatch176185Context.Dns("abc123.onion");var rule=new R179_DnsQueryForTorOnionGatewayRule();Assert.True((await rule.EvaluateAsync(NetworkBatch176185Context.At(r))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch176185Context.At(r,1))).Matched);
    }
    [Fact] public async Task Onion_Subdomain_Identifier_Is_Redacted()
    {
        var r=NetworkBatch176185Context.Dns("secret179.onion.to");var x=await new R179_DnsQueryForTorOnionGatewayRule().EvaluateAsync(NetworkBatch176185Context.At(r));Assert.True(x.Matched);var evt=Assert.Single(x.Events);Assert.DoesNotContain(evt.StructuredEvidence!.Items,i=>i.Value.Contains("secret179",StringComparison.Ordinal));Assert.Equal("[REDACTED]",evt.DestinationHost);Assert.DoesNotContain("secret179",evt.Evidence ?? "",StringComparison.Ordinal);
    }
    [Fact] public void Default_Mode_And_Confidence_Floor_Are_Preserved()
    {
        var p=new R179_DnsQueryForTorOnionGatewayRule().PrecisionProfile;
        Assert.Equal(74,p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Shadow,p.DefaultMode);
    }
}
