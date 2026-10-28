// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R178AdvancedAccuracyBatchTests
{
    [Fact] public async Task Structured_Pool_Subdomain_Qualifies()
    {
        Assert.True((await new R178_DnsQueryForCryptoMiningPoolRule().EvaluateAsync(NetworkBatch176185Context.At(NetworkBatch176185Context.Dns("stratum.2miners.com")))).Matched);
    }
    [Fact] public async Task Brand_Apex_Is_Not_Pool_Activity()
    {
        Assert.False((await new R178_DnsQueryForCryptoMiningPoolRule().EvaluateAsync(NetworkBatch176185Context.At(NetworkBatch176185Context.Dns("2miners.com")))).Matched);
    }
    [Fact] public async Task Provider_Website_Is_Not_A_Mining_Service()
    {
        Assert.False((await new R178_DnsQueryForCryptoMiningPoolRule().EvaluateAsync(NetworkBatch176185Context.At(NetworkBatch176185Context.Dns("www.2miners.com")))).Matched);
    }
    [Fact] public async Task Lookalike_Root_Rejected()
    {
        Assert.False((await new R178_DnsQueryForCryptoMiningPoolRule().EvaluateAsync(NetworkBatch176185Context.At(NetworkBatch176185Context.Dns("stratum.2miners.com.evil.example")))).Matched);
    }
    [Fact] public async Task Info_Only_Mining_Claim_Rejected()
    {
        var r=NetworkBatch176185Context.Dns("www.example.org");r.Info="stratum.2miners.com";Assert.False((await new R178_DnsQueryForCryptoMiningPoolRule().EvaluateAsync(NetworkBatch176185Context.At(r))).Matched);
    }
    [Fact] public async Task Dns_Response_Does_Not_Qualify()
    {
        var r=NetworkBatch176185Context.Dns("stratum.2miners.com");r.DnsIsResponse=true;Assert.False((await new R178_DnsQueryForCryptoMiningPoolRule().EvaluateAsync(NetworkBatch176185Context.At(r))).Matched);
    }
    [Fact] public async Task Contradictory_Http_Protocol_Rejected()
    {
        var r=NetworkBatch176185Context.Dns("stratum.2miners.com");r.Protocol="HTTP";Assert.False((await new R178_DnsQueryForCryptoMiningPoolRule().EvaluateAsync(NetworkBatch176185Context.At(r))).Matched);
    }
    [Fact] public async Task Duplicate_Dns_Id_Rejected()
    {
        var r=NetworkBatch176185Context.Dns("stratum.2miners.com");var rule=new R178_DnsQueryForCryptoMiningPoolRule();Assert.True((await rule.EvaluateAsync(NetworkBatch176185Context.At(r))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch176185Context.At(r,1))).Matched);
    }
    [Fact] public async Task Rig_Label_Is_Redacted()
    {
        var r=NetworkBatch176185Context.Dns("secret-rig-178.pool.2miners.com");var x=await new R178_DnsQueryForCryptoMiningPoolRule().EvaluateAsync(NetworkBatch176185Context.At(r));Assert.True(x.Matched);Assert.DoesNotContain(Assert.Single(x.Events).StructuredEvidence!.Items,i=>i.Value.Contains("secret-rig-178",StringComparison.Ordinal));
    }
    [Fact] public void Default_Mode_And_Confidence_Floor_Are_Preserved()
    {
        var p=new R178_DnsQueryForCryptoMiningPoolRule().PrecisionProfile;
        Assert.Equal(80,p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Alert,p.DefaultMode);
    }
}
