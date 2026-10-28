// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R182AdvancedAccuracyBatchTests
{
    private static TrafficRecord Transfer(string qtype="AXFR")
    {
        var r=NetworkBatch176185Context.Dns("zone.example.org",qtype);
        r.IsUdp=false;r.IsTcp=true;
        return r;
    }
    [Fact] public async Task External_Tcp_Axfr_Qualifies()
    {
        Assert.True((await new R182_DnsZoneTransferAttemptRule().EvaluateAsync(NetworkBatch176185Context.At(Transfer()))).Matched);
    }
    [Fact] public async Task External_Tcp_Ixfr_Qualifies()
    {
        Assert.True((await new R182_DnsZoneTransferAttemptRule().EvaluateAsync(NetworkBatch176185Context.At(Transfer("IXFR")))).Matched);
    }
    [Fact] public async Task Internal_Secondary_Is_Benign()
    {
        var r=Transfer();r.Destination="10.176.0.53";Assert.False((await new R182_DnsZoneTransferAttemptRule().EvaluateAsync(NetworkBatch176185Context.At(r))).Matched);
    }
    [Fact] public async Task Udp_Axfr_Not_Confirmed()
    {
        var r=NetworkBatch176185Context.Dns("zone.example.org","AXFR");Assert.False((await new R182_DnsZoneTransferAttemptRule().EvaluateAsync(NetworkBatch176185Context.At(r))).Matched);
    }
    [Fact] public async Task Info_Only_Claim_Not_Proof()
    {
        var r=Transfer();r.DnsQtype="A";r.Info="AXFR";Assert.False((await new R182_DnsZoneTransferAttemptRule().EvaluateAsync(NetworkBatch176185Context.At(r))).Matched);
    }
    [Fact] public async Task Duplicate_Transfer_Id_Rejected()
    {
        var r=Transfer();var rule=new R182_DnsZoneTransferAttemptRule();Assert.True((await rule.EvaluateAsync(NetworkBatch176185Context.At(r))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch176185Context.At(r,1))).Matched);
    }
    [Fact] public async Task Zone_Name_Redacted()
    {
        var r=Transfer();r.DnsQname="secret182.example.org";var x=await new R182_DnsZoneTransferAttemptRule().EvaluateAsync(NetworkBatch176185Context.At(r));Assert.True(x.Matched);Assert.DoesNotContain(Assert.Single(x.Events).StructuredEvidence!.Items,i=>i.Value.Contains("secret182",StringComparison.Ordinal));
    }
    [Fact] public void Runtime_Policy_And_Floor_Preserved()
    {
        var p=new R182_DnsZoneTransferAttemptRule().PrecisionProfile;
        Assert.Equal(82,p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Alert,p.DefaultMode);
    }
}
