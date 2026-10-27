// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.IPv6;
using Xunit;
namespace Carthago.Tests;
public sealed class R071AdvancedAccuracyBatchTests
{
    private readonly R071_IPv6TrafficOnIPv4OnlyNetworkRule _rule=new(()=>true);
    private async Task<bool> Seen(int s,string src="fd71::10",string dst="2001:4860::8888",string network="IPv4Only")
        => (await _rule.EvaluateAsync(NetworkBatch071075Context.Ipv6(s,src,dst,network))).Matched;
    [Fact] public async Task Approved_Ready_Two_Observations_Trigger_Once()
    {using var scope=await AssetBatch061065Context.Ready();Assert.False(await Seen(1));Assert.True(await Seen(2));Assert.False(await Seen(3));}
    [Fact] public async Task Missing_Operator_Approval_Fails_Closed()
    {using var scope=await AssetBatch061065Context.Ready();var r=new R071_IPv6TrafficOnIPv4OnlyNetworkRule(()=>false);Assert.False((await r.EvaluateAsync(NetworkBatch071075Context.Ipv6(1))).Matched);Assert.False((await r.EvaluateAsync(NetworkBatch071075Context.Ipv6(2))).Matched);}
    [Fact] public async Task Learning_Baseline_Does_Not_Assert_Policy_Violation()
    {using var scope=AssetBatch061065Context.Unready();Assert.False(await Seen(1));Assert.False(await Seen(2));}
    [Fact] public async Task DualStack_Or_Missing_Classification_Is_Not_Proof()
    {using var scope=await AssetBatch061065Context.Ready();Assert.False(await Seen(1,network:"DualStack"));Assert.False(await Seen(2,network:""));Assert.False(await Seen(3));}
    [Fact] public async Task LinkLocal_Multicast_And_Loopback_Are_Excluded()
    {using var scope=await AssetBatch061065Context.Ready();Assert.False(await Seen(1,src:"fe80::1"));Assert.False(await Seen(2,dst:"ff02::1"));Assert.False(await Seen(3,src:"::1"));}
    [Fact] public async Task Duplicate_And_Different_Flow_Do_Not_Corroborate()
    {using var scope=await AssetBatch061065Context.Ready();Assert.False(await Seen(2));Assert.False(await Seen(2));Assert.False(await Seen(1));Assert.False(await Seen(3,dst:"2001:4860::8844"));Assert.True(await Seen(4));}
    [Fact] public async Task Contradictory_Evidence_Cancellation_And_Privacy()
    {using var scope=await AssetBatch061065Context.Ready();var bad=NetworkBatch071075Context.Ipv6(1);bad.Record.IcmpTypeCode=0x8000;Assert.False((await _rule.EvaluateAsync(bad)).Matched);using var c=new CancellationTokenSource();c.Cancel();await Assert.ThrowsAnyAsync<OperationCanceledException>(async()=>await _rule.EvaluateAsync(NetworkBatch071075Context.Ipv6(2),c.Token));Assert.False(await Seen(3));var p=NetworkBatch071075Context.Ipv6(4);p.Record.Info="secret-ipv6";var e=Assert.Single((await _rule.EvaluateAsync(p)).Events);Assert.DoesNotContain("secret-ipv6",e.Description);Assert.DoesNotContain("secret-ipv6",e.Evidence);}
}
