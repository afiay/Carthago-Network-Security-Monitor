// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Existing;
using Carthago.Models;
using Carthago.Services;
using Xunit;
namespace Carthago.Tests;

[Collection("Legacy rules R011-R015 isolated")]
public sealed class R021AdvancedAccuracyBatchTests : IDisposable
{
    private readonly R021_IcmpTunnelingSuspicionRule _rule = new();
    private static readonly DateTime T0 = new(2026, 10, 27, 0, 0, 0, DateTimeKind.Utc);
    public R021AdvancedAccuracyBatchTests() => RuleEngine.ResetRuntimeStateForReplay();
    public void Dispose() => RuleEngine.ResetRuntimeStateForReplay();
    private async Task<RuleEvaluationResult> See(TrafficRecord record, int second = 0)
        => await _rule.EvaluateAsync(new RuleEvaluationContext(record, Sensitivity.Balanced, T0.AddSeconds(second)));

    private static TrafficRecord Echo(string dst = "8.8.8.8", string src = "10.21.0.2", int length = 80)
        => new() { Protocol = "ICMP", Source = src, Destination = dst, Length = length, IcmpTypeCode = 0x0800 };


    [Fact] public async Task Twenty_Attributed_Echoes_Cross_Configured_Packet_Threshold()
    {
        for (int i = 0; i < 19; i++) Assert.False((await See(Echo(), i)).Matched);
        var evt = Assert.Single((await See(Echo(), 19)).Events);
        Assert.Equal("R021", evt.RuleId);
        Assert.Equal("10.21.0.2", evt.SourceIp);
        Assert.Equal("8.8.8.8", evt.DestinationIp);
        Assert.Equal(20, evt.Count);
    }
    [Fact] public async Task Icmp_Errors_Do_Not_Inflate_Echo_Window()
    {
        for (int i = 0; i < 19; i++) await See(Echo(), i);
        var error = Echo(); error.IcmpTypeCode = 0x0301;
        Assert.False((await See(error, 19)).Matched);
        Assert.True((await See(Echo(), 20)).Matched);
    }
    [Fact] public async Task Invalid_Endpoints_And_Empty_Packets_Do_Not_Prime_State()
    {
        foreach (var record in new[] { Echo(src: "invalid"), Echo(dst: "invalid"), Echo(length: 0) })
            Assert.False((await See(record)).Matched);
        for (int i = 0; i < 19; i++) Assert.False((await See(Echo(), i)).Matched);
        Assert.True((await See(Echo(), 19)).Matched);
    }
    [Fact] public async Task Independent_Destinations_Cannot_Combine_Into_A_False_Tunnel()
    {
        for (int i = 0; i < 19; i++)
        {
            Assert.False((await See(Echo("8.8.8.8"), i)).Matched);
            Assert.False((await See(Echo("9.9.9.9"), i)).Matched);
        }
        Assert.Equal("9.9.9.9", Assert.Single((await See(Echo("9.9.9.9"), 19)).Events).DestinationIp);
    }
    [Fact] public async Task Future_Dated_Observations_Are_Not_Transferred_Backward()
    {
        await See(Echo(), 500);
        for (int i = 0; i < 19; i++) Assert.False((await See(Echo(), i)).Matched);
        Assert.True((await See(Echo(), 19)).Matched);
    }
    [Fact] public async Task Cooldown_Clears_Triggered_Window_But_Does_Not_Block_Another_Destination()
    {
        for (int i = 0; i < 20; i++) await See(Echo(), i);
        for (int i = 20; i < 40; i++) await See(Echo(), i);
        var suppressed = await See(Echo(), 40);
        Assert.False(suppressed.Matched);
        for (int i = 20; i < 39; i++) await See(Echo("9.9.9.9"), i);
        Assert.Equal("9.9.9.9", Assert.Single((await See(Echo("9.9.9.9"), 39)).Events).DestinationIp);
    }

}
