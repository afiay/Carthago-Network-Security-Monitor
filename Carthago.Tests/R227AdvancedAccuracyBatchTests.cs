// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R227AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch226230Context.Sample(227);
    private static RuleEvaluationContext At(TrafficRecord r, int seconds = 0)
        => NetworkBatch226230Context.At(r, seconds);
    private static async Task<bool> Hit(TrafficRecord r)
        => (await new R227_ProfinetDcpDiscoverySuspiciousRule().EvaluateAsync(At(r))).Matched;

    // Contract-only: current PacketHandler cannot produce Ethernet DCP records.
    [Fact] public async Task Decoded_L2_Identify_Frame_Burst_Matches_Contract()
    {
        var rule = new R227_ProfinetDcpDiscoverySuspiciousRule();
        for (int i = 0; i < 7; i++)
            Assert.False((await rule.EvaluateAsync(At(Sample(), i))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Sample(), 7))).Matched);
    }
    [Fact] public async Task Ordinary_Profinet_Udp_Port_Is_Not_Dcp_L2_Proof()
    {
        var r = Sample(); r.Protocol = "UDP"; r.IsUdp = true; r.DestinationPort = 34964;
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Packet_Info_Identify_All_Does_Not_Prove_L2_Decoding()
    {
        var r = Sample(); r.ApplicationProtocol = null; r.Info = "DCP identify all";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Invalid_Source_Mac_Fails_Closed()
    {
        var r = Sample(); r.MacSource = "not-a-mac";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Generic_Profinet_Is_Not_Dcp_Identify()
    {
        var r = Sample(); r.ApplicationProtocol = "profinet";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Duplicate_Frame_Id_Cannot_Fill_Window()
    {
        var rule = new R227_ProfinetDcpDiscoverySuspiciousRule();
        var r = Sample();
        Assert.False((await rule.EvaluateAsync(At(r))).Matched);
        for (int i = 1; i < 8; i++)
            Assert.False((await rule.EvaluateAsync(At(r, i))).Matched);
    }
    [Fact] public async Task Independent_Mac_Sources_Do_Not_Join_Windows()
    {
        var rule = new R227_ProfinetDcpDiscoverySuspiciousRule();
        for (int i = 0; i < 7; i++)
        {
            var a = Sample(); a.MacSource = "02:00:00:00:00:01";
            var b = Sample(); b.MacSource = "02:00:00:00:00:02";
            Assert.False((await rule.EvaluateAsync(At(a, i))).Matched);
            Assert.False((await rule.EvaluateAsync(At(b, i))).Matched);
        }
    }
    [Fact] public async Task Out_Of_Order_Frame_Is_Ignored()
    {
        var rule = new R227_ProfinetDcpDiscoverySuspiciousRule();
        Assert.False((await rule.EvaluateAsync(At(Sample(), 20))).Matched);
        Assert.False((await rule.EvaluateAsync(At(Sample(), 5))).Matched);
    }
    [Fact] public void Original_Shadow_Mode_And_Confidence_Floor_Remain()
    {
        var p = new R227_ProfinetDcpDiscoverySuspiciousRule().PrecisionProfile;
        Assert.Equal(76, p.MinimumConfidence); Assert.Equal(RuleRuntimeMode.Shadow, p.DefaultMode);
    }
}
