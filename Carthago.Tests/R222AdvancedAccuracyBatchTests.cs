// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R222AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch221225Context.Flow(222);
    private static RuleEvaluationContext At(TrafficRecord r, int seconds = 0)
        => NetworkBatch221225Context.At(r, seconds);
    private static async Task<bool> Burst(Action<TrafficRecord>? change = null, int count = 3)
    {
        var rule = new R222_UnauthorizedOverlayNetworkEgressRule();
        var source = Sample().Source;
        bool last = false;
        for (var i = 0; i < count; i++)
        {
            var r = Sample(); r.Source = source; change?.Invoke(r);
            last = (await rule.EvaluateAsync(At(r, i))).Matched;
        }
        return last;
    }

    [Fact] public async Task Repeated_Attributed_Process_And_Endpoint_Reaches_Threshold()
        => Assert.True(await Burst());

    [Fact] public async Task Vendor_Host_Without_Remote_Client_Process_Is_Benign()
        => Assert.False(await Burst(r => r.ProcessName = "chrome.exe"));

    [Fact] public async Task Packet_Info_Only_Vendor_Claim_Is_Not_Evidence()
        => Assert.False(await Burst(r =>
        {
            r.ProcessName = "chrome.exe"; r.Sni = "docs.example.net";
            r.Info = "anydesk tailscale teamviewer cloudflared ngrok";
        }));

    [Fact] public async Task Contradictory_Udp_Flow_Is_Not_Valid_Tcp_Client_Beacon()
        => Assert.False(await Burst(r => { r.IsTcp = false; r.IsUdp = true; r.Protocol = "TCP"; }));

    [Fact] public async Task Private_Destination_Is_Not_Internet_Egress()
        => Assert.False(await Burst(r => r.Destination = "10.221.0.10"));

    [Fact] public async Task Process_And_Unrelated_Vendor_Host_Do_Not_Corroborate()
        => Assert.False(await Burst(r => r.Sni = "other.example.net"));

    [Fact] public async Task Duplicate_Packet_Id_Cannot_Fill_Observation_Window()
    {
        var rule = new R222_UnauthorizedOverlayNetworkEgressRule(); var r = Sample();
        for (var i = 0; i < 3; i++)
            Assert.False((await rule.EvaluateAsync(At(r, i))).Matched);
    }

    [Fact] public async Task Out_Of_Order_Observation_Does_Not_Fill_Window()
    {
        var rule = new R222_UnauthorizedOverlayNetworkEgressRule(); var source = Sample().Source;
        var first = Sample(); first.Source = source;
        Assert.False((await rule.EvaluateAsync(At(first, 10))).Matched);
        var old = Sample(); old.Source = source;
        Assert.False((await rule.EvaluateAsync(At(old, 5))).Matched);
        for (var i = 1; i < 2; i++)
        {
            var r = Sample(); r.Source = source;
            Assert.False((await rule.EvaluateAsync(At(r, 10 + i))).Matched);
        }
    }

    [Fact] public async Task Independent_Source_Cannot_Complete_Other_Source_Window()
    {
        var rule = new R222_UnauthorizedOverlayNetworkEgressRule(); var source = Sample().Source;
        for (var i = 0; i < 2; i++)
        {
            var r = Sample(); r.Source = source;
            Assert.False((await rule.EvaluateAsync(At(r, i))).Matched);
        }
        Assert.False((await rule.EvaluateAsync(At(Sample(), 3))).Matched);
    }

    [Fact] public async Task Expired_Observations_Do_Not_Reach_Threshold()
    {
        var rule = new R222_UnauthorizedOverlayNetworkEgressRule(); var source = Sample().Source;
        for (var i = 0; i < 2; i++)
        {
            var r = Sample(); r.Source = source;
            Assert.False((await rule.EvaluateAsync(At(r, i))).Matched);
        }
        var later = Sample(); later.Source = source;
        Assert.False((await rule.EvaluateAsync(At(later, 1000))).Matched);
    }

    [Fact] public async Task Vendor_Subdomain_And_Packet_Info_Not_Stored_In_Rule_Evidence()
    {
        var rule = new R222_UnauthorizedOverlayNetworkEgressRule(); var source = Sample().Source;
        for (var i = 0; i < 3; i++)
        {
            var r = Sample(); r.Source = source;
            r.Sni = "tenantSecretMarker." + r.Sni;
            r.Info = "secretInfoMarker device-password=topsecret";
            var result = await rule.EvaluateAsync(At(r, i));
            if (i == 2)
            {
                Assert.True(result.Matched);
                Assert.DoesNotContain(Assert.Single(result.Events).StructuredEvidence!.Items,
                    e => e.Value.Contains("tenantSecretMarker", StringComparison.Ordinal)
                        || e.Value.Contains("secretInfoMarker", StringComparison.Ordinal));
            }
        }
    }

    [Fact] public void Confidence_And_Default_Mode_Are_Preserved()
    {
        var p = new R222_UnauthorizedOverlayNetworkEgressRule().PrecisionProfile;
        Assert.Equal(82, p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
        Assert.Equal(3, p.Threshold);
    }

    [Fact] public async Task WireGuard_Udp_Service_Port_With_Process_Is_Observable()
        => Assert.True(await Burst(r =>
        {
            r.ProcessName = "wireguard.exe"; r.Sni = null;
            r.IsTcp = false; r.IsUdp = true; r.Protocol = "UDP"; r.DestinationPort = 51820;
        }));
    [Fact] public async Task Bare_WireGuard_Port_Without_Process_Is_Not_Sufficient()
        => Assert.False(await Burst(r =>
        {
            r.ProcessName = null; r.Sni = null;
            r.IsTcp = false; r.IsUdp = true; r.Protocol = "UDP"; r.DestinationPort = 51820;
        }));
    [Fact] public async Task Cloudflared_And_Argotunnel_Host_Are_Corroborated()
        => Assert.True(await Burst(r => { r.ProcessName = "cloudflared.exe"; r.Sni = "region1.v2.argotunnel.com"; }));
}
