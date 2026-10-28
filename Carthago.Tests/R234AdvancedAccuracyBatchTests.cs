// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R234AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch231235Context.Sample(234);
    private static RuleEvaluationContext At(TrafficRecord r, int seconds = 0)
        => NetworkBatch231235Context.At(r, seconds);
    private static async Task<bool> Hit(TrafficRecord r)
        => (await new R234_IpCameraRtspExternalStreamRule().EvaluateAsync(At(r))).Matched;

    [Fact] public async Task Typed_Rtsp_Play_Request_To_External_Endpoint_Matches()
        => Assert.True(await Hit(Sample()));
    [Fact] public async Task Internal_Camera_Viewing_Is_Benign()
    {
        var r = Sample(); r.Destination = "10.231.0.200";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Port_554_And_Info_Cannot_Forge_Rtsp_Play()
    {
        var r = Sample(); r.ApplicationProtocol = null; r.Info = "RTSP PLAY camera";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Rtsp_Describe_Only_Is_Not_A_Stream_Request()
    {
        var r = Sample(); r.ApplicationProtocol = "rtsp.describe";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Contradictory_Udp_Transport_Is_Rejected()
    {
        var r = Sample(); r.IsTcp = false; r.IsUdp = true; r.Protocol = "UDP";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Wrong_Port_Is_Not_Attributed_Rtsp()
    {
        var r = Sample(); r.DestinationPort = 443;
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Duplicate_Id_Is_Not_New_Play_Request()
    {
        var rule = new R234_IpCameraRtspExternalStreamRule(); var r = Sample();
        Assert.True((await rule.EvaluateAsync(At(r))).Matched);
        Assert.False((await rule.EvaluateAsync(At(r, 1))).Matched);
    }
    [Fact] public async Task Sensitive_Rtsp_Url_Info_Is_Not_Exported()
    {
        var r = Sample(); r.Info = "rtsp://user:private-marker@camera.local/live";
        var x = await new R234_IpCameraRtspExternalStreamRule().EvaluateAsync(At(r));
        Assert.True(x.Matched);
        Assert.DoesNotContain(Assert.Single(x.Events).StructuredEvidence!.Items,
            e => e.Value.Contains("private-marker", StringComparison.Ordinal));
    }
    [Fact] public void Original_Alert_And_Confidence_Floor()
    {
        var p = new R234_IpCameraRtspExternalStreamRule().PrecisionProfile;
        Assert.Equal(84, p.MinimumConfidence); Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
