// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules.IotOt;
using Xunit;

namespace Carthago.Tests;

public sealed class R119AdvancedAccuracyBatchTests
{
    private readonly R119_CameraNVRExternalBeaconRule _rule = new();

    [Fact] public async Task Five_Independent_External_Camera_Observations_Reach_Gate()
    {
        var source = NetworkBatch116120Context.Source();
        for (var i = 0; i < 4; i++)
            Assert.False((await _rule.EvaluateAsync(NetworkBatch116120Context.Context(
                NetworkBatch116120Context.Camera(source), i * 120))).Matched);
        var last = await _rule.EvaluateAsync(NetworkBatch116120Context.Context(
            NetworkBatch116120Context.Camera(source), 480));
        Assert.True(last.Matched);
        Assert.Contains(Assert.Single(last.Events).StructuredEvidence!.Items,
            item => item.Key == "count" && item.Value == "5");
    }

    [Fact] public async Task Four_External_Observations_Are_Insufficient()
    {
        var source = NetworkBatch116120Context.Source();
        for (var i = 0; i < 4; i++)
            Assert.False((await _rule.EvaluateAsync(NetworkBatch116120Context.Context(
                NetworkBatch116120Context.Camera(source), i * 120))).Matched);
    }

    [Fact] public async Task Info_Only_Camera_Claim_From_Browser_Cannot_Seed_Beacon()
    {
        var source = NetworkBatch116120Context.Source();
        for (var i = 0; i < 6; i++)
        {
            var record = NetworkBatch116120Context.Camera(source);
            record.ProcessName = "chrome.exe";
            Assert.False((await _rule.EvaluateAsync(NetworkBatch116120Context.Context(record, i * 120))).Matched);
        }
    }

    [Fact] public async Task Port_554_Without_Rtsp_Classification_Is_Not_Direct_Stream()
    {
        var record = NetworkBatch116120Context.Camera(NetworkBatch116120Context.Source());
        record.DestinationPort = 554;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch116120Context.Context(record))).Matched);
    }

    [Fact] public async Task Classified_Rtsp_To_External_Destination_Is_Direct_Stream()
    {
        var record = NetworkBatch116120Context.Camera(NetworkBatch116120Context.Source());
        record.DestinationPort = 554; record.ApplicationProtocol = "RTSP";
        record.ApplicationService = "RTSP";
        var result = await _rule.EvaluateAsync(NetworkBatch116120Context.Context(record));
        Assert.True(result.Matched);
        Assert.Contains(Assert.Single(result.Events).StructuredEvidence!.Items,
            item => item.Key == "matched_conditions" && item.Value.Contains("direct_rtsp_external"));
    }

    [Fact] public async Task Duplicate_Packet_Delivery_Cannot_Manufacture_Five_Beacons()
    {
        var record = NetworkBatch116120Context.Camera(NetworkBatch116120Context.Source());
        for (var i = 0; i < 9; i++)
            Assert.False((await _rule.EvaluateAsync(NetworkBatch116120Context.Context(record, i * 120))).Matched);
    }

    [Fact] public async Task Camera_Private_Cloud_Token_Is_Not_Alert_Evidence()
    {
        const string secret = "camera-cloud-secret-119";
        var record = NetworkBatch116120Context.Camera(NetworkBatch116120Context.Source());
        record.DestinationPort = 554; record.ApplicationProtocol = "RTSP";
        record.ApplicationService = "RTSP"; record.Info += " token=" + secret;
        var result = await _rule.EvaluateAsync(NetworkBatch116120Context.Context(record));
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain(secret, evt.Evidence);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items,
            item => item.Value.Contains(secret, StringComparison.Ordinal));
    }
}
