// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R230AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch226230Context.Sample(230);
    private static RuleEvaluationContext At(TrafficRecord r, int seconds = 0)
        => NetworkBatch226230Context.At(r, seconds);
    private static async Task<bool> Hit(TrafficRecord r)
        => (await new R230_MqttLastWillSuspiciousRule().EvaluateAsync(At(r))).Matched;

    [Fact] public async Task Parsed_Connect_With_Control_Will_Matches()
        => Assert.True(await Hit(Sample()));
    [Fact] public async Task Routine_Internal_Availability_Will_Is_Benign()
    {
        var r = Sample(); r.MqttWillTopic = "devices/availability";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Packet_Info_Last_Will_Claim_Is_Not_Parsed_Will()
    {
        var r = Sample(); r.MqttWillTopic = null; r.Info = "last will topic=devices/control";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Publish_Is_Not_Connect_Will()
    {
        var r = Sample(); r.ApplicationProtocol = "mqtt.publish"; r.MqttRetain = true;
        Assert.False(await Hit(r));
    }
    [Fact] public async Task External_Broker_With_Ordinary_Will_Is_Eligible()
    {
        var r = Sample(); r.Destination = "198.51.100.230"; r.MqttWillTopic = "devices/availability";
        Assert.True(await Hit(r));
    }
    [Fact] public async Task Tls_Port_Without_Decryption_Is_Not_Connect_Will()
    {
        var r = Sample(); r.DestinationPort = 8883; r.TlsVersion = "TLS1.3";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Duplicate_Id_Is_Not_A_New_Will_Configuration()
    {
        var rule = new R230_MqttLastWillSuspiciousRule(); var r = Sample();
        Assert.True((await rule.EvaluateAsync(At(r))).Matched);
        Assert.False((await rule.EvaluateAsync(At(r, 1))).Matched);
    }
    [Fact] public async Task Will_Topic_And_Info_Are_Redacted()
    {
        var r = Sample(); r.MqttWillTopic = "devices/control/secret-token-67890";
        r.Info = "password=private-marker";
        var x = await new R230_MqttLastWillSuspiciousRule().EvaluateAsync(At(r));
        Assert.True(x.Matched);
        Assert.DoesNotContain(Assert.Single(x.Events).StructuredEvidence!.Items,
            e => e.Value.Contains("secret-token-67890", StringComparison.Ordinal)
                || e.Value.Contains("private-marker", StringComparison.Ordinal));
    }
    [Fact] public void Shadow_Mode_And_Confidence_Floor_Remain()
    {
        var p = new R230_MqttLastWillSuspiciousRule().PrecisionProfile;
        Assert.Equal(74, p.MinimumConfidence); Assert.Equal(RuleRuntimeMode.Shadow, p.DefaultMode);
    }
}
