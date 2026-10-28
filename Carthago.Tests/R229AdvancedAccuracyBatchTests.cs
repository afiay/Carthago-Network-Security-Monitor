// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R229AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch226230Context.Sample(229);
    private static RuleEvaluationContext At(TrafficRecord r, int seconds = 0)
        => NetworkBatch226230Context.At(r, seconds);
    private static async Task<bool> Hit(TrafficRecord r)
        => (await new R229_MqttRetainedTopicAbuseRule().EvaluateAsync(At(r))).Matched;

    [Fact] public async Task Parsed_Retained_Control_Publish_Matches()
        => Assert.True(await Hit(Sample()));
    [Fact] public async Task Benign_Internal_Retained_Status_Is_Suppressed()
    {
        var r = Sample(); r.MqttTopic = "sensors/temperature/status";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Unparsed_Info_Retain_Flag_Is_Not_Evidence()
    {
        var r = Sample(); r.MqttRetain = null; r.Info = "PUBLISH retain=1 topic=devices/cmd";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Similar_Looking_Commanded_Topic_Is_Not_Control()
    {
        var r = Sample(); r.MqttTopic = "devices/commanded";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task External_Broker_Still_Qualifies_With_Ordinary_Topic()
    {
        var r = Sample(); r.Destination = "198.51.100.229"; r.MqttTopic = "devices/status";
        Assert.True(await Hit(r));
    }
    [Fact] public async Task Encrypted_Mqtt_Port_Is_Not_Parsed_Cleartext()
    {
        var r = Sample(); r.DestinationPort = 8883; r.TlsVersion = "TLS1.3";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Duplicate_Id_Does_Not_Count_As_Another_Publish()
    {
        var rule = new R229_MqttRetainedTopicAbuseRule(); var r = Sample();
        Assert.True((await rule.EvaluateAsync(At(r))).Matched);
        Assert.False((await rule.EvaluateAsync(At(r, 1))).Matched);
    }
    [Fact] public async Task Topic_And_Info_Secrets_Are_Redacted()
    {
        var r = Sample(); r.MqttTopic = "devices/cmd/secret-token-12345"; r.Info = "password=private-marker";
        var x = await new R229_MqttRetainedTopicAbuseRule().EvaluateAsync(At(r));
        Assert.True(x.Matched);
        Assert.DoesNotContain(Assert.Single(x.Events).StructuredEvidence!.Items,
            e => e.Value.Contains("secret-token-12345", StringComparison.Ordinal)
                || e.Value.Contains("private-marker", StringComparison.Ordinal));
    }
    [Fact] public void Shadow_Mode_And_Confidence_Floor_Remain()
    {
        var p = new R229_MqttRetainedTopicAbuseRule().PrecisionProfile;
        Assert.Equal(74, p.MinimumConfidence); Assert.Equal(RuleRuntimeMode.Shadow, p.DefaultMode);
    }
}
