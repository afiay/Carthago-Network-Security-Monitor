// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules.IotOt;
using Xunit;

namespace Carthago.Tests;

public sealed class R115AdvancedAccuracyBatchTests
{
    private readonly R115_MQTTHighFrequencyPublishBurstRule _rule = new();

    [Fact] public async Task Ninety_Independent_External_Publishes_Reach_Threshold()
    {
        var source = NetworkBatch111115Context.Source();
        for (var i = 0; i < 89; i++)
            Assert.False((await _rule.EvaluateAsync(NetworkBatch111115Context.Mqtt(
                i * 500, source, info: "publish topic=device/" + (i % 12)))).Matched);
        var last = await _rule.EvaluateAsync(NetworkBatch111115Context.Mqtt(
            44500, source, info: "publish topic=device/5"));
        Assert.True(last.Matched);
        Assert.Contains(Assert.Single(last.Events).StructuredEvidence!.Items,
            x => x.Key == "count" && x.Value == "90");
    }

    [Fact] public async Task Eighty_Nine_External_Publishes_Are_Insufficient()
    {
        var source = NetworkBatch111115Context.Source();
        for (var i = 0; i < 89; i++)
            Assert.False((await _rule.EvaluateAsync(NetworkBatch111115Context.Mqtt(
                i * 500, source))).Matched);
    }

    [Fact] public async Task Ninety_Internal_Single_Topic_Publishes_Remain_Below_Elevated_Gate()
    {
        var source = NetworkBatch111115Context.Source();
        for (var i = 0; i < 90; i++)
            Assert.False((await _rule.EvaluateAsync(NetworkBatch111115Context.Mqtt(
                i * 500, source, destination: "10.41.0.20",
                host: "broker.internal.local", info: "publish topic=device/temp"))).Matched);
    }

    [Fact] public async Task Acknowledgements_Cannot_Manufacture_Publish_Burst()
    {
        var source = NetworkBatch111115Context.Source();
        for (var i = 0; i < 95; i++)
            Assert.False((await _rule.EvaluateAsync(NetworkBatch111115Context.Mqtt(
                i * 400, source, info: "puback topic=device/temp"))).Matched);
    }

    [Fact] public async Task Duplicate_Record_Delivery_Does_Not_Inflate_Burst()
    {
        var c = NetworkBatch111115Context.Mqtt(0, NetworkBatch111115Context.Source());
        for (var i = 0; i < 110; i++)
            Assert.False((await _rule.EvaluateAsync(c)).Matched);
    }

    [Fact] public async Task Independent_Brokers_Cannot_Pool_Burst_Counts()
    {
        var source = NetworkBatch111115Context.Source();
        for (var i = 0; i < 45; i++)
        {
            Assert.False((await _rule.EvaluateAsync(NetworkBatch111115Context.Mqtt(
                i * 1000, source, destination: "198.51.100.40",
                host: "broker.hivemq.com"))).Matched);
            Assert.False((await _rule.EvaluateAsync(NetworkBatch111115Context.Mqtt(
                i * 1000, source, destination: "198.51.100.41",
                host: "test.mosquitto.org"))).Matched);
        }
    }

    [Fact] public async Task Contradictory_Http_Or_Udp_Cannot_Seed_Burst()
    {
        var source = NetworkBatch111115Context.Source();
        var http = NetworkBatch111115Context.Mqtt(0, source);
        http.Record.HttpMethod = "POST";
        Assert.False((await _rule.EvaluateAsync(http)).Matched);
        var udp = NetworkBatch111115Context.Mqtt(1000, source);
        udp.Record.IsTcp = false; udp.Record.IsUdp = true;
        Assert.False((await _rule.EvaluateAsync(udp)).Matched);
    }

    [Fact] public async Task Topic_Secrets_Are_Redacted_Even_On_Positive_Burst()
    {
        const string secret = "mqtt-secret-topic-115";
        var source = NetworkBatch111115Context.Source();
        Carthago.Engine.Rules.RuleEvaluationResult? last = null;
        for (var i = 0; i < 90; i++)
            last = await _rule.EvaluateAsync(NetworkBatch111115Context.Mqtt(
                i * 500, source, info: "publish topic=private/" + secret + "/" + (i % 10)));
        Assert.NotNull(last);
        Assert.True(last!.Matched);
        var evt = Assert.Single(last.Events);
        Assert.DoesNotContain(secret, evt.Evidence);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items,
            x => x.Value.Contains(secret, StringComparison.Ordinal));
    }
}
