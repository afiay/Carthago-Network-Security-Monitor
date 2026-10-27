// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules.IotOt;
using Xunit;

namespace Carthago.Tests;

public sealed class R114AdvancedAccuracyBatchTests
{
    private readonly R114_MQTTTopicEnumerationRule _rule = new();

    [Fact] public async Task Explicit_Wildcard_Subscribe_Is_Detected()
    {
        var c = NetworkBatch111115Context.Mqtt(0, NetworkBatch111115Context.Source(),
            info: "subscribe topic=building/#");
        var result = await _rule.EvaluateAsync(c);
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.Equal("R114", evt.RuleId);
        Assert.Contains(evt.StructuredEvidence!.Items,
            x => x.Key == "mqtt.topic" && x.Value == "[redacted]");
    }

    [Fact] public async Task Publish_To_Wildcard_Looking_Topic_Is_Not_Enumeration()
    {
        var c = NetworkBatch111115Context.Mqtt(0, NetworkBatch111115Context.Source(),
            info: "publish topic=building/#");
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
    }

    [Fact] public async Task Info_Only_Subscribe_On_Http_Is_Rejected()
    {
        var c = NetworkBatch111115Context.Mqtt(0, NetworkBatch111115Context.Source(),
            info: "subscribe topic=building/#");
        c.Record.ApplicationProtocol = "HTTP";
        c.Record.ApplicationService = "HTTPS";
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
    }

    [Fact] public async Task Invalid_Wildcard_Filter_Is_Rejected()
    {
        var c = NetworkBatch111115Context.Mqtt(0, NetworkBatch111115Context.Source(),
            info: "subscribe topic=building/#/secret");
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
    }

    [Fact] public async Task Twenty_Distinct_Exact_Subscriptions_Reach_Threshold()
    {
        var source = NetworkBatch111115Context.Source();
        for (var i = 0; i < 19; i++)
            Assert.False((await _rule.EvaluateAsync(NetworkBatch111115Context.Mqtt(i * 1000,
                source, info: "subscribe topic=building/sensor" + i))).Matched);
        var last = await _rule.EvaluateAsync(NetworkBatch111115Context.Mqtt(19000,
            source, info: "subscribe topic=building/sensor19"));
        Assert.True(last.Matched);
        Assert.Contains(Assert.Single(last.Events).StructuredEvidence!.Items,
            x => x.Key == "count" && x.Value == "20");
    }

    [Fact] public async Task Replayed_Record_Id_Cannot_Manufacture_Topic_Sweep()
    {
        var c = NetworkBatch111115Context.Mqtt(0, NetworkBatch111115Context.Source(),
            info: "subscribe topic=building/sensor0");
        for (var i = 0; i < 30; i++)
        {
            c.Record.Info = "subscribe topic=building/sensor" + i;
            Assert.False((await _rule.EvaluateAsync(c)).Matched);
        }
    }

    [Fact] public async Task Different_Brokers_Do_Not_Pool_Topic_Sweeps()
    {
        var source = NetworkBatch111115Context.Source();
        for (var i = 0; i < 10; i++)
        {
            Assert.False((await _rule.EvaluateAsync(NetworkBatch111115Context.Mqtt(
                i * 1000, source, destination: "10.41.0.20", host: "broker-a.local",
                info: "subscribe topic=building/sensor" + i))).Matched);
            Assert.False((await _rule.EvaluateAsync(NetworkBatch111115Context.Mqtt(
                i * 1000, source, destination: "10.41.0.21", host: "broker-b.local",
                info: "subscribe topic=building/sensor" + i))).Matched);
        }
    }

    [Fact] public async Task Sensitive_Topic_Is_Not_Exposed_In_Alert()
    {
        const string secret = "device-secret-topic-114";
        var c = NetworkBatch111115Context.Mqtt(0, NetworkBatch111115Context.Source(),
            info: "subscribe topic=private/" + secret + "/#");
        var result = await _rule.EvaluateAsync(c);
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain(secret, evt.Description);
        Assert.DoesNotContain(secret, evt.Evidence);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items,
            x => x.Value.Contains(secret, StringComparison.Ordinal));
    }
}
