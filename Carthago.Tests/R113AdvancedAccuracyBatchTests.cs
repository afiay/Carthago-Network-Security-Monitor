// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules.IotOt;
using Xunit;

namespace Carthago.Tests;

public sealed class R113AdvancedAccuracyBatchTests
{
    private readonly R113_MQTTBrokerConnectionToUnapprovedHostRule _rule = new();

    [Fact] public async Task Parser_Attributed_External_Mqtt_Broker_Matches()
    {
        var c = NetworkBatch111115Context.Mqtt(0, NetworkBatch111115Context.Source(),
            info: "mqtt connect clientid=sensor");
        var result = await _rule.EvaluateAsync(c);
        Assert.True(result.Matched);
        Assert.Equal("R113", Assert.Single(result.Events).RuleId);
    }

    [Fact] public async Task Internal_Broker_Is_Not_Public_Egress()
    {
        var c = NetworkBatch111115Context.Mqtt(0, NetworkBatch111115Context.Source(),
            destination: "10.41.0.20", host: "broker.internal.local");
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
    }

    [Fact] public async Task Info_Keyword_And_Port_Alone_Cannot_Forge_Mqtt()
    {
        var c = NetworkBatch111115Context.Mqtt(0, NetworkBatch111115Context.Source(),
            info: "mqtt connect clientid=sensor");
        c.Record.Protocol = "TCP";
        c.Record.ApplicationProtocol = "HTTP";
        c.Record.ApplicationService = "HTTPS";
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
    }

    [Fact] public async Task Udp_And_Http_Contradictions_Are_Rejected()
    {
        var c = NetworkBatch111115Context.Mqtt(0, NetworkBatch111115Context.Source());
        c.Record.IsTcp = false; c.Record.IsUdp = true;
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        var other = NetworkBatch111115Context.Mqtt(0, NetworkBatch111115Context.Source());
        other.Record.HttpMethod = "GET";
        Assert.False((await _rule.EvaluateAsync(other)).Matched);
    }

    [Fact] public async Task Contradictory_Sni_Or_Invalid_Destination_Is_Rejected()
    {
        var c = NetworkBatch111115Context.Mqtt(0, NetworkBatch111115Context.Source());
        c.Record.Sni = "other.example";
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        var other = NetworkBatch111115Context.Mqtt(0, NetworkBatch111115Context.Source());
        other.Record.Destination = "not-an-ip";
        Assert.False((await _rule.EvaluateAsync(other)).Matched);
    }

    [Fact] public async Task Mqtt_Client_Identifier_Is_Not_Copied_To_Evidence()
    {
        const string secret = "client-private-identifier-113";
        var c = NetworkBatch111115Context.Mqtt(0, NetworkBatch111115Context.Source(),
            info: "mqtt connect clientid=" + secret);
        var result = await _rule.EvaluateAsync(c);
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain(secret, evt.Evidence);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items, x => x.Value.Contains(secret, StringComparison.Ordinal));
    }

    [Fact] public async Task Repeated_Broker_Connection_Uses_Rule_Owned_Cooldown()
    {
        var source = NetworkBatch111115Context.Source();
        Assert.True((await _rule.EvaluateAsync(NetworkBatch111115Context.Mqtt(0, source))).Matched);
        var second = await _rule.EvaluateAsync(NetworkBatch111115Context.Mqtt(1000, source));
        Assert.True(second.Matched);
        Assert.Contains(Assert.Single(second.Events).StructuredEvidence!.Items,
            x => x.Key == "suppression.remainingSeconds");
    }
}
