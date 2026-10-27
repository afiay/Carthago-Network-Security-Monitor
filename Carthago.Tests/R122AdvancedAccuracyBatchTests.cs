// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules.IotOt;
using Xunit;

namespace Carthago.Tests;

public sealed class R122AdvancedAccuracyBatchTests
{
    private readonly R122_CoAPZigbeeGatewaySuspiciousEgressRule _rule = new();
    [Fact] public async Task Classified_External_Coap_Is_Candidate()
    {
        Assert.True((await _rule.EvaluateAsync(NetworkBatch121125Context.At(NetworkBatch121125Context.Coap()))).Matched);
    }
    [Fact] public async Task Internal_Coap_Is_Benign()
    {
        var r = NetworkBatch121125Context.Coap(); r.Destination = "10.122.1.20";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch121125Context.At(r))).Matched);
    }
    [Fact] public async Task Coap_Port_Without_Classification_Fails_Closed()
    {
        var r = NetworkBatch121125Context.Coap(); r.ApplicationProtocol = "UDP"; r.ApplicationService = null;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch121125Context.At(r))).Matched);
    }
    [Fact] public async Task Gateway_Reaches_Existing_Three_Event_Threshold()
    {
        for (int i = 0; i < 2; i++)
            Assert.True((await _rule.EvaluateAsync(NetworkBatch121125Context.At(NetworkBatch121125Context.Zigbee(), i))).Matched);
        var result = await _rule.EvaluateAsync(NetworkBatch121125Context.At(NetworkBatch121125Context.Zigbee(), 2));
        Assert.True(result.Matched);
        Assert.Contains(Assert.Single(result.Events).StructuredEvidence!.Items,
            x => x.Key == "count" && x.Value == "3");
    }
    [Fact] public async Task Duplicate_Packet_Identity_Does_Not_Inflate_Count()
    {
        var r = NetworkBatch121125Context.Zigbee();
        for (int i = 0; i < 4; i++)
            await _rule.EvaluateAsync(NetworkBatch121125Context.At(r, i));
        var result = await _rule.EvaluateAsync(NetworkBatch121125Context.At(r, 5));
        Assert.Contains(Assert.Single(result.Events).StructuredEvidence!.Items,
            x => x.Key == "count" && x.Value == "1");
    }
    [Fact] public async Task Spoofed_Info_Without_Gateway_Process_Is_Benign()
    {
        var r = NetworkBatch121125Context.Zigbee(); r.ProcessName = "chrome.exe";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch121125Context.At(r))).Matched);
    }
    [Fact] public async Task Contradictory_Transport_And_Secret_Are_Handled()
    {
        var bad = NetworkBatch121125Context.Coap(); bad.IsTcp = true;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch121125Context.At(bad))).Matched);
        const string secret = "zigbee-private-122";
        var good = NetworkBatch121125Context.Zigbee(); good.Info += " token=" + secret;
        var evt = Assert.Single((await _rule.EvaluateAsync(NetworkBatch121125Context.At(good))).Events);
        Assert.DoesNotContain(secret, evt.Evidence);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items, x => x.Value.Contains(secret, StringComparison.Ordinal));
    }
}
