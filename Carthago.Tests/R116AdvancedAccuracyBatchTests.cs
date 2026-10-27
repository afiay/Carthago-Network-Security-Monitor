// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules.IotOt;
using Xunit;

namespace Carthago.Tests;

public sealed class R116AdvancedAccuracyBatchTests
{
    private readonly R116_UPnPExposureDiscoveryAbuseRule _rule = new();

    [Fact] public async Task Classified_External_Ssdp_Discovery_Is_A_Candidate()
    {
        var result = await _rule.EvaluateAsync(NetworkBatch116120Context.Context(
            NetworkBatch116120Context.Ssdp(NetworkBatch116120Context.Source())));
        Assert.True(result.Matched);
        Assert.Contains(Assert.Single(result.Events).StructuredEvidence!.Items,
            item => item.Key == "matched_conditions" && item.Value.Contains("external_destination"));
    }

    [Fact] public async Task Twenty_Five_Independent_Local_Discoveries_Reach_Existing_Threshold()
    {
        var source = NetworkBatch116120Context.Source();
        for (var i = 0; i < 24; i++)
            Assert.False((await _rule.EvaluateAsync(NetworkBatch116120Context.Context(
                NetworkBatch116120Context.Ssdp(source, "239.255.255.250"), i))).Matched);
        var last = await _rule.EvaluateAsync(NetworkBatch116120Context.Context(
            NetworkBatch116120Context.Ssdp(source, "239.255.255.250"), 24));
        Assert.True(last.Matched);
        Assert.Contains(Assert.Single(last.Events).StructuredEvidence!.Items,
            item => item.Key == "count" && item.Value == "25");
    }

    [Fact] public async Task Ordinary_Single_Multicast_Discovery_Remains_Benign()
    {
        Assert.False((await _rule.EvaluateAsync(NetworkBatch116120Context.Context(
            NetworkBatch116120Context.Ssdp(NetworkBatch116120Context.Source(), "239.255.255.250")))).Matched);
    }

    [Fact] public async Task Port_And_Info_Cannot_Replace_Parser_Attribution()
    {
        var record = NetworkBatch116120Context.Ssdp(NetworkBatch116120Context.Source());
        record.ApplicationProtocol = null; record.ApplicationService = null;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch116120Context.Context(record))).Matched);
    }

    [Fact] public async Task Contradictory_Tcp_And_Http_Cannot_Seed_Discovery()
    {
        var tcp = NetworkBatch116120Context.Ssdp(NetworkBatch116120Context.Source());
        tcp.IsTcp = true;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch116120Context.Context(tcp))).Matched);
        var http = NetworkBatch116120Context.Ssdp(NetworkBatch116120Context.Source());
        http.HttpMethod = "GET";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch116120Context.Context(http))).Matched);
    }

    [Fact] public async Task Replayed_Record_Identity_Cannot_Create_A_Burst()
    {
        var record = NetworkBatch116120Context.Ssdp(NetworkBatch116120Context.Source(), "239.255.255.250");
        for (var i = 0; i < 35; i++)
            Assert.False((await _rule.EvaluateAsync(NetworkBatch116120Context.Context(record, i))).Matched);
    }

    [Fact] public async Task Discovery_Payload_Secrets_Never_Appear_In_Alert()
    {
        const string secret = "ssdp-private-device-token-116";
        var record = NetworkBatch116120Context.Ssdp(NetworkBatch116120Context.Source());
        record.Info += " X-Device: " + secret;
        var result = await _rule.EvaluateAsync(NetworkBatch116120Context.Context(record));
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain(secret, evt.Evidence);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items,
            item => item.Value.Contains(secret, StringComparison.Ordinal));
    }
}
